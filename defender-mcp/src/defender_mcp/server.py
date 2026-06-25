"""FastMCP server exposing read-only Microsoft Defender XDR tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. All tools are read-only: there are no response/remediation actions.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config import ConfigError, Settings
from .graph import GraphClient

mcp = FastMCP("defender-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: GraphClient | None = None


def _get_client() -> GraphClient:
    global _client
    if _client is None:
        _client = GraphClient(Settings.from_env())
    return _client


# --- enum sets for friendly validation (escape-hatch tools bypass these) ---
_SEVERITIES = ("informational", "low", "medium", "high")
_ALERT_STATUS = ("new", "inProgress", "resolved")
_INCIDENT_STATUS = ("active", "inProgress", "resolved", "redirected")

_INCIDENT_KEYS = (
    "id", "displayName", "severity", "status", "determination", "classification",
    "assignedTo", "createdDateTime", "lastUpdateDateTime", "incidentWebUrl",
    "customTags", "systemTags",
)
_ALERT_KEYS = (
    "id", "title", "severity", "status", "categories", "serviceSource", "detectionSource",
    "createdDateTime", "lastUpdateDateTime", "assignedTo", "incidentId", "mitreTechniques",
    "alertWebUrl",
)


# ---- helpers ------------------------------------------------------------

def _validate(value: str | None, allowed: tuple[str, ...], name: str) -> None:
    if value is not None and value not in allowed:
        raise ValueError(f"{name} must be one of {allowed}; got {value!r}.")


def _quote(value: str) -> str:
    """Escape a string for an OData literal (single quotes are doubled)."""
    return value.replace("'", "''")


def _kql_str(value: str) -> str:
    """Render a safe double-quoted KQL string literal."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _odata_filter(clauses: list[str]) -> str | None:
    clauses = [c for c in clauses if c]
    return " and ".join(clauses) if clauses else None


def _shape_hunt(data: dict[str, Any], *, full: bool, limit: int) -> dict[str, Any]:
    """Trim a hunting payload to a row cap unless ``full``; always expose column names."""
    schema = data.get("schema") or []
    results = data.get("results") or []
    columns = [c.get("name") for c in schema if isinstance(c, dict)]
    total = len(results)
    if not full and total > limit:
        results = results[:limit]
    return {
        "columns": columns,
        "schema": schema,
        "row_count": total,
        "returned": len(results),
        "truncated": (not full) and total > len(results),
        "results": results,
    }


def _trim_incident(inc: dict[str, Any]) -> dict[str, Any]:
    out = {k: inc.get(k) for k in _INCIDENT_KEYS if k in inc}
    alerts = inc.get("alerts")
    if isinstance(alerts, list):
        out["alertCount"] = len(alerts)
    return out


def _trim_alert(alert: dict[str, Any]) -> dict[str, Any]:
    out = {k: alert.get(k) for k in _ALERT_KEYS if k in alert}
    evidence = alert.get("evidence")
    if isinstance(evidence, list):
        out["evidenceCount"] = len(evidence)
    return out


# ---- tools --------------------------------------------------------------

@mcp.tool()
async def advanced_hunting(
    query: Annotated[str, Field(description="A Kusto Query Language (KQL) hunting query, e.g. 'DeviceInfo | take 5'.")],
    timespan: Annotated[
        str | None,
        Field(description="Optional ISO-8601 window, e.g. 'P7D' (7 days) or 'start/end'. Default 30 days; the shorter of this and any in-query time filter wins."),
    ] = None,
    full: Annotated[bool, Field(description="Return all rows untrimmed. Default False caps rows to keep the payload small.")] = False,
) -> dict[str, Any]:
    """Run an arbitrary KQL advanced-hunting query against Microsoft Defender XDR telemetry.

    This is the headline tool: it reaches essentially all Defender telemetry tables, e.g.
    DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, AlertEvidence,
    EmailEvents, IdentityLogonEvents, DeviceTvmSoftwareVulnerabilities.

    Examples:
      - Recent devices:        DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId | take 20
      - PowerShell from Office: DeviceProcessEvents
                                  | where InitiatingProcessFileName in~ ('winword.exe','excel.exe','outlook.exe')
                                    and FileName =~ 'powershell.exe'
                                  | project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
      - Outbound to an IP:     DeviceNetworkEvents | where RemoteIP == '1.2.3.4' | take 50
      - Critical vulns:        DeviceTvmSoftwareVulnerabilities
                                  | where DeviceName has 'host01' and VulnerabilitySeverityLevel == 'Critical'

    Limits: ~30-day data window, up to 100,000 rows, ~3-minute query timeout. Use '| take N' to bound
    results. Read column names from the returned 'columns'/'schema'; row-key casing follows the projection.
    """
    client = _get_client()
    data = await client.run_hunting_query(query, timespan)
    return _shape_hunt(data, full=full, limit=client.settings.max_rows)


@mcp.tool()
async def list_incidents(
    status: Annotated[str | None, Field(description="Filter by status: active, inProgress, resolved, redirected.")] = None,
    severity: Annotated[str | None, Field(description="Filter by severity: informational, low, medium, high.")] = None,
    assigned_to: Annotated[str | None, Field(description="Filter by the assignee (UPN/email) the incident is assigned to.")] = None,
    top: Annotated[int, Field(description="Max incidents to return (most recent first).", ge=1, le=1000)] = 20,
    full: Annotated[bool, Field(description="Return full incident objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Microsoft Defender XDR incidents, most recent first.

    Filters map to OData $filter on the documented fields (status, severity, assignedTo).
    Use get_incident(incident_id) to retrieve one incident with its alerts expanded.
    """
    _validate(status, _INCIDENT_STATUS, "status")
    _validate(severity, _SEVERITIES, "severity")
    clauses: list[str] = []
    if status:
        clauses.append(f"status eq '{_quote(status)}'")
    if severity:
        clauses.append(f"severity eq '{_quote(severity)}'")
    if assigned_to:
        clauses.append(f"assignedTo eq '{_quote(assigned_to)}'")
    params: dict[str, Any] = {"$top": top}
    flt = _odata_filter(clauses)
    if flt:
        params["$filter"] = flt
    data = await _get_client().get("/security/incidents", params=params)
    items = (data or {}).get("value", [])
    if full:
        return {"count": len(items), "incidents": items}
    return {"count": len(items), "incidents": [_trim_incident(i) for i in items]}


@mcp.tool()
async def get_incident(
    incident_id: Annotated[str, Field(description="The incident id (a string, e.g. '29').")],
) -> dict[str, Any]:
    """Get a single Defender XDR incident with its alerts expanded ($expand=alerts)."""
    data = await _get_client().get(
        f"/security/incidents/{incident_id}", params={"$expand": "alerts"}
    )
    return data or {}


@mcp.tool()
async def list_alerts(
    severity: Annotated[str | None, Field(description="Filter by severity: informational, low, medium, high.")] = None,
    status: Annotated[str | None, Field(description="Filter by status: new, inProgress, resolved.")] = None,
    category: Annotated[str | None, Field(description="Match a MITRE category (client-side filter against each alert's categories).")] = None,
    top: Annotated[int, Field(description="Max alerts to return (most recent first).", ge=1, le=1000)] = 50,
    full: Annotated[bool, Field(description="Return full alert objects (incl. evidence) instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Defender XDR alerts (alerts_v2), most recent first.

    severity and status are applied server-side via OData $filter. 'category' is not a documented
    $filter field, so it is matched client-side against each alert's categories. Use get_alert(alert_id)
    for a single alert with full evidence.
    """
    _validate(severity, _SEVERITIES, "severity")
    _validate(status, _ALERT_STATUS, "status")
    clauses: list[str] = []
    if severity:
        clauses.append(f"severity eq '{_quote(severity)}'")
    if status:
        clauses.append(f"status eq '{_quote(status)}'")
    params: dict[str, Any] = {"$top": top}
    flt = _odata_filter(clauses)
    if flt:
        params["$filter"] = flt
    data = await _get_client().get("/security/alerts_v2", params=params)
    items = (data or {}).get("value", [])
    if category:
        needle = category.lower()
        items = [a for a in items if any(needle == str(c).lower() for c in (a.get("categories") or []))]
    if full:
        return {"count": len(items), "alerts": items}
    return {"count": len(items), "alerts": [_trim_alert(a) for a in items]}


@mcp.tool()
async def get_alert(
    alert_id: Annotated[str, Field(description="The alert id.")],
) -> dict[str, Any]:
    """Get a single Defender XDR alert (alerts_v2) including its evidence and comments."""
    data = await _get_client().get(f"/security/alerts_v2/{alert_id}")
    return data or {}


@mcp.tool()
async def list_devices(
    filter: Annotated[str | None, Field(description="Free-text substring matched against DeviceName or OSPlatform.")] = None,
    top: Annotated[int, Field(description="Max devices to return.", ge=1, le=1000)] = 50,
    full: Annotated[bool, Field(description="Return all rows untrimmed.")] = False,
) -> dict[str, Any]:
    """List onboarded devices via a DeviceInfo advanced-hunting query (latest state per device).

    Because device inventory is derived from hunting telemetry, only devices seen within the ~30-day
    window appear, and 'last seen' is the latest event Timestamp rather than a real-time field.
    """
    top = max(1, min(top, 1000))
    where = ""
    if filter:
        needle = _kql_str(filter)
        where = f"| where DeviceName has {needle} or OSPlatform has {needle} "
    query = (
        "DeviceInfo "
        "| summarize arg_max(Timestamp, *) by DeviceId "
        f"{where}"
        "| project DeviceId, DeviceName, OSPlatform, OSVersion, OSArchitecture, OnboardingStatus, "
        "ExposureLevel, IsInternetFacing, MachineGroup, DeviceType, Timestamp "
        f"| take {top}"
    )
    client = _get_client()
    data = await client.run_hunting_query(query)
    return _shape_hunt(data, full=full, limit=client.settings.max_rows)


@mcp.tool()
async def get_vulnerabilities(
    device: Annotated[str | None, Field(description="Match against DeviceName (substring).")] = None,
    severity: Annotated[str | None, Field(description="TVM severity: Low, Medium, High, Critical.")] = None,
    cve: Annotated[str | None, Field(description="Exact CVE id, e.g. 'CVE-2024-1234'.")] = None,
    top: Annotated[int, Field(description="Max rows to return.", ge=1, le=1000)] = 50,
    full: Annotated[bool, Field(description="Return all rows untrimmed.")] = False,
) -> dict[str, Any]:
    """List software vulnerabilities via a DeviceTvmSoftwareVulnerabilities advanced-hunting query.

    Optional filters combine with AND. Bounded to the ~30-day hunting window.
    """
    top = max(1, min(top, 1000))
    clauses: list[str] = []
    if device:
        clauses.append(f"DeviceName has {_kql_str(device)}")
    if severity:
        clauses.append(f"VulnerabilitySeverityLevel == {_kql_str(severity)}")
    if cve:
        clauses.append(f"CveId == {_kql_str(cve)}")
    where = ("| where " + " and ".join(clauses) + " ") if clauses else ""
    query = (
        "DeviceTvmSoftwareVulnerabilities "
        f"{where}"
        "| project DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, "
        "CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, CveTags "
        f"| take {top}"
    )
    client = _get_client()
    data = await client.run_hunting_query(query)
    return _shape_hunt(data, full=full, limit=client.settings.max_rows)


@mcp.tool()
async def graph_get(
    path: Annotated[str, Field(description="A Graph path such as '/security/incidents' or '/security/alerts_v2/{id}', or a full https://graph.microsoft.com/... URL.")],
    params: Annotated[dict[str, Any] | None, Field(description="Optional query parameters, e.g. {\"$top\": 5, \"$filter\": \"severity eq 'high'\"}.")] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only HTTP GET against any Microsoft Graph endpoint.

    Only GET is supported, and absolute URLs must target the configured Graph host. Use this to reach
    Graph capabilities not covered by a dedicated tool.
    """
    client = _get_client()
    if path.startswith(("http://", "https://")) and not path.startswith(client.settings.graph_origin):
        raise ValueError(
            f"graph_get only allows the configured Graph host ({client.settings.graph_origin})."
        )
    data = await client.get(path, params=params)
    return data if data is not None else {}


@mcp.tool()
async def graph_hunt(
    kql: Annotated[str, Field(description="A KQL advanced-hunting query.")],
    timespan: Annotated[str | None, Field(description="Optional ISO-8601 window (e.g. 'P7D').")] = None,
) -> dict[str, Any]:
    """Escape hatch: run a raw KQL hunting query and return Graph's exact {schema, results}, untrimmed.

    Like advanced_hunting but with no result shaping or row cap — use when you need the raw payload.
    """
    return await _get_client().run_hunting_query(kql, timespan)


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"defender-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = GraphClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
