"""FastMCP server exposing Microsoft Defender XDR tools (Microsoft Graph security API).

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools cover advanced hunting, incidents, alerts, devices,
vulnerabilities and (Graph beta) case management. Write tools (triage incidents and alerts: status,
owner, classification, determination, tags, comments; cases: create/update, comments, tasks) are
**opt-in**: they refuse unless ``DEFENDER_ALLOW_WRITE=true`` and need the admin-consented
``SecurityIncident.ReadWrite.All`` / ``SecurityAlert.ReadWrite.All`` / ``CaseManagement.ReadWrite.All``
permissions. With the flag off the server is read-only. Unless ``DEFENDER_CONFIRM_WRITE=false``, every
write first returns a preview plus a confirm code and only runs when called again with that code,
after the user has confirmed. With ``DEFENDER_AUTH=delegated`` every call runs as the signed-in user
(``defender-mcp login``) instead of the app. There are no device response/remediation actions
(isolate, AV scan): those live in the separate Defender for Endpoint API.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import asyncio
import secrets
import sys
import time
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from . import tokencache
from .config import ConfigError, Settings
from .graph import GraphClient, GraphError

mcp = FastMCP(
    "defender-mcp",
    instructions=(
        "Write tools (update_incident/update_alert/add_incident_comment/add_alert_comment, create_case/"
        "update_case/add_case_comment/add_case_task/update_case_task) need the user's confirmation: the "
        "first call changes nothing and returns a preview with a confirm_code. Show the user a short "
        "overview of what will change, end with 'Confirm it?', and only after they say yes repeat the "
        "call with confirm=<code>. whoami shows whether calls run as a signed-in user or as the app; "
        "with a signed-in user, assigned_to='me' assigns to that user."
    ),
)

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: GraphClient | None = None


def _get_client() -> GraphClient:
    global _client
    if _client is None:
        _client = GraphClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in DEFENDER_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set DEFENDER_ALLOW_WRITE=true (and grant the app registration the "
            "admin-consented SecurityIncident.ReadWrite.All / SecurityAlert.ReadWrite.All / "
            "CaseManagement.ReadWrite.All permissions) to change incidents, alerts and cases."
        )


async def _assignee(value: str | None) -> str | None:
    """Resolve assigned_to: 'me' becomes the signed-in user's UPN (delegated mode only)."""
    if value is None or value.strip().lower() != "me":
        return value
    client = _get_client()
    if not client.settings.delegated:
        raise ValueError("assigned_to='me' needs DEFENDER_AUTH=delegated; give a UPN instead.")
    user = (await client.whoami()).get("user")
    if not user:
        raise ValueError("Could not tell who is signed in; give a UPN instead of 'me'.")
    return user


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when DEFENDER_CONFIRM_WRITE=false, or when ``code`` matches this exact
    tool + change (so what runs is what the user saw).
    """
    if not _get_client().settings.confirm_write:
        return None
    raw = json.dumps([tool, change], sort_keys=True, default=str).encode()
    expected = hmac.new(_CONFIRM_KEY, raw, hashlib.sha256).hexdigest()[:12]
    if code and hmac.compare_digest(code.strip(), expected):
        return None
    out: dict[str, Any] = {
        "status": "confirmation_required",
        "changed": False,
        "summary": summary,
        "change": change,
        "confirm_code": expected,
        "next": (
            "Show the user a short overview of this change and end with 'Confirm it?'. Only after they "
            f"confirm, call {tool} again with the same arguments and confirm='{expected}'."
        ),
    }
    if code:
        out["note"] = "The confirm code did not match these arguments (changed, expired or restarted) — confirm again."
    return out


# --- enum sets for friendly validation (escape-hatch tools bypass these) ---
_SEVERITIES = ("informational", "low", "medium", "high")
_ALERT_STATUS = ("new", "inProgress", "resolved")
_INCIDENT_STATUS = ("active", "inProgress", "resolved", "redirected")
# Settable values for the write tools. 'redirected' is set by Defender when incidents are merged and
# 'awaitingAction' only by Defender Experts, so neither is offered; unknownFutureValue is a sentinel.
_INCIDENT_SET_STATUS = ("active", "inProgress", "resolved")
_ALERT_SET_STATUS = ("new", "inProgress", "resolved")
_CLASSIFICATIONS = ("unknown", "falsePositive", "truePositive", "informationalExpectedActivity")
# alertDetermination as in the v1.0 alert resource enum table / metadata (shared by incidents). Some
# MS pages still list older names (compromisedUser, clean, insufficientData, confirmedUserActivity).
_DETERMINATIONS = (
    "unknown", "apt", "malware", "securityPersonnel", "securityTesting", "unwantedSoftware", "other",
    "multiStagedAttack", "compromisedAccount", "phishing", "maliciousUserActivity", "notMalicious",
    "notEnoughDataToValidate", "confirmedActivity", "lineOfBusinessApplication",
)

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


@mcp.tool()
async def whoami() -> dict[str, Any]:
    """Show which identity the tools act as and which Graph permissions its token carries.

    auth='delegated': calls run as the signed-in user (user, name, delegated scopes); comments and
    changes are attributed to that user and limited by their Defender role. auth='app': calls run as
    the app registration (client_id, application roles). Also whether writes are enabled.
    """
    client = _get_client()
    out = await client.whoami()
    out["writes_enabled"] = client.settings.allow_write
    out["confirm_writes"] = client.settings.confirm_write
    return out


# ---- tools: case management (Graph beta, reads) --------------------------

_CASE_NS = "microsoft.graph.security.caseManagement"
_CASE_TYPES = {"generic": "genericCase", "incident": "incidentCase"}
_CASE_PRIORITIES = ("veryLow", "low", "medium", "high", "critical")
_SEVERITY_SET = ("informational", "low", "medium", "high")
_TASK_STATUS = ("new", "inProgress", "failed", "partiallyCompleted", "skipped", "completed")
_TASK_PRIORITIES = ("notSet", "veryLow", "low", "medium", "high", "critical")
_TASK_CATEGORIES = ("uncategorized", "triage", "contain", "investigate", "remediate", "prevent")
# Which case properties a PATCH may set, per concrete type (Graph beta "Update case").
_CASE_SETTABLE = {
    "genericCase": {"displayName", "status", "assignedTo", "closingNotes", "customFields", "description",
                    "dueDateTime", "priority"},
    "incidentCase": {"displayName", "status", "assignedTo", "classification", "determination", "severity",
                     "customFields", "dueDateTime"},
}
# incidentCase fields mirrored onto the incident: a PATCH containing any of them answers 202, no body.
_INCIDENT_SYNCED = {"assignedTo", "classification", "determination", "displayName", "severity", "status"}
# Custom field definition type -> (value @odata.type, value property).
_CUSTOM_FIELD_VALUES = {
    "stringCustomFieldDefinition": ("customFieldStringValue", "value"),
    "numberCustomFieldDefinition": ("customFieldNumberValue", "value"),
    "optionsCustomFieldDefinition": ("customFieldOptionsValue", "values"),
    "dateTimeCustomFieldDefinition": ("customFieldDateTimeValue", "valueDateTime"),
}
_CASE_KEYS = (
    "@odata.type", "id", "displayName", "status", "assignedTo", "priority", "severity", "classification",
    "determination", "incidentId", "dueDateTime", "createdBy", "createdDateTime", "lastModifiedBy",
    "lastModifiedDateTime", "incidentWebUrl",
)
_TASK_KEYS = ("id", "displayName", "status", "priority", "category", "assignedTo", "dueDateTime",
              "description", "closingNotes", "lastModifiedBy", "lastModifiedDateTime")


def _cases_url(path: str = "") -> str:
    return f"{_get_client().settings.graph_beta_url}/security/caseManagement{path}"


def _case_type_id(case: dict[str, Any]) -> str:
    """'#microsoft.graph.security.caseManagement.incidentCase' -> 'incidentCase'."""
    return str(case.get("@odata.type", "")).rsplit(".", 1)[-1]


def _trim_case(case: dict[str, Any]) -> dict[str, Any]:
    out = {k: case.get(k) for k in _CASE_KEYS if k in case}
    if "@odata.type" in out:
        out["caseType"] = _case_type_id(case)
        del out["@odata.type"]
    return out


def _resolve_case_type(case_type: str | None) -> str | None:
    if case_type is None:
        return None
    if case_type not in _CASE_TYPES:
        raise ValueError(f"case_type must be one of {tuple(_CASE_TYPES)}; got {case_type!r}.")
    return _CASE_TYPES[case_type]


async def _statuses(type_id: str) -> list[dict[str, Any]]:
    data = await _get_client().get(_cases_url(f"/caseTypeConfigurations/{type_id}/statuses"))
    return (data or {}).get("value", [])


async def _custom_field_defs(type_id: str) -> list[dict[str, Any]]:
    data = await _get_client().get(_cases_url(f"/caseTypeConfigurations/{type_id}/customFields"))
    return (data or {}).get("value", [])


def _status_names(tree: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for top in tree:
        names.append(str(top.get("displayName")))
        names += [str(c.get("displayName")) for c in top.get("customStatuses") or []]
    return [n for n in names if n and n != "None"]


async def _check_status(type_id: str, status: str) -> str:
    """Match ``status`` against the tenant's status tree (case-insensitive), return its exact spelling."""
    names = _status_names(await _statuses(type_id))
    for name in names:
        if name.lower() == status.strip().lower():
            return name
    raise ValueError(f"status must be one of this tenant's {type_id} statuses {names}; got {status!r}.")


async def _custom_fields(type_id: str, values: dict[str, Any]) -> dict[str, Any]:
    """Wrap plain values into Graph's typed customFieldValues, keyed by the definition displayName."""
    defs = {str(d.get("displayName")): d for d in await _custom_field_defs(type_id)}
    out: dict[str, Any] = {}
    for name, value in values.items():
        d = defs.get(name)
        if d is None:
            raise ValueError(f"Unknown custom field {name!r}; this tenant's {type_id} fields are {sorted(defs)}.")
        if d.get("isDisabled"):
            raise ValueError(f"Custom field {name!r} is disabled.")
        kind = _case_type_id(d)
        if kind not in _CUSTOM_FIELD_VALUES:
            raise ValueError(f"Custom field {name!r} has an unsupported type {kind!r}.")
        value_type, prop = _CUSTOM_FIELD_VALUES[kind]
        if prop == "values":
            value = [value] if isinstance(value, str) else list(value)
            allowed = [str(o) for o in d.get("options") or []]
            if allowed and (bad := [v for v in value if v not in allowed]):
                raise ValueError(f"Custom field {name!r} only takes {allowed}; got {bad}.")
        elif kind == "numberCustomFieldDefinition":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
                raise ValueError(f"Custom field {name!r} needs a whole number; got {value!r}.")
            value = int(value)
        else:
            value = str(value)
        out[name] = {"@odata.type": f"#{_CASE_NS}.{value_type}", prop: value}
    return out


@mcp.tool()
async def list_cases(
    case_type: Annotated[str | None, Field(description="Only 'generic' (analyst-created) or 'incident' (one per Defender incident) cases. Required when filtering by assigned_to.")] = None,
    status: Annotated[str | None, Field(description="Exact tenant status name (see get_case_type_config), e.g. 'Active'.")] = None,
    assigned_to: Annotated[str | None, Field(description="Owner UPN; 'me' = the signed-in user (delegated mode). Needs case_type.")] = None,
    top: Annotated[int, Field(description="Max cases to return (Graph caps at 100).", ge=1, le=100)] = 25,
    skip: Annotated[int, Field(description="Skip this many cases (paging).", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full case objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Defender case management cases (Graph BETA, preview), newest first.

    Needs CaseManagement.Read.All. Incident cases mirror Defender incidents (incidentId links them);
    generic cases are created by analysts. Use get_case(case_id) for tasks and comments.
    """
    type_id = _resolve_case_type(case_type)
    assigned_to = await _assignee(assigned_to)
    if assigned_to and not type_id:
        raise ValueError("assigned_to only works together with case_type ('generic' or 'incident').")
    clauses: list[str] = []
    if status:
        clauses.append(f"status eq '{_quote(status)}'")
    if assigned_to:
        clauses.append(f"assignedTo eq '{_quote(assigned_to)}'")
    params: dict[str, Any] = {"$top": top, "$orderby": "createdDateTime desc"}
    if skip:
        params["$skip"] = skip
    if flt := _odata_filter(clauses):
        params["$filter"] = flt
    path = f"/cases/{_CASE_NS}.{type_id}" if type_id else "/cases"
    data = await _get_client().get(_cases_url(path), params=params)
    items = (data or {}).get("value", [])
    return {"count": len(items), "cases": items if full else [_trim_case(c) for c in items]}


@mcp.tool()
async def get_case(
    case_id: Annotated[str, Field(description="The case id (a GUID, from list_cases).", min_length=1)],
    include_audit: Annotated[bool, Field(description="Also return audit-log activities (who changed what), not just comments.")] = False,
) -> dict[str, Any]:
    """Get one case (Graph BETA) with its tasks and comments.

    Needs CaseManagement.Read.All. Returns the full case object plus 'tasks' and 'comments' (and
    'auditLog' with include_audit).
    """
    case_id = _path_id(case_id, "case_id")
    client = _get_client()
    case = await client.get(_cases_url(f"/cases/{case_id}")) or {}
    tasks = (await client.get(_cases_url(f"/cases/{case_id}/tasks")) or {}).get("value", [])
    activities = (await client.get(_cases_url(f"/cases/{case_id}/activities")) or {}).get("value", [])
    comments = [
        {k: a.get(k) for k in ("id", "message", "createdBy", "createdDateTime")}
        for a in activities if _case_type_id(a) == "comment"
    ]
    out = {**case, "caseType": _case_type_id(case), "tasks": [{k: t.get(k) for k in _TASK_KEYS if k in t} for t in tasks],
           "comments": comments}
    if include_audit:
        out["auditLog"] = [a for a in activities if _case_type_id(a) == "auditLog"]
    return out


@mcp.tool()
async def get_case_type_config(
    case_type: Annotated[str, Field(description="'generic' or 'incident'.")],
) -> dict[str, Any]:
    """The tenant's case statuses and custom fields for one case type (Graph BETA).

    Case status values are tenant-defined: use one of these names in create_case / update_case /
    list_cases. Custom fields list their type, options and whether they're required.
    """
    type_id = _resolve_case_type(case_type) or ""
    tree = await _statuses(type_id)
    fields = [
        {k: d.get(k) for k in ("displayName", "description", "isRequired", "isDisabled", "options", "defaultValue", "defaultValues") if k in d}
        | {"type": _case_type_id(d).removesuffix("CustomFieldDefinition")}
        for d in await _custom_field_defs(type_id)
    ]
    statuses = [
        {"displayName": t.get("displayName"),
         "customStatuses": [{k: c.get(k) for k in ("displayName", "isFinal")} for c in t.get("customStatuses") or []]}
        for t in tree
    ]
    return {"caseType": type_id, "statuses": statuses, "customFields": fields}


# ---- tools: writes (opt-in, gated by DEFENDER_ALLOW_WRITE) ---------------

def _triage_payload(
    *,
    status: str | None,
    status_values: tuple[str, ...],
    assigned_to: str | None,
    classification: str | None,
    determination: str | None,
) -> dict[str, Any]:
    """Validate and build the shared PATCH body fields of incidents and alerts (camelCase)."""
    _validate(status, status_values, "status")
    _validate(classification, _CLASSIFICATIONS, "classification")
    _validate(determination, _DETERMINATIONS, "determination")
    payload: dict[str, Any] = {}
    if status is not None:
        payload["status"] = status
    if assigned_to is not None:
        payload["assignedTo"] = assigned_to.strip() or None  # '' unassigns (null)
    if classification is not None:
        payload["classification"] = classification
    if determination is not None:
        payload["determination"] = determination
    return payload


def _path_id(value: str, name: str) -> str:
    """Reject ids that would change the request path (a write must hit exactly the named object)."""
    value = value.strip()
    if not value or any(c in value for c in "/?#\\") or value in (".", ".."):
        raise ValueError(f"{name} must be a plain id; got {value!r}.")
    return value


def _comments_result(key: str, ident: str, data: Any) -> dict[str, Any]:
    """Graph answers a comment POST with the full comment list; return its size and the newest one."""
    comments = (data or {}).get("value", []) if isinstance(data, dict) else []
    return {key: ident, "commentCount": len(comments), "latest": comments[-1] if comments else None}


@mcp.tool()
async def update_incident(
    incident_id: Annotated[str, Field(description="The incident id (a string, e.g. '29').", min_length=1)],
    status: Annotated[str | None, Field(description="New status: active, inProgress, resolved.")] = None,
    assigned_to: Annotated[str | None, Field(description="New owner (UPN/email, free text); 'me' = the signed-in user (delegated mode); '' unassigns.")] = None,
    classification: Annotated[str | None, Field(description="unknown, falsePositive, truePositive, informationalExpectedActivity.")] = None,
    determination: Annotated[str | None, Field(description="unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedAccount, phishing, maliciousUserActivity, notMalicious, notEnoughDataToValidate, confirmedActivity, lineOfBusinessApplication.")] = None,
    custom_tags: Annotated[list[str] | None, Field(description="Replaces ALL custom tags of the incident; [] clears them. Omit to keep the current tags.")] = None,
    resolving_comment: Annotated[str | None, Field(description="Free-text explanation of the resolution and classification.", min_length=1)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Triage an incident: status, owner, classification, determination, tags (WRITE — requires DEFENDER_ALLOW_WRITE).

    PATCHes /security/incidents/{id}; only the fields you give change. Needs the
    SecurityIncident.ReadWrite.All permission. Read the current tags with get_incident
    first if you only want to add one (custom_tags replaces the whole list).
    """
    _require_write()
    incident_id = _path_id(incident_id, "incident_id")
    payload = _triage_payload(
        status=status, status_values=_INCIDENT_SET_STATUS, assigned_to=await _assignee(assigned_to),
        classification=classification, determination=determination,
    )
    if custom_tags is not None:
        payload["customTags"] = list(dict.fromkeys(t.strip() for t in custom_tags if t.strip()))
    if resolving_comment is not None:
        payload["resolvingComment"] = resolving_comment
    if not payload:
        raise ValueError(
            "Nothing to update: provide status, assigned_to, classification, determination, custom_tags "
            "or resolving_comment."
        )
    change = {"incident_id": incident_id, **payload}
    if preview := _confirm("update_incident", change, f"Update incident {incident_id}: {', '.join(payload)}.", confirm):
        return preview
    data = await _get_client().patch(f"/security/incidents/{incident_id}", json=payload)
    out = _trim_incident(data) if isinstance(data, dict) else {"id": incident_id}
    if isinstance(data, dict) and "resolvingComment" in data:
        out["resolvingComment"] = data["resolvingComment"]
    return out


@mcp.tool()
async def add_incident_comment(
    incident_id: Annotated[str, Field(description="The incident id (a string, e.g. '29').", min_length=1)],
    comment: Annotated[str, Field(description="Comment text (plain text).", min_length=1)],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add a comment to an incident (WRITE — requires DEFENDER_ALLOW_WRITE). POSTs /security/incidents/{id}/comments.

    Needs SecurityIncident.ReadWrite.All. Comments can't be edited or deleted through Graph.
    """
    _require_write()
    incident_id = _path_id(incident_id, "incident_id")
    payload = {"@odata.type": "microsoft.graph.security.alertComment", "comment": comment}
    if preview := _confirm("add_incident_comment", {"incident_id": incident_id, **payload}, f"Comment on incident {incident_id}.", confirm):
        return preview
    data = await _get_client().post(f"/security/incidents/{incident_id}/comments", json=payload)
    return _comments_result("incidentId", incident_id, data)


@mcp.tool()
async def update_alert(
    alert_id: Annotated[str, Field(description="The alert id (alerts_v2).", min_length=1)],
    status: Annotated[str | None, Field(description="New status: new, inProgress, resolved.")] = None,
    assigned_to: Annotated[str | None, Field(description="New owner (UPN/email, free text); 'me' = the signed-in user (delegated mode); '' unassigns.")] = None,
    classification: Annotated[str | None, Field(description="unknown, falsePositive, truePositive, informationalExpectedActivity.")] = None,
    determination: Annotated[str | None, Field(description="unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedAccount, phishing, maliciousUserActivity, notMalicious, notEnoughDataToValidate, confirmedActivity, lineOfBusinessApplication.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Triage an alert: status, owner, classification, determination (WRITE — requires DEFENDER_ALLOW_WRITE).

    PATCHes /security/alerts_v2/{id}; only the fields you give change. Needs the
    SecurityAlert.ReadWrite.All permission.
    """
    _require_write()
    alert_id = _path_id(alert_id, "alert_id")
    payload = _triage_payload(
        status=status, status_values=_ALERT_SET_STATUS, assigned_to=await _assignee(assigned_to),
        classification=classification, determination=determination,
    )
    if not payload:
        raise ValueError("Nothing to update: provide status, assigned_to, classification or determination.")
    change = {"alert_id": alert_id, **payload}
    if preview := _confirm("update_alert", change, f"Update alert {alert_id}: {', '.join(payload)}.", confirm):
        return preview
    data = await _get_client().patch(f"/security/alerts_v2/{alert_id}", json=payload)
    out = _trim_alert(data) if isinstance(data, dict) else {"id": alert_id}
    if isinstance(data, dict):
        for key in ("classification", "determination"):
            if key in data:
                out[key] = data[key]
    return out


@mcp.tool()
async def add_alert_comment(
    alert_id: Annotated[str, Field(description="The alert id (alerts_v2).", min_length=1)],
    comment: Annotated[str, Field(description="Comment text (plain text).", min_length=1)],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add a comment to an alert (WRITE — requires DEFENDER_ALLOW_WRITE). POSTs /security/alerts_v2/{id}/comments.

    Needs SecurityAlert.ReadWrite.All. Comments can't be edited or deleted through Graph.
    """
    _require_write()
    alert_id = _path_id(alert_id, "alert_id")
    payload = {"@odata.type": "microsoft.graph.security.alertComment", "comment": comment}
    if preview := _confirm("add_alert_comment", {"alert_id": alert_id, **payload}, f"Comment on alert {alert_id}.", confirm):
        return preview
    data = await _get_client().post(f"/security/alerts_v2/{alert_id}/comments", json=payload)
    return _comments_result("alertId", alert_id, data)


_DUE_DESC = "Target date/time, ISO-8601 (e.g. '2026-11-01T17:00:00Z'); '' clears it."
_CUSTOM_DESC = (
    "Custom field values keyed by the field's displayName, as plain values (text, whole number, ISO "
    "date/time, or a list of options); see get_case_type_config."
)


@mcp.tool()
async def create_case(
    display_name: Annotated[str, Field(description="Case title.", min_length=1)],
    status: Annotated[str, Field(description="A tenant status name for generic cases (see get_case_type_config), e.g. 'Active'.", min_length=1)],
    description: Annotated[str | None, Field(description="What the case is about.")] = None,
    assigned_to: Annotated[str | None, Field(description="Owner UPN; 'me' = the signed-in user (delegated mode).")] = None,
    priority: Annotated[str | None, Field(description="veryLow, low, medium, high, critical.")] = None,
    due_date_time: Annotated[str | None, Field(description="Target date/time, ISO-8601 (e.g. '2026-11-01T17:00:00Z').")] = None,
    custom_fields: Annotated[dict[str, Any] | None, Field(description=_CUSTOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a generic case (Graph BETA) (WRITE — requires DEFENDER_ALLOW_WRITE).

    POSTs /security/caseManagement/cases. Needs CaseManagement.ReadWrite.All. Incident cases can't be
    created: Defender creates one per incident. Cases can't be deleted with this server.
    """
    _require_write()
    _validate(priority, _CASE_PRIORITIES, "priority")
    payload: dict[str, Any] = {
        "@odata.type": f"#{_CASE_NS}.genericCase",
        "displayName": display_name,
        "status": await _check_status("genericCase", status),
    }
    for key, value in (("description", description), ("assignedTo", await _assignee(assigned_to)),
                       ("priority", priority), ("dueDateTime", due_date_time)):
        if value is not None:
            payload[key] = value
    if custom_fields:
        payload["customFields"] = await _custom_fields("genericCase", custom_fields)
    if preview := _confirm("create_case", payload, f"Create case '{display_name}'.", confirm):
        return preview
    data = await _get_client().post(_cases_url("/cases"), json=payload)
    return _trim_case(data) if isinstance(data, dict) else {"created": True}


@mcp.tool()
async def update_case(
    case_id: Annotated[str, Field(description="The case id (a GUID, from list_cases).", min_length=1)],
    status: Annotated[str | None, Field(description="A tenant status name for this case type (see get_case_type_config).")] = None,
    display_name: Annotated[str | None, Field(description="New title.", min_length=1)] = None,
    assigned_to: Annotated[str | None, Field(description="New owner UPN; 'me' = the signed-in user (delegated mode); '' unassigns.")] = None,
    priority: Annotated[str | None, Field(description="Generic cases: veryLow, low, medium, high, critical.")] = None,
    description: Annotated[str | None, Field(description="Generic cases: new description.")] = None,
    closing_notes: Annotated[str | None, Field(description="Generic cases: notes recorded when closing.")] = None,
    severity: Annotated[str | None, Field(description="Incident cases: informational, low, medium, high.")] = None,
    classification: Annotated[str | None, Field(description="Incident cases: unknown, falsePositive, truePositive, informationalExpectedActivity.")] = None,
    determination: Annotated[str | None, Field(description="Incident cases: same values as update_incident's determination.")] = None,
    due_date_time: Annotated[str | None, Field(description=_DUE_DESC)] = None,
    custom_fields: Annotated[dict[str, Any] | None, Field(description=_CUSTOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a case (Graph BETA) (WRITE — requires DEFENDER_ALLOW_WRITE). PATCHes /security/caseManagement/cases/{id}.

    Needs CaseManagement.ReadWrite.All. Which fields apply depends on the case type (read first to
    find it). On incident cases, status/owner/title/severity/classification/determination are mirrored
    to the Defender incident: Graph accepts them (202) and they show up after a few minutes.
    """
    _require_write()
    case_id = _path_id(case_id, "case_id")
    _validate(priority, _CASE_PRIORITIES, "priority")
    _validate(severity, _SEVERITY_SET, "severity")
    _validate(classification, _CLASSIFICATIONS, "classification")
    _validate(determination, _DETERMINATIONS, "determination")
    case = await _get_client().get(_cases_url(f"/cases/{case_id}")) or {}
    type_id = _case_type_id(case)
    if type_id not in _CASE_SETTABLE:
        raise ValueError(f"Case {case_id} has an unsupported type {type_id!r}.")
    assignee = await _assignee(assigned_to)
    payload: dict[str, Any] = {}
    for key, value in (("displayName", display_name), ("priority", priority), ("description", description),
                       ("closingNotes", closing_notes), ("severity", severity),
                       ("classification", classification), ("determination", determination)):
        if value is not None:
            payload[key] = value
    if assignee is not None:
        payload["assignedTo"] = assignee.strip() or None  # '' unassigns
    if due_date_time is not None:
        payload["dueDateTime"] = due_date_time.strip() or None  # '' clears
    if status is not None:
        payload["status"] = await _check_status(type_id, status)
    if custom_fields:
        payload["customFields"] = await _custom_fields(type_id, custom_fields)
    if not payload:
        raise ValueError("Nothing to update: give at least one field.")
    if wrong := sorted(set(payload) - _CASE_SETTABLE[type_id]):
        raise ValueError(f"{type_id} can't set {wrong}; it takes {sorted(_CASE_SETTABLE[type_id])}.")
    payload = {"@odata.type": f"#{_CASE_NS}.{type_id}", **payload}
    title = case.get("displayName") or case_id
    summary = f"Update {type_id} '{title}': {', '.join(k for k in payload if k != '@odata.type')}."
    if preview := _confirm("update_case", {"case_id": case_id, **payload}, summary, confirm):
        return preview
    data = await _get_client().patch(_cases_url(f"/cases/{case_id}"), json=payload)
    if isinstance(data, dict):
        return _trim_case(data)
    out: dict[str, Any] = {"id": case_id, "accepted": True}
    if type_id == "incidentCase" and _INCIDENT_SYNCED & set(payload):
        out["note"] = "Mirrored to the Defender incident; can take a few minutes to show on the case."
    return out


@mcp.tool()
async def add_case_comment(
    case_id: Annotated[str, Field(description="The case id (a GUID, from list_cases).", min_length=1)],
    comment: Annotated[str, Field(description="Comment text (plain text).", min_length=1)],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add a comment to a case (Graph BETA) (WRITE — requires DEFENDER_ALLOW_WRITE). POSTs .../cases/{id}/activities.

    Needs CaseManagement.ReadWrite.All. A case holds at most 100 comments; comments on incident cases
    can't be edited or deleted afterwards.
    """
    _require_write()
    case_id = _path_id(case_id, "case_id")
    payload = {"@odata.type": f"#{_CASE_NS}.comment", "message": comment}
    if preview := _confirm("add_case_comment", {"case_id": case_id, **payload}, f"Comment on case {case_id}.", confirm):
        return preview
    data = await _get_client().post(_cases_url(f"/cases/{case_id}/activities"), json=payload)
    if isinstance(data, dict):
        return {"caseId": case_id, **{k: data.get(k) for k in ("id", "message", "createdBy", "createdDateTime")}}
    return {"caseId": case_id, "created": True}


@mcp.tool()
async def add_case_task(
    case_id: Annotated[str, Field(description="The case id (a GUID, from list_cases).", min_length=1)],
    display_name: Annotated[str, Field(description="Task title.", min_length=1)],
    category: Annotated[str, Field(description="uncategorized, triage, contain, investigate, remediate, prevent.")] = "uncategorized",
    priority: Annotated[str, Field(description="notSet, veryLow, low, medium, high, critical.")] = "notSet",
    status: Annotated[str, Field(description="new, inProgress, failed, partiallyCompleted, skipped, completed.")] = "new",
    description: Annotated[str | None, Field(description="What needs doing.")] = None,
    assigned_to: Annotated[str | None, Field(description="Owner UPN; 'me' = the signed-in user (delegated mode).")] = None,
    due_date_time: Annotated[str | None, Field(description="Target date/time, ISO-8601.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add a task to a case (Graph BETA) (WRITE — requires DEFENDER_ALLOW_WRITE). POSTs .../cases/{id}/tasks.

    Needs CaseManagement.ReadWrite.All.
    """
    _require_write()
    case_id = _path_id(case_id, "case_id")
    _validate(category, _TASK_CATEGORIES, "category")
    _validate(priority, _TASK_PRIORITIES, "priority")
    _validate(status, _TASK_STATUS, "status")
    payload: dict[str, Any] = {
        "@odata.type": f"#{_CASE_NS}.task",
        "displayName": display_name, "status": status, "priority": priority, "category": category,
    }
    for key, value in (("description", description), ("assignedTo", await _assignee(assigned_to)),
                       ("dueDateTime", due_date_time)):
        if value is not None:
            payload[key] = value
    if preview := _confirm("add_case_task", {"case_id": case_id, **payload}, f"Add task '{display_name}' to case {case_id}.", confirm):
        return preview
    data = await _get_client().post(_cases_url(f"/cases/{case_id}/tasks"), json=payload)
    if isinstance(data, dict):
        return {"caseId": case_id, **{k: data.get(k) for k in _TASK_KEYS if k in data}}
    return {"caseId": case_id, "created": True}


@mcp.tool()
async def update_case_task(
    case_id: Annotated[str, Field(description="The case id (a GUID).", min_length=1)],
    task_id: Annotated[str, Field(description="The task id (from get_case).", min_length=1)],
    status: Annotated[str | None, Field(description="new, inProgress, failed, partiallyCompleted, skipped, completed.")] = None,
    assigned_to: Annotated[str | None, Field(description="Owner UPN; 'me' = the signed-in user (delegated mode); '' unassigns.")] = None,
    priority: Annotated[str | None, Field(description="notSet, veryLow, low, medium, high, critical.")] = None,
    category: Annotated[str | None, Field(description="uncategorized, triage, contain, investigate, remediate, prevent.")] = None,
    display_name: Annotated[str | None, Field(description="New title.", min_length=1)] = None,
    description: Annotated[str | None, Field(description="New description.")] = None,
    closing_notes: Annotated[str | None, Field(description="Notes recorded when finishing the task.")] = None,
    due_date_time: Annotated[str | None, Field(description=_DUE_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a case task (Graph BETA) (WRITE — requires DEFENDER_ALLOW_WRITE). PATCHes .../cases/{id}/tasks/{taskId}.

    Needs CaseManagement.ReadWrite.All. Only the fields you give change.
    """
    _require_write()
    case_id = _path_id(case_id, "case_id")
    task_id = _path_id(task_id, "task_id")
    _validate(status, _TASK_STATUS, "status")
    _validate(priority, _TASK_PRIORITIES, "priority")
    _validate(category, _TASK_CATEGORIES, "category")
    assignee = await _assignee(assigned_to)
    payload: dict[str, Any] = {}
    for key, value in (("status", status), ("priority", priority), ("category", category),
                       ("displayName", display_name), ("description", description),
                       ("closingNotes", closing_notes)):
        if value is not None:
            payload[key] = value
    if assignee is not None:
        payload["assignedTo"] = assignee.strip() or None
    if due_date_time is not None:
        payload["dueDateTime"] = due_date_time.strip() or None
    if not payload:
        raise ValueError("Nothing to update: give at least one field.")
    change = {"case_id": case_id, "task_id": task_id, **payload}
    if preview := _confirm("update_case_task", change, f"Update task {task_id} of case {case_id}: {', '.join(payload)}.", confirm):
        return preview
    data = await _get_client().patch(_cases_url(f"/cases/{case_id}/tasks/{task_id}"), json=payload)
    if isinstance(data, dict):
        return {"caseId": case_id, **{k: data.get(k) for k in _TASK_KEYS if k in data}}
    return {"caseId": case_id, "id": task_id, "updated": True}


# ---- CLI: sign-in for DEFENDER_AUTH=delegated ----------------------------

_USAGE = """usage: defender-mcp [login | logout | status]
  (no argument)  run the MCP server
  login          sign in as yourself (device code); needs DEFENDER_AUTH=delegated
  logout         forget the stored sign-in
  status         show who the server acts as"""


def _cli(settings: Settings, command: str) -> int:
    client = GraphClient(settings)
    try:
        if command == "login":
            user = asyncio.run(client.device_login(show=lambda msg: print(msg, flush=True)))
            print(f"Signed in as {user.get('username') or user.get('oid')}. "
                  f"Sign-in stored in {settings.token_cache}; the server uses it from its next call.")
        elif command == "logout":
            removed = tokencache.clear(settings.token_cache)
            print("Signed out." if removed else "Nobody was signed in.")
            if removed:
                print("To revoke the refresh token itself, sign out the sessions in the Entra/My Account portal.")
        elif command == "status":
            if settings.delegated:
                entry = tokencache.load(settings.token_cache, tenant_id=settings.tenant_id, client_id=settings.client_id)
                if entry is None:
                    print(f"Not signed in (DEFENDER_AUTH=delegated, cache {settings.token_cache}).")
                    return 1
                saved = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.get("saved_at", 0)))
                print(f"Signed in as {entry.get('username')} (token renewed {saved}).")
            info = asyncio.run(client.whoami())
            print(json.dumps(info, indent=2))
        else:
            print(_USAGE, file=sys.stderr)
            return 2
    except GraphError as exc:
        print(f"defender-mcp: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server (or a CLI command)."""
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help", "help"):
        print(_USAGE)
        raise SystemExit(0)
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"defender-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)
    if args:
        raise SystemExit(_cli(settings, args[0]))

    # Share the configured client with the tools.
    global _client
    _client = GraphClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
