"""FastMCP server exposing read-only PRTG Network Monitor (HTTP API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. All tools are read-only (GET). Curated tools cover the monitoring hierarchy
(probes → groups → devices → sensors → channels), status, logs, health and historic data; the raw
``prtg_get`` escape hatch reaches anything else.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .client import PrtgClient
from .config import ConfigError, Settings

mcp = FastMCP("prtg-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: PrtgClient | None = None


def _get_client() -> PrtgClient:
    global _client
    if _client is None:
        _client = PrtgClient(Settings.from_env())
    return _client


# ---- curated columns per content type -----------------------------------
_SENSOR_COLUMNS = (
    "objid", "sensor", "device", "group", "probe", "status", "status_raw", "lastvalue",
    "message", "priority", "lastcheck", "tags", "active", "parentid",
)
_DEVICE_COLUMNS = (
    "objid", "device", "host", "group", "probe", "status", "status_raw", "active", "priority",
    "tags", "parentid",
)
_GROUP_COLUMNS = ("objid", "group", "probe", "status", "status_raw", "active", "priority", "tags", "parentid")
_PROBE_COLUMNS = ("objid", "probe", "status", "status_raw", "active", "tags")
_CHANNEL_COLUMNS = ("objid", "name", "lastvalue", "lastvalue_raw")
_MESSAGE_COLUMNS = ("datetime", "parent", "type", "name", "status", "message", "priority")

# PRTG status names -> status_raw codes (a name can map to several codes).
_STATUS_CODES = {
    "up": [3],
    "warning": [4],
    "down": [5, 13, 14],
    "paused": [7, 8, 9, 11, 12],
    "unusual": [10],
    "unknown": [1, 2],
}


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 5000) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field in fields:
        out[field] = obj.get(field) if isinstance(obj, dict) else None
    return out


def _status_filter(status: str | None) -> list[int] | None:
    if not status:
        return None
    key = status.strip().lower()
    if key not in _STATUS_CODES:
        raise ValueError(f"status must be one of {tuple(_STATUS_CODES)}; got {status!r}.")
    return _STATUS_CODES[key]


async def _get_table(
    content: str,
    columns: tuple[str, ...],
    *,
    limit: int = 50,
    sortby: str | None = None,
    filters: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
    full: bool = False,
) -> dict[str, Any]:
    """Query /api/table.json for a content type, project to ``columns`` (unless ``full``), and cap."""
    params: dict[str, Any] = {"content": content, "count": _clamp(limit), "output": "json"}
    if not full:
        params["columns"] = ",".join(columns)
    if sortby:
        params["sortby"] = sortby
    if extra:
        params.update(extra)
    if filters:
        params.update(filters)
    data = await _get_client().get("table.json", params=params)
    rows = data.get(content, []) if isinstance(data, dict) else []
    total = data.get("treesize") if isinstance(data, dict) else None
    if not full:
        rows = [_pick(r, columns) for r in rows if isinstance(r, dict)]
    return {"treesize": total, "count": len(rows), content: rows}


# ---- tools: hierarchy ---------------------------------------------------

@mcp.tool()
async def list_sensors(
    status: Annotated[str | None, Field(description="Filter by state: up, down, warning, paused, unusual, unknown.")] = None,
    device_id: Annotated[int | None, Field(description="Only sensors on this device (parentid).")] = None,
    tag: Annotated[str | None, Field(description="Only sensors carrying this tag.")] = None,
    name_contains: Annotated[str | None, Field(description="Only sensors whose name contains this text.")] = None,
    limit: Annotated[int, Field(description="Max sensors to return.", ge=1, le=5000)] = 100,
    full: Annotated[bool, Field(description="Return PRTG's default full columns instead of the trimmed set.")] = False,
) -> dict[str, Any]:
    """List sensors and their state (table.json content=sensors).

    'status_raw' is the numeric code (3=Up, 4=Warning, 5=Down, 7-12=Paused, 10=Unusual, 1/2=Unknown).
    """
    filters: dict[str, Any] = {}
    sf = _status_filter(status)
    if sf is not None:
        filters["filter_status"] = sf
    if device_id is not None:
        filters["filter_parentid"] = device_id
    if tag:
        filters["filter_tags"] = f"@tag({tag})"
    if name_contains:
        filters["filter_name"] = f"@sub({name_contains})"
    return await _get_table("sensors", _SENSOR_COLUMNS, limit=limit, filters=filters, full=full)


@mcp.tool()
async def list_devices(
    status: Annotated[str | None, Field(description="Filter by state: up, down, warning, paused, unusual, unknown.")] = None,
    group_id: Annotated[int | None, Field(description="Only devices in this group (parentid).")] = None,
    name_contains: Annotated[str | None, Field(description="Only devices whose name contains this text.")] = None,
    limit: Annotated[int, Field(description="Max devices to return.", ge=1, le=5000)] = 100,
    full: Annotated[bool, Field(description="Return PRTG's default full columns instead of the trimmed set.")] = False,
) -> dict[str, Any]:
    """List devices and their state (table.json content=devices)."""
    filters: dict[str, Any] = {}
    sf = _status_filter(status)
    if sf is not None:
        filters["filter_status"] = sf
    if group_id is not None:
        filters["filter_parentid"] = group_id
    if name_contains:
        filters["filter_name"] = f"@sub({name_contains})"
    return await _get_table("devices", _DEVICE_COLUMNS, limit=limit, filters=filters, full=full)


@mcp.tool()
async def list_groups(
    status: Annotated[str | None, Field(description="Filter by state: up, down, warning, paused, unusual, unknown.")] = None,
    parent_id: Annotated[int | None, Field(description="Only subgroups of this group/probe (parentid).")] = None,
    limit: Annotated[int, Field(description="Max groups to return.", ge=1, le=5000)] = 100,
    full: Annotated[bool, Field(description="Return PRTG's default full columns instead of the trimmed set.")] = False,
) -> dict[str, Any]:
    """List groups and their state (table.json content=groups)."""
    filters: dict[str, Any] = {}
    sf = _status_filter(status)
    if sf is not None:
        filters["filter_status"] = sf
    if parent_id is not None:
        filters["filter_parentid"] = parent_id
    return await _get_table("groups", _GROUP_COLUMNS, limit=limit, filters=filters, full=full)


@mcp.tool()
async def list_probes(
    limit: Annotated[int, Field(description="Max probes to return.", ge=1, le=5000)] = 100,
    full: Annotated[bool, Field(description="Return PRTG's default full columns instead of the trimmed set.")] = False,
) -> dict[str, Any]:
    """List probes (local + remote) and their state (table.json content=probes)."""
    return await _get_table("probes", _PROBE_COLUMNS, limit=limit, full=full)


@mcp.tool()
async def list_channels(
    sensor_id: Annotated[int, Field(description="The sensor's object id.")],
    limit: Annotated[int, Field(description="Max channels to return.", ge=1, le=5000)] = 100,
    full: Annotated[bool, Field(description="Return PRTG's default full columns instead of the trimmed set.")] = False,
) -> dict[str, Any]:
    """List a sensor's channels and their current values (table.json content=channels&id=...)."""
    return await _get_table("channels", _CHANNEL_COLUMNS, limit=limit, extra={"id": sensor_id}, full=full)


# ---- tools: detail, status, logs ----------------------------------------

@mcp.tool()
async def get_sensor(
    sensor_id: Annotated[int, Field(description="The sensor's object id.")],
) -> dict[str, Any]:
    """Get one sensor's detail snapshot (getsensordetails.json) — type, last value, status, message."""
    data = await _get_client().get("getsensordetails.json", params={"id": sensor_id})
    return data.get("sensordata", data) if isinstance(data, dict) else {"data": data}


@mcp.tool()
async def server_status() -> dict[str, Any]:
    """PRTG core status and sensor counts (getstatus.json) — version, Up/Down/Warning/Paused totals, alarms."""
    return await _get_client().get("getstatus.json", params={"id": 0})


@mcp.tool()
async def system_health() -> dict[str, Any]:
    """PRTG system health metrics (health.json) — CPU, memory, disk, probe/sensor health."""
    return await _get_client().get("health.json")


@mcp.tool()
async def list_messages(
    sensor_id: Annotated[int | None, Field(description="Scope log to one object id (sensor/device/group); omit for all.")] = None,
    status: Annotated[str | None, Field(description="Filter by state: up, down, warning, paused, unusual, unknown.")] = None,
    limit: Annotated[int, Field(description="Max log entries to return (newest first).", ge=1, le=5000)] = 50,
    full: Annotated[bool, Field(description="Return PRTG's default full columns instead of the trimmed set.")] = False,
) -> dict[str, Any]:
    """List log / event messages (table.json content=messages), newest first."""
    filters: dict[str, Any] = {}
    sf = _status_filter(status)
    if sf is not None:
        filters["filter_status"] = sf
    extra = {"id": sensor_id} if sensor_id is not None else None
    return await _get_table("messages", _MESSAGE_COLUMNS, limit=limit, sortby="-datetime", filters=filters, extra=extra, full=full)


@mcp.tool()
async def historic_data(
    sensor_id: Annotated[int, Field(description="The sensor's object id.")],
    start: Annotated[str, Field(description="Start date-time, format 'yyyy-mm-dd-hh-mm-ss'.")],
    end: Annotated[str, Field(description="End date-time, format 'yyyy-mm-dd-hh-mm-ss'.")],
    avg: Annotated[int, Field(description="Averaging interval in seconds (0 = raw; 3600 = hourly; 86400 = daily).", ge=0)] = 3600,
    limit: Annotated[int, Field(description="Max data points to return.", ge=1, le=5000)] = 500,
) -> dict[str, Any]:
    """Historic channel data for a sensor (historicdata.json).

    Dates use 'yyyy-mm-dd-hh-mm-ss'. Use a non-zero 'avg' for wide ranges — raw data is capped to
    ~40 days by PRTG and can be very large. Results are also capped client-side to 'limit'.
    """
    data = await _get_client().get(
        "historicdata.json",
        params={"id": sensor_id, "sdate": start, "edate": end, "avg": avg, "usecaption": 1},
    )
    rows = data.get("histdata", []) if isinstance(data, dict) else []
    if not isinstance(rows, list):
        rows = []
    capped = rows[: _clamp(limit, 500, 5000)]
    return {"count": len(capped), "histdata": capped}


# ---- tool: raw escape hatch ---------------------------------------------

@mcp.tool()
async def prtg_get(
    endpoint: Annotated[str, Field(description="API endpoint relative to /api, e.g. 'table.json' or 'getsensortree.xml'.")],
    params: Annotated[dict[str, Any] | None, Field(description="Query params, e.g. {\"content\": \"sensors\", \"columns\": \"objid,sensor,status\", \"count\": 50}. Auth is added automatically.")] = None,
    as_text: Annotated[bool, Field(description="Return the raw text body instead of parsed JSON (use for .xml/.csv endpoints).")] = False,
) -> Any:
    """Escape hatch: raw read-only GET against any PRTG ``/api/...`` endpoint.

    Use for endpoints without a dedicated tool (e.g. 'getsensortree.xml', 'gettreenodestats.xml',
    'getobjectstatus.htm'). Pass as_text=true for XML/CSV/HTML responses. Returns JSON or raw text.
    """
    data = await _get_client().get_raw(endpoint, params=params, as_text=as_text)
    if as_text:
        return {"content": data}
    return data if isinstance(data, dict) else {"data": data}


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"prtg-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = PrtgClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
