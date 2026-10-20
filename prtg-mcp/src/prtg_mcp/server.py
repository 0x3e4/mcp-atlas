"""FastMCP server exposing PRTG Network Monitor (HTTP API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools cover the monitoring hierarchy (probes → groups → devices →
sensors → channels), status, logs, health and historic data; the raw read-only ``prtg_get`` escape
hatch reaches anything else. Write tools (pause/resume, acknowledge, scan now, rename, edit tags/
priority/comments/location/host/interval, channel limits, clone, move, add device/group, auto-discovery)
are **opt-in**: they refuse unless ``PRTG_ALLOW_WRITE=true`` and need credentials with write access on
the objects. With the flag off the server is read-only. Unless ``PRTG_CONFIRM_WRITE=false``, every
write first returns a preview plus a confirm code and only runs when called again with that code,
after the user has confirmed.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import PrtgClient, PrtgError
from .config import ConfigError, Settings

mcp = FastMCP(
    "prtg-mcp",
    instructions=(
        "Write tools (pause/resume/acknowledge/scan, rename/update/clone/move objects, channel limits, "
        "add device/group, discover) need the user's confirmation: "
        "the first call changes nothing and returns a preview with a confirm_code. Show the user a short "
        "overview of what will change, end with 'Confirm it?', and only after they say yes repeat the call "
        "with confirm=<code>."
    ),
)

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: PrtgClient | None = None


def _get_client() -> PrtgClient:
    global _client
    if _client is None:
        _client = PrtgClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in PRTG_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set PRTG_ALLOW_WRITE=true (and use an API key / user with write "
            "access on the objects) to pause/resume, acknowledge, scan, edit, clone, move or add objects."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when PRTG_CONFIRM_WRITE=false, or when ``code`` matches this exact
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
    State-changing endpoints (pause.htm, setobjectproperty.htm, deleteobject.htm, ...) are refused.
    """
    data = await _get_client().get_raw(endpoint, params=params, as_text=as_text)
    if as_text:
        return {"content": data}
    return data if isinstance(data, dict) else {"data": data}


def _xml_result(text: str) -> str:
    """The ``<result>`` of a getobjectproperty.htm answer (``<prtg>…<result>v</result></prtg>``)."""
    match = re.search(r"<result>(.*?)</result>", text or "", re.S)
    if match is None:
        err = re.search(r"<error>(.*?)</error>", text or "", re.S)
        raise PrtgError(f"PRTG refused the property read: {err.group(1).strip() if err else (text or '')[:200]}")
    return html.unescape(match.group(1))


async def _own_tags(object_id: int) -> list[str]:
    """The object's own tags (not inherited ones — those must not be written back)."""
    text = await _get_client().get(
        "getobjectproperty.htm", params={"id": object_id, "name": "tags", "show": "nohtmlencode"}, as_text=True
    )
    return [t for t in re.split(r"[\s,]+", _xml_result(text)) if t]


@mcp.tool()
async def get_object_property(
    object_id: Annotated[int, Field(description="Object id (probe, group, device, sensor, notification, ...).", ge=0)],
    property: Annotated[str, Field(description="Settings field name without the trailing underscore, e.g. 'name', 'tags', 'priority', 'host', 'location', 'interval', 'comments', 'intervalgroup'. For a channel: 'limitmaxerror', 'limitmode', ...", min_length=1)],
    channel_id: Annotated[int | None, Field(description="Read a channel property of sensor object_id (subtype=channel&subid=).", ge=0)] = None,
) -> dict[str, Any]:
    """Read one raw setting of an object (getobjectproperty.htm?id=&name=&show=nohtmlencode).

    Returns the object's own value (for 'tags' only its own tags, not inherited ones). Use it to see
    the current value before update_object / set_channel_limits. Unknown names come back as
    '(Property not found)'.
    """
    params: dict[str, Any] = {"id": object_id, "name": property.strip().rstrip("_"), "show": "nohtmlencode"}
    if channel_id is not None:
        params.update(subtype="channel", subid=channel_id)
    text = await _get_client().get("getobjectproperty.htm", params=params, as_text=True)
    out: dict[str, Any] = {"object_id": object_id, "property": params["name"], "value": _xml_result(text)}
    if channel_id is not None:
        out["channel_id"] = channel_id
    return out


# ---- tools: writes (opt-in, gated by PRTG_ALLOW_WRITE) -------------------

async def _act(
    tool: str, endpoint: str, params: dict[str, Any], *, root: bool = False, redirect_ok: bool = False
) -> dict[str, Any]:
    """Run a PRTG action call and return a trimmed result (PRTG applies the change asynchronously)."""
    result = await _get_client().action(endpoint, params=params, root=root, redirect_ok=redirect_ok)
    path = f"/{endpoint}" if root else f"/api/{endpoint}"
    return {"ok": True, "tool": tool, "endpoint": path, **params, **result}


async def _run_steps(tool: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Run several property calls in order; on a failure say which ones already went through."""
    done: list[dict[str, Any]] = []
    for step in steps:
        params = {k: v for k, v in step.items() if k != "endpoint"}
        try:
            await _get_client().action(step["endpoint"], params=params, redirect_ok=True)
        except PrtgError as exc:
            applied = ", ".join(str(d.get("name", d["endpoint"])) for d in done) or "nothing"
            raise PrtgError(f"{exc} (step {step.get('name', step['endpoint'])}; already applied: {applied})") from exc
        done.append(step)
    return {"ok": True, "tool": tool, "applied": done}


def _new_id(location: str | None) -> int | None:
    match = re.search(r"[?&]id=(\d+)", location or "")
    return int(match.group(1)) if match else None


@mcp.tool()
async def pause_object(
    object_id: Annotated[int, Field(description="Object id of the sensor, device, group or probe to pause (not the root group 0).", ge=1)],
    message: Annotated[str | None, Field(description="Pause message shown on the object while it is paused.", min_length=1, max_length=255)] = None,
    duration_minutes: Annotated[int | None, Field(description="Pause for this many minutes, then resume automatically. Omit to pause indefinitely.", ge=1, le=525600)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Pause monitoring of a sensor, device, group or probe (WRITE — requires PRTG_ALLOW_WRITE).

    GETs /api/pause.htm?id=&action=0&pausemsg= (indefinitely) or
    /api/pauseobjectfor.htm?id=&duration=&pausemsg= (minutes, then auto-resume). Pausing a
    device/group/probe pauses everything below it. Undo with resume_object.
    """
    _require_write()
    if duration_minutes is None:
        endpoint, params = "pause.htm", {"id": object_id, "action": 0}
        how = "indefinitely"
    else:
        endpoint, params = "pauseobjectfor.htm", {"id": object_id, "duration": duration_minutes}
        how = f"for {duration_minutes} min"
    if message is not None:
        params["pausemsg"] = message
    if preview := _confirm("pause_object", {"endpoint": endpoint, **params}, f"Pause object {object_id} {how}.", confirm):
        return preview
    return await _act("pause_object", endpoint, params)


@mcp.tool()
async def resume_object(
    object_id: Annotated[int, Field(description="Object id of the paused sensor, device, group or probe.", ge=0)],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Resume monitoring of a paused object (WRITE — requires PRTG_ALLOW_WRITE). GETs /api/pause.htm?id=&action=1.

    Only lifts a manual pause; objects paused by a dependency, schedule or a paused parent stay paused.
    """
    _require_write()
    params = {"id": object_id, "action": 1}
    if preview := _confirm("resume_object", {"endpoint": "pause.htm", **params}, f"Resume object {object_id}.", confirm):
        return preview
    return await _act("resume_object", "pause.htm", params)


@mcp.tool()
async def acknowledge_alarm(
    sensor_id: Annotated[int, Field(description="Object id of the sensor in a Down state.", ge=1)],
    message: Annotated[str | None, Field(description="Acknowledgement message shown on the sensor.", min_length=1, max_length=255)] = None,
    duration_minutes: Annotated[int | None, Field(description="Acknowledge for this many minutes only. Omit to acknowledge indefinitely (until the sensor changes state).", ge=1, le=525600)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Acknowledge a Down sensor's alarm (WRITE — requires PRTG_ALLOW_WRITE). GETs /api/acknowledgealarm.htm?id=&ackmsg=.

    The sensor goes to 'Down (Acknowledged)' (status_raw 13) and stops re-alerting until it changes
    state (or the optional duration ends). Only sensors in a Down state can be acknowledged.
    """
    _require_write()
    params: dict[str, Any] = {"id": sensor_id}
    if message is not None:
        params["ackmsg"] = message
    if duration_minutes is not None:
        params["duration"] = duration_minutes
    how = "indefinitely" if duration_minutes is None else f"for {duration_minutes} min"
    if preview := _confirm("acknowledge_alarm", {"endpoint": "acknowledgealarm.htm", **params},
                           f"Acknowledge the alarm on sensor {sensor_id} {how}.", confirm):
        return preview
    return await _act("acknowledge_alarm", "acknowledgealarm.htm", params)


@mcp.tool()
async def scan_now(
    object_id: Annotated[int, Field(description="Object id of the sensor, device, group or probe to scan.", ge=0)],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Trigger an immediate scan of an object (WRITE — requires PRTG_ALLOW_WRITE). GETs /api/scannow.htm?id=.

    On a device/group/probe every sensor below it is scanned. Results appear after the scan finishes
    (check with get_sensor / list_sensors).
    """
    _require_write()
    params = {"id": object_id}
    if preview := _confirm("scan_now", {"endpoint": "scannow.htm", **params}, f"Scan object {object_id} now.", confirm):
        return preview
    return await _act("scan_now", "scannow.htm", params)


_TAG_RE = re.compile(r"^[^\s,]+$")


def _check_tags(tags: list[str] | None, what: str) -> list[str]:
    for tag in tags or ():
        if not _TAG_RE.match(tag):
            raise ValueError(f"{what}: {tag!r} is not a valid PRTG tag (no spaces or commas).")
    return list(dict.fromkeys(tags or ()))


def _interval(seconds: int) -> str:
    """PRTG's scanning-interval value: '<seconds>|<label>', e.g. '60|60 seconds', '300|5 minutes', '3600|1 hour'."""
    if seconds <= 60 or seconds % 60:
        return f"{seconds}|{seconds} seconds"
    if seconds < 3600 or seconds % 3600:
        minutes = seconds // 60
        return f"{seconds}|{minutes} minute{'s' if minutes != 1 else ''}"
    hours = seconds // 3600
    return f"{seconds}|{hours} hour{'s' if hours != 1 else ''}"


@mcp.tool()
async def rename_object(
    object_id: Annotated[int, Field(description="Object id of the group, device, sensor (or map, report, notification template, ...).", ge=1)],
    name: Annotated[str, Field(description="The new name.", min_length=1, max_length=255)],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Rename an object (WRITE — requires PRTG_ALLOW_WRITE). GETs /api/rename.htm?id=&value=."""
    _require_write()
    name = name.strip()
    if not name:
        raise ValueError("name must not be blank.")
    params = {"id": object_id, "value": name}
    if preview := _confirm("rename_object", {"endpoint": "rename.htm", **params}, f"Rename object {object_id} to '{name}'.", confirm):
        return preview
    return await _act("rename_object", "rename.htm", params, redirect_ok=True)


@mcp.tool()
async def update_object(
    object_id: Annotated[int, Field(description="Object id of the probe, group, device or sensor.", ge=1)],
    tags: Annotated[list[str] | None, Field(description="Replace the object's own tags with exactly these (no spaces/commas in a tag). [] clears them.")] = None,
    add_tags: Annotated[list[str] | None, Field(description="Tags to add to the object's own tags (keeps the others).")] = None,
    remove_tags: Annotated[list[str] | None, Field(description="Tags to remove from the object's own tags.")] = None,
    priority: Annotated[int | None, Field(description="Priority 1 (lowest) to 5 (highest).", ge=1, le=5)] = None,
    comments: Annotated[str | None, Field(description="Replace the object's comments field ('' clears it).", max_length=10000)] = None,
    location: Annotated[str | None, Field(description="Location (group/device), e.g. an address shown on geo maps.", max_length=255)] = None,
    host: Annotated[str | None, Field(description="Device only: new IPv4 address or DNS name.", min_length=1, max_length=255)] = None,
    interval_seconds: Annotated[int | None, Field(description="Scanning interval in seconds (e.g. 60, 300, 3600). Also switches off 'inherit interval' on the object.", ge=1, le=86400)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change an object's tags, priority, comments, location, host or scanning interval (WRITE — requires PRTG_ALLOW_WRITE).

    One GET per field: /api/setobjectproperty.htm?id=&name=&value= (priority via /api/setpriority.htm).
    add_tags/remove_tags read the object's own tags first (inherited tags are left alone). A new
    interval also sets intervalgroup_=0 so the object stops inheriting its parent's interval.
    """
    _require_write()
    if tags is not None and (add_tags or remove_tags):
        raise ValueError("Give tags (replace all) or add_tags/remove_tags, not both.")
    tags = _check_tags(tags, "tags") if tags is not None else None
    add = _check_tags(add_tags, "add_tags")
    remove = set(_check_tags(remove_tags, "remove_tags"))
    steps: list[dict[str, Any]] = []
    if add or remove:
        current = await _own_tags(object_id)
        tags = [t for t in current if t not in remove] + [t for t in add if t not in current]
    if tags is not None:
        steps.append({"endpoint": "setobjectproperty.htm", "id": object_id, "name": "tags", "value": " ".join(tags)})
    if priority is not None:
        steps.append({"endpoint": "setpriority.htm", "id": object_id, "prio": priority})
    for name, value in (("comments", comments), ("location", location), ("host", host)):
        if value is not None:
            steps.append({"endpoint": "setobjectproperty.htm", "id": object_id, "name": name, "value": value})
    if interval_seconds is not None:
        steps.append({"endpoint": "setobjectproperty.htm", "id": object_id, "name": "intervalgroup_", "value": 0})
        steps.append({"endpoint": "setobjectproperty.htm", "id": object_id, "name": "interval", "value": _interval(interval_seconds)})
    if not steps:
        raise ValueError("Nothing to update: give tags, add_tags/remove_tags, priority, comments, location, host or interval_seconds.")
    fields = [str(st.get("name", "priority")) for st in steps if st.get("name") != "intervalgroup_"]
    summary = f"Update object {object_id}: {', '.join(fields)}."
    if tags is not None:
        summary += f" Tags become: {' '.join(tags) or '(none)'}."
    if preview := _confirm("update_object", {"object_id": object_id, "steps": steps}, summary, confirm):
        return preview
    return await _run_steps("update_object", steps)


@mcp.tool()
async def set_channel_limits(
    sensor_id: Annotated[int, Field(description="Object id of the sensor.", ge=1)],
    channel_id: Annotated[int, Field(description="The channel's id within the sensor (see list_channels 'objid').", ge=0)],
    upper_error: Annotated[float | None, Field(description="Upper error limit (limitmaxerror).")] = None,
    upper_warning: Annotated[float | None, Field(description="Upper warning limit (limitmaxwarning).")] = None,
    lower_warning: Annotated[float | None, Field(description="Lower warning limit (limitminwarning).")] = None,
    lower_error: Annotated[float | None, Field(description="Lower error limit (limitminerror).")] = None,
    error_message: Annotated[str | None, Field(description="Message shown when an error limit is breached.", max_length=255)] = None,
    warning_message: Annotated[str | None, Field(description="Message shown when a warning limit is breached.", max_length=255)] = None,
    enabled: Annotated[bool | None, Field(description="Switch limit checking on (true) or off (false). Omit to leave it as is.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Set a sensor channel's warning/error limits (WRITE — requires PRTG_ALLOW_WRITE).

    One GET per value: /api/setobjectproperty.htm?id=<sensor>&subtype=channel&subid=<channel>&name=&value=.
    Limits are written before limitmode, because PRTG only enables limits once at least one is set.
    Values are in the channel's display unit.
    """
    _require_write()
    base = {"endpoint": "setobjectproperty.htm", "id": sensor_id, "subtype": "channel", "subid": channel_id}
    steps: list[dict[str, Any]] = []
    for name, value in (("limitmaxerror", upper_error), ("limitmaxwarning", upper_warning),
                        ("limitminwarning", lower_warning), ("limitminerror", lower_error)):
        if value is not None:
            steps.append({**base, "name": name, "value": f"{value:g}"})
    for name, value in (("limiterrormsg", error_message), ("limitwarningmsg", warning_message)):
        if value is not None:
            steps.append({**base, "name": name, "value": value})
    if enabled is not None:
        steps.append({**base, "name": "limitmode", "value": 1 if enabled else 0})
    if not steps:
        raise ValueError("Nothing to set: give at least one limit, message or enabled.")
    summary = f"Set limits on sensor {sensor_id} channel {channel_id}: " + ", ".join(f"{st['name']}={st['value']}" for st in steps) + "."
    if preview := _confirm("set_channel_limits", {"steps": steps}, summary, confirm):
        return preview
    return await _run_steps("set_channel_limits", steps)


@mcp.tool()
async def clone_object(
    object_id: Annotated[int, Field(description="Object id of the group, device or sensor to clone.", ge=1)],
    name: Annotated[str, Field(description="Name of the copy.", min_length=1, max_length=255)],
    target_id: Annotated[int, Field(description="Where the copy goes: a group/probe for a group or device, a device for a sensor.", ge=0)],
    host: Annotated[str | None, Field(description="Device only: IPv4 address or DNS name of the copy (else it keeps the source's host).", min_length=1, max_length=255)] = None,
    resume: Annotated[bool, Field(description="Resume the copy right away. PRTG creates clones paused.")] = False,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Clone a group, device or sensor (WRITE — requires PRTG_ALLOW_WRITE). GETs /api/duplicateobject.htm.

    This is PRTG's supported way to add monitoring: clone a well-configured device (with all its
    sensors) and give it a new host. The copy starts paused; resume=true (or resume_object) starts it.
    Returns the new object's id.
    """
    _require_write()
    params: dict[str, Any] = {"id": object_id, "name": name.strip(), "targetid": target_id}
    if host is not None:
        params["host"] = host.strip()
    how = f"into {target_id}" + (f" with host {params['host']}" if host else "") + (" and resume it" if resume else " (stays paused)")
    if preview := _confirm("clone_object", {"endpoint": "duplicateobject.htm", "resume": resume, **params},
                           f"Clone object {object_id} as '{params['name']}' {how}.", confirm):
        return preview
    out = await _act("clone_object", "duplicateobject.htm", params, redirect_ok=True)
    new_id = _new_id(out.get("location"))
    location = (out.get("location") or "").lower()
    if new_id is None or "duplicateobject" in location or "not valid" in location:
        raise PrtgError(
            f"PRTG answered the clone with {out.get('location')!r} instead of the new object's page; check "
            f"under {target_id} whether '{params['name']}' was created."
        )
    out["new_id"] = new_id
    if resume:
        await _get_client().action("pause.htm", params={"id": new_id, "action": 1})
    out["paused"] = not resume
    return out


@mcp.tool()
async def move_object(
    object_id: Annotated[int, Field(description="Object id of the group or device (move) or any object (position).", ge=1)],
    target_id: Annotated[int | None, Field(description="New parent group or probe for a group/device.", ge=0)] = None,
    position: Annotated[str | None, Field(description="Reorder among its siblings: 'up', 'down', 'top' or 'bottom'.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Move a group/device to another parent and/or reorder it (WRITE — requires PRTG_ALLOW_WRITE).

    target_id GETs /moveobjectnow.htm?id=&targetid= (undocumented by Paessler but what PRTG's own
    UI and PrtgAPI use; sensors can't be moved, clone them instead). position GETs
    /api/setposition.htm?id=&newpos=.
    """
    _require_write()
    if target_id is None and position is None:
        raise ValueError("Give target_id (new parent) and/or position (up, down, top, bottom).")
    if position is not None and position not in ("up", "down", "top", "bottom"):
        raise ValueError("position must be one of: up, down, top, bottom.")
    change: dict[str, Any] = {"object_id": object_id, "target_id": target_id, "position": position}
    parts = ([f"move it under {target_id}"] if target_id is not None else []) + ([f"move it {position}"] if position else [])
    if preview := _confirm("move_object", change, f"Object {object_id}: {' and '.join(parts)}.", confirm):
        return preview
    out: dict[str, Any] = {"ok": True, "tool": "move_object", "object_id": object_id}
    if target_id is not None:
        out["move"] = await _get_client().action(
            "moveobjectnow.htm", params={"id": object_id, "targetid": target_id}, root=True, redirect_ok=True
        )
    if position is not None:
        out["position"] = await _get_client().action(
            "setposition.htm", params={"id": object_id, "newpos": position}, redirect_ok=True
        )
    return out


async def _child_ids(content: str, parent_id: int, name: str) -> set[int]:
    data = await _get_client().get(
        "table.json",
        params={"content": content, "columns": "objid,name", "count": 5000, "output": "json",
                "filter_parentid": parent_id, "filter_name": f"@sub({name})"},
    )
    rows = data.get(content, []) if isinstance(data, dict) else []
    return {int(r["objid"]) for r in rows if isinstance(r, dict) and r.get("name") == name and r.get("objid") is not None}


async def _add(tool: str, endpoint: str, content: str, parent_id: int, name: str, params: dict[str, Any]) -> dict[str, Any]:
    before = await _child_ids(content, parent_id, name)
    out = await _act(tool, endpoint, params, root=True, redirect_ok=True)
    created = sorted((await _child_ids(content, parent_id, name)) - before)
    if created:
        out["new_id"] = created[-1]
    else:
        out["note"] = f"PRTG accepted the request but no new {content[:-1]} named '{name}' showed up under {parent_id} yet; check with list_{content}."
    return out


@mcp.tool()
async def add_group(
    parent_id: Annotated[int, Field(description="The probe or group to create the group in.", ge=0)],
    name: Annotated[str, Field(description="Group name.", min_length=1, max_length=255)],
    tags: Annotated[list[str] | None, Field(description="Tags for the group (no spaces/commas in a tag).")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create an empty group (WRITE — requires PRTG_ALLOW_WRITE). GETs /addgroup2.htm?id=&name_=&tags_=.

    Undocumented by Paessler (it is what PRTG's add-group form and PrtgAPI use); Paessler recommends
    clone_object where possible. Returns the new group's id, found by name under the parent.
    """
    _require_write()
    name = name.strip()
    params: dict[str, Any] = {"id": parent_id, "name_": name}
    if tags:
        params["tags_"] = " ".join(_check_tags(tags, "tags"))
    if preview := _confirm("add_group", {"endpoint": "addgroup2.htm", **params}, f"Create group '{name}' under {parent_id}.", confirm):
        return preview
    return await _add("add_group", "addgroup2.htm", "groups", parent_id, name, params)


_DISCOVERY = {"none": 0, "standard": 1, "detailed": 3}


@mcp.tool()
async def add_device(
    group_id: Annotated[int, Field(description="The group or probe to create the device in.", ge=0)],
    name: Annotated[str, Field(description="Device name.", min_length=1, max_length=255)],
    host: Annotated[str, Field(description="IP address or DNS name of the device.", min_length=1, max_length=255)],
    ipv6: Annotated[bool, Field(description="host is an IPv6 address / name.")] = False,
    tags: Annotated[list[str] | None, Field(description="Tags for the device (no spaces/commas in a tag).")] = None,
    discovery: Annotated[str, Field(description="Auto-discovery: 'none' (empty device, add sensors yourself), 'standard' or 'detailed' (PRTG creates sensors it finds).")] = "none",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a device (WRITE — requires PRTG_ALLOW_WRITE). GETs /adddevice2.htm?id=&name_=&host_=&ipversion_=&discoverytype_=.

    Undocumented by Paessler (it is what PRTG's add-device form and PrtgAPI use). To get a device
    with sensors already set up, prefer clone_object from a template device. Returns the new id.
    """
    _require_write()
    if discovery not in _DISCOVERY:
        raise ValueError("discovery must be one of: none, standard, detailed.")
    name = name.strip()
    params: dict[str, Any] = {
        "id": group_id, "name_": name, ("hostv6_" if ipv6 else "host_"): host.strip(), "ipversion_": 1 if ipv6 else 0,
        "discoverytype_": _DISCOVERY[discovery], "discoveryschedule_": 0,
    }
    if tags:
        params["tags_"] = " ".join(_check_tags(tags, "tags"))
    summary = f"Create device '{name}' ({host.strip()}) under {group_id}, auto-discovery {discovery}."
    if preview := _confirm("add_device", {"endpoint": "adddevice2.htm", **params}, summary, confirm):
        return preview
    return await _add("add_device", "adddevice2.htm", "devices", group_id, name, params)


@mcp.tool()
async def discover_now(
    object_id: Annotated[int, Field(description="Object id of the group or device to run auto-discovery on.", ge=1)],
    templates: Annotated[list[str] | None, Field(description="Device template file names, e.g. ['Linux SNMP.odt']. Omit to use the object's own discovery settings.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Run auto-discovery now (WRITE — requires PRTG_ALLOW_WRITE). GETs /api/discovernow.htm?id=[&template=].

    PRTG may add sensors (and, on a group, devices). If the object was set to 'No auto-discovery',
    PRTG switches it to 'Standard auto-discovery'.
    """
    _require_write()
    params: dict[str, Any] = {"id": object_id}
    if templates:
        params["template"] = ",".join(f'"{t.strip()}"' for t in templates if t.strip())
    what = f" with template(s) {params['template']}" if templates else ""
    if preview := _confirm("discover_now", {"endpoint": "discovernow.htm", **params}, f"Run auto-discovery on object {object_id}{what}.", confirm):
        return preview
    return await _act("discover_now", "discovernow.htm", params)


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
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
