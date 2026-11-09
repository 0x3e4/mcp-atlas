"""MCP server exposing NetScaler ADC (NITRO) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Curated read tools cover the common questions; the raw ``nitro_get`` escape
hatch reaches anything else.

Load balancing and content switching: get_object shows one LB/CS vserver, service, group, server,
CS policy/action or monitor with everything bound to it (a CS vserver's policies in priority order
with their targets); add_object / update_object / set_object_state / change_bindings create, change,
enable/disable and bind them (table in ``lb.py``). delete_object removes them; it needs
``NETSCALER_ALLOW_DELETE`` on top and always asks for confirmation.

WAF (AppFw) rollout tools list learned rules, the URL inventory and configured rules, and export
profiles as portable JSON (reads). Their write tools — add/remove rules, deploy/discard learned rules,
set check actions, import/rehost profiles, save config — are **opt-in**: they preview by default
(``dry_run=true``) and refuse to apply unless ``NETSCALER_ALLOW_WRITE=true``. With the flag off the
server is effectively read-only. Unless ``NETSCALER_CONFIRM_WRITE=false``, every preview also carries a
confirm code, and a write only applies when called again with that code, after the user has confirmed.
The regex/host/plan logic lives in ``waf.py``.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import hmac
import inspect
import json
import re
import secrets
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field, validate_call

from . import __version__, bot, lb, waf
from .client import NitroClient, NitroError
from .config import DEFAULT_INSTANCE, ConfigError, load_instances

mcp = MCPServer(
    "netscaler-mcp",
    instructions=(
        "Write tools (add_*/remove_*/update_object/change_bindings/delete_object/deploy_*/discard_*/set_*/"
        "import_*/rehost_*/update_signatures/save_config) need the user's confirmation: a preview (dry_run=true, or a first dry_run=false call) "
        "changes nothing and returns a confirm_code. Show the user a short overview of what will change, "
        "end with 'Confirm it?', and only after they say yes repeat the call with dry_run=false and "
        "confirm=<code>. When the user wants more than one change, put them all into one apply_batch call "
        "(optionally save=true) so they get one overview and one confirmation. Several NetScaler appliances may be configured (list_instances): every tool takes "
        "instance=<name>; read tools also accept instance='all' to run on each one, and compare_instances "
        "diffs configuration (e.g. GSLB) between them. Writes go to one named instance at a time."
    ),
    version=__version__,
)

# Lazily-built clients, one per configured appliance, so the module imports without credentials (tests).
_clients: dict[str, NitroClient] = {}
_default_instance = DEFAULT_INSTANCE
# The instance the running tool call targets; set by _tool for the duration of one call.
_instance: ContextVar[str | None] = ContextVar("netscaler_instance", default=None)
_ALL_INSTANCES = ("all", "*")


def _load_clients() -> dict[str, NitroClient]:
    global _clients, _default_instance
    if not _clients:
        settings, _default_instance = load_instances()
        _clients = {name: NitroClient(s) for name, s in settings.items()}
    return _clients


def _get_client() -> NitroClient:
    """The client for the instance the current tool call targets (the default one outside a call)."""
    return _load_clients()[_instance.get() or _default_instance]


def _resolve_instance(instance: str | None, *, write: bool) -> str:
    """Validate a tool's ``instance`` argument; omitted means the caller's instance, else the default."""
    clients = _load_clients()
    name = (instance or "").strip().lower()
    if not name:
        current = _instance.get()
        if current:
            return current
        if write and len(clients) > 1:
            raise ValueError(
                f"Several NetScaler instances are configured ({', '.join(clients)}): write tools need an "
                "explicit instance=<name>."
            )
        return _default_instance
    if name not in clients:
        raise ValueError(f"Unknown NetScaler instance {instance!r}; configured: {', '.join(clients)}.")
    return name


_READ_INSTANCE_DESC = (
    "NetScaler instance to query (names from list_instances); omit for the default one. 'all' runs this "
    "read on every configured instance and returns the results keyed by instance."
)
_WRITE_INSTANCE_DESC = (
    "NetScaler instance to change (names from list_instances). Required when several are configured; "
    "a write always goes to exactly one instance."
)


async def _on_each(call: Any, names: list[str] | None = None) -> dict[str, Any]:
    """Run ``call()`` once per instance, concurrently; a failing instance reports its error instead."""
    async def one(name: str) -> tuple[str, Any]:
        token = _instance.set(name)
        try:
            return name, await call()
        except (NitroError, ValueError) as exc:
            return name, {"error": str(exc)}
        finally:
            _instance.reset(token)

    results = await asyncio.gather(*(one(n) for n in names or list(_load_clients())))
    return dict(results)


def _tool(fn: Any) -> Any:
    """``@mcp.tool()`` plus an ``instance`` parameter that picks the appliance for this call.

    Read tools also accept ``instance='all'`` (results keyed by instance); write tools — those taking a
    ``confirm`` code — refuse it and, with several instances configured, need the instance named.
    """
    sig = inspect.signature(fn, eval_str=True)
    write = "confirm" in sig.parameters

    @functools.wraps(fn)
    async def wrapper(*args: Any, instance: str | None = None, **kwargs: Any) -> Any:
        if (instance or "").strip().lower() in _ALL_INSTANCES:
            if write:
                raise ValueError("instance='all' is for reads; a write goes to one named instance at a time.")
            return {"instances": await _on_each(lambda: fn(*args, **kwargs))}
        if write and not instance and kwargs.get("instances"):
            instance = kwargs["instances"][0]  # apply_batch / clone_app_setup over several instances
        token = _instance.set(_resolve_instance(instance, write=write))
        try:
            return await fn(*args, **kwargs)
        finally:
            _instance.reset(token)

    param = inspect.Parameter(
        "instance",
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=Annotated[
            str | None, Field(description=_WRITE_INSTANCE_DESC if write else _READ_INSTANCE_DESC)
        ],
    )
    wrapper.__signature__ = sig.replace(parameters=[*sig.parameters.values(), param])
    mcp.tool()(wrapper)
    if write:
        # apply_batch calls write tools as steps, with the same argument validation the MCP call gets.
        _WRITE_TOOLS[fn.__name__] = validate_call(fn)
    return wrapper


# Write tools by name (unwrapped, argument-validated): the steps apply_batch may run.
_WRITE_TOOLS: dict[str, Any] = {}
# Write tools that delete: they always need a confirmation, even with NETSCALER_CONFIRM_WRITE=false.
_DELETE_TOOLS = {"delete_object"}


def _instance_note() -> dict[str, str]:
    """``{"instance": name}`` for results that should say which appliance they touch (multi-instance only)."""
    return {"instance": _instance.get() or _default_instance} if len(_load_clients()) > 1 else {}


def _require_delete() -> None:
    """Deletes need NETSCALER_ALLOW_DELETE on top of NETSCALER_ALLOW_WRITE."""
    _require_write()
    if not _get_client().settings.allow_delete:
        raise ValueError(
            "Delete tools are disabled. Set NETSCALER_ALLOW_DELETE=true (in addition to "
            "NETSCALER_ALLOW_WRITE=true) to delete objects. dry_run=true previews still work."
        )


def _require_write() -> None:
    """Gate write tools behind the opt-in NETSCALER_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set NETSCALER_ALLOW_WRITE=true (and use a system user whose "
            "command policy allows these changes, see the README) to apply changes. dry_run=true previews still work."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)
# Set by apply_batch around its steps: {"record": [...]} collects each step's plan during the preview
# pass; {"approved": [...]} then lets exactly those plans through, once each, without asking again.
_batch: ContextVar[dict[str, list[str]] | None] = ContextVar("netscaler_batch", default=None)


def _confirm(
    tool: str, change: dict[str, Any], summary: str, code: str | None, *, always: bool = False
) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when NETSCALER_CONFIRM_WRITE=false (unless ``always``: deletes), or when
    ``code`` matches this exact tool + change on this instance (so what runs is what the user saw, where
    they saw it). Inside an apply_batch, a step runs when its plan is one the user confirmed with the batch.
    """
    if not always and not _get_client().settings.confirm_write:
        return None
    instance = _instance.get() or _default_instance
    entry = json.dumps([tool, instance, change], sort_keys=True, default=str)
    batch = _batch.get()
    if batch is not None:
        if "record" in batch:
            batch["record"].append(entry)
        elif entry in batch["approved"]:
            batch["approved"].remove(entry)
            return None
    raw = entry.encode()
    expected = hmac.new(_CONFIRM_KEY, raw, hashlib.sha256).hexdigest()[:12]
    if code and hmac.compare_digest(code.strip(), expected):
        return None
    out: dict[str, Any] = {
        "status": "confirmation_required",
        "changed": False,
        **_instance_note(),
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


def _call_args(params: dict[str, Any]) -> dict[str, Any]:
    """A write tool's own arguments (from ``locals()`` at the top of the tool) minus dry_run/confirm."""
    return {k: v for k, v in params.items() if k not in ("dry_run", "confirm")}


def _gate(
    tool: str,
    change: dict[str, Any],
    summary: str,
    preview: dict[str, Any],
    *,
    dry_run: bool,
    confirm: str | None,
    writes: bool = True,
    always: bool = False,
) -> bool:
    """Decide whether a previewing (dry_run) write tool applies now; True means go ahead.

    ``change`` is the tool's arguments plus the plan computed against the live appliance, so a changed
    live state needs a new preview. Otherwise ``preview`` (built in "would ..." form) becomes the answer:
    dry_run=true stays a pure preview, and with NETSCALER_CONFIRM_WRITE on it carries the confirm_code;
    dry_run=false without the matching code answers the same way and applies nothing. A plan without
    writes needs no confirmation.
    """
    if not writes:
        return not dry_run
    pending = _confirm(tool, change, summary, None if dry_run else confirm, always=always)
    if pending is None:
        return not dry_run
    code = pending["confirm_code"]
    # deploy/discard already use "summary" for their status tally
    preview["change_summary" if "summary" in preview else "summary"] = summary
    preview.update(
        _instance_note(),
        dry_run=True,
        status=pending["status"],
        confirm_code=code,
        next=(
            "Show the user a short overview of this plan and end with 'Confirm it?'. Only after they "
            f"confirm, call {tool} again with the same arguments, dry_run=false and confirm='{code}'."
        ),
    )
    if "note" in pending:
        preview["note"] = pending["note"]
    return False


_EXPORT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,150}\.json")


def _export_path(name: str) -> Path:
    """Resolve a bare file name inside NETSCALER_EXPORT_DIR (no directories, so nothing escapes it)."""
    base = _get_client().settings.export_dir
    if not base:
        raise ValueError(
            "File export/import is off: set NETSCALER_EXPORT_DIR (and mount a volume there), or pass "
            "the document inline instead."
        )
    name = (name or "").strip()
    if not name.endswith(".json"):
        name += ".json"
    if not _EXPORT_NAME.fullmatch(name) or ".." in name:
        raise ValueError(
            f"file must be a bare name like 'pr_app-dev.json' (letters, digits, '.', '_', '-'); got {name!r}."
        )
    return Path(base) / name


# ---- curated field projections (the useful columns per resource) --------
_LBVSERVER_FIELDS = (
    "name", "ipv46", "port", "servicetype", "curstate", "effectivestate", "lbmethod",
    "persistencetype",
)
_CSVSERVER_FIELDS = ("name", "ipv46", "port", "servicetype", "curstate", "targettype")
_GSLBVSERVER_FIELDS = ("name", "servicetype", "curstate", "iptype", "persistencetype")
_SERVICE_FIELDS = ("name", "ip", "servername", "port", "servicetype", "svrstate")
_SERVICEGROUP_FIELDS = ("servicegroupname", "servicetype", "state")
_SERVER_FIELDS = ("name", "ipaddress", "state", "domain")
_CERT_FIELDS = (
    "certkey", "subject", "issuer", "status", "daystoexpiration", "clientcertnotbefore",
    "clientcertnotafter",
)
_HANODE_FIELDS = ("id", "name", "ipaddress", "state", "hastatus", "hasync", "masterstate")
_NS_STAT_FIELDS = (
    "cpuusagepcnt", "mgmtcpuusagepcnt", "memusagepcnt", "memuseinmb", "starttime",
    "disk0perusage", "disk1perusage", "numcpus",
)
_LBVSERVER_STAT_FIELDS = (
    "name", "state", "vslbhealth", "totalrequests", "totalresponses", "curclntconnections",
    "cursrvrconnections", "requestbytesrate", "hitsrate",
)
_CSVSERVER_STAT_FIELDS = (
    "name", "state", "totalrequests", "totalresponses", "curclntconnections", "cursrvrconnections",
)
_GSLBVSERVER_STAT_FIELDS = (
    "name", "state", "vsvrhealth", "totalrequests", "totalresponses", "establishedconn",
)

# GSLB (config)
_GSLBSERVICE_FIELDS = ("servicename", "servicetype", "ipaddress", "port", "sitename", "state")
_GSLBSITE_FIELDS = ("sitename", "sitetype", "siteipaddress", "publicip", "metricexchange")

# DNS (config) — record_type -> (resourcetype, projected fields)
_DNS_RECORD_TYPES = {
    "A": ("dnsaddrec", ("hostname", "ipaddress", "ttl")),
    "AAAA": ("dnsaaaarec", ("hostname", "ipv6address", "ttl")),
    "CNAME": ("dnscnamerec", ("aliasname", "canonicalname", "ttl")),
    "NS": ("dnsnsrec", ("domain", "nameserver", "ttl")),
    "SOA": ("dnssoarec", ("domain", "originserver", "contact", "ttl")),
    "MX": ("dnsmxrec", ("domain", "mx", "pref", "ttl")),
    "TXT": ("dnstxtrec", ("domain", "string", "ttl")),
    "SRV": ("dnssrvrec", ("domain", "target", "priority", "weight", "port", "ttl")),
    "PTR": ("dnsptrrec", ("reversedomain", "domain", "ttl")),
}
_DNSZONE_FIELDS = ("zonename", "proxymode", "type", "dnssecoffload")
_DNSNAMESERVER_FIELDS = ("ip", "type", "state", "local")

# Application Firewall (WAF) + Bot management (config / stat)
_APPFWPROFILE_FIELDS = ("name", "type", "starturlaction", "sqlinjectionaction", "crosssitescriptingaction")
_APPFWPOLICY_FIELDS = ("name", "rule", "profilename")
_APPFWPOLICY_STAT_FIELDS = ("name", "pipolicyhits")
_BOTPROFILE_FIELDS = ("name", "signaturemultipleuseragentheaderaction", "errorurl")
_BOTPOLICY_FIELDS = ("name", "rule", "profilename")
_BOTPOLICY_STAT_FIELDS = ("name", "pipolicyhits")


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 500) -> int:
    """Bound a caller-supplied limit so a tool can't flood the agent's context."""
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Project a dict down to ``fields`` (supports dotted paths like ``a.b.c``)."""
    out: dict[str, Any] = {}
    for field in fields:
        cur: Any = obj
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        out[field] = cur
    return out


def _csv(value: str | None) -> tuple[str, ...] | None:
    """Split a comma string into a tuple (for caller-supplied attribute lists)."""
    if not value:
        return None
    return tuple(v.strip() for v in value.split(",") if v.strip())


def _one(env: dict[str, Any], key: str) -> dict[str, Any]:
    """Return a single resource object whether NITRO returned a dict or a 1-element list."""
    val = env.get(key)
    if isinstance(val, list):
        return val[0] if val else {}
    return val or {}


async def _get_list(
    tree: str,
    resourcetype: str,
    fields: tuple[str, ...],
    *,
    name: str | None = None,
    limit: int = 50,
    full: bool = False,
    key: str | None = None,
) -> dict[str, Any]:
    """Fetch a NITRO collection, project to ``fields`` (unless ``full``), and cap to ``limit``."""
    key = key or resourcetype
    client = _get_client()
    # ``attrs`` is reliable on the config tree; for stats we project client-side instead.
    send_attrs = (not full) and tree == "config"
    kwargs: dict[str, Any] = {"resource_name": name, "attrs": fields if send_attrs else None}
    if name is None and tree == "config":
        kwargs["pagesize"] = _clamp(limit)
        kwargs["pageno"] = 1
    env = await client.get(tree, resourcetype, **kwargs)
    rows = env.get(key) or []
    if not isinstance(rows, list):
        rows = [rows]
    rows = rows[: _clamp(limit)]
    if not full:
        rows = [_pick(r, fields) for r in rows]
    return {"count": len(rows), key: rows}


# ---- tools: configuration -----------------------------------------------

@_tool
async def list_lb_vservers(
    name: Annotated[str | None, Field(description="Exact LB vserver name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max vservers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List load-balancing virtual servers and their state (config tree, lbvserver).

    'curstate' is the configured/admin state; 'effectivestate' reflects the health of bound services
    (e.g. DOWN when no service is UP). Use vserver_stats(kind='lb') for live traffic counters.
    """
    return await _get_list("config", "lbvserver", _LBVSERVER_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_cs_vservers(
    name: Annotated[str | None, Field(description="Exact CS vserver name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max vservers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List content-switching virtual servers and their state (config tree, csvserver)."""
    return await _get_list("config", "csvserver", _CSVSERVER_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_gslb_vservers(
    name: Annotated[str | None, Field(description="Exact GSLB vserver name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max vservers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List GSLB virtual servers and their state (config tree, gslbvserver).

    Requires the GSLB feature to be enabled; otherwise NITRO returns a clean 'feature not enabled' error.
    """
    return await _get_list("config", "gslbvserver", _GSLBVSERVER_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_services(
    name: Annotated[str | None, Field(description="Exact service/servicegroup name to fetch one; omit to list all.")] = None,
    servicegroup: Annotated[bool, Field(description="List service GROUPS (servicegroup) instead of individual services.")] = False,
    limit: Annotated[int, Field(description="Max entries to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List backend services or service groups and their state (config tree).

    Individual services (service) by default; pass servicegroup=true for service groups.
    'svrstate' (services) / 'state' (groups) shows UP/DOWN.
    """
    if servicegroup:
        return await _get_list(
            "config", "servicegroup", _SERVICEGROUP_FIELDS, name=name, limit=limit, full=full
        )
    return await _get_list("config", "service", _SERVICE_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_servers(
    name: Annotated[str | None, Field(description="Exact server name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max servers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List backend server objects (config tree, server) — name, IP/domain and enabled state."""
    return await _get_list("config", "server", _SERVER_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_certificates(
    expiring_within_days: Annotated[
        int | None,
        Field(description="Only return certs expiring within this many days (client-side filter on daystoexpiration).", ge=0),
    ] = None,
    limit: Annotated[int, Field(description="Max certificates to return.", ge=1, le=1000)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List SSL certificate-key pairs and their expiry (config tree, sslcertkey).

    'daystoexpiration' counts down to expiry. Pass expiring_within_days to surface soon-to-expire
    certs. Results are sorted soonest-expiry first; certs whose expiry can't be determined sort last.
    """
    env = await _get_client().get("config", "sslcertkey", attrs=None if full else _CERT_FIELDS)
    rows = env.get("sslcertkey") or []
    if not isinstance(rows, list):
        rows = [rows]

    def _days(cert: dict[str, Any]) -> int | None:
        try:
            return int(cert.get("daystoexpiration"))
        except (TypeError, ValueError):
            return None

    if expiring_within_days is not None:
        rows = [c for c in rows if (_days(c) is not None and _days(c) <= expiring_within_days)]
    rows.sort(key=lambda c: (_days(c) is None, _days(c) if _days(c) is not None else 0))
    rows = rows[: _clamp(limit, default=100, maximum=1000)]
    if not full:
        rows = [_pick(c, _CERT_FIELDS) for c in rows]
    return {"count": len(rows), "sslcertkey": rows}


@_tool
async def ha_status(
    full: Annotated[bool, Field(description="Return full hanode objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Show High Availability node status for the pair (config tree, hanode).

    Returns every node the appliance knows about (itself + peer), so it always reflects the whole
    pair regardless of which node you pointed at. 'masterstate' indicates PRIMARY/SECONDARY and
    'hasync' the sync state.
    """
    return await _get_list("config", "hanode", _HANODE_FIELDS, full=full)


@_tool
async def system_health(
    full: Annotated[bool, Field(description="Return the full stats object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Show appliance CPU, management-CPU, memory, disk usage and uptime (stat tree, ns)."""
    env = await _get_client().get("stat", "ns")
    ns = _one(env, "ns")
    return ns if full else _pick(ns, _NS_STAT_FIELDS)


@_tool
async def vserver_stats(
    kind: Annotated[str, Field(description="Which vserver type: 'lb', 'cs' or 'gslb'.")] = "lb",
    name: Annotated[str | None, Field(description="Exact vserver name; omit for all of that kind.")] = None,
    limit: Annotated[int, Field(description="Max vservers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full stat objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live traffic and health statistics for LB, CS or GSLB virtual servers (stat tree).

    kind='lb' → lbvserver stats (vslbhealth, request/response counts, connections, rates);
    kind='cs' → csvserver stats; kind='gslb' → gslbvserver stats (vsvrhealth, request/response
    counts). Use the matching list_*_vservers tools for configuration.
    """
    stat_kinds = {
        "lb": ("lbvserver", _LBVSERVER_STAT_FIELDS),
        "cs": ("csvserver", _CSVSERVER_STAT_FIELDS),
        "gslb": ("gslbvserver", _GSLBVSERVER_STAT_FIELDS),
    }
    if kind not in stat_kinds:
        raise ValueError("kind must be 'lb', 'cs', or 'gslb'.")
    resourcetype, fields = stat_kinds[kind]
    return await _get_list("stat", resourcetype, fields, name=name, limit=limit, full=full)


@_tool
async def system_info(
    full: Annotated[bool, Field(description="Return full objects for each section instead of a summary.")] = False,
) -> dict[str, Any]:
    """Appliance fingerprint: NetScaler version, hardware, license and HA node summary.

    Merges several read-only config resources into one overview; each section is fetched
    independently so a missing/feature-gated one doesn't fail the whole call.
    """
    client = _get_client()
    out: dict[str, Any] = {}
    for section, resourcetype in (("version", "nsversion"), ("hardware", "nshardware"), ("license", "nslicense")):
        try:
            env = await client.get("config", resourcetype)
            out[section] = _one(env, resourcetype)
        except NitroError as exc:
            out[section] = {"error": str(exc)}
    try:
        env = await client.get("config", "hanode", attrs=None if full else _HANODE_FIELDS)
        nodes = env.get("hanode") or []
        if not isinstance(nodes, list):
            nodes = [nodes]
        out["ha_nodes"] = nodes if full else [_pick(n, _HANODE_FIELDS) for n in nodes]
    except NitroError as exc:
        out["ha_nodes"] = {"error": str(exc)}
    return out


# ---- tools: GSLB --------------------------------------------------------

@_tool
async def list_gslb_services(
    name: Annotated[str | None, Field(description="Exact GSLB service name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max services to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List GSLB services and their state (config tree, gslbservice). Requires the GSLB feature."""
    return await _get_list("config", "gslbservice", _GSLBSERVICE_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_gslb_sites(
    name: Annotated[str | None, Field(description="Exact GSLB site name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max sites to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List GSLB sites (config tree, gslbsite) — LOCAL/REMOTE sites and their IPs. Requires GSLB."""
    return await _get_list("config", "gslbsite", _GSLBSITE_FIELDS, name=name, limit=limit, full=full)


# ---- tools: DNS ---------------------------------------------------------

@_tool
async def list_dns_records(
    record_type: Annotated[str, Field(description="DNS record type: A, AAAA, CNAME, NS, SOA, MX, TXT, SRV or PTR.")] = "A",
    limit: Annotated[int, Field(description="Max records to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List DNS records of a given type from the appliance's DNS config (config tree, dns*rec).

    record_type routes to the matching NITRO resource (A→dnsaddrec, CNAME→dnscnamerec, …).
    """
    key = (record_type or "").strip().upper()
    if key not in _DNS_RECORD_TYPES:
        raise ValueError(f"record_type must be one of {tuple(_DNS_RECORD_TYPES)}; got {record_type!r}.")
    resourcetype, fields = _DNS_RECORD_TYPES[key]
    return await _get_list("config", resourcetype, fields, limit=limit, full=full)


@_tool
async def list_dns_zones(
    name: Annotated[str | None, Field(description="Exact zone name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max zones to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List configured DNS zones (config tree, dnszone)."""
    return await _get_list("config", "dnszone", _DNSZONE_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_dns_nameservers(
    limit: Annotated[int, Field(description="Max name servers to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List configured DNS name servers (config tree, dnsnameserver) and their state."""
    return await _get_list("config", "dnsnameserver", _DNSNAMESERVER_FIELDS, limit=limit, full=full)


# ---- tools: Application Firewall (WAF) ----------------------------------

@_tool
async def list_waf_profiles(
    name: Annotated[str | None, Field(description="Exact AppFW profile name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max profiles to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Application Firewall (WAF) profiles (config tree, appfwprofile). Requires the AppFw feature."""
    return await _get_list("config", "appfwprofile", _APPFWPROFILE_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_waf_policies(
    name: Annotated[str | None, Field(description="Exact AppFW policy name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Application Firewall (WAF) policies and the profile each binds (config tree, appfwpolicy)."""
    return await _get_list("config", "appfwpolicy", _APPFWPOLICY_FIELDS, name=name, limit=limit, full=full)


@_tool
async def waf_stats(
    name: Annotated[str | None, Field(description="Exact AppFW policy name; omit for all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full stat objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live WAF policy hit counters (stat tree, appfwpolicy) — how often each AppFW policy fired."""
    return await _get_list("stat", "appfwpolicy", _APPFWPOLICY_STAT_FIELDS, name=name, limit=limit, full=full)


# ---- tools: Bot management ----------------------------------------------

@_tool
async def list_bot_profiles(
    name: Annotated[str | None, Field(description="Exact bot profile name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max profiles to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Bot management profiles (config tree, botprofile). Requires the Bot feature."""
    return await _get_list("config", "botprofile", _BOTPROFILE_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_bot_policies(
    name: Annotated[str | None, Field(description="Exact bot policy name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Bot management policies and the profile each binds (config tree, botpolicy)."""
    return await _get_list("config", "botpolicy", _BOTPOLICY_FIELDS, name=name, limit=limit, full=full)


@_tool
async def bot_stats(
    name: Annotated[str | None, Field(description="Exact bot policy name; omit for all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full stat objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live Bot policy hit counters (stat tree, botpolicy) — how often each bot policy fired."""
    return await _get_list("stat", "botpolicy", _BOTPOLICY_STAT_FIELDS, name=name, limit=limit, full=full)


# ---- tools: WAF rollout (learned rules, URL inventory, rules, export/import) ----

def _profiles(profile: str) -> list[str]:
    """Split a comma-separated profile list (order kept, duplicates dropped)."""
    names = list(dict.fromkeys(p.strip() for p in (profile or "").split(",") if p.strip()))
    if not names:
        raise ValueError("profile is required.")
    return names


def _rows(env: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = env.get(key) or []
    return rows if isinstance(rows, list) else [rows]


def _matches(row: dict[str, Any], needle: str | None) -> bool:
    """Case-insensitive substring match against any scalar value of a row."""
    if not needle:
        return True
    needle = needle.lower()
    return any(needle in str(v).lower() for v in row.values() if isinstance(v, (str, int)))


def _is_exists(exc: NitroError) -> bool:
    return exc.errorcode in waf.EXISTS_CODES or "already exist" in (exc.nitro_message or "").lower()


def _is_missing(exc: NitroError) -> bool:
    message = (exc.nitro_message or "").lower()
    return exc.errorcode in waf.MISSING_CODES or "no such" in message or "does not exist" in message


def _tally(statuses: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for status in statuses:
        label = "error" if status.startswith("error") else status
        counts[label] = counts.get(label, 0) + 1
    return counts


async def _profile_rules(
    kind: waf.ProfileKind, profile: str
) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """A profile's live bindings split into modelled rule types and other binding arrays."""
    env = await _get_client().get("config", kind.aggregate, resource_name=profile)
    return kind.split_bindings(_one(env, kind.aggregate))


async def _extra_settings(kind: waf.ProfileKind, profile: str) -> dict[str, Any]:
    """The family's second per-profile resource (AppFw learning thresholds); {} when it has none."""
    if kind.extra is None:
        return {}
    try:
        env = await _get_client().get("config", kind.extra.resource, resource_name=profile)
    except NitroError:
        return {}
    return _one(env, kind.extra.resource)


async def _learned_entries(
    profile: str,
    check: str,
    rule: waf.RuleType | None,
    contains: str | None = None,
    min_hits: int | None = None,
) -> list[dict[str, Any]]:
    """Learned entries of one check with hit counts and the rule each deploys as, most hits first."""
    env = await _get_client().get(
        "config", "appfwlearningdata", args={"profilename": profile, "securitycheck": check}
    )
    entries: list[dict[str, Any]] = []
    for raw in _rows(env, "appfwlearningdata"):
        learned = waf.clean_learned(raw)
        hits = waf.as_int(raw.get("hits"))
        if (min_hits is not None and (hits or 0) < min_hits) or not _matches(learned, contains):
            continue
        entry: dict[str, Any] = {"hits": hits, "learned": learned}
        if rule is not None:
            entry["rule"] = waf.learned_rule(rule, raw)
        entries.append(entry)
    entries.sort(key=lambda e: -(e["hits"] or 0))
    return entries


async def _bind(rule: waf.RuleType, profile: str, row: dict[str, Any]) -> str:
    try:
        await _get_client().update(rule.binding, {"name": profile, **row})
        return "added"
    except NitroError as exc:
        return "exists" if _is_exists(exc) else f"error: {exc}"


async def _unbind(rule: waf.RuleType, profile: str, row: dict[str, Any]) -> str:
    try:
        await _get_client().delete(rule.binding, profile, args=waf.delete_args(rule, row))
        return "removed"
    except NitroError as exc:
        return "absent" if _is_missing(exc) else f"error: {exc}"


async def _forget_learned(rule: waf.RuleType, profile: str, row: dict[str, Any]) -> str:
    try:
        await _get_client().delete(
            "appfwlearningdata", args={"profilename": profile, **waf.learned_delete_args(rule, row)}
        )
        return "removed"
    except NitroError as exc:
        return "absent" if _is_missing(exc) else f"error: {exc}"


async def _update_attrs(resourcetype: str, ident: dict[str, str], changes: dict[str, Any]) -> list[str]:
    """PUT changed attributes in one call; if rejected, retry one by one to isolate the bad ones."""
    client = _get_client()
    try:
        await client.update(resourcetype, {**ident, **changes})
        return []
    except NitroError as exc:
        if len(changes) == 1:
            return [f"{resourcetype}.{next(iter(changes))}: {exc}"]
    errors: list[str] = []
    for attr, value in changes.items():
        try:
            await client.update(resourcetype, {**ident, attr: value})
        except NitroError as exc:
            errors.append(f"{resourcetype}.{attr}: {exc}")
    return errors


async def _export_document(kind: waf.ProfileKind, profile: str) -> dict[str, Any]:
    client = _get_client()
    settings = _one(await client.get("config", kind.profile, resource_name=profile), kind.profile)
    rules, other = await _profile_rules(kind, profile)
    return kind.build_document(
        profile=profile,
        appliance=client.settings.base_origin,
        exported_at=datetime.now(UTC).isoformat(timespec="seconds"),
        settings=settings,
        rules=rules,
        other_bindings=other,
        extra_settings=await _extra_settings(kind, profile),
    )


async def _apply_document(
    kind: waf.ProfileKind,
    doc: dict[str, Any],
    target: str,
    *,
    mode: str,
    include_settings: bool | None,
    dry_run: bool,
    tool: str,
    args: dict[str, Any],
    confirm: str | None,
) -> dict[str, Any]:
    """Plan a profile document against ``target`` and, once confirmed, apply it in a traffic-safe order."""
    if mode not in ("merge", "replace"):
        raise ValueError("mode must be 'merge' or 'replace'.")
    if not dry_run:
        _require_write()
    client = _get_client()
    try:
        current = _one(await client.get("config", kind.profile, resource_name=target), kind.profile)
    except NitroError as exc:
        if not _is_missing(exc):
            raise
        current = {}
    exists = bool(current)
    apply_settings = (not exists) if include_settings is None else include_settings
    desired_settings = doc.get("settings") or {}
    extra_key = kind.extra.doc_key if kind.extra else None
    desired_extra = (doc.get(extra_key) or {}) if extra_key else {}
    setting_changes: dict[str, Any] = {}
    extra_changes: dict[str, Any] = {}
    if apply_settings and exists:
        setting_changes = waf.settings_changes(desired_settings, current)
        if extra_key:
            extra_changes = waf.settings_changes(desired_extra, await _extra_settings(kind, target))
    elif apply_settings:  # a new profile's defaults are unknown until it exists
        setting_changes, extra_changes = dict(desired_settings), dict(desired_extra)
    current_rules = (await _profile_rules(kind, target))[0] if exists else {}
    plan = kind.plan_bindings(doc.get("rules") or {}, current_rules, replace=mode == "replace")

    out: dict[str, Any] = {
        "kind": kind.key,
        "target_profile": target,
        "mode": mode,
        "dry_run": dry_run,
        "profile": "exists" if exists else "would create",
        "settings_changes": setting_changes,
        "rules": {
            key: {op: len(v) if isinstance(v, list) else v for op, v in ops.items()} for key, ops in plan.items()
        },
        "not_imported": {k: len(v) for k, v in (doc.get("other_bindings") or {}).items()},
    }
    if extra_key:
        out[f"{extra_key}_changes"] = extra_changes
    preview = {
        **out,
        "preview": {
            key: {op: v[:25] for op, v in ops.items() if isinstance(v, list) and v} for key, ops in plan.items()
        },
        "next": "Review, then call again with dry_run=false (needs NETSCALER_ALLOW_WRITE); persist with save_config.",
    }
    writes = not exists or bool(setting_changes or extra_changes) or any(
        isinstance(v, list) and v for ops in plan.values() for v in ops.values()
    )
    change = {
        "args": args,
        "plan": {"profile_exists": exists, "settings": setting_changes, "extra": extra_changes, "rules": plan},
    }
    summary = f"{'Update' if exists else 'Create'} {kind.key} profile '{target}' ({mode}) from a profile document."
    if not _gate(tool, change, summary, preview, dry_run=dry_run, confirm=confirm, writes=writes):
        return preview
    if not exists:
        out["profile"] = "created"

    errors: list[str] = []
    if not exists:
        body: dict[str, Any] = {"name": target}
        for attr in kind.create_attrs:
            if desired_settings.get(attr):
                body[attr] = desired_settings[attr]
        await client.add(kind.profile, body)
        if apply_settings:  # diff against the fresh profile's defaults so only real differences are sent
            fresh = _one(await client.get("config", kind.profile, resource_name=target), kind.profile)
            setting_changes = waf.settings_changes(desired_settings, fresh)
            if extra_key:
                extra_changes = waf.settings_changes(desired_extra, await _extra_settings(kind, target))
    if setting_changes:
        errors += await _update_attrs(kind.profile, {"name": target}, setting_changes)
    if extra_changes and kind.extra:
        errors += await _update_attrs(kind.extra.resource, {kind.extra.ident: target}, extra_changes)

    applied: dict[str, list[str]] = {}

    def _record(key: str, op: str, status: str, row: dict[str, Any]) -> None:
        applied.setdefault(key, []).append(status)
        if status.startswith("error") and len(errors) < 50:
            errors.append(f"{key} {op} {row.get(kind.types[key].identity[0])!r}: {status[len('error: '):]}")

    # Add first, re-bind changed, remove last: allowed traffic never loses its rule mid-import.
    for key, ops in plan.items():
        for row in ops["add"]:
            _record(key, "add", await _bind(kind.types[key], target, row), row)
    for key, ops in plan.items():
        for change in ops["update"]:
            status = await _unbind(kind.types[key], target, change["current"])
            if not status.startswith("error"):
                status = await _bind(kind.types[key], target, change["desired"])
                status = "updated" if status == "added" else status
            _record(key, "update", status, change["desired"])
    for key, ops in plan.items():
        for row in ops["remove"]:
            _record(key, "remove", await _unbind(kind.types[key], target, row), row)

    out["applied"] = {key: _tally(statuses) for key, statuses in applied.items()}
    out["errors"] = errors
    return out


# ---- shared tool bodies: the WAF and Bot families differ only in their ProfileKind ----

async def _rules_overview(
    kind: waf.ProfileKind, profile: str, rule_type: str | None, contains: str | None, limit: int
) -> dict[str, Any]:
    """Shared body of list_waf_rules / list_bot_rules."""
    rules, other = await _profile_rules(kind, profile)
    keys = [kind.rule_type(rule_type)] if rule_type else list(kind.types)
    counts: dict[str, int] = {}
    shown: dict[str, list[dict[str, Any]]] = {}
    for key in keys:
        rows = [r for r in (waf.clean_binding(row) for row in rules.get(key, [])) if _matches(r, contains)]
        if rows:
            counts[key] = len(rows)
            shown[key] = rows[: _clamp(limit, default=200, maximum=2000)]
    return {
        "profile": profile,
        "counts": counts,
        "rules": shown,
        "other_bindings": {k: len(v) for k, v in other.items()},
    }


async def _apply_rule(
    kind: waf.ProfileKind,
    profile: str,
    key: str,
    row: dict[str, Any],
    *,
    comment: str | None = None,
    dry_run: bool = True,
    tool: str,
    args: dict[str, Any],
    confirm: str | None = None,
) -> dict[str, Any]:
    """Shared body of add_waf_rule / add_bot_rule: bind the rule on each profile that lacks it."""
    spec = kind.types[key]
    if not row.get(spec.identity[0]):
        raise ValueError(f"The rule needs {spec.identity[0]!r} (in binding_attrs for rule='raw').")
    if comment:
        row[spec.comment_attr] = comment
    if not dry_run:
        _require_write()
    results = []
    for name in _profiles(profile):
        try:
            existing = _rows(await _get_client().get("config", spec.binding, resource_name=name), spec.binding)
        except NitroError as exc:
            results.append({"profile": name, "status": f"error: {exc}"})
            continue
        exists = waf.binding_key(spec, row) in {waf.binding_key(spec, r) for r in existing}
        results.append({"profile": name, "status": "exists" if exists else "would add"})
    out: dict[str, Any] = {"dry_run": dry_run, "rule_type": key, "rule": row, "results": results}
    targets = [r["profile"] for r in results if r["status"] == "would add"]
    preview = {
        **out,
        "next": "Call again with dry_run=false to bind (needs NETSCALER_ALLOW_WRITE); persist with save_config.",
    }
    change = {"args": args, "plan": {"rule_type": key, "rule": row, "results": results}}
    summary = f"Add {kind.key} {key} rule to {', '.join(targets) or 'no profile'}."
    if not _gate(tool, change, summary, preview, dry_run=dry_run, confirm=confirm, writes=bool(targets)):
        return preview
    out["results"] = [
        {**r, "status": await _bind(spec, r["profile"], row)} if r["status"] == "would add" else r for r in results
    ]
    return out


async def _remove_rule(
    kind: waf.ProfileKind,
    profile: str,
    rule_type: str,
    rule: dict[str, Any],
    all_matches: bool,
    dry_run: bool,
    tool: str,
    args: dict[str, Any],
    confirm: str | None,
) -> dict[str, Any]:
    """Shared body of remove_waf_rule / remove_bot_rule."""
    key = kind.rule_type(rule_type)
    spec = kind.types[key]
    identity = spec.identity + spec.ident_extra
    given = {a: v for a, v in (rule or {}).items() if a in identity and v not in (None, "")}
    if spec.identity[0] not in given:
        raise ValueError(f"rule must include {spec.identity[0]!r}.")
    if not dry_run:
        _require_write()
    existing = _rows(await _get_client().get("config", spec.binding, resource_name=profile), spec.binding)
    matches = [waf.clean_binding(r) for r in existing if waf.row_matches(spec, r, given)]
    if len(matches) > 1 and not all_matches:
        raise ValueError(
            f"{len(matches)} rules match; add identifying attributes or pass all_matches=true. "
            f"Matches: {matches[:10]}"
        )
    out: dict[str, Any] = {"profile": profile, "rule_type": key, "dry_run": dry_run, "matched": len(matches)}
    preview = {**out, "results": [{"rule": row, "status": "would remove"} for row in matches]}
    change = {"args": args, "plan": {"rule_type": key, "remove": matches}}
    summary = f"Remove {len(matches)} {kind.key} {key} rule(s) from profile '{profile}'."
    if not _gate(tool, change, summary, preview, dry_run=dry_run, confirm=confirm, writes=bool(matches)):
        return preview
    out["results"] = [{"rule": row, "status": await _unbind(spec, profile, row)} for row in matches]
    return out


async def _export_profile(
    kind: waf.ProfileKind, profile: str, host_map: dict[str, str] | None, save_as: str | None
) -> dict[str, Any]:
    """Shared body of export_waf_profile / export_bot_profile."""
    doc = await _export_document(kind, profile)
    extra: dict[str, Any] = {}
    if host_map:
        doc, replacements = kind.apply_host_map(doc, host_map)
        extra["host_replacements"] = replacements
    if not save_as:
        return {**doc, **extra}
    path = _export_path(save_as)
    try:
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not write {path}: {exc}") from exc
    return {
        "saved_to": str(path),
        "source": doc["source"],
        "hosts": doc["hosts"],
        "settings": len(doc["settings"]),
        "rules": {k: len(v) for k, v in doc["rules"].items()},
        "other_bindings": {k: len(v) for k, v in doc["other_bindings"].items()},
        **extra,
    }


async def _import_profile(
    kind: waf.ProfileKind,
    document: dict[str, Any] | str | None,
    file: str | None,
    target_profile: str | None,
    host_map: dict[str, str] | None,
    mode: str,
    include_settings: bool | None,
    dry_run: bool,
    tool: str,
    args: dict[str, Any],
    confirm: str | None,
) -> dict[str, Any]:
    """Shared body of import_waf_profile / import_bot_profile."""
    if (document is None) == (file is None):
        raise ValueError("Pass exactly one of document or file.")
    if file is not None:
        path = _export_path(file)
        try:
            document = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Could not read {path}: {exc}") from exc
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError as exc:
            raise ValueError(f"document is not valid JSON: {exc}") from exc
    doc = kind.check_document(document)
    target = (target_profile or "").strip() or str((doc.get("source") or {}).get("profile") or "")
    if not target:
        raise ValueError("target_profile is required (the document names no source profile).")
    extra: dict[str, Any] = {}
    if host_map:
        doc, extra["host_replacements"] = kind.apply_host_map(doc, host_map)
    out = await _apply_document(
        kind, doc, target, mode=mode, include_settings=include_settings, dry_run=dry_run,
        tool=tool, args=args, confirm=confirm,
    )
    return {**extra, **out}


async def _rehost_profile(
    kind: waf.ProfileKind,
    profile: str,
    from_host: str,
    to_host: str,
    target_profile: str | None,
    dry_run: bool,
    tool: str,
    args: dict[str, Any],
    confirm: str | None,
) -> dict[str, Any]:
    """Shared body of rehost_waf_profile / rehost_bot_profile."""
    doc, replacements = kind.apply_host_map(await _export_document(kind, profile), {from_host: to_host})
    if not replacements:
        return {
            "profile": profile,
            "message": f"No rule or setting references {from_host!r}; nothing to switch.",
            "hosts": doc["hosts"],
        }
    target = (target_profile or "").strip() or profile
    in_place = target == profile
    out = await _apply_document(
        kind, doc, target, mode="replace", include_settings=True if in_place else None, dry_run=dry_run,
        tool=tool, args=args, confirm=confirm,
    )
    return {"host_replacements": replacements, **out}


@_tool
async def list_waf_rules(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str | None, Field(description="Only this rule type: start_url, deny_url, sql_injection, cross_site_scripting, cmd_injection, field_consistency, cookie_consistency, csrf_tag, field_format, content_type, credit_card, safe_object, trusted_learning_client, xml_dos_url, xml_wsi_url, xml_attachment_url, json_dos_url, json_sql_url, json_xss_url, json_cmd_url. Omit for all.")] = None,
    contains: Annotated[str | None, Field(description="Case-insensitive substring filter on any rule value (URL, field name, comment).")] = None,
    limit: Annotated[int, Field(description="Max rules returned per rule type.", ge=1, le=2000)] = 200,
) -> dict[str, Any]:
    """List a WAF profile's configured rules, grouped by rule type (config tree, appfwprofile_binding).

    Covers relaxations (start URLs, SQL/XSS/command-injection field exemptions, field/cookie
    consistency, CSRF, field formats, content types, …) and deny URLs. Rows hold the bindable
    attributes, so one can be passed straight to remove_waf_rule. 'counts' are totals after the filter;
    binding types this server doesn't model are counted under 'other_bindings'.
    """
    return await _rules_overview(waf.WAF, profile, rule_type, contains, limit)


@_tool
async def list_waf_learned_rules(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str, Field(description="'all' for a per-check overview, or one learned check: start_url, sql_injection, cross_site_scripting, field_consistency, cookie_consistency, field_format, csrf_tag, content_type, credit_card, xml_dos, xml_wsi, xml_attachment (NITRO names like 'startURL' work too).")] = "all",
    contains: Annotated[str | None, Field(description="Case-insensitive substring filter on the learned values (URL, field name, …).")] = None,
    min_hits: Annotated[int | None, Field(description="Only entries seen at least this many times.", ge=0)] = None,
    limit: Annotated[int, Field(description="Max entries returned for a single check.", ge=1, le=2000)] = 100,
) -> dict[str, Any]:
    """Show what the WAF learning engine recorded for a profile (config tree, appfwlearningdata).

    A check learns while its action list includes 'learn' and traffic flows (only from trusted learning
    clients, if any are bound). Each entry carries its hit count, the raw learned record and the 'rule'
    (binding attributes) deploy_waf_learned_rules would create — check that mapping before deploying.
    For start URLs, 'groups' condenses the learned URLs by host and first path segment with a suggested
    prefix regex: a few add_waf_rule(rule='allow_url') calls often replace hundreds of exact URLs.
    'all' returns counts plus the top 5 entries per check that has data.
    """
    if (rule_type or "").strip().lower() == "all":
        checks: dict[str, Any] = {}
        names = [k for k, r in waf.RULE_TYPES.items() if r.check] + list(waf.LIST_ONLY_CHECKS)
        for name in names:
            key, check = waf.resolve_check(name)
            try:
                entries = await _learned_entries(profile, check, waf.RULE_TYPES.get(key or ""), contains, min_hits)
            except NitroError as exc:
                checks[name] = {"error": str(exc)}
                continue
            if entries:
                checks[name] = {"count": len(entries), "top": entries[:5]}
        return {"profile": profile, "checks": checks}

    key, check = waf.resolve_check(rule_type)
    entries = await _learned_entries(profile, check, waf.RULE_TYPES.get(key or ""), contains, min_hits)
    out: dict[str, Any] = {
        "profile": profile,
        "rule_type": key or check,
        "securitycheck": check,
        "count": len(entries),
        "entries": entries[: _clamp(limit, default=100, maximum=2000)],
    }
    if key == "start_url":
        out["groups"] = waf.group_urls([e["rule"]["starturl"] for e in entries if e.get("rule")])[:50]
    return out


@_tool
async def list_waf_urls(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    host: Annotated[str | None, Field(description="Only URLs for this hostname (rules for any host '*' are kept).")] = None,
    include_learned: Annotated[bool, Field(description="Also list learned start URLs and whether a configured start URL already covers each.")] = True,
    limit: Annotated[int, Field(description="Max URLs per section.", ge=1, le=5000)] = 500,
) -> dict[str, Any]:
    """URL inventory of a WAF profile — everything it allows, denies, references or has learned.

    - hosts: hostnames per section (what rehost_waf_profile would switch)
    - start_urls / deny_urls: the configured allow list (start URL closure) and deny list
    - rule_urls: form-action / CSRF / credit-card / XML / JSON URLs used by other rules
    - learned: learned start URLs with hits; 'covered' = an enabled start URL already matches it
      (checked with Python's regex engine; null when the learned URL is itself a pattern)
    - uncovered_groups: uncovered learned URLs grouped by host + first path segment, each with a
      suggested prefix rule — the shortlist to add before switching the start URL check to block.
    """
    rules, _ = await _profile_rules(waf.WAF, profile)
    only = waf.normalize_host(host) if host else None
    cap = _clamp(limit, default=500, maximum=5000)
    hosts: dict[str, dict[str, int]] = {}

    def _section(name: str, items: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
        section = []
        for pattern, extra in items:
            entry = {"pattern": pattern, **waf.parse_url_pattern(pattern), **extra}
            if only and entry["host"] not in (only, "*"):
                continue
            if entry["host"] not in ("", "*"):
                counts = hosts.setdefault(entry["host"], {})
                counts[name] = counts.get(name, 0) + 1
            section.append(entry)
        return section

    start = _section("start_urls", [
        (r["starturl"], {"state": r.get("state")}) for r in rules.get("start_url", []) if r.get("starturl")
    ])
    deny = _section("deny_urls", [
        (r["denyurl"], {"state": r.get("state")}) for r in rules.get("deny_url", []) if r.get("denyurl")
    ])
    referenced = _section("rule_urls", [
        (row[attr], {"rule_type": key, "attr": attr})
        for key, rule in waf.RULE_TYPES.items() if key not in ("start_url", "deny_url")
        for row in rules.get(key, []) for attr in rule.url_attrs if row.get(attr)
    ])
    out: dict[str, Any] = {
        "profile": profile,
        "hosts": hosts,
        "counts": {"start_urls": len(start), "deny_urls": len(deny), "rule_urls": len(referenced)},
        "start_urls": start[:cap],
        "deny_urls": deny[:cap],
        "rule_urls": referenced[:cap],
    }
    if include_learned:
        try:
            entries = await _learned_entries(profile, "startURL", waf.RULE_TYPES["start_url"])
        except NitroError as exc:
            out["learned_error"] = str(exc)
            entries = []
        allow = waf.compile_patterns(
            [e["pattern"] for e in start if str(e.get("state") or "").upper() != "DISABLED"]
        )
        learned = _section("learned", [(e["rule"]["starturl"], {"hits": e["hits"]}) for e in entries if e.get("rule")])
        for entry in learned:
            entry["covered"] = waf.is_covered(entry["pattern"], allow)
        uncovered = [e["pattern"] for e in learned if e["covered"] is not True]
        out["counts"].update(learned=len(learned), learned_uncovered=len(uncovered))
        out["learned"] = learned[:cap]
        out["uncovered_groups"] = waf.group_urls(uncovered)[:50]
    return out


@_tool
async def export_waf_profile(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    host_map: Annotated[dict[str, str] | None, Field(description="Rewrite hostnames on the way out, e.g. {\"app.test.corp\": \"app.corp\"}.")] = None,
    save_as: Annotated[str | None, Field(description="Save to NETSCALER_EXPORT_DIR under this bare file name (e.g. 'pr_app-test.json'); the result is then a summary instead of the whole document.")] = None,
) -> dict[str, Any]:
    """Export a WAF profile — settings, learning thresholds and every rule — as a portable JSON document.

    import_waf_profile consumes it on this or another appliance: keep it in git as the app's WAF
    baseline, diff environments, or seed another environment's profile (host_map switches hostnames).
    'hosts' lists the hostnames the rules reference. Bindings this server doesn't model are kept under
    'other_bindings' for reference but are not imported. Read-only on the appliance.
    """
    return await _export_profile(waf.WAF, profile, host_map, save_as)


@_tool
async def add_waf_rule(
    profile: Annotated[str, Field(description="AppFw profile name; comma-separate several to add the same rule to each.")],
    rule: Annotated[str, Field(description="Preset: allow_url, allow_static, deny_url, allow_sql_field, allow_xss_field, allow_cmd_field, allow_field_consistency, allow_cookie, allow_csrf, allow_content_type, trusted_learning_client — or 'raw' (rule_type + binding_attrs).")],
    host: Annotated[str | None, Field(description="Hostname for URL-based rules, e.g. 'app.example.com' (':port' allowed); '*' = any host, so the rule works in every environment.")] = None,
    path: Annotated[str, Field(description="URL path, e.g. '/', '/api/', '/login.php'.")] = "/",
    match: Annotated[str, Field(description="'prefix' (the path and everything below it), 'exact', or 'regex' (path is a regex fragment).")] = "prefix",
    scheme: Annotated[str, Field(description="'https', 'http' or 'any'.")] = "https",
    extensions: Annotated[list[str] | None, Field(description="Limit a prefix rule to file extensions, e.g. ['css','js','png']; allow_static defaults to common static types.")] = None,
    field: Annotated[str | None, Field(description="Form field or cookie name for field/cookie rules; '*' = every field.")] = None,
    field_is_regex: Annotated[bool, Field(description="Treat field as a regex.")] = False,
    location: Annotated[str, Field(description="Where SQL/XSS/command field rules apply: FORMFIELD, HEADER or COOKIE.")] = "FORMFIELD",
    value: Annotated[str | None, Field(description="allow_content_type: content-type regex; trusted_learning_client: IP or CIDR; allow_csrf: form action URL regex (defaults to the built URL).")] = None,
    rule_type: Annotated[str | None, Field(description="rule='raw' only: the rule type (see list_waf_rules).")] = None,
    binding_attrs: Annotated[dict[str, Any] | None, Field(description="rule='raw' only: NITRO binding attributes, e.g. {\"denyurl\": \"^https://x/admin/.*$\"}.")] = None,
    comment: Annotated[str | None, Field(description="Comment stored on the rule.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add an easy WAF rule without hand-writing NetScaler regexes (WRITE — requires NETSCALER_ALLOW_WRITE).

    Builds the anchored, escaped PCRE for you, e.g. allow_url(host='app.example.com', path='/api/') →
    start URL ^https://app\\.example\\.com/api/.*$ ; host='*' gives a global rule that survives a hostname
    switch. Field rules relax one check for a field on the matching URLs (field='*' = all fields there).
    Skips profiles that already have the rule. Previews by default. Live immediately once applied;
    persist with save_config.
    """
    args = _call_args(locals())
    if rule == "raw":
        key = waf.WAF.rule_type(rule_type)
        row = waf.clean_binding(dict(binding_attrs or {}))
    else:
        key, row = waf.easy_rule(
            rule, host=host, path=path, match=match, scheme=scheme, extensions=extensions, field=field,
            field_is_regex=field_is_regex, location=location, value=value,
        )
    return await _apply_rule(
        waf.WAF, profile, key, row, comment=comment, dry_run=dry_run, tool="add_waf_rule", args=args, confirm=confirm
    )


@_tool
async def remove_waf_rule(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str, Field(description="Rule type, as in list_waf_rules (e.g. 'start_url').")],
    rule: Annotated[dict[str, Any], Field(description="The rule to remove: a row from list_waf_rules, or just its main value, e.g. {\"starturl\": \"^https://app\\\\.corp/old/.*$\"}.")],
    all_matches: Annotated[bool, Field(description="Remove every rule matching the given attributes (otherwise several matches is an error).")] = False,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Remove (unbind) a WAF rule from a profile (WRITE — requires NETSCALER_ALLOW_WRITE).

    Matches live rules on the identifying attributes you pass (value, form action URL, location, value
    type/expression, ruletype); other keys are ignored. Previews by default. Live immediately once
    applied; persist with save_config.
    """
    return await _remove_rule(
        waf.WAF, profile, rule_type, rule, all_matches, dry_run,
        tool="remove_waf_rule", args=_call_args(locals()), confirm=confirm,
    )


@_tool
async def deploy_waf_learned_rules(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str, Field(description="Learned check to deploy: start_url, sql_injection, cross_site_scripting, field_consistency, cookie_consistency, field_format, csrf_tag, content_type or credit_card.")],
    contains: Annotated[str | None, Field(description="Only entries whose learned values contain this (case-insensitive).")] = None,
    min_hits: Annotated[int | None, Field(description="Only entries seen at least this many times.", ge=0)] = None,
    remove_learned: Annotated[bool, Field(description="Delete deployed entries from the learning database, as the GUI's Deploy does.")] = True,
    limit: Annotated[int, Field(description="Max rules to deploy in one call.", ge=1, le=2000)] = 500,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Deploy learned entries as WAF relaxation rules (WRITE — requires NETSCALER_ALLOW_WRITE).

    Filters the learned entries and binds each one's 'rule' (see list_waf_learned_rules) unless it
    already exists — or, for start URLs, an enabled start URL rule already covers it — then removes the
    entry from the learning database. Review the preview: NITRO returns learned data as generic
    url/name/value fields, so confirm the mapped rule looks right on your build first. For start URLs a
    few broad add_waf_rule prefixes usually beat hundreds of exact URLs (add those first; covered
    entries are then just cleared). Live immediately once applied; persist with save_config.
    """
    args = _call_args(locals())
    key = waf.WAF.rule_type(rule_type)
    spec = waf.RULE_TYPES[key]
    if not spec.learned:
        learnable = tuple(k for k, r in waf.RULE_TYPES.items() if r.learned)
        raise ValueError(f"{key} rules can't be deployed from learned data; use one of {learnable}.")
    if not dry_run:
        _require_write()
    entries = await _learned_entries(profile, spec.check, spec, contains, min_hits)
    existing = _rows(await _get_client().get("config", spec.binding, resource_name=profile), spec.binding)
    have = {waf.binding_key(spec, row) for row in existing}
    allow = waf.compile_patterns([
        r["starturl"] for r in existing
        if key == "start_url" and r.get("starturl") and str(r.get("state") or "").upper() != "DISABLED"
    ])
    cap = _clamp(limit, default=500, maximum=2000)
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    unmapped = 0
    for entry in entries:
        row = entry.get("rule")
        if not row:
            unmapped += 1
            continue
        ident = waf.binding_key(spec, row)
        if ident in seen:
            continue
        if len(results) >= cap:
            break
        seen.add(ident)
        result: dict[str, Any] = {"hits": entry["hits"], "rule": row}
        if ident in have:
            result["status"] = "exists"
        elif allow and waf.is_covered(row["starturl"], allow):
            result["status"] = "covered"
        else:
            result["status"] = "would add"
        if remove_learned:
            result["learned"] = "would remove"
        results.append(result)

    def _answer(rows: list[dict[str, Any]], applied: bool) -> dict[str, Any]:
        return {
            "profile": profile,
            "rule_type": key,
            "dry_run": not applied,
            "matched": len(entries),
            "unmapped": unmapped,
            "summary": _tally([r["status"] for r in rows]),
            "results": rows[:200],
        }

    preview = _answer(results, False)
    preview["next"] = "Check each 'rule', then call again with dry_run=false; persist with save_config."
    # Hit counts keep moving (and reorder entries) while learning runs: bind the rules, not the counts.
    plan = sorted(json.dumps({k: v for k, v in r.items() if k != "hits"}, sort_keys=True) for r in results)
    adds = sum(r["status"] == "would add" for r in results)
    summary = f"Deploy {adds} learned {key} rule(s) on profile '{profile}'" + (
        f" and clear {len(results)} learned entries." if remove_learned else "."
    )
    if not _gate(
        "deploy_waf_learned_rules", {"args": args, "plan": plan}, summary, preview,
        dry_run=dry_run, confirm=confirm, writes=bool(adds or (remove_learned and results)),
    ):
        return preview
    for result in results:
        if result["status"] == "would add":
            result["status"] = await _bind(spec, profile, result["rule"])
        if "learned" in result:
            if result["status"] in ("exists", "covered", "added"):
                result["learned"] = await _forget_learned(spec, profile, result["rule"])
            else:  # the bind failed: keep the learned entry
                del result["learned"]
    return _answer(results, True)


@_tool
async def discard_waf_learned_rules(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str, Field(description="Learned check: start_url, sql_injection, cross_site_scripting, field_consistency, cookie_consistency, field_format, csrf_tag, content_type or credit_card.")],
    contains: Annotated[str | None, Field(description="Only entries whose learned values contain this (case-insensitive).")] = None,
    max_hits: Annotated[int | None, Field(description="Only entries seen at most this many times (one-off noise).", ge=0)] = None,
    all_entries: Annotated[bool, Field(description="Discard every learned entry of this check (required when no filter is given).")] = False,
    limit: Annotated[int, Field(description="Max entries to discard in one call.", ge=1, le=2000)] = 500,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Delete learned entries that must not become rules — scanner noise, attack attempts, test junk
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    Needs a filter (contains / max_hits) or all_entries=true, and previews by default.
    """
    args = _call_args(locals())
    key = waf.WAF.rule_type(rule_type)
    spec = waf.RULE_TYPES[key]
    if not spec.learned:
        learnable = tuple(k for k, r in waf.RULE_TYPES.items() if r.learned)
        raise ValueError(f"{key} has no learned data to discard; use one of {learnable}.")
    if not (contains or max_hits is not None or all_entries):
        raise ValueError("Give a filter (contains / max_hits) or all_entries=true.")
    if not dry_run:
        _require_write()
    entries = await _learned_entries(profile, spec.check, spec, contains)
    if max_hits is not None:
        entries = [e for e in entries if (e["hits"] or 0) <= max_hits]
    picked = entries[: _clamp(limit, default=500, maximum=2000)]
    results: list[dict[str, Any]] = [
        {
            "hits": entry["hits"],
            "learned": entry["learned"],
            "status": "would remove" if waf.learned_delete_args(spec, entry.get("rule") or {}) else "unmapped",
        }
        for entry in picked
    ]

    def _answer(applied: bool) -> dict[str, Any]:
        return {
            "profile": profile,
            "rule_type": key,
            "dry_run": not applied,
            "matched": len(entries),
            "summary": _tally([r["status"] for r in results]),
            "results": results[:200],
        }

    preview = _answer(False)
    plan = sorted(json.dumps({"learned": r["learned"], "status": r["status"]}, sort_keys=True) for r in results)
    removals = sum(r["status"] == "would remove" for r in results)
    summary = f"Discard {removals} learned {key} entries from profile '{profile}'."
    if not _gate(
        "discard_waf_learned_rules", {"args": args, "plan": plan}, summary, preview,
        dry_run=dry_run, confirm=confirm, writes=bool(removals),
    ):
        return preview
    for entry, result in zip(picked, results):
        if result["status"] == "would remove":
            result["status"] = await _forget_learned(spec, profile, entry.get("rule") or {})
    return _answer(True)


@_tool
async def set_waf_check_actions(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    checks: Annotated[list[str], Field(description="Checks to change, e.g. ['start_url', 'sql_injection', 'cross_site_scripting'], or ['all'] for every check the profile has.")],
    set_actions: Annotated[list[str] | None, Field(description="Replace the action list with these: none, block, learn, log, stats.")] = None,
    add_actions: Annotated[list[str] | None, Field(description="Add these actions, e.g. ['block'] when going live.")] = None,
    remove_actions: Annotated[list[str] | None, Field(description="Remove these actions, e.g. ['learn'] once rules are deployed.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change what a WAF profile does per security check — the learn → block switch (WRITE — requires
    NETSCALER_ALLOW_WRITE).

    Typical rollout: learn+log+stats while real traffic flows → deploy/add relaxations → watch the logs
    → add_actions=['block'], remove_actions=['learn']. Only start URL, content type, cookie/field
    consistency, CSRF, XSS, SQL, field format, credit card and XML DoS/XSS/WSI/attachment can learn
    (with checks=['all'], 'learn' is skipped where unsupported). Shows before/after per check; previews
    by default. Live immediately once applied; persist with save_config.
    """
    args = _call_args(locals())
    if set_actions is None and not add_actions and not remove_actions:
        raise ValueError("Pass set_actions, or add_actions / remove_actions.")
    if not dry_run:
        _require_write()
    current = _one(await _get_client().get("config", "appfwprofile", resource_name=profile), "appfwprofile")
    names = [c.strip().lower() for c in checks if c and c.strip()]
    everything = names == ["all"]
    if everything:
        names = [check for check, attr in waf.CHECK_ACTION_ATTRS.items() if attr in current]
    unknown = [c for c in names if c not in waf.CHECK_ACTION_ATTRS]
    if unknown or not names:
        raise ValueError(f"Unknown check(s) {unknown}; use {tuple(waf.CHECK_ACTION_ATTRS)} or ['all'].")
    table: dict[str, Any] = {}
    changes: dict[str, list[str]] = {}
    for check in names:
        attr = waf.CHECK_ACTION_ATTRS[check]
        after = waf.new_actions(
            check, current.get(attr), set_to=set_actions, add=add_actions, remove=remove_actions,
            strict=not everything,
        )
        changed = bool(waf.settings_changes({attr: after}, current))
        table[check] = {"attribute": attr, "before": current.get(attr), "after": after, "changed": changed}
        if changed:
            changes[attr] = after
    out: dict[str, Any] = {"profile": profile, "dry_run": dry_run, "changed": len(changes), "checks": table}
    summary = f"Change the actions of {len(changes)} check(s) on WAF profile '{profile}'."
    change = {"args": args, "plan": changes}
    if not _gate("set_waf_check_actions", change, summary, out, dry_run=dry_run, confirm=confirm, writes=bool(changes)):
        return out
    if changes:
        await _get_client().update("appfwprofile", {"name": profile, **changes})
    return out


@_tool
async def import_waf_profile(
    document: Annotated[dict[str, Any] | str | None, Field(description="An export_waf_profile document (object or JSON string).")] = None,
    file: Annotated[str | None, Field(description="Or a bare file name in NETSCALER_EXPORT_DIR, e.g. 'pr_app-test.json'.")] = None,
    target_profile: Annotated[str | None, Field(description="Profile to import into (created if missing); defaults to the document's source profile name.")] = None,
    host_map: Annotated[dict[str, str] | None, Field(description="Switch hostnames on the way in, e.g. {\"app.test.corp\": \"app.corp\"}.")] = None,
    mode: Annotated[str, Field(description="'merge' adds missing rules only; 'replace' makes the profile's rules match the document — it also re-binds changed rules and REMOVES rules not in the document.")] = "merge",
    include_settings: Annotated[bool | None, Field(description="Apply the document's profile settings (check actions, limits, …) and learning thresholds. Default: only when the profile is created, so an existing profile keeps its own learn/block actions.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Import a WAF profile document — copy a tuned profile to another environment or appliance
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    Plans against the live target first: settings changes, and per rule type how many rules are added,
    updated and removed (the preview shows up to 25 of each). Apply order is safe for live traffic:
    create profile → settings → add rules → re-bind changed → remove extras. A new profile still has to
    be bound to an AppFw policy to take effect. Live immediately once applied; persist with save_config.
    """
    return await _import_profile(
        waf.WAF, document, file, target_profile, host_map, mode, include_settings, dry_run,
        tool="import_waf_profile", args=_call_args(locals()), confirm=confirm,
    )


@_tool
async def rehost_waf_profile(
    profile: Annotated[str, Field(description="AppFw profile whose rules to switch.")],
    from_host: Annotated[str, Field(description="Hostname in the current rules, e.g. 'app.test.corp' (append ':port' to switch a port as well).")],
    to_host: Annotated[str, Field(description="New hostname, e.g. 'app.corp'.")],
    target_profile: Annotated[str | None, Field(description="Write the rehosted copy into this profile (created if missing) and leave the source untouched.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Switch a WAF profile's rules to another hostname — e.g. reuse the test app's tuned profile for
    prod (WRITE — requires NETSCALER_ALLOW_WRITE).

    Rewrites the host in every rule URL and URL-bearing setting (start/deny URLs, form action URLs,
    CSRF, error URL, …) in literal and regex-escaped form, on whole-host matches only. In place, the
    new-host rules are bound before the old-host ones are removed, so allowed traffic isn't blocked
    mid-change. With target_profile the target's rules are made to match the rehosted source (replace
    mode; settings are copied only when the target is created). Rules for any host ('*') need no
    switching. Previews by default; persist with save_config.
    """
    return await _rehost_profile(
        waf.WAF, profile, from_host, to_host, target_profile, dry_run,
        tool="rehost_waf_profile", args=_call_args(locals()), confirm=confirm,
    )


@_tool
async def save_config(
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Save the running configuration (save ns config) so applied changes survive a reboot
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    NITRO changes are live immediately but only in the running config until saved.
    """
    _require_write()
    if preview := _confirm("save_config", {"action": "save ns config"}, "Save the running configuration.", confirm):
        return preview
    await _get_client().action("nsconfig", "save")
    return {"saved": True}


@_tool
async def apply_batch(
    changes: Annotated[list[dict[str, Any]], Field(description="The changes in order, each {\"tool\": <write tool>, \"args\": {<that tool's arguments>}}, e.g. [{\"tool\": \"add_object\", \"args\": {\"kind\": \"server\", \"name\": \"srv_app1\", \"settings\": {\"ipaddress\": \"10.0.0.51\"}}}, {\"tool\": \"change_bindings\", \"args\": {\"binding\": \"lb_vserver_rewrite_policy\", \"name\": \"vs_app\", \"add\": [{\"policyname\": \"rw_404\", \"priority\": 100, \"bindpoint\": \"RESPONSE\"}]}}]. Any write tool except save_config / apply_batch / clone_app_setup; leave dry_run, confirm and instance out of args.", min_length=1, max_length=50)],
    save: Annotated[bool, Field(description="Save the running config (save ns config) once every step applied cleanly.")] = False,
    instances: Annotated[list[str] | None, Field(description="Run the same steps on several appliances (names from list_instances), e.g. two standalone boxes: one preview per instance, ONE confirmation, applied instance by instance and stopped on the first failure; afterwards the touched objects and bindings are compared across them.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Several changes with ONE preview and ONE confirmation — on one instance or the same changes on
    several (WRITE — requires NETSCALER_ALLOW_WRITE).

    Use this whenever the user wants more than one change — a whole app setup, several rules, policies
    plus bindings, then save — instead of confirming each write tool separately. Every step is previewed
    exactly as its own tool would preview it; the single confirm code covers all of them (a batch with a
    delete always asks). On apply, steps run in order and stop at the first failure (later steps are
    reported 'not run', nothing is saved, and further instances are not touched). A step whose live plan
    no longer matches the preview is not applied either.
    """
    args = _call_args(locals())
    return await _run_batch("apply_batch", changes, save=save, dry_run=dry_run, confirm=confirm, args=args,
                            instances=instances)


# ---- tools: Bot management rollout ---------------------------------------

@_tool
async def list_bot_rules(
    profile: Annotated[str, Field(description="Bot profile name.")],
    rule_type: Annotated[str | None, Field(description="Only this rule type: allow_list, deny_list, rate_limit, tps, captcha, ip_reputation, log_expression, km_expression, trap_url. Omit for all.")] = None,
    contains: Annotated[str | None, Field(description="Case-insensitive substring filter on any rule value (IP, URL, category, comment).")] = None,
    limit: Annotated[int, Field(description="Max rules returned per rule type.", ge=1, le=2000)] = 200,
) -> dict[str, Any]:
    """List a Bot profile's configured entries, grouped by rule type (config tree, botprofile_binding).

    Covers the list-style detections: allow (whitelist) and deny (blacklist) entries, rate-limit and TPS
    thresholds, CAPTCHA URLs, IP-reputation categories, log/KM expressions and trap URLs. Rows hold the
    bindable attributes, so one can be passed straight to remove_bot_rule. Whether a detection runs at
    all is a profile switch — see list_bot_detections.
    """
    return await _rules_overview(bot.BOT, profile, rule_type, contains, limit)


@_tool
async def list_bot_detections(
    profile: Annotated[str | None, Field(description="Bot profile name; omit for appliance-wide counters only.")] = None,
    full: Annotated[bool, Field(description="Also return the raw stat object (every counter).")] = False,
) -> dict[str, Any]:
    """What a Bot profile detects, and what it is actually catching (config + stat trees).

    Per detection: whether it is switched on, its profile-level action list where it has one (device
    fingerprint, trap, the signature header checks, spoofed requests), how many entries it has bound, and
    the live counters split by outcome under 'caught' (log / drop / redirect / reset / captcha). With a
    profile it reads stat/botprofile, otherwise the appliance-wide stat/bot. Use it before moving a
    detection to DROP: what it counts while only logging is what would start being blocked.
    """
    client = _get_client()
    out: dict[str, Any] = {"profile": profile, "scope": "profile" if profile else "appliance"}
    if profile:
        settings = _one(await client.get("config", bot.BOT.profile, resource_name=profile), bot.BOT.profile)
        rules, _ = await _profile_rules(bot.BOT, profile)
        out["signature_object"] = settings.get("signature")
        out["detections"] = bot.detection_config(settings, {k: len(v) for k, v in rules.items()})
        stats = _one(await client.get("stat", "botprofile", args={"name": profile}), "botprofile")
    else:
        stats = _one(await client.get("stat", "bot"), "bot")
    summary = bot.stat_summary(stats)
    out["traffic"] = summary["traffic"]
    out["caught"] = summary["detections"]
    out["configured"] = summary["configured"]
    if full:
        out["raw_stats"] = stats
    return out


@_tool
async def add_bot_rule(
    profile: Annotated[str, Field(description="Bot profile name; comma-separate several to add the same entry to each.")],
    rule: Annotated[str, Field(description="Preset: allow_ip, allow_expression, block_ip, block_expression, rate_limit_url, rate_limit_source_ip, rate_limit_session, rate_limit_geo, tps_source_ip, tps_url, tps_geo, tps_host, captcha, ip_reputation, trap_url, log_expression, km_expression — or 'raw' (rule_type + binding_attrs).")],
    value: Annotated[str | None, Field(description="The entry's main value: an IP or CIDR for allow_ip / block_ip; also accepted instead of the named parameter below for the other presets.")] = None,
    url: Annotated[str | None, Field(description="URL path for rate_limit_url / captcha / trap_url, e.g. '/login' or '/trap'.")] = None,
    expression: Annotated[str | None, Field(description="NetScaler policy expression for allow_expression / block_expression / log_expression / km_expression.")] = None,
    name: Annotated[str | None, Field(description="Name for a log_expression / km_expression entry.")] = None,
    country: Annotated[str | None, Field(description="ISO country code for rate_limit_geo, e.g. 'DE'.")] = None,
    cookie: Annotated[str | None, Field(description="Session cookie name for rate_limit_session.")] = None,
    category: Annotated[str | None, Field(description="IP-reputation category for ip_reputation, e.g. BOTNETS, TOR_PROXY, SCANNERS, PROXY.")] = None,
    actions: Annotated[list[str] | None, Field(description="What happens when the entry matches: NONE, LOG, DROP, REDIRECT, RESET, MITIGATION, or RESPOND_STATUS_TOO_MANY_REQUESTS (rate limit). Deny/rate-limit/CAPTCHA/IP-reputation default to ['DROP'], TPS to ['LOG']; allow-list and expression entries take none.")] = None,
    rate: Annotated[int | None, Field(description="Rate-limit requests per timeslice (default 100).", ge=1)] = None,
    timeslice: Annotated[int | None, Field(description="Rate-limit timeslice in milliseconds (default 1000).", ge=10)] = None,
    threshold: Annotated[int | None, Field(description="TPS threshold: requests per second that trips the detection.", ge=1)] = None,
    percentage: Annotated[int | None, Field(description="TPS percentage rise over the moving average that trips the detection.", ge=1)] = None,
    log: Annotated[bool, Field(description="allow_ip / allow_expression: also log the allowed requests.")] = False,
    rule_type: Annotated[str | None, Field(description="rule='raw' only: the rule type (see list_bot_rules).")] = None,
    binding_attrs: Annotated[dict[str, Any] | None, Field(description="rule='raw' only: NITRO binding attributes, e.g. {\"bot_whitelist\": true, \"bot_whitelist_type\": \"SUBNET\", \"bot_whitelist_value\": \"10.0.0.0/24\"}.")] = None,
    comment: Annotated[str | None, Field(description="Comment stored on the entry.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add a Bot management entry without hand-writing NITRO attributes (WRITE — requires NETSCALER_ALLOW_WRITE).

    allow_ip / block_ip classify the value themselves (IPv4, IPv6, SUBNET, IPv6_SUBNET), so
    add_bot_rule(rule='allow_ip', value='10.0.0.0/24') whitelists a monitoring range and
    rule='block_ip', actions=['DROP'] blocks one; rate limiting, TPS, CAPTCHA, IP reputation, trap URLs
    and expression entries follow the same shape. The detection also has to be switched on at profile
    level — set_bot_detections does that. Skips profiles that already have the entry; previews by
    default. Live immediately once applied; persist with save_config.
    """
    args = _call_args(locals())
    if rule == "raw":
        key = bot.BOT.rule_type(rule_type)
        row = waf.clean_binding(dict(binding_attrs or {}))
    else:
        key, row = bot.easy_rule(
            rule, value=value, url=url, expression=expression, name=name, country=country, cookie=cookie,
            category=category, actions=actions, rate=rate, timeslice=timeslice, threshold=threshold,
            percentage=percentage, log=log,
        )
    return await _apply_rule(
        bot.BOT, profile, key, row, comment=comment, dry_run=dry_run, tool="add_bot_rule", args=args, confirm=confirm
    )


@_tool
async def remove_bot_rule(
    profile: Annotated[str, Field(description="Bot profile name.")],
    rule_type: Annotated[str, Field(description="Rule type, as in list_bot_rules (e.g. 'allow_list').")],
    rule: Annotated[dict[str, Any], Field(description="The entry to remove: a row from list_bot_rules, or just its selector and value, e.g. {\"bot_whitelist\": true, \"bot_whitelist_value\": \"10.0.0.0/24\"}.")],
    all_matches: Annotated[bool, Field(description="Remove every entry matching the given attributes (otherwise several matches is an error).")] = False,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Remove (unbind) a Bot entry from a profile (WRITE — requires NETSCALER_ALLOW_WRITE).

    Matches live entries on the identifying attributes you pass (the detection's boolean selector plus
    its value, type, category or URL); other keys are ignored. Previews by default. Live immediately
    once applied; persist with save_config.
    """
    return await _remove_rule(
        bot.BOT, profile, rule_type, rule, all_matches, dry_run,
        tool="remove_bot_rule", args=_call_args(locals()), confirm=confirm,
    )


@_tool
async def set_bot_detections(
    profile: Annotated[str, Field(description="Bot profile name.")],
    detections: Annotated[list[str], Field(description="Detections to change: allow_list, deny_list, rate_limit, tps, ip_reputation, device_fingerprint, trap, km_detection, headless_browser, signature_no_user_agent, signature_multiple_user_agent, spoofed_request — or ['all'].")],
    enable: Annotated[bool | None, Field(description="Switch the detections on (true) or off (false); omit to change actions only.")] = None,
    actions: Annotated[list[str] | None, Field(description="Action list for the detections that carry one on the profile (device_fingerprint, trap, signature_no_user_agent, signature_multiple_user_agent, spoofed_request): NONE, LOG, DROP, REDIRECT, RESET, MITIGATION — CHECKLAST instead of NONE for signature_multiple_user_agent.")] = None,
    signature: Annotated[str | None, Field(description="Bind this botsignature object to the profile (static signature detection); see list_signatures.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Switch Bot detections on/off and set their actions — the bot counterpart of the WAF learn→block
    step (WRITE — requires NETSCALER_ALLOW_WRITE).

    Allow/deny lists, rate limiting, TPS and IP reputation only have an on/off switch at profile level;
    each of their entries carries its own action (add_bot_rule). Device fingerprint, trap, the signature
    header checks and spoofed-request detection do have a profile-level action list. A safe rollout runs
    them on LOG first, then moves to DROP once list_bot_detections shows what is being caught. Shows
    before/after per detection; previews by default. Live immediately once applied; persist with
    save_config.
    """
    args = _call_args(locals())
    if enable is None and not actions and not signature:
        raise ValueError("Pass enable, actions and/or signature.")
    if not dry_run:
        _require_write()
    current = _one(await _get_client().get("config", bot.BOT.profile, resource_name=profile), bot.BOT.profile)
    names = [d.strip().lower() for d in detections if d and d.strip()]
    everything = names == ["all"]
    if everything:
        names = list(bot.DETECTIONS)
    table: dict[str, Any] = {}
    changes: dict[str, Any] = {}
    for name in names:
        key = bot.detection(name)
        spec = bot.DETECTIONS[key]
        row: dict[str, Any] = {}
        if enable is not None:
            if spec.enable:
                after = "ON" if enable else "OFF"
                row["enabled"] = {"before": current.get(spec.enable), "after": after}
                if waf.settings_changes({spec.enable: after}, current):
                    changes[spec.enable] = after
            else:
                row["enabled"] = "always on (no switch)"
        if actions:
            if spec.action:
                after_actions = bot.detection_actions(key, actions)
                row["action"] = {"before": current.get(spec.action), "after": after_actions}
                if waf.settings_changes({spec.action: after_actions}, current):
                    changes[spec.action] = after_actions
            elif everything:
                row["action"] = "per entry (add_bot_rule)"
            else:
                raise ValueError(f"'{key}' has no profile-level action; set it per entry with add_bot_rule.")
        table[key] = row
    if signature:
        table["signature_object"] = {"before": current.get("signature"), "after": signature}
        if waf.settings_changes({"signature": signature}, current):
            changes["signature"] = signature
    out: dict[str, Any] = {"profile": profile, "dry_run": dry_run, "changed": len(changes), "detections": table}
    summary = f"Change {len(changes)} detection setting(s) on Bot profile '{profile}'."
    change = {"args": args, "plan": changes}
    if not _gate("set_bot_detections", change, summary, out, dry_run=dry_run, confirm=confirm, writes=bool(changes)):
        return out
    if changes:
        await _get_client().update(bot.BOT.profile, {"name": profile, **changes})
    return out


@_tool
async def export_bot_profile(
    profile: Annotated[str, Field(description="Bot profile name.")],
    host_map: Annotated[dict[str, str] | None, Field(description="Rewrite hostnames on the way out, e.g. {\"app.test.corp\": \"app.corp\"} (bot URLs are usually paths, so this often changes nothing).")] = None,
    save_as: Annotated[str | None, Field(description="Save to NETSCALER_EXPORT_DIR under this bare file name (e.g. 'bot_app-test.json'); the result is then a summary instead of the whole document.")] = None,
) -> dict[str, Any]:
    """Export a Bot profile — its detection settings and every entry — as a portable JSON document.

    import_bot_profile consumes it on this or another appliance: keep it in git as the app's bot
    baseline, diff environments, or seed another environment. Binding types this server doesn't model
    are kept under 'other_bindings' for reference but are not imported. Read-only on the appliance.
    """
    return await _export_profile(bot.BOT, profile, host_map, save_as)


@_tool
async def import_bot_profile(
    document: Annotated[dict[str, Any] | str | None, Field(description="An export_bot_profile document (object or JSON string).")] = None,
    file: Annotated[str | None, Field(description="Or a bare file name in NETSCALER_EXPORT_DIR, e.g. 'bot_app-test.json'.")] = None,
    target_profile: Annotated[str | None, Field(description="Profile to import into (created if missing); defaults to the document's source profile name.")] = None,
    host_map: Annotated[dict[str, str] | None, Field(description="Switch hostnames on the way in, e.g. {\"app.test.corp\": \"app.corp\"}.")] = None,
    mode: Annotated[str, Field(description="'merge' adds missing entries only; 'replace' makes the profile's entries match the document — it also re-binds changed ones and REMOVES entries not in the document.")] = "merge",
    include_settings: Annotated[bool | None, Field(description="Apply the document's profile settings (detection switches and actions). Default: only when the profile is created, so an existing profile keeps its own switches.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Import a Bot profile document — copy a tuned profile to another environment or appliance
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    Plans against the live target first: settings changes, and per rule type how many entries are added,
    updated and removed (the preview shows up to 25 of each). Apply order is safe for live traffic:
    create profile → settings → add entries → re-bind changed → remove extras. A new profile still has
    to be selected by a bot policy to take effect (list_enforcement). Live immediately once applied;
    persist with save_config.
    """
    return await _import_profile(
        bot.BOT, document, file, target_profile, host_map, mode, include_settings, dry_run,
        tool="import_bot_profile", args=_call_args(locals()), confirm=confirm,
    )


@_tool
async def rehost_bot_profile(
    profile: Annotated[str, Field(description="Bot profile whose entries to switch.")],
    from_host: Annotated[str, Field(description="Hostname in the current entries, e.g. 'app.test.corp'.")],
    to_host: Annotated[str, Field(description="New hostname, e.g. 'app.corp'.")],
    target_profile: Annotated[str | None, Field(description="Write the rehosted copy into this profile (created if missing) and leave the source untouched.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Switch a Bot profile's entries to another hostname (WRITE — requires NETSCALER_ALLOW_WRITE).

    The bot counterpart of rehost_waf_profile, for the entries that carry absolute URLs or host-bearing
    expressions. Most bot URLs (rate-limit, CAPTCHA, trap) are paths and need no switching, so this
    often reports nothing to do — copy such a profile with import_bot_profile instead. Previews by
    default; persist with save_config.
    """
    return await _rehost_profile(
        bot.BOT, profile, from_host, to_host, target_profile, dry_run,
        tool="rehost_bot_profile", args=_call_args(locals()), confirm=confirm,
    )


# ---- tools: signatures, enforcement and violations (WAF + Bot) -----------

# Per feature: signature resource + projected fields, settings resource + projected fields.
_SIGNATURE_SOURCES = {
    "waf": (
        "appfwsignatures", ("name", "src", "encryptedversion"),
        "appfwsettings",
        ("signatureautoupdate", "signatureurl", "learning", "centralizedlearning", "defaultprofile",
         "undefaction", "sessiontimeout", "learnratelimit", "malformedreqaction", "ceflogging"),
    ),
    "bot": (
        "botsignature", ("name", "src", "comment", "response"),
        "botsettings",
        ("signatureautoupdate", "signatureurl", "defaultprofile", "defaultnonintrusiveprofile",
         "javascriptname", "sessiontimeout", "trapurlautogenerate", "proxyserver", "proxyport"),
    ),
}
_POLICY_FIELDS = ("name", "rule", "profilename", "hits", "undefhits", "comment")
_BOUND_FIELDS = ("boundto", "priority", "labeltype", "labelname", "gotopriorityexpression", "activepolicy")
_LOG_CHECK = re.compile(r"\b(?:APPFW|BOT)_[A-Z0-9_]+")
_LOG_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LOG_URL = re.compile(r"https?://\S+|(?<=\s)/\S*")


def _features(kind: str) -> list[str]:
    """Resolve a kind/feature argument into ['waf'], ['bot'] or both."""
    key = (kind or "both").strip().lower()
    if key not in ("waf", "bot", "both"):
        raise ValueError("kind must be 'waf', 'bot' or 'both'.")
    return ["waf", "bot"] if key == "both" else [key]


async def _profile_names() -> list[str]:
    """AppFw + Bot profile names, longest first, to attribute log lines to a profile (best effort)."""
    names: list[str] = []
    for resource in ("appfwprofile", "botprofile"):
        try:
            env = await _get_client().get("config", resource, attrs=("name",))
        except NitroError:
            continue
        names += [str(r.get("name")) for r in _rows(env, resource) if r.get("name")]
    return sorted(set(names), key=len, reverse=True)


async def _enforcement(kind: waf.ProfileKind, profile: str | None, limit: int) -> dict[str, Any]:
    """Policies of one family with their bind points, plus profiles no policy selects."""
    client = _get_client()
    policies = _rows(await client.get("config", kind.policy), kind.policy)
    if profile:
        policies = [p for p in policies if str(p.get("profilename") or "") == profile]
    selected = {str(p.get("profilename") or "") for p in policies}
    rows: list[dict[str, Any]] = []
    for policy in policies[: _clamp(limit, default=50, maximum=200)]:
        name = str(policy.get("name") or "")
        row = {k: policy.get(k) for k in _POLICY_FIELDS if policy.get(k) not in (None, "")}
        bindings: list[dict[str, Any]] = []
        try:
            env = await client.get("config", f"{kind.policy}_binding", resource_name=name)
        except NitroError as exc:
            row["bindings_error"] = str(exc)
        else:
            for attr, bound_rows in _one(env, f"{kind.policy}_binding").items():
                if not attr.endswith("_binding") or not isinstance(bound_rows, list):
                    continue
                where = attr.removeprefix(f"{kind.policy}_").removesuffix("_binding")
                for bound in bound_rows:
                    entry = {"bound_to_type": where}
                    entry.update({k: bound.get(k) for k in _BOUND_FIELDS if bound.get(k) not in (None, "")})
                    bindings.append(entry)
        row["bindings"] = bindings
        row["enforced"] = bool(bindings)
        rows.append(row)
    unused: list[str] = []
    try:
        env = await client.get("config", kind.profile, attrs=("name", "builtin"))
    except NitroError:
        env = {}
    for entry in _rows(env, kind.profile):
        name = str(entry.get("name") or "")
        builtin = entry.get("builtin") or []
        if name and name not in selected and "IMMUTABLE" not in (builtin if isinstance(builtin, list) else [builtin]):
            unused.append(name)
    return {"policies": rows, "profiles_without_policy": sorted(unused)}


@_tool
async def waf_violations(
    profile: Annotated[str | None, Field(description="AppFw profile name; omit for appliance-wide counters.")] = None,
    include_zero: Annotated[bool, Field(description="Also list checks that have counted nothing.")] = False,
    full: Annotated[bool, Field(description="Also return the raw stat object (every counter).")] = False,
) -> dict[str, Any]:
    """Which WAF checks are firing, per security check (stat tree, appfwprofile / appfw).

    Buckets NITRO's flat counters into one row per check with its 'violations' and 'logged' counts, plus
    request/response totals. This is the readiness check before switching a check to block: violations
    counted while the check only logs are what would start being blocked. With a profile it reads
    stat/appfwprofile, otherwise appliance-wide stat/appfw. NITRO exposes no per-violation detail — use
    recent_security_violations for the log lines behind the numbers.
    """
    client = _get_client()
    if profile:
        stats = _one(await client.get("stat", "appfwprofile", args={"name": profile}), "appfwprofile")
    else:
        stats = _one(await client.get("stat", "appfw"), "appfw")
    summary = waf.violation_summary(stats)
    checks = summary["checks"]
    if not include_zero:
        checks = {k: v for k, v in checks.items() if any(v.values())}
    out: dict[str, Any] = {
        "profile": profile,
        "scope": "profile" if profile else "appliance",
        "traffic": summary["traffic"],
        "checks": checks,
    }
    if full:
        out["raw_stats"] = stats
    return out


@_tool
async def list_signatures(
    kind: Annotated[str, Field(description="'waf', 'bot' or 'both'.")] = "both",
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Installed WAF / Bot signature objects and the matching appliance settings (config tree).

    Signatures are the vendor rule sets both features match requests against, so a stale set is a real
    gap. Per object NITRO exposes only the source URL and an 'encryptedversion' integer — there is no
    version string or update timestamp, so compare that integer or check the source. 'settings' carries
    the signature auto-update switch and URL plus the related appliance defaults (appfwsettings /
    botsettings). Read-only.
    """
    client = _get_client()
    out: dict[str, Any] = {}
    for feature in _features(kind):
        resource, fields, settings_resource, settings_fields = _SIGNATURE_SOURCES[feature]
        section: dict[str, Any] = {}
        try:
            rows = _rows(await client.get("config", resource), resource)
            section["signatures"] = rows if full else [_pick(r, fields) for r in rows]
        except NitroError as exc:
            section["signatures_error"] = str(exc)
        try:
            settings = _one(await client.get("config", settings_resource), settings_resource)
            section["settings"] = settings if full else _pick(settings, settings_fields)
        except NitroError as exc:
            section["settings_error"] = str(exc)
        out[feature] = section
    return out


@_tool
async def update_signatures(
    kind: Annotated[str, Field(description="'waf' or 'bot'.")],
    name: Annotated[str, Field(description="Signature object name, as listed by list_signatures.")],
    merge_default: Annotated[bool, Field(description="WAF only: merge the fetched rules with the default signatures (NITRO 'mergedefault').")] = False,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Re-fetch a signature object from its configured source URL (WRITE — requires NETSCALER_ALLOW_WRITE).

    The same action as 'update appfw signatures' / 'update bot signatures': it pulls the newest rules
    from the object's own src URL and cannot change that URL. The appliance has to reach that URL (NITRO
    answers 3319 / 1768 when it cannot, 3323 when a sha1 check fails). New rules take effect at once for
    every profile bound to the object, so prefer a change window; persist with save_config.
    """
    args = _call_args(locals())
    features = _features(kind)
    if len(features) != 1:
        raise ValueError("kind must be 'waf' or 'bot' for an update.")
    if not dry_run:
        _require_write()
    resource = _SIGNATURE_SOURCES[features[0]][0]
    body: dict[str, Any] = {"name": name}
    if features[0] == "waf" and merge_default:
        body["mergedefault"] = True
    preview = {
        "dry_run": True,
        "kind": features[0],
        "would_post": f"config/{resource}?action=update",
        "body": body,
        "next": "Call again with dry_run=false to update (needs NETSCALER_ALLOW_WRITE).",
    }
    change = {"args": args, "plan": {"resource": resource, "body": body}}
    summary = f"Update {features[0]} signature object '{name}' from its source URL."
    if not _gate("update_signatures", change, summary, preview, dry_run=dry_run, confirm=confirm):
        return preview
    await _get_client().action(resource, "update", body)
    return {"dry_run": False, "kind": features[0], "updated": name}


@_tool
async def list_enforcement(
    kind: Annotated[str, Field(description="'waf', 'bot' or 'both'.")] = "both",
    profile: Annotated[str | None, Field(description="Only policies that select this profile.")] = None,
    limit: Annotated[int, Field(description="Max policies inspected per feature (each costs one extra call).", ge=1, le=200)] = 50,
) -> dict[str, Any]:
    """Trace the enforcement path: which policies select a profile and where those policies are bound.

    A profile does nothing until a policy selects it and that policy is bound — to a vserver, a policy
    label or globally. Per policy this shows its rule, hit counters and every bind point, flags policies
    that are bound nowhere ('enforced': false), and lists profiles no policy selects. That is the usual
    reason a freshly imported or rehosted profile seems to have no effect. Read-only.
    """
    return {
        feature: await _enforcement(waf.WAF if feature == "waf" else bot.BOT, profile, limit)
        for feature in _features(kind)
    }


@_tool
async def recent_security_violations(
    feature: Annotated[str, Field(description="'waf', 'bot' or 'both' — which log lines to keep (APPFW_* / BOT_*).")] = "both",
    contains: Annotated[str | None, Field(description="Only lines containing this (case-insensitive): a URL, profile name or client IP.")] = None,
    loglevel: Annotated[str, Field(description="Syslog level to pull: ALL, EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL or DEBUG.")] = "ALL",
    limit: Annotated[int, Field(description="How many recent messages to pull (NITRO caps at 256).", ge=1, le=256)] = 100,
) -> dict[str, Any]:
    """Recent WAF / Bot log lines from the appliance's audit messages (config tree, auditmessages).

    NITRO has no structured violation records, so this pulls the raw syslog buffer and keeps the APPFW_*
    / BOT_* lines, pulling out the check, the profile, the client IP and the URL where a line carries
    them — the answer to "why was this request blocked?". Lines only exist while the check logs (its
    action list includes log), the format varies by build and CEF setting (the raw line is always
    included), and the account needs permission for 'show audit messages'. Read-only.
    """
    wanted = tuple(f"{'APPFW' if f == 'waf' else 'BOT'}_" for f in _features(feature))
    env = await _get_client().get(
        "config",
        "auditmessages",
        args={"loglevel": (loglevel or "ALL").strip().upper(), "numofmesgs": _clamp(limit, default=100, maximum=256)},
    )
    profiles = await _profile_names()
    messages: list[dict[str, Any]] = []
    by_check: dict[str, int] = {}
    for row in _rows(env, "auditmessages"):
        line = str(row.get("value") or "")
        found = _LOG_CHECK.search(line)
        if not found or not found.group().startswith(wanted):
            continue
        if contains and contains.lower() not in line.lower():
            continue
        check = found.group()
        by_check[check] = by_check.get(check, 0) + 1
        tail = line[found.end():]
        url = _LOG_URL.search(tail)
        client_ip = _LOG_IP.search(tail)
        lowered = line.lower()
        messages.append({
            "check": check,
            "profile": next((p for p in profiles if p and p in line), None),
            "client_ip": client_ip.group() if client_ip else None,
            "url": url.group() if url else None,
            "blocked": "blocked" in lowered and "not blocked" not in lowered,
            "raw": line,
        })
    return {
        "feature": (feature or "both").strip().lower(),
        "loglevel": (loglevel or "ALL").strip().upper(),
        "count": len(messages),
        "by_check": dict(sorted(by_check.items(), key=lambda kv: -kv[1])),
        "messages": messages,
    }


# ---- tools: several appliances (GSLB peers, standalone boxes, separate HA pairs) ----

# What identifies the same object on every instance, and which configuration attributes must agree.
# gslbsite leaves out sitetype: a site is LOCAL on its own appliance and REMOTE everywhere else.
_COMPARE: dict[str, tuple[str, tuple[str, ...]]] = {
    "gslbsite": ("sitename", (
        "siteipaddress", "publicip", "metricexchange", "nwmetricexchange", "sessionexchange",
        "triggermonitor", "parentsite",
    )),
    "gslbvserver": ("name", (
        "servicetype", "dnsrecordtype", "lbmethod", "backuplbmethod", "persistencetype", "persistenceid",
        "timeout", "tolerance", "iptype", "state", "considereffectivestate", "mir", "disableprimaryondown",
        "backupvserver",
    )),
    "gslbservice": ("servicename", (
        "servicetype", "ipaddress", "port", "publicip", "publicport", "sitename", "cnameentry",
        "servername", "state", "maxclient",
    )),
}
# The identity of a row inside the gslbvserver_binding aggregate, and its comparable attributes.
_GSLB_BINDING_KEYS = ("servicename", "servicegroupname", "domainname", "policyname")
_GSLB_BINDING_ATTRS = ("weight", "ttl", "backupip", "cookietimeout", "sitedomainttl", "priority", "gotopriorityexpression")
# Runtime attributes left out of a generic (non-curated) comparison.
_VOLATILE = re.compile(r"state|time|ticks|health|hits|count|status|cur|active|total|rate|^_")


def _keyed(rows: list[dict[str, Any]], key: str, attrs: tuple[str, ...] | None) -> dict[str, dict[str, Any]]:
    """Rows by their ``key`` value, reduced to ``attrs`` (or every non-runtime attribute)."""
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get(key) is None:
            continue
        if attrs is None:
            out[str(row[key])] = {a: v for a, v in row.items() if a != key and not _VOLATILE.search(a)}
        else:
            out[str(row[key])] = {a: row.get(a) for a in attrs}
    return out


def _diff(found: dict[str, dict[str, dict[str, Any]]], limit: int) -> dict[str, Any]:
    """Compare one resource's keyed objects across instances: what is missing where, and what differs."""
    names = list(found)
    keys = sorted(set().union(*found.values()))
    missing: dict[str, list[str]] = {n: [k for k in keys if k not in found[n]] for n in names}
    different: list[dict[str, Any]] = []
    for key in keys:
        holders = [n for n in names if key in found[n]]
        if len(holders) < 2:
            continue
        delta = {}
        for attr in sorted(set().union(*(found[n][key] for n in holders))):
            values = {n: found[n][key].get(attr) for n in holders}
            if len({json.dumps(v, sort_keys=True, default=str) for v in values.values()}) > 1:
                delta[attr] = values
        if delta:
            different.append({"key": key, "attrs": delta})
    differ = {d["key"] for d in different}
    out: dict[str, Any] = {
        "objects": len(keys),
        "identical": sum(1 for k in keys if k not in differ and all(k in found[n] for n in names)),
    }
    if any(missing.values()):
        out["missing_on"] = {n: v[:limit] for n, v in missing.items() if v}
        out["missing_counts"] = {n: len(v) for n, v in missing.items() if v}
    if different:
        out["different"] = different[:limit]
        out["different_count"] = len(different)
    return out


async def _fetch_keyed(
    resourcetype: str, key: str, attrs: tuple[str, ...] | None, extra: tuple[str, ...] = ()
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """GET a config collection on the current instance; returns (keyed for comparison, raw rows)."""
    wire = (key, *attrs, *extra) if attrs is not None else None
    rows = _rows(await _get_client().get("config", resourcetype, attrs=wire), resourcetype)
    return _keyed(rows, key, attrs), rows


async def _gslb_snapshot(limit: int) -> dict[str, Any]:
    """Everything GSLB on the current instance, keyed for comparison, plus its LOCAL site(s)."""
    out: dict[str, Any] = {}
    sites, site_rows = await _fetch_keyed("gslbsite", *_COMPARE["gslbsite"], extra=("sitetype",))
    out["gslbsite"] = sites
    out["local_sites"] = sorted(
        str(r.get("sitename")) for r in site_rows if str(r.get("sitetype", "")).upper() == "LOCAL"
    )
    out["gslbvserver"], _ = await _fetch_keyed("gslbvserver", *_COMPARE["gslbvserver"])
    out["gslbservice"], _ = await _fetch_keyed("gslbservice", *_COMPARE["gslbservice"])
    # One aggregate GET per vserver returns all of its bindings (services, domains, policies).
    bindings: dict[str, dict[str, dict[str, Any]]] = {}
    for vserver in sorted(out["gslbvserver"])[: _clamp(limit, maximum=500)]:
        agg = _one(await _get_client().get("config", "gslbvserver_binding", resource_name=vserver), "gslbvserver_binding")
        for btype, rows in agg.items():
            if not btype.endswith("_binding") or not isinstance(rows, list):
                continue
            for row in rows:
                ident = next((row[k] for k in _GSLB_BINDING_KEYS if row.get(k)), None)
                if ident is not None:
                    attrs = {a: row[a] for a in _GSLB_BINDING_ATTRS if a in row}
                    bindings.setdefault(btype, {})[f"{vserver} -> {ident}"] = attrs
    out["bindings"] = bindings
    return out


@mcp.tool()
async def list_instances(
    probe: Annotated[bool, Field(description="Also contact each instance: firmware version and HA role (one quick read each), and whether it answers at all.")] = False,
) -> dict[str, Any]:
    """List the NetScaler appliances this server is configured for, and the default one.

    Every other tool takes instance=<name> (omit it for the default); read tools also take
    instance='all' to run on every appliance at once. probe=true tells standalone boxes, GSLB peers and
    HA pairs apart: 'ha_peers' is empty for a standalone appliance. compare_instances diffs
    configuration between them.
    """
    clients = _load_clients()
    rows: dict[str, dict[str, Any]] = {
        name: {
            "url": c.settings.base_origin,
            "default": name == _default_instance,
            "auth_mode": c.settings.auth_mode,
            "allow_write": c.settings.allow_write,
            "confirm_write": c.settings.confirm_write,
        }
        for name, c in clients.items()
    }
    if probe:
        async def probe_one() -> dict[str, Any]:
            client = _get_client()
            version = _one(await client.get("config", "nsversion"), "nsversion").get("version")
            nodes = _rows(await client.get("config", "hanode", attrs=_HANODE_FIELDS), "hanode")
            local = next((n for n in nodes if str(n.get("id")) == "0"), {})
            return {
                "reachable": True,
                "version": version,
                "ha_role": local.get("masterstate"),
                "ha_peers": [n.get("ipaddress") for n in nodes if str(n.get("id")) != "0"],
            }

        for name, result in (await _on_each(probe_one)).items():
            rows[name].update({"reachable": False, **result} if "error" in result else result)
    return {"default": _default_instance, "count": len(rows), "instances": rows}


@mcp.tool()
async def compare_instances(
    resourcetype: Annotated[str, Field(description="'gslb' (sites, vservers, services and every vserver's service/domain bindings), or any config resource type, e.g. 'gslbservice', 'appfwprofile', 'sslcertkey'.")] = "gslb",
    key: Annotated[str | None, Field(description="Attribute that names the same object on every instance. Default: servicename for gslbservice, sitename for gslbsite, else 'name'.")] = None,
    attrs: Annotated[str | None, Field(description="Comma-separated attributes to compare. Default: a curated configuration set for GSLB resources, else every attribute except runtime ones (states, counters, timestamps).")] = None,
    instances: Annotated[str | None, Field(description="Comma-separated instance names to compare; default: all configured.")] = None,
    limit: Annotated[int, Field(description="Max missing / differing objects listed per resource (totals are always reported).", ge=1, le=500)] = 50,
) -> dict[str, Any]:
    """Diff configuration between NetScaler instances that are not an HA pair (nothing syncs them).

    Typical use: GSLB peers. Every participating site must carry the same GSLB sites, vservers,
    services and bindings, and only HA pairs sync that by themselves. resourcetype='gslb' compares all of
    it, including each GSLB vserver's service and domain bindings, and checks that each site is LOCAL
    on exactly one compared instance (sitetype itself legitimately differs). Any other config resource
    type is compared object by object, keyed by `key`. Instances that fail (unreachable, feature off)
    are listed under 'errors' and left out of the diff.
    """
    names = [_resolve_instance(n, write=False) for n in (_csv(instances) or tuple(_load_clients()))]
    names = list(dict.fromkeys(names))
    if len(names) < 2:
        raise ValueError(
            f"compare_instances needs at least two instances; configured: {', '.join(_load_clients())}. "
            "Add more appliances via NETSCALER_INSTANCES."
        )
    rt = (resourcetype or "").strip()
    if rt.lower() == "gslb":
        snaps = await _on_each(lambda: _gslb_snapshot(limit), names)
    else:
        default_key, default_attrs = _COMPARE.get(rt, ("name", None))
        wanted = _csv(attrs) or default_attrs
        key = (key or "").strip() or default_key

        async def fetch() -> dict[str, Any]:
            keyed, _ = await _fetch_keyed(rt, key, wanted)
            return {rt: keyed}

        snaps = await _on_each(fetch, names)

    errors = {n: s["error"] for n, s in snaps.items() if "error" in s}
    ok = {n: s for n, s in snaps.items() if "error" not in s}
    out: dict[str, Any] = {"instances": names}
    if errors:
        out["errors"] = errors
    if len(ok) < 2:
        out["in_sync"] = None
        out["note"] = "Fewer than two instances answered, so nothing was compared."
        return out

    resources: dict[str, Any] = {}
    plain = [r for r in next(iter(ok.values())) if r not in ("local_sites", "bindings")]
    for res in plain:
        resources[res] = _diff({n: s[res] for n, s in ok.items()}, limit)
    if rt.lower() == "gslb":
        btypes = sorted(set().union(*(s["bindings"] for s in ok.values())))
        for btype in btypes:
            resources[btype] = _diff({n: s["bindings"].get(btype, {}) for n, s in ok.items()}, limit)
        local = {n: s["local_sites"] for n, s in ok.items()}
        out["local_sites"] = local
        warnings = []
        holders: dict[str, list[str]] = {}
        for n, sites in local.items():
            if not sites:
                warnings.append(f"{n} has no LOCAL GSLB site.")
            for site in sites:
                holders.setdefault(site, []).append(n)
        warnings += [f"GSLB site {site} is LOCAL on {', '.join(h)}." for site, h in holders.items() if len(h) > 1]
        if warnings:
            out["warnings"] = warnings
    out["in_sync"] = not out.get("warnings") and all(
        "missing_on" not in r and "different" not in r for r in resources.values()
    )
    out["resources"] = resources
    return out


# ---- tools: traffic management objects (LB, CS, SSL, rewrite/responder, GSLB, DNS) -------

_KIND_DESC = (
    "Object type. LB/CS: lb_vserver, cs_vserver, service, service_group, server, cs_policy, cs_action, monitor. "
    "SSL: ssl_certkey, ssl_vserver / ssl_service / ssl_service_group (the SSL side of a vserver / service; "
    "update only), ssl_profile, ssl_policy, ssl_action. Rewrite/responder: rewrite_policy, rewrite_action, "
    "rewrite_policylabel, responder_policy, responder_action, responder_policylabel, responder_htmlpage. "
    "Policy data: policy_patset, policy_dataset, policy_stringmap, policy_expression. GSLB: gslb_vserver, "
    "gslb_service, gslb_site. DNS: dns_a, dns_aaaa, dns_cname, dns_txt, dns_ns, dns_soa."
)
_STATE_KIND_DESC = "Object type: lb_vserver, cs_vserver, service, service_group, server or gslb_vserver."
_BINDING_DESC = (
    "Which relation. LB/CS: lb_vserver_service, lb_vserver_service_group, service_group_member (server:port), "
    "service_monitor, service_group_monitor, cs_vserver_policy (CS policies, with priority), cs_vserver_default "
    "(default LB vserver). Policies per feature on a vserver: lb_vserver_<f>_policy / cs_vserver_<f>_policy with "
    "f = responder, rewrite, appfw, bot, cache, cmp, transform (priority; bindpoint REQUEST/RESPONSE; "
    "gotopriorityexpression, invoke, labeltype, labelname); lb_vserver_analytics_profile, "
    "cs_vserver_analytics_profile. SSL: ssl_vserver_certkey (snicert, ca, crlcheck, ocspcheck), "
    "ssl_service_certkey, ssl_service_group_certkey, ssl_vserver_policy, ssl_profile_cipher (cipherpriority), "
    "ssl_certkey_link (certificate → CA certificate, one at most). Global (no name): rewrite_global_policy, "
    "responder_global_policy (priority, type e.g. REQ_DEFAULT / RES_DEFAULT). Labels: "
    "rewrite_policylabel_policy, responder_policylabel_policy. Data: policy_patset_pattern (String), "
    "policy_dataset_value (value), policy_stringmap_pattern (key + value). GSLB: gslb_vserver_service, "
    "gslb_vserver_domain."
)
_DRY_RUN_DESC = (
    "Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE and, unless "
    "NETSCALER_CONFIRM_WRITE=false, the confirm code from the preview."
)
_CSPOLICY_FIELDS = lb.KINDS["cs_policy"].fields
_CSACTION_FIELDS = lb.KINDS["cs_action"].fields
_LBMONITOR_FIELDS = lb.KINDS["monitor"].fields
# Runtime values that legitimately differ between appliances; left out of the post-batch comparison.
_RUNTIME = frozenset({"curstate", "effectivestate", "svrstate", "state", "status", "hits", "daystoexpiration",
                      "servicegroupeffectivestate", "referencecount", "monstate", "undefhits", "clientcertnotafter"})


def _batch_preview() -> bool:
    """Whether this call is apply_batch's preview pass (earlier steps have not run yet)."""
    batch = _batch.get()
    return batch is not None and "record" in batch


async def _object(k: lb.Kind, name: str) -> dict[str, Any] | None:
    """The live object, or None when it doesn't exist."""
    try:
        env = await _get_client().get("config", k.resource, resource_name=name)
    except NitroError as exc:
        if _is_missing(exc):
            return None
        raise
    return _one(env, k.resource) or None


async def _records(k: lb.Kind, name: str) -> list[dict[str, Any]]:
    """Every live record under a name (DNS kinds keep several); [] when there is none."""
    try:
        env = await _get_client().get("config", k.resource, resource_name=name)
    except NitroError as exc:
        if _is_missing(exc):
            return []
        raise
    return _rows(env, k.resource)


async def _bound_rows(b: lb.Binding, name: str | None) -> list[dict[str, Any]]:
    """The live rows of one binding type; [] when nothing is bound or the parent doesn't exist (yet)."""
    if b.link:
        obj = await _object(lb.KINDS[b.parent], name or "")
        linked = (obj or {}).get("linkcertkeyname")
        return [{"linkcertkeyname": linked}] if linked else []
    try:
        env = await _get_client().get("config", b.resource, resource_name=name or None)
    except NitroError as exc:
        if _is_missing(exc):
            return []
        raise
    return _rows(env, b.resource)


async def _cs_routes(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """CS policy bindings in evaluation order with each policy's rule and where its action sends traffic."""
    rows = sorted(rows, key=lambda r: waf.as_int(r.get("priority")) or 0)[:limit]
    policies = await asyncio.gather(*(_object(lb.KINDS["cs_policy"], r.get("policyname", "")) for r in rows))
    actions: dict[str, dict[str, Any] | None] = {}
    for policy in policies:
        if policy and policy.get("action") and policy["action"] not in actions:
            actions[policy["action"]] = None
    found = await asyncio.gather(*(_object(lb.KINDS["cs_action"], a) for a in actions))
    actions = dict(zip(actions, found))
    routes = []
    for row, policy in zip(rows, policies):
        policy = policy or {}
        action = actions.get(policy.get("action") or "") or {}
        target = (row.get("targetlbvserver") or action.get("targetlbvserver") or action.get("targetvserver")
                  or action.get("targetvserverexpr"))
        routes.append({
            "priority": row.get("priority"), "policy": row.get("policyname"), "rule": policy.get("rule"),
            "action": policy.get("action"), "target": target, "hits": row.get("hits", policy.get("hits")),
            "gotopriorityexpression": row.get("gotopriorityexpression"),
            "target_via": "binding" if row.get("targetlbvserver") else "action",
            "lb_target": row.get("targetlbvserver") or action.get("targetlbvserver"),
        })
    return routes


@_tool
async def get_object(
    kind: Annotated[str, Field(description=_KIND_DESC)],
    name: Annotated[str, Field(description="The object's name (its key: policyname for cs_policy, monitorname for monitor, certkey for ssl_certkey, vservername for ssl_vserver, hostname / domain / aliasname for DNS records).")],
    limit: Annotated[int, Field(description="Max rows per binding type.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return the raw object and binding rows instead of a trimmed view.")] = False,
) -> dict[str, Any]:
    """One traffic-management object with everything bound to it (config tree, <resource> + <resource>_binding).

    lb_vserver → services / service groups (state, weight), bound policies per feature and analytics
    profiles; cs_vserver → 'routes': the CS policies in priority order with rule, action and target LB
    vserver, plus the default LB vserver; service_group → members and monitors; ssl_vserver → certificates
    (SNI or not), SSL policies, ciphers; ssl_certkey → expiry and the linked CA; DNS kinds → every record
    under the name. Passwords are never shown. Use list_objects to find names, vserver_diagnose for a
    path's live health.
    """
    k = lb.kind(kind)
    if k.multi:
        rows = await _records(k, name)
        if not rows:
            raise ValueError(f"No {k.name} record named {name!r} (NITRO {k.resource}).")
        return {"kind": k.name, "count": len(rows), k.resource: lb.mask(rows if full else [_pick(r, k.fields) for r in rows])}
    obj = await _object(k, name)
    if obj is None:
        raise ValueError(f"No {k.name} named {name!r} (NITRO {k.resource}).")
    out: dict[str, Any] = {"kind": k.name, k.resource: lb.mask(obj if full else _pick(obj, k.fields))}
    try:
        aggregate = _one(await _get_client().get("config", k.aggregate, resource_name=name), k.aggregate)
    except NitroError as exc:
        out["bindings"] = {"error": str(exc)}
        return out
    bindings: dict[str, Any] = {}
    for resource, rows in aggregate.items():
        if not isinstance(rows, list) or not rows:
            continue
        modelled = lb.BINDING_BY_RESOURCE.get(resource)
        fields = None if full or modelled is None else modelled.fields
        bindings[resource] = [r if full else lb.trim_row(r, fields, k.key) for r in rows[:limit]]
        if len(rows) > limit:
            bindings[resource + "_total"] = len(rows)
    out["bindings"] = bindings
    if k.name == "cs_vserver":
        out["routes"] = await _cs_routes(aggregate.get("csvserver_cspolicy_binding") or [], limit)
        default = aggregate.get("csvserver_lbvserver_binding") or []
        out["default_lb_vserver"] = default[0].get("lbvserver") if default else None
    return out


@_tool
async def list_objects(
    kind: Annotated[str, Field(description=_KIND_DESC)],
    name_contains: Annotated[str | None, Field(description="Case-insensitive substring of the name (key) to keep.")] = None,
    limit: Annotated[int, Field(description="Max objects to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List objects of any kind above (config tree), e.g. every SSL profile, rewrite action or DNS A record.

    With name_contains the first 500 objects are fetched and filtered here. Passwords are never shown.
    """
    k = lb.kind(kind)
    fetch = 500 if name_contains else limit
    result = await _get_list("config", k.resource, k.fields, limit=fetch, full=full)
    rows = result.get(k.resource) or []
    if name_contains:
        needle = name_contains.lower()
        rows = [r for r in rows if needle in str(r.get(k.key, "")).lower()]
    rows = rows[: _clamp(limit)]
    return {"kind": k.name, "count": len(rows), k.resource: lb.mask(rows)}


@_tool
async def list_cs_policies(
    name: Annotated[str | None, Field(description="Exact CS policy name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List content-switching policies: rule, action and hits (config tree, cspolicy).

    get_object(kind='cs_vserver') shows them in the order a CS vserver evaluates them, with targets.
    """
    return await _get_list("config", "cspolicy", _CSPOLICY_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_cs_actions(
    name: Annotated[str | None, Field(description="Exact CS action name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max actions to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List content-switching actions: the LB vserver (or expression) each sends traffic to (config tree, csaction)."""
    return await _get_list("config", "csaction", _CSACTION_FIELDS, name=name, limit=limit, full=full)


@_tool
async def list_lb_monitors(
    name: Annotated[str | None, Field(description="Exact monitor name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max monitors to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List load-balancing health monitors: type, interval, timeouts and what they send/expect (config tree, lbmonitor)."""
    return await _get_list("config", "lbmonitor", _LBMONITOR_FIELDS, name=name, limit=limit, full=full)


@_tool
async def add_object(
    kind: Annotated[str, Field(description=_KIND_DESC)],
    name: Annotated[str, Field(description="Name (key) of the new object; for DNS records the host / domain / alias name.")],
    settings: Annotated[dict[str, Any], Field(description="Its NITRO attributes (the CLI option names, lower case), e.g. lb_vserver {\"servicetype\": \"HTTP\", \"ipv46\": \"10.0.0.20\", \"port\": 80}; server {\"ipaddress\": \"10.0.0.31\"}; cs_policy {\"rule\": \"HTTP.REQ.HOSTNAME.EQ(\\\"app.example.com\\\")\", \"action\": \"ca_app\"}; ssl_certkey {\"cert\": \"app.example.com.pem\", \"key\": \"app.example.com.key\", \"inform\": \"PEM\", \"expirymonitor\": \"ENABLED\", \"notificationperiod\": 30} (PFX: inform PFX + passplain); ssl_profile {\"sslprofiletype\": \"BackEnd\", \"tls12\": \"DISABLED\", \"tls13\": \"ENABLED\"}; rewrite_action {\"type\": \"replace\", \"target\": \"...\", \"stringbuilderexpr\": \"...\"}; responder_htmlpage {\"src\": \"http://...\"}; policy_dataset {\"type\": \"ipv4\"}; gslb_service {\"servicetype\": \"HTTP\", \"ip\": \"10.0.0.40\", \"port\": 80, \"sitename\": \"site_a\"}; dns_a {\"ipaddress\": \"10.0.0.50\", \"ttl\": 300}.")],
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create any traffic-management object listed under kind (WRITE — requires NETSCALER_ALLOW_WRITE).

    Previews the exact NITRO body by default (passwords masked). An object that already exists — for DNS
    kinds, a record with the same value — is left alone (use update_object). Certificate files must be on
    the appliance first (upload_ssl_file). Bind things together with change_bindings; put a whole setup
    into apply_batch for one confirmation. Live immediately once applied; persist with save_config.
    """
    args = _call_args(locals())
    k = lb.kind(kind, operation="add")
    body = lb.add_body(k, name, settings)
    if not dry_run:
        _require_write()
    if k.multi:
        exists = any(lb.same_record(k, r, body) for r in await _records(k, name))
    else:
        exists = await _object(k, name) is not None
    out: dict[str, Any] = {
        "kind": k.name, "name": name, "dry_run": dry_run,
        "result": "exists: nothing to add (change it with update_object)" if exists else "would add",
        "nitro": {k.resource: lb.mask(body)},
    }
    if k.add_action:
        out["nitro_action"] = k.add_action
    summary = f"Add {k.name} '{name}'."
    if not _gate("add_object", {"args": args, "plan": None if exists else body}, summary, out,
                 dry_run=dry_run, confirm=confirm, writes=not exists):
        return out
    if not exists:
        if k.add_action:
            await _get_client().action(k.resource, k.add_action, body)
        else:
            await _get_client().add(k.resource, body)
        out["result"] = "added"
    return out


@_tool
async def update_object(
    kind: Annotated[str, Field(description=_KIND_DESC)],
    name: Annotated[str, Field(description="The object's name (key).")],
    settings: Annotated[dict[str, Any] | None, Field(description="Attributes to set, e.g. {\"lbmethod\": \"ROUNDROBIN\"}; ssl_service_group {\"sslprofile\": \"prof_backend_tls13\"}; ssl_certkey {\"cert\": \"app-2027.pem\", \"key\": \"app-2027.key\"} replaces the certificate (update ssl certKey; nodomaincheck true if the new one has other names).")] = None,
    unset: Annotated[list[str] | None, Field(description="Attributes to reset to their default (NITRO unset), e.g. [\"persistencetype\", \"comment\"].")] = None,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change settings of any traffic-management object listed under kind, e.g. assign an SSL profile to
    a vserver's / service group's SSL side or renew a certificate (WRITE — requires NETSCALER_ALLOW_WRITE).

    Shows before/after per attribute and only sends attributes whose value differs. ssl_certkey cert / key /
    password / inform go through 'update ssl certKey' and are always sent (a renewed file often keeps its
    name). Attributes NetScaler can't change in place are rejected by the appliance and named in the
    result. Inside apply_batch, an object created by an earlier step may not exist yet in the preview.
    Passwords are masked. Previews by default. Live immediately once applied; persist with save_config.
    """
    args = _call_args(locals())
    k = lb.kind(kind, operation="update")
    if not settings and not unset:
        raise ValueError("Pass settings and/or unset.")
    if not dry_run:
        _require_write()
    current = await _object(k, name)
    pending = current is None and _batch_preview()
    if current is None and not pending:
        raise ValueError(f"No {k.name} named {name!r} (NITRO {k.resource}).")
    changes, action, reset, table = lb.update_plan(k, current or {}, settings, unset)
    out: dict[str, Any] = {"kind": k.name, "name": name, "dry_run": dry_run, "changes": table,
                           "unchanged": sorted(set(settings or {}) - set(changes) - set(action))}
    if pending:
        out["note"] = f"{k.name} '{name}' does not exist yet; an earlier step of this batch is expected to create it."
    summary = f"Change {len(table)} setting(s) of {k.name} '{name}'."
    # bound to the request itself: inside a batch the object may only exist once earlier steps ran
    if not _gate("update_object", {"args": args}, summary, out, dry_run=dry_run, confirm=confirm,
                 writes=bool(table)):
        return out
    ident = {k.key: name, **{a: (current or {}).get(a) for a in k.ident_extra}}
    errors = await _update_attrs(k.resource, ident, changes) if changes else []
    if action:
        try:
            await _get_client().action(k.resource, "update", {k.key: name, **action})
        except NitroError as exc:
            errors.append(f"{k.resource} update: {exc}")
    if reset:
        try:
            await _get_client().action(k.resource, "unset", {**ident, **{a: True for a in reset}})
        except NitroError as exc:
            errors.append(f"{k.resource} unset {', '.join(reset)}: {exc}")
    if errors:
        out["error"] = "; ".join(errors)
    return out


@_tool
async def set_object_state(
    kind: Annotated[str, Field(description=_STATE_KIND_DESC)],
    names: Annotated[list[str], Field(description="Objects to switch, e.g. [\"srv_web1\", \"srv_web2\"].", min_length=1, max_length=50)],
    enabled: Annotated[bool, Field(description="true = enable, false = disable (take out of service).")],
    members: Annotated[list[str] | None, Field(description="service_group only: switch just these members ('<server or IP>:<port>') instead of the whole group.")] = None,
    graceful: Annotated[bool, Field(description="Disable only (service, service_group, server): let existing connections finish (graceful YES).")] = False,
    delay_seconds: Annotated[int | None, Field(description="Disable only (service, service_group, server): seconds until the object goes out of service.", ge=0)] = None,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Enable or disable LB/CS/GSLB vservers, services, service groups (or single members) and servers
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    Disabling a server takes it out of every service and group that uses it; disabling a group member
    only drains it from that group. Shows the current state per target. Previews by default. Live
    immediately once applied; persist with save_config.
    """
    args = _call_args(locals())
    k = lb.kind(kind, stateful=True)
    if members and k.name != "service_group":
        raise ValueError("members is only for kind='service_group'.")
    if (graceful or delay_seconds is not None) and (enabled or not k.graceful):
        raise ValueError("graceful / delay_seconds only apply when disabling a service, service_group or server.")
    if not dry_run:
        _require_write()
    names = list(dict.fromkeys(n.strip() for n in names if n and n.strip()))
    member_entries = [lb.entry(lb.BINDINGS["service_group_member"], m) for m in members or []]
    extra: dict[str, Any] = {}
    if not enabled and delay_seconds is not None:
        extra["delay"] = delay_seconds
    if not enabled and graceful:
        extra["graceful"] = "YES"
    targets: list[dict[str, Any]] = []
    for name in names:
        if member_entries:
            rows = await _bound_rows(lb.BINDINGS["service_group_member"], name)
            for m in member_entries:
                row = next((r for r in rows if lb.matches(lb.BINDINGS["service_group_member"], r, m)), None)
                ident = lb.identity(lb.BINDINGS["service_group_member"], m)
                now = (row.get("svrstate") or row.get("state")) if row else "not a member"
                label = f"{name} {ident['servername']}:{ident['port']}"
                targets.append({"body": {k.key: name, **ident, **extra}, "now": now, "label": label})
            continue
        obj = await _object(k, name)
        now = obj.get(k.state_field) if obj else "not found"
        targets.append({"body": {k.key: name, **extra}, "now": now, "label": name})
    verb = "enable" if enabled else "disable"
    out: dict[str, Any] = {
        "kind": k.name, "dry_run": dry_run, "action": verb,
        "targets": [{**t["body"], "state_now": t["now"], "result": f"would {verb}"} for t in targets],
    }
    what = f"{k.name} member(s)" if member_entries else f"{k.name}(s)"
    summary = f"{verb.capitalize()} {len(targets)} {what}: {', '.join(t['label'] for t in targets)}."
    if not _gate("set_object_state", {"args": args, "plan": [t["body"] for t in targets]}, summary, out,
                 dry_run=dry_run, confirm=confirm, writes=bool(targets)):
        return out
    failed = 0
    for t, shown in zip(targets, out["targets"]):
        try:
            await _get_client().action(k.resource, verb, t["body"])
            shown["result"] = f"{verb}d"
        except NitroError as exc:
            shown["result"] = f"error: {exc}"
            failed += 1
    if failed:
        out["error"] = f"{failed} of {len(targets)} target(s) failed; see targets."
    return out


@_tool
async def change_bindings(
    binding: Annotated[str, Field(description=_BINDING_DESC)],
    name: Annotated[str | None, Field(description="The object entries are bound to (LB/CS vserver, service group, service, SSL vserver = the vserver's name, SSL profile, certificate, policy label, pattern set, GSLB vserver). Omit for the global bindings.")] = None,
    add: Annotated[list[dict[str, Any] | str] | None, Field(description="Entries to bind. A string is the plain name ('svc_web1', 'mon_http', a certkey, a pattern) or for members '<server or IP>:<port>'; an object adds attributes, e.g. {\"servicename\": \"svc_web1\", \"weight\": 2}, {\"policyname\": \"cp_api\", \"priority\": 100}, {\"policyname\": \"rw_404\", \"priority\": 100, \"bindpoint\": \"RESPONSE\"}, {\"certkeyname\": \"app.example.com\", \"snicert\": true}, {\"ciphername\": \"TLS1.3-AES256-GCM-SHA384\", \"cipherpriority\": 1}.")] = None,
    remove: Annotated[list[dict[str, Any] | str] | None, Field(description="Entries to unbind, same forms (the live binding supplies bindpoint / priority / SNI flags).")] = None,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Bind / unbind anything listed under binding: services and members, monitors, CS policies, feature
    policies (responder, rewrite, appfw, bot, …) and analytics profiles on vservers, certificates (SNI)
    and SSL policies on SSL vservers / services, ciphers on SSL profiles, the CA link of a certificate,
    global rewrite / responder policies, patterns of pattern sets / data sets / string maps, GSLB services
    and domains (WRITE — requires NETSCALER_ALLOW_WRITE).

    Plans against the live bindings: entries already bound the same way are skipped, an entry bound with
    a different weight / priority / flag is re-bound (unbind + bind, so it is briefly out of effect), and a
    new single entry (CS default, CA link) replaces the old one. Order keeps traffic flowing: new binds
    first, removals last. Previews by default. Live immediately once applied; persist with save_config.
    """
    args = _call_args(locals())
    b = lb.binding(binding)
    if b.parent is None and name:
        raise ValueError(f"{b.name} is a global binding; leave name out.")
    if b.parent is not None and not (name or "").strip():
        raise ValueError(f"{b.name} needs name: the {b.parent} the entries are bound to.")
    adds = [lb.entry(b, e) for e in add or []]
    removes = [lb.removal(b, e) for e in remove or []]
    if not adds and not removes:
        raise ValueError("Pass add and/or remove.")
    for item in adds:
        if missing := [a for a in b.required if item.get(a) in (None, "")]:
            raise ValueError(f"{b.name} entry {item} needs {', '.join(missing)}.")
    if not dry_run:
        _require_write()
    rows = await _bound_rows(b, name)
    steps = lb.plan_bindings(b, rows, adds, removes)
    ops = [s for s in steps if s["op"]]
    counts = {op: sum(s["op"] == op for s in ops) for op in ("bind", "rebind", "unbind")}
    where = {b.parent_attr: name} if b.parent else {"scope": "global"}
    out: dict[str, Any] = {
        "binding": b.name, **where, "dry_run": dry_run, "counts": counts,
        "steps": [{k: v for k, v in s.items() if k not in ("op", "unbind")} for s in steps],
    }
    target = f"'{name}'" if b.parent else "global"
    summary = (f"{b.name} on {target}: bind {counts['bind']}, re-bind {counts['rebind']}, "
               f"unbind {counts['unbind']}.")
    change = {"args": args, "plan": [[s["op"], s["entry"], s.get("unbind")] for s in ops]}
    if not _gate("change_bindings", change, summary, out, dry_run=dry_run, confirm=confirm, writes=bool(ops)):
        return out
    client = _get_client()

    async def bind(item: dict[str, Any]) -> str:
        try:
            if b.link:
                await client.action(b.resource, "link", {b.parent_attr: name, **item})
            else:
                await client.update(b.resource, {b.parent_attr: name, **item} if b.parent else item)
            return "bound"
        except NitroError as exc:
            return "exists" if _is_exists(exc) else f"error: {exc}"

    async def unbind(item: dict[str, Any]) -> str:
        try:
            if b.link:
                await client.action(b.resource, "unlink", {b.parent_attr: name})
            else:
                await client.delete(b.resource, name or None, args=lb.delete_args(b, item))
            return "unbound"
        except NitroError as exc:
            return "absent" if _is_missing(exc) else f"error: {exc}"

    for step, shown in zip(steps, out["steps"]):
        if step["op"] == "bind":
            shown["status"] = await bind(step["entry"])
        elif step["op"] == "unbind":
            shown["status"] = await unbind(step["entry"])
        elif step["op"] == "rebind":
            status = await unbind(step["unbind"])
            if status in ("unbound", "absent"):
                status = await bind(step["entry"])
            shown["status"] = "rebound" if status == "bound" else f"rebind failed: {status}"
    if failed := [s for s in out["steps"] if str(s.get("status", "")).startswith(("error", "rebind failed"))]:
        out["error"] = f"{len(failed)} step(s) failed; see steps."
    return out


@_tool
async def delete_object(
    kind: Annotated[str, Field(description=_KIND_DESC)],
    names: Annotated[list[str | dict[str, Any]], Field(description="Objects to delete, in this order, e.g. [\"cp_old\", \"ca_old\"] (a policy before the action it uses). DNS kinds: a name deletes every record under it; {\"hostname\": \"app.example.com\", \"ipaddress\": \"10.0.0.50\"} only the matching one.", min_length=1, max_length=50)],
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to delete; needs NETSCALER_ALLOW_WRITE and NETSCALER_ALLOW_DELETE, and always the confirm code from the preview.")] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Delete traffic-management objects of any deletable kind listed under kind (WRITE, DELETE — requires
    NETSCALER_ALLOW_WRITE and NETSCALER_ALLOW_DELETE; always confirmed).

    The preview lists, per object, what is still bound to it or uses it — e.g. the services on a server,
    the CS vservers a policy is bound to — so the user sees what goes with it or what blocks it. The
    appliance refuses deletes that would leave dangling references (unbind first with change_bindings)
    and, for some objects, removes their own bindings along with them. Unlike other writes this always
    asks for confirmation, even with NETSCALER_CONFIRM_WRITE=false. Gone immediately once applied;
    persist with save_config (until then a reboot without save brings it back).
    """
    args = _call_args(locals())
    k = lb.kind(kind, operation="delete")
    if not dry_run:
        _require_delete()
    targets: list[dict[str, Any]] = []
    plan: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in names:
        want = raw if isinstance(raw, dict) else {k.key: str(raw).strip()}
        name = str(want.get(k.key) or "").strip()
        if not name:
            raise ValueError(f"Each entry needs the {k.key}; got {raw!r}.")
        if k.multi:
            records = [r for r in await _records(k, name)
                       if all(lb._norm(r.get(a)) == lb._norm(v) for a, v in want.items() if a != k.key)]
            if not records:
                targets.append({"name": name, "result": "not found"})
            for r in records:
                del_args = {a: r.get(a) for a in k.delete_by}
                label = json.dumps([name, del_args], sort_keys=True, default=str)
                if label in seen:
                    continue
                seen.add(label)
                shown = {a: r.get(a) for a in k.multi}
                targets.append({"name": name, **shown, "args": del_args, "result": "would delete"})
                plan.append({"name": name, **shown, "args": del_args})
            continue
        if name in seen:
            continue
        seen.add(name)
        obj = await _object(k, name)
        if obj is None:
            targets.append({"name": name, "result": "not found"})
            continue
        refs: dict[str, int] = {}
        try:
            aggregate = _one(await _get_client().get("config", k.aggregate, resource_name=name), k.aggregate)
            refs = {r: len(v) for r, v in aggregate.items() if isinstance(v, list) and v}
        except NitroError:
            pass
        if waf.as_int(obj.get("referencecount")):
            refs["referencecount"] = waf.as_int(obj.get("referencecount"))
        del_args = {a: obj.get(a) for a in k.delete_by}
        targets.append({"name": name, **({"args": del_args} if del_args else {}), "bound": refs,
                        "result": "would delete"})
        plan.append({"name": name, "args": del_args, "bound": refs})
    out: dict[str, Any] = {"kind": k.name, "dry_run": dry_run, "targets": targets}
    summary = f"DELETE {len(plan)} {k.name}(s): {', '.join(p['name'] for p in plan)}."
    if any(p.get("bound") for p in plan):
        summary += " Some still have bindings or references (see targets)."
    if not _gate("delete_object", {"args": args, "plan": plan}, summary, out, dry_run=dry_run, confirm=confirm,
                 writes=bool(plan), always=True):
        return out
    failed = 0
    for target in targets:
        if target["result"] != "would delete":
            continue
        try:
            await _get_client().delete(k.resource, target["name"], args=target.get("args") or None)
            target["result"] = "deleted"
        except NitroError as exc:
            target["result"] = f"error: {exc}"
            failed += 1
    if failed:
        out["error"] = f"{failed} delete(s) failed; see targets."
    return out


# ---- SSL files -------------------------------------------------------------

_SSL_DIR = "/nsconfig/ssl"
_SSL_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,250}")


def _ssl_content(data: bytes) -> dict[str, Any]:
    """What a certificate / key file looks like, without showing it."""
    head = data[:4096].decode("ascii", "ignore")
    found = [label for marker, label in (
        ("BEGIN CERTIFICATE", "certificate"), ("PRIVATE KEY", "private key"),
        ("BEGIN CERTIFICATE REQUEST", "CSR"), ("BEGIN X509 CRL", "CRL"),
    ) if marker in head]
    if found:
        return {"format": "PEM", "contains": found}
    if data[:1] == b"\x30":
        return {"format": "DER or PFX (binary)", "contains": []}
    return {"format": "unknown", "contains": []}


def _drop_file(name: str) -> bytes:
    """Read a bare file name from NETSCALER_EXPORT_DIR (the files directory; nothing outside it)."""
    base = _get_client().settings.export_dir
    if not base:
        raise ValueError("file= needs NETSCALER_EXPORT_DIR (a mounted files directory); pass text or content_base64 instead.")
    if not _SSL_FILE.fullmatch(name or "") or ".." in name:
        raise ValueError(f"file must be a bare name in the files directory; got {name!r}.")
    path = Path(base) / name
    if not path.is_file():
        raise ValueError(f"{name!r} is not in the files directory.")
    return path.read_bytes()


async def _ssl_file(name: str) -> bytes | None:
    """The bytes of /nsconfig/ssl/<name> on the appliance, or None when there is no such file."""
    try:
        env = await _get_client().get("config", "systemfile", args={"filelocation": _SSL_DIR, "filename": name})
    except NitroError as exc:
        message = (exc.nitro_message or "").lower()
        if _is_missing(exc) or "not exist" in message or "no such file" in message:
            return None
        raise
    row = _one(env, "systemfile")
    if not row:
        return None
    try:
        return base64.b64decode(row.get("filecontent") or "")
    except ValueError:
        return b""


@_tool
async def upload_ssl_file(
    filename: Annotated[str, Field(description="Bare file name in /nsconfig/ssl, e.g. 'app.example.com-2027.pem' (letters, digits, '.', '_', '-').")],
    text: Annotated[str | None, Field(description="The file as text (PEM certificate, chain or key).")] = None,
    content_base64: Annotated[str | None, Field(description="Or the file as base64 (DER, PFX).")] = None,
    file: Annotated[str | None, Field(description="Or a bare file name in NETSCALER_EXPORT_DIR (the mounted files directory): keeps private keys out of the conversation.")] = None,
    overwrite: Annotated[bool, Field(description="Replace an existing file of that name with different content (delete + upload).")] = False,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Upload a certificate / key / chain file to /nsconfig/ssl — and only there (WRITE — requires
    NETSCALER_ALLOW_WRITE).

    For add_object / update_object kind ssl_certkey, which reference files in /nsconfig/ssl. The preview
    shows name, size, SHA-256 and what the file contains, never its content. An identical file is left
    alone; a different one needs overwrite=true. Private keys sent as text pass through the conversation:
    prefer file= with a mounted files directory.
    """
    name = (filename or "").strip()
    if not _SSL_FILE.fullmatch(name) or ".." in name:
        raise ValueError(f"filename must be a bare name like 'app.example.com.pem'; got {filename!r}.")
    if sum(v is not None for v in (text, content_base64, file)) != 1:
        raise ValueError("Pass exactly one of text, content_base64 or file.")
    if text is not None:
        data = text.encode("utf-8")
    elif content_base64 is not None:
        try:
            data = base64.b64decode(content_base64.split(",", 1)[-1], validate=True)
        except ValueError as exc:
            raise ValueError(f"content_base64 is not valid base64: {exc}") from None
    else:
        data = _drop_file(file.strip())
    if not data:
        raise ValueError("The file is empty.")
    if not dry_run:
        _require_write()
    digest = hashlib.sha256(data).hexdigest()
    existing = await _ssl_file(name)
    if existing is None:
        result, ops = "would upload", ["upload"]
    elif hashlib.sha256(existing).hexdigest() == digest:
        result, ops = "identical file already there: nothing to do", []
    elif overwrite:
        result, ops = "would replace the existing file", ["delete", "upload"]
    else:
        result, ops = "a different file of that name exists: pass overwrite=true to replace it", []
    out: dict[str, Any] = {
        "filename": name, "filelocation": _SSL_DIR, "size": len(data), "sha256": digest,
        **_ssl_content(data), "dry_run": dry_run, "result": result,
    }
    # arguments without the content: the code binds the file by its digest
    change = {"args": {"filename": name, "overwrite": overwrite, "sha256": digest}, "plan": ops}
    summary = f"Upload {name} ({len(data)} bytes) to {_SSL_DIR}" + (" replacing the existing file." if "delete" in ops else ".")
    if not _gate("upload_ssl_file", change, summary, out, dry_run=dry_run, confirm=confirm, writes=bool(ops)):
        return out
    client = _get_client()
    if "delete" in ops:
        await client.delete("systemfile", args={"filename": name, "filelocation": _SSL_DIR})
    if "upload" in ops:
        await client.add("systemfile", {
            "filename": name, "filelocation": _SSL_DIR, "fileencoding": "BASE64",
            "filecontent": base64.b64encode(data).decode("ascii"),
        })
        out["result"] = "replaced" if "delete" in ops else "uploaded"
    return out


# ---- pattern sets, data sets, string maps, expressions --------------------

_SEARCHABLE = (
    ("policy_patset", "policy_patset_pattern"), ("policy_dataset", "policy_dataset_value"),
    ("policy_stringmap", "policy_stringmap_pattern"), ("policy_expression", None),
)


@_tool
async def search_policy_objects(
    text: Annotated[str, Field(description="Case-insensitive text to find in names, patterns / values / keys and expressions, e.g. the name inside CONTAINS_ANY(\"...\").", min_length=1)],
    include_values: Annotated[bool, Field(description="Also search the patterns / values bound to each pattern set, data set and string map (one request per object).")] = True,
    limit: Annotated[int, Field(description="Max matches to return.", ge=1, le=500)] = 50,
) -> dict[str, Any]:
    """Find pattern sets, data sets, string maps and named expressions together — by name, by a pattern /
    value / key they hold, or by expression text (config tree).

    Policy rules like CONTAINS_ANY("x") may refer to a pattern set or a data set; this searches both.
    Name matches list the object's first 20 values.
    """
    needle = text.lower()
    matches: list[dict[str, Any]] = []
    searched: dict[str, int] = {}
    for kind_name, binding_name in _SEARCHABLE:
        k = lb.KINDS[kind_name]
        try:
            rows = (await _get_list("config", k.resource, k.fields, limit=500)).get(k.resource) or []
        except NitroError as exc:
            searched[kind_name] = 0
            matches.append({"kind": kind_name, "error": str(exc)})
            continue
        searched[kind_name] = len(rows)
        for row in rows:
            name = str(row.get(k.key, ""))
            hit_name = needle in name.lower()
            hit_expr = kind_name == "policy_expression" and needle in str(row.get("value", "")).lower()
            values: list[dict[str, Any]] = []
            if binding_name and (include_values or hit_name):
                b = lb.BINDINGS[binding_name]
                values = [lb.trim_row(v, b.fields, b.parent_attr) for v in await _bound_rows(b, name)]
            hit_values = [v for v in values if any(needle in str(x).lower() for x in v.values())]
            if hit_name:
                matches.append({"kind": kind_name, "name": name, "match": "name", **_pick(row, k.fields),
                                "values": values[:20], "values_total": len(values)})
            elif hit_expr:
                matches.append({"kind": kind_name, "name": name, "match": "expression", "value": row.get("value")})
            elif hit_values and include_values:
                matches.append({"kind": kind_name, "name": name, "match": "value", "values": hit_values[:20]})
            if len(matches) >= limit:
                break
    return {"text": text, "count": len(matches[:limit]), "matches": matches[:limit], "searched": searched}


# ---- GSLB sync ---------------------------------------------------------------

@_tool
async def sync_gslb_config(
    force_site: Annotated[str | None, Field(description="Force a full sync to this one site (sync gslb config -forceSync <site>).")] = None,
    save_on_sites: Annotated[bool, Field(description="Have each site save its config after the sync (-saveconfig).")] = False,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Push this appliance's GSLB configuration to the other GSLB sites with sync gslb config (WRITE —
    requires NETSCALER_ALLOW_WRITE).

    The preview lists the local and the target (remote) sites. The sync overwrites the GSLB configuration
    on the targets, so run it from the site that holds the intended state; compare_instances shows
    differences first when the sites are configured as instances. Batchable, e.g. as the last step after
    GSLB changes.
    """
    args = _call_args(locals())
    if not dry_run:
        _require_write()
    rows = (await _get_list("config", "gslbsite", _GSLBSITE_FIELDS + ("status",), limit=500)).get("gslbsite") or []
    local = [r for r in rows if str(r.get("sitetype", "")).upper() == "LOCAL"]
    remote = [r for r in rows if str(r.get("sitetype", "")).upper() == "REMOTE"]
    if force_site and force_site not in {r.get("sitename") for r in remote}:
        raise ValueError(f"force_site must be one of the remote sites {[r.get('sitename') for r in remote]}.")
    body: dict[str, Any] = {"nowarn": True}
    if force_site:
        body["forcesync"] = force_site
    if save_on_sites:
        body["saveconfig"] = True
    targets = [r for r in remote if not force_site or r.get("sitename") == force_site]
    out: dict[str, Any] = {"dry_run": dry_run, "local": local, "targets": targets, "nitro": {"gslbconfig": body},
                           "result": "would sync" if targets else "no remote site: nothing to sync"}
    summary = (f"Sync the GSLB configuration from {', '.join(r.get('sitename', '?') for r in local) or 'this site'} "
               f"to {', '.join(r.get('sitename', '?') for r in targets) or 'no site'}.")
    if not _gate("sync_gslb_config", {"args": args, "plan": [r.get("sitename") for r in targets]}, summary, out,
                 dry_run=dry_run, confirm=confirm, writes=bool(targets)):
        return out
    if targets:
        env = await _get_client().action("gslbconfig", "sync", body)
        out["result"] = "synced"
        if env.get("message"):
            out["message"] = env["message"]
    return out


# ---- diagnosis ----------------------------------------------------------------

_SSL_TYPES = ("SSL", "SSL_BRIDGE", "SSL_TCP", "DTLS", "SSL_DIAMETER", "SSL_PUSH")
_MEMBER_STAT_FIELDS = ("servername", "primaryipaddress", "primaryport", "state", "svrstate", "totalrequests",
                       "totalresponses", "curclntconnections", "cursrvrconnections", "svrestablishedconn",
                       "totalsvrbusyerr", "avgsvrttfb")


async def _stat(resource: str, name: str) -> dict[str, Any]:
    try:
        return _one(await _get_client().get("stat", resource, resource_name=name), resource)
    except NitroError as exc:
        return {"error": str(exc)}


async def _monitor_view(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    views = []
    for row in rows:
        name = row.get("monitor_name") or row.get("monitorname")
        mon = await _object(lb.KINDS["monitor"], name) if name else None
        views.append({"monitor": name, "type": (mon or {}).get("type") or ("TCP" if name == "tcp-default" else None),
                      "monstate": row.get("monstate")})
    return views


_TCP_ONLY_MONITORS = ("TCP", "TCP-ECV", "PING", "UDP", "UDP-ECV", "ARP")


def _tls_unchecked(servicetype: str, monitors: list[dict[str, Any]]) -> bool:
    """An SSL backend whose monitors (or the implicit tcp-default) never complete a TLS handshake."""
    if str(servicetype).upper() not in _SSL_TYPES:
        return False
    return all(str(m.get("type") or "").upper() in _TCP_ONLY_MONITORS for m in monitors)


async def _diag_group(name: str, lb_requests: int, warnings: list[str]) -> dict[str, Any]:
    config = await _object(lb.KINDS["service_group"], name) or {}
    monitors = await _monitor_view(await _bound_rows(lb.BINDINGS["service_group_monitor"], name))
    try:
        env = await _get_client().get_raw(f"stat/servicegroup/{quote(name, safe='')}", params={"statbindings": "yes"})
        stat = _one(env, "servicegroup")
    except NitroError as exc:
        stat = {"error": str(exc)}
    members = [_pick(m, _MEMBER_STAT_FIELDS) for m in _rows(stat, "servicegroupmember")] if "error" not in stat else []
    members = [{k: v for k, v in m.items() if v is not None} for m in members]
    if not members and "error" not in stat:
        warnings.append(f"service group {name}: no members.")
    for m in members:
        label = f"{name} {m.get('servername') or m.get('primaryipaddress')}:{m.get('primaryport')}"
        state = str(m.get("state") or m.get("svrstate") or "").upper()
        if state and state != "UP":
            warnings.append(f"member {label} is {state}.")
        elif (lb_requests and not waf.as_int(m.get("svrestablishedconn"))
              and not waf.as_int(m.get("totalrequests"))):
            warnings.append(f"member {label} is UP but has handled no requests and has no established "
                            "connections while the vserver gets traffic: check the backend protocol / TLS.")
    if _tls_unchecked(config.get("servicetype", ""), monitors):
        warnings.append(f"service group {name} is {config.get('servicetype')} but its monitors "
                        f"({', '.join(m['monitor'] for m in monitors) or 'none: tcp-default'}) only check TCP, "
                        "not the TLS handshake; bind an HTTPS / SSL-ECV monitor (secure YES).")
    return {"name": name, "servicetype": config.get("servicetype"), "state": config.get("state"),
            "monitors": monitors, "members": members, **({"stat_error": stat["error"]} if "error" in stat else {})}


async def _diag_service(name: str, warnings: list[str]) -> dict[str, Any]:
    config = await _object(lb.KINDS["service"], name) or {}
    monitors = await _monitor_view(await _bound_rows(lb.BINDINGS["service_monitor"], name))
    stat = await _stat("service", name)
    state = str(stat.get("state") or config.get("svrstate") or "").upper()
    if state and state != "UP":
        warnings.append(f"service {name} is {state}.")
    if _tls_unchecked(config.get("servicetype", ""), monitors):
        warnings.append(f"service {name} is {config.get('servicetype')} but its monitors only check TCP, "
                        "not the TLS handshake.")
    return {"name": name, "servicetype": config.get("servicetype"), "state": state or None, "monitors": monitors,
            "stat": _pick(stat, ("totalrequests", "curclntconnections", "cursrvrconnections", "svrestablishedconn"))}


async def _diag_lb(name: str, warnings: list[str]) -> dict[str, Any]:
    config = await _object(lb.KINDS["lb_vserver"], name)
    if config is None:
        warnings.append(f"LB vserver {name} does not exist.")
        return {"name": name, "error": "not found"}
    stat = await _stat("lbvserver", name)
    requests = waf.as_int(stat.get("totalrequests")) or 0
    state = str(stat.get("state") or config.get("curstate") or "").upper()
    if state and state != "UP":
        warnings.append(f"LB vserver {name} is {state} (effective state {config.get('effectivestate')}).")
    groups = await _bound_rows(lb.BINDINGS["lb_vserver_service_group"], name)
    services = await _bound_rows(lb.BINDINGS["lb_vserver_service"], name)
    if not groups and not services:
        warnings.append(f"LB vserver {name} has no service or service group bound.")
    return {
        "name": name, "state": state or None, "servicetype": config.get("servicetype"),
        "stat": _pick(stat, ("vslbhealth", "totalrequests", "totalresponses", "curclntconnections",
                              "cursrvrconnections", "hitsrate")),
        "service_groups": [await _diag_group(g.get("servicegroupname"), requests, warnings) for g in groups],
        "services": [await _diag_service(s.get("servicename"), warnings) for s in services],
    }


@_tool
async def vserver_diagnose(
    name: Annotated[str, Field(description="A CS vserver (checks every LB vserver it routes to) or an LB vserver.")],
) -> dict[str, Any]:
    """Health of one traffic path: CS vserver → its routes → LB vservers → service groups / services →
    members, with live state and counters and warnings (stat + config trees).

    Warns about vservers or members not UP, members that are UP but handle no requests while the vserver
    gets traffic (typically a broken backend protocol or TLS that the monitor does not notice), SSL
    backends monitored only by TCP / tcp-default (no TLS handshake checked), and empty groups.
    """
    warnings: list[str] = []
    out: dict[str, Any] = {"name": name}
    cs = await _object(lb.KINDS["cs_vserver"], name)
    if cs is not None:
        stat = await _stat("csvserver", name)
        routes = await _cs_routes(await _bound_rows(lb.BINDINGS["cs_vserver_policy"], name), 200)
        default = await _bound_rows(lb.BINDINGS["cs_vserver_default"], name)
        state = str(stat.get("state") or cs.get("curstate") or "").upper()
        if state and state != "UP":
            warnings.append(f"CS vserver {name} is {state}.")
        targets = list(dict.fromkeys([r["lb_target"] for r in routes if r["lb_target"]]
                                     + [d.get("lbvserver") for d in default if d.get("lbvserver")]))
        out["cs_vserver"] = {"state": state or None, "stat": _pick(stat, ("totalrequests", "curclntconnections")),
                             "routes": routes, "default_lb_vserver": default[0].get("lbvserver") if default else None}
        lb_names = targets
    elif await _object(lb.KINDS["lb_vserver"], name) is not None:
        lb_names = [name]
    else:
        raise ValueError(f"No CS or LB vserver named {name!r}.")
    out["lb_vservers"] = [await _diag_lb(n, warnings) for n in lb_names]
    out["warnings"] = warnings
    out["healthy"] = not warnings
    return out


# ---- clone an application setup ------------------------------------------------

_BATCH_EXCLUDED = ("save_config", "apply_batch", "clone_app_setup")


def _swap(text: str, old: str, new: str, what: str) -> str:
    if old.lower() not in text.lower():
        raise ValueError(f"{what} {text!r} does not contain {old!r}, so its new name / rule can't be derived; "
                         "pass name_part / new_name_part that it does contain.")
    return re.sub(re.escape(old), new.replace("\\", "\\\\"), text, flags=re.I)


async def _template_route(template: str, cs_vserver: str | None) -> tuple[str, dict[str, Any], list[dict[str, Any]]] | None:
    """(CS vserver, the route to the template LB vserver, all routes of that CS vserver), or None."""
    names = [cs_vserver] if cs_vserver else [
        r.get("name") for r in (await _get_list("config", "csvserver", ("name",), limit=200)).get("csvserver") or []]
    for cs in names:
        routes = await _cs_routes(await _bound_rows(lb.BINDINGS["cs_vserver_policy"], cs), 500)
        for route in routes:
            if route["target"] == template:
                return cs, route, routes
    return None


def _free_priority(routes: list[dict[str, Any]], after: int) -> int:
    taken = {waf.as_int(r.get("priority")) for r in routes}
    p = after + 1
    while p in taken:
        p += 1
    return p


def _backend(entry: str) -> tuple[str | None, dict[str, Any]]:
    """'name=10.0.0.5:443' (new named server) / '10.0.0.5:443' / 'srv_existing:443' → (server to add, member)."""
    named, sep, rest = entry.partition("=")
    if sep:
        member = lb.entry(lb.BINDINGS["service_group_member"], rest.strip())
        if "ip" not in member:
            raise ValueError(f"'name=ip:port' needs an IP after '='; got {entry!r}.")
        return named.strip(), {"servername": named.strip(), "port": member["port"], "_ip": member["ip"]}
    return None, lb.entry(lb.BINDINGS["service_group_member"], entry.strip())


@_tool
async def clone_app_setup(
    template_lb_vserver: Annotated[str, Field(description="LB vserver of the existing app to copy.")],
    template_hostname: Annotated[str, Field(description="Hostname the template's CS policy rule matches, e.g. 'old.example.com'.")],
    new_hostname: Annotated[str, Field(description="Hostname for the new app, e.g. 'new.example.com'.")],
    backends: Annotated[list[str], Field(description="Backend members: '10.0.0.5:443', an existing server 'srv_x:443', or 'srv_new=10.0.0.5:443' to create a named server.", min_length=1, max_length=50)],
    name_part: Annotated[str | None, Field(description="Text in the template's object names to replace (default: template_hostname).")] = None,
    new_name_part: Annotated[str | None, Field(description="Replacement in the new object names (default: new_hostname).")] = None,
    cs_vserver: Annotated[str | None, Field(description="CS vserver that routes to the template (default: found by searching every CS vserver).")] = None,
    certkey: Annotated[str | None, Field(description="Certificate to bind as SNI certificate on the CS vserver (an existing ssl_certkey).")] = None,
    ssl_profile: Annotated[str | None, Field(description="SSL profile for the new service group's SSL side (default: the template's).")] = None,
    lb_ip: Annotated[str | None, Field(description="VIP for the new LB vserver when the template LB vserver is directly addressable.")] = None,
    lb_port: Annotated[int | None, Field(description="Port for the new LB vserver when lb_ip is given.")] = None,
    instances: Annotated[list[str] | None, Field(description="Apply the same setup to several appliances (names from list_instances) with one confirmation; the template is read from the first.")] = None,
    save: Annotated[bool, Field(description="Save the running config once everything applied cleanly.")] = False,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a new application from an existing one as template — server(s), service group with its
    settings, monitors and SSL profile, LB vserver with its settings and every policy / analytics binding,
    CS action + policy for the new hostname at the next free priority, and the SNI certificate (WRITE —
    requires NETSCALER_ALLOW_WRITE).

    Object names and the CS rule are the template's with the hostname (or name_part) swapped. Builds an
    apply_batch plan from the live template, previews every step and applies it with one confirmation,
    optionally on several instances.
    """
    args = _call_args(locals())
    old = name_part or template_hostname
    new = new_name_part or new_hostname
    template = await _object(lb.KINDS["lb_vserver"], template_lb_vserver)
    if template is None:
        raise ValueError(f"No LB vserver named {template_lb_vserver!r}.")
    steps: list[dict[str, Any]] = []
    plan: dict[str, Any] = {}
    new_lb = _swap(template_lb_vserver, old, new, "LB vserver")
    plan["lb_vserver"] = new_lb

    # backend: service group, members, monitors, SSL side
    groups = await _bound_rows(lb.BINDINGS["lb_vserver_service_group"], template_lb_vserver)
    if len(groups) != 1:
        raise ValueError(f"The template LB vserver needs exactly one service group; it has {len(groups)}.")
    tmpl_sg = groups[0].get("servicegroupname")
    sg_conf = await _object(lb.KINDS["service_group"], tmpl_sg) or {}
    new_sg = _swap(tmpl_sg, old, new, "service group")
    plan["service_group"] = new_sg
    sg_settings = {a: sg_conf[a] for a in lb.COPY_ATTRS["service_group"] if sg_conf.get(a) not in (None, "")}
    members = []
    for raw in backends:
        server, member = _backend(raw)
        if server:
            steps.append({"tool": "add_object", "args": {"kind": "server", "name": server,
                                                          "settings": {"ipaddress": member.pop("_ip")}}})
        members.append(member)
    steps.append({"tool": "add_object", "args": {"kind": "service_group", "name": new_sg, "settings": sg_settings}})
    steps.append({"tool": "change_bindings", "args": {"binding": "service_group_member", "name": new_sg,
                                                      "add": members}})
    monitors = [r.get("monitor_name") for r in await _bound_rows(lb.BINDINGS["service_group_monitor"], tmpl_sg)]
    if monitors:
        steps.append({"tool": "change_bindings", "args": {"binding": "service_group_monitor", "name": new_sg,
                                                          "add": monitors}})
    if str(sg_conf.get("servicetype", "")).upper() in _SSL_TYPES:
        ssl_side = await _object(lb.KINDS["ssl_service_group"], tmpl_sg) or {}
        profile = ssl_profile or ssl_side.get("sslprofile")
        if profile:
            steps.append({"tool": "update_object", "args": {"kind": "ssl_service_group", "name": new_sg,
                                                            "settings": {"sslprofile": profile}}})
        certs = await _bound_rows(lb.BINDINGS["ssl_service_group_certkey"], tmpl_sg)
        if certs:
            b = lb.BINDINGS["ssl_service_group_certkey"]
            steps.append({"tool": "change_bindings", "args": {"binding": b.name, "name": new_sg, "add": [
                lb.trim_row(c, b.fields, b.parent_attr) for c in certs]}})

    # LB vserver, its policies and analytics profiles
    lb_settings = {a: template[a] for a in lb.COPY_ATTRS["lb_vserver"] if template.get(a) not in (None, "")}
    addressable = str(template.get("ipv46") or "0.0.0.0") not in ("0.0.0.0", "::")
    if addressable and not lb_ip:
        raise ValueError("The template LB vserver has its own VIP; pass lb_ip (and lb_port) for the new one.")
    if lb_ip:
        lb_settings.update(ipv46=lb_ip, port=lb_port or template.get("port"))
    steps.append({"tool": "add_object", "args": {"kind": "lb_vserver", "name": new_lb, "settings": lb_settings}})
    steps.append({"tool": "change_bindings", "args": {"binding": "lb_vserver_service_group", "name": new_lb,
                                                      "add": [new_sg]}})
    aggregate = _one(await _get_client().get("config", "lbvserver_binding", resource_name=template_lb_vserver),
                     "lbvserver_binding")
    for b in lb.BINDINGS.values():
        if b.parent != "lb_vserver" or b.name in ("lb_vserver_service", "lb_vserver_service_group"):
            continue
        rows = aggregate.get(b.resource) or []
        if rows:
            entries = [{k: v for k, v in lb.trim_row(r, b.fields, b.parent_attr).items() if k != "hits"} for r in rows]
            steps.append({"tool": "change_bindings", "args": {"binding": b.name, "name": new_lb, "add": entries}})
    if str(template.get("servicetype", "")).upper() in _SSL_TYPES:
        ssl_vs = await _object(lb.KINDS["ssl_vserver"], template_lb_vserver) or {}
        if ssl_vs.get("sslprofile"):
            steps.append({"tool": "update_object", "args": {"kind": "ssl_vserver", "name": new_lb,
                                                            "settings": {"sslprofile": ssl_vs["sslprofile"]}}})
        if lb_ip and certkey:
            steps.append({"tool": "change_bindings", "args": {"binding": "ssl_vserver_certkey", "name": new_lb,
                                                              "add": [certkey]}})

    # content switching: action, policy at the next free priority, SNI certificate
    found = await _template_route(template_lb_vserver, cs_vserver)
    if found:
        cs, route, routes = found
        rule = _swap(route["rule"] or "", template_hostname, new_hostname, "CS policy rule")
        new_policy = _swap(route["policy"], old, new, "CS policy")
        priority = _free_priority(routes, waf.as_int(route["priority"]) or 0)
        bind_entry: dict[str, Any] = {"policyname": new_policy, "priority": priority}
        if route.get("gotopriorityexpression"):
            bind_entry["gotopriorityexpression"] = route["gotopriorityexpression"]
        policy_settings: dict[str, Any] = {"rule": rule}
        if route["target_via"] == "action" and route.get("action"):
            new_action = _swap(route["action"], old, new, "CS action")
            steps.append({"tool": "add_object", "args": {"kind": "cs_action", "name": new_action,
                                                         "settings": {"targetlbvserver": new_lb}}})
            policy_settings["action"] = new_action
            plan["cs_action"] = new_action
        else:
            bind_entry["targetlbvserver"] = new_lb
        steps.append({"tool": "add_object", "args": {"kind": "cs_policy", "name": new_policy, "settings": policy_settings}})
        steps.append({"tool": "change_bindings", "args": {"binding": "cs_vserver_policy", "name": cs, "add": [bind_entry]}})
        plan.update(cs_vserver=cs, cs_policy=new_policy, priority=priority, rule=rule)
        if certkey:
            steps.append({"tool": "change_bindings", "args": {"binding": "ssl_vserver_certkey", "name": cs,
                                                              "add": [{"certkeyname": certkey, "snicert": True}]}})
    else:
        plan["cs_vserver"] = None
        plan["note"] = "No CS vserver routes to the template; only the LB part is created."
    return await _run_batch("clone_app_setup", steps, save=save, dry_run=dry_run, confirm=confirm, args=args,
                            instances=instances, extra={"template": template_lb_vserver, "new": plan})


# ---- batches: one confirmation, one or several instances -----------------------

_BATCH_TOOL_KEYS = ("status", "confirm_code", "next", "note", "dry_run")


async def _compare_after(steps: list[tuple[str, dict[str, Any]]], names: list[str]) -> dict[str, Any]:
    """After a batch on several instances: do the objects and bindings it touched now match everywhere?"""
    differences: list[dict[str, Any]] = []
    for tool, sub in steps:
        if tool == "add_object":
            k = lb.KINDS.get(str(sub.get("kind")))
            if not k or k.multi:
                continue
            found = await _on_each(lambda k=k, n=sub["name"]: _object(k, n), names)
            views = {i: {f: v for f, v in _pick(o or {}, k.fields).items() if f not in _RUNTIME} if isinstance(o, dict)
                     else o for i, o in found.items()}
            if len({json.dumps(v, sort_keys=True, default=str) for v in views.values()}) > 1:
                differences.append({"kind": k.name, "name": sub["name"], "per_instance": views})
        elif tool == "change_bindings":
            b = lb.BINDINGS.get(str(sub.get("binding")))
            if not b:
                continue
            found = await _on_each(lambda b=b, n=sub.get("name"): _bound_rows(b, n), names)
            views = {i: sorted(json.dumps(lb.identity(b, r), sort_keys=True, default=str) for r in rows)
                     if isinstance(rows, list) else rows for i, rows in found.items()}
            if len({json.dumps(v, sort_keys=True) for v in views.values()}) > 1:
                differences.append({"binding": b.name, "name": sub.get("name"), "per_instance": views})
    return {"instances": names, "identical": not differences, "differences": differences}


async def _run_batch(
    tool: str,
    changes: list[dict[str, Any]],
    *,
    save: bool,
    dry_run: bool,
    confirm: str | None,
    args: dict[str, Any],
    instances: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The engine behind apply_batch and clone_app_setup: preview every step (on every instance), one
    confirmation for all, then apply in order and stop at the first failure."""
    steps: list[tuple[str, dict[str, Any]]] = []
    for i, item in enumerate(changes, 1):
        name = str(item.get("tool") or "").strip()
        sub = item.get("args") or {}
        if name not in _WRITE_TOOLS or name in _BATCH_EXCLUDED:
            usable = sorted(set(_WRITE_TOOLS) - set(_BATCH_EXCLUDED))
            raise ValueError(f"Step {i}: tool must be one of {usable} (save with save=true); got {name!r}.")
        if not isinstance(sub, dict):
            raise ValueError(f"Step {i}: args must be an object of {name}'s arguments.")
        if reserved := sorted(set(sub) & {"dry_run", "confirm", "instance"}):
            raise ValueError(f"Step {i}: leave {reserved} out of args; apply_batch sets them for every step.")
        steps.append((name, sub))
    multi = bool(instances)
    names = [_resolve_instance(n, write=True) for n in instances] if multi else [_instance.get() or _default_instance]
    if len(set(names)) != len(names):
        raise ValueError("instances lists an appliance twice.")
    if not dry_run:
        for n in names:
            token = _instance.set(n)
            try:
                _require_write()
            finally:
                _instance.reset(token)

    async def run(apply: bool) -> tuple[list[dict[str, Any]], bool]:
        done: list[dict[str, Any]] = []
        for i, (name, sub) in enumerate(steps, 1):
            try:
                result = await _WRITE_TOOLS[name](**sub, dry_run=not apply)
            except (NitroError, ValueError) as exc:
                done.append({"step": i, "tool": name, "error": str(exc)})
                break
            if apply and result.get("status") == "confirmation_required":
                done.append({"step": i, "tool": name, "error": (
                    "Its live plan differs from the confirmed preview (an earlier step or someone else changed "
                    "it), so it was not applied. Preview the remaining steps again."
                ), "plan_now": {k: v for k, v in result.items() if k not in _BATCH_TOOL_KEYS}})
                break
            done.append({"step": i, "tool": name, **{k: v for k, v in result.items() if k not in _BATCH_TOOL_KEYS}})
        done += [{"step": j, "tool": n, "status": "not run"} for j, (n, _) in enumerate(steps, 1) if j > len(done)]
        return done, all("error" not in s and "status" not in s for s in done)

    async def on(instance: str, apply: bool) -> tuple[list[dict[str, Any]], bool]:
        token = _instance.set(instance)
        try:
            return await run(apply)
        finally:
            _instance.reset(token)

    def shaped(per: dict[str, Any]) -> dict[str, Any]:
        return {"instances": per} if multi else {**_instance_note(), "steps": per[names[0]]}

    batch: dict[str, list[str]] = {"record": []}
    token = _batch.set(batch)
    try:
        previews, ok = {}, True
        for n in names:
            previews[n], fine = await on(n, apply=False)
            ok = ok and fine
    finally:
        _batch.reset(token)
    if not ok:
        return {"dry_run": True, **shaped(previews), **(extra or {}),
                "error": "A step failed in the preview; fix it and preview the batch again. Nothing was applied."}
    first = previews[names[0]]
    parts = [s.get("change_summary") or s.get("summary") for s in first]
    summary = f"{len(steps)} step(s)" + (f" on each of {', '.join(names)}" if multi else "") + ": " + " ".join(
        p for p in parts if isinstance(p, str))
    if save:
        summary += " Then save the running configuration."
    preview = {"dry_run": dry_run, **shaped(previews), "save": save, **(extra or {})}
    change = {"args": args, "plans": batch["record"]}
    deletes = any(name in _DELETE_TOOLS for name, _ in steps)
    if not _gate(tool, change, summary, preview, dry_run=dry_run, confirm=confirm,
                 writes=bool(batch["record"]) or save, always=deletes):
        return preview

    token = _batch.set({"approved": list(batch["record"])})
    results: dict[str, Any] = {}
    all_ok = True
    try:
        for idx, n in enumerate(names):
            applied, ok = await on(n, apply=True)
            entry: dict[str, Any] = {"steps": applied, "saved": False}
            if save and ok:
                inner = _instance.set(n)
                try:
                    await _get_client().action("nsconfig", "save")
                finally:
                    _instance.reset(inner)
                entry["saved"] = True
            elif save:
                entry["note"] = "Not saved because a step failed; the applied steps are live but unsaved (save_config)."
            results[n] = entry
            if not ok:
                all_ok = False
                for rest in names[idx + 1:]:
                    results[rest] = {"status": "not run", "note": f"Stopped: a step failed on {n}."}
                break
    finally:
        _batch.reset(token)
    if multi:
        out: dict[str, Any] = {"dry_run": False, "instances": results, **(extra or {})}
        if all_ok:
            out["comparison"] = await _compare_after(steps, names)
        return out
    return {"dry_run": False, **_instance_note(), **results[names[0]], **(extra or {})}


# ---- tool: raw escape hatch ---------------------------------------------

def _pairs(value: dict[str, Any] | str | None, param: str) -> dict[str, str] | None:
    """Parse NITRO ``key:value,key:value`` text (or take a dict as-is) for the filter / args params."""
    if not value:
        return None
    if isinstance(value, dict):
        return {str(k).strip(): str(v) for k, v in value.items()}
    pairs: dict[str, str] = {}
    for item in value.split(","):
        if not item.strip():
            continue
        if ":" not in item:
            raise ValueError(f"{param} must be comma-separated key:value pairs; got {item.strip()!r}.")
        key, val = item.split(":", 1)
        pairs[key.strip()] = val.strip()
    return pairs


@_tool
async def nitro_get(
    tree: Annotated[str, Field(description="Which NITRO tree: 'config' or 'stat'.")],
    resourcetype: Annotated[str, Field(description="NITRO resource type, e.g. 'route', 'nsip', 'sslcertkey'. Note the stat 'Interface' resource is Capitalized.")],
    name: Annotated[str | None, Field(description="Optional exact resource name to fetch a single object (sent as a path segment).")] = None,
    attrs: Annotated[str | None, Field(description="Comma-separated attributes to project, e.g. 'name,curstate'.")] = None,
    filter: Annotated[str | None, Field(description="NITRO filter: comma-separated key:value pairs, e.g. 'curstate:UP,servicetype:HTTP'.")] = None,
    args: Annotated[dict[str, str] | str | None, Field(description="NITRO lookup arguments (?args=) for resources that require them: comma-separated key:value pairs, e.g. 'profilename:pr_app,securitycheck:startURL' for appfwlearningdata or 'filelocation:/nsconfig/ssl' for systemfile. Pass an object instead when a value contains a comma.")] = None,
    count: Annotated[bool, Field(description="Return only the count of matching resources.")] = False,
    pagesize: Annotated[int | None, Field(description="Page size for pagination.", ge=1)] = None,
    pageno: Annotated[int | None, Field(description="Page number (1-indexed).", ge=1)] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only NITRO GET against any config/stat resource on the appliance.

    Use for resources without a dedicated tool (routes, nsip, nsfeature, appfw policies, the
    capitalized 'Interface' stat, etc.). Resources with required lookup arguments — appfwlearningdata
    (profilename + securitycheck), systemfile (filelocation), … — take them via args, not name or
    filter: NITRO answers 1095 "Required argument missing" without them and reads a name as 'arguid'.
    args values are percent-encoded with literal ':' / ',' separators, as the NITRO SDKs send them.
    (For WAF learned data, list_waf_learned_rules adds hit sorting and the deployable rule.) The
    whole-config resources 'nsrunningconfig' and 'nssavedconfig' are reachable here but return very
    large payloads — prefer a targeted resource. Returns the raw NITRO envelope.
    """
    if tree not in ("config", "stat"):
        raise ValueError("tree must be 'config' or 'stat'.")
    filt, lookup = _pairs(filter, "filter"), _pairs(args, "args")
    return await _get_client().get(
        tree,
        resourcetype,
        resource_name=name,
        attrs=_csv(attrs),
        filter=filt,
        args=lookup,
        count=count,
        pagesize=pagesize,
        pageno=pageno,
    )


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    global _clients, _default_instance
    try:
        instances, _default_instance = load_instances()
    except ConfigError as exc:
        print(f"netscaler-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)
    settings = instances[_default_instance]  # transport / host / port are shared by every instance

    # Share the configured clients with the tools.
    _clients = {name: NitroClient(s) for name, s in instances.items()}

    if settings.transport == "streamable-http":
        # MCPServer.run() takes host/port per transport (mcp 1.x read them from mcp.settings).
        mcp.run(
            transport="streamable-http",
            host=settings.host,
            port=settings.port,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
