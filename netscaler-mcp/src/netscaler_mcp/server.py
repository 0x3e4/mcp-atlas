"""FastMCP server exposing NetScaler ADC (NITRO) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Curated read tools cover the common questions; the raw ``nitro_get`` escape
hatch reaches anything else.

WAF (AppFw) rollout tools list learned rules, the URL inventory and configured rules, and export
profiles as portable JSON (reads). Their write tools — add/remove rules, deploy/discard learned rules,
set check actions, import/rehost profiles, save config — are **opt-in**: they preview by default
(``dry_run=true``) and refuse to apply unless ``NETSCALER_ALLOW_WRITE=true``. With the flag off the
server is effectively read-only. The regex/host/plan logic lives in ``waf.py``.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from . import waf
from .client import NitroClient, NitroError
from .config import ConfigError, Settings

mcp = FastMCP("netscaler-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: NitroClient | None = None


def _get_client() -> NitroClient:
    global _client
    if _client is None:
        _client = NitroClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in NETSCALER_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set NETSCALER_ALLOW_WRITE=true (and use a system user whose "
            "command policy allows appfw changes) to apply WAF changes. dry_run=true previews still work."
        )


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

@mcp.tool()
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


@mcp.tool()
async def list_cs_vservers(
    name: Annotated[str | None, Field(description="Exact CS vserver name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max vservers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List content-switching virtual servers and their state (config tree, csvserver)."""
    return await _get_list("config", "csvserver", _CSVSERVER_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
async def list_gslb_vservers(
    name: Annotated[str | None, Field(description="Exact GSLB vserver name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max vservers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List GSLB virtual servers and their state (config tree, gslbvserver).

    Requires the GSLB feature to be enabled; otherwise NITRO returns a clean 'feature not enabled' error.
    """
    return await _get_list("config", "gslbvserver", _GSLBVSERVER_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
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


@mcp.tool()
async def list_servers(
    name: Annotated[str | None, Field(description="Exact server name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max servers to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List backend server objects (config tree, server) — name, IP/domain and enabled state."""
    return await _get_list("config", "server", _SERVER_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
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


@mcp.tool()
async def ha_status(
    full: Annotated[bool, Field(description="Return full hanode objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Show High Availability node status for the pair (config tree, hanode).

    Returns every node the appliance knows about (itself + peer), so it always reflects the whole
    pair regardless of which node you pointed at. 'masterstate' indicates PRIMARY/SECONDARY and
    'hasync' the sync state.
    """
    return await _get_list("config", "hanode", _HANODE_FIELDS, full=full)


@mcp.tool()
async def system_health(
    full: Annotated[bool, Field(description="Return the full stats object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Show appliance CPU, management-CPU, memory, disk usage and uptime (stat tree, ns)."""
    env = await _get_client().get("stat", "ns")
    ns = _one(env, "ns")
    return ns if full else _pick(ns, _NS_STAT_FIELDS)


@mcp.tool()
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


@mcp.tool()
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

@mcp.tool()
async def list_gslb_services(
    name: Annotated[str | None, Field(description="Exact GSLB service name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max services to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List GSLB services and their state (config tree, gslbservice). Requires the GSLB feature."""
    return await _get_list("config", "gslbservice", _GSLBSERVICE_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
async def list_gslb_sites(
    name: Annotated[str | None, Field(description="Exact GSLB site name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max sites to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List GSLB sites (config tree, gslbsite) — LOCAL/REMOTE sites and their IPs. Requires GSLB."""
    return await _get_list("config", "gslbsite", _GSLBSITE_FIELDS, name=name, limit=limit, full=full)


# ---- tools: DNS ---------------------------------------------------------

@mcp.tool()
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


@mcp.tool()
async def list_dns_zones(
    name: Annotated[str | None, Field(description="Exact zone name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max zones to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List configured DNS zones (config tree, dnszone)."""
    return await _get_list("config", "dnszone", _DNSZONE_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
async def list_dns_nameservers(
    limit: Annotated[int, Field(description="Max name servers to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List configured DNS name servers (config tree, dnsnameserver) and their state."""
    return await _get_list("config", "dnsnameserver", _DNSNAMESERVER_FIELDS, limit=limit, full=full)


# ---- tools: Application Firewall (WAF) ----------------------------------

@mcp.tool()
async def list_waf_profiles(
    name: Annotated[str | None, Field(description="Exact AppFW profile name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max profiles to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Application Firewall (WAF) profiles (config tree, appfwprofile). Requires the AppFw feature."""
    return await _get_list("config", "appfwprofile", _APPFWPROFILE_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
async def list_waf_policies(
    name: Annotated[str | None, Field(description="Exact AppFW policy name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Application Firewall (WAF) policies and the profile each binds (config tree, appfwpolicy)."""
    return await _get_list("config", "appfwpolicy", _APPFWPOLICY_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
async def waf_stats(
    name: Annotated[str | None, Field(description="Exact AppFW policy name; omit for all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full stat objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live WAF policy hit counters (stat tree, appfwpolicy) — how often each AppFW policy fired."""
    return await _get_list("stat", "appfwpolicy", _APPFWPOLICY_STAT_FIELDS, name=name, limit=limit, full=full)


# ---- tools: Bot management ----------------------------------------------

@mcp.tool()
async def list_bot_profiles(
    name: Annotated[str | None, Field(description="Exact bot profile name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max profiles to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Bot management profiles (config tree, botprofile). Requires the Bot feature."""
    return await _get_list("config", "botprofile", _BOTPROFILE_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
async def list_bot_policies(
    name: Annotated[str | None, Field(description="Exact bot policy name to fetch one; omit to list all.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Bot management policies and the profile each binds (config tree, botpolicy)."""
    return await _get_list("config", "botpolicy", _BOTPOLICY_FIELDS, name=name, limit=limit, full=full)


@mcp.tool()
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


async def _profile_rules(profile: str) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """A profile's live bindings split into modelled rule types and other binding arrays."""
    env = await _get_client().get("config", "appfwprofile_binding", resource_name=profile)
    return waf.split_bindings(_one(env, "appfwprofile_binding"))


async def _learning_settings(profile: str) -> dict[str, Any]:
    try:
        env = await _get_client().get("config", "appfwlearningsettings", resource_name=profile)
    except NitroError:
        return {}
    return _one(env, "appfwlearningsettings")


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


async def _export_document(profile: str) -> dict[str, Any]:
    client = _get_client()
    settings = _one(await client.get("config", "appfwprofile", resource_name=profile), "appfwprofile")
    rules, other = await _profile_rules(profile)
    return waf.build_document(
        profile=profile,
        appliance=client.settings.base_origin,
        exported_at=datetime.now(UTC).isoformat(timespec="seconds"),
        settings=settings,
        learning_settings=await _learning_settings(profile),
        rules=rules,
        other_bindings=other,
    )


async def _apply_document(
    doc: dict[str, Any], target: str, *, mode: str, include_settings: bool | None, dry_run: bool
) -> dict[str, Any]:
    """Plan a WAF profile document against ``target`` and, unless dry_run, apply it in a traffic-safe order."""
    if mode not in ("merge", "replace"):
        raise ValueError("mode must be 'merge' or 'replace'.")
    if not dry_run:
        _require_write()
    client = _get_client()
    try:
        current = _one(await client.get("config", "appfwprofile", resource_name=target), "appfwprofile")
    except NitroError as exc:
        if not _is_missing(exc):
            raise
        current = {}
    exists = bool(current)
    apply_settings = (not exists) if include_settings is None else include_settings
    desired_settings = doc.get("settings") or {}
    desired_learning = doc.get("learning_settings") or {}
    setting_changes: dict[str, Any] = {}
    learning_changes: dict[str, Any] = {}
    if apply_settings and exists:
        setting_changes = waf.settings_changes(desired_settings, current)
        learning_changes = waf.settings_changes(desired_learning, await _learning_settings(target))
    elif apply_settings:  # a new profile's defaults are unknown until it exists
        setting_changes, learning_changes = dict(desired_settings), dict(desired_learning)
    current_rules = (await _profile_rules(target))[0] if exists else {}
    plan = waf.plan_bindings(doc.get("rules") or {}, current_rules, replace=mode == "replace")

    out: dict[str, Any] = {
        "target_profile": target,
        "mode": mode,
        "dry_run": dry_run,
        "profile": "exists" if exists else ("would create" if dry_run else "created"),
        "settings_changes": setting_changes,
        "learning_settings_changes": learning_changes,
        "rules": {
            key: {op: len(v) if isinstance(v, list) else v for op, v in ops.items()} for key, ops in plan.items()
        },
        "not_imported": {k: len(v) for k, v in (doc.get("other_bindings") or {}).items()},
    }
    if dry_run:
        out["preview"] = {
            key: {op: v[:25] for op, v in ops.items() if isinstance(v, list) and v} for key, ops in plan.items()
        }
        out["next"] = (
            "Review, then call again with dry_run=false (needs NETSCALER_ALLOW_WRITE); persist with save_config."
        )
        return out

    errors: list[str] = []
    if not exists:
        body: dict[str, Any] = {"name": target}
        if desired_settings.get("type"):
            body["type"] = desired_settings["type"]
        await client.add("appfwprofile", body)
        if apply_settings:  # diff against the fresh profile's defaults so only real differences are sent
            fresh = _one(await client.get("config", "appfwprofile", resource_name=target), "appfwprofile")
            setting_changes = waf.settings_changes(desired_settings, fresh)
            learning_changes = waf.settings_changes(desired_learning, await _learning_settings(target))
    if setting_changes:
        errors += await _update_attrs("appfwprofile", {"name": target}, setting_changes)
    if learning_changes:
        errors += await _update_attrs("appfwlearningsettings", {"profilename": target}, learning_changes)

    applied: dict[str, list[str]] = {}

    def _record(key: str, op: str, status: str, row: dict[str, Any]) -> None:
        applied.setdefault(key, []).append(status)
        if status.startswith("error") and len(errors) < 50:
            errors.append(f"{key} {op} {row.get(waf.RULE_TYPES[key].identity[0])!r}: {status[len('error: '):]}")

    # Add first, re-bind changed, remove last: allowed traffic never loses its rule mid-import.
    for key, ops in plan.items():
        for row in ops["add"]:
            _record(key, "add", await _bind(waf.RULE_TYPES[key], target, row), row)
    for key, ops in plan.items():
        for change in ops["update"]:
            status = await _unbind(waf.RULE_TYPES[key], target, change["current"])
            if not status.startswith("error"):
                status = await _bind(waf.RULE_TYPES[key], target, change["desired"])
                status = "updated" if status == "added" else status
            _record(key, "update", status, change["desired"])
    for key, ops in plan.items():
        for row in ops["remove"]:
            _record(key, "remove", await _unbind(waf.RULE_TYPES[key], target, row), row)

    out["applied"] = {key: _tally(statuses) for key, statuses in applied.items()}
    out["errors"] = errors
    return out


@mcp.tool()
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
    rules, other = await _profile_rules(profile)
    keys = [waf.rule_type(rule_type)] if rule_type else list(waf.RULE_TYPES)
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


@mcp.tool()
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


@mcp.tool()
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
    rules, _ = await _profile_rules(profile)
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


@mcp.tool()
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
    doc = await _export_document(profile)
    extra: dict[str, Any] = {}
    if host_map:
        doc, replacements = waf.apply_host_map(doc, host_map)
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


@mcp.tool()
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
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE.")] = True,
) -> dict[str, Any]:
    """Add an easy WAF rule without hand-writing NetScaler regexes (WRITE — requires NETSCALER_ALLOW_WRITE).

    Builds the anchored, escaped PCRE for you, e.g. allow_url(host='app.example.com', path='/api/') →
    start URL ^https://app\\.example\\.com/api/.*$ ; host='*' gives a global rule that survives a hostname
    switch. Field rules relax one check for a field on the matching URLs (field='*' = all fields there).
    Skips profiles that already have the rule. Previews by default. Live immediately once applied;
    persist with save_config.
    """
    if rule == "raw":
        key = waf.rule_type(rule_type)
        row = waf.clean_binding(dict(binding_attrs or {}))
    else:
        key, row = waf.easy_rule(
            rule, host=host, path=path, match=match, scheme=scheme, extensions=extensions, field=field,
            field_is_regex=field_is_regex, location=location, value=value,
        )
    spec = waf.RULE_TYPES[key]
    if not row.get(spec.identity[0]):
        raise ValueError(f"The rule needs {spec.identity[0]!r} (in binding_attrs for rule='raw').")
    if comment:
        row["comment"] = comment
    if not dry_run:
        _require_write()
    results = []
    for name in _profiles(profile):
        try:
            existing = _rows(await _get_client().get("config", spec.binding, resource_name=name), spec.binding)
        except NitroError as exc:
            results.append({"profile": name, "status": f"error: {exc}"})
            continue
        if waf.binding_key(spec, row) in {waf.binding_key(spec, r) for r in existing}:
            status = "exists"
        elif dry_run:
            status = "would add"
        else:
            status = await _bind(spec, name, row)
        results.append({"profile": name, "status": status})
    out: dict[str, Any] = {"dry_run": dry_run, "rule_type": key, "rule": row, "results": results}
    if dry_run:
        out["next"] = "Call again with dry_run=false to bind (needs NETSCALER_ALLOW_WRITE); persist with save_config."
    return out


@mcp.tool()
async def remove_waf_rule(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str, Field(description="Rule type, as in list_waf_rules (e.g. 'start_url').")],
    rule: Annotated[dict[str, Any], Field(description="The rule to remove: a row from list_waf_rules, or just its main value, e.g. {\"starturl\": \"^https://app\\\\.corp/old/.*$\"}.")],
    all_matches: Annotated[bool, Field(description="Remove every rule matching the given attributes (otherwise several matches is an error).")] = False,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE.")] = True,
) -> dict[str, Any]:
    """Remove (unbind) a WAF rule from a profile (WRITE — requires NETSCALER_ALLOW_WRITE).

    Matches live rules on the identifying attributes you pass (value, form action URL, location, value
    type/expression, ruletype); other keys are ignored. Previews by default. Live immediately once
    applied; persist with save_config.
    """
    key = waf.rule_type(rule_type)
    spec = waf.RULE_TYPES[key]
    given = {a: v for a, v in (rule or {}).items() if a in spec.identity + ("ruletype",) and v not in (None, "")}
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
    results = []
    for row in matches:
        status = "would remove" if dry_run else await _unbind(spec, profile, row)
        results.append({"rule": row, "status": status})
    return {"profile": profile, "rule_type": key, "dry_run": dry_run, "matched": len(matches), "results": results}


@mcp.tool()
async def deploy_waf_learned_rules(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str, Field(description="Learned check to deploy: start_url, sql_injection, cross_site_scripting, field_consistency, cookie_consistency, field_format, csrf_tag, content_type or credit_card.")],
    contains: Annotated[str | None, Field(description="Only entries whose learned values contain this (case-insensitive).")] = None,
    min_hits: Annotated[int | None, Field(description="Only entries seen at least this many times.", ge=0)] = None,
    remove_learned: Annotated[bool, Field(description="Delete deployed entries from the learning database, as the GUI's Deploy does.")] = True,
    limit: Annotated[int, Field(description="Max rules to deploy in one call.", ge=1, le=2000)] = 500,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE.")] = True,
) -> dict[str, Any]:
    """Deploy learned entries as WAF relaxation rules (WRITE — requires NETSCALER_ALLOW_WRITE).

    Filters the learned entries and binds each one's 'rule' (see list_waf_learned_rules) unless it
    already exists — or, for start URLs, an enabled start URL rule already covers it — then removes the
    entry from the learning database. Review the preview: NITRO returns learned data as generic
    url/name/value fields, so confirm the mapped rule looks right on your build first. For start URLs a
    few broad add_waf_rule prefixes usually beat hundreds of exact URLs (add those first; covered
    entries are then just cleared). Live immediately once applied; persist with save_config.
    """
    key = waf.rule_type(rule_type)
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
            result["status"] = "would add" if dry_run else await _bind(spec, profile, row)
        if remove_learned and result["status"] in ("exists", "covered", "added", "would add"):
            result["learned"] = "would remove" if dry_run else await _forget_learned(spec, profile, row)
        results.append(result)
    out: dict[str, Any] = {
        "profile": profile,
        "rule_type": key,
        "dry_run": dry_run,
        "matched": len(entries),
        "unmapped": unmapped,
        "summary": _tally([r["status"] for r in results]),
        "results": results[:200],
    }
    if dry_run:
        out["next"] = "Check each 'rule', then call again with dry_run=false; persist with save_config."
    return out


@mcp.tool()
async def discard_waf_learned_rules(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    rule_type: Annotated[str, Field(description="Learned check: start_url, sql_injection, cross_site_scripting, field_consistency, cookie_consistency, field_format, csrf_tag, content_type or credit_card.")],
    contains: Annotated[str | None, Field(description="Only entries whose learned values contain this (case-insensitive).")] = None,
    max_hits: Annotated[int | None, Field(description="Only entries seen at most this many times (one-off noise).", ge=0)] = None,
    all_entries: Annotated[bool, Field(description="Discard every learned entry of this check (required when no filter is given).")] = False,
    limit: Annotated[int, Field(description="Max entries to discard in one call.", ge=1, le=2000)] = 500,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE.")] = True,
) -> dict[str, Any]:
    """Delete learned entries that must not become rules — scanner noise, attack attempts, test junk
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    Needs a filter (contains / max_hits) or all_entries=true, and previews by default.
    """
    key = waf.rule_type(rule_type)
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
    results: list[dict[str, Any]] = []
    for entry in entries[: _clamp(limit, default=500, maximum=2000)]:
        row = entry.get("rule") or {}
        if not waf.learned_delete_args(spec, row):
            status = "unmapped"
        else:
            status = "would remove" if dry_run else await _forget_learned(spec, profile, row)
        results.append({"hits": entry["hits"], "learned": entry["learned"], "status": status})
    return {
        "profile": profile,
        "rule_type": key,
        "dry_run": dry_run,
        "matched": len(entries),
        "summary": _tally([r["status"] for r in results]),
        "results": results[:200],
    }


@mcp.tool()
async def set_waf_check_actions(
    profile: Annotated[str, Field(description="AppFw profile name.")],
    checks: Annotated[list[str], Field(description="Checks to change, e.g. ['start_url', 'sql_injection', 'cross_site_scripting'], or ['all'] for every check the profile has.")],
    set_actions: Annotated[list[str] | None, Field(description="Replace the action list with these: none, block, learn, log, stats.")] = None,
    add_actions: Annotated[list[str] | None, Field(description="Add these actions, e.g. ['block'] when going live.")] = None,
    remove_actions: Annotated[list[str] | None, Field(description="Remove these actions, e.g. ['learn'] once rules are deployed.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE.")] = True,
) -> dict[str, Any]:
    """Change what a WAF profile does per security check — the learn → block switch (WRITE — requires
    NETSCALER_ALLOW_WRITE).

    Typical rollout: learn+log+stats while real traffic flows → deploy/add relaxations → watch the logs
    → add_actions=['block'], remove_actions=['learn']. Only start URL, content type, cookie/field
    consistency, CSRF, XSS, SQL, field format, credit card and XML DoS/XSS/WSI/attachment can learn
    (with checks=['all'], 'learn' is skipped where unsupported). Shows before/after per check; previews
    by default. Live immediately once applied; persist with save_config.
    """
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
    if changes and not dry_run:
        await _get_client().update("appfwprofile", {"name": profile, **changes})
    return {"profile": profile, "dry_run": dry_run, "changed": len(changes), "checks": table}


@mcp.tool()
async def import_waf_profile(
    document: Annotated[dict[str, Any] | str | None, Field(description="An export_waf_profile document (object or JSON string).")] = None,
    file: Annotated[str | None, Field(description="Or a bare file name in NETSCALER_EXPORT_DIR, e.g. 'pr_app-test.json'.")] = None,
    target_profile: Annotated[str | None, Field(description="Profile to import into (created if missing); defaults to the document's source profile name.")] = None,
    host_map: Annotated[dict[str, str] | None, Field(description="Switch hostnames on the way in, e.g. {\"app.test.corp\": \"app.corp\"}.")] = None,
    mode: Annotated[str, Field(description="'merge' adds missing rules only; 'replace' makes the profile's rules match the document — it also re-binds changed rules and REMOVES rules not in the document.")] = "merge",
    include_settings: Annotated[bool | None, Field(description="Apply the document's profile settings (check actions, limits, …) and learning thresholds. Default: only when the profile is created, so an existing profile keeps its own learn/block actions.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE.")] = True,
) -> dict[str, Any]:
    """Import a WAF profile document — copy a tuned profile to another environment or appliance
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    Plans against the live target first: settings changes, and per rule type how many rules are added,
    updated and removed (the preview shows up to 25 of each). Apply order is safe for live traffic:
    create profile → settings → add rules → re-bind changed → remove extras. A new profile still has to
    be bound to an AppFw policy to take effect. Live immediately once applied; persist with save_config.
    """
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
    doc = waf.check_document(document)
    target = (target_profile or "").strip() or str((doc.get("source") or {}).get("profile") or "")
    if not target:
        raise ValueError("target_profile is required (the document names no source profile).")
    extra: dict[str, Any] = {}
    if host_map:
        doc, extra["host_replacements"] = waf.apply_host_map(doc, host_map)
    out = await _apply_document(doc, target, mode=mode, include_settings=include_settings, dry_run=dry_run)
    return {**extra, **out}


@mcp.tool()
async def rehost_waf_profile(
    profile: Annotated[str, Field(description="AppFw profile whose rules to switch.")],
    from_host: Annotated[str, Field(description="Hostname in the current rules, e.g. 'app.test.corp' (append ':port' to switch a port as well).")],
    to_host: Annotated[str, Field(description="New hostname, e.g. 'app.corp'.")],
    target_profile: Annotated[str | None, Field(description="Write the rehosted copy into this profile (created if missing) and leave the source untouched.")] = None,
    dry_run: Annotated[bool, Field(description="Preview only (default). Set false to apply; needs NETSCALER_ALLOW_WRITE.")] = True,
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
    doc, replacements = waf.apply_host_map(await _export_document(profile), {from_host: to_host})
    if not replacements:
        return {
            "profile": profile,
            "message": f"No rule or setting references {from_host!r}; nothing to switch.",
            "hosts": doc["hosts"],
        }
    target = (target_profile or "").strip() or profile
    in_place = target == profile
    out = await _apply_document(
        doc, target, mode="replace", include_settings=True if in_place else None, dry_run=dry_run
    )
    return {"host_replacements": replacements, **out}


@mcp.tool()
async def save_config() -> dict[str, Any]:
    """Save the running configuration (save ns config) so applied WAF changes survive a reboot
    (WRITE — requires NETSCALER_ALLOW_WRITE).

    NITRO changes are live immediately but only in the running config until saved.
    """
    _require_write()
    await _get_client().action("nsconfig", "save")
    return {"saved": True}


# ---- tool: raw escape hatch ---------------------------------------------

@mcp.tool()
async def nitro_get(
    tree: Annotated[str, Field(description="Which NITRO tree: 'config' or 'stat'.")],
    resourcetype: Annotated[str, Field(description="NITRO resource type, e.g. 'route', 'nsip', 'sslcertkey'. Note the stat 'Interface' resource is Capitalized.")],
    name: Annotated[str | None, Field(description="Optional exact resource name to fetch a single object.")] = None,
    attrs: Annotated[str | None, Field(description="Comma-separated attributes to project, e.g. 'name,curstate'.")] = None,
    filter: Annotated[str | None, Field(description="NITRO filter: comma-separated key:value pairs, e.g. 'curstate:UP,servicetype:HTTP'.")] = None,
    count: Annotated[bool, Field(description="Return only the count of matching resources.")] = False,
    pagesize: Annotated[int | None, Field(description="Page size for pagination.", ge=1)] = None,
    pageno: Annotated[int | None, Field(description="Page number (1-indexed).", ge=1)] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only NITRO GET against any config/stat resource on the appliance.

    Use for resources without a dedicated tool (routes, nsip, nsfeature, appfw policies, the
    capitalized 'Interface' stat, etc.). The whole-config resources 'nsrunningconfig' and
    'nssavedconfig' are reachable here but return very large payloads — prefer a targeted resource.
    Returns the raw NITRO envelope.
    """
    if tree not in ("config", "stat"):
        raise ValueError("tree must be 'config' or 'stat'.")
    filt: dict[str, str] | None = None
    if filter:
        filt = {}
        for pair in filter.split(","):
            if ":" in pair:
                key, value = pair.split(":", 1)
                filt[key.strip()] = value.strip()
    return await _get_client().get(
        tree,
        resourcetype,
        resource_name=name,
        attrs=_csv(attrs),
        filter=filt,
        count=count,
        pagesize=pagesize,
        pageno=pageno,
    )


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"netscaler-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = NitroClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
