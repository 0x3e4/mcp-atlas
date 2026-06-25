"""FastMCP server exposing read-only NetScaler ADC (NITRO) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. All tools are read-only — there are no configuration/write actions. Curated
tools cover the common questions; the raw ``nitro_get`` escape hatch reaches anything else.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

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
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
