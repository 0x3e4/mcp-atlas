"""FastMCP server exposing FortiGate (FortiOS REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (GET) cover the common questions across the cmdb (config) and
monitor (live) trees; the raw ``fortios_get`` escape hatch reaches anything else. Write tools
(create/update address objects, add/remove address-group members, enable/disable a policy) are
**opt-in**: they refuse unless ``FORTIGATE_ALLOW_WRITE=true`` and need a REST API admin with a
read-write access profile for Firewall. With the flag off the server is read-only. Unless
``FORTIGATE_CONFIRM_WRITE=false``, every write first returns a preview plus a confirm code and only
runs when called again with that code, after the user has confirmed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import sys
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import FortiClient, FortiError
from .config import ConfigError, Settings

mcp = FastMCP(
    "fortigate-mcp",
    instructions=(
        "Write tools (create_address/update_address/add_to_address_group/remove_from_address_group/"
        "set_policy_status) need the user's confirmation: the first call changes nothing and returns a "
        "preview with a confirm_code. Show the user a short overview of what will change, end with "
        "'Confirm it?', and only after they say yes repeat the call with confirm=<code>."
    ),
)

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: FortiClient | None = None


def _get_client() -> FortiClient:
    global _client
    if _client is None:
        _client = FortiClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in FORTIGATE_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set FORTIGATE_ALLOW_WRITE=true (and use a REST API admin whose "
            "access profile has read-write on Firewall) to change address objects, groups and policies."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when FORTIGATE_CONFIRM_WRITE=false, or when ``code`` matches this exact
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


# ---- curated field projections (the useful columns per resource) --------
_POLICY_FIELDS = (
    "policyid", "name", "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "action",
    "status", "schedule", "nat", "logtraffic", "comments",
)
_ADDRESS_FIELDS = ("name", "type", "subnet", "start-ip", "end-ip", "fqdn", "comment")
_ADDRGRP_FIELDS = ("name", "member", "comment")
_SERVICE_FIELDS = ("name", "protocol", "tcp-portrange", "udp-portrange", "category", "comment")
_SERVICEGRP_FIELDS = ("name", "member", "comment")
_VIP_FIELDS = (
    "name", "type", "extip", "mappedip", "extintf", "extport", "mappedport", "protocol", "comment",
)
_INTERFACE_CFG_FIELDS = ("name", "type", "ip", "allowaccess", "status", "vdom", "alias", "description")
_ROUTE_FIELDS = (
    "seq-num", "dst", "gateway", "device", "distance", "weight", "priority", "status", "comment",
)
_INTERFACE_MON_FIELDS = (
    "name", "alias", "link", "speed", "duplex", "tx_bytes", "rx_bytes", "tx_packets",
    "rx_packets", "tx_errors", "rx_errors", "mac",
)
_POLICY_STAT_FIELDS = (
    "policyid", "uuid", "active_sessions", "bytes", "packets", "hit_count", "last_used", "first_used",
)
_VPN_FIELDS = ("name", "rgwy", "incoming_bytes", "outgoing_bytes", "connection_count", "proxyid")
_ROUTE_MON_FIELDS = ("type", "ip_mask", "gateway", "interface", "distance", "metric", "uptime")
# fields kept from a cmdb POST/PUT response envelope
_WRITE_FIELDS = ("http_method", "status", "http_status", "mkey", "vdom", "revision_changed")


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


def _results(env: dict[str, Any]) -> Any:
    return env.get("results")


def _one(env: dict[str, Any]) -> dict[str, Any]:
    """Return a single object whether FortiOS returned a dict or a 1-element list under results."""
    r = env.get("results")
    if isinstance(r, list):
        return r[0] if r else {}
    return r or {}


async def _get_list(
    tree: str,
    path: str,
    fields: tuple[str, ...],
    *,
    vdom: str | None = None,
    mkey: Any = None,
    limit: int = 50,
    full: bool = False,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fetch a FortiOS collection, project to ``fields`` (unless ``full``), and cap to ``limit``."""
    client = _get_client()
    p = path if mkey is None else f"{path}/{quote(str(mkey), safe='')}"
    env = await client.get(tree, p, vdom=vdom, params=params)
    rows = _results(env)
    if rows is None:
        rows = []
    elif not isinstance(rows, list):
        rows = [rows]
    rows = rows[: _clamp(limit)]
    if not full:
        rows = [_pick(r, fields) if isinstance(r, dict) else r for r in rows]
    return {"vdom": env.get("vdom"), "count": len(rows), "results": rows}


def _written(env: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """Trim a cmdb write response to the envelope essentials plus what was written."""
    out = {k: v for k, v in _pick(env, _WRITE_FIELDS).items() if v is not None}
    out.update(extra)
    return out


def _enc(name: str) -> str:
    """URL-encode an object name for a cmdb path segment (names may hold spaces, '/', etc.)."""
    return quote(str(name), safe="")


def _ipv4(value: str, what: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value.strip())
    except ValueError as exc:
        raise ValueError(f"{what} must be an IPv4 address; got {value!r}.") from exc


def _subnet(value: str) -> str:
    """'10.0.0.0/24', '10.0.0.0 255.255.255.0' or a bare IP -> FortiOS 'ip mask' form."""
    v = " ".join(value.split())
    try:
        iface = ipaddress.IPv4Interface(v.replace(" ", "/"))
    except ValueError as exc:
        raise ValueError(
            f"subnet must be an IPv4 address/prefix like '10.0.0.0/24' or '10.0.0.10'; got {value!r}."
        ) from exc
    return f"{iface.ip} {iface.netmask}"


def _address_payload(
    subnet: str | None, fqdn: str | None, start_ip: str | None, end_ip: str | None,
    *, required: bool,
) -> dict[str, Any]:
    """Build the type + value part of a firewall/address body (exactly one kind, or none)."""
    rng = start_ip is not None or end_ip is not None
    kinds = sum((subnet is not None, fqdn is not None, rng))
    if kinds > 1:
        raise ValueError("Give one kind of address: subnet, fqdn, or start_ip+end_ip — not several.")
    if kinds == 0:
        if required:
            raise ValueError("Give the address: subnet, fqdn, or start_ip+end_ip.")
        return {}
    if subnet is not None:
        return {"type": "ipmask", "subnet": _subnet(subnet)}
    if fqdn is not None:
        f = fqdn.strip()
        if not f or " " in f:
            raise ValueError(f"fqdn must be a hostname like 'app.test.corp'; got {fqdn!r}.")
        return {"type": "fqdn", "fqdn": f}
    if start_ip is None or end_ip is None:
        raise ValueError("An IP range needs both start_ip and end_ip.")
    lo, hi = _ipv4(start_ip, "start_ip"), _ipv4(end_ip, "end_ip")
    if lo > hi:
        raise ValueError("start_ip must not be greater than end_ip.")
    return {"type": "iprange", "start-ip": str(lo), "end-ip": str(hi)}


async def _group_members(group: str, vdom: str | None) -> list[str]:
    """Current member names of a firewall address group (FortiError 404 if it doesn't exist)."""
    env = await _get_client().get("cmdb", f"firewall/addrgrp/{_enc(group)}", vdom=vdom)
    members = _one(env).get("member") or []
    return [m.get("name") for m in members if isinstance(m, dict) and m.get("name")]


def _names(values: list[str]) -> list[str]:
    """Strip, drop blanks and de-duplicate member names (keeping order)."""
    return list(dict.fromkeys(v.strip() for v in values if v and v.strip()))


# ---- tools: configuration (cmdb) ----------------------------------------

@mcp.tool()
async def list_policies(
    policyid: Annotated[int | None, Field(description="Fetch a single policy by its numeric policyid; omit to list all.")] = None,
    ipv6: Annotated[bool, Field(description="List IPv6 policies (firewall/ipv6policy) instead of IPv4.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default (root).")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List firewall policies and their action/state (cmdb firewall/policy).

    Each policy shows source/destination interfaces & addresses, service, action (accept/deny),
    status, NAT and logging. Use policy_stats for live hit counters.
    """
    path = "firewall/ipv6policy" if ipv6 else "firewall/policy"
    return await _get_list("cmdb", path, _POLICY_FIELDS, vdom=vdom, mkey=policyid, limit=limit, full=full)


@mcp.tool()
async def list_addresses(
    name: Annotated[str | None, Field(description="Fetch a single address/group by name; omit to list all.")] = None,
    groups: Annotated[bool, Field(description="List address GROUPS (firewall/addrgrp) instead of individual addresses.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max entries to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List firewall address objects, or address groups with groups=true (cmdb firewall/address[grp])."""
    if groups:
        return await _get_list("cmdb", "firewall/addrgrp", _ADDRGRP_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)
    return await _get_list("cmdb", "firewall/address", _ADDRESS_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)


@mcp.tool()
async def list_services(
    name: Annotated[str | None, Field(description="Fetch a single service/group by name; omit to list all.")] = None,
    groups: Annotated[bool, Field(description="List service GROUPS (firewall/service/group) instead of custom services.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max entries to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List custom firewall services, or service groups with groups=true (cmdb firewall/service/*)."""
    if groups:
        return await _get_list("cmdb", "firewall/service/group", _SERVICEGRP_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)
    return await _get_list("cmdb", "firewall/service/custom", _SERVICE_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)


@mcp.tool()
async def list_vips(
    name: Annotated[str | None, Field(description="Fetch a single VIP by name; omit to list all.")] = None,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max VIPs to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List virtual IPs / destination-NAT objects (cmdb firewall/vip) — external/mapped IPs and ports."""
    return await _get_list("cmdb", "firewall/vip", _VIP_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)


@mcp.tool()
async def list_interfaces(
    name: Annotated[str | None, Field(description="Fetch a single interface by name; omit to list all.")] = None,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max interfaces to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List interface configuration (cmdb system/interface) — IP, allowaccess, type, admin status.

    For live link/traffic state use interface_status (the monitor tree).
    """
    return await _get_list("cmdb", "system/interface", _INTERFACE_CFG_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)


@mcp.tool()
async def list_static_routes(
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max routes to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List configured IPv4 static routes (cmdb router/static). Use routing_table for the live RIB."""
    return await _get_list("cmdb", "router/static", _ROUTE_FIELDS, vdom=vdom, limit=limit, full=full)


# ---- tools: live status (monitor) ---------------------------------------

@mcp.tool()
async def system_info() -> dict[str, Any]:
    """Appliance fingerprint: FortiOS version, serial, hostname/model, firmware and license status.

    Merges monitor system/status, system/firmware and license/status; each section is fetched
    independently so a missing one doesn't fail the whole call. Version/serial/build also come from
    the API response envelope.
    """
    client = _get_client()
    out: dict[str, Any] = {}
    try:
        env = await client.get("monitor", "system/status")
        out["serial"] = env.get("serial")
        out["version"] = env.get("version")
        out["build"] = env.get("build")
        out["status"] = _one(env)
    except FortiError as exc:
        out["status"] = {"error": str(exc)}
    for section, path in (("firmware", "system/firmware"), ("license", "license/status")):
        try:
            out[section] = _one(await client.get("monitor", path))
        except FortiError as exc:
            out[section] = {"error": str(exc)}
    return out


@mcp.tool()
async def system_resources() -> dict[str, Any]:
    """Live system resource usage (monitor system/resource/usage) — CPU, memory, sessions, disk."""
    env = await _get_client().get("monitor", "system/resource/usage")
    return {"results": _results(env)}


@mcp.tool()
async def ha_status(
    full: Annotated[bool, Field(description="Return full member objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """High Availability cluster status (monitor system/ha-statistics) — member role, sync, CPU/mem.

    On a standalone unit this returns a single member (or an empty/zero set).
    """
    env = await _get_client().get("monitor", "system/ha-statistics")
    rows = _results(env)
    if rows is None:
        rows = []
    elif not isinstance(rows, list):
        rows = [rows]
    if not full:
        keep = ("serial", "hostname", "is_root_primary", "is_root_master", "priority", "sync_status",
                "cpu_usage", "mem_usage", "sessions", "tnow")
        rows = [_pick(r, keep) if isinstance(r, dict) else r for r in rows]
    return {"count": len(rows), "results": rows}


@mcp.tool()
async def interface_status(
    name: Annotated[str | None, Field(description="Fetch a single interface by name; omit to list all.")] = None,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max interfaces to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live interface status (monitor system/interface) — link up/down, speed, tx/rx bytes & errors."""
    return await _get_list("monitor", "system/interface", _INTERFACE_MON_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)


@mcp.tool()
async def policy_stats(
    policyid: Annotated[int | None, Field(description="Fetch stats for a single policyid; omit for all.")] = None,
    ipv6: Annotated[bool, Field(description="IPv6 policy stats (firewall/ipv6policy) instead of IPv4.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live per-policy traffic counters (monitor firewall/policy) — hit_count, bytes, packets, sessions.

    Counters are 7-day rolling on FortiOS 7.0+. Cross-reference policyid with list_policies.
    """
    path = "firewall/ipv6policy" if ipv6 else "firewall/policy"
    return await _get_list("monitor", path, _POLICY_STAT_FIELDS, vdom=vdom, mkey=policyid, limit=limit, full=full)


@mcp.tool()
async def vpn_status(
    name: Annotated[str | None, Field(description="Fetch a single IPsec tunnel by name; omit to list all.")] = None,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max tunnels to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live IPsec VPN tunnel status (monitor vpn/ipsec) — remote gateway, traffic, and per-phase2 up/down.

    Each tunnel's 'proxyid' array holds the phase-2 selectors and their up/down 'status'.
    """
    return await _get_list("monitor", "vpn/ipsec", _VPN_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)


@mcp.tool()
async def routing_table(
    ipv6: Annotated[bool, Field(description="Return the IPv6 routing table (router/ipv6) instead of IPv4.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max routes to return (the live table can be large).", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live routing table / RIB (monitor router/ipv4|ipv6) — destination, gateway, interface, metric.

    Capped to 'limit' both server-side (count) and client-side, since the table can be large.
    """
    path = "router/ipv6" if ipv6 else "router/ipv4"
    return await _get_list(
        "monitor", path, _ROUTE_MON_FIELDS, vdom=vdom, limit=limit, full=full,
        params={"start": 0, "count": _clamp(limit)},
    )


# ---- tool: raw escape hatch ---------------------------------------------

@mcp.tool()
async def fortios_get(
    tree: Annotated[str, Field(description="Which API tree: 'cmdb' (config) or 'monitor' (live status).")],
    path: Annotated[str, Field(description="Resource path under the tree, e.g. 'firewall/vip' or 'system/status'.")],
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    filter: Annotated[str | None, Field(description="FortiOS filter expression, e.g. 'name==WAN' or 'srcintf=@port1'.")] = None,
    count: Annotated[int | None, Field(description="Max records (server-side). Useful for large endpoints like firewall/session.", ge=1)] = None,
    start: Annotated[int | None, Field(description="Pagination start index (0-based).", ge=0)] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only GET against any FortiOS cmdb/monitor resource.

    Use for resources without a dedicated tool. NOTE: 'monitor/firewall/session' can return tens of
    thousands of rows — always pass a 'filter' and a small 'count'. Returns the raw FortiOS envelope.
    """
    if tree not in ("cmdb", "monitor"):
        raise ValueError("tree must be 'cmdb' or 'monitor'.")
    params: dict[str, Any] = {}
    if filter:
        params["filter"] = filter
    if count is not None:
        params["count"] = count
    if start is not None:
        params["start"] = start
    return await _get_client().get(tree, path, vdom=vdom, params=params or None)


# ---- tools: writes (opt-in, gated by FORTIGATE_ALLOW_WRITE) --------------

_VDOM_DESC = "VDOM to change; omit to use the configured default."


@mcp.tool()
async def create_address(
    name: Annotated[str, Field(description="Name of the new address object.", min_length=1)],
    subnet: Annotated[str | None, Field(description="IPv4 host or subnet, e.g. '10.0.0.10' or '10.0.0.0/24' (type ipmask).")] = None,
    fqdn: Annotated[str | None, Field(description="Hostname, e.g. 'app.test.corp' (type fqdn).")] = None,
    start_ip: Annotated[str | None, Field(description="First IPv4 address of a range (type iprange; needs end_ip).")] = None,
    end_ip: Annotated[str | None, Field(description="Last IPv4 address of a range (type iprange; needs start_ip).")] = None,
    comment: Annotated[str | None, Field(description="Comment on the object.")] = None,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create an IPv4 firewall address object (WRITE — requires FORTIGATE_ALLOW_WRITE).

    POSTs /api/v2/cmdb/firewall/address. Give exactly one of subnet, fqdn or start_ip+end_ip.
    FortiOS refuses a duplicate name (error -5). Use add_to_address_group to put it in a group.
    """
    _require_write()
    name = name.strip()
    if not name:
        raise ValueError("name must not be blank.")
    payload: dict[str, Any] = {"name": name, **_address_payload(subnet, fqdn, start_ip, end_ip, required=True)}
    if comment is not None:
        payload["comment"] = comment
    value = payload.get("subnet") or payload.get("fqdn") or f"{payload.get('start-ip')}-{payload.get('end-ip')}"
    if preview := _confirm("create_address", {"vdom": vdom, **payload}, f"Create address '{name}' ({payload['type']} {value}).", confirm):
        return preview
    env = await _get_client().post("firewall/address", json=payload, vdom=vdom)
    return _written(env, address=payload)


@mcp.tool()
async def update_address(
    name: Annotated[str, Field(description="Name of the existing address object.", min_length=1)],
    subnet: Annotated[str | None, Field(description="New IPv4 host or subnet, e.g. '10.0.0.0/24' (sets type ipmask).")] = None,
    fqdn: Annotated[str | None, Field(description="New hostname (sets type fqdn).")] = None,
    start_ip: Annotated[str | None, Field(description="New range start (sets type iprange; needs end_ip).")] = None,
    end_ip: Annotated[str | None, Field(description="New range end (sets type iprange; needs start_ip).")] = None,
    comment: Annotated[str | None, Field(description="New comment ('' clears it).")] = None,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change an address object's value or comment (WRITE — requires FORTIGATE_ALLOW_WRITE).

    PUTs /api/v2/cmdb/firewall/address/{name}; only the fields you give change. The change applies
    at once to every policy/group that uses the object — check list_addresses / list_policies first.
    The object can't be renamed here.
    """
    _require_write()
    payload = _address_payload(subnet, fqdn, start_ip, end_ip, required=False)
    if comment is not None:
        payload["comment"] = comment
    if not payload:
        raise ValueError("Nothing to update: provide subnet, fqdn, start_ip+end_ip or comment.")
    change = {"name": name, "vdom": vdom, **payload}
    if preview := _confirm("update_address", change, f"Update address '{name}': {', '.join(payload)}.", confirm):
        return preview
    env = await _get_client().put(f"firewall/address/{_enc(name)}", json=payload, vdom=vdom)
    return _written(env, address={"name": name, **payload})


@mcp.tool()
async def add_to_address_group(
    group: Annotated[str, Field(description="Name of the existing address group.", min_length=1)],
    members: Annotated[list[str], Field(description="Address or address-group names to add.", min_length=1)],
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add members to an address group, keeping the existing ones (WRITE — requires FORTIGATE_ALLOW_WRITE).

    FortiOS replaces a group's whole member list, so this reads the current members
    (GET /api/v2/cmdb/firewall/addrgrp/{group}) and PUTs the merged list back to the same path.
    The members must already exist as address objects/groups.
    """
    _require_write()
    wanted = _names(members)
    if not wanted:
        raise ValueError("Give at least one member name.")
    current = await _group_members(group, vdom)
    added = [m for m in wanted if m not in current]
    if not added:
        raise ValueError(f"Nothing to change: {', '.join(wanted)} already in group '{group}'.")
    member = current + added
    payload = {"member": [{"name": m} for m in member]}
    change = {"group": group, "vdom": vdom, "add": added, **payload}
    if preview := _confirm("add_to_address_group", change, f"Add {', '.join(added)} to address group '{group}'.", confirm):
        return preview
    env = await _get_client().put(f"firewall/addrgrp/{_enc(group)}", json=payload, vdom=vdom)
    return _written(env, group=group, added=added, members=member)


@mcp.tool()
async def remove_from_address_group(
    group: Annotated[str, Field(description="Name of the existing address group.", min_length=1)],
    members: Annotated[list[str], Field(description="Member names to take out of the group (the objects themselves stay).", min_length=1)],
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Remove members from an address group, keeping the others (WRITE — requires FORTIGATE_ALLOW_WRITE).

    Reads the current members (GET /api/v2/cmdb/firewall/addrgrp/{group}) and PUTs the remaining
    list back to the same path. A group can't be emptied (FortiOS needs at least one member); the
    address objects themselves are not deleted.
    """
    _require_write()
    drop = _names(members)
    if not drop:
        raise ValueError("Give at least one member name.")
    current = await _group_members(group, vdom)
    removed = [m for m in current if m in drop]
    if not removed:
        raise ValueError(
            f"Nothing to change: none of {', '.join(drop)} is in group '{group}' (members: {', '.join(current)})."
        )
    member = [m for m in current if m not in drop]
    if not member:
        raise ValueError(f"Refusing to empty address group '{group}': FortiOS needs at least one member.")
    payload = {"member": [{"name": m} for m in member]}
    change = {"group": group, "vdom": vdom, "remove": removed, **payload}
    if preview := _confirm("remove_from_address_group", change, f"Remove {', '.join(removed)} from address group '{group}'.", confirm):
        return preview
    env = await _get_client().put(f"firewall/addrgrp/{_enc(group)}", json=payload, vdom=vdom)
    out = _written(env, group=group, removed=removed, members=member)
    if not_found := [m for m in drop if m not in removed]:
        out["not_members"] = not_found
    return out


@mcp.tool()
async def set_policy_status(
    policy_id: Annotated[int, Field(description="Numeric policyid of the firewall policy (see list_policies).", ge=0)],
    enabled: Annotated[bool, Field(description="true = enable the policy, false = disable it.")],
    comment: Annotated[str | None, Field(description="Optional note; REPLACES the policy's comments field. Omit to keep it.")] = None,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Enable or disable a firewall policy (WRITE — requires FORTIGATE_ALLOW_WRITE).

    PUTs {"status": "enable"|"disable"} to /api/v2/cmdb/firewall/policy/{policy_id}. Disabling stops
    new sessions matching the policy at once (traffic falls through to later policies / implicit
    deny); it is reversible with enabled=true. Nothing else in the policy changes.
    """
    _require_write()
    payload: dict[str, Any] = {"status": "enable" if enabled else "disable"}
    if comment is not None:
        payload["comments"] = comment
    change = {"policy_id": policy_id, "vdom": vdom, **payload}
    if preview := _confirm("set_policy_status", change, f"{payload['status'].capitalize()} firewall policy {policy_id}.", confirm):
        return preview
    env = await _get_client().put(f"firewall/policy/{policy_id}", json=payload, vdom=vdom)
    return _written(env, policy={"policyid": policy_id, **payload})


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"fortigate-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = FortiClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
