"""MCP server exposing FortiGate (FortiOS REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (GET) cover the common questions across the cmdb (config), monitor
(live) and log trees; the generic object tools reach every table in ``KINDS`` and the raw
``fortios_get`` escape hatch anything else. Write tools (objects, policies, address groups) are
**opt-in**: they refuse unless ``FORTIGATE_ALLOW_WRITE=true`` and need a REST API admin with a
read-write access profile. With the flag off the server is read-only. Deletes additionally need
``FORTIGATE_ALLOW_DELETE=true`` and always ask for confirmation; banning IPs and de-authenticating
users need ``FORTIGATE_ALLOW_USER_ACTIONS=true``. Unless ``FORTIGATE_CONFIRM_WRITE=false``, every
write first returns a preview plus a confirm code and only runs when called again with that code,
after the user has confirmed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sys
from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from . import __version__
from .client import FortiClient, FortiError
from .config import ConfigError, Settings

mcp = MCPServer(
    "fortigate-mcp",
    instructions=(
        "Write tools need the user's confirmation: the first call changes nothing and returns a preview "
        "with a confirm_code. Show the user a short overview of what will change, end with 'Confirm it?', "
        "and only after they say yes repeat the call with confirm=<code>. delete_object always asks this "
        "way. FortiOS attribute names are hyphenated (e.g. 'start-ip'); list_kinds shows the tables the "
        "object tools cover. Changes are live at once (no commit step)."
    ),
    version=__version__,
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
            "access profile has read-write on the affected group, e.g. Firewall) to change the configuration."
        )


def _require_delete() -> None:
    """Deletes need FORTIGATE_ALLOW_DELETE on top of FORTIGATE_ALLOW_WRITE (per instance, e.g. per user)."""
    _require_write()
    if not _get_client().settings.allow_delete:
        raise ValueError(
            "Delete tools are disabled. Set FORTIGATE_ALLOW_DELETE=true (in addition to "
            "FORTIGATE_ALLOW_WRITE=true) in this instance's env file to delete objects."
        )


def _require_user_actions() -> None:
    """Banning IPs / de-authenticating users need FORTIGATE_ALLOW_USER_ACTIONS on top of writes."""
    _require_write()
    if not _get_client().settings.allow_user_actions:
        raise ValueError(
            "User actions are disabled. Set FORTIGATE_ALLOW_USER_ACTIONS=true (in addition to "
            "FORTIGATE_ALLOW_WRITE=true) in this instance's env file to ban IPs or de-authenticate users."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(
    tool: str, change: dict[str, Any], summary: str, code: str | None, *, always: bool = False
) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when FORTIGATE_CONFIRM_WRITE=false (unless ``always``: deletes), or when
    ``code`` matches this exact tool + change (so what runs is what the user saw).
    """
    if not always and not _get_client().settings.confirm_write:
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
    ipv6: Annotated[bool, Field(description="FortiOS 6.x only: the separate IPv6 table (firewall/policy6). FortiOS 7.x keeps IPv4 and IPv6 rules together in firewall/policy (srcaddr6/dstaddr6), so leave this off there.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default (root).")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List firewall policies and their action/state (cmdb firewall/policy).

    Each policy shows source/destination interfaces & addresses, service, action (accept/deny),
    status, NAT and logging. Use policy_stats for live hit counters and policy_lookup to find the
    policy a given flow hits.
    """
    path = "firewall/policy6" if ipv6 else "firewall/policy"
    fields = (*_POLICY_FIELDS, "srcaddr6", "dstaddr6") if not ipv6 else _POLICY_FIELDS
    return await _get_list("cmdb", path, fields, vdom=vdom, mkey=policyid, limit=limit, full=full)


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
    groups: Annotated[bool, Field(description="List service GROUPS (firewall.service/group) instead of custom services.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max entries to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List custom firewall services, or service groups with groups=true (cmdb firewall.service/*)."""
    if groups:
        return await _get_list("cmdb", "firewall.service/group", _SERVICEGRP_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)
    return await _get_list("cmdb", "firewall.service/custom", _SERVICE_FIELDS, vdom=vdom, mkey=name, limit=limit, full=full)


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
    ipv6: Annotated[bool, Field(description="IPv6 counters (ip_version=ipv6) instead of IPv4.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max policies to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Live per-policy traffic counters (monitor firewall/policy) — hit_count, bytes, packets, sessions.

    Counters are 7-day rolling on FortiOS 7.0+. Cross-reference policyid with list_policies.
    """
    params: dict[str, Any] = {"ip_version": "ipv6"} if ipv6 else {}
    if policyid is not None:
        params["policyid"] = policyid
    return await _get_list("monitor", "firewall/policy", _POLICY_STAT_FIELDS, vdom=vdom, limit=limit, full=full,
                           params=params or None)


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
    tree: Annotated[str, Field(description="Which API tree: 'cmdb' (config), 'monitor' (live status) or 'log'.")],
    path: Annotated[str, Field(description="Resource path under the tree, e.g. 'firewall/vip', 'firewall.service/custom' (cmdb paths use dots between the path parts) or 'system/status'.")],
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    filter: Annotated[str | None, Field(description="FortiOS filter expression, e.g. 'name==WAN' or 'srcintf=@port1'.")] = None,
    count: Annotated[int | None, Field(description="Max records (server-side). Useful for large endpoints like firewall/session.", ge=1)] = None,
    start: Annotated[int | None, Field(description="Pagination start index (0-based).", ge=0)] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only GET against any FortiOS cmdb/monitor resource.

    Use for resources without a dedicated tool. NOTE: 'monitor/firewall/session' can return tens of
    thousands of rows — always pass a 'filter' and a small 'count'. Returns the raw FortiOS envelope.
    """
    if tree not in ("cmdb", "monitor", "log"):
        raise ValueError("tree must be 'cmdb', 'monitor' or 'log'.")
    params: dict[str, Any] = {}
    if filter:
        params["filter"] = filter
    if count is not None:
        params["count"] = count
    if start is not None:
        params["start"] = start
    return _mask(await _get_client().get(tree, path, vdom=vdom, params=params or None))


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


# ---- generic object tools (table-driven) -------------------------------------

class Kind:
    """A cmdb table the generic object tools cover."""

    def __init__(self, path: str, mkey: str, fields: tuple[str, ...], *, int_key: bool = False,
                 table_keys: dict[str, str] | None = None) -> None:
        self.path, self.mkey, self.fields, self.int_key = path, mkey, fields, int_key
        self.table_keys = table_keys or {}  # list attribute → key of its entries when not "name"


KINDS: dict[str, Kind] = {
    "address": Kind("firewall/address", "name", _ADDRESS_FIELDS),
    "address6": Kind("firewall/address6", "name", ("name", "type", "ip6", "fqdn", "comment")),
    "addrgrp": Kind("firewall/addrgrp", "name", _ADDRGRP_FIELDS),
    "addrgrp6": Kind("firewall/addrgrp6", "name", _ADDRGRP_FIELDS),
    "service": Kind("firewall.service/custom", "name", _SERVICE_FIELDS),
    "service_group": Kind("firewall.service/group", "name", _SERVICEGRP_FIELDS),
    "vip": Kind("firewall/vip", "name", _VIP_FIELDS),
    "vipgrp": Kind("firewall/vipgrp", "name", ("name", "interface", "member", "comments")),
    "ippool": Kind("firewall/ippool", "name", ("name", "type", "startip", "endip", "comments")),
    "schedule_recurring": Kind("firewall.schedule/recurring", "name", ("name", "day", "start", "end")),
    "schedule_onetime": Kind("firewall.schedule/onetime", "name", ("name", "start", "end", "expiration-days")),
    "schedule_group": Kind("firewall.schedule/group", "name", ("name", "member")),
    "policy": Kind("firewall/policy", "policyid", (*_POLICY_FIELDS, "srcaddr6", "dstaddr6"), int_key=True),
    "local_in_policy": Kind("firewall/local-in-policy", "policyid",
                            ("policyid", "intf", "srcaddr", "dstaddr", "service", "action", "schedule", "status", "comments"),
                            int_key=True),
    "static_route": Kind("router/static", "seq-num", _ROUTE_FIELDS, int_key=True),
    "policy_route": Kind("router/policy", "seq-num", ("seq-num", "input-device", "src", "dst", "protocol", "gateway",
                                                      "output-device", "status", "comments"), int_key=True),
    "zone": Kind("system/zone", "name", ("name", "interface", "intrazone", "description"),
                 table_keys={"interface": "interface-name"}),
    "interface": Kind("system/interface", "name", (*_INTERFACE_CFG_FIELDS, "vlanid", "interface")),
    "dhcp_server": Kind("system.dhcp/server", "id", ("id", "interface", "default-gateway", "netmask", "ip-range",
                                                    "dns-service", "status"), int_key=True),
    "user_local": Kind("user/local", "name", ("name", "type", "status", "email-to", "two-factor")),
    "user_group": Kind("user/group", "name", ("name", "group-type", "member")),
    "ipsec_phase1": Kind("vpn.ipsec/phase1-interface", "name", ("name", "interface", "remote-gw", "proposal",
                                                                "ike-version", "peertype", "comments")),
    "ipsec_phase2": Kind("vpn.ipsec/phase2-interface", "name", ("name", "phase1name", "proposal", "src-subnet",
                                                                "dst-subnet", "src-addr-type", "dst-addr-type", "comments")),
    "ssl_vpn_portal": Kind("vpn.ssl.web/portal", "name", ("name", "tunnel-mode", "web-mode", "ip-pools", "split-tunneling")),
    "traffic_shaper": Kind("firewall.shaper/traffic-shaper", "name", ("name", "guaranteed-bandwidth",
                                                                      "maximum-bandwidth", "priority")),
    "webfilter_profile": Kind("webfilter/profile", "name", ("name", "comment", "feature-set")),
    "antivirus_profile": Kind("antivirus/profile", "name", ("name", "comment", "feature-set")),
    "ips_sensor": Kind("ips/sensor", "name", ("name", "comment")),
    "application_list": Kind("application/list", "name", ("name", "comment")),
    "ssl_ssh_profile": Kind("firewall/ssl-ssh-profile", "name", ("name", "comment")),
}
KindName = Literal[tuple(KINDS)]  # type: ignore[valid-type]

_SECRET_KEY = re.compile(r"^(passwd|password|psksecret(-remote)?|secret|private-key|passphrase|.*-password|.*-secret|.*-psk)$")


def _mask(obj: Any) -> Any:
    """Hide secrets: values of password-like attributes and every 'ENC …' blob."""
    if isinstance(obj, dict):
        return {k: ("<masked>" if isinstance(v, str) and v and _SECRET_KEY.match(str(k)) else _mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(v) for v in obj]
    if isinstance(obj, str) and obj.startswith("ENC "):
        return "ENC <masked>"
    return obj


def _kind(kind: str) -> Kind:
    if kind not in KINDS:
        raise ValueError(f"Unknown kind {kind!r}. Kinds: {', '.join(KINDS)}.")
    return KINDS[kind]


def _mkey(k: Kind, name: str | int) -> str:
    value = str(name).strip()
    if not value:
        raise ValueError(f"Give the object's {k.mkey}.")
    if k.int_key and not value.isdigit():
        raise ValueError(f"{k.mkey} must be a number; got {name!r}.")
    return value


def _tableize(k: Kind, data: dict[str, Any]) -> dict[str, Any]:
    """Lists of plain names become FortiOS tables: ["a", "b"] → [{"name": "a"}, {"name": "b"}]."""
    out: dict[str, Any] = {}
    for attr, value in data.items():
        if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            key = k.table_keys.get(attr, "name")
            value = [{key: v} for v in value]
        out[attr] = value
    return out


async def _current(k: Kind, mkey: str, vdom: str | None, *, meta: bool = False) -> dict[str, Any] | None:
    """The object as it is now, or None if it doesn't exist."""
    try:
        env = await _get_client().get("cmdb", f"{k.path}/{_enc(mkey)}", vdom=vdom, params={"with_meta": 1} if meta else None)
    except FortiError as exc:
        if exc.status == 404:
            return None
        raise
    obj = _one(env)
    return obj or None


@mcp.tool()
async def list_kinds() -> dict[str, Any]:
    """The cmdb tables the generic object tools (list_objects, get_object, add_object, update_object,
    delete_object) cover, with their key attribute and API path."""
    return {"kinds": [{"kind": name, "path": k.path, "key": k.mkey} for name, k in KINDS.items()]}


@mcp.tool()
async def list_objects(
    kind: Annotated[KindName, Field(description="Which table (see list_kinds), e.g. 'zone', 'ippool', 'user_group', 'ipsec_phase1'.")],
    filter: Annotated[str | None, Field(description="FortiOS filter, e.g. 'name=@web' (contains) or 'status==enable'.")] = None,
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
    limit: Annotated[int, Field(description="Max entries.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List the objects of any covered cmdb table (secrets masked)."""
    k = _kind(kind)
    out = await _get_list("cmdb", k.path, k.fields, vdom=vdom, limit=limit, full=full,
                          params={"filter": filter} if filter else None)
    return _mask(out)


@mcp.tool()
async def get_object(
    kind: Annotated[KindName, Field(description="Which table (see list_kinds).")],
    name: Annotated[str, Field(description="The object's key: name, or policyid / seq-num / id for numbered tables.")],
    vdom: Annotated[str | None, Field(description="VDOM to query; omit to use the configured default.")] = None,
) -> dict[str, Any]:
    """One object with all its attributes (secrets masked) and how often it is referenced (q_ref)."""
    k = _kind(kind)
    obj = await _current(k, _mkey(k, name), vdom, meta=True)
    if obj is None:
        raise ValueError(f"No {kind} '{name}'.")
    return _mask(obj)


@mcp.tool()
async def add_object(
    kind: Annotated[KindName, Field(description="Which table (see list_kinds).")],
    data: Annotated[dict[str, Any], Field(description="The object in FortiOS attribute names, incl. its key, e.g. {\"name\": \"dmz\", \"interface\": [\"port3\", \"port4\"]}. Lists of plain names become tables. Numbered tables (policy, static_route …) get the next free number when the key is omitted.")],
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create an object in any covered cmdb table (WRITE — requires FORTIGATE_ALLOW_WRITE). POSTs
    /api/v2/cmdb/<path>. For firewall policies create_policy is easier."""
    _require_write()
    k = _kind(kind)
    body = _tableize(k, data)
    if k.mkey not in body and not k.int_key:
        raise ValueError(f"data needs the key attribute '{k.mkey}'.")
    if k.int_key:
        body.setdefault(k.mkey, 0)
    elif await _current(k, _mkey(k, body[k.mkey]), vdom) is not None:
        raise ValueError(f"A {kind} '{body[k.mkey]}' exists already; use update_object.")
    label = body.get(k.mkey) or "(next free number)"
    summary = f"Create {kind} {label}: " + ", ".join(f"{a}={_short(v)}" for a, v in body.items() if a != k.mkey) + "."
    if preview := _confirm("add_object", {"kind": kind, "vdom": vdom, "data": body}, summary, confirm):
        return _mask(preview)
    env = await _get_client().post(k.path, json=body, vdom=vdom)
    return _written(env, kind=kind)


@mcp.tool()
async def update_object(
    kind: Annotated[KindName, Field(description="Which table (see list_kinds).")],
    name: Annotated[str, Field(description="The object's key (name, policyid, seq-num or id).")],
    data: Annotated[dict[str, Any], Field(description="Only the attributes to change, e.g. {\"comments\": \"x\", \"srcaddr\": [\"lan\", \"vpn-users\"]}. Table attributes (members, interfaces, addresses) are REPLACED whole.")],
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change attributes of an object in any covered cmdb table (WRITE — requires FORTIGATE_ALLOW_WRITE).

    The preview shows each attribute's current and new value; the code is tied to the current values,
    so a change in between needs a new confirmation. PUTs /api/v2/cmdb/<path>/<key>.
    """
    _require_write()
    k = _kind(kind)
    mkey = _mkey(k, name)
    if not data:
        raise ValueError("data is empty: give the attributes to change.")
    body = _tableize(k, data)
    current = await _current(k, mkey, vdom)
    if current is None:
        raise ValueError(f"No {kind} '{name}'.")
    diff = {a: {"from": current.get(a), "to": v} for a, v in body.items()}
    if same := [a for a, d in diff.items() if d["from"] == d["to"]]:
        body = {a: v for a, v in body.items() if a not in same}
        if not body:
            return {"changed": False, "note": f"{kind} '{name}' already has these values."}
    summary = f"Update {kind} '{name}': " + ", ".join(f"{a} {_short(diff[a]['from'])} → {_short(v)}" for a, v in body.items()) + "."
    change = {"kind": kind, "name": mkey, "vdom": vdom, "diff": {a: diff[a] for a in body}}
    if preview := _confirm("update_object", change, summary, confirm):
        return _mask(preview)
    env = await _get_client().put(f"{k.path}/{_enc(mkey)}", json=body, vdom=vdom)
    return _written(env, kind=kind, name=mkey, changed=list(body))


@mcp.tool()
async def delete_object(
    kind: Annotated[KindName, Field(description="Which table (see list_kinds).")],
    name: Annotated[str, Field(description="The object's key (name, policyid, seq-num or id).")],
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Delete an object from any covered cmdb table (WRITE, DELETE — requires FORTIGATE_ALLOW_WRITE and
    FORTIGATE_ALLOW_DELETE; always confirmed, even with FORTIGATE_CONFIRM_WRITE=false).

    The preview shows the object and how many other objects reference it (FortiOS refuses to delete a
    referenced object — remove the references first). The code is tied to the object's current state.
    DELETEs /api/v2/cmdb/<path>/<key>.
    """
    _require_delete()
    k = _kind(kind)
    mkey = _mkey(k, name)
    current = await _current(k, mkey, vdom, meta=True)
    if current is None:
        return {"deleted": False, "note": f"No {kind} '{name}': nothing to delete."}
    refs = current.get("q_ref")
    shown = _mask(_pick(current, k.fields))
    summary = f"Delete {kind} '{name}'" + (f" — it is referenced {refs} time(s), FortiOS will refuse until those references are gone" if refs else "") + "."
    change = {"kind": kind, "name": mkey, "vdom": vdom, "object": shown}
    if preview := _confirm("delete_object", change, summary, confirm, always=True):
        return {**preview, "references": refs}
    env = await _get_client().delete(f"{k.path}/{_enc(mkey)}", vdom=vdom)
    return _written(env, kind=kind, deleted=mkey)


def _short(value: Any, limit: int = 80) -> str:
    if isinstance(value, list) and all(isinstance(v, dict) and len(v) == 1 for v in value):
        value = [next(iter(v.values())) for v in value]
    text = json.dumps(value, default=str) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---- policies ------------------------------------------------------------------------

@mcp.tool()
async def create_policy(
    name: Annotated[str, Field(description="Policy name (max 35 characters).", min_length=1, max_length=35)],
    srcintf: Annotated[list[str], Field(description="Incoming interfaces / zones, e.g. ['port1'].", min_length=1)],
    dstintf: Annotated[list[str], Field(description="Outgoing interfaces / zones, e.g. ['wan1'].", min_length=1)],
    srcaddr: Annotated[list[str], Field(description="Source addresses / groups, e.g. ['lan-net'] or ['all'].", min_length=1)],
    dstaddr: Annotated[list[str], Field(description="Destination addresses / groups.", min_length=1)],
    service: Annotated[list[str], Field(description="Services / groups, e.g. ['HTTPS'] or ['ALL'].", min_length=1)],
    action: Annotated[Literal["accept", "deny"], Field(description="accept or deny.")] = "accept",
    schedule: Annotated[str, Field(description="Schedule name.")] = "always",
    nat: Annotated[bool, Field(description="Source NAT to the outgoing interface address.")] = False,
    logtraffic: Annotated[Literal["all", "utm", "disable"], Field(description="Traffic logging.")] = "all",
    enabled: Annotated[bool, Field(description="Create it enabled.")] = True,
    comments: Annotated[str | None, Field(description="Comment.")] = None,
    extra: Annotated[dict[str, Any] | None, Field(description="More FortiOS attributes, e.g. {\"utm-status\": \"enable\", \"av-profile\": \"default\", \"ippool\": \"enable\", \"poolname\": [\"pool1\"]}.")] = None,
    before: Annotated[int | None, Field(description="Place it before this policyid (policies match top-down). Default: at the end.")] = None,
    after: Annotated[int | None, Field(description="Place it after this policyid.")] = None,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a firewall policy and optionally place it before / after another one (WRITE — requires
    FORTIGATE_ALLOW_WRITE). New policies go to the end of the list unless placed; order decides which
    policy matches. POSTs /api/v2/cmdb/firewall/policy, then moves it."""
    _require_write()
    if before is not None and after is not None:
        raise ValueError("Give before or after, not both.")
    k = KINDS["policy"]
    body = _tableize(k, {"policyid": 0, "name": name.strip(), "srcintf": srcintf, "dstintf": dstintf, "srcaddr": srcaddr,
                         "dstaddr": dstaddr, "service": service, "action": action, "schedule": schedule,
                         "nat": "enable" if nat else "disable", "logtraffic": logtraffic,
                         "status": "enable" if enabled else "disable", **({"comments": comments} if comments else {}),
                         **(extra or {})})
    where = f", placed before policy {before}" if before is not None else f", placed after policy {after}" if after is not None else ", at the end"
    summary = (f"Create {action.upper()} policy '{name}': {', '.join(srcintf)} → {', '.join(dstintf)}, "
               f"{', '.join(srcaddr)} → {', '.join(dstaddr)}, {', '.join(service)}{', NAT' if nat else ''}"
               f"{'' if enabled else ', disabled'}{where}.")
    change = {"vdom": vdom, "data": body, "before": before, "after": after}
    if preview := _confirm("create_policy", change, summary, confirm):
        return preview
    client = _get_client()
    env = await client.post(k.path, json=body, vdom=vdom)
    policyid = env.get("mkey")
    out = _written(env, policy={"name": name, "policyid": policyid})
    if (before is not None or after is not None) and policyid is not None:
        params = {"action": "move", **({"before": before} if before is not None else {"after": after})}
        await client.put(f"{k.path}/{policyid}", json=None, vdom=vdom, params=params)
        out["moved"] = params
    return out


@mcp.tool()
async def move_policy(
    policy_id: Annotated[int, Field(description="The policy to move.", ge=0)],
    before: Annotated[int | None, Field(description="Move it before this policyid.")] = None,
    after: Annotated[int | None, Field(description="Move it after this policyid.")] = None,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change a firewall policy's position — policies match top-down (WRITE — requires FORTIGATE_ALLOW_WRITE).
    PUTs /api/v2/cmdb/firewall/policy/{id}?action=move&before=|after=."""
    _require_write()
    if (before is None) == (after is None):
        raise ValueError("Give exactly one of before or after.")
    target = before if before is not None else after
    if target == policy_id:
        raise ValueError("A policy can't be moved relative to itself.")
    params = {"action": "move", **({"before": before} if before is not None else {"after": after})}
    summary = f"Move firewall policy {policy_id} {'before' if before is not None else 'after'} policy {target}."
    if preview := _confirm("move_policy", {"policy_id": policy_id, "vdom": vdom, **params}, summary, confirm):
        return preview
    env = await _get_client().put(f"firewall/policy/{policy_id}", json=None, vdom=vdom, params=params)
    return _written(env, moved={"policyid": policy_id, **params})


@mcp.tool()
async def policy_lookup(
    srcintf: Annotated[str, Field(description="Incoming interface, e.g. 'port1'.")],
    source_ip: Annotated[str, Field(description="Source IP.")],
    dest: Annotated[str, Field(description="Destination IP or FQDN.")],
    protocol: Annotated[str, Field(description="tcp, udp, icmp, or an IP protocol number.")] = "tcp",
    dest_port: Annotated[int | None, Field(description="Destination port (tcp/udp).", ge=1, le=65535)] = None,
    source_port: Annotated[int | None, Field(description="Source port.", ge=1, le=65535)] = None,
    ipv6: Annotated[bool, Field(description="IPv6 flow.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM; omit for the configured default.")] = None,
) -> dict[str, Any]:
    """Which firewall policy would a flow hit? (monitor firewall/policy-lookup) — the answer to 'is X
    allowed to reach Y on port Z'."""
    params: dict[str, Any] = {"srcintf": srcintf, "sourceip": source_ip, "dest": dest, "protocol": protocol}
    if dest_port is not None:
        params["destport"] = dest_port
    if source_port is not None:
        params["sourceport"] = source_port
    if ipv6:
        params["ipv6"] = "true"
    env = await _get_client().get("monitor", "firewall/policy-lookup", vdom=vdom, params=params)
    return {"query": params, "result": _results(env)}


@mcp.tool()
async def route_lookup(
    destination: Annotated[str, Field(description="Destination IP or FQDN.")],
    ipv6: Annotated[bool, Field(description="IPv6.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM; omit for the configured default.")] = None,
) -> dict[str, Any]:
    """Which route / interface traffic to a destination takes (monitor router/lookup)."""
    params: dict[str, Any] = {"destination": destination, **({"ipv6": "true"} if ipv6 else {})}
    env = await _get_client().get("monitor", "router/lookup", vdom=vdom, params=params)
    return {"query": params, "result": _results(env)}


# ---- live tables, sessions, logs, config backup -----------------------------------------

_LIVE = {
    "arp": "network/arp",
    "dhcp_leases": "system/dhcp",
    "fqdn_addresses": "firewall/address-fqdns",
    "sdwan_health": "virtual-wan/health-check",
    "ssl_vpn_sessions": "vpn/ssl",
    "firewall_users": "user/firewall",
    "banned_ips": "user/banned",
    "fortiguard": "system/fortiguard/server-info",
    "certificates": "system/available-certificates",
    "managed_switches": "switch-controller/managed-switch",
    "managed_aps": "wifi/managed_ap",
    "ha_checksums": "system/ha-checksums",
    "license": "license/status",
}


@mcp.tool()
async def live_table(
    topic: Annotated[Literal[tuple(_LIVE)], Field(description="What to show: arp, dhcp_leases, fqdn_addresses (what FQDN objects resolve to), sdwan_health (SD-WAN SLA / health checks), ssl_vpn_sessions, firewall_users (authenticated users), banned_ips, fortiguard (FortiGuard servers), certificates, managed_switches (FortiSwitch), managed_aps (FortiAP), ha_checksums, license.")],  # type: ignore[valid-type]
    vdom: Annotated[str | None, Field(description="VDOM; omit for the configured default.")] = None,
    limit: Annotated[int, Field(description="Max rows.", ge=1, le=1000)] = 200,
) -> dict[str, Any]:
    """Live operational tables from the monitor API (secrets masked)."""
    env = await _get_client().get("monitor", _LIVE[topic], vdom=vdom)
    rows = _results(env)
    if isinstance(rows, dict) and rows and all(isinstance(v, dict) for v in rows.values()):
        rows = [{"name": key, **value} for key, value in rows.items()]  # e.g. SD-WAN health keyed by name
    if isinstance(rows, list):
        return _mask({"topic": topic, "count": min(len(rows), limit), "total": len(rows), "results": rows[:limit]})
    return _mask({"topic": topic, "results": rows})


_SESSION_FIELDS = ("proto", "saddr", "sport", "daddr", "dport", "srcintf", "dstintf", "policyid", "duration",
                   "sentbyte", "rcvdbyte", "username", "apps", "country")


@mcp.tool()
async def list_sessions(
    source: Annotated[str | None, Field(description="Source IP.")] = None,
    destination: Annotated[str | None, Field(description="Destination IP.")] = None,
    dest_port: Annotated[int | None, Field(description="Destination port.", ge=1, le=65535)] = None,
    protocol: Annotated[int | None, Field(description="IP protocol number (6 tcp, 17 udp, 1 icmp).", ge=0, le=255)] = None,
    policy_id: Annotated[int | None, Field(description="Only sessions of this policy.", ge=0)] = None,
    srcintf: Annotated[str | None, Field(description="Incoming interface.")] = None,
    dstintf: Annotated[str | None, Field(description="Outgoing interface.")] = None,
    count: Annotated[int, Field(description="Max sessions (the table can be huge).", ge=1, le=1000)] = 50,
    full: Annotated[bool, Field(description="Return full session objects.")] = False,
    vdom: Annotated[str | None, Field(description="VDOM; omit for the configured default.")] = None,
) -> dict[str, Any]:
    """Current firewall sessions, filtered (monitor firewall/session) — who talks to whom right now."""
    params: dict[str, Any] = {"count": count}
    for key, value in (("source", source), ("destination", destination), ("destport", dest_port),
                       ("protocol", protocol), ("policyid", policy_id), ("srcintf", srcintf), ("dstintf", dstintf)):
        if value is not None:
            params[key] = value
    env = await _get_client().get("monitor", "firewall/session", vdom=vdom, params=params)
    res = _results(env)
    rows = res.get("details", []) if isinstance(res, dict) else (res or [])
    rows = [r if full else _pick(r, _SESSION_FIELDS) for r in rows[:count] if isinstance(r, dict)]
    out: dict[str, Any] = {"count": len(rows), "results": rows}
    if isinstance(res, dict) and "total" in res:
        out["total"] = res["total"]
    return out


@mcp.tool()
async def search_logs(
    log_type: Annotated[Literal["traffic", "event", "virus", "webfilter", "ips", "app-ctrl", "anomaly", "dlp", "emailfilter", "dns", "ssl", "ssh", "file-filter", "waf"], Field(description="Log type.")] = "traffic",
    subtype: Annotated[str | None, Field(description="Subtype; default 'forward' for traffic, 'system' for event. Others: traffic local / multicast / sniffer; event vpn / user / router / wireless / endpoint / ha / sdwan …")] = None,
    filter: Annotated[str | None, Field(description="FortiOS log filter, e.g. 'srcip==10.0.0.5' or 'dstport==443,action==deny' (comma = AND).")] = None,
    source: Annotated[Literal["memory", "disk", "fortianalyzer", "forticloud"], Field(description="Where the logs are stored.")] = "disk",
    rows: Annotated[int, Field(description="Max log lines (newest first).", ge=1, le=1000)] = 50,
    vdom: Annotated[str | None, Field(description="VDOM; omit for the configured default.")] = None,
) -> dict[str, Any]:
    """Search FortiGate logs (GET /api/v2/log/<source>/<type>/<subtype>) — e.g. denied traffic from a host,
    VPN or admin events. Boxes without a disk log to memory: use source='memory'."""
    sub = subtype or {"traffic": "forward", "event": "system"}.get(log_type)
    path = f"{source}/{log_type}" + (f"/{sub}" if sub else "")
    params: dict[str, Any] = {"rows": rows, **({"filter": filter} if filter else {})}
    env = await _get_client().get("log", path, vdom=vdom, params=params)
    lines = _results(env) or []
    return _mask({"path": path, "total_lines": env.get("total_lines"), "count": len(lines) if isinstance(lines, list) else None,
                  "results": lines})


_ENC_RE = re.compile(r"(\bENC\s+)\S+")
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def _config_section(text: str, section: str) -> str:
    """The top-level 'config <section>' block(s) of a FortiOS config file."""
    out: list[str] = []
    inside = False
    head = f"config {section.strip()}"
    for line in text.splitlines():
        if not inside and line.strip() == head and not line.startswith(" "):
            inside = True
        if inside:
            out.append(line)
            if line == "end":
                inside = False
    return "\n".join(out)


@mcp.tool()
async def config_backup(
    section: Annotated[str | None, Field(description="Only this top-level block, e.g. 'firewall policy', 'firewall address', 'system interface', 'router static'.")] = None,
    scope: Annotated[Literal["global", "vdom"], Field(description="global = the whole box; vdom = one VDOM.")] = "global",
    vdom: Annotated[str | None, Field(description="With scope=vdom: which VDOM; omit for the configured default.")] = None,
    max_chars: Annotated[int, Field(description="Cut the text after this many characters.", ge=1000, le=2_000_000)] = 200_000,
) -> dict[str, Any]:
    """The configuration as FortiOS CLI text (monitor system/config/backup) — handy to review or diff a
    whole area at once. Encrypted secrets ('ENC …') and private keys are masked. Needs an admin profile
    that may back up the configuration."""
    params: dict[str, Any] = {"scope": scope}
    text = await _get_client().get_text("monitor", "system/config/backup", vdom=vdom if scope == "vdom" else None,
                                        params=params)
    text = _PEM_RE.sub("<private key masked>", _ENC_RE.sub(r"\1<masked>", text))
    if section:
        text = _config_section(text, section)
        if not text:
            raise ValueError(f"No top-level 'config {section}' block in the configuration.")
    out: dict[str, Any] = {"scope": scope, "section": section, "config": text[:max_chars]}
    if len(text) > max_chars:
        out["truncated"] = f"{len(text) - max_chars} more characters (of {len(text)}); pass section to narrow it."
    return out


# ---- user actions (FORTIGATE_ALLOW_WRITE + FORTIGATE_ALLOW_USER_ACTIONS) ------------------

def _ips(values: list[str]) -> list[str]:
    out = []
    for v in values:
        try:
            out.append(str(ipaddress.ip_address(v.strip())))
        except ValueError as exc:
            raise ValueError(f"Not an IP address: {v!r}.") from exc
    return list(dict.fromkeys(out))


@mcp.tool()
async def ban_ips(
    ips: Annotated[list[str], Field(description="IP addresses to quarantine (block all their traffic).", min_length=1, max_length=100)],
    expiry_seconds: Annotated[int, Field(description="Unban automatically after this many seconds; 0 = until unbanned.", ge=0)] = 0,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Ban (quarantine) IP addresses — the FortiGate drops their traffic (WRITE — requires FORTIGATE_ALLOW_WRITE
    and FORTIGATE_ALLOW_USER_ACTIONS). POSTs monitor user/banned/add_users."""
    _require_user_actions()
    addrs = _ips(ips)
    body: dict[str, Any] = {"ip_addresses": addrs, **({"expiry": expiry_seconds} if expiry_seconds else {})}
    summary = f"Ban {', '.join(addrs)}" + (f" for {expiry_seconds} s." if expiry_seconds else " until unbanned.")
    if preview := _confirm("ban_ips", {"vdom": vdom, **body}, summary, confirm):
        return preview
    env = await _get_client().monitor_post("user/banned/add_users", json=body, vdom=vdom)
    return {"banned": addrs, "status": env.get("status")}


@mcp.tool()
async def unban_ips(
    ips: Annotated[list[str] | None, Field(description="IP addresses to release; omit with all=true to release every banned IP.")] = None,
    all: Annotated[bool, Field(description="Release every banned IP.")] = False,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Release banned (quarantined) IPs (WRITE — requires FORTIGATE_ALLOW_WRITE and FORTIGATE_ALLOW_USER_ACTIONS)."""
    _require_user_actions()
    if bool(ips) == all:
        raise ValueError("Give ips, or all=true — one of them.")
    addrs = _ips(ips or [])
    summary = "Release ALL banned IPs." if all else f"Release {', '.join(addrs)}."
    if preview := _confirm("unban_ips", {"vdom": vdom, "ips": addrs, "all": all}, summary, confirm):
        return preview
    client = _get_client()
    if all:
        env = await client.monitor_post("user/banned/clear_all", vdom=vdom)
    else:
        env = await client.monitor_post("user/banned/clear_users", json={"ip_addresses": addrs}, vdom=vdom)
    return {"released": "all" if all else addrs, "status": env.get("status")}


@mcp.tool()
async def deauth_users(
    ips: Annotated[list[str] | None, Field(description="IPs of authenticated firewall users to log out (see live_table firewall_users).")] = None,
    all: Annotated[bool, Field(description="Log out every authenticated firewall user.")] = False,
    vdom: Annotated[str | None, Field(description=_VDOM_DESC)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Log out authenticated firewall users (WRITE — requires FORTIGATE_ALLOW_WRITE and
    FORTIGATE_ALLOW_USER_ACTIONS). POSTs monitor user/firewall/deauth."""
    _require_user_actions()
    if bool(ips) == all:
        raise ValueError("Give ips, or all=true — one of them.")
    addrs = _ips(ips or [])
    summary = "Log out ALL firewall users." if all else f"Log out the firewall users at {', '.join(addrs)}."
    if preview := _confirm("deauth_users", {"vdom": vdom, "ips": addrs, "all": all}, summary, confirm):
        return preview
    client = _get_client()
    if all:
        await client.monitor_post("user/firewall/deauth", json={"all": True}, vdom=vdom)
        return {"logged_out": "all"}
    for ip in addrs:
        await client.monitor_post("user/firewall/deauth", json={"ip": ip}, vdom=vdom)
    return {"logged_out": addrs}


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
