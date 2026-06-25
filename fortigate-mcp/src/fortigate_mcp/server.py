"""FastMCP server exposing read-only FortiGate (FortiOS REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. All tools are GET-only (read-only) — there are no configuration actions.
Curated tools cover the common questions across the cmdb (config) and monitor (live) trees; the raw
``fortios_get`` escape hatch reaches anything else.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import FortiClient, FortiError
from .config import ConfigError, Settings

mcp = FastMCP("fortigate-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: FortiClient | None = None


def _get_client() -> FortiClient:
    global _client
    if _client is None:
        _client = FortiClient(Settings.from_env())
    return _client


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
