"""FastMCP server exposing read-only NetBox (DCIM/IPAM) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. All tools are read-only (GET). Curated tools cover devices, interfaces,
IP addresses/prefixes, virtual machines and the reference catalogs; the raw ``netbox_get`` escape
hatch reaches anything else.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .client import NetBoxClient
from .config import ConfigError, Settings

mcp = FastMCP("netbox-mcp")

_client: NetBoxClient | None = None


def _get_client() -> NetBoxClient:
    global _client
    if _client is None:
        _client = NetBoxClient(Settings.from_env())
    return _client


# ---- curated field projections (dotted paths reach nested {id,display} objects) --
_DEVICE_FIELDS = (
    "id", "name", "device_type.display", "role.display", "site.display", "location.display",
    "rack.display", "status.value", "primary_ip.address", "serial", "asset_tag",
)
_INTERFACE_FIELDS = ("id", "name", "device.display", "type.label", "enabled", "mtu", "description")
_IP_FIELDS = ("id", "address", "status.value", "dns_name", "vrf.display", "assigned_object.display", "description")
_PREFIX_FIELDS = ("id", "prefix", "status.value", "site.display", "vrf.display", "vlan.display", "description")
_VM_FIELDS = (
    "id", "name", "status.value", "cluster.display", "role.display", "primary_ip.address",
    "vcpus", "memory", "disk",
)

_OBJECT_KINDS = {
    "sites": ("dcim/sites", ("id", "name", "slug", "status.value", "region.display")),
    "racks": ("dcim/racks", ("id", "name", "site.display", "status.value", "u_height", "device_count")),
    "device-roles": ("dcim/device-roles", ("id", "name", "slug")),
    "device-types": ("dcim/device-types", ("id", "manufacturer.display", "model", "slug", "u_height")),
    "manufacturers": ("dcim/manufacturers", ("id", "name", "slug")),
    "locations": ("dcim/locations", ("id", "name", "site.display")),
    "vlans": ("ipam/vlans", ("id", "vid", "name", "site.display", "status.value")),
    "vrfs": ("ipam/vrfs", ("id", "name", "rd", "tenant.display")),
    "aggregates": ("ipam/aggregates", ("id", "prefix", "rir.display")),
    "ip-ranges": ("ipam/ip-ranges", ("id", "start_address", "end_address", "status.value")),
    "clusters": ("virtualization/clusters", ("id", "name", "type.display", "site.display")),
    "tenants": ("tenancy/tenants", ("id", "name", "slug")),
    "tags": ("extras/tags", ("id", "name", "slug", "color")),
}


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 1000) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
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


async def _get_list(
    path: str,
    fields: tuple[str, ...],
    *,
    params: dict[str, Any] | None = None,
    limit: int = 50,
    offset: int = 0,
    full: bool = False,
) -> dict[str, Any]:
    """GET a NetBox list endpoint, project to ``fields`` (unless ``full``), and cap to ``limit``."""
    q: dict[str, Any] = {"limit": _clamp(limit), "offset": offset}
    if params:
        q.update({k: v for k, v in params.items() if v is not None})
    data = await _get_client().get(path, params=q)
    results = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    count = data.get("count") if isinstance(data, dict) else None
    if not full:
        results = [_pick(r, fields) for r in results if isinstance(r, dict)]
    return {"count": count, "returned": len(results), "results": results}


# ---- tools --------------------------------------------------------------

@mcp.tool()
async def list_devices(
    q: Annotated[str | None, Field(description="Free-text search across device fields.")] = None,
    name: Annotated[str | None, Field(description="Exact device name.")] = None,
    site_id: Annotated[int | None, Field(description="Filter by site id.")] = None,
    role: Annotated[str | None, Field(description="Filter by device role slug.")] = None,
    status: Annotated[str | None, Field(description="Filter by status, e.g. 'active', 'offline'.")] = None,
    limit: Annotated[int, Field(description="Max devices to return.", ge=1, le=1000)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List/search DCIM devices (GET /api/dcim/devices/)."""
    params = {"q": q, "name": name, "site_id": site_id, "role": role, "status": status}
    return await _get_list("dcim/devices", _DEVICE_FIELDS, params=params, limit=limit, offset=offset, full=full)


@mcp.tool()
async def get_device(
    device_id: Annotated[int, Field(description="The device id.")],
    full: Annotated[bool, Field(description="Return the full object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get one device with its details (GET /api/dcim/devices/{id}/)."""
    data = await _get_client().get(f"dcim/devices/{device_id}")
    return data if full else _pick(data, _DEVICE_FIELDS)


@mcp.tool()
async def list_interfaces(
    device_id: Annotated[int | None, Field(description="Filter to one device's interfaces.")] = None,
    name: Annotated[str | None, Field(description="Exact interface name.")] = None,
    limit: Annotated[int, Field(description="Max interfaces to return.", ge=1, le=1000)] = 100,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List DCIM interfaces (GET /api/dcim/interfaces/) — filter by device_id for one device."""
    params = {"device_id": device_id, "name": name}
    return await _get_list("dcim/interfaces", _INTERFACE_FIELDS, params=params, limit=limit, offset=offset, full=full)


@mcp.tool()
async def list_ip_addresses(
    q: Annotated[str | None, Field(description="Free-text search.")] = None,
    address: Annotated[str | None, Field(description="Exact address or CIDR, e.g. '10.0.0.1/24'.")] = None,
    vrf_id: Annotated[int | None, Field(description="Filter by VRF id.")] = None,
    status: Annotated[str | None, Field(description="Filter by status, e.g. 'active'.")] = None,
    dns_name: Annotated[str | None, Field(description="Filter by DNS name (exact).")] = None,
    limit: Annotated[int, Field(description="Max IPs to return.", ge=1, le=1000)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List/search IP addresses (GET /api/ipam/ip-addresses/)."""
    params = {"q": q, "address": address, "vrf_id": vrf_id, "status": status, "dns_name": dns_name}
    return await _get_list("ipam/ip-addresses", _IP_FIELDS, params=params, limit=limit, offset=offset, full=full)


@mcp.tool()
async def list_prefixes(
    q: Annotated[str | None, Field(description="Free-text search.")] = None,
    prefix: Annotated[str | None, Field(description="Exact prefix, e.g. '10.0.0.0/24'.")] = None,
    site_id: Annotated[int | None, Field(description="Filter by site id.")] = None,
    vrf_id: Annotated[int | None, Field(description="Filter by VRF id.")] = None,
    status: Annotated[str | None, Field(description="Filter by status, e.g. 'active', 'reserved'.")] = None,
    limit: Annotated[int, Field(description="Max prefixes to return.", ge=1, le=1000)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List/search IP prefixes (GET /api/ipam/prefixes/)."""
    params = {"q": q, "prefix": prefix, "site_id": site_id, "vrf_id": vrf_id, "status": status}
    return await _get_list("ipam/prefixes", _PREFIX_FIELDS, params=params, limit=limit, offset=offset, full=full)


@mcp.tool()
async def list_virtual_machines(
    q: Annotated[str | None, Field(description="Free-text search.")] = None,
    name: Annotated[str | None, Field(description="Exact VM name.")] = None,
    cluster_id: Annotated[int | None, Field(description="Filter by cluster id.")] = None,
    status: Annotated[str | None, Field(description="Filter by status, e.g. 'active'.")] = None,
    limit: Annotated[int, Field(description="Max VMs to return.", ge=1, le=1000)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List/search virtual machines (GET /api/virtualization/virtual-machines/)."""
    params = {"q": q, "name": name, "cluster_id": cluster_id, "status": status}
    return await _get_list("virtualization/virtual-machines", _VM_FIELDS, params=params, limit=limit, offset=offset, full=full)


@mcp.tool()
async def list_objects(
    kind: Annotated[str, Field(description="Catalog to list: sites, racks, device-roles, device-types, manufacturers, locations, vlans, vrfs, aggregates, ip-ranges, clusters, tenants, tags.")],
    q: Annotated[str | None, Field(description="Free-text search.")] = None,
    name: Annotated[str | None, Field(description="Exact name filter.")] = None,
    limit: Annotated[int, Field(description="Max rows to return.", ge=1, le=1000)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List a reference catalog (sites/racks/roles/types/manufacturers/vlans/vrfs/clusters/tenants/tags/…)."""
    key = (kind or "").strip().lower()
    if key not in _OBJECT_KINDS:
        raise ValueError(f"kind must be one of {tuple(_OBJECT_KINDS)}; got {kind!r}.")
    path, fields = _OBJECT_KINDS[key]
    return await _get_list(path, fields, params={"q": q, "name": name}, limit=limit, offset=offset, full=full)


@mcp.tool()
async def netbox_get(
    path: Annotated[str, Field(description="API path relative to /api, e.g. 'dcim/devices', 'ipam/prefixes/5', 'dcim/cables'.")],
    params: Annotated[dict[str, Any] | None, Field(description="Query params, e.g. {\"limit\": 10, \"q\": \"core\", \"status\": \"active\"}.")] = None,
) -> Any:
    """Escape hatch: raw read-only GET against any NetBox ``/api/...`` resource (trailing slash added)."""
    data = await _get_client().get_raw(path, params=params)
    return data if isinstance(data, (dict, list)) else {"data": data}


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"netbox-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    global _client
    _client = NetBoxClient(settings)

    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
