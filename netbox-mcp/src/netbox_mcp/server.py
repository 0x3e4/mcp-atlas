"""FastMCP server exposing NetBox (DCIM/IPAM) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (GET) cover devices, interfaces, IP addresses/prefixes, virtual
machines and the reference catalogs; the raw ``netbox_get`` escape hatch reaches anything else. Write
tools (create/update IP addresses, allocate the next free IP of a prefix, update a device, add a
journal entry) are **opt-in**: they refuse unless ``NETBOX_ALLOW_WRITE=true`` and need a
write-enabled token whose user has the matching object permissions. With the flag off the server is
read-only. Unless ``NETBOX_CONFIRM_WRITE=false``, every write first returns a preview plus a confirm
code and only runs when called again with that code, after the user has confirmed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sys
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import NetBoxClient
from .config import ConfigError, Settings

mcp = FastMCP(
    "netbox-mcp",
    instructions=(
        "Write tools (create_ip_address/update_ip_address/assign_next_ip/update_device/add_journal_entry) "
        "need the user's confirmation: the first call changes nothing and returns a preview with a "
        "confirm_code. Show the user a short overview of what will change, end with 'Confirm it?', and "
        "only after they say yes repeat the call with confirm=<code>."
    ),
)

_client: NetBoxClient | None = None


def _get_client() -> NetBoxClient:
    global _client
    if _client is None:
        _client = NetBoxClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in NETBOX_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set NETBOX_ALLOW_WRITE=true (and use a write-enabled token whose "
            "user has the matching add/change object permissions) to create or edit IP addresses, "
            "devices and journal entries."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when NETBOX_CONFIRM_WRITE=false, or when ``code`` matches this exact
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

# write responses carry full objects; keep these plus the browser URL (display_url, NetBox 4.x)
_IP_WRITE_FIELDS = (
    "id", "address", "status.value", "role.value", "dns_name", "vrf.display", "tenant.display",
    "assigned_object_type", "assigned_object_id", "assigned_object.display", "description",
)
_DEVICE_WRITE_FIELDS = _DEVICE_FIELDS + (
    "tenant.display", "primary_ip4.address", "primary_ip6.address", "description", "comments",
)
_JOURNAL_FIELDS = (
    "id", "assigned_object_type", "assigned_object_id", "assigned_object.display", "kind.value",
    "created", "comments",
)

# Choice values (NetBox 4.x: ipam/choices.py, dcim/choices.py, extras/choices.py)
IpStatus = Literal["active", "reserved", "deprecated", "dhcp", "slaac"]
IpRole = Literal["loopback", "secondary", "anycast", "vip", "vrrp", "hsrp", "glbp", "carp"]
DeviceStatus = Literal["offline", "active", "planned", "staged", "failed", "inventory", "decommissioning"]
JournalKind = Literal["info", "success", "warning", "danger"]
InterfaceType = Literal["dcim.interface", "virtualization.vminterface"]

_OBJECT_TYPE_RE = re.compile(r"^[a-z_]+\.[a-z_]+$")

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


def _fields(**values: Any) -> dict[str, Any]:
    """Drop unset (None) fields so a write only sends — and a PATCH only changes — what was given."""
    return {k: v for k, v in values.items() if v is not None}


def _assignment(interface_id: int | None, interface_type: str) -> dict[str, Any]:
    """Interface assignment as NetBox's generic relation (assigned_object_type + assigned_object_id)."""
    if interface_id is None:
        return {}
    return {"assigned_object_type": interface_type, "assigned_object_id": interface_id}


def _written(fields: tuple[str, ...], data: Any) -> dict[str, Any]:
    """Trim a create/update response to the key fields plus the object's browser URL."""
    if not isinstance(data, dict):
        return {"result": data}
    out = _pick(data, fields)
    out["url"] = data.get("display_url") or data.get("url")
    return out


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


# ---- write tools (opt-in: NETBOX_ALLOW_WRITE) -----------------------------

_IFACE_ID_DESC = (
    "Interface to assign the address to: a device interface id, or a VM interface id with "
    "interface_type='virtualization.vminterface'."
)
_IFACE_TYPE_DESC = "Kind of interface assigned_interface_id refers to."


@mcp.tool()
async def create_ip_address(
    address: Annotated[str, Field(description="Address with mask, e.g. '10.0.0.10/24'.", min_length=3)],
    status: Annotated[IpStatus | None, Field(description="Status (NetBox default: active).")] = None,
    role: Annotated[IpRole | None, Field(description="Role, e.g. 'vip', 'loopback'.")] = None,
    dns_name: Annotated[str | None, Field(description="DNS name (FQDN), e.g. 'app.test.corp'.", max_length=255)] = None,
    description: Annotated[str | None, Field(description="Short description.", max_length=200)] = None,
    vrf_id: Annotated[int | None, Field(description="VRF id (omit for the global table).")] = None,
    tenant_id: Annotated[int | None, Field(description="Tenant id.")] = None,
    assigned_interface_id: Annotated[int | None, Field(description=_IFACE_ID_DESC)] = None,
    interface_type: Annotated[InterfaceType, Field(description=_IFACE_TYPE_DESC)] = "dcim.interface",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create (document) an IP address (WRITE — requires NETBOX_ALLOW_WRITE). POSTs /api/ipam/ip-addresses/.

    To take the next free address of a prefix, use assign_next_ip instead. NetBox only rejects a
    duplicate when ENFORCE_GLOBAL_UNIQUE (or the VRF's enforce_unique) is on.
    """
    _require_write()
    payload = _fields(
        address=address.strip(), status=status, role=role, dns_name=dns_name, description=description,
        vrf=vrf_id, tenant=tenant_id,
    ) | _assignment(assigned_interface_id, interface_type)
    where = f" on {interface_type} {assigned_interface_id}" if assigned_interface_id is not None else ""
    if preview := _confirm("create_ip_address", payload, f"Create IP address {payload['address']}{where}.", confirm):
        return preview
    return _written(_IP_WRITE_FIELDS, await _get_client().post("ipam/ip-addresses", json=payload))


@mcp.tool()
async def update_ip_address(
    id: Annotated[int, Field(description="IP address id.")],
    status: Annotated[IpStatus | None, Field(description="New status.")] = None,
    role: Annotated[IpRole | None, Field(description="New role.")] = None,
    dns_name: Annotated[str | None, Field(description="New DNS name ('' clears it).", max_length=255)] = None,
    description: Annotated[str | None, Field(description="New description ('' clears it).", max_length=200)] = None,
    tenant_id: Annotated[int | None, Field(description="New tenant id.")] = None,
    assigned_interface_id: Annotated[int | None, Field(description=_IFACE_ID_DESC)] = None,
    interface_type: Annotated[InterfaceType, Field(description=_IFACE_TYPE_DESC)] = "dcim.interface",
    unassign: Annotated[bool, Field(description="Detach the address from its interface.")] = False,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update an IP address's status, role, DNS name, description, tenant or interface (WRITE — requires NETBOX_ALLOW_WRITE).

    PATCHes /api/ipam/ip-addresses/{id}/; only the fields you give change. NetBox refuses to move or
    unassign an address that is the primary IP of its device/VM.
    """
    _require_write()
    if unassign and assigned_interface_id is not None:
        raise ValueError("Give assigned_interface_id or unassign, not both.")
    payload = _fields(
        status=status, role=role, dns_name=dns_name, description=description, tenant=tenant_id,
    ) | _assignment(assigned_interface_id, interface_type)
    if unassign:
        payload |= {"assigned_object_type": None, "assigned_object_id": None}
    if not payload:
        raise ValueError(
            "Nothing to update: provide status, role, dns_name, description, tenant_id or an interface change."
        )
    if preview := _confirm("update_ip_address", {"id": id, **payload}, f"Update IP address {id}: {', '.join(payload)}.", confirm):
        return preview
    return _written(_IP_WRITE_FIELDS, await _get_client().patch(f"ipam/ip-addresses/{id}", json=payload))


@mcp.tool()
async def assign_next_ip(
    prefix_id: Annotated[int, Field(description="Prefix to allocate from (see list_prefixes).")],
    status: Annotated[IpStatus | None, Field(description="Status (NetBox default: active).")] = None,
    dns_name: Annotated[str | None, Field(description="DNS name (FQDN), e.g. 'vm-42.test.corp'.", max_length=255)] = None,
    description: Annotated[str | None, Field(description="Short description.", max_length=200)] = None,
    tenant_id: Annotated[int | None, Field(description="Tenant id.")] = None,
    assigned_interface_id: Annotated[int | None, Field(description=_IFACE_ID_DESC)] = None,
    interface_type: Annotated[InterfaceType, Field(description=_IFACE_TYPE_DESC)] = "dcim.interface",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Allocate the next free IP address of a prefix (WRITE — requires NETBOX_ALLOW_WRITE).

    POSTs /api/ipam/prefixes/{id}/available-ips/. NetBox picks the address under a lock (mask and VRF
    come from the prefix), so it is only known once applied; a full prefix answers 409.
    """
    _require_write()
    payload = _fields(
        status=status, dns_name=dns_name, description=description, tenant=tenant_id,
    ) | _assignment(assigned_interface_id, interface_type)
    where = f" on {interface_type} {assigned_interface_id}" if assigned_interface_id is not None else ""
    summary = (
        f"Allocate the next free address in prefix {prefix_id}{where} "
        "(NetBox chooses the address when this is applied)."
    )
    if preview := _confirm("assign_next_ip", {"prefix_id": prefix_id, **payload}, summary, confirm):
        return preview
    data = await _get_client().post(f"ipam/prefixes/{prefix_id}/available-ips", json=payload)
    if isinstance(data, list):  # a list request returns a list; a single object returns one object
        data = data[0] if data else {}
    return _written(_IP_WRITE_FIELDS, data)


@mcp.tool()
async def update_device(
    id: Annotated[int, Field(description="Device id.")],
    status: Annotated[DeviceStatus | None, Field(description="New status, e.g. 'offline', 'failed', 'decommissioning'.")] = None,
    description: Annotated[str | None, Field(description="New description ('' clears it).", max_length=200)] = None,
    comments: Annotated[str | None, Field(description="New comments (markdown) — replaces the whole field ('' clears it).")] = None,
    serial: Annotated[str | None, Field(description="New serial number.", max_length=50)] = None,
    tenant_id: Annotated[int | None, Field(description="New tenant id.")] = None,
    primary_ip4_id: Annotated[int | None, Field(description="IP address id to make the primary IPv4 (must be assigned to one of the device's interfaces).")] = None,
    primary_ip6_id: Annotated[int | None, Field(description="IP address id to make the primary IPv6 (must be assigned to one of the device's interfaces).")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a device's status, description, comments, serial, tenant or primary IP (WRITE — requires NETBOX_ALLOW_WRITE).

    PATCHes /api/dcim/devices/{id}/; only the fields you give change. For a running log of what
    happened, prefer add_journal_entry over rewriting comments.
    """
    _require_write()
    payload = _fields(
        status=status, description=description, comments=comments, serial=serial, tenant=tenant_id,
        primary_ip4=primary_ip4_id, primary_ip6=primary_ip6_id,
    )
    if not payload:
        raise ValueError(
            "Nothing to update: provide status, description, comments, serial, tenant_id or a primary IP."
        )
    if preview := _confirm("update_device", {"id": id, **payload}, f"Update device {id}: {', '.join(payload)}.", confirm):
        return preview
    return _written(_DEVICE_WRITE_FIELDS, await _get_client().patch(f"dcim/devices/{id}", json=payload))


@mcp.tool()
async def add_journal_entry(
    object_type: Annotated[str, Field(description="Object type as app_label.model, e.g. 'dcim.device', 'ipam.prefix', 'virtualization.virtualmachine', 'dcim.site'.")],
    object_id: Annotated[int, Field(description="Id of that object.")],
    comments: Annotated[str, Field(description="Entry text (markdown).", min_length=1)],
    kind: Annotated[JournalKind | None, Field(description="Kind (NetBox default: info).")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add a journal entry to any object (WRITE — requires NETBOX_ALLOW_WRITE). POSTs /api/extras/journal-entries/.

    Journal entries are the human change log of an object (maintenance, incidents, checks); the
    object itself is left untouched.
    """
    _require_write()
    object_type = object_type.strip().lower()
    if not _OBJECT_TYPE_RE.match(object_type):
        raise ValueError(f"object_type must look like 'app_label.model' (e.g. 'dcim.device'); got {object_type!r}.")
    payload = _fields(assigned_object_type=object_type, assigned_object_id=object_id, kind=kind, comments=comments)
    summary = f"Add a {kind or 'info'} journal entry to {object_type} {object_id}."
    if preview := _confirm("add_journal_entry", payload, summary, confirm):
        return preview
    return _written(_JOURNAL_FIELDS, await _get_client().post("extras/journal-entries", json=payload))


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
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
