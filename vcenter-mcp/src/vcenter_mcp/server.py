"""FastMCP server exposing VMware vCenter (vSphere Automation API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (GET) cover VMs, hosts, clusters, datastores, networks and appliance
health; the raw ``vcenter_get`` escape hatch reaches anything else. Write tools (VM power and guest
power actions) are **opt-in**: they refuse unless ``VCENTER_ALLOW_WRITE=true`` and need an account
whose role has the matching ``VirtualMachine.Interact.*`` privileges. With the flag off the server is
read-only. Unless ``VCENTER_CONFIRM_WRITE=false``, every write first returns a preview plus a confirm
code and only runs when called again with that code, after the user has confirmed.

Note: vCenter list endpoints have a result cap and **no pagination** — narrow with filters.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import VCenterClient
from .config import ConfigError, Settings

mcp = FastMCP(
    "vcenter-mcp",
    instructions=(
        "Write tools (vm_power/vm_guest_power) need the user's confirmation: the first call changes "
        "nothing and returns a preview with a confirm_code. Show the user a short overview of what will "
        "change, end with 'Confirm it?', and only after they say yes repeat the call with confirm=<code>. "
        "Prefer vm_guest_power (clean shutdown/reboot via VMware Tools) over the hard vm_power actions."
    ),
)

_client: VCenterClient | None = None


def _get_client() -> VCenterClient:
    global _client
    if _client is None:
        _client = VCenterClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in VCENTER_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set VCENTER_ALLOW_WRITE=true (and use an account whose role has "
            "the matching VirtualMachine.Interact.* privileges) to change VM power states."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when VCENTER_CONFIRM_WRITE=false, or when ``code`` matches this exact
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


# ---- curated field projections ------------------------------------------
_VM_FIELDS = ("vm", "name", "power_state", "cpu_count", "memory_size_MiB")
_VM_DETAIL_FIELDS = ("name", "power_state", "cpu.count", "memory.size_MiB", "guest_OS")
_HOST_FIELDS = ("host", "name", "connection_state", "power_state")
_CLUSTER_FIELDS = ("cluster", "name", "drs_enabled", "ha_enabled")
_DATASTORE_FIELDS = ("datastore", "name", "type", "free_space", "capacity")
_NETWORK_FIELDS = ("network", "name", "type")
_DATACENTER_FIELDS = ("datacenter", "name")
_RESOURCE_POOL_FIELDS = ("resource_pool", "name")

# action -> wording for the preview summary. "Hard" = hypervisor-level, the guest OS is not asked.
_POWER_ACTIONS = {
    "start": "Power on",
    "stop": "HARD power off (no guest shutdown, like pulling the plug)",
    "reset": "HARD reset (no guest reboot, like pressing the reset button)",
    "suspend": "Suspend (hypervisor-level)",
}
_GUEST_POWER_ACTIONS = {
    "shutdown": "clean guest OS shutdown (via VMware Tools)",
    "reboot": "clean guest OS reboot (via VMware Tools)",
    "standby": "guest OS standby (via VMware Tools)",
}


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 100, maximum: int = 1000) -> int:
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


def _lst(value: str | None) -> list[str] | None:
    return [value] if value else None


async def _vm_state(vm: str) -> tuple[Any, Any]:
    """One GET /api/vcenter/vm/{vm} for the write preview -> (name, power_state); 404s on an unknown VM."""
    data = await _get_client().get(f"vcenter/vm/{vm}")
    data = data if isinstance(data, dict) else {}
    return data.get("name"), data.get("power_state")


async def _get_list(
    path: str,
    fields: tuple[str, ...],
    *,
    filters: dict[str, Any] | None = None,
    limit: int = 100,
    full: bool = False,
) -> dict[str, Any]:
    """GET a vCenter list endpoint, cap to ``limit`` (no server pagination), and project."""
    params = {k: v for k, v in (filters or {}).items() if v}
    data = await _get_client().get(path, params=params)
    rows = data if isinstance(data, list) else ([data] if data else [])
    rows = rows[: _clamp(limit)]
    if not full:
        rows = [_pick(r, fields) if isinstance(r, dict) else r for r in rows]
    return {"count": len(rows), "items": rows}


# ---- tools: inventory ---------------------------------------------------

@mcp.tool()
async def list_vms(
    name: Annotated[str | None, Field(description="Filter by exact VM name.")] = None,
    power_state: Annotated[str | None, Field(description="Filter by power state: POWERED_ON, POWERED_OFF, SUSPENDED.")] = None,
    cluster: Annotated[str | None, Field(description="Filter by cluster id (e.g. 'domain-c12').")] = None,
    host: Annotated[str | None, Field(description="Filter by host id (e.g. 'host-42').")] = None,
    limit: Annotated[int, Field(description="Max VMs to return.", ge=1, le=1000)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List virtual machines (GET /api/vcenter/vm). Narrow with filters — the API caps results."""
    filters = {
        "names": _lst(name),
        "power_states": _lst(power_state.upper() if power_state else None),
        "clusters": _lst(cluster),
        "hosts": _lst(host),
    }
    return await _get_list("vcenter/vm", _VM_FIELDS, filters=filters, limit=limit, full=full)


@mcp.tool()
async def get_vm(
    vm: Annotated[str, Field(description="The VM id (e.g. 'vm-123').")],
    full: Annotated[bool, Field(description="Return the full hardware object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get one VM's details (GET /api/vcenter/vm/{vm}) — cpu, memory, guest OS, disks, nics."""
    data = await _get_client().get(f"vcenter/vm/{vm}")
    return data if full else _pick(data, _VM_DETAIL_FIELDS)


@mcp.tool()
async def get_vm_power(
    vm: Annotated[str, Field(description="The VM id (e.g. 'vm-123').")],
) -> dict[str, Any]:
    """Get a VM's power state (GET /api/vcenter/vm/{vm}/power) — POWERED_ON/OFF/SUSPENDED."""
    data = await _get_client().get(f"vcenter/vm/{vm}/power")
    return data if isinstance(data, dict) else {"state": data}


@mcp.tool()
async def list_hosts(
    name: Annotated[str | None, Field(description="Filter by exact host name.")] = None,
    cluster: Annotated[str | None, Field(description="Filter by cluster id.")] = None,
    connection_state: Annotated[str | None, Field(description="Filter by connection state: CONNECTED, DISCONNECTED, NOT_RESPONDING.")] = None,
    limit: Annotated[int, Field(description="Max hosts to return.", ge=1, le=1000)] = 200,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List ESXi hosts (GET /api/vcenter/host) — connection and power state."""
    filters = {"names": _lst(name), "clusters": _lst(cluster), "connection_states": _lst(connection_state)}
    return await _get_list("vcenter/host", _HOST_FIELDS, filters=filters, limit=limit, full=full)


@mcp.tool()
async def list_clusters(
    name: Annotated[str | None, Field(description="Filter by exact cluster name.")] = None,
    limit: Annotated[int, Field(description="Max clusters to return.", ge=1, le=1000)] = 200,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List clusters (GET /api/vcenter/cluster) — DRS/HA enabled flags."""
    return await _get_list("vcenter/cluster", _CLUSTER_FIELDS, filters={"names": _lst(name)}, limit=limit, full=full)


@mcp.tool()
async def list_datastores(
    name: Annotated[str | None, Field(description="Filter by exact datastore name.")] = None,
    type: Annotated[str | None, Field(description="Filter by type: VMFS, NFS, NFS41, VVOL, …")] = None,
    limit: Annotated[int, Field(description="Max datastores to return.", ge=1, le=1000)] = 200,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List datastores (GET /api/vcenter/datastore) — type, free space and capacity (bytes)."""
    filters = {"names": _lst(name), "types": _lst(type.upper() if type else None)}
    return await _get_list("vcenter/datastore", _DATASTORE_FIELDS, filters=filters, limit=limit, full=full)


@mcp.tool()
async def list_networks(
    name: Annotated[str | None, Field(description="Filter by exact network name.")] = None,
    type: Annotated[str | None, Field(description="Filter by type: STANDARD_PORTGROUP, DISTRIBUTED_PORTGROUP, OPAQUE_NETWORK.")] = None,
    limit: Annotated[int, Field(description="Max networks to return.", ge=1, le=1000)] = 200,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List networks (GET /api/vcenter/network)."""
    filters = {"names": _lst(name), "types": _lst(type.upper() if type else None)}
    return await _get_list("vcenter/network", _NETWORK_FIELDS, filters=filters, limit=limit, full=full)


@mcp.tool()
async def list_datacenters(
    name: Annotated[str | None, Field(description="Filter by exact datacenter name.")] = None,
    limit: Annotated[int, Field(description="Max datacenters to return.", ge=1, le=1000)] = 200,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List datacenters (GET /api/vcenter/datacenter)."""
    return await _get_list("vcenter/datacenter", _DATACENTER_FIELDS, filters={"names": _lst(name)}, limit=limit, full=full)


@mcp.tool()
async def list_resource_pools(
    name: Annotated[str | None, Field(description="Filter by exact resource pool name.")] = None,
    cluster: Annotated[str | None, Field(description="Filter by cluster id.")] = None,
    limit: Annotated[int, Field(description="Max resource pools to return.", ge=1, le=1000)] = 200,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List resource pools (GET /api/vcenter/resource-pool)."""
    filters = {"names": _lst(name), "clusters": _lst(cluster)}
    return await _get_list("vcenter/resource-pool", _RESOURCE_POOL_FIELDS, filters=filters, limit=limit, full=full)


# ---- tools: appliance ---------------------------------------------------

@mcp.tool()
async def appliance_version() -> dict[str, Any]:
    """vCenter appliance version/build (GET /api/appliance/system/version)."""
    data = await _get_client().get("appliance/system/version")
    return data if isinstance(data, dict) else {"version": data}


@mcp.tool()
async def appliance_health() -> dict[str, Any]:
    """Overall vCenter appliance health (GET /api/appliance/health/system) — GREEN/ORANGE/RED."""
    data = await _get_client().get("appliance/health/system")
    return data if isinstance(data, dict) else {"status": data}


# ---- tool: raw escape hatch ---------------------------------------------

@mcp.tool()
async def vcenter_get(
    path: Annotated[str, Field(description="API path relative to /api, e.g. 'vcenter/vm', 'vcenter/folder', 'appliance/health/storage'.")],
    params: Annotated[dict[str, Any] | None, Field(description="Query params (filter values), e.g. {\"names\": [\"web01\"], \"power_states\": [\"POWERED_ON\"]}.")] = None,
) -> Any:
    """Escape hatch: raw read-only GET against any vCenter ``/api/...`` resource."""
    data = await _get_client().get_raw(path, params=params)
    return data if isinstance(data, (dict, list)) else {"data": data}


# ---- tools: writes (opt-in, gated by VCENTER_ALLOW_WRITE) ----------------

@mcp.tool()
async def vm_power(
    vm: Annotated[str, Field(description="The VM id (e.g. 'vm-123'); resolve it with list_vms.")],
    action: Annotated[
        Literal["start", "stop", "reset", "suspend"],
        Field(description="start = power on; stop / reset = HARD power off / reset (no guest shutdown); suspend."),
    ],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Hard VM power action (WRITE — requires VCENTER_ALLOW_WRITE). POSTs /api/vcenter/vm/{vm}/power?action=<action>.

    ``stop`` and ``reset`` act at the hypervisor level, like pulling the plug / pressing the reset
    button: the guest OS gets no chance to shut down. For a running VM prefer vm_guest_power
    (shutdown/reboot); use these to power on, or when the guest hangs or has no VMware Tools.
    Needs VirtualMachine.Interact.PowerOn / PowerOff / Reset / Suspend for start / stop / reset / suspend.
    """
    _require_write()
    action = str(action).strip().lower()  # type: ignore[assignment]
    if action not in _POWER_ACTIONS:
        raise ValueError(f"action must be one of {', '.join(_POWER_ACTIONS)}; got {action!r}.")
    name, state = await _vm_state(vm)
    change = {"vm": vm, "action": action}
    summary = f"{_POWER_ACTIONS[action]}: VM '{name}' ({vm}), currently {state}."
    if preview := _confirm("vm_power", change, summary, confirm):
        return preview
    await _get_client().post(f"vcenter/vm/{vm}/power", params={"action": action})
    return {"vm": vm, "name": name, "action": action, "previous_state": state, "done": True,
            "next": "Check the new state with get_vm_power."}


@mcp.tool()
async def vm_guest_power(
    vm: Annotated[str, Field(description="The VM id (e.g. 'vm-123'); resolve it with list_vms.")],
    action: Annotated[
        Literal["shutdown", "reboot", "standby"],
        Field(description="Ask the guest OS (via VMware Tools) to shut down cleanly, reboot, or go to standby."),
    ],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Clean guest-OS power action via VMware Tools (WRITE — requires VCENTER_ALLOW_WRITE). POSTs /api/vcenter/vm/{vm}/guest/power?action=<action>.

    The preferred way to shut down or reboot a running VM. Needs the VM powered on with VMware Tools
    running (vCenter answers 503 otherwise; fall back to vm_power). Returns as soon as the guest has the
    request; the guest finishes on its own, so check get_vm_power afterwards. Needs
    VirtualMachine.Interact.PowerOff / Reset / Suspend for shutdown / reboot / standby.
    """
    _require_write()
    action = str(action).strip().lower()  # type: ignore[assignment]
    if action not in _GUEST_POWER_ACTIONS:
        raise ValueError(f"action must be one of {', '.join(_GUEST_POWER_ACTIONS)}; got {action!r}.")
    name, state = await _vm_state(vm)
    change = {"vm": vm, "action": action}
    summary = f"Request a {_GUEST_POWER_ACTIONS[action]}: VM '{name}' ({vm}), currently {state}."
    if preview := _confirm("vm_guest_power", change, summary, confirm):
        return preview
    await _get_client().post(f"vcenter/vm/{vm}/guest/power", params={"action": action})
    return {"vm": vm, "name": name, "action": action, "previous_state": state, "requested": True,
            "next": "The guest completes this on its own; check the state with get_vm_power in a moment."}


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"vcenter-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    global _client
    _client = VCenterClient(settings)

    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
