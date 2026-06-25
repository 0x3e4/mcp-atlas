# vcenter-mcp

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to a **VMware vCenter Server** through the vSphere Automation REST API (the
new `/api`, vSphere 7.0u2+/8.0). Ask about your virtual infrastructure in natural language — VMs and
their power state, hosts, clusters, datastores, networks, and appliance health.

- One shared `httpx.AsyncClient`; **session** auth (login → `vmware-api-session-id`, re-auth on expiry).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — GET requests only (power on/off etc. are deliberately not exposed; see Notes).
- A raw escape-hatch tool (`vcenter_get`) so any `/api/...` resource stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_vms(name?, power_state?, cluster?, host?, limit?, full?)` | VMs + power state, CPU, memory. |
| `get_vm(vm, full?)` | One VM's details (cpu, memory, guest OS, disks, nics). |
| `get_vm_power(vm)` | A VM's power state. |
| `list_hosts(name?, cluster?, connection_state?, limit?, full?)` | ESXi hosts + connection/power state. |
| `list_clusters(name?, limit?, full?)` | Clusters + DRS/HA flags. |
| `list_datastores(name?, type?, limit?, full?)` | Datastores + type, free space, capacity. |
| `list_networks(name?, type?, limit?, full?)` | Networks (port groups). |
| `list_datacenters(name?, limit?, full?)` | Datacenters. |
| `list_resource_pools(name?, cluster?, limit?, full?)` | Resource pools. |
| `appliance_version()` | vCenter version/build. |
| `appliance_health()` | Overall appliance health (GREEN/ORANGE/RED). |
| `vcenter_get(path, params?)` | Escape hatch: raw read-only GET against any `/api/...` path. |

Results are trimmed by default; pass `full=true` for raw objects. vCenter list endpoints have a result
cap and **no pagination**, so tools cap to `limit` and you narrow with filters (ids like `vm-123`,
`domain-c12`, `host-42`). Resolve ids by listing the parent (e.g. `list_clusters` → cluster id).

## 1. Use a read-only account

Use vCenter SSO credentials for a user/role with **read-only** privileges (vSphere has a built-in
"Read-only" role). That's `VCENTER_USERNAME` / `VCENTER_PASSWORD`.

## 2. Configure

```bash
cp .env.example vcenter.env
# edit vcenter.env: VCENTER_BASE_URL, VCENTER_USERNAME, VCENTER_PASSWORD
```

- **`VCENTER_BASE_URL`** — e.g. `https://vcenter.example.com` (no `/api` suffix).
- **TLS** — vCenter ships a **self-signed cert** by default; set `VCENTER_CA_BUNDLE` to its CA PEM, or
  (lab only) `VCENTER_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t vcenter-mcp .
claude mcp add vcenter -- docker run -i --rm --env-file ./vcenter.env vcenter-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
claude mcp add vcenter -- poetry run vcenter-mcp   # export vcenter.env vars into your shell first
```

### Always-on HTTP (optional)

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

## 4. Verify

`/mcp` to confirm, then ask:

- "How many VMs are powered on?"
- "Show details and power state of VM vm-101."
- "List ESXi hosts that are NOT_RESPONDING."
- "Which datastores are below 10% free?"
- "What's the vCenter version and overall health?"

## Notes & scope

- **Read-only.** Power actions (`POST /api/vcenter/vm/{vm}/power/start|stop|…`) are intentionally not
  exposed. If you want them, they can be added behind an explicit env flag (and a privileged account).
- **No pagination** — vCenter caps list results (e.g. ~4000 VMs); always narrow with filters.
- **Session auth** is handled automatically: the server logs in on first use and transparently
  re-authenticates if the session expires.
- **`vcenter_get`** reaches everything else (folders, VM guest/networking, appliance subsystem health,
  storage, etc.); pass vSphere filter params as arrays, e.g. `{"names": ["web01"]}`.
