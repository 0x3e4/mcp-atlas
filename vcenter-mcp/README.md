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

Run the server as a long-lived `streamable-http` service instead of per-session stdio.
[`compose.yml`](compose.yml) already sets `MCP_TRANSPORT=streamable-http` and binds `0.0.0.0:8000`:

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

Point any HTTP MCP client at `http://<host>:8000/mcp` (also the only mode remote clients like
OpenAI support). **On localhost this works as-is — nothing else to change.**

#### Behind an MCP gateway (shared Docker network)

A gateway (e.g. [mcpjungle](https://github.com/mcpjungle/MCPJungle)) fronts many servers behind one
endpoint. Running several atlas servers next to a gateway on one host changes two things:

- The published **`8000:8000` host port collides** once more than one server uses it. Drop the host
  port and let the gateway reach the server **by its compose service name** over a shared Docker
  network (or, if you must publish, give each server a distinct host port like `"8001:8000"`).
- Put the **gateway and the servers on one shared network**, so `http://vcenter-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  vcenter-mcp:
    build: .
    image: vcenter-mcp
    env_file: ./vcenter.env
    environment:
      MCP_TRANSPORT: streamable-http
      MCP_HOST: 0.0.0.0
      FASTMCP_HOST: 0.0.0.0
      MCP_PORT: "8000"
    # no `ports:` — only the gateway reaches it, over atlas-net
    networks: [atlas-net]
    restart: unless-stopped

networks:
  atlas-net:
    external: true
```

With the gateway also on `atlas-net`, register this server at `http://vcenter-mcp:8000/mcp`
(`mcpjungle register --name vcenter --url http://vcenter-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

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
