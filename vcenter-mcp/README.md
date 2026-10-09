# vcenter-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to a **VMware vCenter Server** through the vSphere Automation REST API (the
new `/api`, vSphere 7.0u2+/8.0). Ask about your virtual infrastructure in natural language — VMs and
their power state, hosts, clusters, datastores, networks, and appliance health.

- One shared `httpx.AsyncClient`; **session** auth (login → `vmware-api-session-id`, re-auth on expiry).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; VM power write tools are **opt-in** behind `VCENTER_ALLOW_WRITE` (see below).
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

### Write tools (opt-in)

These change VM power states and only work when **`VCENTER_ALLOW_WRITE=true`** (otherwise they refuse
with a clear message). The account also needs a role with the matching privileges (see section 1).
Before acting, each tool reads the VM once so the preview shows its **name and current power state**.

| Tool | What it does |
|---|---|
| `vm_guest_power(vm, action: shutdown\|reboot\|standby)` | **Preferred.** Asks the guest OS via VMware Tools for a clean shutdown, reboot or standby. Needs the VM powered on with Tools running (503 otherwise). Returns immediately; the guest finishes on its own. |
| `vm_power(vm, action: start\|stop\|reset\|suspend)` | Hypervisor-level power action. `start` powers on; **`stop` and `reset` are hard** (like pulling the plug / pressing reset, no guest shutdown) — use them only when the guest hangs or has no Tools. |

Check the result with `get_vm_power`. A VM already in the target state comes back as a clean
`ALREADY_IN_DESIRED_STATE` error. There is no snapshot tool: the vSphere Automation REST API has no
documented snapshot endpoint (checked up to 9.1.1).

**Confirmation before every write** (`VCENTER_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments, so a changed request needs a fresh confirmation (codes also
expire when the server restarts). Set `VCENTER_CONFIRM_WRITE=false` to let writes run directly.

## 1. Use a read-only account

Use vCenter SSO credentials for a user/role with **read-only** privileges (vSphere has a built-in
"Read-only" role). That's `VCENTER_USERNAME` / `VCENTER_PASSWORD`.

For the **write** tools, give the account a custom role (instead of Read-only) on the VMs or folders it
may act on, with the privileges it needs — *Virtual machine → Interaction*:

| Tool / action | Privilege |
|---|---|
| `vm_power` `start` | `VirtualMachine.Interact.PowerOn` |
| `vm_power` `stop`, `vm_guest_power` `shutdown` | `VirtualMachine.Interact.PowerOff` |
| `vm_power` `reset`, `vm_guest_power` `reboot` | `VirtualMachine.Interact.Reset` |
| `vm_power` `suspend`, `vm_guest_power` `standby` | `VirtualMachine.Interact.Suspend` |

(A custom role also carries `System.Read`, which the read tools need.) Better still, use a separate
write-enabled instance with its own account and keep the shared one read-only.

## 2. Configure

```bash
cp .env.example vcenter.env
# edit vcenter.env: VCENTER_BASE_URL, VCENTER_USERNAME, VCENTER_PASSWORD
#   (set VCENTER_ALLOW_WRITE=true to enable the power tools)
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

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
account, or one container per vCenter.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-vcenter: &vcenter
  image: ghcr.io/0x3e4/vcenter-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  vcenter-mcp:                    # existing shared read-only instance
    <<: *vcenter
    container_name: vcenter-mcp
    env_file: ./vcenter.env

  vcenter-mcp-instance-a:         # write access with instance a's account
    <<: *vcenter
    container_name: vcenter-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's account and `VCENTER_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `VCENTER_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name vcenter --url http://vcenter-mcp:8000/mcp
  mcpjungle register --name vcenter-instance-a --url http://vcenter-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add vcenter-instance-a -- docker run -i --rm --env-file ./env/instance_a.env vcenter-mcp`

## 4. Verify

`/mcp` to confirm, then ask:

- "How many VMs are powered on?"
- "Show details and power state of VM vm-101."
- "List ESXi hosts that are NOT_RESPONDING."
- "Which datastores are below 10% free?"
- "What's the vCenter version and overall health?"

With `VCENTER_ALLOW_WRITE=true` you can also:

- "Shut down VM vm-42 cleanly."
- "Reboot the guest OS of app01."
- "Power on vm-42."
- "vm-42 is hung and Tools don't answer — hard reset it."

## Notes & scope

- **Writes are opt-in.** Reads are always available; the power tools refuse unless
  `VCENTER_ALLOW_WRITE=true` and the account has the privileges. Leave the flag unset for read-only.
  Only power actions are covered (`POST /api/vcenter/vm/{vm}/power?action=…` and
  `.../guest/power?action=…`); there are no create/delete/reconfigure tools and no raw write escape hatch.
- **No pagination** — vCenter caps list results (e.g. ~4000 VMs); always narrow with filters.
- **Session auth** is handled automatically: the server logs in on first use and transparently
  re-authenticates if the session expires.
- **`vcenter_get`** reaches everything else (folders, VM guest/networking, appliance subsystem health,
  storage, etc.); pass vSphere filter params as arrays, e.g. `{"names": ["web01"]}`.
