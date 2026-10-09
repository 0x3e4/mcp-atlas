# netbox-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to **[NetBox](https://netbox.dev)** (the DCIM/IPAM network source of truth) through its
REST API. Ask about your infrastructure in natural language — devices and interfaces, IP addresses and
prefixes, virtual machines, and the supporting catalogs (sites, racks, VLANs, …) — and, opt-in,
**document and allocate IP addresses, update devices and write journal entries**.

- One shared `httpx.AsyncClient`; **token** auth (auto: `Token` for v1, `Bearer` for v2 `nbt_…`).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `NETBOX_ALLOW_WRITE` (see below).
- A raw escape-hatch tool (`netbox_get`) so any `/api/...` endpoint stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_devices(q?, name?, site_id?, role?, status?, limit?, offset?, full?)` | DCIM devices + role/site/rack/status/primary IP. |
| `get_device(device_id, full?)` | One device's details. |
| `list_interfaces(device_id?, name?, limit?, offset?, full?)` | DCIM interfaces (filter by device). |
| `list_ip_addresses(q?, address?, vrf_id?, status?, dns_name?, limit?, offset?, full?)` | IP addresses + assignment. |
| `list_prefixes(q?, prefix?, site_id?, vrf_id?, status?, limit?, offset?, full?)` | IP prefixes. |
| `list_virtual_machines(q?, name?, cluster_id?, status?, limit?, offset?, full?)` | VMs + cluster/resources. |
| `list_objects(kind, q?, name?, limit?, offset?, full?)` | A catalog: `sites`, `racks`, `device-roles`, `device-types`, `manufacturers`, `locations`, `vlans`, `vrfs`, `aggregates`, `ip-ranges`, `clusters`, `tenants`, `tags`. |
| `netbox_get(path, params?)` | Escape hatch: raw read-only GET against any `/api/...` path. |

Results are trimmed to useful fields by default (nested names like `site.display`, `status.value`);
pass `full=true` for raw objects. Lists are capped (`NETBOX_MAX_ROWS`, default 50; NetBox caps at
1000) and support `limit`/`offset`.

### Write tools (opt-in)

These change NetBox and only work when **`NETBOX_ALLOW_WRITE=true`** (otherwise they refuse with a
clear message). They also need a **write-enabled** token whose user has the matching object
permissions (see section 1). Results are trimmed to the key fields plus the object's browser `url`;
NetBox's per-field validation errors (HTTP 400) are passed back verbatim.

| Tool | What it does |
|---|---|
| `create_ip_address(address, status?, role?, dns_name?, description?, vrf_id?, tenant_id?, assigned_interface_id?, interface_type?)` | Document an IP address (`POST /api/ipam/ip-addresses/`), optionally on an interface. |
| `update_ip_address(id, status?, role?, dns_name?, description?, tenant_id?, assigned_interface_id?, interface_type?, unassign?)` | Change an IP's status/role/DNS name/description/tenant, or move/detach it (`PATCH`). |
| `assign_next_ip(prefix_id, status?, dns_name?, description?, tenant_id?, assigned_interface_id?, interface_type?)` | Allocate the **next free address** of a prefix (`POST /api/ipam/prefixes/{id}/available-ips/`). The address is chosen by NetBox when applied, so the preview names the prefix; a full prefix answers 409. |
| `update_device(id, status?, description?, comments?, serial?, tenant_id?, primary_ip4_id?, primary_ip6_id?)` | Change a device's status/description/comments/serial/tenant or set its primary IP (`PATCH /api/dcim/devices/{id}/`). |
| `add_journal_entry(object_type, object_id, comments, kind?)` | Journal entry on any object, e.g. `object_type='dcim.device'` (`POST /api/extras/journal-entries/`). |

`interface_type` is `dcim.interface` (default) or `virtualization.vminterface` for a VM interface.
Only the fields you pass are sent; on the `update_*` tools `''` clears a text field.

**Confirmation before every write** (`NETBOX_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments, so a changed request needs a fresh confirmation (codes also
expire when the server restarts). Set `NETBOX_CONFIRM_WRITE=false` to let writes run directly.

## 1. Create a token

In NetBox: **profile → API Tokens → Add Token**. For a read-only server **uncheck "Write enabled"**.
(Optionally restrict by client IP / set an expiry.) That's `NETBOX_TOKEN`.

For the **write** tools the token must be **write-enabled** (a read-only token gets 403 on every
POST/PATCH), and its user needs object permissions (Admin → Permissions) for what the tools touch —
the token can never do more than its user:

- `ipam.add_ipaddress` — `create_ip_address`, `assign_next_ip` (plus `ipam.view_prefix` for the prefix)
- `ipam.change_ipaddress` — `update_ip_address`
- `dcim.change_device` — `update_device`
- `extras.add_journalentry` — `add_journal_entry` (and view on the target object)

Object permissions can be narrowed with constraints (e.g. only certain prefixes/tenants).

## 2. Configure

```bash
cp .env.example netbox.env
# edit netbox.env: NETBOX_BASE_URL, NETBOX_TOKEN
#   (set NETBOX_ALLOW_WRITE=true to enable writes)
```

- **`NETBOX_BASE_URL`** — e.g. `https://netbox.example.com` (no `/api` suffix).
- **TLS** — for a self-signed / internal-CA instance set `NETBOX_CA_BUNDLE`, or (lab only)
  `NETBOX_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t netbox-mcp .
claude mcp add netbox -- docker run -i --rm --env-file ./netbox.env netbox-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
claude mcp add netbox -- poetry run netbox-mcp   # export netbox.env vars into your shell first
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
- Put the **gateway and the servers on one shared network**, so `http://netbox-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  netbox-mcp:
    build: .
    image: netbox-mcp
    env_file: ./netbox.env
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

With the gateway also on `atlas-net`, register this server at `http://netbox-mcp:8000/mcp`
(`mcpjungle register --name netbox --url http://netbox-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
token, or one container per NetBox.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-netbox: &netbox
  image: ghcr.io/0x3e4/netbox-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  netbox-mcp:                    # existing shared read-only instance
    <<: *netbox
    container_name: netbox-mcp
    env_file: ./netbox.env

  netbox-mcp-instance-a:         # write access with instance a's token
    <<: *netbox
    container_name: netbox-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's token and `NETBOX_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `NETBOX_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name netbox --url http://netbox-mcp:8000/mcp
  mcpjungle register --name netbox-instance-a --url http://netbox-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add netbox-instance-a -- docker run -i --rm --env-file ./env/instance_a.env netbox-mcp`

## 4. Verify

`/mcp` to confirm, then ask:

- "Find device core-sw-01 and its primary IP."
- "List active devices at site 3."
- "Which IP addresses have a DNS name containing 'vpn'?"
- "Show prefixes in VRF 2."

With `NETBOX_ALLOW_WRITE=true` you can also:

- "Give vm-42's eth0 the next free IP in prefix 10.0.0.0/24 with DNS name vm-42.test.corp."
- "Mark 10.0.0.10/24 as deprecated."
- "Set device 7 to offline and add a warning journal entry: PSU failed, RMA opened."
- "Make 10.0.0.10 the primary IPv4 of device 7."

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `NETBOX_ALLOW_WRITE=true`, the token is write-enabled and its user has the object permissions.
  Leave the flag unset for read-only. There are no delete tools; every change is recorded in NetBox's
  changelog (Other → Change Log), and `netbox_get` stays read-only.
- **Trailing slashes** are required by NetBox and added automatically by this server.
- **Large tables** (devices, interfaces, ip-addresses) — use filters (`q`, `*_id`, `status`) and
  `limit`/`offset`. `netbox_get` reaches `available-ips`, `cables`, `circuits`, and anything else.
