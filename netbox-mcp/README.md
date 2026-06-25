# netbox-mcp

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to **[NetBox](https://netbox.dev)** (the DCIM/IPAM network source of truth)
through its REST API. Ask about your infrastructure in natural language — devices and interfaces,
IP addresses and prefixes, virtual machines, and the supporting catalogs (sites, racks, VLANs, …).

- One shared `httpx.AsyncClient`; **token** auth (auto: `Token` for v1, `Bearer` for v2 `nbt_…`).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — GET requests only; pair with a NetBox **read-only** token.
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

## 1. Create a read-only token

In NetBox: **profile → API Tokens → Add Token**, and **uncheck "Write enabled"** to make it
read-only. (Optionally restrict by client IP / set an expiry.) That's `NETBOX_TOKEN`.

## 2. Configure

```bash
cp .env.example netbox.env
# edit netbox.env: NETBOX_BASE_URL, NETBOX_TOKEN
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

## 4. Verify

`/mcp` to confirm, then ask:

- "Find device core-sw-01 and its primary IP."
- "List active devices at site 3."
- "Which IP addresses have a DNS name containing 'vpn'?"
- "Show prefixes in VRF 2."

## Notes & scope

- **Read-only.** No write tools. If you add them (create/update objects), gate behind an explicit env
  flag and use a write-enabled token.
- **Trailing slashes** are required by NetBox and added automatically by this server.
- **Large tables** (devices, interfaces, ip-addresses) — use filters (`q`, `*_id`, `status`) and
  `limit`/`offset`. `netbox_get` reaches `available-ips`, `cables`, `circuits`, and anything else.
