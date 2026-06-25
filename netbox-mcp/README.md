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

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

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
