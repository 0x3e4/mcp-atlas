# snipeit-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **[Snipe-IT](https://snipeitapp.com)** IT-asset-management instance through its REST
API. Ask about your inventory in natural language — assets, who has what, models/categories/locations,
licenses/accessories/consumables — and, opt-in, **check assets out/in, update, create and audit them**.

- One shared `httpx.AsyncClient`; **Bearer-token** auth (`Authorization: Bearer` + `Accept: json`).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `SNIPEIT_ALLOW_WRITE` (see below).
- A raw escape-hatch tool (`snipeit_get`) so any `/api/v1/...` resource stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_assets(search?, status_id?, model_id?, category_id?, location_id?, limit?, offset?, full?)` | List/search hardware assets. |
| `get_asset(asset_id? \| asset_tag? \| serial?, full?)` | One asset by id, tag, or serial. |
| `list_users(search?, limit?, offset?, full?)` | List/search users. |
| `get_user_assets(user_id, limit?, full?)` | Assets currently checked out to a user. |
| `list_objects(kind, search?, limit?, offset?, full?)` | A catalog: `models`, `categories`, `manufacturers`, `statuslabels`, `locations`, `companies`, `departments`, `suppliers`, `licenses`, `accessories`, `consumables`, `components`, `maintenances`. |
| `snipeit_get(path, params?)` | Escape hatch: raw read-only GET against any `/api/v1/...` path. |

Results are trimmed to useful fields by default (nested names like `model.name`, `assigned_to.name`);
pass `full=true` for raw objects, and lists are capped (`SNIPEIT_MAX_ROWS`, default 50; hard cap 500).

### Write tools (opt-in)

These mutate Snipe-IT and only work when **`SNIPEIT_ALLOW_WRITE=true`** (otherwise they refuse with a
clear message). The token's **user** must also hold the matching Snipe-IT permissions.

| Tool | What it does |
|---|---|
| `checkout_asset(asset_id, to_type, to_id, status_id?, expected_checkin?, note?)` | Check an asset out to a `user`/`location`/`asset`. |
| `checkin_asset(asset_id, status_id?, location_id?, note?)` | Check an asset back in. |
| `update_asset(asset_id, name?, status_id?, model_id?, asset_tag?, serial?, notes?, location_id?, company_id?)` | Update asset fields. |
| `create_asset(asset_tag, model_id, status_id, name?, serial?, notes?, company_id?)` | Create an asset (required: tag, model, status). |
| `audit_asset(asset_tag, location_id?, note?, next_audit_date?)` | Record an audit of an asset. |

Use `list_objects` to resolve the ids these tools need (e.g. `statuslabels` → `status_id`,
`models` → `model_id`, `locations` → `location_id`).

## 1. Create an API token

In Snipe-IT: **account menu → Manage API Keys → Create New Token** (the token is shown once). The
token inherits its **user's** permissions — there is no read-only token, so use a least-privileged
user for read-only, and a user with Checkout/Edit/Create/Audit rights if you enable writes. That's
`SNIPEIT_TOKEN`.

## 2. Configure

```bash
cp .env.example snipeit.env
# edit snipeit.env: SNIPEIT_BASE_URL, SNIPEIT_TOKEN  (set SNIPEIT_ALLOW_WRITE=true to enable writes)
```

- **`SNIPEIT_BASE_URL`** — e.g. `https://snipe.example.com` (no `/api` suffix).
- **TLS** — for a self-signed / internal-CA instance set `SNIPEIT_CA_BUNDLE`, or (lab only)
  `SNIPEIT_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t snipeit-mcp .
claude mcp add snipeit -- docker run -i --rm --env-file ./snipeit.env snipeit-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from snipeit.env into your shell first, then:
claude mcp add snipeit -- poetry run snipeit-mcp
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
- Put the **gateway and the servers on one shared network**, so `http://snipeit-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  snipeit-mcp:
    build: .
    image: snipeit-mcp
    env_file: ./snipeit.env
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

With the gateway also on `atlas-net`, register this server at `http://snipeit-mcp:8000/mcp`
(`mcpjungle register --name snipeit --url http://snipeit-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

## 4. Verify

In Claude Code, run `/mcp` to confirm the `snipeit` server connected, then ask things like:

- "Find the asset with tag LAP-0421 and who it's assigned to."
- "List laptops with status 'Ready to Deploy'."
- "What assets are checked out to user 57?"

With `SNIPEIT_ALLOW_WRITE=true` you can also:

- "Check out asset 1234 to user 57 with a note 'onboarding'."
- "Check in asset 1234 and set status to 5 (Ready to Deploy)."
- "Create an asset: tag LAP-0999, model 12, status 2."

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `SNIPEIT_ALLOW_WRITE=true` and the token's user has rights. No delete tools are provided.
- **Snipe-IT returns HTTP 200 even on errors**, signalling failure via `status:"error"` in the body —
  this server detects that and raises a clear error (with the field-level `messages`) for both reads
  and writes. Write tools return the `{status, messages, asset}` summary on success.
- **Resolve ids first.** Many writes need numeric ids (status/model/location); `list_objects` maps
  names ↔ ids.
- **`snipeit_get`** reaches everything else (license seats, fieldsets, version, …).
