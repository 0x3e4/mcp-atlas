# template-mcp

> **This is the scaffold.** Copy this folder and find/replace `template_mcp` → `<name>_mcp`,
> `template-mcp` → `<name>-mcp` and `TEMPLATE_` → `<NAME>_` across it (the repo-root README →
> "Adding a server" has the full checklist). Then delete this note and fill in the bracketed
> `<…>` placeholders below.

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to **\<UPSTREAM SYSTEM\>**. Ask about your data in natural language.

- One shared `httpx.AsyncClient`; auth applied per request.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — no write/remediation actions.
- A raw escape-hatch tool (`api_get`) so anything reachable via the API stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `search_items(query?, limit=50, full?)` | List/search items (the headline list tool). |
| `get_item(item_id)` | Fetch a single item by id. |
| `api_get(path, params?)` | Escape hatch: raw read-only GET against any endpoint on the configured host. |

Results are trimmed to the useful fields by default; pass `full=true` for the raw payload, and row
counts are capped (`TEMPLATE_MAX_ROWS`, default 200) unless `full`.

## 1. Get credentials

> TODO: describe how to obtain an API key / token for \<UPSTREAM SYSTEM\> and which (read-only)
> scopes or permissions it needs. This is `TEMPLATE_API_KEY`.

## 2. Configure

```bash
cp .env.example template.env
# edit template.env: TEMPLATE_BASE_URL, TEMPLATE_API_KEY
```

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t template-mcp .
claude mcp add template -- docker run -i --rm --env-file ./template.env template-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from template.env into your shell first, then:
claude mcp add template -- poetry run template-mcp
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
- Put the **gateway and the servers on one shared network**, so `http://template-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  template-mcp:
    build: .
    image: template-mcp
    env_file: ./template.env
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

With the gateway also on `atlas-net`, register this server at `http://template-mcp:8000/mcp`
(`mcpjungle register --name template --url http://template-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

## 4. Verify

In Claude Code, run `/mcp` to confirm the `template` server connected, then ask things like:

- "search items matching \<…\>"
- "show item \<id\>"

## Development

```bash
poetry install
poetry run pytest -q                          # static smoke tests (no network, no credentials)
poetry run mcp dev src/template_mcp/server.py # MCP Inspector to exercise tools
```

## Notes & scope

- **Read-only.** No write tools in this version. If you add them, gate behind an explicit env flag
  (e.g. `TEMPLATE_ALLOW_WRITE`) and a separate tool group.
- Searches trim to the most useful fields; pass `full=true` for raw documents.
