# wazuh-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that lets a local agent
(Claude Code) query your Wazuh deployment in natural language — **alerts, the full event
archive, vulnerabilities, agents, inventory, rules, SCA, and manager status**.

Unlike most Wazuh MCP servers, this one queries **`wazuh-archives-*`** (every collected event,
not just rule-triggered alerts), and it runs as a tiny stdio server rather than a heavy web service.

## How it works

Wazuh data lives in two places, and this server talks to both:

| Data | Source | Port |
|------|--------|------|
| Alerts, **archives** (all events), vulnerabilities | Wazuh **Indexer** (OpenSearch) | 9200 |
| Agents, inventory, rules/decoders, SCA, status | Wazuh **Manager** REST API | 55000 |

> The Manager API does **not** serve alert/archive events — those only exist in the Indexer.
> Archives must be enabled (`logall_json` + the Filebeat `archives` module). This is assumed
> to be already set up on your deployment.

## Tools (all read-only)

**Events (Indexer):**
- `search_alerts` — rule-triggered alerts, with agent/level/group/time/text filters
- `search_archives` — **all** events (the firehose), with agent/decoder/location/time/text filters
- `alerts_summary` — top rules / agents / level counts over a window
- `get_vulnerabilities` — CVEs from `wazuh-states-vulnerabilities-*`
- `indexer_search` — raw OpenSearch Query DSL against any `wazuh-*` index (escape hatch)

**Management (Manager API):**
- `list_agents` — agents + status/version/last-keepalive
- `get_agent_inventory` — syscollector (packages, ports, processes, hardware, os, netaddr, …)
- `get_sca` — Security Configuration Assessment results
- `search_rules` — the ruleset
- `manager_status` — daemons + info + cluster health
- `manager_api_get` — raw GET against any Manager API endpoint (escape hatch)

## Configuration

Copy `.env.example` to `wazuh.env` and fill in your URLs and credentials. Key variables:
`WAZUH_MANAGER_URL`, `WAZUH_USER`, `WAZUH_PASS`, `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`,
`WAZUH_INDEXER_PASS`, `WAZUH_VERIFY_SSL`, `WAZUH_CA_BUNDLE`. See `.env.example` for the rest.

For self-signed certs, either mount the Wazuh root CA and set `WAZUH_CA_BUNDLE`, or (lab only)
set `WAZUH_VERIFY_SSL=false`.

## Run with Docker + Claude Code (recommended)

```bash
# 1. Build (run from the project directory)
poetry lock          # first time only, generates poetry.lock
docker build -t wazuh-mcp .

# 2. Register with Claude Code — it launches the container per session over stdio
claude mcp add wazuh -- docker run -i --rm --env-file /abs/path/to/wazuh.env wazuh-mcp
```

Then in Claude Code run `/mcp` to confirm the `wazuh` server connected, and ask things like:

- "Show the last 20 archive events for agent web-01 in the past hour"
- "What are the top 10 alert rules today?"
- "Which agents are disconnected?"
- "List critical vulnerabilities on agent 003"
- "What packages are installed on agent 005?"

## Run locally without Docker (dev)

```bash
poetry install
# Export the WAZUH_* vars (or use a tool that loads wazuh.env), then:
claude mcp add wazuh -- poetry run wazuh-mcp
```

## Always-on HTTP variant (optional)

Run the server as a long-lived `streamable-http` service instead of per-session stdio.
[`compose.yml`](compose.yml) already sets `MCP_TRANSPORT=streamable-http` and binds `0.0.0.0:8000`:

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
claude mcp add --transport http wazuh http://localhost:8000/mcp
```

Point any HTTP MCP client at `http://<host>:8000/mcp` (also the only mode remote clients like
OpenAI support). **On localhost this works as-is — nothing else to change.**

### Behind an MCP gateway (shared Docker network)

A gateway (e.g. [mcpjungle](https://github.com/mcpjungle/MCPJungle)) fronts many servers behind one
endpoint. Running several atlas servers next to a gateway on one host changes two things:

- The published **`8000:8000` host port collides** once more than one server uses it. Drop the host
  port and let the gateway reach the server **by its compose service name** over a shared Docker
  network (or, if you must publish, give each server a distinct host port like `"8001:8000"`).
- Put the **gateway and the servers on one shared network**, so `http://wazuh-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  wazuh-mcp:
    build: .
    image: wazuh-mcp
    env_file: wazuh.env
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

With the gateway also on `atlas-net`, register this server at `http://wazuh-mcp:8000/mcp`
(`mcpjungle register --name wazuh --url http://wazuh-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

## Inspect / test the tools

```bash
poetry run mcp dev src/wazuh_mcp/server.py    # opens the MCP Inspector
```

## Notes & scope

- **Read-only.** No active-response/write tools (block IP, isolate host, …) in this version.
- Searches default to the **last 24h** and trim results to the most useful fields; pass
  `full=true` for raw documents, and explicit `start`/`end` (ISO8601 or `now-1h`) to widen the window.
- A single `_search` returns at most 10,000 hits (`max_result_window`).
- Archives grow fast — make sure an ISM retention/rollover policy caps `wazuh-archives-*`.
