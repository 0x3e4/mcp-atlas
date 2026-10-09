# wazuh-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that lets a local agent
(Claude Code) query your Wazuh deployment in natural language — **alerts, the full event
archive, vulnerabilities, agents, inventory, rules, SCA, and manager status** — and, opt-in,
**restart agents, change agent groups, and run active-response commands**.

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

## Tools

The tools below are read-only and always available.

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

### Write tools (opt-in)

These change your Wazuh deployment and only work when **`WAZUH_ALLOW_WRITE=true`** (otherwise they
refuse with a clear message). They go to the **Manager API only** (never the Indexer), and the API
user's RBAC role must allow the action (see [Credentials & RBAC](#credentials--rbac)). Agent ids are
numeric (`1` → `001`); an empty agent list is refused, because the API would treat it as *all agents*.

| Tool | API call | What it does |
|---|---|---|
| `restart_agents(agent_ids)` | `PUT /agents/restart?agents_list=…` | Restart the Wazuh agent service (not the host) on the given agents, e.g. after a group config change. Inactive agents come back under `failed`. |
| `add_agent_to_group(agent_id, group_id, exclusive?)` | `PUT /agents/{agent_id}/group/{group_id}` | Assign an agent to an existing group; `exclusive=true` (`force_single_group`) removes it from its other groups first. |
| `remove_agent_from_group(agent_id, group_id)` | `DELETE /agents/{agent_id}/group/{group_id}` | Unassign an agent from one group. Deletes nothing; an agent left without groups goes back to `default`. |
| `run_active_response(agent_ids, command, arguments?, alert_data?)` | `PUT /active-response?agents_list=…` | **Executes an active-response script on the endpoints** — it can block an IP in the host firewall, kill processes, disable an account or restart Wazuh, depending on the command. |

`run_active_response` takes a command name as listed in the manager's `ar.conf` (a configured
`<command>` with its timeout appended, e.g. `firewall-drop0`) or `!<script>` to call an AR script
by name (e.g. `!firewall-drop`). Since Wazuh 4.2 the scripts read their input from the alert, so pass
e.g. `alert_data={"srcip": "10.0.0.10"}` for `firewall-drop` / `host-deny`; `arguments` become the
script's `extra_args`. The agent must be active and have active response enabled. Stateful commands
are undone only by their timeout or by hand.

**Confirmation before every write** (`WAZUH_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments, so a changed request needs a fresh confirmation (codes also
expire when the server restarts). Set `WAZUH_CONFIRM_WRITE=false` to let writes run directly.

## Configuration

Copy `.env.example` to `wazuh.env` and fill in your URLs and credentials. Key variables:
`WAZUH_MANAGER_URL`, `WAZUH_USER`, `WAZUH_PASS`, `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`,
`WAZUH_INDEXER_PASS`, `WAZUH_VERIFY_SSL`, `WAZUH_CA_BUNDLE`, and for the opt-in write tools
`WAZUH_ALLOW_WRITE` / `WAZUH_CONFIRM_WRITE`. See `.env.example` for the rest.

For self-signed certs, either mount the Wazuh root CA and set `WAZUH_CA_BUNDLE`, or (lab only)
set `WAZUH_VERIFY_SSL=false`.

### Credentials & RBAC

- **Indexer user** (`WAZUH_INDEXER_USER`) — only needs read access to the `wazuh-*` indices.
- **Manager API user** (`WAZUH_USER`) — for the read tools, the built-in **`readonly`** role is enough.
  Better than reusing `wazuh-wui` (administrator): create a dedicated API user (`POST /security/users`,
  or the dashboard's Security section) and give it only what it needs.
- **For the write tools** the Manager API user additionally needs these RBAC actions:

  | Tool | RBAC action(s) | Resource |
  |---|---|---|
  | `restart_agents` | `agent:restart` | `agent:id:*` (or `agent:group:<name>`) |
  | `add_agent_to_group`, `remove_agent_from_group` | `agent:modify_group` **and** `group:modify_assignments` | `agent:id:*` / `group:id:*` |
  | `run_active_response` | `active-response:command` | `agent:id:*` (built-in policy `agents_commands`) |

  The built-in `agents_admin` role covers the first three but also allows deleting, upgrading and
  uninstalling agents — prefer custom policies attached to a custom role, e.g.:

  ```json
  {"name": "mcp_agents_write", "policy": {"actions": ["agent:restart", "agent:modify_group"], "resources": ["agent:id:*"], "effect": "allow"}}
  {"name": "mcp_groups_assign", "policy": {"actions": ["group:modify_assignments"], "resources": ["group:id:*"], "effect": "allow"}}
  ```

  Create them with `POST /security/policies`, a role with `POST /security/roles`, then link them with
  `POST /security/roles/{role_id}/policies?policy_ids=…` and
  `POST /security/users/{user_id}/roles?role_ids=…` (keep `readonly` on the user too). Add the
  built-in `agents_commands` policy only if you want `run_active_response`. Narrow `agent:id:*` /
  `group:id:*` to specific agents or groups to limit what the agent can touch. See the
  [Wazuh RBAC docs](https://documentation.wazuh.com/current/user-manual/api/rbac/index.html).

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

With `WAZUH_ALLOW_WRITE=true` you can also:

- "Restart the agents in group webservers that are active."
- "Move agent vm-42 into the dmz group only."
- "Remove agent 004 from the legacy group."
- "Block 10.0.0.10 on agent 001 with firewall-drop."

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

### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
API user, or one container per Wazuh deployment.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-wazuh: &wazuh
  image: ghcr.io/0x3e4/wazuh-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  wazuh-mcp:                    # existing shared read-only instance
    <<: *wazuh
    container_name: wazuh-mcp
    env_file: ./wazuh.env

  wazuh-mcp-instance-a:         # write access with instance a's API user
    <<: *wazuh
    container_name: wazuh-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's API user and `WAZUH_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `WAZUH_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name wazuh --url http://wazuh-mcp:8000/mcp
  mcpjungle register --name wazuh-instance-a --url http://wazuh-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add wazuh-instance-a -- docker run -i --rm --env-file /abs/path/to/env/instance_a.env wazuh-mcp`

## Inspect / test the tools

```bash
poetry run mcp dev src/wazuh_mcp/server.py    # opens the MCP Inspector
```

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `WAZUH_ALLOW_WRITE=true` and the Manager API user's RBAC role allows the action. Leave the flag unset
  for read-only. They go to the Manager API only, ask for confirmation first (`WAZUH_CONFIRM_WRITE`),
  and there are no delete tools (no agent/group deletion, no config or ruleset edits).
  `run_active_response` is the one with real-world side effects (blocked IPs, killed processes).
- Searches default to the **last 24h** and trim results to the most useful fields; pass
  `full=true` for raw documents, and explicit `start`/`end` (ISO8601 or `now-1h`) to widen the window.
- A single `_search` returns at most 10,000 hits (`max_result_window`).
- Archives grow fast — make sure an ISM retention/rollover policy caps `wazuh-archives-*`.
