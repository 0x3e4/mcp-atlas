# prtg-mcp

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to a **PRTG Network Monitor** (Paessler) server through its HTTP API. Ask
about your monitoring in natural language — sensors and their state, devices/groups/probes, channels,
the log, server/system health, and historic data.

- One shared `httpx.AsyncClient`; **API-token** auth (`Authorization: Bearer` + `apitoken`), with a
  legacy **username + passhash** fallback.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — GET requests only; pair with a PRTG read-only API key/account.
- A raw escape-hatch tool (`prtg_get`) so any `/api/...` endpoint stays reachable (incl. XML ones).

## Tools

| Tool | What it does |
|---|---|
| `list_sensors(status?, device_id?, tag?, name_contains?, limit?, full?)` | Sensors + state (`status_raw`: 3=Up, 4=Warn, 5=Down, 7-12=Paused…). |
| `list_devices(status?, group_id?, name_contains?, limit?, full?)` | Devices + state. |
| `list_groups(status?, parent_id?, limit?, full?)` | Groups + state. |
| `list_probes(limit?, full?)` | Probes (local + remote) + state. |
| `list_channels(sensor_id, limit?, full?)` | A sensor's channels and current values. |
| `get_sensor(sensor_id)` | One sensor's detail snapshot (type, last value, status, message). |
| `server_status()` | Core status + sensor counts (version, Up/Down/Warning/Paused, alarms). |
| `system_health()` | System health metrics (CPU / memory / disk / probe health). |
| `list_messages(sensor_id?, status?, limit?, full?)` | Log / event messages, newest first. |
| `historic_data(sensor_id, start, end, avg?, limit?)` | Historic channel data (dates `yyyy-mm-dd-hh-mm-ss`). |
| `prtg_get(endpoint, params?, as_text?)` | Escape hatch: raw read-only GET against any `/api/...` endpoint. |

Results are trimmed to useful columns by default; pass `full=true` for PRTG's default columns, and
lists are capped (`PRTG_MAX_ROWS`, default 200; hard cap 5000). `status` accepts `up`/`down`/
`warning`/`paused`/`unusual`/`unknown` (mapped to the right `status_raw` codes).

## 1. Get credentials

**Preferred — API key:** in PRTG, **Setup → Account Settings → API Keys** (PRTG 23.x+), create a key
with **read** access. That's `PRTG_API_TOKEN`.

**Legacy — passhash:** use a read-only PRTG user and its passhash (from **Account Settings → Show
Passhash**, or `GET /api/getpasshash.htm?username=<u>&password=<p>`). Set `PRTG_USERNAME` +
`PRTG_PASSHASH`.

## 2. Configure

```bash
cp .env.example prtg.env
# edit prtg.env: PRTG_BASE_URL and PRTG_API_TOKEN  (or PRTG_USERNAME + PRTG_PASSHASH)
```

- **`PRTG_BASE_URL`** — e.g. `https://prtg.example.com` (no `/api` suffix).
- **TLS** — PRTG ships a self-signed cert by default; set `PRTG_CA_BUNDLE` to its CA PEM, or (lab
  only) `PRTG_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t prtg-mcp .
claude mcp add prtg -- docker run -i --rm --env-file ./prtg.env prtg-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from prtg.env into your shell first, then:
claude mcp add prtg -- poetry run prtg-mcp
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
- Put the **gateway and the servers on one shared network**, so `http://prtg-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  prtg-mcp:
    build: .
    image: prtg-mcp
    env_file: ./prtg.env
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

With the gateway also on `atlas-net`, register this server at `http://prtg-mcp:8000/mcp`
(`mcpjungle register --name prtg --url http://prtg-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

## 4. Verify

In Claude Code, run `/mcp` to confirm the `prtg` server connected, then ask things like:

- "How many sensors are down right now?"
- "List the down sensors on device 2040."
- "Show the channels and current values for sensor 2143."
- "What's the PRTG core status and version?"
- "Show the last 20 log messages with Warning or Down status."

## Notes & scope

- **Read-only.** No write/acknowledge tools. If you add them (e.g. acknowledge alarm, pause), gate
  behind an explicit env flag and use a key with the right access level.
- **`status_raw` codes:** 1/2 = Unknown/Collecting, 3 = Up, 4 = Warning, 5 = Down, 7-12 = Paused
  (user/dependency/schedule/license), 10 = Unusual, 13 = DownAcknowledged, 14 = DownPartial.
- **Large payloads:** `historic_data` (use a non-zero `avg` and a bounded date range — PRTG caps raw
  data to ~40 days and rate-limits historic queries) and the full `getsensortree.xml` (reach it via
  `prtg_get("getsensortree.xml", as_text=true)`).
- **`prtg_get`** reaches XML/CSV/HTML endpoints too — pass `as_text=true` for those.
