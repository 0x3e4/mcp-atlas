# prtg-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **PRTG Network Monitor** (Paessler) server through its HTTP API. Ask about your
monitoring in natural language — sensors and their state, devices/groups/probes, channels, the log,
server/system health, and historic data — and, opt-in, **pause/resume objects, acknowledge alarms
and trigger a scan**.

- One shared `httpx.AsyncClient`; **API-token** auth (`Authorization: Bearer` + `apitoken`), with a
  legacy **username + passhash** fallback.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `PRTG_ALLOW_WRITE` (see below).
- A raw read-only escape-hatch tool (`prtg_get`) so any `/api/...` endpoint stays reachable (incl.
  XML ones); it refuses state-changing endpoints.

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

### Write tools (opt-in)

These change PRTG and only work when **`PRTG_ALLOW_WRITE=true`** (otherwise they refuse with a clear
message). The API key / user also needs **write access** on the objects (see section 1). They use
PRTG's classic GET-style action calls; a failure (PRTG's `/error.htm` or login-page redirect, an
error block in the body) is reported as an error, never as success.

| Tool | What it does |
|---|---|
| `pause_object(object_id, message?, duration_minutes?)` | Pause a sensor/device/group/probe indefinitely (`pause.htm?action=0`) or for N minutes, then auto-resume (`pauseobjectfor.htm`). Not the root group (id 0). |
| `resume_object(object_id)` | Resume a manually paused object (`pause.htm?action=1`). |
| `acknowledge_alarm(sensor_id, message?, duration_minutes?)` | Acknowledge a Down sensor (`acknowledgealarm.htm`) → Down (Acknowledged), indefinitely or for N minutes. |
| `scan_now(object_id)` | Scan a sensor now, or every sensor below a device/group/probe (`scannow.htm`). |

PRTG applies these asynchronously; check the result with `get_sensor` / `list_sensors` afterwards.

**Confirmation before every write** (`PRTG_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments, so a changed request needs a fresh confirmation (codes also
expire when the server restarts). Set `PRTG_CONFIRM_WRITE=false` to let writes run directly.

## 1. Get credentials

**Preferred — API key:** in PRTG, **Setup → Account Settings → API Keys** (PRTG 23.x+), create a key
with **read** access. That's `PRTG_API_TOKEN`.

**Legacy — passhash:** use a read-only PRTG user and its passhash (from **Account Settings → Show
Passhash**, or `GET /api/getpasshash.htm?username=<u>&password=<p>`). Set `PRTG_USERNAME` +
`PRTG_PASSHASH`.

**For the write tools** the credential needs write rights: an API key with **Write access** (a key
with **Acknowledge access** is enough for `acknowledge_alarm` only), created by a **read/write user**
whose user group has **write access** on the objects to pause/resume/scan/acknowledge (PRTG object
access rights). With the legacy passhash, use such a read/write user. Read-only PRTG users can at most
acknowledge alarms, and only if their account allows it.

## 2. Configure

```bash
cp .env.example prtg.env
# edit prtg.env: PRTG_BASE_URL and PRTG_API_TOKEN  (or PRTG_USERNAME + PRTG_PASSHASH)
#   (set PRTG_ALLOW_WRITE=true to enable writes)
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

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
API key, or one container per PRTG server.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-prtg: &prtg
  image: ghcr.io/0x3e4/prtg-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  prtg-mcp:                    # existing shared read-only instance
    <<: *prtg
    container_name: prtg-mcp
    env_file: ./prtg.env

  prtg-mcp-instance-a:         # write access with instance a's API key
    <<: *prtg
    container_name: prtg-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's API key and `PRTG_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `PRTG_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name prtg --url http://prtg-mcp:8000/mcp
  mcpjungle register --name prtg-instance-a --url http://prtg-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add prtg-instance-a -- docker run -i --rm --env-file ./env/instance_a.env prtg-mcp`

## 4. Verify

In Claude Code, run `/mcp` to confirm the `prtg` server connected, then ask things like:

- "How many sensors are down right now?"
- "List the down sensors on device 2040."
- "Show the channels and current values for sensor 2143."
- "What's the PRTG core status and version?"
- "Show the last 20 log messages with Warning or Down status."

With `PRTG_ALLOW_WRITE=true` you can also:

- "Pause device 2040 for 60 minutes with the message 'patching vm-42'."
- "Resume device 2040."
- "Acknowledge the alarm on sensor 2143: 'on it, disk cleanup running'."
- "Scan sensor 2143 now and tell me whether it's back up."

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `PRTG_ALLOW_WRITE=true` and the key/user has write access on the objects. Leave the flag unset for
  read-only. All writes are reversible (pause ↔ resume; an acknowledgement ends when the sensor
  changes state). There are no delete/edit-settings tools, and `prtg_get` refuses state-changing
  endpoints (`pause*`, `set*`, `delete*`, `add*`, `duplicate*`, …).
- **`status_raw` codes:** 1/2 = Unknown/Collecting, 3 = Up, 4 = Warning, 5 = Down, 7-12 = Paused
  (user/dependency/schedule/license), 10 = Unusual, 13 = DownAcknowledged, 14 = DownPartial.
- **Large payloads:** `historic_data` (use a non-zero `avg` and a bounded date range — PRTG caps raw
  data to ~40 days and rate-limits historic queries) and the full `getsensortree.xml` (reach it via
  `prtg_get("getsensortree.xml", as_text=true)`).
- **`prtg_get`** reaches XML/CSV/HTML endpoints too — pass `as_text=true` for those.
