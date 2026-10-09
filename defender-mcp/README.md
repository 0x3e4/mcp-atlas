# defender-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to **Microsoft Defender XDR** through the **Microsoft Graph security API**. Ask about
your Defender data in natural language — advanced hunting (KQL telemetry), incidents, alerts,
devices, and vulnerabilities — and, opt-in, **triage incidents and alerts** (status, owner,
classification, determination, tags, comments).

- One OAuth2 client-credentials token, one `httpx.AsyncClient`.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `DEFENDER_ALLOW_WRITE` (see below).
  No device response/remediation actions (isolate device, run AV scan, etc.).
- Raw escape-hatch tools (`graph_get`, `graph_hunt`) so anything reachable via Graph stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `advanced_hunting(query, timespan?, full?)` | Run an arbitrary **KQL** hunting query (the headline tool). |
| `list_incidents(status?, severity?, assigned_to?, top=20, full?)` | List Defender incidents. |
| `get_incident(incident_id)` | One incident with its alerts (`$expand=alerts`). |
| `list_alerts(severity?, status?, category?, top=50, full?)` | List alerts (`alerts_v2`). |
| `get_alert(alert_id)` | One alert with full evidence. |
| `list_devices(filter?, top=50, full?)` | Onboarded devices (via a `DeviceInfo` hunt). |
| `get_vulnerabilities(device?, severity?, cve?, top=50, full?)` | Software vulns (via a `DeviceTvmSoftwareVulnerabilities` hunt). |
| `graph_get(path, params?)` | Escape hatch: raw read-only GET against any Graph endpoint. |
| `graph_hunt(kql, timespan?)` | Escape hatch: raw hunting query, untrimmed `{schema, results}`. |

Results are trimmed to the useful columns by default; pass `full=true` for the raw payload, and row
counts are capped (`DEFENDER_MAX_ROWS`, default 200) unless `full`.

### Write tools (opt-in)

These change Defender incidents/alerts and only work when **`DEFENDER_ALLOW_WRITE=true`** (otherwise
they refuse with a clear message). The app registration also needs the **ReadWrite** Graph
permissions (see [section 1](#1-register-an-entra-id-application)). Only the fields you give change.

| Tool | What it does |
|---|---|
| `update_incident(incident_id, status?, assigned_to?, classification?, determination?, custom_tags?, resolving_comment?)` | `PATCH /security/incidents/{id}` — triage an incident. |
| `add_incident_comment(incident_id, comment)` | `POST /security/incidents/{id}/comments` — add a comment. |
| `update_alert(alert_id, status?, assigned_to?, classification?, determination?)` | `PATCH /security/alerts_v2/{id}` — triage an alert. |
| `add_alert_comment(alert_id, comment)` | `POST /security/alerts_v2/{id}/comments` — add a comment. |

- **status** — incidents: `active`, `inProgress`, `resolved`; alerts: `new`, `inProgress`, `resolved`
  (`redirected` is set by Defender when incidents are merged, so it isn't offered).
- **classification** — `unknown`, `falsePositive`, `truePositive`, `informationalExpectedActivity`.
- **determination** — `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`,
  `unwantedSoftware`, `other`, `multiStagedAttack`, `compromisedAccount`, `phishing`,
  `maliciousUserActivity`, `notMalicious`, `notEnoughDataToValidate`, `confirmedActivity`,
  `lineOfBusinessApplication`.
- **assigned_to** is free text (usually a UPN); `''` unassigns. **custom_tags replaces all custom
  tags** of the incident (`[]` clears them); omit it to leave them alone.
- Comments can't be edited or deleted through Graph — they show up in the portal as written by the app.

**Confirmation before every write** (`DEFENDER_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments, so a changed request needs a fresh confirmation (codes also
expire when the server restarts). Set `DEFENDER_CONFIRM_WRITE=false` to let writes run directly.

## 1. Register an Entra ID application

1. **Entra admin center** → **App registrations** → **New registration**. Name it (e.g.
   `defender-mcp`), single-tenant, no redirect URI needed. Note the **Application (client) ID** and
   **Directory (tenant) ID**.
2. **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions** →
   add all three (read-only):
   - `ThreatHunting.Read.All` — advanced hunting, devices, vulnerabilities
   - `SecurityAlert.Read.All` — alerts
   - `SecurityIncident.Read.All` — incidents

   For the **write** tools (`DEFENDER_ALLOW_WRITE=true`) add as well:
   - `SecurityIncident.ReadWrite.All` — `update_incident`, `add_incident_comment`
   - `SecurityAlert.ReadWrite.All` — `update_alert`, `add_alert_comment`

   Leave them out for a read-only deployment: the token then can't change anything even if the flag
   is set. A second app registration (and env file) with the ReadWrite permissions keeps the
   read-only instance separate.
3. Click **Grant admin consent for &lt;tenant&gt;** (a tenant admin must do this). Without consent,
   Graph returns `403 Authorization_RequestDenied`.
4. **Certificates & secrets** → **New client secret** → copy the **Value** immediately (you can't
   read it again). This is `DEFENDER_CLIENT_SECRET`.

> The client-credentials flow uses the scope `https://graph.microsoft.com/.default`, which grants the
> token **all** admin-consented application permissions for Graph. There is no refresh token — the
> server re-fetches on expiry (~60 min).

## 2. Configure

```bash
cp .env.example defender.env
# edit defender.env: DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, DEFENDER_CLIENT_SECRET
#   (set DEFENDER_ALLOW_WRITE=true to enable writes)
```

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
docker build -t defender-mcp .
claude mcp add defender -- docker run -i --rm --env-file ./defender.env defender-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from defender.env into your shell first, then:
claude mcp add defender -- poetry run defender-mcp
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
- Put the **gateway and the servers on one shared network**, so `http://defender-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  defender-mcp:
    build: .
    image: defender-mcp
    env_file: ./defender.env
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

With the gateway also on `atlas-net`, register this server at `http://defender-mcp:8000/mcp`
(`mcpjungle register --name defender --url http://defender-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
app registration, or one container per tenant.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-defender: &defender
  image: ghcr.io/0x3e4/defender-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  defender-mcp:                    # existing shared read-only instance
    <<: *defender
    container_name: defender-mcp
    env_file: ./defender.env

  defender-mcp-instance-a:         # write access with instance a's app registration
    <<: *defender
    container_name: defender-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's app registration and `DEFENDER_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `DEFENDER_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name defender --url http://defender-mcp:8000/mcp
  mcpjungle register --name defender-instance-a --url http://defender-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add defender-instance-a -- docker run -i --rm --env-file ./env/instance_a.env defender-mcp`

## 4. Verify end-to-end

After registering, ask Claude Code things like:

- "show high-severity incidents from the last 24h"
- "hunt for powershell spawning from office apps in the last 7 days"
- "list critical vulnerabilities on device host01"

A trivial first check is `advanced_hunting` with `DeviceInfo | take 1` — if it returns a row, auth and
permissions are working.

With `DEFENDER_ALLOW_WRITE=true` you can also:

- "Assign incident 29 to soc@app.test.corp and set it to in progress."
- "Resolve incident 29 as a true positive, determination malware, and tag it ir-2026-10."
- "Mark alert da123 as a false positive (not malicious) and comment that it was the admin backup script."
- "Add a comment to incident 29: contained, vm-42 reimaged."

## Notes & limits

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `DEFENDER_ALLOW_WRITE=true` and the app has the admin-consented ReadWrite permissions. Leave the flag
  unset for read-only. Triage changes are reversible (set the field back); comments are permanent.
  There are no delete tools and no raw write escape hatch.
- **Device response actions are out of scope** — isolate device, run AV scan, collect investigation
  package, etc. live in the separate Defender for Endpoint API (its own token audience and `Machine.*`
  permissions), not in Microsoft Graph.

- **Advanced hunting**: ~30-day data window, up to 100,000 rows, ~3-minute query timeout. Bound your
  results with `| take N`. A `429` means the tenant hit its hunting CPU/rate budget — back off.
- **`list_devices` / `get_vulnerabilities`** are derived from hunting telemetry, so they only see
  devices/vulns observed in the ~30-day window and have no real-time "last seen" beyond the latest
  event timestamp.
- **`list_alerts` `category`** is filtered client-side (it isn't a documented `$filter` field); other
  filters are server-side OData. `alerts_v2` does not support `$orderby` (results are most-recent-first).

## Future

- Device response/remediation actions (isolate device, run AV scan) via the Defender for Endpoint API —
  would be flag-gated and explicitly opt-in.
- A dedicated Defender for Endpoint REST client for real-time machine state (needs a second token
  audience and heavier permissions).
- Certificate / federated-credential auth as an alternative to the client secret.

## Development

```bash
poetry install
poetry run pytest -q       # static smoke tests (no network, no credentials)
```
