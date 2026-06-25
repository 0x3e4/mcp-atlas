# defender-mcp

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to **Microsoft Defender XDR** through the **Microsoft Graph security API**.
Ask about your Defender data in natural language — advanced hunting (KQL telemetry), incidents,
alerts, devices, and vulnerabilities.

- One OAuth2 client-credentials token, one `httpx.AsyncClient`.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — no response/remediation actions (isolate device, run AV scan, etc.).
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

## 1. Register an Entra ID application

1. **Entra admin center** → **App registrations** → **New registration**. Name it (e.g.
   `defender-mcp`), single-tenant, no redirect URI needed. Note the **Application (client) ID** and
   **Directory (tenant) ID**.
2. **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions** →
   add all three (read-only):
   - `ThreatHunting.Read.All` — advanced hunting, devices, vulnerabilities
   - `SecurityAlert.Read.All` — alerts
   - `SecurityIncident.Read.All` — incidents
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

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

## 4. Verify end-to-end

After registering, ask Claude Code things like:

- "show high-severity incidents from the last 24h"
- "hunt for powershell spawning from office apps in the last 7 days"
- "list critical vulnerabilities on device host01"

A trivial first check is `advanced_hunting` with `DeviceInfo | take 1` — if it returns a row, auth and
permissions are working.

## Notes & limits

- **Advanced hunting**: ~30-day data window, up to 100,000 rows, ~3-minute query timeout. Bound your
  results with `| take N`. A `429` means the tenant hit its hunting CPU/rate budget — back off.
- **`list_devices` / `get_vulnerabilities`** are derived from hunting telemetry, so they only see
  devices/vulns observed in the ~30-day window and have no real-time "last seen" beyond the latest
  event timestamp.
- **`list_alerts` `category`** is filtered client-side (it isn't a documented `$filter` field); other
  filters are server-side OData. `alerts_v2` does not support `$orderby` (results are most-recent-first).

## Future (not in v1)

- Response/remediation actions (isolate device, run AV scan) — would be flag-gated and explicitly opt-in.
- A dedicated Defender for Endpoint REST client for real-time machine state (needs a second token
  audience and heavier permissions).
- Certificate / federated-credential auth as an alternative to the client secret.

## Development

```bash
poetry install
poetry run pytest -q       # static smoke tests (no network, no credentials)
```
