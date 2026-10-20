# defender-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to **Microsoft Defender XDR** through the **Microsoft Graph security API**. Ask about
your Defender data in natural language — advanced hunting (KQL telemetry), incidents, alerts,
devices, vulnerabilities and **cases** — and, opt-in, **triage incidents and alerts** (status, owner,
classification, determination, tags, comments) and **work cases** (create/update, comments, tasks).

- Acts as the **app registration** (client credentials, default) or as **you** (`DEFENDER_AUTH=delegated`,
  see [Act as yourself](#act-as-yourself-delegated-sign-in)); one `httpx.AsyncClient`.
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
| `whoami()` | Who the tools act as (signed-in user or app) and the permissions in its token. |
| `list_cases(case_type?, status?, assigned_to?, top=25, skip?, full?)` | Case management cases (**Graph beta**). |
| `get_case(case_id, include_audit?)` | One case with its tasks and comments. |
| `get_case_type_config(case_type)` | The tenant's case statuses and custom fields (`generic` / `incident`). |

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
| `create_case(display_name, status, description?, assigned_to?, priority?, due_date_time?, custom_fields?)` | Create a generic case (beta). |
| `update_case(case_id, status?, display_name?, assigned_to?, priority?, description?, closing_notes?, severity?, classification?, determination?, due_date_time?, custom_fields?)` | Update a case (beta); fields depend on the case type. |
| `add_case_comment(case_id, comment)` | Comment on a case (beta). |
| `add_case_task(case_id, display_name, category?, priority?, status?, description?, assigned_to?, due_date_time?)` | Add a task to a case (beta). |
| `update_case_task(case_id, task_id, status?, assigned_to?, priority?, category?, display_name?, description?, closing_notes?, due_date_time?)` | Update a case task (beta). |

- **status** — incidents: `active`, `inProgress`, `resolved`; alerts: `new`, `inProgress`, `resolved`
  (`redirected` is set by Defender when incidents are merged, so it isn't offered).
- **classification** — `unknown`, `falsePositive`, `truePositive`, `informationalExpectedActivity`.
- **determination** — `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`,
  `unwantedSoftware`, `other`, `multiStagedAttack`, `compromisedAccount`, `phishing`,
  `maliciousUserActivity`, `notMalicious`, `notEnoughDataToValidate`, `confirmedActivity`,
  `lineOfBusinessApplication`.
- **assigned_to** is free text (usually a UPN); `''` unassigns; `'me'` means the signed-in user
  (delegated mode only). **custom_tags replaces all custom tags** of the incident (`[]` clears them);
  omit it to leave them alone.
- Comments can't be edited or deleted through Graph — they show up in the portal as written by the app,
  or by you in delegated mode.

**Cases (Graph beta, preview).** Defender's case management (public preview since 2026-09) is only in
Microsoft Graph **beta** (`/beta/security/caseManagement`), so it may change without notice. The case
tools use the beta endpoint on your configured Graph host (global cloud only).

- **Incident cases** are created by Defender, one per incident; you can only update them. Status, owner,
  title, severity, classification and determination are mirrored to the incident: Graph answers
  `202 Accepted` and the case shows the change after a few minutes. **Generic cases** are yours to
  create.
- **Case statuses are tenant-defined** (e.g. *Active* with custom sub-statuses like *Triage*). The
  tools check the status against `get_case_type_config` and send its exact spelling.
- **custom_fields** take plain values keyed by the field's name (`{"Region": "EU", "Users affected": 3}`);
  the server wraps them into Graph's typed values and rejects unknown/disabled fields and invalid options.
- Tasks: category `uncategorized|triage|contain|investigate|remediate|prevent`, priority
  `notSet|veryLow|low|medium|high|critical`, status `new|inProgress|failed|partiallyCompleted|skipped|completed`.
- A case holds at most 100 comments. There are no delete tools.

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

   For the **case** tools add `CaseManagement.Read.All`.

   For the **write** tools (`DEFENDER_ALLOW_WRITE=true`) add as well:
   - `SecurityIncident.ReadWrite.All` — `update_incident`, `add_incident_comment`
   - `SecurityAlert.ReadWrite.All` — `update_alert`, `add_alert_comment`
   - `CaseManagement.ReadWrite.All` — `create_case`, `update_case`, `add_case_comment`, `add_case_task`, `update_case_task`

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

### Act as yourself (delegated sign-in)

With `DEFENDER_AUTH=delegated` the server calls Graph **as a signed-in user** instead of as the app:
comments, status changes and case edits carry that person's name in Defender and in the audit log,
and the server can only do what **both** the consented permissions **and** the user's Defender role
allow (writes: *Security Operator* / *Security Administrator* or a matching Defender XDR RBAC role;
a *Security Reader* can only read).

1. Use a **separate app registration** (e.g. `defender-mcp-delegated`) so the app-only one stays
   untouched. **Authentication** → *Allow public client flows* = **Yes**. No secret, no redirect URI.
2. **API permissions** → Microsoft Graph → **Delegated permissions**: the same names as above
   (`ThreatHunting.Read.All`, `SecurityAlert.Read.All`, `SecurityIncident.Read.All`,
   `CaseManagement.Read.All`, and the `*.ReadWrite.All` ones for writes), plus `offline_access`,
   `openid`, `profile`. **Grant admin consent**.
3. Optional but recommended: in **Enterprise applications** → the app → *Properties*, set
   *Assignment required* = Yes and assign only the analysts who should use it.
4. Env file: `DEFENDER_AUTH=delegated`, tenant + client id, **no** `DEFENDER_CLIENT_SECRET`.
5. Sign in once, inside the container (the code is shown on the console; open the URL on any device):

   ```bash
   docker compose exec defender-mcp-user-a defender-mcp login     # always-on container
   # stdio: docker run -it --rm --env-file ./env/user_a.env -v defender-user-a-token:/home/appuser/.defender-mcp defender-mcp login
   docker compose exec defender-mcp-user-a defender-mcp status    # who am I, which scopes
   docker compose exec defender-mcp-user-a defender-mcp logout    # forget the sign-in
   ```

   The refresh token is stored in `DEFENDER_TOKEN_CACHE` (default `/home/appuser/.defender-mcp/token.json`,
   mode 0600) — mount a **volume** there, or every restart needs a new login. The server picks up a
   new login on its next call; no restart needed. Without a sign-in, tools answer
   *"Not signed in … run `defender-mcp login`"*.

**Run one container per person, reachable only by that person.** Whoever can reach the container acts
as the signed-in user, and whoever can read the token volume can too. Don't register a delegated
instance as the shared gateway entry. See [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

Things that can get in the way:

- **Conditional Access** may block the device code flow (Microsoft recommends blocking it for most
  users) → `AADSTS53003`. Ask for an exception for this app/your account, or keep app-only auth.
- The sign-in lasts as long as the refresh token: 90 days of inactivity, sign-in-frequency policies,
  password resets or revoked sessions end it → *"Sign-in of … can't be renewed"* → `login` again.
- New permissions after you signed in: `login` again so the token includes them.

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
- "Show my open cases" (delegated) / "list incident cases with status Active".
- "Open a case 'Insider review', priority high, assign it to me, and add a contain task 'Reset creds'."
- "Set the case of incident 29 to Resolved, true positive, phishing."

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

- **Case management is Graph beta.** Microsoft can change it before it reaches v1.0; the docs also
  list read-only roles for write calls, which is likely a copy error — expect writes to need Security
  Operator or higher.

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
