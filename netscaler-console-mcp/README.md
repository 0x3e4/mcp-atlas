# netscaler-console-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server for **NetScaler Console** (formerly
Citrix ADM) — on-prem or the Console service — built for **analysis and troubleshooting** across all
your NetScaler ADCs, including **WAF**. Ask in natural language: which apps are unhealthy and why, which
backend is down, what the event log and syslog say, which certificates expire, what the WAF blocked for
a user, which learned WAF rules are pending, whether a box has unsaved or drifted config — and, opt-in,
clear events, re-poll inventories, or take a service / server / member out of rotation.

- Works with any MCP client: Claude Code, VS Code / Copilot, a gateway such as mcpjungle, or your own
  LLM (Ollama, vLLM …) — see the [repo README](../README.md#using-with-other-clients--gateways).
- One Console login reaches every managed ADC: per-ADC live data goes through the Console's **API
  proxy**, so the ADCs need no credentials in this server.
- **Read-only by default**; writes opt-in, ADC changes behind a second switch, every write confirmed.
- Secrets in configuration output are masked. Raw escape hatches: `console_get`, `instance_get`.

Pairs well with [netscaler-mcp](../netscaler-mcp/) (direct NITRO to the ADCs, with full config writes):
use this one for the fleet-wide picture and analytics, that one to change configuration.

## Tools

### Fleet-wide (Console data)

| Tool | What it does |
|---|---|
| `list_instances(search?, problems_only?, limit?, full?)` | Managed instances: state, version, HA role, load, critical / major event counts. |
| `list_applications(search?, problems_only?, sort_by?, limit?, full?)` | Apps / vservers across instances: state, health score, response time, error rate, throughput, issues. |
| `app_anomalies(server_ip?, limit?)` | Anomalies the Console detected per application server. |
| `list_vservers(search?, instance?, kind?, limit?)` | Find vservers by a part of their name: across all ADCs from the Console's application summary, or live from one ADC (IP, port, type, state). |
| `performance_report(name, instance_ip?, kind?, limit?)` | Collected counters of one LB vserver, service, service group or CS vserver on one ADC over time (the Console serves these reports only per entity). A unique part of the name is enough; several matches come back as candidates. Services and service groups need `instance_ip`. |
| `list_events(active_only?, severity?, instance?, category?, text?, hours?, limit?)` | Active or historic events: entity up/down, thresholds, HA, config changes — newest first. |
| `search_syslog(instance?, severity?, module?, text?, limit?)` | Syslog the Console collected from the instances. |
| `ssl_certificates(expiring_within_days?, instance_ip?, search?, limit?)` | Certificates on every instance, soonest expiry first. |
| `config_audit(instance?, drift_only?)` | Unsaved changes (running vs saved) and template drift per instance. |
| `list_config_jobs(status?, search?, limit?)` | Configuration jobs with commands and per-instance results. |
| `license_status()` | Console licenses, expiry and pooled-capacity usage. |
| `console_get(resource, filter?, args?, attrs?, pagesize?, pageno?, count?)` | Escape hatch: any Console NITRO resource (`/nitro/v2/config/…`); `args` for resources that need them, e.g. `ip_address:192.0.2.10,vsvrName:web-lb`. |

### WAF / security

| Tool | What it does |
|---|---|
| `security_violations(group_by?, order_by?, app?, source_ip?, limit?)` | Security Insight: violation types, attack counts, threat / safety index, source IPs and countries. |
| `waf_violation_logs(instance?, profile?, client_ip?, text?, limit?)` | Single violations from the APPFW syslog — type, client IP, profile, URL, blocked or not — with top lists. The tool for "the site blocks me". |
| `waf_learned_rules(profile?, state?, url?, limit?)` | Relaxation rules learned from violations, with how much each would relax and whether it is deployed. |
| `waf_profile_status(instance, profile)` | One profile on one ADC: which checks block / log / learn, and its per-check violation counters. |

### One ADC, through the Console

| Tool | What it does |
|---|---|
| `vserver_diagnose(instance, name, kind?)` | LB or CS vserver: state and counters, every bound service and service-group member with state, CS policies and target states — and a list of what is DOWN. |
| `instance_get(instance, path, params?)` | Raw GET of any ADC NITRO resource (`config/…`, `stat/…`). |
| `instance_running_config(instance, grep?, max_chars?)` | The running config as CLI lines, secrets masked; `grep` shows everything for one app. |

### Write tools (opt-in)

| Tool | Needs | What it does |
|---|---|---|
| `clear_events(event_ids)` | `NETSCALER_CONSOLE_ALLOW_WRITE` | Clear active events (the history keeps them). |
| `refresh_inventory(what, instances?)` | `NETSCALER_CONSOLE_ALLOW_WRITE` | Re-poll SSL certificates or configurations now. Nothing on the ADCs changes. |
| `set_entity_state(instance, kind, name, enabled, delay_seconds?, member?)` | `…_ALLOW_WRITE` **and** `NETSCALER_CONSOLE_ALLOW_INSTANCE_WRITE` | Enable / disable a service, server, service group (or one member) or vserver on an ADC — gracefully with `delay_seconds`. Running config only, not saved. |

**Confirmation before every write** (`NETSCALER_CONSOLE_CONFIRM_WRITE`, default `true`): the first call
changes nothing and returns a preview with a `confirm_code`; the agent shows it, asks *"Confirm it?"*,
and repeats the call with `confirm=<code>` only after you say yes. The code is tied to the exact
arguments and dies with a server restart.

## 1. Credentials

**On-prem:** create a Console user (**Settings → Users & Roles → Users**) with a read-only role for the
read tools, or a role that may manage instances and events for the writes. The server sends it as
`X-NITRO-USER` / `X-NITRO-PASS` on each Console request. The API proxy (all per-ADC tools) does not take
those headers, so for proxied calls the server logs in once (`/nitro/v1/config/login`), reuses the
session and logs in again when it expires.

**Console service (cloud):** create a Citrix Cloud API client (**Identity and Access Management → API
Access → Secure Clients**) and note the customer ID; set `NETSCALER_CONSOLE_CUSTOMER_ID`,
`_CLIENT_ID`, `_CLIENT_SECRET` and `_CLOUD_REGION` instead of user and password.

**ADC calls through the Console** use the instance profile credentials the Console already holds. If
*Prompt Credentials for Instance Login* is enabled (**Settings → Administration → System
Configurations**), disable it or set `NETSCALER_CONSOLE_INSTANCE_USERNAME` / `_PASSWORD` (a read-only
ADC user is enough for everything but `set_entity_state`).

**Data sources:** events and SSL inventory work out of the box; `search_syslog` and
`waf_violation_logs` need the instances to send syslog to the Console; `list_applications`,
`security_violations` and `waf_learned_rules` need analytics (Web / Security Insight) enabled for the
vservers and the matching Console licenses.

## 2. Configure

```bash
cp .env.example netscaler-console.env
# edit: NETSCALER_CONSOLE_BASE_URL, NETSCALER_CONSOLE_USERNAME, NETSCALER_CONSOLE_PASSWORD
```

TLS: set `NETSCALER_CONSOLE_CA_BUNDLE` to the CA of the Console's certificate, or (lab only)
`NETSCALER_CONSOLE_VERIFY_SSL=false`.

## 3. Run & register

```bash
docker build -t netscaler-console-mcp .
claude mcp add netscaler-console -- docker run -i --rm --env-file ./netscaler-console.env netscaler-console-mcp
```

Always-on HTTP / gateway: `cp compose.yml.example compose.yml && docker compose up -d` serves
`http://<host>:8000/mcp`; behind mcpjungle register it with
`mcpjungle register --name netscaler-console --url http://netscaler-console-mcp:8000/mcp`. A read-only
and a write-enabled instance side by side: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).
Your own LLM: [`examples/llm_bridge.py`](../examples/llm_bridge.py).

## 4. Verify

- "Which NetScaler instances are down or have critical events?"
- "Which applications have the worst health score, and why?"
- "The shop is slow — diagnose vserver web-lb on 192.0.2.10."
- "What did the WAF block for client 203.0.113.66 in the last messages?"
- "Which WAF violations hit the shop most, and from which countries?"
- "Which learned WAF rules for profile web-fw are ready, and are any of them suspicious?"
- "Which certificates expire in the next 30 days?"
- "Which ADCs have unsaved configuration changes?"

With writes enabled: "Take web2:443 out of sg-web on 192.0.2.10, gracefully over 60 seconds."

## Security & hardening

This server uses the shared mcp-atlas guard (see the [repo README → Security](../README.md#security)):
writes are confirmed in the client's own dialog where the client supports it (`MCP_CONFIRM_MODE`), every
tool carries read-only / destructive hints, text other people wrote comes back marked as
`<untrusted>`, secrets are masked, writes that would carry secrets out are refused, and every write is
audited (stderr, GELF `MCP_AUDIT_GELF`, syslog `MCP_AUDIT_SYSLOG`). In HTTP mode set `MCP_AUTH_TOKEN` and
`MCP_ALLOWED_HOSTS`; the compose examples already run the container read-only and without capabilities.
Credentials can come from files (Docker / Kubernetes secrets) instead of the env file: set `NETSCALER_CONSOLE_PASSWORD_FILE=/run/secrets/…` and leave `NETSCALER_CONSOLE_PASSWORD` unset; this works for every password, secret, token, API key and user variable (`<VAR>_FILE`). The variables are in [`.env.example`](.env.example).

## Notes & scope

- **Untested against a live Console.** Built from the NetScaler Console (ADM) 14.1 NITRO reference and
  NetScaler's own Ansible collection / Terraform provider. Things to check first on your Console:
  - The instance resource (`managed_device`); `list_instances` falls back to the event summary.
  - The spelling of the API-proxy headers. Both documented forms are sent.
  - How the proxy session is passed: the docs show both a `SESSID` header and a cookie, so both are sent.
  - The `args` keys of the `perf_*` reports (not documented): `performance_report` tries
    `ip_address` / `device_ip_address` with the entity-name key and says which one worked.
  - The APPFW syslog line format your firmware writes (`waf_violation_logs` parses it, and shows the raw
    line when it can't).
- Analytics resources differ between Console builds and licenses; an empty result usually means the
  feature (Insight, syslog forwarding) is not enabled, not that all is well.
- Not covered on purpose: StyleBooks / config packs, configuration job creation and execution,
  backups / restores, upgrades. Change ADC configuration with [netscaler-mcp](../netscaler-mcp/).
