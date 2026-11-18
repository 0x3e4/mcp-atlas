# audiocodes-sbc-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to an **AudioCodes Mediant SBC** (or Media Gateway) through the device's **REST API**
(`/api/v1`, documented for firmware 7.4). Ask about your SBC in natural language — status and HA,
active and historic alarms, call statistics and other KPIs, the configuration (proxy sets, IP groups,
SIP interfaces, routing …), live CLI `show` output, TLS certificates and their expiry, the license —
and, opt-in, **change the configuration**, save it, place SIP test calls and, behind extra switches,
reset, replace the configuration, upgrade firmware, change TLS identities or install a license.

- One shared `httpx.AsyncClient`; **HTTP Basic** auth with a device user, no session.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `AUDIOCODES_ALLOW_WRITE`, the
  disruptive ones each behind a switch of their own (see below). Every write shows a preview and
  asks first.
- Passwords, shared secrets, SNMP communities and keys are **masked** in configuration output.
- A raw escape-hatch tool (`sbc_get`) so any other `/api/v1` JSON resource stays reachable.

## Tools

### Read

| Tool | What it does | Min. user level |
|---|---|---|
| `device_status()` | Product, firmware, IP, serial, uptime, operational and HA state, `saveNeeded` / `resetNeeded`. | Monitor |
| `list_alarms(kind?, limit?, after?, detailed?)` | Active or historic alarms with severity, source and date (pages with `after`). | Monitor |
| `get_alarm(alarm_id, kind?, include_oid?)` | One alarm, optionally with its SNMP trap OID. | Monitor |
| `sbc_call_stats(ip_group?)` | Current SBC call statistics, device-wide or for one IP Group. | Monitor |
| `kpi(path?, interval?, kpi_name?, detailed?, limit?, after?)` | Browse and read any performance monitor (`current/…`, `history/…`). | Monitor |
| `kpi_intervals(limit?)` | The stored history intervals. | Monitor |
| `get_configuration(format?, grep?, max_chars?)` | The configuration as CLI script or INI, secrets masked; `grep` picks blocks (`proxy-set`, `ip-group`, `IPGroup` …). | Security Admin |
| `run_show_commands(commands)` | Run CLI `show …` commands (registrations, proxy status, calls …) and return their output. Only `show` lines are accepted. | Security Admin |
| `list_files()` | The device's file resources. | Admin |
| `license_info(show_key?)` | Serial, key description, MAC; the key is shortened unless `show_key`. | Admin |
| `list_tls_contexts()` / `get_tls_context(context_id, include_pem?)` | TLS contexts; per context the key size, the device certificate and every trusted root with expiry and days left. | Security Admin |
| `get_test_call(session_id?)` | A SIP test call's state, release cause, MOS / jitter / loss — or the default test call settings. | Monitor |
| `sbc_get(path, params?)` | Escape hatch: raw GET of any `/api/v1` JSON resource (not the configuration files). | — |

### Write tools (opt-in)

These change the SBC and only work when **`AUDIOCODES_ALLOW_WRITE=true`** (otherwise they refuse with
a clear message). The device user also needs the privilege level the resource requires.

| Tool | What it does |
|---|---|
| `apply_cli_script(script, save?)` | Change the configuration with an incremental CLI script — live, **no reset**. `reload`, `copy`, `erase` and `write factory` are refused. `save=true` saves to flash afterwards. |
| `apply_ini(ini, save?)` | The same with an incremental INI file. |
| `save_configuration()` | Save the running configuration to flash (all unsaved changes, not only yours). |
| `start_test_call(called_number, calling_number, dest_ip_group? \| dest_address?, transport?, out_interface?, timeout?, play_dtmf?)` / `drop_test_call(session_id)` | Place / end a real SIP test call from the SBC. |
| `sip_recording(command, call_key, role?, recording_dest_username?, headers?)` | Start, stop, pause or resume SIPREC recording of a live call. |
| `create_csr(context_id, common_name, …)` | A certificate signing request for a TLS context's key (nothing on the device changes). |

Sensitive writes need **a second switch** on top of `AUDIOCODES_ALLOW_WRITE` (all default `false`,
read per instance env file):

| Switch | Tools | Always confirmed |
|---|---|---|
| `AUDIOCODES_ALLOW_RESET` | `reset_device(save_config?, wait_for_calls?, max_wait_seconds?)` (graceful by default: waits for calls), `replace_configuration(content, format?)` (the whole CLI / INI, preview shows a diff, then resets), `upgrade_firmware(file_name, hitless?)` (a `.cmp` from `AUDIOCODES_FILE_DIR`; resets, or switches over on HA with `hitless`) | yes |
| `AUDIOCODES_ALLOW_TLS` | `upload_certificate(context_id, pem)` (preview compares old and new), `add_trusted_root(context_id, pem)`, `generate_private_key(context_id, size?)`, `generate_self_signed(context_id, common_name, …)` | key and self-signed generation |
| `AUDIOCODES_ALLOW_LICENSE` | `install_license(key, description?, serial_number?)` | yes |

**Confirmation before every write** (`AUDIOCODES_CONFIRM_WRITE`, default `true`): a write tool's
first call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short
overview and asks *"Confirm it?"*; only after you say yes does it repeat the call with
`confirm=<code>`. The code is tied to those exact arguments (and for a configuration replace to the
current configuration), so a changed request needs a fresh confirmation (codes also expire when the
server restarts). "Always confirmed" tools ask even with `AUDIOCODES_CONFIRM_WRITE=false`.

## 1. Create a device user

In the SBC's Web interface: **Setup → Administration → Web & CLI → Local Users → New**. Give the
user the lowest privilege level that covers what you enable:

| Level | Enough for |
|---|---|
| Monitor | status, alarms, KPIs, test calls |
| Administrator | + files, license info, save, reset, firmware, SIP recording |
| Security Administrator | + configuration (read and change), `show` commands, TLS, license install |

Prefer a separate user for the API (and a separate, more privileged one for a write instance). LDAP /
RADIUS users need access level 50 or more.

## 2. Configure

```bash
cp .env.example audiocodes.env
# edit audiocodes.env: AUDIOCODES_BASE_URL, AUDIOCODES_USERNAME, AUDIOCODES_PASSWORD
#   (set AUDIOCODES_ALLOW_WRITE=true to enable writes)
```

- **`AUDIOCODES_BASE_URL`** — the device's web address, e.g. `https://sbc.example.com` (no
  `/api/v1`). For an HA pair, the active unit's OAMP address.
- **TLS** — set `AUDIOCODES_CA_BUNDLE` to the CA that signed the device's web certificate, or (lab
  only) `AUDIOCODES_VERIFY_SSL=false`. Use HTTPS: Basic auth sends the password with every request.
- **Firmware** — `upgrade_firmware` reads `.cmp` files only from `AUDIOCODES_FILE_DIR`; mount a
  folder into the container (`-v /srv/sbc-firmware:/firmware:ro`, `AUDIOCODES_FILE_DIR=/firmware`).

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
docker build -t audiocodes-sbc-mcp .
claude mcp add audiocodes-sbc -- docker run -i --rm --env-file ./audiocodes.env audiocodes-sbc-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from audiocodes.env into your shell first, then:
claude mcp add audiocodes-sbc -- poetry run audiocodes-sbc-mcp
```

### Always-on HTTP (optional)

[`compose.yml.example`](compose.yml.example) runs the server as a long-lived `streamable-http`
service (`cp compose.yml.example compose.yml && docker compose up -d`), serving MCP at
`http://<host>:8000/mcp`. Behind a gateway (e.g. mcpjungle), drop the published port and join the
shared network as described in the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle), then
`mcpjungle register --name audiocodes-sbc --url http://audiocodes-sbc-mcp:8000/mcp`.

#### Multiple instances (one image, several env files)

One container per SBC (or HA pair), or a read-only instance next to a write-enabled one with a more
privileged device user: each container gets its own env file. Ready to copy:
[`compose.yml.multiuser.example`](compose.yml.multiuser.example). The switches
(`AUDIOCODES_ALLOW_WRITE`, `_RESET`, `_TLS`, `_LICENSE`) go into each instance's env file, so they can
be on for one user only. `*.env` is gitignored.

## 4. Verify

In Claude Code, run `/mcp` to confirm the `audiocodes-sbc` server connected, then ask things like:

- "What firmware is the SBC on, is HA operational, and does the configuration need saving?"
- "Which alarms are active right now?"
- "How many active SBC calls are there, and how are the call failures per IP Group?"
- "Show me the proxy set and IP group configuration for the ITSP trunk."
- "Is the ITSP proxy set reachable? Run the show command for the proxy set status."
- "When do the TLS certificates expire?"

With `AUDIOCODES_ALLOW_WRITE=true` you can also:

- "Set the keep-alive of proxy set 1 to OPTIONS every 60 seconds and save."
- "Place a test call to 100 from 200 via IP group ITSP and tell me the MOS."
- "Create a CSR for TLS context 0 with CN sbc.example.com."
- "Reset the SBC once all calls have ended." (with `AUDIOCODES_ALLOW_RESET=true`)

## Security & hardening

This server uses the shared mcp-atlas guard (see the [repo README → Security](../README.md#security)):
writes are confirmed in the client's own dialog where the client supports it (`MCP_CONFIRM_MODE`), every
tool carries read-only / destructive hints, text other people wrote comes back marked as
`<untrusted>`, secrets are masked, writes that would carry secrets out are refused, and every write is
audited (stderr, GELF `MCP_AUDIT_GELF`, syslog `MCP_AUDIT_SYSLOG`). In HTTP mode set `MCP_AUTH_TOKEN` and
`MCP_ALLOWED_HOSTS`; the compose examples already run the container read-only and without capabilities.
The variables are in [`.env.example`](.env.example).

## Notes & scope

- **No per-table configuration API.** The device REST API documents no endpoints for single tables
  (IP Groups, Proxy Sets, routing …): configuration is read as a whole CLI script / INI and changed
  with incremental CLI scripts or INI files. The agent reads the relevant block first
  (`get_configuration(grep=…)`) and writes only the lines to change.
- **Not persistent until saved.** Incremental changes are live at once but lost on a reset until the
  configuration is saved (`save=true` or `save_configuration`); `device_status` shows `saveNeeded`.
  There is no rollback: keep the old block to restore it with another script.
- **`run_show_commands`** goes through the incremental CLI script endpoint (the API returns show
  output there), which is why it needs a Security Administrator user.
- **Untested against a live device.** Built from AudioCodes' REST API reference for 7.4: the exact
  KPI names, the output field of show commands and whether incremental scripts accept every command
  should be checked on your firmware first.
- Not covered: the Web UI auth-token endpoint, debug file creation and other file uploads (call
  progress tones, dial plans, voice prompts) — reachable via the Web UI.
