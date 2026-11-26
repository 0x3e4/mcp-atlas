# Changelog

All notable changes to netscaler-console-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-11-26

### Changed

- Dependencies (each release at least 7 days old): annotated-doc 0.0.7, httpcore2 / httpx2 2.16.2, python-multipart 0.0.34, typer 0.29.2.
- Held back by the 7-day rule: certifi 2026.11.20, packaging 26.4, pydantic 2.14.4 / pydantic-core 2.50.5, sse-starlette 3.7.1 (and Poetry 2.5.2 in the image) until they are a week old.

### Security

- Credentials can come from files (Docker / Kubernetes secrets): `NETSCALER_CONSOLE_PASSWORD_FILE=/run/secrets/…` fills
  `NETSCALER_CONSOLE_PASSWORD`, and the same works for every password, secret, token, API key, user and client-id
  variable (`<VAR>_FILE`). The value is then neither in the env file nor in `docker inspect`. A missing
  or empty file, or both variables set to different values, stops the server at start instead of
  running with the wrong credentials (shared guard `load_secret_files`).

## [1.3.0] - 2026-11-18

### Fixed

- The Console login for the API proxy failed with errorcode 10008 ("payload should start with object="):
  the Console's classic NITRO login takes a form body `object=<json>`, not plain JSON. The login (and
  logout) now sends `object=` with the JSON URL-encoded, and falls back once to the unencoded form the
  docs' curl examples use; the form that worked is used first from then on. Wrong credentials are not
  retried. This fixes every per-ADC tool (`vserver_diagnose`, `instance_get`, `instance_running_config`,
  `waf_profile_status`, `set_entity_state`).

### Added

- `list_vservers`: find vservers by a part of their name, across all ADCs (the Console's application
  summary) or live from one ADC.

### Changed

- `performance_report` takes a part of the name: it resolves it to the one vserver / service / service
  group it matches (on the ADC when `instance_ip` is given, else in the application summary, which also
  supplies the instance IP), and returns the candidates when several match. `name` now comes first and
  `instance_ip` is optional for vservers.

## [1.2.0] - 2026-11-18

### Security

- The shared mcp-atlas guard (`_atlas_guard.py`, from `_shared/atlas_guard.py`) wraps every tool:
  - Writes are confirmed in the client's own dialog (MCP elicitation) when the client supports it, so
    the model never sees or relays the confirm code. `MCP_CONFIRM_MODE`: `auto` (default; the code
    flow stays as the fallback), `elicit`, `elicit-destructive`, `code`.
  - Tool annotations: read-only, destructive, idempotent and open-world hints.
  - Audit log of every write as JSON lines on stderr, GELF to Graylog (`MCP_AUDIT_GELF`) and RFC 5424
    syslog over UDP / TCP / TLS (`MCP_AUDIT_SYSLOG`); `MCP_AUDIT_INSTANCE`, `MCP_AUDIT_READS`.
  - Text other people wrote comes back wrapped in `<untrusted>…</untrusted>`; invisible, bidi and
    Unicode-tag characters are removed; secrets are masked in every result.
    Read tools repeat that warning in their description (`MCP_DESCRIBE_UNTRUSTED`), because
    gateways such as mcpjungle drop the server instructions.
  - Writes whose arguments carry private keys, tokens or the server's own credentials are refused
    (`MCP_SECRET_SCAN`). Writes are limited per minute (`MCP_WRITE_LIMIT`, default 30), and tools can
    be limited (`MCP_TOOLS` / `MCP_DISABLED_TOOLS`).
- HTTP mode: DNS-rebinding protection with `MCP_ALLOWED_HOSTS` (it was switched off) and an optional
  bearer token (`MCP_AUTH_TOKEN` / `MCP_AUTH_TOKEN_FILE`).
- The compose examples run the container with a read-only root file system, no capabilities and
  no privilege escalation, `/tmp` as tmpfs and memory / CPU limits. They set `MCP_ALLOWED_HOSTS` to the
  container name: HTTP clients that use another host name get 421 until it is added. The base image is
  pinned by digest.

## [1.1.0] - 2026-11-18

### Fixed

- Per-ADC tools (`instance_get`, `instance_running_config`, `vserver_diagnose`, `waf_profile_status`,
  `set_entity_state`) failed with 401 "Invalid Session ID in APIProxy request": the Console's API proxy
  does not accept `X-NITRO-USER` / `X-NITRO-PASS`. Proxied calls now use a Console session
  (`POST /nitro/v1/config/login`, sent as `SESSID` header and cookie), shared by parallel calls,
  renewed once on 401 and logged out on shutdown. The 401 message now points to the
  *Prompt Credentials for Instance Login* setting.
- `performance_report` failed with "Either IP Address or vSvrName is missing" (errorcode 10006): the
  Console serves the `perf_*` reports only for one entity on one ADC. `instance_ip` and `name` are now
  required and sent as NITRO `args`; the key spellings, which the reference does not document, are tried
  in turn.
- Error messages reached the model only as "Error executing tool …" (mcp 2.3 hides the text of
  anything but a `ToolError`). Console errors and the tools' own hints (writes disabled, bad path …) are
  now `ToolError`s, so the model sees the reason, and the server log no longer shows them as crashes.

### Added

- `console_get` takes `args` (NITRO `args=key:value,…`).

## [1.0.0] - 2026-11-18

First release.

### Added

- Reads over the NetScaler Console NITRO API (on-prem with a Console user, or the Console service with a
  Citrix Cloud API client): instances with state, HA role and event counts; applications with health
  score, response time and error rate; application anomalies; performance reports per vserver /
  service / service group; active and historic events; collected syslog; SSL certificates by expiry;
  configuration audit (unsaved changes, template drift); configuration jobs with per-instance results;
  licensing; a raw `console_get` escape hatch.
- WAF: `security_violations` (Security Insight), `waf_violation_logs` (single violations parsed from the
  APPFW syslog: type, client, profile, URL, blocked or not), `waf_learned_rules` (learned relaxation
  rules), `waf_profile_status` (checks and violation counters of one profile on one ADC).
- Per-ADC troubleshooting through the Console's API proxy: `vserver_diagnose` (LB / CS vserver, bound
  services and service-group members, what is DOWN), `instance_get`, `instance_running_config`
  (secrets masked).
- Opt-in writes behind `NETSCALER_CONSOLE_ALLOW_WRITE`: clear active events, re-poll certificates /
  configurations. `set_entity_state` (enable / disable services, servers, service-group members,
  vservers, optionally graceful) additionally needs `NETSCALER_CONSOLE_ALLOW_INSTANCE_WRITE`.
