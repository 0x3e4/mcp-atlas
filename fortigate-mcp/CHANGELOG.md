# Changelog

All notable changes to fortigate-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-26

### Changed

- Dependencies (each release at least 7 days old): annotated-doc 0.0.7, httpcore2 / httpx2 2.16.2, python-multipart 0.0.34, typer 0.29.2.
- Held back by the 7-day rule: certifi 2026.11.20, packaging 26.4, pydantic 2.14.4 / pydantic-core 2.50.5, sse-starlette 3.7.1 (and Poetry 2.5.2 in the image) until they are a week old.

### Security

- Credentials can come from files (Docker / Kubernetes secrets): `FORTIGATE_API_TOKEN_FILE=/run/secrets/…` fills
  `FORTIGATE_API_TOKEN`, and the same works for every password, secret, token, API key, user and client-id
  variable (`<VAR>_FILE`). The value is then neither in the env file nor in `docker inspect`. A missing
  or empty file, or both variables set to different values, stops the server at start instead of
  running with the wrong credentials (shared guard `load_secret_files`).

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

### Fixed

- Errors from bad arguments or from the upstream API reached the model only as "Error executing tool …",
  because mcp 2.x hides the text of anything but a `ToolError`. The reason comes through now. Unexpected
  crashes still show only the generic message, and their traceback goes to the server log.

## [1.1.1] - 2026-11-18

### Changed

- Dependencies moved to the newest releases that are at least 7 days old: annotated-doc 0.0.6,
  markdown-it-py 4.3.0, typer 0.29.0.

## [1.1.0] - 2026-11-16

### Added

- Generic object tools over 30 config tables (`list_kinds`): `list_objects`, `get_object` (with the
  reference count), `add_object`, `update_object` (preview shows old → new; code tied to the current
  values) and `delete_object`.
- `delete_object` behind the new `FORTIGATE_ALLOW_DELETE` switch (on top of `FORTIGATE_ALLOW_WRITE`,
  per instance); it always asks for confirmation, even with `FORTIGATE_CONFIRM_WRITE=false`, and
  shows how often the object is referenced.
- Policies: `create_policy` (with placement), `move_policy`, `policy_lookup` (which policy a flow hits),
  `route_lookup`.
- Operations: `list_sessions`, `live_table` (ARP, DHCP leases, FQDN resolution, SD-WAN health,
  SSL-VPN sessions, firewall users, banned IPs, FortiGuard, certificates, FortiSwitch, FortiAP, HA
  checksums, license), `search_logs`, `config_backup` (CLI text, whole or one block).
- `ban_ips`, `unban_ips`, `deauth_users` behind the new `FORTIGATE_ALLOW_USER_ACTIONS` switch.
- Secrets (`ENC …` values, password / PSK attributes, private keys) are masked in every result.

### Changed

- Dependencies moved to the newest releases that are at least 7 days old: click 8.5.1, pydantic
  2.14.3, pydantic-core 2.50.4, sse-starlette 3.7.0, typer 0.28.0, typing-inspection 0.4.5.

### Fixed

- `list_services` read `firewall/service/custom` and `firewall/service/group`, which FortiOS doesn't
  have; it reads `firewall.service/custom` and `firewall.service/group` now.
- `list_policies(ipv6=true)` read the non-existent `firewall/ipv6policy`; it reads `firewall/policy6`
  (FortiOS 6.x). `policy_stats(ipv6=true)` asks `firewall/policy` with `ip_version=ipv6`.

## [1.0.1] - 2026-11-09

### Changed

- Dependencies only move to releases that are at least 7 days old. pydantic 2.14.3 → 2.14.2,
  pydantic-core 2.50.4 → 2.50.2 and typing-inspection 0.4.5 → 0.4.4 went back to the newest
  releases that meet this; the newer ones follow once they are old enough.

## [1.0.0] - 2026-11-05

First versioned release.

### Added

- Read tools for a FortiGate (policies with hit counters, objects, VIPs, interfaces, routing, VPN, HA, health) and opt-in writes for address objects, groups and policy state.

### Changed

- Moved to MCP SDK 2.x (`MCPServer`). Tools, parameters and env vars are unchanged; the server now
  reports its own version as `serverInfo.version`. `FASTMCP_HOST` is no longer read: the HTTP daemon
  binds to `MCP_HOST`.
- All dependencies updated; Docker images use Poetry 2.5.1.

### Security

- mcp 1.30+ / 2.x: CVE-2026-59950, CVE-2026-59951, CVE-2026-116684, CVE-2026-116685,
  CVE-2026-116686.
- pyjwt 2.15.1, anyio 4.16.0, cryptography 50.0.2 (CVE-2026-69247) and certifi 2026.10.23 fix the
  advisories pip-audit reported for the earlier locks.
