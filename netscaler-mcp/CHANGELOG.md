# Changelog

All notable changes to netscaler-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Changed

- `upload_ssl_file` is exempt from the outgoing secret scan: uploading a private key is its job.

## [1.1.2] - 2026-11-18

### Changed

- Dependencies moved to the newest releases that are at least 7 days old: annotated-doc 0.0.6,
  markdown-it-py 4.3.0, typer 0.29.0.

## [1.1.1] - 2026-11-16

### Changed

- Dependencies moved to the newest releases that are at least 7 days old: click 8.5.1, pydantic
  2.14.3, pydantic-core 2.50.4, sse-starlette 3.7.0, typer 0.28.0, typing-inspection 0.4.5.

## [1.1.0] - 2026-11-09

### Added

- New kinds for the generic tools: SSL (`ssl_certkey` incl. renewal through `update ssl certKey`,
  `ssl_profile`, `ssl_policy`, `ssl_action`, the SSL side of vservers / services / service groups),
  rewrite / responder (policies, actions, policy labels, HTML page import), pattern sets, data sets,
  string maps, named expressions, GSLB vservers / services / sites and DNS records (A, AAAA, CNAME,
  TXT, NS, SOA).
- New bindings: feature policies (responder, rewrite, appfw, bot, cache, cmp, transform) and analytics
  profiles on LB / CS vservers, certificates incl. SNI and SSL policies on SSL vservers / services,
  ciphers on SSL profiles, a certificate's CA link, global rewrite / responder policies, policy label
  entries, pattern set / data set / string map values, GSLB services and domains.
- `list_objects`, `search_policy_objects` (pattern sets, data sets, string maps and expressions
  searched together), `vserver_diagnose` (CS → LB → members with warnings for idle members and
  TCP-only monitors on SSL backends).
- `upload_ssl_file`: certificates and keys to `/nsconfig/ssl` only, content never shown.
- `sync_gslb_config` with a preview of the target sites.
- `clone_app_setup`: a new app from an existing one, including policies, analytics, CS rule at the
  next free priority and SNI certificate.
- `apply_batch(instances=[...])`: the same changes on several appliances with one confirmation, stops
  on the first failing appliance and compares the result afterwards.

### Fixed

- Boolean unbind arguments are sent lower case (`snicert:true`), as NITRO expects.

### Changed

- Dependencies only move to releases that are at least 7 days old. pydantic 2.14.3 → 2.14.2,
  pydantic-core 2.50.4 → 2.50.2 and typing-inspection 0.4.5 → 0.4.4 went back to the newest
  releases that meet this; the newer ones follow once they are old enough.
- CI pins the GitHub Actions to exact releases (checkout v7.0.1, setup-buildx-action v4.4.1,
  login-action v4.7.0, build-push-action v7.4.0), so the 7-day rule applies to them too.

## [1.0.0] - 2026-11-05

First versioned release.

### Added

- Read tools for one or more NetScaler ADCs (vservers, services, certificates, GSLB, DNS, WAF, Bot, HA, health), WAF and Bot rollout writes, and comparison of appliances that don't sync.
- Load balancing / content switching: `get_object`, `list_cs_policies`, `list_cs_actions`,
  `list_lb_monitors`, `add_object`, `update_object`, `set_object_state`, `change_bindings`.
- `delete_object` behind its own `NETSCALER_ALLOW_DELETE` switch; deletes always ask for confirmation.

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
