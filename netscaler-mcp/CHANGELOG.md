# Changelog

All notable changes to netscaler-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-26

### Added

- WAF rule types for the 14.1 bindings that were missing: `block_keyword`, `json_block_keyword`,
  `allow_list` (bypass list), `deny_list`, `fake_account`, `file_upload_type`, `xml_sql_injection`,
  `xml_xss`, `log_expression`, `exclude_response_content_type`, `confidential_field`, `rest_validation`,
  `grpc_validation`, `xml_validation_url`. Attribute names come from NetScaler's Go SDK, the DELETE
  arguments from its Terraform provider. Export, import, rehost, `add_waf_rule(rule='raw')`,
  `remove_waf_rule` and the new state tool handle them; before, they were exported under
  `other_bindings` only.
- `set_waf_rule_state`: park (`DISABLED`) or re-activate (`ENABLED`) relaxation rules without deleting
  them. NITRO has no binding update, so this unbinds and binds again with the new state; if the bind
  fails, the original rule is bound again.
- `set_signature_rules`: enable / disable WAF signature rules (`rule_ids`) or a whole `category`, set
  their actions (`block`, `log`, `stats`) and `auto_enable_new` (`set appfw signatures`, PUT
  `appfwsignatures`). Not yet tried on a live appliance.
- `set_signature_auto_update`: signature auto-update switch, https URL and proxy for WAF
  (`appfwsettings`) and Bot (`botsettings`), with the current values in the preview.
- `NETSCALER_WRITE_CONCURRENCY` (default 4, 1-16) and `NETSCALER_BULK_BIND` (default off), also per
  instance.

### Changed

- Rule writes run in parallel: deploy / discard learned rules, import, rehost, remove and add to several
  profiles send up to `NETSCALER_WRITE_CONCURRENCY` requests at once, with one status per rule. An import
  still adds first, re-binds second and removes last; only the writes inside a phase overlap.
- `NETSCALER_BULK_BIND=true` binds new rules with NITRO bulk requests (100 per request,
  `X-NITRO-ONERROR: continue`, one status per rule) and falls back to single requests whenever the
  appliance rejects a bulk request. Off by default until tried on a live box.
- Parallel requests share one session: only one of them logs in again when the session is missing or
  has expired.
- Dependencies (each release at least 7 days old): annotated-doc 0.0.7, httpcore2 / httpx2 2.16.2, python-multipart 0.0.34, typer 0.29.2.
- Held back by the 7-day rule: certifi 2026.11.20, packaging 26.4, pydantic 2.14.4 / pydantic-core 2.50.5, sse-starlette 3.7.1 (and Poetry 2.5.2 in the image) until they are a week old.

### Security

- Credentials can come from files (Docker / Kubernetes secrets): `NETSCALER_PASSWORD_FILE=/run/secrets/…` fills
  `NETSCALER_PASSWORD`, and the same works for every password, secret, token, API key, user and client-id
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
