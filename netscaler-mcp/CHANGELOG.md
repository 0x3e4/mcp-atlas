# Changelog

All notable changes to netscaler-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
