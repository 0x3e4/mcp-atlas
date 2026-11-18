# Changelog

All notable changes to fortigate-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
