# Changelog

All notable changes to netscaler-console-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
