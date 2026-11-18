# Changelog

All notable changes to netscaler-console-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
