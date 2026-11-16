# Changelog

All notable changes to audiocodes-sbc-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-16

First release.

### Added

- Reads over the AudioCodes device REST API (`/api/v1`, documented for firmware 7.4): device status,
  active and historic alarms, performance monitoring (KPIs, SBC call statistics), the configuration
  as CLI script or INI (passwords masked, filterable by block), CLI `show` commands, files, TLS
  contexts with certificate and trusted-root expiry, the license, SIP test call status, and a raw
  `sbc_get` escape hatch.
- Opt-in writes behind `AUDIOCODES_ALLOW_WRITE`: incremental CLI script / INI (live, no reset), save
  the configuration, SIP test calls, SIP recording control, certificate signing requests.
- Sensitive writes each behind a switch of their own: `AUDIOCODES_ALLOW_RESET` (reset, whole
  configuration replace with a diff preview, firmware upgrade incl. hitless on HA),
  `AUDIOCODES_ALLOW_TLS` (certificates, trusted roots, key / self-signed generation) and
  `AUDIOCODES_ALLOW_LICENSE`. Resets, configuration replaces, firmware, key and self-signed
  generation and license installs always ask for confirmation.
