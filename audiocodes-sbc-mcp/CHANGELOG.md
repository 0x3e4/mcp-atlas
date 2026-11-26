# Changelog

All notable changes to audiocodes-sbc-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-11-26

### Changed

- Dependencies (each release at least 7 days old): annotated-doc 0.0.7, httpcore2 / httpx2 2.16.2, python-multipart 0.0.34, typer 0.29.2.
- Held back by the 7-day rule: certifi 2026.11.20, packaging 26.4, pydantic 2.14.4 / pydantic-core 2.50.5, sse-starlette 3.7.1 (and Poetry 2.5.2 in the image) until they are a week old.

### Security

- Credentials can come from files (Docker / Kubernetes secrets): `AUDIOCODES_PASSWORD_FILE=/run/secrets/…` fills
  `AUDIOCODES_PASSWORD`, and the same works for every password, secret, token, API key, user and client-id
  variable (`<VAR>_FILE`). The value is then neither in the env file nor in `docker inspect`. A missing
  or empty file, or both variables set to different values, stops the server at start instead of
  running with the wrong credentials (shared guard `load_secret_files`).

## [1.1.0] - 2026-11-18

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

- `drop_test_call` counts as a write tool: annotations and audit.

## [1.0.1] - 2026-11-18

### Changed

- Dependencies moved to the newest releases that are at least 7 days old: annotated-doc 0.0.6,
  markdown-it-py 4.3.0, typer 0.29.0.

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
