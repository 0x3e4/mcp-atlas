# Changelog

All notable changes to bookstack-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-09

### Changed

- Dependencies only move to releases that are at least 7 days old. pydantic 2.14.3 → 2.14.2,
  pydantic-core 2.50.4 → 2.50.2 and typing-inspection 0.4.5 → 0.4.4 went back to the newest
  releases that meet this; the newer ones follow once they are old enough.

## [1.0.0] - 2026-11-05

First versioned release.

### Added

- Read tools for a BookStack wiki (hierarchy, page content, search, attachments incl. PDF / mail / images, gallery images, exports) and opt-in writes for pages, chapters, books, shelves, comments, attachments, images and draw.io drawings.

### Fixed

- The HTTP client no longer keeps cookies. A BookStack session cookie (e.g. from a web URL passed to
  `bookstack_get`) made every later call a guest session and answered 403 for everyone using the
  server. `bookstack_get` only reads `/api/` now, and the cookie-session 403 is explained.
- A page body update's confirm code is tied to the page's current revision, so a save in the browser
  between preview and confirmation needs a new confirmation.

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
