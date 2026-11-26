# Changelog

All notable changes to atlas-hub-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-26

First release.

### Added

- Hub in front of other MCP servers (streamable HTTP, bearer token per upstream, or one gateway such as
  mcpjungle): `list_servers`, `search_tools`, `describe_tool`, `call_read_tool`, `call_write_tool`. Meant
  for local models and clients that attach every tool to every request; Claude Code and the Claude API
  search tools on their own and do not need it.
- Search: BM25 over tool names, descriptions and parameter names; optional semantic search via any
  OpenAI-compatible embeddings endpoint (`ATLAS_HUB_EMBED_URL` / `ATLAS_HUB_EMBED_MODEL`), falling back to
  keywords when it fails.
- Tool listings cached for `ATLAS_HUB_REFRESH` seconds; a server that is briefly down keeps its last
  listing. `ATLAS_HUB_TOOLS` / `ATLAS_HUB_HIDDEN_TOOLS` narrow the catalog.

### Security

- Reads and writes are separate tools. `call_read_tool` runs only tools the upstream annotates read-only;
  `call_write_tool` is off unless `ATLAS_HUB_ALLOW_WRITE=true` and is annotated destructive.
- Upstream confirm flows pass through: the preview comes back, the shared guard asks the user and repeats
  the call with the code. Upstream write tools without a confirm flow get a hub confirm code bound to the
  tool and its arguments.
- Upstream tool descriptions are marked `<untrusted>` (tool poisoning by foreign servers).
- The shared guard as in every mcp-atlas server: audit, secret scan, write budget, `<VAR>_FILE` secrets,
  `MCP_COMPACT_TOOLS`.
