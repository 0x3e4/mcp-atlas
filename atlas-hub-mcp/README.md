# atlas-hub-mcp

A small [MCP](https://modelcontextprotocol.io) server that sits **in front of other MCP servers** and
gives the model five tools instead of hundreds: it searches the upstream servers' tools, shows one
tool's parameters, and forwards calls.

> **Only worth it for local models** (Ollama, vLLM, LM Studio, llama.cpp …) and for gateways or clients
> that attach every tool to every request. **Claude Code and the Claude API do not need it**: they
> already load MCP tools on demand (built-in tool search), so a hub in front would only add a detour.

Why: tool definitions are sent with every request. All mcp-atlas servers together are about 354 tools
and **~116,000 tokens** (netscaler-mcp alone ~32,000), more than many local models can hold, and the
more tools a model sees, the worse it picks. With the hub the model starts with five tools (about 1,000
tokens) and looks up what it needs. `MCP_COMPACT_TOOLS=true` on the servers (about −35 %) is the simpler
first step; the hub is for when that is still too much.

- Works with any MCP server that speaks **streamable HTTP**, not only mcp-atlas servers, and with a
  gateway such as mcpjungle as the single upstream.
- **Keyword search** (BM25 over tool names, descriptions and parameter names) out of the box;
  **semantic search** when you point it at an embeddings endpoint (Ollama, vLLM, LM Studio, any
  OpenAI-compatible `/v1/embeddings`), which also finds tools for queries in other languages.
- **Reads and writes stay apart**, writes are **off by default**, and every write still needs the user's
  confirmation (see [Security](#security)).

## Tools

| Tool | What it does |
|---|---|
| `list_servers(refresh?)` | The upstream servers, their tool counts, and which ones are not answering. |
| `search_tools(query, server?, kind?, limit?)` | Best-matching tools for a task: tool id, read / write / destructive, one-line summary, parameters (`name: type`, `*` = required). |
| `describe_tool(tool, full?)` | One tool's description and parameter schema (compact by default). |
| `call_read_tool(tool, arguments)` | Run a read-only tool and return its result. Refuses tools that change something. |
| `call_write_tool(tool, arguments, confirm?)` | Run a tool that changes something (needs `ATLAS_HUB_ALLOW_WRITE=true`). The first call returns a preview with a confirm code; nothing changes until it is repeated with the code after the user agreed. |

A typical exchange: the model calls `search_tools("disable a WAF rule")`, gets
`netscaler.set_waf_rule_state` with its parameters, calls `call_write_tool` with them, shows the user
the preview, and repeats the call with `confirm=<code>` after the user says yes.

## 1. Run the upstream servers in HTTP mode

The hub talks streamable HTTP to every upstream, so each server runs as an always-on container
(`MCP_TRANSPORT=streamable-http`, see each server's `compose.yml.example`). Per upstream:

- Give it a bearer token (`MCP_AUTH_TOKEN`) and the hub the same token (`ATLAS_HUB_<NAME>_TOKEN`).
- Add the hub's view of its host name to `MCP_ALLOWED_HOSTS` (e.g. `netscaler-mcp:8000`).
- Keep `MCP_CONFIRM_MODE` at `auto` or `code`. With `elicit`, an upstream refuses every write, because
  the hub answers previews with a confirm code instead of a dialog.

Behind **mcpjungle**, list just the gateway: `ATLAS_HUB_UPSTREAMS=jungle=http://mcpjungle:8080/mcp`
(tool ids then look like `jungle.netscaler__list_lb_vservers`).

## 2. Configure

Copy [`.env.example`](.env.example) to `atlas-hub.env` and fill it in:

| Variable | Default | Meaning |
|---|---|---|
| `ATLAS_HUB_UPSTREAMS` | – (required) | `name=url` pairs, comma-separated: `netscaler=http://netscaler-mcp:8000/mcp,zammad=http://zammad-mcp:8000/mcp`. |
| `ATLAS_HUB_<NAME>_TOKEN` / `ATLAS_HUB_TOKEN` | – | Bearer token per upstream (`-` in a name becomes `_`), or one for all. `…_TOKEN_FILE` reads it from a file (Docker secret). |
| `ATLAS_HUB_ALLOW_WRITE` | `false` | Allow `call_write_tool`. The upstream servers' own write switches still apply on top. |
| `ATLAS_HUB_TOOLS` / `ATLAS_HUB_HIDDEN_TOOLS` | – | Only offer / hide upstream tools by id pattern, e.g. `ATLAS_HUB_HIDDEN_TOOLS=*.delete_*,azure.merge_*`. |
| `ATLAS_HUB_EMBED_URL` / `ATLAS_HUB_EMBED_MODEL` | – | OpenAI-compatible embeddings endpoint and model for semantic search, e.g. `http://ollama:11434/v1` + `nomic-embed-text` (or `bge-m3` for many languages). Optional `ATLAS_HUB_EMBED_KEY`. If the endpoint fails, search falls back to keywords. |
| `ATLAS_HUB_MAX_RESULTS` | `8` | Default number of search results (1–50). |
| `ATLAS_HUB_REFRESH` | `300` | Seconds a tool listing is cached; `list_servers(refresh=true)` reloads at once. |
| `ATLAS_HUB_TIMEOUT` | `60` | Seconds per upstream request. |
| `ATLAS_HUB_VERIFY_SSL` / `ATLAS_HUB_CA_BUNDLE` | `true` / – | TLS verification for https upstreams. |

The shared `MCP_*` security variables apply as in every mcp-atlas server (see the
[repo README → Security](../README.md#security)).

## 3. Run

```bash
cp compose.yml.example compose.yml   # adjust networks / names
docker compose up -d
```

The hub joins the same Docker network as the upstream containers and is itself reachable at
`http://atlas-hub-mcp:8000/mcp`. Point your local-model client at it, for example the
[OpenAI-compatible bridge](../examples/llm_bridge.py) from the repo README, Open WebUI's MCP support, or
any client that speaks MCP. It also runs over stdio (`docker run -i --rm --env-file ./atlas-hub.env
ghcr.io/0x3e4/atlas-hub-mcp`) for clients that launch servers themselves.

## Security

- **Read and write are separate tools**, so a client can auto-allow `call_read_tool` and always ask
  before `call_write_tool` (it is annotated destructive). `call_read_tool` refuses any tool that is not
  annotated read-only by its server; tools without annotations count as writes.
- **Confirmation is kept.** mcp-atlas servers return a preview with a confirm code; it passes through the
  hub, the hub's guard asks the user (in the client's dialog where supported, otherwise via the code) and
  repeats the call with the code. For upstream tools without such a flow, the hub creates its own confirm
  code, bound to the tool and the exact arguments.
- **Upstream tool descriptions are marked `<untrusted>`.** A foreign MCP server could hide instructions
  in a description ("tool poisoning"), so the model is told to read them as data.
- The shared guard does the rest as everywhere: audit of every write (stderr / GELF / syslog), the
  outgoing secret scan on write arguments, the write budget, and masking of the upstream tokens.
- Results are passed on as the upstream returns them. mcp-atlas servers mark text other people wrote;
  other servers may not.

## Notes & scope

- **Untested against live clients and gateways.** Tested against in-process MCP servers only.
- HTTP upstreams only (no stdio upstreams). Each call opens a short connection to its upstream, which
  costs a handshake but keeps no session that could go stale behind a gateway or a container restart.
- Small models do better with fewer tools but need more steps here (search → call). If a model keeps
  filling arguments wrongly, let it call `describe_tool` first, or narrow the catalog with
  `ATLAS_HUB_TOOLS`.
