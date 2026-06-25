# bookstack-mcp

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to a **[BookStack](https://www.bookstackapp.com)** instance through its REST
API. Ask about your documentation in natural language — browse the shelves → books → chapters → pages
hierarchy, read and search page content, and export pages/books to markdown.

- One shared `httpx.AsyncClient`; **API-token** auth (`Authorization: Token <id>:<secret>`).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — GET requests only.
- A raw escape-hatch tool (`bookstack_get`) so any `/api/...` resource stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_shelves(name_contains?, limit?, offset?, sort?, full?)` | List bookshelves. |
| `list_books(name_contains?, limit?, offset?, sort?, full?)` | List books. |
| `list_chapters(book_id?, name_contains?, limit?, offset?, sort?, full?)` | List chapters (optionally in one book). |
| `list_pages(book_id?, chapter_id?, name_contains?, limit?, offset?, sort?, full?)` | List pages (metadata only). |
| `get_book(id, full?)` | A book with its chapters/pages table of contents. |
| `get_chapter(id, full?)` | A chapter and its pages outline. |
| `get_page(id, content?, full?)` | A page's metadata + body (`markdown`/`html`/`none`). |
| `search(query, count?, page?)` | Cross-content search (shelves/books/chapters/pages). |
| `export_content(kind, id, format?)` | Export a page/chapter/book as `markdown`/`html`/`plaintext`. |
| `list_attachments(page_id?, limit?, offset?, full?)` | List attachments & links (metadata). |
| `system_info()` | Instance version / name / base URL. |
| `bookstack_get(path, params?)` | Escape hatch: raw read-only GET against any `/api/...` path. |

Results are trimmed to the useful fields by default; pass `full=true` for raw objects, and lists are
capped (`BOOKSTACK_MAX_ROWS`, default 100; BookStack's hard cap is 500). Page bodies and exports can
be large — `get_page` returns one body (markdown by default), `content='none'` for metadata only.

## 1. Create an API token

In BookStack: **your profile → API Tokens → Create Token**. The token's user needs the **"Access
System API"** role permission, and only sees content its permissions allow. You get a **Token ID** and
**Token Secret** (the secret is shown once) — those are `BOOKSTACK_TOKEN_ID` / `BOOKSTACK_TOKEN_SECRET`.

## 2. Configure

```bash
cp .env.example bookstack.env
# edit bookstack.env: BOOKSTACK_BASE_URL, BOOKSTACK_TOKEN_ID, BOOKSTACK_TOKEN_SECRET
```

- **`BOOKSTACK_BASE_URL`** — the instance URL, e.g. `https://docs.example.com` (no `/api` suffix).
- **TLS** — for a self-signed / internal-CA instance set `BOOKSTACK_CA_BUNDLE`, or (lab only)
  `BOOKSTACK_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t bookstack-mcp .
claude mcp add bookstack -- docker run -i --rm --env-file ./bookstack.env bookstack-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from bookstack.env into your shell first, then:
claude mcp add bookstack -- poetry run bookstack-mcp
```

### Always-on HTTP (optional)

Run the server as a long-lived `streamable-http` service instead of per-session stdio.
[`compose.yml`](compose.yml) already sets `MCP_TRANSPORT=streamable-http` and binds `0.0.0.0:8000`:

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

Point any HTTP MCP client at `http://<host>:8000/mcp` (also the only mode remote clients like
OpenAI support). **On localhost this works as-is — nothing else to change.**

#### Behind an MCP gateway (shared Docker network)

A gateway (e.g. [mcpjungle](https://github.com/mcpjungle/MCPJungle)) fronts many servers behind one
endpoint. Running several atlas servers next to a gateway on one host changes two things:

- The published **`8000:8000` host port collides** once more than one server uses it. Drop the host
  port and let the gateway reach the server **by its compose service name** over a shared Docker
  network (or, if you must publish, give each server a distinct host port like `"8001:8000"`).
- Put the **gateway and the servers on one shared network**, so `http://bookstack-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  bookstack-mcp:
    build: .
    image: bookstack-mcp
    env_file: ./bookstack.env
    environment:
      MCP_TRANSPORT: streamable-http
      MCP_HOST: 0.0.0.0
      FASTMCP_HOST: 0.0.0.0
      MCP_PORT: "8000"
    # no `ports:` — only the gateway reaches it, over atlas-net
    networks: [atlas-net]
    restart: unless-stopped

networks:
  atlas-net:
    external: true
```

With the gateway also on `atlas-net`, register this server at `http://bookstack-mcp:8000/mcp`
(`mcpjungle register --name bookstack --url http://bookstack-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

## 4. Verify

In Claude Code, run `/mcp` to confirm the `bookstack` server connected, then ask things like:

- "Search the wiki for our backup runbook and summarise it."
- "List the books on the Infrastructure shelf."
- "Show the table of contents of book 12."
- "Read page 134 and explain the deploy steps."
- "Export the 'Onboarding' page as markdown."

## Notes & scope

- **Read-only.** No write tools in this version. If you want them (create/update pages, books,
  chapters, shelves, attachments), they can be added behind an explicit `BOOKSTACK_ALLOW_WRITE` flag
  and a write-scoped token — same pattern as `azure-devops-mcp`.
- **Permissions** follow the token's user: content it can't see won't appear, and `users` / `roles` /
  `audit-log` / `recycle-bin` (via `bookstack_get`) need elevated permissions.
- **Large payloads** — page bodies, exports and book `contents` can be big; tools trim by default and
  cap list sizes. Use `content='none'`, `name_contains`, filters and `limit`/`offset` to stay small.
- **`bookstack_get`** reaches everything else: `users`, `roles`, `comments`, `image-gallery`, `tags`,
  `audit-log`, `recycle-bin`, single attachment content (`attachments/{id}`), etc.
