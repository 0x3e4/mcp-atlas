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

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

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
