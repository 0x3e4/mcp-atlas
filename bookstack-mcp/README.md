# bookstack-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **[BookStack](https://www.bookstackapp.com)** instance through its REST API. Ask
about your documentation in natural language — browse the shelves → books → chapters → pages
hierarchy, read and search page content, and export pages/books to markdown — and, opt-in, **create
and edit pages, chapters, books and shelves, and comment on pages**.

- One shared `httpx.AsyncClient`; **API-token** auth (`Authorization: Token <id>:<secret>`).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `BOOKSTACK_ALLOW_WRITE` (see below).
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

### Write tools (opt-in)

These change BookStack and only work when **`BOOKSTACK_ALLOW_WRITE=true`** (otherwise they refuse
with a clear message). The token's user also needs the matching role permissions (create/update for
the item type; moving needs delete). Results are trimmed to ids, names, tags and a browser `url`.

| Tool | What it does |
|---|---|
| `create_page(name, book_id? \| chapter_id?, markdown? \| html?, tags?, changelog?)` | Create a published page in a book or chapter. |
| `update_page(id, name?, markdown? \| html?, tags?, move_to_book_id? \| move_to_chapter_id?, changelog?)` | Change title/body/tags or move a page. A new body replaces the whole content; BookStack keeps the old one as a revision. |
| `create_chapter(book_id, name, description?, tags?)` | Create a chapter in a book. |
| `update_chapter(id, name?, description?, tags?, move_to_book_id?)` | Rename/describe/tag a chapter, or move it (with its pages) to another book. |
| `create_book(name, description?, tags?)` | Create a book. |
| `update_book(id, name?, description?, tags?)` | Rename/describe/tag a book. |
| `create_shelf(name, description?, book_ids?, tags?)` | Create a shelf, optionally with books on it. |
| `update_shelf(id, name?, description?, add_book_ids?, remove_book_ids?, tags?)` | Rename/describe/tag a shelf, or add/remove books without retyping the rest. |
| `add_comment(page_id, body, html?, reply_to?)` | Comment on a page (plain text by default). Needs a BookStack release with the comments API. |

`tags` is `{name: value}` (`''` for a tag without a value). On the `update_*` tools it **replaces all
tags** of the item; omit it to leave them alone.

**Confirmation before every write** (`BOOKSTACK_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments, so a changed request needs a fresh confirmation (codes also
expire when the server restarts). Set `BOOKSTACK_CONFIRM_WRITE=false` to let writes run directly.

## 1. Create an API token

In BookStack: **your profile → API Tokens → Create Token**. The token's user needs the **"Access
System API"** role permission, and only sees content its permissions allow. You get a **Token ID** and
**Token Secret** (the secret is shown once) — those are `BOOKSTACK_TOKEN_ID` / `BOOKSTACK_TOKEN_SECRET`.
For the **write** tools, give the token's user a role that may create/update the content it should
edit (BookStack has no read-only tokens: the user's role decides).

## 2. Configure

```bash
cp .env.example bookstack.env
# edit bookstack.env: BOOKSTACK_BASE_URL, BOOKSTACK_TOKEN_ID, BOOKSTACK_TOKEN_SECRET
#   (set BOOKSTACK_ALLOW_WRITE=true to enable writes)
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

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
token, or one container per BookStack server.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-bookstack: &bookstack
  image: ghcr.io/0x3e4/bookstack-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  bookstack-mcp:                    # existing shared read-only instance
    <<: *bookstack
    container_name: bookstack-mcp
    env_file: ./bookstack.env

  bookstack-mcp-instance-a:         # write access with instance a's token
    <<: *bookstack
    container_name: bookstack-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's token and `BOOKSTACK_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `BOOKSTACK_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name bookstack --url http://bookstack-mcp:8000/mcp
  mcpjungle register --name bookstack-instance-a --url http://bookstack-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add bookstack-instance-a -- docker run -i --rm --env-file ./env/instance_a.env bookstack-mcp`

## 4. Verify

In Claude Code, run `/mcp` to confirm the `bookstack` server connected, then ask things like:

- "Search the wiki for our backup runbook and summarise it."
- "List the books on the Infrastructure shelf."
- "Show the table of contents of book 12."
- "Read page 134 and explain the deploy steps."
- "Export the 'Onboarding' page as markdown."

With `BOOKSTACK_ALLOW_WRITE=true` you can also:

- "Write a page 'Restore test 2026-10' in the Backups chapter with today's checklist."
- "Fix the typo in the second step of page 134."
- "Create a book 'Network' with chapters 'Firewalls' and 'DNS', and put it on the Infrastructure shelf."
- "Tag page 134 with reviewed=2026-10 and comment that the steps were tested."

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `BOOKSTACK_ALLOW_WRITE=true` and the token's user has the permissions. Leave the flag unset for
  read-only. Page edits are recoverable from the page's revisions. There are no delete tools, and
  attachments/images (multipart uploads) are not covered.
- **Permissions** follow the token's user: content it can't see won't appear, and `users` / `roles` /
  `audit-log` / `recycle-bin` (via `bookstack_get`) need elevated permissions.
- **Large payloads** — page bodies, exports and book `contents` can be big; tools trim by default and
  cap list sizes. Use `content='none'`, `name_contains`, filters and `limit`/`offset` to stay small.
- **`bookstack_get`** reaches everything else: `users`, `roles`, `comments`, `image-gallery`, `tags`,
  `audit-log`, `recycle-bin`, single attachment content (`attachments/{id}`), etc.
