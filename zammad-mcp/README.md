# zammad-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **[Zammad](https://zammad.org)** helpdesk through its REST API. Ask about your
tickets in natural language — browse/search tickets, read the conversation (articles), look up users
and organizations — and, opt-in, **add notes/comments, update tickets, and create tickets**.

- One shared `httpx.AsyncClient`; **token** auth (`Authorization: Token token=<token>`).
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `ZAMMAD_ALLOW_WRITE` (see below).
- Reads pass `expand=true`, so `*_id` fields come back as names (state, group, owner, customer…).
- A raw escape-hatch tool (`zammad_get`) so any `/api/v1/...` resource stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_tickets(limit?, page?, full?)` | List tickets. |
| `get_ticket(ticket_id, full?)` | One ticket with resolved names. |
| `search_tickets(query, limit?, page?, full?)` | Search tickets (title/number/body + field filters). |
| `get_ticket_articles(ticket_id, limit?, full?)` | A ticket's articles (the conversation/notes). |
| `get_article(article_id, full?)` | One article by id. |
| `list_users(limit?, page?, full?)` | List users. |
| `search_users(query, limit?, full?)` | Search users by name/login/email. |
| `whoami()` | The user behind the token (connectivity/permission check). |
| `list_organizations(limit?, page?, full?)` | List organizations. |
| `list_reference(kind)` | Reference data: `groups`, `states` or `priorities`. |
| `zammad_get(path, params?)` | Escape hatch: raw read-only GET against any `/api/v1/...` path. |

Results are trimmed to useful fields by default (with names from `expand=true`); pass `full=true` for
raw objects, and lists are capped (`ZAMMAD_MAX_ROWS`, default 50; hard cap 200).

### Write tools (opt-in)

These mutate Zammad and only work when **`ZAMMAD_ALLOW_WRITE=true`** (otherwise they refuse with a
clear message). The token also needs **agent** (`ticket.agent`) permission.

| Tool | What it does |
|---|---|
| `add_note(ticket_id, body, internal=true, html=false)` | Add a note to a ticket. `internal=true` (default) is an **agent-only internal comment**; `internal=false` is visible to the customer. Always `type=note`, so it never sends an email. |
| `update_ticket(ticket_id, state?, priority?, group?, owner_id?, title?)` | Update a ticket's fields (state/priority/group by name). |
| `create_ticket(title, group, customer, body, internal?, state?, priority?, html?)` | Create a ticket with an initial note. `customer` is an email or user id (prefix an unknown email with `guess:`). |

## 1. Create an API token

In Zammad: **Profile → Token Access → Create** (an admin must enable *API Token Access* first). For
read-only use, the token's user needs at least agent or customer view rights; for the **write** tools
the token needs **agent** (`ticket.agent`) permission. The token is shown once — that's `ZAMMAD_TOKEN`.

## 2. Configure

```bash
cp .env.example zammad.env
# edit zammad.env: ZAMMAD_BASE_URL, ZAMMAD_TOKEN  (set ZAMMAD_ALLOW_WRITE=true to enable writes)
```

- **`ZAMMAD_BASE_URL`** — e.g. `https://zammad.example.com` (no `/api` suffix).
- **TLS** — for a self-signed / internal-CA instance set `ZAMMAD_CA_BUNDLE`, or (lab only)
  `ZAMMAD_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t zammad-mcp .
claude mcp add zammad -- docker run -i --rm --env-file ./zammad.env zammad-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from zammad.env into your shell first, then:
claude mcp add zammad -- poetry run zammad-mcp
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
- Put the **gateway and the servers on one shared network**, so `http://zammad-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  zammad-mcp:
    build: .
    image: zammad-mcp
    env_file: ./zammad.env
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

With the gateway also on `atlas-net`, register this server at `http://zammad-mcp:8000/mcp`
(`mcpjungle register --name zammad --url http://zammad-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

## 4. Verify

In Claude Code, run `/mcp` to confirm the `zammad` server connected, then ask things like:

- "Search open tickets about VPN and summarise the latest one."
- "Show the conversation on ticket 4521."
- "Who is the customer on ticket 4521?"

With `ZAMMAD_ALLOW_WRITE=true` you can also:

- "Add an internal note to ticket 4521: 'Called the user, awaiting logs.'"
- "Set ticket 4521 to pending reminder and assign it to agent 8."
- "Create a ticket in group Support for alice@example.com titled 'Laptop won't boot'."

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `ZAMMAD_ALLOW_WRITE=true` and the token has agent permission. Leave the flag unset for read-only.
- **No email is sent** by `add_note` (it posts `type=note`). Zammad's quirk where an `internal=true`
  *email* article still sends does **not** apply here — these are notes, not emails. No delete tools.
- **`expand=true`** is always sent on reads so the agent sees names, not just ids. Use `list_reference`
  to map state/priority/group names ↔ ids.
- **`zammad_get`** reaches everything else (roles, tags, overviews, mentions, …).
