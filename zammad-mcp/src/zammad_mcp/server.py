"""FastMCP server exposing Zammad (REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (tickets, articles, users, organizations, reference data) are GET;
the raw ``zammad_get`` escape hatch reaches anything else. Write tools (add a note/comment, update
a ticket, create a ticket) are **opt-in**: they refuse unless ``ZAMMAD_ALLOW_WRITE=true`` and need a
token with agent (ticket.agent) permission. With the flag off the server is effectively read-only.

Reads pass ``expand=true`` so *_id fields come back as human-readable names.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .client import ZammadClient
from .config import ConfigError, Settings

mcp = FastMCP("zammad-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: ZammadClient | None = None


def _get_client() -> ZammadClient:
    global _client
    if _client is None:
        _client = ZammadClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in ZAMMAD_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set ZAMMAD_ALLOW_WRITE=true (and use a token with "
            "ticket.agent permission) to enable adding notes / updating / creating tickets."
        )


# ---- curated field projections (expand=true resolves the *_id names) -----
_TICKET_FIELDS = (
    "id", "number", "title", "state", "priority", "group", "owner", "customer", "organization",
    "created_at", "updated_at",
)
_ARTICLE_FIELDS = (
    "id", "ticket_id", "type", "sender", "internal", "from", "to", "subject", "body",
    "content_type", "created_by", "created_at",
)
_USER_FIELDS = ("id", "login", "firstname", "lastname", "email", "organization", "active")
_ORG_FIELDS = ("id", "name", "domain", "shared", "active")
_REFERENCE = {
    "groups": ("groups", ("id", "name", "active", "note")),
    "states": ("ticket_states", ("id", "name", "state_type_id", "active")),
    "priorities": ("ticket_priorities", ("id", "name", "active", "default_create")),
}


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 200) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {f: obj.get(f) for f in fields} if isinstance(obj, dict) else {}


async def _get_list(
    path: str,
    fields: tuple[str, ...],
    *,
    params: dict[str, Any] | None = None,
    limit: int = 50,
    page: int = 1,
    full: bool = False,
) -> dict[str, Any]:
    """GET a list endpoint with expand=true, project to ``fields`` (unless ``full``), and cap."""
    q: dict[str, Any] = {"expand": "true", "per_page": _clamp(limit), "page": page}
    if params:
        q.update(params)
    data = await _get_client().get(path, params=q)
    rows = data if isinstance(data, list) else ([data] if data else [])
    if not full:
        rows = [_pick(r, fields) for r in rows if isinstance(r, dict)]
    return {"count": len(rows), "items": rows}


# ---- tools: tickets -----------------------------------------------------

@mcp.tool()
async def list_tickets(
    limit: Annotated[int, Field(description="Max tickets to return.", ge=1, le=200)] = 25,
    page: Annotated[int, Field(description="Page number (1-based).", ge=1)] = 1,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List tickets, newest by id (GET /tickets). Use search_tickets to filter by state/owner/etc."""
    return await _get_list("tickets", _TICKET_FIELDS, limit=limit, page=page, full=full)


@mcp.tool()
async def get_ticket(
    ticket_id: Annotated[int, Field(description="The ticket id.")],
    full: Annotated[bool, Field(description="Return the full object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get one ticket with resolved names (GET /tickets/{id}?expand=true)."""
    data = await _get_client().get(f"tickets/{ticket_id}", params={"expand": "true"})
    return data if full else _pick(data, _TICKET_FIELDS)


@mcp.tool()
async def search_tickets(
    query: Annotated[str, Field(description="Search query; supports Zammad search syntax, e.g. 'state.name:open priority.name:\"3 high\"' or free text.")],
    limit: Annotated[int, Field(description="Max tickets to return.", ge=1, le=200)] = 25,
    page: Annotated[int, Field(description="Page number (1-based).", ge=1)] = 1,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Search tickets (GET /tickets/search) — by title/number/body and field filters."""
    return await _get_list("tickets/search", _TICKET_FIELDS, params={"query": query}, limit=limit, page=page, full=full)


@mcp.tool()
async def get_ticket_articles(
    ticket_id: Annotated[int, Field(description="The ticket id.")],
    limit: Annotated[int, Field(description="Max articles to return.", ge=1, le=200)] = 50,
    full: Annotated[bool, Field(description="Return full objects (attachments, raw fields) instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get a ticket's articles — the conversation/notes (GET /ticket_articles/by_ticket/{id}).

    Each article has 'internal' (agent-only vs customer-visible), 'sender', 'type' and 'body'.
    """
    return await _get_list(f"ticket_articles/by_ticket/{ticket_id}", _ARTICLE_FIELDS, limit=limit, full=full)


@mcp.tool()
async def get_article(
    article_id: Annotated[int, Field(description="The article id.")],
    full: Annotated[bool, Field(description="Return the full object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get one ticket article by id (GET /ticket_articles/{id})."""
    data = await _get_client().get(f"ticket_articles/{article_id}", params={"expand": "true"})
    return data if full else _pick(data, _ARTICLE_FIELDS)


# ---- tools: users & orgs ------------------------------------------------

@mcp.tool()
async def list_users(
    limit: Annotated[int, Field(description="Max users to return.", ge=1, le=200)] = 50,
    page: Annotated[int, Field(description="Page number (1-based).", ge=1)] = 1,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List users (GET /users). Requires agent/admin permission."""
    return await _get_list("users", _USER_FIELDS, limit=limit, page=page, full=full)


@mcp.tool()
async def search_users(
    query: Annotated[str, Field(description="Search by name, login or email.")],
    limit: Annotated[int, Field(description="Max users to return.", ge=1, le=200)] = 25,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Search users (GET /users/search)."""
    return await _get_list("users/search", _USER_FIELDS, params={"query": query}, limit=limit, full=full)


@mcp.tool()
async def whoami() -> dict[str, Any]:
    """The authenticated user behind the token (GET /users/me) — a quick connectivity/permission check."""
    data = await _get_client().get("users/me", params={"expand": "true"})
    return _pick(data, ("id", "login", "firstname", "lastname", "email", "roles", "organization", "active"))


@mcp.tool()
async def list_organizations(
    limit: Annotated[int, Field(description="Max organizations to return.", ge=1, le=200)] = 50,
    page: Annotated[int, Field(description="Page number (1-based).", ge=1)] = 1,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List organizations (GET /organizations)."""
    return await _get_list("organizations", _ORG_FIELDS, limit=limit, page=page, full=full)


@mcp.tool()
async def list_reference(
    kind: Annotated[str, Field(description="Which reference data: 'groups', 'states' or 'priorities'.")],
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List reference data needed to interpret/update tickets: groups, ticket states, or priorities."""
    key = (kind or "").strip().lower()
    if key not in _REFERENCE:
        raise ValueError(f"kind must be one of {tuple(_REFERENCE)}; got {kind!r}.")
    path, fields = _REFERENCE[key]
    return await _get_list(path, fields, limit=200, full=full)


# ---- tool: raw escape hatch ---------------------------------------------

@mcp.tool()
async def zammad_get(
    path: Annotated[str, Field(description="API path relative to /api/v1, e.g. 'tickets/12', 'roles', 'tags'.")],
    params: Annotated[dict[str, Any] | None, Field(description="Query params, e.g. {\"expand\": \"true\", \"per_page\": 10}.")] = None,
) -> Any:
    """Escape hatch: raw read-only GET against any Zammad ``/api/v1/...`` resource."""
    data = await _get_client().get_raw(path, params=params)
    return data if isinstance(data, (dict, list)) else {"data": data}


# ---- tools: writes (opt-in, gated by ZAMMAD_ALLOW_WRITE) -----------------

@mcp.tool()
async def add_note(
    ticket_id: Annotated[int, Field(description="The ticket to add the note to.")],
    body: Annotated[str, Field(description="The note text.")],
    internal: Annotated[bool, Field(description="True = internal (agent-only) note; False = note visible to the customer.")] = True,
    html: Annotated[bool, Field(description="Treat body as HTML (content_type text/html) instead of plain text.")] = False,
) -> dict[str, Any]:
    """Add a note/comment to a ticket (WRITE — requires ZAMMAD_ALLOW_WRITE).

    Posts a ``type=note`` article. internal=true (default) is an agent-only internal comment;
    internal=false makes it visible to the customer. This never sends an email (type=note), so it is
    safe from the Zammad 'internal email still sends' footgun.
    """
    _require_write()
    payload = {
        "ticket_id": ticket_id,
        "body": body,
        "type": "note",
        "internal": internal,
        "sender": "Agent",
        "content_type": "text/html" if html else "text/plain",
    }
    data = await _get_client().post("ticket_articles", json=payload)
    return _pick(data, ("id", "ticket_id", "type", "internal", "sender", "created_at"))


@mcp.tool()
async def update_ticket(
    ticket_id: Annotated[int, Field(description="The ticket id to update.")],
    state: Annotated[str | None, Field(description="New state name, e.g. 'open', 'closed', 'pending reminder'.")] = None,
    priority: Annotated[str | None, Field(description="New priority name, e.g. '1 low', '2 normal', '3 high'.")] = None,
    group: Annotated[str | None, Field(description="New group name.")] = None,
    owner_id: Annotated[int | None, Field(description="New owner (agent) user id.")] = None,
    title: Annotated[str | None, Field(description="New title.")] = None,
) -> dict[str, Any]:
    """Update a ticket's state/priority/group/owner/title (WRITE — requires ZAMMAD_ALLOW_WRITE).

    PUTs /tickets/{id}. State/priority/group accept their names (Zammad resolves them).
    """
    _require_write()
    payload: dict[str, Any] = {}
    if state is not None:
        payload["state"] = state
    if priority is not None:
        payload["priority"] = priority
    if group is not None:
        payload["group"] = group
    if owner_id is not None:
        payload["owner_id"] = owner_id
    if title is not None:
        payload["title"] = title
    if not payload:
        raise ValueError("Nothing to update: provide state, priority, group, owner_id and/or title.")
    data = await _get_client().put(f"tickets/{ticket_id}", json=payload, params={"expand": "true"})
    return _pick(data, _TICKET_FIELDS)


@mcp.tool()
async def create_ticket(
    title: Annotated[str, Field(description="Ticket title/subject.")],
    group: Annotated[str, Field(description="Group name to file the ticket under, e.g. 'Users' or 'Support'.")],
    customer: Annotated[str, Field(description="Customer email or user id. Prefix an unknown email with 'guess:' to auto-create the user.")],
    body: Annotated[str, Field(description="The first article's text.")],
    internal: Annotated[bool, Field(description="Make the first article internal (agent-only). Default False (visible to customer).")] = False,
    state: Annotated[str | None, Field(description="Initial state name (optional, e.g. 'new', 'open').")] = None,
    priority: Annotated[str | None, Field(description="Initial priority name (optional).")] = None,
    html: Annotated[bool, Field(description="Treat body as HTML instead of plain text.")] = False,
) -> dict[str, Any]:
    """Create a ticket with an initial note (WRITE — requires ZAMMAD_ALLOW_WRITE).

    POSTs /tickets with an inline article. 'customer' is an email or user id.
    """
    _require_write()
    article = {
        "body": body,
        "type": "note",
        "internal": internal,
        "content_type": "text/html" if html else "text/plain",
    }
    payload: dict[str, Any] = {"title": title, "group": group, "customer": customer, "article": article}
    if state is not None:
        payload["state"] = state
    if priority is not None:
        payload["priority"] = priority
    data = await _get_client().post("tickets", json=payload, params={"expand": "true"})
    return _pick(data, _TICKET_FIELDS)


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"zammad-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = ZammadClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
