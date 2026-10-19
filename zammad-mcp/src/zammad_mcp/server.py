"""FastMCP server exposing Zammad (REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (tickets, articles, users, organizations, reference data) are GET;
the raw ``zammad_get`` escape hatch reaches anything else. Write tools (add a note/comment, update
a ticket, create a ticket, tag a ticket, reply by email) are **opt-in**: they refuse unless ``ZAMMAD_ALLOW_WRITE=true`` and need a
token with agent (ticket.agent) permission. With the flag off the server is effectively read-only.

Reads pass ``expand=true`` so *_id fields come back as human-readable names.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from email.utils import getaddresses
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from . import attachments
from .client import ZammadClient, ZammadError
from .config import ConfigError, Settings

mcp = FastMCP(
    "zammad-mcp",
    instructions=(
        "Write tools need the user's confirmation: the first call changes nothing and returns a preview "
        "with a confirm_code. Show the user a short overview of what will change, end with 'Confirm it?', "
        "and only after they say yes repeat the call with confirm=<code>."
    ),
)

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
            "ticket.agent permission) to enable adding notes / updating / creating / tagging tickets."
        )

# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when ZAMMAD_CONFIRM_WRITE=false, or when ``code`` matches this exact
    tool + change (so what runs is what the user saw).
    """
    if not _get_client().settings.confirm_write:
        return None
    raw = json.dumps([tool, change], sort_keys=True, default=str).encode()
    expected = hmac.new(_CONFIRM_KEY, raw, hashlib.sha256).hexdigest()[:12]
    if code and hmac.compare_digest(code.strip(), expected):
        return None
    out: dict[str, Any] = {
        "status": "confirmation_required",
        "changed": False,
        "summary": summary,
        "change": change,
        "confirm_code": expected,
        "next": (
            "Show the user a short overview of this change and end with 'Confirm it?'. Only after they "
            f"confirm, call {tool} again with the same arguments and confirm='{expected}'."
        ),
    }
    if code:
        out["note"] = "The confirm code did not match these arguments (changed, expired or restarted) — confirm again."
    return out


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

    Each article has 'internal' (agent-only vs customer-visible), 'sender', 'type', 'body' and its
    'attachments' (incl. inline screenshots) — view one with get_attachment.
    """
    out = await _get_list(f"ticket_articles/by_ticket/{ticket_id}", (), limit=limit, full=True)
    if not full:
        out["items"] = [_article(a) for a in out["items"] if isinstance(a, dict)]
    return out


@mcp.tool()
async def get_article(
    article_id: Annotated[int, Field(description="The article id.")],
    full: Annotated[bool, Field(description="Return the full object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get one ticket article by id (GET /ticket_articles/{id}), with its attachment list."""
    data = await _get_client().get(f"ticket_articles/{article_id}", params={"expand": "true"})
    return data if full else _article(data)


def _article(data: dict[str, Any]) -> dict[str, Any]:
    """Trim an article and list its attachments compactly (inline = an image embedded in the body)."""
    out = _pick(data, _ARTICLE_FIELDS)
    out["attachments"] = [
        {
            "id": att.get("id"),
            "filename": att.get("filename"),
            "size": _int(att.get("size")),
            "content_type": (att.get("preferences") or {}).get("Content-Type") or (att.get("preferences") or {}).get("Mime-Type"),
            "inline": bool((att.get("preferences") or {}).get("Content-ID"))
            or "inline" in str((att.get("preferences") or {}).get("Content-Disposition") or "").lower(),
        }
        for att in data.get("attachments") or []
        if isinstance(att, dict)
    ]
    return out


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@mcp.tool()
async def get_attachment(
    ticket_id: Annotated[int, Field(description="The ticket id.")],
    article_id: Annotated[int, Field(description="The article the attachment belongs to.")],
    attachment_id: Annotated[int, Field(description="The attachment id (from get_ticket_articles / get_article → attachments).")],
    part: Annotated[int | None, Field(description="For an e-mail attachment (.eml/.msg): open its N-th own attachment (1-based, see 'attachments' in the first call).", ge=1)] = None,
    pages: Annotated[str | None, Field(description="For a PDF: page range to read, e.g. '3' or '31-60'. Default: the first 30 pages.")] = None,
):
    """Read a ticket attachment (GET /ticket_attachment/{ticket}/{article}/{id}).

    - Images (PNG, JPEG, GIF, WebP, incl. screenshots pasted into a mail) → an image you can look at.
    - PDF → text per page; scanned pages without text are rendered as images (up to 5 per call).
    - E-mails (.eml, Outlook .msg) → headers, body and the mail's own attachments; open one with part=N
      (it goes through the same pipeline, so a PDF or screenshot inside a forwarded mail works too).
    - Text files (logs, CSV, JSON, XML …) → text.
    - Anything else (Office, archives) → metadata only.
    """
    data, content_type, filename = await _get_client().get_file(f"ticket_attachment/{ticket_id}/{article_id}/{attachment_id}")
    content = attachments.read(data, content_type, filename, part=part, pages=pages)
    content[0] = {"ticket_id": ticket_id, "article_id": article_id, "attachment_id": attachment_id, **content[0]}
    return content


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
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
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
    if preview := _confirm("add_note", payload, f"Add {'an internal' if internal else 'a customer-visible'} note to ticket {ticket_id}.", confirm):
        return preview
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
    pending_time: Annotated[str | None, Field(description="When a pending state is due, ISO 8601 (e.g. '2026-10-12T08:00:00Z'). Give it with state 'pending reminder' / 'pending close'.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a ticket's state/priority/group/owner/title (WRITE — requires ZAMMAD_ALLOW_WRITE).

    PUTs /tickets/{id}. State/priority/group accept their names (Zammad resolves them). Pending
    states need a pending_time.
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
    if pending_time is not None:
        payload["pending_time"] = pending_time
    if not payload:
        raise ValueError("Nothing to update: provide state, priority, group, owner_id, title and/or pending_time.")
    if preview := _confirm("update_ticket", {"ticket_id": ticket_id, **payload}, f"Update ticket {ticket_id}: {', '.join(payload)}.", confirm):
        return preview
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
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
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
    if preview := _confirm("create_ticket", payload, f"Create ticket '{title}' in group {group} for {customer}.", confirm):
        return preview
    data = await _get_client().post("tickets", json=payload, params={"expand": "true"})
    return _pick(data, _TICKET_FIELDS)


@mcp.tool()
async def tag_ticket(
    ticket_id: Annotated[int, Field(description="The ticket id.")],
    add: Annotated[list[str] | None, Field(description="Tags to add, e.g. ['vpn', 'escalated'].")] = None,
    remove: Annotated[list[str] | None, Field(description="Tags to remove.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add and/or remove tags on a ticket (WRITE — requires ZAMMAD_ALLOW_WRITE).

    POSTs /tags/add and DELETEs /tags/remove once per tag, then returns the ticket's tags. A tag that
    doesn't exist yet is created, unless the instance only lets admins create new tags.
    """
    _require_write()
    if not add and not remove:
        raise ValueError("Nothing to do: provide add and/or remove.")
    if preview := _confirm("tag_ticket", {"ticket_id": ticket_id, "add": add or [], "remove": remove or []}, f"Tags on ticket {ticket_id}: add {add or []}, remove {remove or []}.", confirm):
        return preview
    client = _get_client()
    for tag in add or ():
        await client.post("tags/add", json={"item": tag, "object": "Ticket", "o_id": ticket_id})
    for tag in remove or ():
        await client.delete("tags/remove", json={"item": tag, "object": "Ticket", "o_id": ticket_id})
    data = await client.get("tags", params={"object": "Ticket", "o_id": ticket_id})
    return {"ticket_id": ticket_id, "tags": data.get("tags", []) if isinstance(data, dict) else data}


def _addresses(line: str | None) -> list[str]:
    """``'"Name" <a@b>, c@d'`` → ``['a@b', 'c@d']`` (lowercased, only entries with an @)."""
    return [addr.strip().strip("'").lower() for _, addr in getaddresses([line or ""]) if "@" in addr]


async def _local_addresses(client: ZammadClient) -> set[str]:
    """Zammad's own sending addresses plus the token user's — never reply to those."""
    local: set[str] = set()
    try:
        for row in await client.get("email_addresses") or []:
            if isinstance(row, dict) and row.get("email"):
                local.add(str(row["email"]).lower())
    except ZammadError:
        pass  # older instances / unusual roles: fall back to the token user's address only
    me = await client.get("users/me")
    if isinstance(me, dict) and me.get("email"):
        local.add(str(me["email"]).lower())
    return local


async def _reply_all_recipients(
    client: ZammadClient, article: dict[str, Any], local: set[str]
) -> tuple[list[str], list[str]]:
    """Zammad's own reply-all recipients for ``article`` (port of App.Utils.getRecipientArticle)."""
    sender_is_local = any(a in local for a in _addresses(article.get("from")))
    recipient_is_local = any(a in local for a in _addresses(article.get("to")))
    if sender_is_local:
        line = article.get("reply_to") or article.get("to")
    else:
        line = None
        if article.get("sender") == "Agent" and not recipient_is_local and article.get("created_by_id"):
            author = await client.get(f"users/{article['created_by_id']}")
            email = str(author.get("email") or "").lower() if isinstance(author, dict) else ""
            if email and email in str(article.get("from") or "").lower():
                line = article.get("to")  # an agent's email sent via Zammad: reply goes to its recipients
        if line is None:
            line = article.get("reply_to") or article.get("from")

    seen: set[str] = set()

    def add(text: str | None) -> list[str]:
        out = [a for a in dict.fromkeys(_addresses(text)) if a not in local and a not in seen]
        seen.update(out)
        return out

    to = add(line) + add(article.get("from")) + add(article.get("to"))
    return to, add(article.get("cc"))


@mcp.tool()
async def reply_email(
    ticket_id: Annotated[int, Field(description="The ticket to reply on.")],
    body: Annotated[str, Field(description="The email text (plain text unless html=true). Zammad does not add the group signature for API articles — include a greeting/signature if wanted.", min_length=1)],
    recipients: Annotated[str, Field(description="'customer' = email only the ticket's customer (the creator); 'all' = reply to all on the last email (its sender, To and Cc, minus Zammad's own addresses).")] = "customer",
    article_id: Annotated[int | None, Field(description="Reply to this article instead of the ticket's last email (threading, and the recipient source for 'all').")] = None,
    cc: Annotated[list[str] | None, Field(description="Extra Cc addresses.")] = None,
    subject: Annotated[str | None, Field(description="Subject override. Default: the replied-to email's subject, else the ticket title (Zammad adds 'RE:' and the ticket number).")] = None,
    html: Annotated[bool, Field(description="Treat body as HTML (content_type text/html) instead of plain text.")] = False,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Send an email reply on a ticket (WRITE — requires ZAMMAD_ALLOW_WRITE). This sends a real email.

    POSTs a ``type=email`` article (never internal) that Zammad sends through the group's email
    channel, threaded to the replied-to email. recipients='customer' writes to the ticket's
    customer; recipients='all' works like the "reply all" button on the last email. The preview
    shows the resolved To/Cc/subject before anything is sent.
    """
    _require_write()
    mode = (recipients or "").strip().lower()
    if mode not in ("customer", "all"):
        raise ValueError("recipients must be 'customer' or 'all'.")
    client = _get_client()
    ticket = await client.get(f"tickets/{ticket_id}")

    if article_id is not None:
        source = await client.get(f"ticket_articles/{article_id}", params={"expand": "true"})
        if not isinstance(source, dict) or source.get("ticket_id") != ticket_id:
            raise ValueError(f"Article {article_id} does not belong to ticket {ticket_id}.")
    else:
        articles = await client.get(f"ticket_articles/by_ticket/{ticket_id}", params={"expand": "true"})
        emails = [
            a for a in articles or []
            if isinstance(a, dict) and a.get("type") in ("email", "web") and not a.get("internal")
        ]
        source = max(emails, key=lambda a: a.get("id") or 0) if emails else None

    local = await _local_addresses(client)
    if mode == "all":
        if source is None:
            raise ValueError(f"Ticket {ticket_id} has no email to reply to all on — use recipients='customer'.")
        to, cc_list = await _reply_all_recipients(client, source, local)
    else:
        customer = await client.get(f"users/{ticket.get('customer_id')}")
        email = str(customer.get("email") or "").strip() if isinstance(customer, dict) else ""
        if "@" not in email:
            raise ValueError(f"The customer of ticket {ticket_id} has no email address.")
        to, cc_list = [email.lower()], []
    cc_list += [a for a in dict.fromkeys(_addresses(", ".join(cc or ()))) if a not in to and a not in cc_list]
    if not to:
        raise ValueError("No recipients left after removing Zammad's own addresses — give article_id or use recipients='customer'.")

    payload: dict[str, Any] = {
        "ticket_id": ticket_id,
        "type": "email",
        "internal": False,  # internal=true on an email article would still send it
        "sender": "Agent",
        "to": ", ".join(to),
        "subject": subject or (source or {}).get("subject") or ticket.get("title") or "",
        "body": body,
        "content_type": "text/html" if html else "text/plain",
        "subtype": "reply",
    }
    if cc_list:
        payload["cc"] = ", ".join(cc_list)
    if source and source.get("message_id"):
        payload["in_reply_to"] = source["message_id"]
    summary = f"Send an email on ticket {ticket_id} to {payload['to']}"
    summary += f" (cc {payload['cc']})" if cc_list else ""
    summary += f", subject '{payload['subject']}'."
    if preview := _confirm("reply_email", payload, summary, confirm):
        return preview
    data = await client.post("ticket_articles", json=payload)
    return _pick(data, ("id", "ticket_id", "type", "internal", "to", "cc", "subject", "created_at"))


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
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
