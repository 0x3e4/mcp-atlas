"""FastMCP server exposing BookStack (REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (GET) cover the content hierarchy (shelves → books → chapters →
pages), search, export and attachments; the raw ``bookstack_get`` escape hatch reaches anything else
(users, roles, comments, image-gallery, audit-log, …). Write tools (create/update pages, chapters,
books and shelves, comment on a page) are **opt-in**: they refuse unless ``BOOKSTACK_ALLOW_WRITE=true``
and need a token whose user has the matching permissions. With the flag off the server is read-only.
Unless ``BOOKSTACK_CONFIRM_WRITE=false``, every write first returns a preview plus a confirm code and
only runs when called again with that code, after the user has confirmed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from html import escape
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import BookStackClient
from .config import ConfigError, Settings

mcp = FastMCP(
    "bookstack-mcp",
    instructions=(
        "Write tools (create_*/update_*/add_comment) need the user's confirmation: the first call changes "
        "nothing and returns a preview with a confirm_code. Show the user a short overview of what will "
        "change, end with 'Confirm it?', and only after they say yes repeat the call with confirm=<code>."
    ),
)

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: BookStackClient | None = None


def _get_client() -> BookStackClient:
    global _client
    if _client is None:
        _client = BookStackClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in BOOKSTACK_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set BOOKSTACK_ALLOW_WRITE=true (and use a token whose user has "
            "the matching create/update permissions) to create or edit pages, chapters, books and shelves."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when BOOKSTACK_CONFIRM_WRITE=false, or when ``code`` matches this exact
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


# ---- curated field projections ------------------------------------------
_SHELF_FIELDS = ("id", "name", "slug", "description", "created_at", "updated_at")
_BOOK_FIELDS = ("id", "name", "slug", "description", "created_at", "updated_at")
_CHAPTER_FIELDS = ("id", "book_id", "name", "slug", "description", "priority", "updated_at")
_PAGE_FIELDS = (
    "id", "book_id", "chapter_id", "name", "slug", "priority", "draft", "template",
    "created_at", "updated_at",
)
_ATTACHMENT_FIELDS = ("id", "name", "extension", "external", "uploaded_to", "order", "updated_at")
_BOOK_DETAIL_FIELDS = ("id", "name", "slug", "description", "tags", "created_at", "updated_at", "contents")
_CHAPTER_DETAIL_FIELDS = ("id", "book_id", "name", "slug", "description", "priority", "tags", "pages")
_PAGE_DETAIL_FIELDS = (
    "id", "book_id", "chapter_id", "name", "slug", "draft", "template", "tags",
    "created_by", "owned_by", "created_at", "updated_at",
)
# kind -> fields kept from a create/update response (write responses carry full bodies)
_WRITE_FIELDS = {
    "page": ("id", "book_id", "chapter_id", "name", "slug", "draft", "revision_count", "tags", "updated_at"),
    "chapter": ("id", "book_id", "name", "slug", "description", "tags", "updated_at"),
    "book": ("id", "name", "slug", "description", "tags", "updated_at"),
    "shelf": ("id", "name", "slug", "description", "tags", "updated_at"),
}
_COMMENT_FIELDS = ("id", "local_id", "commentable_id", "parent_id", "created_at")


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 500) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Project a dict down to ``fields`` (supports dotted paths like ``a.b.c``)."""
    out: dict[str, Any] = {}
    for field in fields:
        cur: Any = obj
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        out[field] = cur
    return out


async def _get_list(
    path: str,
    fields: tuple[str, ...],
    *,
    limit: int = 50,
    offset: int = 0,
    sort: str | None = None,
    name_contains: str | None = None,
    extra_filters: dict[str, Any] | None = None,
    full: bool = False,
) -> dict[str, Any]:
    """List a BookStack resource (``{data, total}`` envelope), projecting and capping results."""
    params: dict[str, Any] = {"count": _clamp(limit)}
    if offset:
        params["offset"] = offset
    if sort:
        params["sort"] = sort
    if name_contains:
        params["filter[name:like]"] = f"%{name_contains}%"
    for key, value in (extra_filters or {}).items():
        if value is not None:
            params[f"filter[{key}]"] = value
    data = await _get_client().get(path, params=params)
    rows = data.get("data", []) if isinstance(data, dict) else (data or [])
    total = data.get("total") if isinstance(data, dict) else None
    if not full:
        rows = [_pick(r, fields) if isinstance(r, dict) else r for r in rows]
    return {"total": total, "count": len(rows), "data": rows}


def _fields(**values: Any) -> dict[str, Any]:
    """Drop unset (None) fields so a write only sends — and a PUT only changes — what was given."""
    return {k: v for k, v in values.items() if v is not None}


def _tags(tags: dict[str, str] | None) -> list[dict[str, str]] | None:
    """``{name: value}`` → BookStack's ``[{name, value}]`` tag list (``''`` = a tag without a value)."""
    if tags is None:
        return None
    return [{"name": name, "value": "" if value is None else str(value)} for name, value in tags.items()]


def _text_html(text: str) -> str:
    """Plain text → escaped HTML paragraphs (blank line = new paragraph, newline = ``<br>``)."""
    paragraphs = [p.strip() for p in text.replace("\r\n", "\n").split("\n\n") if p.strip()]
    return "".join("<p>" + escape(p).replace("\n", "<br>") + "</p>" for p in paragraphs)


def _written(kind: str, data: Any) -> dict[str, Any]:
    """Trim a create/update response to the key fields plus the item's browser URL."""
    if not isinstance(data, dict):
        return {"result": data}
    out = _pick(data, _WRITE_FIELDS[kind])
    base = _get_client().settings.base_url
    out["url"] = {
        "page": f"{base}/link/{data.get('id')}",  # BookStack's page permalink
        "chapter": f"{base}/books/{data.get('book_slug')}/chapter/{data.get('slug')}",
        "book": f"{base}/books/{data.get('slug')}",
        "shelf": f"{base}/shelves/{data.get('slug')}",
    }[kind]
    return out


# ---- tools: content hierarchy (list) ------------------------------------

@mcp.tool()
async def list_shelves(
    name_contains: Annotated[str | None, Field(description="Filter to shelves whose name contains this text.")] = None,
    limit: Annotated[int, Field(description="Max shelves to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    sort: Annotated[str | None, Field(description="Sort, e.g. '+name' or '-updated_at'.")] = None,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List bookshelves (GET /api/shelves)."""
    return await _get_list("shelves", _SHELF_FIELDS, limit=limit, offset=offset, sort=sort, name_contains=name_contains, full=full)


@mcp.tool()
async def list_books(
    name_contains: Annotated[str | None, Field(description="Filter to books whose name contains this text.")] = None,
    limit: Annotated[int, Field(description="Max books to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    sort: Annotated[str | None, Field(description="Sort, e.g. '+name' or '-updated_at'.")] = None,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List books (GET /api/books)."""
    return await _get_list("books", _BOOK_FIELDS, limit=limit, offset=offset, sort=sort, name_contains=name_contains, full=full)


@mcp.tool()
async def list_chapters(
    book_id: Annotated[int | None, Field(description="Filter to chapters in this book id.")] = None,
    name_contains: Annotated[str | None, Field(description="Filter to chapters whose name contains this text.")] = None,
    limit: Annotated[int, Field(description="Max chapters to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    sort: Annotated[str | None, Field(description="Sort, e.g. '+priority' or '-updated_at'.")] = None,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List chapters (GET /api/chapters), optionally filtered to one book."""
    return await _get_list(
        "chapters", _CHAPTER_FIELDS, limit=limit, offset=offset, sort=sort,
        name_contains=name_contains, extra_filters={"book_id": book_id}, full=full,
    )


@mcp.tool()
async def list_pages(
    book_id: Annotated[int | None, Field(description="Filter to pages in this book id.")] = None,
    chapter_id: Annotated[int | None, Field(description="Filter to pages in this chapter id.")] = None,
    name_contains: Annotated[str | None, Field(description="Filter to pages whose name contains this text.")] = None,
    limit: Annotated[int, Field(description="Max pages to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    sort: Annotated[str | None, Field(description="Sort, e.g. '+name' or '-updated_at'.")] = None,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List pages (GET /api/pages) — metadata only; use get_page for content.

    Optionally filter to a book and/or chapter.
    """
    return await _get_list(
        "pages", _PAGE_FIELDS, limit=limit, offset=offset, sort=sort, name_contains=name_contains,
        extra_filters={"book_id": book_id, "chapter_id": chapter_id}, full=full,
    )


# ---- tools: content hierarchy (single, with content) --------------------

@mcp.tool()
async def get_book(
    id: Annotated[int, Field(description="Book id.")],
    full: Annotated[bool, Field(description="Return the full object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get a book with its table of contents (GET /api/books/{id}) — chapters and pages outline."""
    data = await _get_client().get(f"books/{id}")
    return data if full else _pick(data, _BOOK_DETAIL_FIELDS)


@mcp.tool()
async def get_chapter(
    id: Annotated[int, Field(description="Chapter id.")],
    full: Annotated[bool, Field(description="Return the full object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get a chapter and its pages outline (GET /api/chapters/{id})."""
    data = await _get_client().get(f"chapters/{id}")
    return data if full else _pick(data, _CHAPTER_DETAIL_FIELDS)


@mcp.tool()
async def get_page(
    id: Annotated[int, Field(description="Page id.")],
    content: Annotated[str, Field(description="Which body to include: 'markdown', 'html', or 'none'.")] = "markdown",
    full: Annotated[bool, Field(description="Return the full raw object (all bodies, comments, …).")] = False,
) -> dict[str, Any]:
    """Get a page with its content (GET /api/pages/{id}).

    By default returns the page metadata plus one body (markdown if the page has it, else html).
    Set content='none' for metadata only, or full=true for the complete raw object.
    """
    if content not in ("markdown", "html", "none"):
        raise ValueError("content must be one of: markdown, html, none.")
    data = await _get_client().get(f"pages/{id}")
    if full:
        return data
    out = _pick(data, _PAGE_DETAIL_FIELDS)
    if content == "markdown":
        out["content"] = data.get("markdown") or data.get("html") or ""
    elif content == "html":
        out["content"] = data.get("html") or ""
    return out


# ---- tools: search & export ---------------------------------------------

@mcp.tool()
async def search(
    query: Annotated[str, Field(description="Search query; supports BookStack syntax, e.g. 'backups {type:page}' or '{updated_after:2024-01-01}'.")],
    count: Annotated[int, Field(description="Max results.", ge=1, le=100)] = 20,
    page: Annotated[int, Field(description="Result page (1-based).", ge=1)] = 1,
) -> dict[str, Any]:
    """Search across all content (GET /api/search) — shelves, books, chapters and pages."""
    data = await _get_client().get("search", params={"query": query, "count": _clamp(count, 20, 100), "page": page})
    rows = data.get("data", []) if isinstance(data, dict) else []
    results = [
        {
            "type": r.get("type"),
            "id": r.get("id"),
            "name": r.get("name"),
            "url": r.get("url"),
            "book": (r.get("book") or {}).get("name"),
            "chapter": (r.get("chapter") or {}).get("name"),
            "preview": (r.get("preview_html") or {}).get("content"),
        }
        for r in rows
        if isinstance(r, dict)
    ]
    return {"total": data.get("total") if isinstance(data, dict) else None, "count": len(results), "results": results}


@mcp.tool()
async def export_content(
    kind: Annotated[str, Field(description="What to export: 'page', 'chapter' or 'book'.")],
    id: Annotated[int, Field(description="The id of the page/chapter/book.")],
    format: Annotated[str, Field(description="Text format: 'markdown', 'html' or 'plaintext'. (PDF/ZIP are binary — use the BookStack UI.)")] = "markdown",
) -> dict[str, Any]:
    """Export a page, chapter or book as text (GET /api/{kind}s/{id}/export/{format})."""
    if kind not in ("page", "chapter", "book"):
        raise ValueError("kind must be one of: page, chapter, book.")
    if format not in ("markdown", "html", "plaintext"):
        raise ValueError("format must be one of: markdown, html, plaintext (pdf/zip are binary).")
    text = await _get_client().get_text(f"{kind}s/{id}/export/{format}")
    return {"kind": kind, "id": id, "format": format, "content": text}


# ---- tools: attachments -------------------------------------------------

@mcp.tool()
async def list_attachments(
    page_id: Annotated[int | None, Field(description="Filter to attachments uploaded to this page id.")] = None,
    limit: Annotated[int, Field(description="Max attachments to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List attachments and links (GET /api/attachments). 'external'=true means a link, not a file.

    Metadata only — fetch a single attachment's content via bookstack_get('attachments/{id}').
    """
    return await _get_list(
        "attachments", _ATTACHMENT_FIELDS, limit=limit, offset=offset,
        extra_filters={"uploaded_to": page_id}, full=full,
    )


# ---- tools: system & escape hatch ---------------------------------------

@mcp.tool()
async def system_info() -> dict[str, Any]:
    """BookStack instance info (GET /api/system) — version, app name, base URL."""
    return await _get_client().get("system")


@mcp.tool()
async def bookstack_get(
    path: Annotated[str, Field(description="API path relative to /api, e.g. 'users', 'roles', 'comments', 'image-gallery', 'audit-log', or 'pages/12'.")],
    params: Annotated[dict[str, Any] | None, Field(description="Optional query params, e.g. {\"count\": 10, \"filter[name:like]\": \"%infra%\"}.")] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only GET against any BookStack ``/api/...`` resource.

    Use for resources without a dedicated tool (users, roles, comments, image-gallery, tags,
    audit-log, recycle-bin — some need elevated permissions). Returns the raw JSON.
    """
    data = await _get_client().get_raw(path, params=params)
    return data if isinstance(data, dict) else {"data": data}


# ---- tools: writes (opt-in, gated by BOOKSTACK_ALLOW_WRITE) --------------

@mcp.tool()
async def create_page(
    name: Annotated[str, Field(description="Page title.", min_length=1, max_length=255)],
    book_id: Annotated[int | None, Field(description="Book to create the page in (top level). Give this or chapter_id.")] = None,
    chapter_id: Annotated[int | None, Field(description="Chapter to create the page in. Wins over book_id if both are given.")] = None,
    markdown: Annotated[str | None, Field(description="Page body as markdown (the page then uses the markdown editor). Give this or html.")] = None,
    html: Annotated[str | None, Field(description="Page body as HTML. Give this or markdown.")] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Tags as {name: value}; use '' for a tag without a value.")] = None,
    changelog: Annotated[str | None, Field(description="Revision note for the page history.", min_length=1, max_length=180)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a page in a book or chapter (WRITE — requires BOOKSTACK_ALLOW_WRITE). POSTs /api/pages.

    The page is published straight away (no draft). Returns its id and URL.
    """
    _require_write()
    if book_id is None and chapter_id is None:
        raise ValueError("Give book_id or chapter_id for the new page.")
    if (markdown is None) == (html is None):
        raise ValueError("Give exactly one body: markdown or html.")
    payload = _fields(
        name=name, book_id=book_id, chapter_id=chapter_id, markdown=markdown, html=html,
        tags=_tags(tags), changelog=changelog,
    )
    where = f"chapter {chapter_id}" if chapter_id is not None else f"book {book_id}"
    if preview := _confirm("create_page", payload, f"Create page '{name}' in {where}.", confirm):
        return preview
    return _written("page", await _get_client().post("pages", json=payload))


@mcp.tool()
async def update_page(
    id: Annotated[int, Field(description="Page id.")],
    name: Annotated[str | None, Field(description="New title.", min_length=1, max_length=255)] = None,
    markdown: Annotated[str | None, Field(description="New body as markdown — replaces the whole page content.")] = None,
    html: Annotated[str | None, Field(description="New body as HTML — replaces the whole page content.")] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Replaces ALL tags: {name: value} ('' = no value), {} clears them. Omit to keep the current tags.")] = None,
    move_to_book_id: Annotated[int | None, Field(description="Move the page to the top level of this book.")] = None,
    move_to_chapter_id: Annotated[int | None, Field(description="Move the page into this chapter.")] = None,
    changelog: Annotated[str | None, Field(description="Revision note for the page history.", min_length=1, max_length=180)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a page's title, body or tags, or move it (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    PUTs /api/pages/{id}; only the fields you give change. A new body replaces the whole content
    (read it with get_page first to edit in place); BookStack keeps the old version as a revision.
    Moving needs delete permission on the page.
    """
    _require_write()
    if markdown is not None and html is not None:
        raise ValueError("Give one body: markdown or html, not both.")
    if move_to_book_id is not None and move_to_chapter_id is not None:
        raise ValueError("Move to a book or to a chapter, not both.")
    payload = _fields(
        name=name, markdown=markdown, html=html, tags=_tags(tags),
        book_id=move_to_book_id, chapter_id=move_to_chapter_id, changelog=changelog,
    )
    if not payload.keys() - {"changelog"}:
        raise ValueError("Nothing to update: provide name, markdown/html, tags or a move target.")
    if preview := _confirm("update_page", {"id": id, **payload}, f"Update page {id}: {', '.join(payload)}.", confirm):
        return preview
    return _written("page", await _get_client().put(f"pages/{id}", json=payload))


@mcp.tool()
async def create_chapter(
    book_id: Annotated[int, Field(description="Book to create the chapter in.")],
    name: Annotated[str, Field(description="Chapter name.", min_length=1, max_length=255)],
    description: Annotated[str | None, Field(description="Plain-text description.", max_length=1900)] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Tags as {name: value}; use '' for a tag without a value.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a chapter in a book (WRITE — requires BOOKSTACK_ALLOW_WRITE). POSTs /api/chapters."""
    _require_write()
    payload = _fields(book_id=book_id, name=name, description=description, tags=_tags(tags))
    if preview := _confirm("create_chapter", payload, f"Create chapter '{name}' in book {book_id}.", confirm):
        return preview
    return _written("chapter", await _get_client().post("chapters", json=payload))


@mcp.tool()
async def update_chapter(
    id: Annotated[int, Field(description="Chapter id.")],
    name: Annotated[str | None, Field(description="New name.", min_length=1, max_length=255)] = None,
    description: Annotated[str | None, Field(description="New plain-text description.", max_length=1900)] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Replaces ALL tags: {name: value} ('' = no value), {} clears them. Omit to keep the current tags.")] = None,
    move_to_book_id: Annotated[int | None, Field(description="Move the chapter (with its pages) to this book.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a chapter's name, description or tags, or move it (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    PUTs /api/chapters/{id}; only the fields you give change. Moving needs delete permission.
    """
    _require_write()
    payload = _fields(name=name, description=description, tags=_tags(tags), book_id=move_to_book_id)
    if not payload:
        raise ValueError("Nothing to update: provide name, description, tags or move_to_book_id.")
    if preview := _confirm("update_chapter", {"id": id, **payload}, f"Update chapter {id}: {', '.join(payload)}.", confirm):
        return preview
    return _written("chapter", await _get_client().put(f"chapters/{id}", json=payload))


@mcp.tool()
async def create_book(
    name: Annotated[str, Field(description="Book name.", min_length=1, max_length=255)],
    description: Annotated[str | None, Field(description="Plain-text description.", max_length=1900)] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Tags as {name: value}; use '' for a tag without a value.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a book (WRITE — requires BOOKSTACK_ALLOW_WRITE). POSTs /api/books.

    New books sit on no shelf; use update_shelf(add_book_ids=[...]) to place one.
    """
    _require_write()
    payload = _fields(name=name, description=description, tags=_tags(tags))
    if preview := _confirm("create_book", payload, f"Create book '{name}'.", confirm):
        return preview
    return _written("book", await _get_client().post("books", json=payload))


@mcp.tool()
async def update_book(
    id: Annotated[int, Field(description="Book id.")],
    name: Annotated[str | None, Field(description="New name.", min_length=1, max_length=255)] = None,
    description: Annotated[str | None, Field(description="New plain-text description.", max_length=1900)] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Replaces ALL tags: {name: value} ('' = no value), {} clears them. Omit to keep the current tags.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a book's name, description or tags (WRITE — requires BOOKSTACK_ALLOW_WRITE). PUTs /api/books/{id}."""
    _require_write()
    payload = _fields(name=name, description=description, tags=_tags(tags))
    if not payload:
        raise ValueError("Nothing to update: provide name, description and/or tags.")
    if preview := _confirm("update_book", {"id": id, **payload}, f"Update book {id}: {', '.join(payload)}.", confirm):
        return preview
    return _written("book", await _get_client().put(f"books/{id}", json=payload))


@mcp.tool()
async def create_shelf(
    name: Annotated[str, Field(description="Shelf name.", min_length=1, max_length=255)],
    description: Annotated[str | None, Field(description="Plain-text description.", max_length=1900)] = None,
    book_ids: Annotated[list[int] | None, Field(description="Books to put on the shelf, in display order.")] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Tags as {name: value}; use '' for a tag without a value.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a shelf, optionally with books on it (WRITE — requires BOOKSTACK_ALLOW_WRITE). POSTs /api/shelves."""
    _require_write()
    payload = _fields(name=name, description=description, books=book_ids, tags=_tags(tags))
    if preview := _confirm("create_shelf", payload, f"Create shelf '{name}'.", confirm):
        return preview
    return _written("shelf", await _get_client().post("shelves", json=payload))


@mcp.tool()
async def update_shelf(
    id: Annotated[int, Field(description="Shelf id.")],
    name: Annotated[str | None, Field(description="New name.", min_length=1, max_length=255)] = None,
    description: Annotated[str | None, Field(description="New plain-text description.", max_length=1900)] = None,
    add_book_ids: Annotated[list[int] | None, Field(description="Books to add to the end of the shelf.")] = None,
    remove_book_ids: Annotated[list[int] | None, Field(description="Books to take off the shelf (the books themselves stay).")] = None,
    tags: Annotated[dict[str, str] | None, Field(description="Replaces ALL tags: {name: value} ('' = no value), {} clears them. Omit to keep the current tags.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update a shelf's name, description or tags, or add/remove books (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    PUTs /api/shelves/{id}. BookStack replaces a shelf's whole book list, so add/remove reads the
    current list first and keeps every other book in its place.
    """
    _require_write()
    payload = _fields(name=name, description=description, tags=_tags(tags))
    if add_book_ids or remove_book_ids:
        shelf = await _get_client().get(f"shelves/{id}")
        current = [b.get("id") for b in shelf.get("books") or [] if isinstance(b, dict)]
        drop = set(remove_book_ids or ())
        keep = [b for b in current if b not in drop]
        payload["books"] = keep + [b for b in dict.fromkeys(add_book_ids or ()) if b not in keep]
    if not payload:
        raise ValueError("Nothing to update: provide name, description, tags, add_book_ids or remove_book_ids.")
    if preview := _confirm("update_shelf", {"id": id, **payload}, f"Update shelf {id}: {', '.join(payload)}.", confirm):
        return preview
    out = _written("shelf", await _get_client().put(f"shelves/{id}", json=payload))
    if "books" in payload:
        out["book_ids"] = payload["books"]
    return out


@mcp.tool()
async def add_comment(
    page_id: Annotated[int, Field(description="The page to comment on.")],
    body: Annotated[str, Field(description="Comment text (plain text unless html=true).", min_length=1)],
    html: Annotated[bool, Field(description="Treat body as HTML instead of plain text.")] = False,
    reply_to: Annotated[int | None, Field(description="local_id of the comment to reply to (see get_page full=true → comments).")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Comment on a page (WRITE — requires BOOKSTACK_ALLOW_WRITE). POSTs /api/comments.

    Needs a BookStack release with the comments API (older ones answer 404).
    """
    _require_write()
    payload = _fields(page_id=page_id, html=body if html else _text_html(body), reply_to=reply_to)
    if preview := _confirm("add_comment", payload, f"Comment on page {page_id}.", confirm):
        return preview
    data = await _get_client().post("comments", json=payload)
    out = _pick(data, _COMMENT_FIELDS) if isinstance(data, dict) else {"result": data}
    out["url"] = f"{_get_client().settings.base_url}/link/{page_id}"
    return out


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"bookstack-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = BookStackClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
