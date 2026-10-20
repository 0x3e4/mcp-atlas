"""FastMCP server exposing BookStack (REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools (GET) cover the content hierarchy (shelves → books → chapters →
pages), search, export, attachments and images (incl. their content); the raw ``bookstack_get``
escape hatch reaches anything else (users, roles, comments, audit-log, …). Write tools (create/update
pages, chapters, books and shelves, comment on a page, upload/replace attachments and images, draw.io
drawings) are **opt-in**: they refuse unless ``BOOKSTACK_ALLOW_WRITE=true``
and need a token whose user has the matching permissions. With the flag off the server is read-only.
Unless ``BOOKSTACK_CONFIRM_WRITE=false``, every write first returns a preview plus a confirm code and
only runs when called again with that code, after the user has confirmed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import mimetypes
import secrets
import sys
from html import escape
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from . import attachments
from .client import BookStackClient, BookStackError
from .config import ConfigError, Settings
from .drawio import embed_xml, extract_xml, normalize_xml

mcp = FastMCP(
    "bookstack-mcp",
    instructions=(
        "Write tools (create_*/update_*/upload_*/add_comment) need the user's confirmation: the first call changes "
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
            "the matching create/update permissions) to create or edit pages, chapters, books, shelves, "
            "attachments and images."
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

    Metadata only — read one with get_attachment.
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


# ---- tools: draw.io drawings --------------------------------------------

_DIAGRAM_DESC = (
    "draw.io diagram XML: an <mxfile> or a bare <mxGraphModel><root><mxCell id=\"0\"/>"
    "<mxCell id=\"1\" parent=\"0\"/>…</root></mxGraphModel>. Shapes are vertex cells "
    "(style e.g. 'rounded=1;whiteSpace=wrap;html=1;') with an <mxGeometry x y width height as=\"geometry\"/>; "
    "connectors are edge cells with source/target ids and <mxGeometry relative=\"1\" as=\"geometry\"/>."
)
_DRAWING_FIELDS = ("id", "name", "uploaded_to", "url", "created_at", "updated_at")


def _require_renderer() -> None:
    if not _get_client().settings.drawio_export_url:
        raise ValueError(
            "Drawing tools need a draw.io export server to render the PNG. Set BOOKSTACK_DRAWIO_EXPORT_URL "
            "(e.g. http://drawio-export:8000/ for a jgraph/export-server sidecar)."
        )


def _diagram_change(xml: str, cells: int) -> dict[str, Any]:
    """The diagram's part of a confirm binding: a digest instead of the whole XML (keeps previews short)."""
    return {"diagram_sha256": hashlib.sha256(xml.encode()).hexdigest()[:16], "cells": cells}


async def _render(xml: str) -> bytes:
    return embed_xml(await _get_client().render_drawio(xml), xml)


async def _get_drawing_meta(image_id: int) -> dict[str, Any]:
    data = await _get_client().get(f"image-gallery/{image_id}")
    if not isinstance(data, dict) or data.get("type") != "drawio":
        raise ValueError(f"Image {image_id} is not a draw.io drawing (type {data.get('type') if isinstance(data, dict) else None!r}).")
    return data


@mcp.tool()
async def get_drawing(
    image_id: Annotated[int, Field(description="The drawing's image id — the number in <div drawio-diagram=\"…\"> in a page's HTML.")],
) -> dict[str, Any]:
    """Get a draw.io drawing with its diagram XML (GET /api/image-gallery/{id} + its PNG data).

    The XML is what create_drawing/update_drawing take, so read it, change it and write it back with
    update_drawing. List a page's drawings with bookstack_get('image-gallery',
    {"filter[type]": "drawio", "filter[uploaded_to]": <page id>}).
    """
    meta = await _get_drawing_meta(image_id)
    out = _pick(meta, _DRAWING_FIELDS)
    out["xml"] = extract_xml(await _get_client().get_bytes(f"image-gallery/{image_id}/data"))
    if out["xml"] is None:
        out["note"] = "This PNG carries no diagram XML (not saved by draw.io); it can only be redrawn from scratch."
    return out


@mcp.tool()
async def create_drawing(
    page_id: Annotated[int, Field(description="The page the drawing belongs to (and is inserted into).")],
    xml: Annotated[str, Field(description=_DIAGRAM_DESC, min_length=1)],
    name: Annotated[str, Field(description="Drawing name shown in the image gallery.", min_length=1, max_length=180)] = "drawing.png",
    position: Annotated[str, Field(description="Where to put it on the page: 'end', 'start', or 'none' (upload only; place the returned snippet yourself with update_page).")] = "end",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Draw a draw.io diagram and add it to a page (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    Renders the XML to PNG on the draw.io export server, uploads it as a BookStack drawing
    (POST /api/image-gallery, type=drawio) and inserts BookStack's drawing snippet at the start or end
    of the page (a new page revision). The PNG carries the XML, so the drawing stays editable in
    BookStack's own draw.io editor and via get_drawing/update_drawing.
    """
    _require_write()
    _require_renderer()
    if position not in ("end", "start", "none"):
        raise ValueError("position must be one of: end, start, none.")
    diagram, cells = normalize_xml(xml)
    change = {"page_id": page_id, "name": name, "position": position, **_diagram_change(diagram, cells)}
    where = "upload only, not placed on the page" if position == "none" else f"inserted at the {position} of page {page_id}"
    if preview := _confirm("create_drawing", change, f"Create drawing '{name}' ({cells} cells), {where}.", confirm):
        return preview

    client = _get_client()
    png = await _render(diagram)
    image = await client.post_form(
        "image-gallery",
        data={"type": "drawio", "uploaded_to": str(page_id), "name": name},
        files={"image": ("drawing.png", png, "image/png")},
    )
    snippet = (image.get("content") or {}).get("html") or (
        f'<div drawio-diagram="{image.get("id")}"><img src="{escape(str(image.get("url")))}"></div>'
    )
    out: dict[str, Any] = {"drawing": _pick(image, _DRAWING_FIELDS), "snippet": snippet}
    if position != "none":
        out.update(await _insert(page_id, snippet, snippet, position, f"Added drawing {name}", "Drawing"))
    return out


async def _insert(page_id: int, html: str, markdown: str, position: str, changelog: str, what: str) -> dict[str, Any]:
    """Put a snippet at the start or end of a page (a new revision); report a failure instead of raising."""
    client = _get_client()
    try:
        page = await client.get(f"pages/{page_id}")
        if page.get("markdown"):
            body = {"markdown": _place(page["markdown"], markdown, position, "\n\n")}
        else:
            body = {"html": _place(page.get("raw_html") or page.get("html") or "", html, position, "\n")}
        return {"page": _written("page", await client.put(f"pages/{page_id}", json={**body, "changelog": changelog[:180]}))}
    except (BookStackError, ValueError) as exc:
        return {"page_error": f"{what} uploaded, but adding it to page {page_id} failed: {exc}. Insert the snippet with update_page."}


def _place(content: str, snippet: str, position: str, gap: str) -> str:
    content = content.strip()
    if not content:
        return snippet
    return f"{snippet}{gap}{content}" if position == "start" else f"{content}{gap}{snippet}"


@mcp.tool()
async def update_drawing(
    image_id: Annotated[int, Field(description="The drawing's image id (see get_drawing).")],
    xml: Annotated[str, Field(description="The new diagram — replaces the whole drawing. " + _DIAGRAM_DESC, min_length=1)],
    name: Annotated[str | None, Field(description="New drawing name.", min_length=1, max_length=180)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Redraw an existing draw.io drawing in place (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    Renders the new XML and replaces the drawing's PNG (POST /api/image-gallery/{id} with
    _method=PUT). The URL stays the same, so every page showing it shows the new version (browsers may
    cache the old image briefly). The old image is not kept: read it with get_drawing first if needed.
    """
    _require_write()
    _require_renderer()
    meta = await _get_drawing_meta(image_id)
    if not str(meta.get("path") or meta.get("url") or "").lower().endswith(".png"):
        raise ValueError(f"Drawing {image_id} is not stored as PNG; BookStack only replaces a file with the same type.")
    diagram, cells = normalize_xml(xml)
    change = {"image_id": image_id, "name": name, **_diagram_change(diagram, cells)}
    summary = f"Redraw drawing {image_id} '{meta.get('name')}' (page {meta.get('uploaded_to')}, {cells} cells)"
    summary += f", rename to '{name}'." if name else "."
    if preview := _confirm("update_drawing", change, summary, confirm):
        return preview
    data = _fields(_method="PUT", name=name)
    image = await _get_client().post_form(
        f"image-gallery/{image_id}", data=data, files={"image": ("drawing.png", await _render(diagram), "image/png")}
    )
    return _pick(image, _DRAWING_FIELDS)


# ---- tools: attachments & images (content) ------------------------------

_IMAGE_EXTENSIONS = ("jpg", "jpeg", "png", "gif", "webp", "avif")  # BookStack's ImageService list
_IMAGE_FIELDS = ("id", "name", "type", "uploaded_to", "url", "created_at", "updated_at")
_ATTACHMENT_WRITE_FIELDS = ("id", "name", "extension", "uploaded_to", "external", "updated_at")
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # BookStack's default FILE_UPLOAD_SIZE_LIMIT (50 MB)
_SOURCE_DESC = (
    "File source — give exactly one of text, content_base64 or path. "
)


def _ext(filename: str) -> str:
    suffix = PurePosixPath(filename).suffix
    return suffix[1:].lower() if suffix else ""


def _ctype(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def _read_upload_dir(path: str) -> bytes:
    """Read ``path`` from BOOKSTACK_UPLOAD_DIR, refusing anything outside it."""
    upload_dir = _get_client().settings.upload_dir
    if not upload_dir:
        raise ValueError(
            "path needs BOOKSTACK_UPLOAD_DIR: mount a folder into the container (e.g. -v ~/bookstack-upload:/upload:ro) "
            "and set BOOKSTACK_UPLOAD_DIR=/upload. Otherwise pass text or content_base64."
        )
    base = Path(upload_dir).resolve()
    target = (base / path.lstrip("/\\")).resolve()
    if not target.is_relative_to(base):
        raise ValueError(f"path must stay inside BOOKSTACK_UPLOAD_DIR; {path!r} does not.")
    if not target.is_file():
        raise ValueError(f"No file {path!r} in BOOKSTACK_UPLOAD_DIR.")
    if target.stat().st_size > _MAX_UPLOAD_BYTES:
        raise ValueError(f"{path!r} is larger than {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    return target.read_bytes()


def _file_source(text: str | None, content_base64: str | None, path: str | None, filename: str | None) -> tuple[bytes, str]:
    """Resolve the one given file source into (bytes, filename-with-extension)."""
    if sum(x is not None for x in (text, content_base64, path)) != 1:
        raise ValueError("Give exactly one file source: text, content_base64 or path.")
    if text is not None:
        data = text.encode("utf-8")
    elif content_base64 is not None:
        raw = content_base64.split(",", 1)[1] if content_base64.startswith("data:") else content_base64
        try:
            data = base64.b64decode("".join(raw.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("content_base64 is not valid base64.") from exc
    else:
        data = _read_upload_dir(path)
    name = (filename or (PurePosixPath(path.replace("\\", "/")).name if path else "")).strip()
    if not name or not _ext(name):
        raise ValueError("Give filename with an extension (e.g. 'backup.sh', 'diagram.png'); BookStack takes the type from it.")
    if not data:
        raise ValueError("The file is empty.")
    if len(data) > _MAX_UPLOAD_BYTES:
        raise ValueError(f"The file is larger than {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    return data, name


def _file_change(data: bytes, filename: str) -> dict[str, Any]:
    """The file's part of a confirm binding: name, size and a digest (not the bytes)."""
    return {"filename": filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()[:16]}


def _check_position(position: str) -> None:
    if position not in ("end", "start", "none"):
        raise ValueError("insert must be one of: end, start, none.")


@mcp.tool()
async def get_attachment(
    id: Annotated[int, Field(description="Attachment id (see list_attachments).")],
    pages: Annotated[str | None, Field(description="For a PDF: page range to read, e.g. '3' or '31-60'. Default: the first 30 pages.")] = None,
    part: Annotated[int | None, Field(description="For an e-mail attachment (.eml/.msg): open its N-th own attachment (1-based).", ge=1)] = None,
):
    """Read an attachment (GET /api/attachments/{id}) — the file's content, or the target of a link.

    - Images (PNG, JPEG, GIF, WebP) → an image you can look at.
    - PDF → text per page; scanned pages without text are rendered as images (up to 5 per call).
    - E-mails (.eml, Outlook .msg) → headers, body and the mail's own attachments (open one with part=N).
    - Text files (logs, configs, scripts, CSV, JSON, XML …) → text.
    - Anything else (Office, archives) → metadata only.
    Also returns the html/markdown link to put the attachment into a page body.
    """
    data = await _get_client().get(f"attachments/{id}")
    meta = _pick(data, _ATTACHMENT_WRITE_FIELDS)
    meta["links"] = data.get("links")
    if data.get("external"):
        return {**meta, "link": data.get("content")}
    try:
        raw = base64.b64decode(data.get("content") or "")
    except (binascii.Error, ValueError) as exc:
        raise BookStackError(f"Attachment {id}: BookStack's content was not valid base64.") from exc
    name, ext = str(data.get("name") or f"attachment-{id}"), str(data.get("extension") or "")
    filename = name if not ext or name.lower().endswith(f".{ext.lower()}") else f"{name}.{ext}"
    content = attachments.read(raw, _ctype(filename), filename, part=part, pages=pages)
    content[0] = {**meta, **content[0]}
    return content


@mcp.tool()
async def list_images(
    page_id: Annotated[int | None, Field(description="Only images uploaded to this page id.")] = None,
    type: Annotated[str | None, Field(description="'gallery' (normal images) or 'drawio' (drawings).")] = None,
    name_contains: Annotated[str | None, Field(description="Only images whose name contains this text.")] = None,
    limit: Annotated[int, Field(description="Max images to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List images in the image gallery (GET /api/image-gallery), e.g. the images on one page."""
    if type is not None and type not in ("gallery", "drawio"):
        raise ValueError("type must be one of: gallery, drawio.")
    return await _get_list(
        "image-gallery", _IMAGE_FIELDS, limit=limit, offset=offset, name_contains=name_contains,
        extra_filters={"uploaded_to": page_id, "type": type}, full=full,
    )


@mcp.tool()
async def get_image(
    id: Annotated[int, Field(description="Image id (see list_images).")],
):
    """Look at a gallery image (GET /api/image-gallery/{id} + /data): its details and the picture itself.

    Also returns the html/markdown snippet BookStack uses to show it on a page. Reading the picture
    needs BookStack v25.11 or newer (the /data endpoint).
    """
    client = _get_client()
    meta = await client.get(f"image-gallery/{id}")
    info = _pick(meta, _IMAGE_FIELDS)
    info["content"] = meta.get("content")
    try:
        raw = await client.get_bytes(f"image-gallery/{id}/data")
    except BookStackError as exc:
        if exc.status == 404:
            info["note"] = "This BookStack has no image data endpoint (added in v25.11); only the details are shown."
            return info
        raise
    filename = PurePosixPath(str(meta.get("path") or meta.get("url") or "image.png")).name
    content = attachments.read(raw, _ctype(filename), filename)
    content[0] = {**info, **content[0]}
    return content


@mcp.tool()
async def upload_attachment(
    page_id: Annotated[int, Field(description="The page to attach the file or link to.")],
    name: Annotated[str | None, Field(description="Display name. Defaults to the file name (or the link).", min_length=1, max_length=255)] = None,
    text: Annotated[str | None, Field(description=_SOURCE_DESC + "text: the file's content as UTF-8 text (configs, scripts, CSV, logs …).")] = None,
    content_base64: Annotated[str | None, Field(description=_SOURCE_DESC + "content_base64: the file as base64 (or a data: URL). Only for small binaries — large ones cost a lot of context; use path.")] = None,
    path: Annotated[str | None, Field(description=_SOURCE_DESC + "path: a file in the server's BOOKSTACK_UPLOAD_DIR drop folder, e.g. 'manuals/switch.pdf'.")] = None,
    filename: Annotated[str | None, Field(description="File name with extension, e.g. 'backup.sh'. Required for text/content_base64; defaults to the file's name for path.", max_length=255)] = None,
    link: Annotated[str | None, Field(description="Attach a link (URL) instead of a file.", min_length=1, max_length=2000)] = None,
    insert: Annotated[str, Field(description="Also link it in the page body: 'none' (only the attachments sidebar), 'end' or 'start'.")] = "none",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Attach a file or a link to a page (WRITE — requires BOOKSTACK_ALLOW_WRITE). POSTs /api/attachments.

    Attachments show in the page's sidebar; insert='end'/'start' also adds a link to it in the page
    body (a new page revision). Max 50 MB (BookStack's default upload limit).
    """
    _require_write()
    _check_position(insert)
    client = _get_client()
    if link is not None:
        if any(x is not None for x in (text, content_base64, path)):
            raise ValueError("Give a link or a file source (text, content_base64, path), not both.")
        payload = {"name": (name or link).strip(), "uploaded_to": page_id, "link": link.strip()}
        change: dict[str, Any] = {**payload, "insert": insert}
        what = f"link {link.strip()}"
    else:
        data, fname = _file_source(text, content_base64, path, filename)
        payload = {"name": (name or fname).strip(), "uploaded_to": page_id}
        change = {**payload, **_file_change(data, fname), "insert": insert}
        what = f"file {fname} ({len(data)} bytes)"
    where = "" if insert == "none" else f", linked at the {insert} of the page"
    if preview := _confirm("upload_attachment", change, f"Attach {what} as '{payload['name']}' to page {page_id}{where}.", confirm):
        return preview
    if link is not None:
        att = await client.post("attachments", json=payload)
    else:
        att = await client.post_form(
            "attachments", data={k: str(v) for k, v in payload.items()}, files={"file": (fname, data, _ctype(fname))}
        )
    out = _pick(att, _ATTACHMENT_WRITE_FIELDS)
    url = f"{client.settings.base_url}/attachments/{att.get('id')}"
    out["url"] = url
    label = escape(str(att.get("name") or payload["name"]))
    snippet_html = f'<p><a target="_blank" href="{escape(url)}">{label}</a></p>'
    snippet_md = f"[{str(att.get('name') or payload['name']).replace('[', '').replace(']', '')}]({url})"
    out["snippet"] = {"html": snippet_html, "markdown": snippet_md}
    if insert != "none":
        out.update(await _insert(page_id, snippet_html, snippet_md, insert, f"Attached {payload['name']}", "Attachment"))
    return out


@mcp.tool()
async def update_attachment(
    id: Annotated[int, Field(description="Attachment id.")],
    name: Annotated[str | None, Field(description="New display name.", min_length=1, max_length=255)] = None,
    text: Annotated[str | None, Field(description="Replace the file — " + _SOURCE_DESC + "text: new content as UTF-8 text.")] = None,
    content_base64: Annotated[str | None, Field(description="Replace the file — content_base64: new file as base64 (small files only).")] = None,
    path: Annotated[str | None, Field(description="Replace the file — path: a file in BOOKSTACK_UPLOAD_DIR.")] = None,
    filename: Annotated[str | None, Field(description="File name with extension for text/content_base64 (defaults to the file's name for path).", max_length=255)] = None,
    link: Annotated[str | None, Field(description="Turn it into (or change) a link attachment with this URL.", min_length=1, max_length=2000)] = None,
    move_to_page_id: Annotated[int | None, Field(description="Move the attachment to another page.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Rename, replace, re-link or move an attachment (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    PUTs /api/attachments/{id} (a new file goes as multipart POST with _method=PUT). A new file
    replaces the old one for good (BookStack keeps no attachment history); the name stays unless you
    give one.
    """
    _require_write()
    client = _get_client()
    has_file = any(x is not None for x in (text, content_base64, path))
    if has_file and link is not None:
        raise ValueError("Give a new file or a new link, not both.")
    listed = await client.get("attachments", params={"filter[id]": id, "count": 1})
    rows = listed.get("data") if isinstance(listed, dict) else None
    if not rows:
        raise ValueError(f"No attachment {id} (or no permission to see it).")
    current = rows[0]
    payload = _fields(name=name, link=link.strip() if link else None, uploaded_to=move_to_page_id)
    change: dict[str, Any] = {"id": id, **payload}
    if has_file:
        data, fname = _file_source(text, content_base64, path, filename)
        payload.setdefault("name", current.get("name"))  # BookStack would rename it to the file name
        change.update(_file_change(data, fname))
    if not has_file and not payload:
        raise ValueError("Nothing to update: give name, a new file, link or move_to_page_id.")
    parts = [f"{k}={v}" for k, v in _fields(name=name, link=payload.get("link"), page=move_to_page_id).items()]
    if has_file:
        parts.append(f"new file {fname} ({len(data)} bytes)")
    summary = f"Update attachment {id} '{current.get('name')}' on page {current.get('uploaded_to')}: {', '.join(parts)}."
    if preview := _confirm("update_attachment", change, summary, confirm):
        return preview
    if has_file:
        att = await client.post_form(
            f"attachments/{id}", data={"_method": "PUT", **{k: str(v) for k, v in payload.items()}},
            files={"file": (fname, data, _ctype(fname))},
        )
    else:
        att = await client.put(f"attachments/{id}", json=payload)
    out = _pick(att, _ATTACHMENT_WRITE_FIELDS)
    out["url"] = f"{client.settings.base_url}/attachments/{id}"
    return out


def _image_source(content_base64: str | None, path: str | None, filename: str | None) -> tuple[bytes, str]:
    data, fname = _file_source(None, content_base64, path, filename)
    if _ext(fname) not in _IMAGE_EXTENSIONS:
        raise ValueError(f"BookStack images must be one of {', '.join(_IMAGE_EXTENSIONS)}; {fname!r} is not (attach it with upload_attachment instead).")
    return data, fname


@mcp.tool()
async def upload_image(
    page_id: Annotated[int, Field(description="The page the image belongs to (and is shown on).")],
    content_base64: Annotated[str | None, Field(description="Image source — give content_base64 or path. content_base64: the image as base64 (or a data: URL). Only for small images — large ones cost a lot of context; use path.")] = None,
    path: Annotated[str | None, Field(description="Image source: a file in the server's BOOKSTACK_UPLOAD_DIR drop folder, e.g. 'screens/rack.png'.")] = None,
    filename: Annotated[str | None, Field(description="File name with extension (png, jpg, jpeg, gif, webp, avif). Required for content_base64.", max_length=255)] = None,
    name: Annotated[str | None, Field(description="Image name / alt text. Defaults to the file name.", min_length=1, max_length=180)] = None,
    insert: Annotated[str, Field(description="Where to show it on the page: 'end', 'start', or 'none' (gallery upload only; place the returned snippet yourself with update_page).")] = "end",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Upload an image to a page's gallery and show it on the page (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    POSTs /api/image-gallery (type=gallery) and inserts BookStack's own snippet (a linked, scaled
    display image) at the start or end of the page — a new page revision. Needs the 'image-create-all'
    role permission plus edit rights on the page.
    """
    _require_write()
    _check_position(insert)
    data, fname = _image_source(content_base64, path, filename)
    label = (name or fname).strip()
    change = {"page_id": page_id, "name": label, "insert": insert, **_file_change(data, fname)}
    where = "gallery only, not placed on the page" if insert == "none" else f"shown at the {insert} of page {page_id}"
    if preview := _confirm("upload_image", change, f"Upload image {fname} ({len(data)} bytes) as '{label}', {where}.", confirm):
        return preview
    image = await _get_client().post_form(
        "image-gallery",
        data={"type": "gallery", "uploaded_to": str(page_id), "name": label},
        files={"image": (fname, data, _ctype(fname))},
    )
    snippet = image.get("content") or {}
    url = escape(str(image.get("url")))
    snippet_html = snippet.get("html") or f'<a href="{url}" target="_blank"><img src="{url}" alt="{escape(label)}"></a>'
    snippet_md = snippet.get("markdown") or f"![{label.replace('[', '').replace(']', '')}]({image.get('url')})"
    out: dict[str, Any] = {"image": _pick(image, _IMAGE_FIELDS), "snippet": {"html": snippet_html, "markdown": snippet_md}}
    if insert != "none":
        out.update(await _insert(page_id, f"<p>{snippet_html}</p>", snippet_md, insert, f"Added image {label}", "Image"))
    return out


@mcp.tool()
async def update_image(
    id: Annotated[int, Field(description="Image id (see list_images).")],
    content_base64: Annotated[str | None, Field(description="Replace the picture — content_base64: the new image as base64 (small images only).")] = None,
    path: Annotated[str | None, Field(description="Replace the picture — path: a file in BOOKSTACK_UPLOAD_DIR.")] = None,
    filename: Annotated[str | None, Field(description="File name with extension for content_base64; must have the same type as the current image.", max_length=255)] = None,
    name: Annotated[str | None, Field(description="New image name.", min_length=1, max_length=180)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Rename a gallery image or replace its picture in place (WRITE — requires BOOKSTACK_ALLOW_WRITE).

    PUTs /api/image-gallery/{id} (a new picture goes as multipart POST with _method=PUT). The URL
    stays the same, so every page showing it shows the new picture; the old one is not kept.
    BookStack only accepts a replacement of the same type (png for png, …). Drawings: update_drawing.
    """
    _require_write()
    client = _get_client()
    meta = await client.get(f"image-gallery/{id}")
    if meta.get("type") == "drawio":
        raise ValueError(f"Image {id} is a draw.io drawing; use update_drawing to change it.")
    has_file = content_base64 is not None or path is not None
    if not has_file and name is None:
        raise ValueError("Nothing to update: give a new picture (content_base64 or path) and/or name.")
    change: dict[str, Any] = {"id": id, "name": name}
    summary = f"Update image {id} '{meta.get('name')}' (page {meta.get('uploaded_to')})"
    if has_file:
        data, fname = _image_source(content_base64, path, filename)
        current_ext = _ext(str(meta.get("path") or meta.get("url") or ""))
        if current_ext and _ext(fname) != current_ext:
            raise ValueError(f"Image {id} is a .{current_ext}; BookStack only replaces it with another .{current_ext}.")
        change.update(_file_change(data, fname))
        summary += f": new picture {fname} ({len(data)} bytes)"
    summary += f", rename to '{name}'." if name else "."
    if preview := _confirm("update_image", change, summary, confirm):
        return preview
    if has_file:
        image = await client.post_form(
            f"image-gallery/{id}", data=_fields(_method="PUT", name=name), files={"image": (fname, data, _ctype(fname))}
        )
    else:
        image = await client.put(f"image-gallery/{id}", json={"name": name})
    return _pick(image, _IMAGE_FIELDS)


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
