"""FastMCP server exposing read-only BookStack (REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. All tools are read-only (GET). Curated tools cover the content hierarchy
(shelves → books → chapters → pages), search, export and attachments; the raw ``bookstack_get``
escape hatch reaches anything else (users, roles, comments, image-gallery, audit-log, …).
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import BookStackClient
from .config import ConfigError, Settings

mcp = FastMCP("bookstack-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: BookStackClient | None = None


def _get_client() -> BookStackClient:
    global _client
    if _client is None:
        _client = BookStackClient(Settings.from_env())
    return _client


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
