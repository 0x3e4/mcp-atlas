"""FastMCP server exposing <NAME> tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server.

This is a starting skeleton: the tools below show the house pattern — a curated list/search tool
(`search_items`), a curated get-one tool (`get_item`), a raw read-only escape hatch (`api_get`), and
one opt-in write tool (`update_item`). Writes refuse unless ``TEMPLATE_ALLOW_WRITE=true`` and, unless
``TEMPLATE_CONFIRM_WRITE=false``, first return a preview + confirm code and only run when called again
with that code after the user confirmed. Replace the endpoint paths and field lists with your API's,
then update tests/test_smoke.py and the README.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import ApiClient
from .config import ConfigError, Settings

mcp = FastMCP(
    "template-mcp",
    instructions=(
        "Write tools need the user's confirmation: the first call changes nothing and returns a preview "
        "with a confirm_code. Show the user a short overview of what will change, end with 'Confirm it?', "
        "and only after they say yes repeat the call with confirm=<code>."
    ),
)

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: ApiClient | None = None


def _get_client() -> ApiClient:
    global _client
    if _client is None:
        _client = ApiClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in TEMPLATE_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set TEMPLATE_ALLOW_WRITE=true (and use a credential with write "
            "rights) to enable them."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when TEMPLATE_CONFIRM_WRITE=false, or when ``code`` matches this exact
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


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 500) -> int:
    """Bound a caller-supplied limit so a tool can't flood the agent's context."""
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


# TODO: set this to the useful columns for your "items" resource.
_ITEM_FIELDS = ("id", "name", "status", "createdAt")


# ---- tools --------------------------------------------------------------

@mcp.tool()
async def search_items(
    query: Annotated[str | None, Field(description="Free-text search; omit to list the most recent items.")] = None,
    limit: Annotated[int, Field(description="Max items to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List or search items from the upstream API (read-only, the headline tool).

    TODO: point this at your real list/search endpoint and adjust the params + field projection.
    """
    params: dict[str, Any] = {"limit": _clamp(limit)}
    if query:
        params["q"] = query
    data = await _get_client().get("/items", params=params)  # TODO: your endpoint
    items = (data or {}).get("value", []) if isinstance(data, dict) else (data or [])
    if full:
        return {"count": len(items), "items": items}
    return {"count": len(items), "items": [_pick(i, _ITEM_FIELDS) for i in items]}


@mcp.tool()
async def get_item(
    item_id: Annotated[str, Field(description="The id of the item to fetch.")],
) -> dict[str, Any]:
    """Get a single item by id (read-only). TODO: adjust the endpoint path."""
    data = await _get_client().get(f"/items/{item_id}")  # TODO: your endpoint
    return data or {}


@mcp.tool()
async def api_get(
    path: Annotated[str, Field(description="An API path such as '/items' or '/items/{id}', or a full URL on the configured host.")],
    params: Annotated[dict[str, Any] | None, Field(description="Optional query parameters, e.g. {\"limit\": 5}.")] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only GET against any endpoint on the configured host.

    Only GET is supported, and absolute URLs must target the configured host. Use this to reach
    capabilities not covered by a dedicated tool.
    """
    client = _get_client()
    if path.startswith(("http://", "https://")) and not path.startswith(client.settings.base_origin):
        raise ValueError(
            f"api_get only allows the configured host ({client.settings.base_origin})."
        )
    data = await client.get(path, params=params)
    return data if data is not None else {}


# ---- tools: writes (opt-in, gated by TEMPLATE_ALLOW_WRITE) ---------------

@mcp.tool()
async def update_item(
    item_id: Annotated[str, Field(description="The id of the item to change.")],
    name: Annotated[str | None, Field(description="New name.")] = None,
    status: Annotated[str | None, Field(description="New status.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Update an item's name/status (WRITE — requires TEMPLATE_ALLOW_WRITE). PATCHes /items/{id}.

    TODO: replace with your API's real write actions. Keep the order: _require_write() → validate →
    build the exact payload → _confirm(...) → request.
    """
    _require_write()
    payload = {k: v for k, v in (("name", name), ("status", status)) if v is not None}
    if not payload:
        raise ValueError("Nothing to update: provide name and/or status.")
    if preview := _confirm("update_item", {"item_id": item_id, **payload}, f"Update item {item_id}: {', '.join(payload)}.", confirm):
        return preview
    data = await _get_client().patch(f"/items/{item_id}", json=payload)  # TODO: your endpoint
    return _pick(data or {}, _ITEM_FIELDS)


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"template-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = ApiClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
