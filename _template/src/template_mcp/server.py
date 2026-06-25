"""FastMCP server exposing read-only <NAME> tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. All tools here are read-only.

This is a starting skeleton: the three tools below (`search_items`, `get_item`, `api_get`) show the
house pattern — a curated list/search tool, a curated get-one tool, and a raw escape hatch. Replace
the endpoint paths and field lists with your API's, then update tests/test_smoke.py and the README.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .client import ApiClient
from .config import ConfigError, Settings

mcp = FastMCP("template-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: ApiClient | None = None


def _get_client() -> ApiClient:
    global _client
    if _client is None:
        _client = ApiClient(Settings.from_env())
    return _client


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
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
