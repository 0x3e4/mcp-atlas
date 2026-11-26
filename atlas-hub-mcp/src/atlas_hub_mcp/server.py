"""atlas-hub-mcp: one small tool set in front of many MCP servers, for local models.

Instead of attaching hundreds of tools (tens of thousands of tokens in every request), the model gets five:
``list_servers``, ``search_tools``, ``describe_tool``, ``call_read_tool`` and ``call_write_tool``. The hub
lists the upstream servers' tools, ranks them for a query and forwards calls.

Safety: reads and writes go through separate tools so the client can still auto-allow reads and ask before
writes (annotations survive). Writes refuse unless ``ATLAS_HUB_ALLOW_WRITE=true``. A write tool that has its
own preview / confirm flow (every mcp-atlas server) keeps it: the upstream's confirmation preview comes back
through the hub, the shared guard asks the user (dialog or confirm code) and repeats the call with the code.
Upstream tools without a confirm flow get one from the hub. Tool descriptions from upstreams are marked as
untrusted text, since a foreign server could put instructions there.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from . import __version__
from ._atlas_guard import compact_description, compact_schema, harden, run_http
from .config import ConfigError, Settings
from .upstream import Hub, HubError

mcp = MCPServer(
    "atlas-hub-mcp",
    instructions=(
        "This server is a hub in front of other MCP servers. Find a tool with search_tools (a few words "
        "about the task), check its parameters with describe_tool when the summary is not enough, then run "
        "it: call_read_tool for read tools, call_write_tool for tools that change something. Write tools "
        "need the user's confirmation: the first call changes nothing and returns a preview with a "
        "confirm_code. Show the user a short overview, end with 'Confirm it?', and only after they say yes "
        "repeat the call with confirm=<code>."
    ),
    version=__version__,
)

_hub: Hub | None = None
_KEY = secrets.token_bytes(32)


def _get_hub() -> Hub:
    global _hub
    if _hub is None:
        _hub = Hub(Settings.from_env())
    return _hub


def _code(change: dict[str, Any]) -> str:
    return hmac.new(_KEY, json.dumps(change, sort_keys=True, default=str).encode(), hashlib.sha256).hexdigest()[:12]


def _entry_view(entry: Any, score: float | None = None) -> dict[str, Any]:
    view: dict[str, Any] = {"tool": entry.id, "kind": entry.kind, "about": entry.summary, "params": entry.params()}
    if score is not None:
        view["score"] = score
    return view


@mcp.tool()
async def list_servers(
    refresh: Annotated[bool, Field(description="Reload every server's tool list now instead of using the cache.")] = False,
) -> dict[str, Any]:
    """The MCP servers behind this hub: how many tools each offers, and which ones are not answering."""
    hub = _get_hub()
    await hub.refresh(force=refresh)
    out: dict[str, Any] = {
        "servers": {
            name: {"tools": hub.counts.get(name, sum(e.server == name for e in hub.catalog.entries)),
                   **({"error": hub.errors[name]} if name in hub.errors else {})}
            for name in hub.settings.upstreams
        },
        "tools_total": len(hub.catalog.entries),
        "search": "keyword + embeddings" if hub.settings.embed_url and not hub.embed_error else "keyword",
        "writes": "enabled" if hub.settings.allow_write else "disabled (ATLAS_HUB_ALLOW_WRITE)",
    }
    if hub.embed_error:
        out["note"] = hub.embed_error
    return out


@mcp.tool()
async def search_tools(
    query: Annotated[str, Field(description="What you want to do, in a few words, e.g. 'list load balancer vservers' or 'open tickets of a customer'.")],
    server: Annotated[str | None, Field(description="Only tools of this server (see list_servers).")] = None,
    kind: Annotated[str, Field(description="'any', 'read' (no changes) or 'write'.")] = "any",
    limit: Annotated[int | None, Field(description="Max results (default ATLAS_HUB_MAX_RESULTS, 8).", ge=1, le=50)] = None,
) -> dict[str, Any]:
    """Find the tools for a task across all servers behind the hub, best match first.

    Each result has the tool id to call, whether it reads or writes, a one-line summary and its parameters
    (name: type, '*' = required). Call read tools with call_read_tool, write tools with call_write_tool.
    """
    hub = _get_hub()
    catalog = await hub.refresh()
    if server and server not in hub.settings.upstreams:
        raise ValueError(f"Unknown server {server!r}; servers: {', '.join(hub.settings.upstreams)}.")
    vectors = await hub.embed([query]) if hub.settings.embed_url else None
    found = catalog.search(query, server=server, kind=(kind or "any").strip().lower(),
                           limit=limit or hub.settings.max_results,
                           query_vector=vectors[0] if vectors else None)
    out: dict[str, Any] = {"query": query, "results": [_entry_view(e, s) for e, s in found]}
    if not found:
        out["hint"] = "No match. Try other words (tool names are English), or list_servers to see what is there."
    if hub.errors:
        out["unavailable_servers"] = sorted(hub.errors)
    return out


@mcp.tool()
async def describe_tool(
    tool: Annotated[str, Field(description="Tool id from search_tools, e.g. 'netscaler.list_lb_vservers'.")],
    full: Annotated[bool, Field(description="The whole description and schema instead of the compact form.")] = False,
) -> dict[str, Any]:
    """A tool's description and parameter schema, so arguments can be filled in correctly."""
    entry = await _get_hub().entry(tool)
    return {
        "tool": entry.id,
        "kind": entry.kind,
        "about": entry.description.strip() if full else compact_description(entry.description),
        "input_schema": entry.schema if full else compact_schema(entry.schema),
        "call_with": "call_read_tool" if entry.kind == "read" else "call_write_tool",
    }


@mcp.tool()
async def call_read_tool(
    tool: Annotated[str, Field(description="Tool id from search_tools (a read tool).")],
    arguments: Annotated[dict[str, Any] | None, Field(description="The tool's arguments as an object, see its params / describe_tool.")] = None,
) -> Any:
    """Run a read-only tool on the server behind the hub and return its result."""
    entry = await _get_hub().entry(tool)
    if entry.kind != "read":
        raise ValueError(f"{entry.id} changes something ({entry.kind}); run it with call_write_tool.")
    return await _get_hub().call(entry, dict(arguments or {}))


@mcp.tool()
async def call_write_tool(
    tool: Annotated[str, Field(description="Tool id from search_tools (a write tool).")],
    arguments: Annotated[dict[str, Any] | None, Field(description="The tool's arguments as an object, without confirm.")] = None,
    confirm: Annotated[str | None, Field(description="Confirm code from the preview; pass it only after the user confirmed.")] = None,
) -> Any:
    """Run a tool that changes something on a server behind the hub (WRITE — requires ATLAS_HUB_ALLOW_WRITE).

    The first call returns the tool's preview with a confirm_code and changes nothing; repeat it with
    confirm=<code> after the user agreed. Read tools also work here, but call_read_tool is the right place.
    """
    hub = _get_hub()
    if not hub.settings.allow_write:
        raise ValueError("Writes through the hub are disabled. Set ATLAS_HUB_ALLOW_WRITE=true to enable them.")
    entry = await hub.entry(tool)
    args = {k: v for k, v in dict(arguments or {}).items() if k != "confirm"}
    if entry.kind == "read":
        return await hub.call(entry, args)
    if "confirm" in (entry.schema.get("properties") or {}):
        # The upstream has its own preview / confirm flow (every mcp-atlas server): pass the code through.
        return await hub.call(entry, {**args, "confirm": confirm} if confirm else args)
    change = {"tool": entry.id, "arguments": args}
    code = _code(change)
    if not (confirm and hmac.compare_digest(confirm, code)):
        return {
            "status": "confirmation_required",
            "changed": False,
            "summary": f"Run {entry.id} ({entry.kind}) with {json.dumps(args, default=str)[:500]}",
            "change": change,
            "confirm_code": code,
            "next": "Show the user what will run; after they confirm, repeat the call with confirm=<code>.",
        }
    return await hub.call(entry, args)


# ---- security guard (shared across mcp-atlas, see _atlas_guard.py) ----------------------------------

GUARD = harden(
    mcp, server="atlas-hub-mcp", version=__version__, errors=(HubError,),
    untrusted_keys={"about"}, destructive={"call_write_tool"},
)


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"atlas-hub-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)
    global _hub
    _hub = Hub(settings)
    if settings.transport == "streamable-http":
        run_http(mcp, host=settings.host, port=settings.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
