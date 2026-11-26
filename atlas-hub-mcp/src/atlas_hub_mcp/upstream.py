"""Talking to the MCP servers behind the hub: tool listings (cached), calls, and optional embeddings.

Each operation opens a short MCP client connection (streamable HTTP, bearer token per upstream) and closes
it again. That costs a handshake per call but keeps no long-lived sessions that could go stale behind a
gateway or a container restart. Tool listings are cached for ``ATLAS_HUB_REFRESH`` seconds.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from .catalog import Catalog, ToolEntry, allowed, tool_kind
from .config import Settings, Upstream


# One INFO line per HTTP request from the client library would drown the hub's own log.
for _noisy in ("httpx2", "httpx"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)


class HubError(RuntimeError):
    """A clean, model-readable failure (unknown tool, upstream error, refused call)."""


def reason(exc: BaseException) -> str:
    """A short, readable cause: the first real error inside task-group wrappers."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return str(exc) if isinstance(exc, HubError) else f"{type(exc).__name__}: {exc}"


Connector = Callable[[Upstream, Settings], contextlib.AbstractAsyncContextManager[Client]]


@contextlib.asynccontextmanager
async def http_connector(upstream: Upstream, settings: Settings) -> AsyncIterator[Client]:
    """A connected MCP client for one upstream over streamable HTTP."""
    headers = {"Authorization": f"Bearer {upstream.token}"} if upstream.token else {}
    timeout = httpx2.Timeout(settings.timeout, read=max(settings.timeout, 60.0))
    seen: dict[str, int] = {}

    async def remember(response: httpx2.Response) -> None:
        seen["status"] = response.status_code

    try:
        async with httpx2.AsyncClient(headers=headers, timeout=timeout, verify=settings.httpx_verify,
                                      event_hooks={"response": [remember]}) as http:
            async with Client(streamable_http_client(upstream.url, http_client=http),
                              read_timeout_seconds=settings.timeout) as client:
                yield client
    except Exception as exc:
        # The SDK reports a refused request only as "Server returned an error response"; say why.
        if seen.get("status") in (401, 403):
            key = f"ATLAS_HUB_{upstream.name.upper().replace('-', '_')}_TOKEN"
            raise HubError(f"HTTP {seen['status']}: {upstream.name} refused the hub's token "
                           f"(check {key} / ATLAS_HUB_TOKEN).") from exc
        if seen.get("status") == 421:
            raise HubError(f"HTTP 421: {upstream.name} does not accept this host name; add it to that "
                           "server's MCP_ALLOWED_HOSTS.") from exc
        raise


def result_value(result: Any) -> Any:
    """The useful part of a CallToolResult: structured content, else JSON text, else plain text."""
    if isinstance(result.structured_content, dict):
        value = result.structured_content
        # MCPServer wraps non-object results as {"result": ...}
        return value["result"] if set(value) == {"result"} else value
    texts = [getattr(c, "text", "") for c in result.content or [] if getattr(c, "type", "") == "text"]
    text = "\n".join(t for t in texts if t)
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


class Hub:
    """Upstream tool catalog with a refresh TTL, plus the call path."""

    def __init__(self, settings: Settings, connector: Connector = http_connector) -> None:
        self.settings = settings
        self.connector = connector
        self.catalog = Catalog([])
        self.errors: dict[str, str] = {}
        self.counts: dict[str, int] = {}
        self.embed_error = ""
        self._embed_retry_at = 0.0
        self._loaded_at = 0.0
        self._lock = asyncio.Lock()

    # ---- catalog -----------------------------------------------------------------------------------

    async def _list(self, upstream: Upstream) -> list[ToolEntry]:
        async with self.connector(upstream, self.settings) as client:
            entries, cursor = [], None
            while True:
                page = await client.list_tools(cursor=cursor) if cursor else await client.list_tools()
                for tool in page.tools:
                    schema = dict(tool.input_schema or {})
                    entry = ToolEntry(upstream.name, tool.name, tool.description or "", schema,
                                      tool_kind(tool.annotations, schema))
                    if allowed(entry.id, self.settings.tools, self.settings.hidden_tools):
                        entries.append(entry)
                cursor = page.next_cursor
                if not cursor:
                    return entries

    async def refresh(self, force: bool = False) -> Catalog:
        """Reload every upstream's tool list when the cache is older than ATLAS_HUB_REFRESH (or forced)."""
        async with self._lock:
            fresh = self._loaded_at and (time.monotonic() - self._loaded_at) < self.settings.refresh_seconds
            if fresh and not force and not self.errors:
                return self.catalog
            names = list(self.settings.upstreams)
            results = await asyncio.gather(
                *(self._list(self.settings.upstreams[n]) for n in names), return_exceptions=True
            )
            entries: list[ToolEntry] = []
            errors: dict[str, str] = {}
            counts: dict[str, int] = {}
            for name, result in zip(names, results):
                if isinstance(result, BaseException):
                    errors[name] = reason(result)[:300]
                    # keep the last good listing of a server that is down for a moment
                    entries += [e for e in self.catalog.entries if e.server == name]
                else:
                    entries += result
                    counts[name] = len(result)
            await self._embed(entries)
            self.catalog, self.errors, self.counts = Catalog(entries), errors, counts
            self._loaded_at = time.monotonic()
            return self.catalog

    # ---- embeddings (optional, any OpenAI-compatible /embeddings endpoint: Ollama, vLLM, LM Studio …) ---

    async def embed(self, texts: list[str]) -> list[list[float]] | None:
        s = self.settings
        if not (s.embed_url and s.embed_model and texts) or time.monotonic() < self._embed_retry_at:
            return None  # off, or failed less than a minute ago: don't make every search wait for a timeout
        headers = {"Authorization": f"Bearer {s.embed_key}"} if s.embed_key else {}
        try:
            async with httpx2.AsyncClient(timeout=s.timeout, headers=headers) as http:
                vectors: list[list[float]] = []
                for start in range(0, len(texts), 64):
                    resp = await http.post(f"{s.embed_url}/embeddings",
                                           json={"model": s.embed_model, "input": texts[start:start + 64]})
                    resp.raise_for_status()
                    data = sorted(resp.json()["data"], key=lambda d: d.get("index", 0))
                    vectors += [d["embedding"] for d in data]
            self.embed_error = ""
            return vectors
        except (httpx2.HTTPError, KeyError, ValueError, TypeError) as exc:
            self.embed_error = f"embeddings unavailable, keyword search only ({type(exc).__name__}: {exc})"[:300]
            self._embed_retry_at = time.monotonic() + 60
            return None

    async def _embed(self, entries: list[ToolEntry]) -> None:
        old = {e.id: (e.embed_text, e.vector) for e in self.catalog.entries}
        todo = []
        for e in entries:
            text, vector = old.get(e.id, (None, None))
            if text == e.embed_text and vector is not None:
                e.vector = vector
            else:
                todo.append(e)
        vectors = await self.embed([e.embed_text for e in todo])
        if vectors and len(vectors) == len(todo):
            for e, v in zip(todo, vectors):
                e.vector = v

    # ---- calls ---------------------------------------------------------------------------------------

    async def entry(self, tool_id: str) -> ToolEntry:
        catalog = await self.refresh()
        found = catalog.by_id.get((tool_id or "").strip())
        if found is None:
            await self.refresh(force=True)  # a tool added upstream since the last listing
            found = self.catalog.by_id.get((tool_id or "").strip())
        if found is None:
            raise HubError(f"Unknown tool {tool_id!r}. Find tools with search_tools; ids look like 'server.tool_name'.")
        return found

    async def call(self, entry: ToolEntry, arguments: dict[str, Any]) -> Any:
        upstream = self.settings.upstreams[entry.server]
        try:
            async with self.connector(upstream, self.settings) as client:
                result = await client.call_tool(entry.name, arguments)
        except Exception as exc:  # network / protocol failures become a readable error
            raise HubError(f"{entry.server} did not answer: {reason(exc)}"[:500]) from exc
        value = result_value(result)
        if result.is_error:
            text = value.get("text") if isinstance(value, dict) else value
            raise HubError(f"{entry.id} failed: {str(text or 'no details')[:1000]}")
        return value
