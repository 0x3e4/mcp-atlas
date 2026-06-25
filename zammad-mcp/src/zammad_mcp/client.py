"""Async Zammad REST API client.

A single ``httpx.AsyncClient`` is shared across all tools. Auth is a token header
(``Authorization: Token token=<token>``). List endpoints return a JSON array; single resources
return the object directly. Failures become a clean ``ZammadError`` (using Zammad's ``error_human``
when present) so tools never leak tracebacks to the model. Writes (POST/PUT) are gated at the tool
layer by ``ZAMMAD_ALLOW_WRITE``.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class ZammadError(RuntimeError):
    """A clean, user-facing error for a failed Zammad API request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ZammadClient:
    """Minimal async client for the Zammad REST API."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None

    @property
    def settings(self) -> Settings:
        return self._settings

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._settings.timeout,
                verify=self._settings.httpx_verify,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _url(self, path: str) -> str:
        return f"{self._settings.api_base}/{path.lstrip('/')}"

    # ---- requests -------------------------------------------------------

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """GET a resource; ``path`` is relative to ``/api/v1`` (e.g. ``tickets`` or ``tickets/12``)."""
        return await self._request("GET", self._url(path), params=params)

    async def post(self, path: str, *, json: Any, params: dict[str, Any] | None = None) -> Any:
        """POST ``json`` (write)."""
        return await self._request("POST", self._url(path), params=params, json=json)

    async def put(self, path: str, *, json: Any, params: dict[str, Any] | None = None) -> Any:
        """PUT ``json`` (write)."""
        return await self._request("PUT", self._url(path), params=params, json=json)

    async def get_raw(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Escape hatch: GET an arbitrary ``/api/v1/...`` path (or absolute URL on the same host)."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"zammad_get only allows the configured host ({self._settings.base_origin})."
                )
            url = path
        else:
            p = path.lstrip("/")
            if p.startswith("api/v1/"):
                p = p[len("api/v1/") :]
            url = self._url(p)
        return await self._request("GET", url, params=params)

    async def _request(
        self, method: str, url: str, *, params: dict[str, Any] | None = None, json: Any | None = None
    ) -> Any:
        client = await self._http()
        try:
            resp = await client.request(
                method, url, params=params, json=json, headers=self._settings.auth_headers
            )
        except httpx.HTTPError as exc:
            raise ZammadError(f"Network error calling Zammad {url}: {exc}") from exc

        if resp.status_code >= 400:
            raise ZammadError(_format_error(resp.status_code, resp), status=resp.status_code)
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            ctype = resp.headers.get("content-type", "")
            raise ZammadError(
                f"Expected JSON from Zammad but got content-type {ctype!r} (HTTP {resp.status_code})."
            )


def _format_error(status: int, resp: httpx.Response) -> str:
    human = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            human = body.get("error_human") or body.get("error") or ""
    except ValueError:
        human = ""
    if status == 401:
        return "Zammad 401 — token rejected. Check ZAMMAD_TOKEN (and that API Token Access is enabled)."
    if status == 403:
        return (
            "Zammad 403 — the token lacks permission for this action "
            f"(writes need a ticket.agent token). {human}".rstrip()
        )
    if status == 404:
        return f"Zammad 404 — not found. {human}".rstrip()
    if status == 422:
        return f"Zammad 422 — validation failed. {human}".rstrip()
    detail = human or (resp.text[:300] if resp.text else "")
    detail = f": {detail}" if detail else ""
    return f"Zammad API {status}{detail}".rstrip()
