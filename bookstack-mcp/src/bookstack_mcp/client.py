"""Async BookStack REST API client (read-only, API-token auth).

A single ``httpx.AsyncClient`` is shared across all tools. Authentication is a BookStack API token
sent as ``Authorization: Token <id>:<secret>`` on every request. List endpoints return
``{"data": [...], "total": N}``; single resources return the object directly; export endpoints
return text. Failures become a clean ``BookStackError`` so tools never leak tracebacks to the model.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class BookStackError(RuntimeError):
    """A clean, user-facing error for a failed BookStack API request."""

    def __init__(self, message: str, *, status: int | None = None, bs_message: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.bs_message = bs_message


class BookStackClient:
    """Minimal async client for the BookStack REST API (GET only)."""

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

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self._settings.token_id}:{self._settings.token_secret}",
            "Accept": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self._settings.api_base}/{path.lstrip('/')}"

    # ---- requests -------------------------------------------------------

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """GET a JSON resource; ``path`` is relative to ``/api`` (e.g. ``books`` or ``pages/12``)."""
        return await self._request("GET", self._url(path), params=params)

    async def get_text(self, path: str, *, params: dict[str, Any] | None = None) -> str:
        """GET a text resource (used for the export endpoints)."""
        return await self._request("GET", self._url(path), params=params, as_text=True)

    async def get_raw(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Escape hatch: GET an arbitrary ``/api/...`` path (or absolute URL on the same host)."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"bookstack_get only allows the configured host ({self._settings.base_origin})."
                )
            url = path
        else:
            p = path.lstrip("/")
            if p.startswith("api/"):
                p = p[len("api/") :]
            url = f"{self._settings.api_base}/{p}"
        return await self._request("GET", url, params=params)

    async def _request(
        self, method: str, url: str, *, params: dict[str, Any] | None = None, as_text: bool = False
    ) -> Any:
        client = await self._http()
        try:
            resp = await client.request(method, url, params=params, headers=self._auth_headers())
        except httpx.HTTPError as exc:
            raise BookStackError(f"Network error calling BookStack {url}: {exc}") from exc

        if resp.status_code >= 400:
            data = _try_json(resp)
            raise BookStackError(
                _format_error(resp.status_code, data, resp),
                status=resp.status_code,
                bs_message=_bs_message(data),
            )
        if as_text:
            return resp.text
        data = _try_json(resp)
        if data is None:
            ctype = resp.headers.get("content-type", "")
            raise BookStackError(
                f"Expected JSON from BookStack but got content-type {ctype!r} (HTTP {resp.status_code})."
            )
        return data


def _try_json(resp: httpx.Response) -> Any:
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        return None


def _bs_message(data: Any) -> str:
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            return err.get("message", "") or ""
        return data.get("message", "") or ""
    return ""


def _format_error(status: int, data: Any, resp: httpx.Response) -> str:
    msg = _bs_message(data)
    if status == 401:
        return (
            "BookStack 401 — token rejected. Check BOOKSTACK_TOKEN_ID / BOOKSTACK_TOKEN_SECRET and "
            "that the token's user has the 'Access System API' permission."
        )
    if status == 403:
        return f"BookStack 403 — the token's user lacks permission for this resource. {msg}".rstrip()
    if status == 404:
        return f"BookStack 404 — not found. {msg}".rstrip()
    if status == 422:
        return f"BookStack 422 — invalid request parameters. {msg}".rstrip()
    if status == 429:
        return "BookStack 429 — rate limit exceeded (API_REQUESTS_PER_MIN); back off and retry."
    detail = msg or (resp.text[:300] if resp.text else "")
    detail = f": {detail}" if detail else ""
    return f"BookStack API {status}{detail}".rstrip()
