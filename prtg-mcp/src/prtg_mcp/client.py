"""Async PRTG Network Monitor HTTP API client (read-only).

A single ``httpx.AsyncClient`` is shared across all tools. Auth (API token as ``Authorization:
Bearer`` + ``apitoken`` query param, or legacy ``username``/``passhash``) is applied to every
request. ``table.json`` and the other ``*.json`` endpoints return JSON; a failure — including PRTG's
habit of returning an XML/HTML error body on a bad token — becomes a clean ``PrtgError`` so tools
never leak tracebacks to the model.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class PrtgError(RuntimeError):
    """A clean, user-facing error for a failed PRTG API request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class PrtgClient:
    """Minimal async client for the PRTG HTTP API (GET only)."""

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

    def _merged(self, params: dict[str, Any] | None) -> dict[str, Any]:
        q: dict[str, Any] = dict(params or {})
        q.update(self._settings.auth_params)
        return q

    async def get(self, endpoint: str, *, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        """GET a PRTG endpoint relative to ``/api`` (e.g. ``table.json``)."""
        url = f"{self._settings.api_base}/{endpoint.lstrip('/')}"
        return await self._request(url, params=params, as_text=as_text)

    async def get_raw(self, endpoint: str, *, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        """Escape hatch: GET an arbitrary ``/api/...`` endpoint (or absolute URL on the same host)."""
        if endpoint.startswith(("http://", "https://")):
            if not endpoint.startswith(self._settings.base_origin):
                raise ValueError(
                    f"prtg_get only allows the configured host ({self._settings.base_origin})."
                )
            url = endpoint
        else:
            ep = endpoint.lstrip("/")
            if ep.startswith("api/"):
                ep = ep[len("api/") :]
            url = f"{self._settings.api_base}/{ep}"
        return await self._request(url, params=params, as_text=as_text)

    async def _request(self, url: str, *, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        client = await self._http()
        try:
            resp = await client.get(url, params=self._merged(params), headers=self._settings.auth_headers)
        except httpx.HTTPError as exc:
            raise PrtgError(f"Network error calling PRTG {url}: {exc}") from exc

        if resp.status_code >= 400:
            raise PrtgError(_format_error(resp.status_code, resp), status=resp.status_code)
        if as_text:
            return resp.text
        try:
            return resp.json()
        except ValueError:
            ctype = resp.headers.get("content-type", "")
            snippet = resp.text[:200].strip().replace("\n", " ")
            raise PrtgError(
                f"PRTG did not return JSON (content-type {ctype!r}). This usually means an auth error "
                f"or an XML-only endpoint (use prtg_get with as_text). Body: {snippet}"
            )


def _format_error(status: int, resp: httpx.Response) -> str:
    snippet = resp.text[:200].strip().replace("\n", " ") if resp.text else ""
    if status == 401:
        return (
            "PRTG 401 — authentication failed. Check PRTG_API_TOKEN (or PRTG_USERNAME / "
            "PRTG_PASSHASH) and that the account/key has read access."
        )
    if status == 403:
        return "PRTG 403 — the account/API key lacks permission for this object."
    if status == 404:
        return "PRTG 404 — no such endpoint or object id."
    detail = f" {snippet}" if snippet else ""
    return f"PRTG HTTP {status}.{detail}".rstrip()
