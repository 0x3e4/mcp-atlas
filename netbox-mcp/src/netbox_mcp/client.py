"""Async NetBox REST API client (read-only, token auth).

A single ``httpx.AsyncClient`` is shared across all tools. List endpoints return
``{"count", "next", "previous", "results": [...]}``; single GETs return the object directly. NetBox
requires a trailing slash on endpoints, which this client adds. Failures become a clean
``NetBoxError`` (using NetBox's ``detail``/field errors) so tools never leak tracebacks to the model.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class NetBoxError(RuntimeError):
    """A clean, user-facing error for a failed NetBox API request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class NetBoxClient:
    """Minimal async client for the NetBox REST API (GET only)."""

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
        p = path.strip("/")
        return f"{self._settings.api_base}/{p}/"

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """GET a resource; ``path`` is relative to ``/api`` (e.g. ``dcim/devices`` or ``dcim/devices/5``)."""
        return await self._request(self._url(path), params=params)

    async def get_raw(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Escape hatch: GET an arbitrary ``/api/...`` path (or absolute URL on the same host)."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"netbox_get only allows the configured host ({self._settings.base_origin})."
                )
            url = path if path.endswith("/") or "?" in path else path + "/"
        else:
            p = path.lstrip("/")
            if p.startswith("api/"):
                p = p[len("api/") :]
            url = self._url(p)
        return await self._request(url, params=params)

    async def _request(self, url: str, *, params: dict[str, Any] | None = None) -> Any:
        client = await self._http()
        try:
            resp = await client.get(url, params=params, headers=self._settings.auth_headers)
        except httpx.HTTPError as exc:
            raise NetBoxError(f"Network error calling NetBox {url}: {exc}") from exc

        if resp.status_code >= 400:
            raise NetBoxError(_format_error(resp.status_code, resp), status=resp.status_code)
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            ctype = resp.headers.get("content-type", "")
            raise NetBoxError(
                f"Expected JSON from NetBox but got content-type {ctype!r} (HTTP {resp.status_code}). "
                "A trailing-slash redirect or an auth/HTML page is the usual cause."
            )


def _format_error(status: int, resp: httpx.Response) -> str:
    detail = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            detail = body.get("detail") or "; ".join(
                f"{k}: {v}" for k, v in body.items() if k != "detail"
            )
    except ValueError:
        detail = resp.text[:200]
    if status in (401, 403):
        return (
            f"NetBox {status} — authentication/permission failed. Check NETBOX_TOKEN and that its "
            f"user can view this object. {detail}".rstrip()
        )
    if status == 404:
        return f"NetBox 404 — not found (check the path and trailing slash). {detail}".rstrip()
    if status == 400:
        return f"NetBox 400 — bad request. {detail}".rstrip()
    detail = f": {detail}" if detail else ""
    return f"NetBox API {status}{detail}".rstrip()
