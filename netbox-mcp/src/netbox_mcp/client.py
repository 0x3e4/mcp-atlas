"""Async NetBox REST API client (token auth; GET plus the POST/PATCH the opt-in write tools use).

A single ``httpx.AsyncClient`` is shared across all tools. List endpoints return
``{"count", "next", "previous", "results": [...]}``; single GETs return the object directly. NetBox
requires a trailing slash on endpoints, which this client adds. Failures become a clean
``NetBoxError`` (using NetBox's ``detail`` and per-field validation errors) so tools never leak
tracebacks to the model.
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
    """Minimal async client for the NetBox REST API (GET; POST/PATCH for the write tools)."""

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
        return await self._request("GET", self._url(path), params=params)

    async def post(self, path: str, *, json: Any) -> Any:
        """POST ``json`` (write)."""
        return await self._request("POST", self._url(path), json=json)

    async def patch(self, path: str, *, json: Any) -> Any:
        """PATCH ``json`` (write; only the given fields change)."""
        return await self._request("PATCH", self._url(path), json=json)

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
        return await self._request("GET", url, params=params)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
    ) -> Any:
        client = await self._http()
        try:
            resp = await client.request(
                method, url, params=params, json=json, headers=self._settings.auth_headers
            )
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


def _flatten(errors: Any, prefix: str = "") -> list[str]:
    """NetBox/DRF validation errors → ``["field: msg", ...]``.

    Handles ``{field: [msgs]}``, nested field dicts, lists of those (bulk/positional) and the
    ``{"detail", "errors": [{"index", "errors"}]}`` shape.
    """
    if isinstance(errors, dict):
        if "index" in errors and "errors" in errors:
            return _flatten(errors["errors"], f"{prefix}[{errors['index']}] ")
        out: list[str] = []
        for key, value in errors.items():
            if key == "errors":
                out += _flatten(value, prefix)
            elif key != "detail":
                out += _flatten(value, f"{prefix}{key}: " if key != "non_field_errors" else prefix)
        return out
    if isinstance(errors, list):
        if all(not isinstance(e, (dict, list)) for e in errors):
            return [f"{prefix}{' '.join(str(e) for e in errors)}"] if errors else []
        out = []
        for item in errors:
            out += _flatten(item, prefix)
        return out
    return [f"{prefix}{errors}"]


def _format_error(status: int, resp: httpx.Response) -> str:
    detail = ""
    try:
        body = resp.json()
        parts = _flatten(body)
        top = body.get("detail") if isinstance(body, dict) else None
        detail = "; ".join(([str(top)] if top else []) + parts)
    except ValueError:
        detail = resp.text[:200]
    if status in (401, 403):
        return (
            f"NetBox {status} — authentication/permission failed. Check NETBOX_TOKEN, that its user "
            f"has the object permission (view, or add/change for writes) and, for writes, that the "
            f"token is write-enabled. {detail}".rstrip()
        )
    if status == 404:
        return f"NetBox 404 — not found (check the path/id and trailing slash). {detail}".rstrip()
    if status == 400:
        return f"NetBox 400 — validation failed. {detail}".rstrip()
    if status == 409:
        return f"NetBox 409 — conflict. {detail}".rstrip()
    detail = f": {detail}" if detail else ""
    return f"NetBox API {status}{detail}".rstrip()
