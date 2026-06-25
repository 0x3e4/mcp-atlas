"""Async Snipe-IT REST API client.

A single ``httpx.AsyncClient`` is shared across all tools. Auth is a Bearer token plus
``Accept: application/json``. List endpoints return ``{"total": N, "rows": [...]}``; single GETs
return the object directly; writes return ``{"status": "success"|"error", "messages": ..., "payload":
...}``.

The big Snipe-IT gotcha: it returns **HTTP 200 even on errors**, signalling failure via
``status: "error"`` in the body — so ``_request`` inspects the body and raises ``SnipeError`` on
``status == "error"`` regardless of the HTTP code. Writes (POST/PATCH) are gated at the tool layer by
``SNIPEIT_ALLOW_WRITE``.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class SnipeError(RuntimeError):
    """A clean, user-facing error for a failed Snipe-IT API request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class SnipeClient:
    """Minimal async client for the Snipe-IT REST API."""

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
        """GET a resource; ``path`` is relative to ``/api/v1`` (e.g. ``hardware`` or ``hardware/12``)."""
        return await self._request("GET", self._url(path), params=params)

    async def post(self, path: str, *, json: Any) -> Any:
        """POST ``json`` (write)."""
        return await self._request("POST", self._url(path), json=json)

    async def patch(self, path: str, *, json: Any) -> Any:
        """PATCH ``json`` (partial write)."""
        return await self._request("PATCH", self._url(path), json=json)

    async def get_raw(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Escape hatch: GET an arbitrary ``/api/v1/...`` path (or absolute URL on the same host)."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"snipeit_get only allows the configured host ({self._settings.base_origin})."
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
            raise SnipeError(f"Network error calling Snipe-IT {url}: {exc}") from exc

        data = _try_json(resp)
        if resp.status_code >= 400:
            raise SnipeError(_format_http_error(resp.status_code, data, resp), status=resp.status_code)
        if data is None:
            raise SnipeError(
                "Snipe-IT returned non-JSON (likely an HTML login page). Check SNIPEIT_TOKEN and that "
                "the request sends 'Accept: application/json'."
            )
        # HTTP-200-on-error: failures are signalled in the body, not the status code.
        if isinstance(data, dict) and data.get("status") == "error":
            raise SnipeError(_format_status_error(data), status=resp.status_code)
        return data


def _try_json(resp: httpx.Response) -> Any:
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        return None


def _flatten_messages(messages: Any) -> str:
    if isinstance(messages, dict):
        parts = []
        for field, errs in messages.items():
            if isinstance(errs, list):
                parts.append(f"{field}: {'; '.join(str(e) for e in errs)}")
            else:
                parts.append(f"{field}: {errs}")
        return " | ".join(parts)
    return str(messages) if messages else ""


def _format_status_error(data: dict[str, Any]) -> str:
    return f"Snipe-IT error: {_flatten_messages(data.get('messages')) or 'request failed'}".rstrip()


def _format_http_error(status: int, data: Any, resp: httpx.Response) -> str:
    msg = _flatten_messages(data.get("messages")) if isinstance(data, dict) else ""
    if status == 401:
        return "Snipe-IT 401 — token rejected. Check SNIPEIT_TOKEN (and that the token's user is active)."
    if status == 403:
        return f"Snipe-IT 403 — the token's user lacks permission for this action. {msg}".rstrip()
    if status == 404:
        return f"Snipe-IT 404 — not found. {msg}".rstrip()
    if status == 429:
        return "Snipe-IT 429 — rate limit exceeded (API_THROTTLE_PER_MINUTE); back off and retry."
    detail = msg or (resp.text[:300] if resp.text else "")
    detail = f": {detail}" if detail else ""
    return f"Snipe-IT API {status}{detail}".rstrip()
