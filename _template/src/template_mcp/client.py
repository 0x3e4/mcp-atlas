"""Async HTTP client for the upstream API.

A single ``httpx.AsyncClient`` is shared across all tools. Authentication is applied per request
(here: a static API key sent as a bearer token). All HTTP and network failures are converted to
``ApiError`` with a short, actionable message so tools never leak tracebacks to the model.

To adapt this to your API, change:
  * ``_auth_headers`` — bearer token, ``X-Api-Key`` header, HTTP Basic, etc.
  * ``_format_error``  — map the upstream error envelope to a clean message.

If your API uses short-lived tokens (OAuth2 client-credentials, a login endpoint returning a JWT,
…), cache the token and clear it in ``_refresh_auth`` so the retry-once-on-401 in ``_request``
fetches a fresh one. See ``defender-mcp/graph.py`` and ``wazuh-mcp/manager.py`` for worked examples.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class ApiError(RuntimeError):
    """A clean, user-facing error for a failed upstream request."""


class ApiClient:
    """Minimal async REST client for the upstream API."""

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

    # ---- authentication -------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        # Swap this for your API's scheme, e.g. {"X-Api-Key": self._settings.api_key}.
        return {"Authorization": f"Bearer {self._settings.api_key}"}

    def _refresh_auth(self) -> None:
        # Static API key: nothing to refresh. If your API uses short-lived tokens, clear the cached
        # token here so ``_auth_headers`` fetches a fresh one on the retry (see module docstring).
        pass

    # ---- requests -------------------------------------------------------

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET ``path`` (relative to the base URL, or an absolute URL on the same host)."""
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json: Any) -> Any:
        """POST ``json`` to ``path``."""
        return await self._request("POST", path, json=json)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
    ) -> Any:
        url = self._url(path)
        client = await self._http()
        # Two attempts: the second runs after ``_refresh_auth`` in case the first 401'd on a
        # stale token. With a static key the retry simply re-sends and then raises.
        for attempt in (1, 2):
            headers = self._auth_headers()
            if json is not None:
                headers["Content-Type"] = "application/json; charset=utf-8"
            try:
                resp = await client.request(method, url, params=params, json=json, headers=headers)
            except httpx.HTTPError as exc:
                raise ApiError(f"Network error calling {method} {path}: {exc}") from exc

            if resp.status_code == 401 and attempt == 1:
                self._refresh_auth()
                continue
            if resp.status_code >= 400:
                raise ApiError(_format_error(resp))
            if resp.status_code == 204 or not resp.content:
                return None
            return resp.json()
        # Loop always returns or raises above.
        raise ApiError("Request failed after retry.")  # pragma: no cover

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return f"{self._settings.base_url}/{path.lstrip('/')}"


def _format_error(resp: httpx.Response) -> str:
    status = resp.status_code
    detail = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            # Common error-envelope shapes; adjust to your API.
            err = body.get("error") or body.get("message") or ""
            if isinstance(err, dict):
                detail = err.get("message") or err.get("code") or ""
            elif isinstance(err, str):
                detail = err
    except ValueError:
        detail = resp.text[:300]

    if status == 401:
        return f"401 Unauthorized — check TEMPLATE_API_KEY (and base URL). {detail}".strip()
    if status == 403:
        return f"403 Forbidden — the credential lacks permission for this call. {detail}".strip()
    if status == 404:
        return f"404 Not Found — {detail or 'no resource at that path'}.".strip()
    if status == 429:
        retry_after = resp.headers.get("Retry-After")
        hint = f" Retry-After={retry_after}s." if retry_after else ""
        return f"429 Too Many Requests — back off and retry.{hint}".strip()
    detail = f" {detail}" if detail else ""
    return f"Upstream {status} error.{detail}".strip()
