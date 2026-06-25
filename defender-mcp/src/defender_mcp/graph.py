"""Async Microsoft Graph client with a cached client-credentials bearer token.

A single ``httpx.AsyncClient`` is shared across all tools. The bearer token is cached and
transparently re-fetched on expiry or on a 401 (retried once). All HTTP failures are converted to
``GraphError`` with a short, actionable message so tools never leak tracebacks to the model.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .config import Settings


class GraphError(RuntimeError):
    """A clean, user-facing error for a failed Graph or Entra token request."""


class GraphClient:
    """Minimal async client for the Microsoft Graph security API."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expiry: float = 0.0

    @property
    def settings(self) -> Settings:
        return self._settings

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._settings.timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ---- authentication -------------------------------------------------

    async def _ensure_token(self, force: bool = False) -> str:
        if not force and self._token and time.monotonic() < self._token_expiry:
            return self._token

        client = await self._http()
        # httpx form-encodes (and URL-encodes) the body, including the secret.
        data = {
            "grant_type": "client_credentials",
            "client_id": self._settings.client_id,
            "client_secret": self._settings.client_secret,
            "scope": self._settings.scope,
        }
        try:
            resp = await client.post(self._settings.token_url, data=data)
        except httpx.HTTPError as exc:
            raise GraphError(f"Network error contacting the Entra token endpoint: {exc}") from exc

        if resp.status_code != 200:
            raise GraphError(_format_token_error(resp))

        payload = resp.json()
        token = payload.get("access_token")
        if not token:
            raise GraphError("Entra token response did not contain an access_token.")
        expires_in = float(payload.get("expires_in", 3600))
        # Refresh a minute early; never cache for less than 30s.
        self._token = token
        self._token_expiry = time.monotonic() + max(expires_in - 60.0, 30.0)
        return token

    # ---- requests -------------------------------------------------------

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET ``path`` (relative to the Graph base URL, or an absolute Graph URL)."""
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json: Any) -> Any:
        """POST ``json`` to ``path``."""
        return await self._request("POST", path, json=json)

    async def run_hunting_query(self, query: str, timespan: str | None = None) -> dict[str, Any]:
        """Run an advanced-hunting KQL query via ``POST /security/runHuntingQuery``.

        Note the PascalCase body keys required by Graph: ``Query`` and (optional) ``Timespan``.
        Returns the raw ``{"schema": [...], "results": [...]}`` payload.
        """
        body: dict[str, Any] = {"Query": query}
        if timespan:
            body["Timespan"] = timespan
        result = await self.post("/security/runHuntingQuery", json=body)
        if not isinstance(result, dict):
            return {"schema": [], "results": []}
        result.setdefault("schema", [])
        result.setdefault("results", [])
        return result

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
    ) -> Any:
        url = self._url(path)
        # Two attempts: the second forces a fresh token in case the first was rejected (401).
        for attempt in (1, 2):
            token = await self._ensure_token(force=(attempt == 2))
            client = await self._http()
            headers = {"Authorization": f"Bearer {token}"}
            if json is not None:
                headers["Content-Type"] = "application/json; charset=utf-8"
            try:
                resp = await client.request(method, url, params=params, json=json, headers=headers)
            except httpx.HTTPError as exc:
                raise GraphError(f"Network error calling Graph {path}: {exc}") from exc

            if resp.status_code == 401 and attempt == 1:
                self._token = None  # force refresh on the retry
                continue
            if resp.status_code >= 400:
                raise GraphError(_format_graph_error(resp))
            if resp.status_code == 204 or not resp.content:
                return None
            return resp.json()
        # Loop always returns or raises above.
        raise GraphError("Graph request failed after retry.")  # pragma: no cover

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return f"{self._settings.graph_base_url}/{path.lstrip('/')}"


def _format_token_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return f"Entra token error (HTTP {resp.status_code}): {resp.text[:300]}"
    error = body.get("error", "unknown_error")
    desc = body.get("error_description", "") or ""
    first_line = desc.splitlines()[0] if desc else ""
    hint = ""
    if "AADSTS7000215" in desc or "AADSTS7000222" in desc:
        hint = " (check/rotate the client secret)"
    elif "AADSTS700016" in desc or error == "unauthorized_client":
        hint = " (check the client/tenant id)"
    elif "AADSTS65001" in desc:
        hint = " (admin consent has not been granted)"
    return f"Entra token error '{error}' (HTTP {resp.status_code}): {first_line}{hint}"


def _format_graph_error(resp: httpx.Response) -> str:
    status = resp.status_code
    code = ""
    message = ""
    try:
        body = resp.json()
        err = body.get("error", {})
        if isinstance(err, dict):
            code = err.get("code", "") or ""
            message = err.get("message", "") or ""
        elif isinstance(err, str):
            code = err
            message = body.get("error_description", "") or ""
    except ValueError:
        message = resp.text[:300]

    if status == 403 or code == "Authorization_RequestDenied":
        return (
            "Graph 403 Authorization_RequestDenied — the app registration is missing an "
            "admin-consented application permission for this call. Read-only permissions needed: "
            "ThreatHunting.Read.All (advanced hunting / devices / vulnerabilities), "
            "SecurityAlert.Read.All (alerts), SecurityIncident.Read.All (incidents). "
            "Grant the permission in Entra and click 'Grant admin consent', then retry."
        )
    if status == 401:
        return (
            f"Graph 401 — bearer token rejected ({code or 'InvalidAuthenticationToken'}). "
            "Verify DEFENDER_TENANT_ID / DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET."
        )
    if status == 429:
        retry_after = resp.headers.get("Retry-After")
        hint = f" Retry-After={retry_after}s." if retry_after else ""
        return (
            "Graph 429 — throttled (or advanced-hunting CPU/rate limit reached). "
            f"Back off and retry.{hint}"
        )
    detail = f" {code}: {message}".rstrip() if (code or message) else ""
    return f"Graph {status} error.{detail}".strip()
