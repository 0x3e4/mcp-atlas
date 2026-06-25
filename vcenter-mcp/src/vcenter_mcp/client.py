"""Async VMware vCenter (vSphere Automation REST API, the new ``/api``) client (read-only).

A single ``httpx.AsyncClient`` is shared across all tools. Auth is session-based: ``POST /api/session``
with HTTP Basic returns a session id (a JSON string), sent on subsequent calls as the
``vmware-api-session-id`` header. The session is re-established transparently on a 401 (retried once).
The new ``/api`` returns objects/arrays directly (no ``{value}`` wrapper). Failures become a clean
``VCenterError`` so tools never leak tracebacks to the model.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class VCenterError(RuntimeError):
    """A clean, user-facing error for a failed vCenter API request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class VCenterClient:
    """Minimal async client for the vSphere Automation REST API (GET only)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None

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
        # Best-effort logout to release the session, then close the transport.
        if self._session_id is not None:
            try:
                client = await self._http()
                await client.delete(
                    f"{self._settings.api_base}/session",
                    headers={"vmware-api-session-id": self._session_id},
                )
            except httpx.HTTPError:
                pass
            self._session_id = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ---- authentication -------------------------------------------------

    async def _login(self) -> str:
        client = await self._http()
        url = f"{self._settings.api_base}/session"
        try:
            resp = await client.post(
                url, auth=httpx.BasicAuth(self._settings.username, self._settings.password)
            )
        except httpx.HTTPError as exc:
            raise VCenterError(f"Network error contacting vCenter session endpoint: {exc}") from exc
        if resp.status_code >= 400:
            if resp.status_code == 401:
                raise VCenterError(
                    "vCenter login failed (401) — check VCENTER_USERNAME / VCENTER_PASSWORD.",
                    status=401,
                )
            raise VCenterError(_format_error(resp), status=resp.status_code)
        sid: str | None = None
        if resp.content:
            try:
                body = resp.json()
                if isinstance(body, str):
                    sid = body
            except ValueError:
                sid = None
        sid = sid or resp.headers.get("vmware-api-session-id")
        if not sid:
            raise VCenterError("vCenter login did not return a session id.")
        self._session_id = sid
        return sid

    # ---- requests -------------------------------------------------------

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """GET a resource; ``path`` is relative to ``/api`` (e.g. ``vcenter/vm``)."""
        return await self._request("GET", f"{self._settings.api_base}/{path.lstrip('/')}", params=params)

    async def get_raw(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """Escape hatch: GET an arbitrary ``/api/...`` path (or absolute URL on the same host)."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"vcenter_get only allows the configured host ({self._settings.base_origin})."
                )
            url = path
        else:
            p = path.lstrip("/")
            if p.startswith("api/"):
                p = p[len("api/") :]
            url = f"{self._settings.api_base}/{p}"
        return await self._request("GET", url, params=params)

    async def _request(self, method: str, url: str, *, params: dict[str, Any] | None = None) -> Any:
        client = await self._http()
        for attempt in (1, 2):
            if self._session_id is None:
                await self._login()
            headers = {"vmware-api-session-id": self._session_id}
            try:
                resp = await client.request(method, url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise VCenterError(f"Network error calling vCenter {url}: {exc}") from exc

            if resp.status_code == 401 and attempt == 1:
                self._session_id = None  # session expired — re-login on retry
                continue
            if resp.status_code >= 400:
                raise VCenterError(_format_error(resp), status=resp.status_code)
            if resp.status_code == 204 or not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                raise VCenterError(
                    f"Expected JSON from vCenter (HTTP {resp.status_code}); got non-JSON body."
                )
        # Loop always returns or raises above.
        raise VCenterError("vCenter request failed after a session refresh retry.")  # pragma: no cover


def _format_error(resp: httpx.Response) -> str:
    status = resp.status_code
    msg = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            msgs = body.get("messages")
            if isinstance(msgs, list) and msgs and isinstance(msgs[0], dict):
                msg = msgs[0].get("default_message", "") or ""
            etype = body.get("error_type")
            if etype and not msg:
                msg = str(etype)
    except ValueError:
        msg = resp.text[:200]
    if status == 401:
        return "vCenter 401 — session invalid or expired (re-login failed). Check credentials."
    if status == 403:
        return f"vCenter 403 — the account lacks permission for this object. {msg}".rstrip()
    if status == 404:
        return f"vCenter 404 — not found. {msg}".rstrip()
    if status == 503:
        return f"vCenter 503 — service unavailable. {msg}".rstrip()
    detail = f": {msg}" if msg else ""
    return f"vCenter API {status}{detail}".rstrip()
