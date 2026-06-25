"""Async FortiGate FortiOS REST API client (read-only, API-token auth).

A single ``httpx.AsyncClient`` is shared across all tools. Authentication is a static REST API
token sent as ``Authorization: Bearer <token>`` on every request — there is no session/login to
maintain. FortiOS response envelopes are validated (``status``/``http_status``) and a failure
becomes a clean ``FortiError`` so tools never leak tracebacks to the model.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class FortiError(RuntimeError):
    """A clean, user-facing error for a failed FortiOS API request."""

    def __init__(self, message: str, *, status: int | None = None, fos_message: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.fos_message = fos_message


class FortiClient:
    """Minimal async client for the FortiGate FortiOS REST API (GET only)."""

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
        return {"Authorization": f"Bearer {self._settings.api_token}"}

    # ---- requests -------------------------------------------------------

    async def get(
        self,
        tree: str,
        path: str,
        *,
        vdom: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """GET a FortiOS resource; returns the unwrapped envelope dict (data under ``results``).

        ``tree`` is ``cmdb`` (configuration) or ``monitor`` (live status). The configured VDOM is
        applied unless ``vdom`` overrides it.
        """
        if tree not in ("cmdb", "monitor"):
            raise ValueError(f"tree must be 'cmdb' or 'monitor'; got {tree!r}.")
        url = f"{self._settings.api_base}/{tree}/{path.lstrip('/')}"
        return await self._request("GET", url, vdom=vdom, params=params)

    async def get_raw(
        self, path: str, *, vdom: str | None = None, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Escape hatch: GET an arbitrary FortiOS path (``cmdb/...`` / ``monitor/...`` / ``/api/v2/...``)."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"fortios_get only allows the configured host ({self._settings.base_origin})."
                )
            url = path
        else:
            p = path.lstrip("/")
            if p.startswith("api/v2/"):
                p = p[len("api/v2/") :]
            url = f"{self._settings.api_base}/{p}"
        return await self._request("GET", url, vdom=vdom, params=params)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        vdom: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        q: dict[str, Any] = dict(params or {})
        effective_vdom = self._settings.vdom if vdom is None else vdom
        if effective_vdom:
            q.setdefault("vdom", effective_vdom)

        client = await self._http()
        try:
            resp = await client.request(method, url, params=q, headers=self._auth_headers())
        except httpx.HTTPError as exc:
            raise FortiError(f"Network error calling FortiGate {url}: {exc}") from exc

        env = _try_json(resp)
        status = resp.status_code
        if status >= 400 or (isinstance(env, dict) and env.get("status") == "error"):
            raise FortiError(
                _format_error(status, env, resp),
                status=status,
                fos_message=(env.get("message", "") if isinstance(env, dict) else ""),
            )
        return env if isinstance(env, dict) else {"results": env}


def _try_json(resp: httpx.Response) -> dict[str, Any]:
    if not resp.content:
        return {}
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {"results": data}


def _format_error(status: int, env: dict[str, Any], resp: httpx.Response) -> str:
    msg = ""
    if isinstance(env, dict):
        msg = env.get("message") or env.get("error") or ""
    if status == 401:
        return (
            "FortiGate 401 — API token invalid/expired, or the source IP is not in the REST API "
            "admin's trusted hosts. Check FORTIGATE_API_TOKEN and the admin's trusthost."
        )
    if status == 403:
        return (
            "FortiGate 403 — the REST API admin's access profile lacks read permission for this "
            "resource (grant read on the relevant permission group, e.g. fwgrp/sysgrp/netgrp)."
        )
    if status == 404:
        return "FortiGate 404 — no resource at that API path (or it does not exist in this VDOM)."
    if status == 424:
        return f"FortiGate 424 — failed dependency. {msg}".rstrip()
    if status == 429:
        return "FortiGate 429 — too many requests; back off and retry."
    detail = msg or (resp.text[:300] if resp.text else "")
    detail = f": {detail}" if detail else ""
    return f"FortiGate API {status}{detail}".rstrip()
