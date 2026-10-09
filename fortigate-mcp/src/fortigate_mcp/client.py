"""Async FortiGate FortiOS REST API client (API-token auth; GET plus opt-in cmdb writes).

A single ``httpx.AsyncClient`` is shared across all tools. Authentication is a static REST API
token sent as ``Authorization: Bearer <token>`` on every request — there is no session/login to
maintain. FortiOS response envelopes are validated (``status``/``http_status``) and a failure
becomes a clean ``FortiError`` so tools never leak tracebacks to the model; FortiOS's numeric
``error`` code and ``cli_error`` text are included in the message.
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
    """Minimal async client for the FortiGate FortiOS REST API (GET, plus POST/PUT on cmdb)."""

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

    async def post(self, path: str, *, json: Any, vdom: str | None = None) -> dict[str, Any]:
        """POST ``json`` to a cmdb table (write: create an object)."""
        url = f"{self._settings.api_base}/cmdb/{path.lstrip('/')}"
        return await self._request("POST", url, vdom=vdom, json=json)

    async def put(self, path: str, *, json: Any, vdom: str | None = None) -> dict[str, Any]:
        """PUT ``json`` to a cmdb object (write: only the given attributes change)."""
        url = f"{self._settings.api_base}/cmdb/{path.lstrip('/')}"
        return await self._request("PUT", url, vdom=vdom, json=json)

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
        json: Any = None,
    ) -> dict[str, Any]:
        q: dict[str, Any] = dict(params or {})
        effective_vdom = self._settings.vdom if vdom is None else vdom
        if effective_vdom:
            q.setdefault("vdom", effective_vdom)

        client = await self._http()
        try:
            resp = await client.request(method, url, params=q, json=json, headers=self._auth_headers())
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


# Common FortiOS cmdb error codes (the envelope's numeric ``error`` field).
_FOS_ERRORS = {
    -1: "invalid length of value",
    -3: "entry not found",
    -5: "a duplicate entry already exists",
    -8: "invalid IP address",
    -14: "permission denied, insufficient privileges",
    -20: "blank entry",
    -651: "input value is invalid",
    -703: "unknown keyword",
}


def _fos_detail(env: dict[str, Any]) -> str:
    """FortiOS's own error detail: message, numeric ``error`` code (+ meaning) and ``cli_error``."""
    if not isinstance(env, dict):
        return ""
    parts: list[str] = []
    if env.get("message"):
        parts.append(str(env["message"]))
    code = env.get("error")
    if isinstance(code, int) and not isinstance(code, bool):
        meaning = _FOS_ERRORS.get(code)
        parts.append(f"error {code}" + (f" ({meaning})" if meaning else ""))
    elif code:
        parts.append(str(code))
    if env.get("cli_error"):
        parts.append(f"cli_error: {str(env['cli_error']).strip()}")
    return "; ".join(parts)


def _format_error(status: int, env: dict[str, Any], resp: httpx.Response) -> str:
    msg = _fos_detail(env)
    if status == 401:
        return (
            "FortiGate 401 — API token invalid/expired, or the source IP is not in the REST API "
            "admin's trusted hosts. Check FORTIGATE_API_TOKEN and the admin's trusthost."
        )
    if status == 403:
        return (
            "FortiGate 403 — the REST API admin's access profile lacks permission for this resource "
            "(grant read on the relevant permission group, e.g. fwgrp/sysgrp/netgrp; write tools need "
            "read-write on Firewall)."
        )
    if status == 404:
        tail = f" ({msg})" if msg else ""
        return f"FortiGate 404 — no resource at that API path (or it does not exist in this VDOM){tail}."
    if status == 424:
        return f"FortiGate 424 — failed dependency. {msg}".rstrip()
    if status == 429:
        return "FortiGate 429 — too many requests; back off and retry."
    detail = msg or (resp.text[:300] if resp.text else "")
    detail = f": {detail}" if detail else ""
    return f"FortiGate API {status}{detail}".rstrip()
