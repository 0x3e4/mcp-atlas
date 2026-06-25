"""Async NetScaler NITRO client with session-cookie or stateless auth.

A single ``httpx.AsyncClient`` is shared across all tools. In ``session`` mode the client logs in
once (``POST /nitro/v1/config/login``), caches the ``NITRO_AUTH_TOKEN`` session id, and transparently
re-logs-in and retries once when the appliance reports the session expired (NITRO errorcode 444 /
HTTP 401). In ``stateless`` mode it sends ``X-NITRO-USER`` / ``X-NITRO-PASS`` on every request and
never holds a session. NITRO response envelopes are unwrapped; a non-zero ``errorcode`` becomes a
clean ``NitroError`` so tools never leak tracebacks to the model.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from .config import Settings

# NITRO errorcode for an expired/killed session.
_SESSION_EXPIRED = 444


class NitroError(RuntimeError):
    """A clean, user-facing error for a failed NITRO request."""

    def __init__(
        self, message: str, *, errorcode: int | None = None, nitro_message: str = ""
    ) -> None:
        super().__init__(message)
        self.errorcode = errorcode
        self.nitro_message = nitro_message


class NitroClient:
    """Minimal async client for the NetScaler ADC NITRO REST API."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._sessionid: str | None = None

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
        # Best-effort logout to free the appliance session slot, then close the transport.
        if self._sessionid is not None:
            try:
                await self.logout()
            except NitroError:
                pass
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ---- authentication -------------------------------------------------

    async def _login(self) -> str:
        client = await self._http()
        body = {
            "login": {
                "username": self._settings.user,
                "password": self._settings.password,
                "timeout": self._settings.session_timeout,
            }
        }
        url = f"{self._settings.nitro_base}/config/login"
        try:
            resp = await client.post(
                url, json=body, headers={"Content-Type": "application/json"}
            )
        except httpx.HTTPError as exc:
            raise NitroError(f"Network error contacting the NITRO login endpoint: {exc}") from exc

        env = _try_json(resp)
        if resp.status_code >= 400:
            raise NitroError(_format_http_error(resp, env))
        code = env.get("errorcode")
        if code not in (0, None):
            raise NitroError(
                _format_nitro_error(env, login=True),
                errorcode=code,
                nitro_message=env.get("message", ""),
            )
        sessionid = env.get("sessionid")
        if not sessionid:
            raise NitroError("NITRO login succeeded but did not return a sessionid.")
        self._sessionid = sessionid
        return sessionid

    async def logout(self) -> None:
        """Best-effort session logout (session mode only)."""
        if self._settings.auth_mode != "session" or self._sessionid is None:
            return
        client = await self._http()
        url = f"{self._settings.nitro_base}/config/logout"
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"NITRO_AUTH_TOKEN={self._sessionid}",
        }
        try:
            await client.post(url, json={"logout": {}}, headers=headers)
        except httpx.HTTPError:
            pass
        finally:
            self._sessionid = None

    async def _auth_headers(self) -> dict[str, str]:
        if self._settings.auth_mode == "stateless":
            return {
                "X-NITRO-USER": self._settings.user,
                "X-NITRO-PASS": self._settings.password,
            }
        if self._sessionid is None:
            await self._login()
        return {"Cookie": f"NITRO_AUTH_TOKEN={self._sessionid}"}

    # ---- requests -------------------------------------------------------

    async def get(
        self,
        tree: str,
        resourcetype: str,
        *,
        resource_name: str | None = None,
        attrs: list[str] | tuple[str, ...] | None = None,
        filter: dict[str, Any] | None = None,
        count: bool = False,
        pagesize: int | None = None,
        pageno: int | None = None,
    ) -> dict[str, Any]:
        """GET a NITRO collection or single object; returns the unwrapped envelope dict.

        ``tree`` is ``config`` or ``stat``. The caller reads ``env[resourcetype]`` (the envelope key
        matches the resource type, including its casing — e.g. the stat ``Interface`` resource).
        """
        if tree not in ("config", "stat"):
            raise ValueError(f"tree must be 'config' or 'stat'; got {tree!r}.")
        path = f"{tree}/{resourcetype}"
        if resource_name:
            path += "/" + quote(resource_name, safe="")
        params: dict[str, Any] = {}
        if attrs:
            params["attrs"] = ",".join(attrs)
        if filter:
            params["filter"] = ",".join(f"{k}:{v}" for k, v in filter.items())
        if count:
            params["count"] = "yes"
        if pagesize is not None:
            params["pagesize"] = pagesize
        if pageno is not None:
            params["pageno"] = pageno
        return await self._request("GET", path, params=params)

    async def get_raw(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Escape hatch: GET an arbitrary NITRO path (e.g. ``config/route``) or absolute URL on the host."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"nitro_get only allows the configured host ({self._settings.base_origin})."
                )
            return await self._request("GET", path, params=params, absolute=True)
        return await self._request("GET", path.lstrip("/"), params=params)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        absolute: bool = False,
    ) -> dict[str, Any]:
        url = path if absolute else f"{self._settings.nitro_base}/{path}"
        client = await self._http()
        session_mode = self._settings.auth_mode == "session"
        # Two attempts: a 444/401 on the first forces a fresh login on the retry (session mode only).
        for attempt in (1, 2):
            headers = await self._auth_headers()
            try:
                resp = await client.request(method, url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise NitroError(f"Network error calling NITRO {path}: {exc}") from exc

            env = _try_json(resp)
            code = env.get("errorcode")

            if (resp.status_code == 401 or code == _SESSION_EXPIRED) and attempt == 1 and session_mode:
                self._sessionid = None  # force re-login on the retry
                continue
            if resp.status_code >= 400:
                raise NitroError(_format_http_error(resp, env))
            if code not in (0, None):
                raise NitroError(
                    _format_nitro_error(env), errorcode=code, nitro_message=env.get("message", "")
                )
            return env
        # Loop always returns or raises above.
        raise NitroError("NITRO request failed after a session refresh retry.")  # pragma: no cover


def _try_json(resp: httpx.Response) -> dict[str, Any]:
    if not resp.content:
        return {}
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _format_nitro_error(env: dict[str, Any], *, login: bool = False) -> str:
    code = env.get("errorcode")
    message = env.get("message", "") or ""
    if code == _SESSION_EXPIRED:
        return (
            "NITRO session expired and re-login failed — check NETSCALER_USER / NETSCALER_PASSWORD "
            "and that the account is not locked."
        )
    if code in (2138, 257):
        return (
            f"NITRO not authorized (errorcode {code}) — the system user needs the built-in "
            "'readonlypolicy' command policy bound for this resource."
        )
    if code == 1067:
        return (
            f"NITRO feature not enabled (errorcode {code}) — enable the relevant feature "
            "(e.g. GSLB, AppFW) on the appliance, or this resource is unavailable."
        )
    if code in (258, 461, 462):
        return f"NITRO resource not found (errorcode {code}): {message}".rstrip(": ").rstrip()
    if login and code == 354:
        return (
            "NITRO login failed (errorcode 354) — invalid credentials; check NETSCALER_USER / "
            "NETSCALER_PASSWORD."
        )
    return f"NITRO error {code}: {message}".rstrip(": ").rstrip()


def _format_http_error(resp: httpx.Response, env: dict[str, Any]) -> str:
    # Prefer a NITRO envelope message when the body carries one.
    if env.get("errorcode") not in (0, None):
        return _format_nitro_error(env)
    status = resp.status_code
    if status == 401:
        return (
            "NITRO 401 — credentials rejected. Verify NETSCALER_USER / NETSCALER_PASSWORD "
            "(and NETSCALER_AUTH_MODE)."
        )
    if status == 403:
        return (
            "NITRO 403 — the system user lacks permission; bind the built-in 'readonlypolicy' "
            "command policy to it."
        )
    if status == 404:
        return "NITRO 404 — no resource at that NITRO path."
    if status == 503:
        return (
            "NITRO 503 — appliance busy, or this node is not serving config (e.g. a secondary HA "
            "node). Point NETSCALER_BASE_URL at the primary / HA management IP."
        )
    body = resp.text[:300] if resp.text else ""
    detail = f": {body}" if body else ""
    return f"NITRO HTTP {status}{detail}".rstrip()
