"""Async client for the NetScaler Console NITRO API (on-prem or the Console service).

- Console resources: ``<base>/nitro/v2/config/<resource>`` (cloud: ``<base>/massvc/<customer>/nitro/v2/…``).
- Per-ADC calls through the Console (API proxy): ``<base>/nitro/v1/<config|stat>/<resource>`` with the
  ``MPS-API-PROXY`` instance headers; the Console forwards them to that managed instance, using its
  stored instance profile credentials unless ``NETSCALER_CONSOLE_INSTANCE_USERNAME/_PASSWORD`` are set.

Auth on-prem: ``X-NITRO-USER`` / ``X-NITRO-PASS`` on every Console request. The API proxy does not take
them ("Invalid Session ID in APIProxy request"): proxied calls use a session from
``POST /nitro/v1/config/login``, sent as the ``SESSID`` header and as a cookie (the docs show both), and
renewed once on 401. Cloud: a Citrix Cloud bearer token (``CwsAuth bearer=…``) from the API client,
refreshed on 401.
NITRO answers ``{"errorcode": 0, "message": "Done", "<resource>": [...]}``; a non-zero errorcode or an
HTTP error becomes a ``ConsoleError`` — a ``ToolError``, so the model sees the message.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from .config import Settings


class ConsoleError(ToolError):
    """A clean, user-facing error for a failed Console / NITRO request (reaches the model as the tool error)."""

    def __init__(self, message: str, *, status: int | None = None, errorcode: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.errorcode = errorcode


class ConsoleClient:
    """Minimal async client for the NetScaler Console NITRO API."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expiry = 0.0
        self._session: str | None = None
        self._session_lock = asyncio.Lock()

    @property
    def settings(self) -> Settings:
        return self._settings

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._settings.timeout, verify=self._settings.httpx_verify,
                                             follow_redirects=False)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            if self._session:
                try:  # best effort: don't leave the proxy session open on the Console
                    await self._client.post(f"{self._settings.base_url}/nitro/v1/config/logout", json={"logout": {}},
                                            headers={"Accept": "application/json", **_session_headers(self._session)})
                except httpx.HTTPError:
                    pass
                self._session = None
            await self._client.aclose()
            self._client = None

    async def _proxy_session(self, *, stale: str | None = None) -> str:
        """Session id for API-proxy calls (on-prem). ``stale``: the id that just got a 401 — log in again
        unless a parallel call already did."""
        async with self._session_lock:
            if self._session and self._session != stale:
                return self._session
            s = self._settings
            client = await self._http()
            try:
                resp = await client.post(f"{s.base_url}/nitro/v1/config/login",
                                         json={"login": {"username": s.username, "password": s.password}},
                                         headers={"Accept": "application/json"})
            except httpx.HTTPError as exc:
                raise ConsoleError(f"Network error logging in to the Console: {exc}") from exc
            data = _json(resp)
            code = data.get("errorcode")
            if resp.status_code >= 400 or (isinstance(code, int) and code != 0):
                raise ConsoleError("Console login for the API proxy failed: " + _format_error(resp, data),
                                   status=resp.status_code, errorcode=code if isinstance(code, int) else None)
            sid = _session_id(data)
            if not sid:
                raise ConsoleError("Console login answered without a sessionid; the API proxy needs one.")
            self._session = sid
            return sid

    async def _auth_headers(self, *, refresh: bool = False) -> dict[str, str]:
        s = self._settings
        if not s.cloud:
            return {"X-NITRO-USER": s.username, "X-NITRO-PASS": s.password}
        if refresh or not self._token or time.monotonic() > self._token_expiry:
            client = await self._http()
            url = f"https://api-{s.cloud_region}.cloud.com/cctrustoauth2/root/tokens/clients"
            try:
                resp = await client.post(url, data={"grant_type": "client_credentials", "client_id": s.client_id,
                                                    "client_secret": s.client_secret})
            except httpx.HTTPError as exc:
                raise ConsoleError(f"Network error getting a Citrix Cloud token: {exc}") from exc
            if resp.status_code >= 400:
                raise ConsoleError(f"Citrix Cloud token request failed ({resp.status_code}): check "
                                   "NETSCALER_CONSOLE_CLIENT_ID / _CLIENT_SECRET / _CLOUD_REGION.", status=resp.status_code)
            body = resp.json()
            self._token = body.get("access_token")
            self._token_expiry = time.monotonic() + max(60, int(body.get("expires_in") or 3600) - 120)
        return {"Authorization": f"CwsAuth bearer={self._token}", "isCloud": "true"}

    def _proxy_headers(self, instance: str) -> dict[str, str]:
        """Headers that make the Console forward a NITRO call to one managed ADC instance.

        The docs and NetScaler's Ansible collection spell them differently (MPS-API-PROXY-… vs
        _MPS_API_PROXY_…); both forms are sent.
        """
        value = instance.strip()
        try:
            ipaddress.ip_address(value)
            kind = "IP"
        except ValueError:
            kind = "NAME"
        out = {f"MPS-API-PROXY-MANAGED-INSTANCE-{kind}": value, f"_MPS_API_PROXY_MANAGED_INSTANCE_{kind}": value}
        s = self._settings
        if s.instance_username:
            out.update({"MPS-API-PROXY-MANAGED-INSTANCE-USERNAME": s.instance_username,
                        "_MPS_API_PROXY_MANAGED_INSTANCE_USERNAME": s.instance_username,
                        "MPS-API-PROXY-MANAGED-INSTANCE-PASSWORD": s.instance_password,
                        "_MPS_API_PROXY_MANAGED_INSTANCE_PASSWORD": s.instance_password})
        return out

    async def _send(self, method: str, url: str, *, params: dict[str, Any] | None = None, json: Any = None,
                    headers: dict[str, str] | None = None, proxy: bool = False) -> dict[str, Any]:
        client = await self._http()
        session = proxy and not self._settings.cloud
        sid: str | None = None
        for attempt in (0, 1):
            if session:
                sid = await self._proxy_session(stale=sid)
                auth = _session_headers(sid)
            else:
                auth = await self._auth_headers(refresh=attempt == 1)
            try:
                resp = await client.request(method, url, params=params, json=json,
                                            headers={"Accept": "application/json", **auth, **(headers or {})})
            except httpx.HTTPError as exc:
                raise ConsoleError(f"Network error calling the Console at {url}: {exc}") from exc
            if resp.status_code == 401 and (self._settings.cloud or session) and attempt == 0:
                continue  # token / session expired: get a new one once
            break
        data = _json(resp)
        code = data.get("errorcode") if isinstance(data, dict) else None
        if resp.status_code >= 400 or (isinstance(code, int) and code != 0):
            raise ConsoleError(_format_error(resp, data), status=resp.status_code,
                               errorcode=code if isinstance(code, int) else None)
        return data

    # ---- Console resources -------------------------------------------------------------

    async def get(self, resource: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._send("GET", f"{self._settings.nitro_base}/{resource.lstrip('/')}", params=params)

    async def post(self, resource: str, *, json: Any = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._send("POST", f"{self._settings.nitro_base}/{resource.lstrip('/')}", params=params,
                                json=json if json is not None else {})

    async def delete(self, resource: str) -> dict[str, Any]:
        return await self._send("DELETE", f"{self._settings.nitro_base}/{resource.lstrip('/')}")

    # ---- one ADC instance, through the Console (API proxy) ---------------------------------

    async def instance(self, method: str, instance: str, path: str, *, params: dict[str, Any] | None = None,
                       json: Any = None) -> dict[str, Any]:
        """``path`` like ``config/lbvserver/web`` or ``stat/lbvserver``; sent to /nitro/v1/<path>."""
        url = f"{self._settings.base_url}/nitro/v1/{path.lstrip('/')}"
        return await self._send(method, url, params=params, json=json, headers=self._proxy_headers(instance), proxy=True)


def _session_headers(sid: str) -> dict[str, str]:
    return {"SESSID": sid, "Cookie": f"SESSID={sid}; NITRO_AUTH_TOKEN={sid}"}


def _session_id(data: dict[str, Any]) -> str | None:
    """``sessionid`` at the top level or in ``{"login": [{"sessionid": …}]}``."""
    if data.get("sessionid"):
        return str(data["sessionid"])
    login = data.get("login")
    for row in login if isinstance(login, list) else [login]:
        if isinstance(row, dict) and row.get("sessionid"):
            return str(row["sessionid"])
    return None


def _json(resp: httpx.Response) -> dict[str, Any]:
    if not resp.content:
        return {}
    try:
        data = resp.json()
    except ValueError:
        return {"text": resp.text[:2000]}
    return data if isinstance(data, dict) else {"items": data}


def _format_error(resp: httpx.Response, data: dict[str, Any]) -> str:
    status = resp.status_code
    msg = str(data.get("message") or "").strip() if isinstance(data, dict) else ""
    code = data.get("errorcode") if isinstance(data, dict) else None
    tail = f" Console says: {msg}" + (f" (errorcode {code})" if code not in (None, 0) else "") if msg else ""
    if 300 <= status < 400:
        return f"Console answered {status} (redirect to {resp.headers.get('location', '?')}); use the https:// URL."
    if status == 401 and "apiproxy" in msg.lower().replace(" ", ""):
        return ("Console 401 — the API proxy rejected the session. If a fresh login does not help: in the Console "
                "disable 'Prompt Credentials for Instance Login' (Settings > Administration > System Configurations) "
                "so it uses the stored instance profile, or set NETSCALER_CONSOLE_INSTANCE_USERNAME/_PASSWORD." + tail)
    if status == 401:
        return "Console 401 — authentication failed. Check the Console user / API client credentials." + tail
    if status == 403:
        return "Console 403 — this user's role lacks permission for that resource." + tail
    if status == 404:
        return "Console 404 — no such resource on this Console version (or no such object)." + tail
    if status == 599 or "proxy" in msg.lower():
        return ("The Console could not forward the call to the instance: check the instance name / IP, and that "
                "the Console has working instance credentials (or set NETSCALER_CONSOLE_INSTANCE_USERNAME/_PASSWORD)." + tail)
    return f"Console API {status}" + (tail or (f": {resp.text[:300]}" if resp.text else ""))
