"""Async client for the AudioCodes SBC / Media Gateway device REST API (``/api/v1``).

A single ``httpx.AsyncClient`` is shared across all tools. Authentication is HTTP Basic with a
device user (Monitor, Administrator or Security Administrator level) on every request — there is no
login or session. Responses are JSON, except file downloads (INI, CLI script, certificates), which
come as ``application/octet-stream``; file uploads are ``multipart/form-data`` with a ``file`` field.
Failures become a clean ``SbcError`` carrying the device's own ``description`` text.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class SbcError(RuntimeError):
    """A clean, user-facing error for a failed device API request."""

    def __init__(self, message: str, *, status: int | None = None, description: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.description = description


class SbcClient:
    """Minimal async client for the AudioCodes device REST API."""

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
                auth=httpx.BasicAuth(self._settings.username, self._settings.password),
                follow_redirects=False,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _url(self, path: str) -> str:
        return f"{self._settings.api_base}/{path.lstrip('/')}"

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        content: bytes | None = None,
        files: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        client = await self._http()
        url = self._url(path)
        try:
            resp = await client.request(method, url, params=params, json=json, content=content, files=files,
                                        headers={"Accept": "application/json, application/octet-stream", **(headers or {})})
        except httpx.HTTPError as exc:
            raise SbcError(f"Network error calling the SBC at {url}: {exc}") from exc
        if resp.status_code >= 400 or 300 <= resp.status_code < 400:
            raise SbcError(_format_error(resp), status=resp.status_code, description=_description(resp))
        return resp

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET JSON; 204 (empty, e.g. no alarms) becomes ``{}``."""
        resp = await self._send("GET", path, params=params)
        return _json(resp)

    async def get_text(self, path: str, *, params: dict[str, Any] | None = None) -> str:
        """GET a file (INI, CLI script, certificate PEM) as text."""
        resp = await self._send("GET", path, params=params)
        return resp.content.decode("utf-8", errors="replace")

    async def post(self, path: str, *, json: Any = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """POST JSON. Without a body the request carries Content-Length: 0 (saveConfiguration needs that)."""
        if json is None:
            resp = await self._send("POST", path, params=params, content=b"")
        else:
            resp = await self._send("POST", path, params=params, json=json)
        return _json(resp)

    async def post_raw(self, path: str, *, json: Any = None) -> httpx.Response:
        """POST JSON and hand back the raw response (CSR download)."""
        return await self._send("POST", path, json=json)

    async def put_json(self, path: str, *, json: Any) -> dict[str, Any]:
        resp = await self._send("PUT", path, json=json)
        return _json(resp)

    async def put_file(self, path: str, data: bytes, *, filename: str = "file.txt") -> dict[str, Any]:
        """PUT a file as multipart/form-data, field ``file`` (INI, CLI script, PEM, firmware)."""
        resp = await self._send("PUT", path, files={"file": (filename, data, "application/octet-stream")})
        return _json(resp)

    async def delete(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await self._send("DELETE", path, params=params)
        return _json(resp)


def _json(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 204 or not resp.content:
        return {}
    try:
        data = resp.json()
    except ValueError:
        return {"text": resp.content.decode("utf-8", errors="replace")}
    return data if isinstance(data, dict) else {"items": data}


def _description(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return ""
    if isinstance(data, dict):
        return str(data.get("description") or data.get("errorDescription") or "")
    return ""


def _format_error(resp: httpx.Response) -> str:
    status = resp.status_code
    desc = _description(resp)
    tail = f" Device says: {desc}" if desc else ""
    if 300 <= status < 400:
        return (f"SBC answered {status} (redirect to {resp.headers.get('location', '?')}). Point AUDIOCODES_BASE_URL "
                "at the URL the device serves the API on (usually https://).")
    if status == 401:
        return "SBC 401 — authentication failed. Check AUDIOCODES_USERNAME / AUDIOCODES_PASSWORD." + tail
    if status == 403:
        return ("SBC 403 — this user's privilege level is too low for that resource. Reads need Monitor, "
                "/files, /actions and /license need Administrator, configuration files, TLS and license "
                "installs need Security Administrator." + tail)
    if status == 404:
        return "SBC 404 — no such resource (or not available on this device / firmware)." + tail
    if status == 405:
        return "SBC 405 — method not allowed for this resource." + tail
    if status == 409:
        return "SBC 409 — the device is busy (e.g. HA synchronisation in progress); try again shortly." + tail
    detail = desc or (resp.text[:300] if resp.text else "")
    return f"SBC API {status}" + (f": {detail}" if detail else "")
