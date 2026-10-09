"""Async PRTG Network Monitor HTTP API client.

A single ``httpx.AsyncClient`` is shared across all tools. Auth (API token as ``Authorization:
Bearer`` + ``apitoken`` query param, or legacy ``username``/``passhash``) is applied to every
request. ``table.json`` and the other ``*.json`` endpoints return JSON; a failure — including PRTG's
habit of returning an XML/HTML error body on a bad token — becomes a clean ``PrtgError`` so tools
never leak tracebacks to the model.

Writes go through ``action()``: PRTG's classic API changes state with GET-style ``*.htm`` calls
(``pause.htm``, ``acknowledgealarm.htm``, ...) that answer with HTML, and report failures as a
redirect to ``/error.htm?errormsg=...`` (or to the login page on bad credentials) rather than an
error status. ``action()`` never follows redirects, so such a failure surfaces as ``PrtgError``.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx

from .config import Settings


# PRTG's classic API changes state through plain GETs (pause.htm, setobjectproperty.htm,
# deleteobject.htm, ...), so the read-only escape hatch refuses endpoints with these name prefixes.
_ACTION_PREFIXES = (
    "pause", "acknowledge", "scannow", "set", "delete", "add", "duplicate", "rename", "move",
    "discover", "simulate", "editsettings", "notificationtest", "reloadfilelists", "restart",
)


class PrtgError(RuntimeError):
    """A clean, user-facing error for a failed PRTG API request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class PrtgClient:
    """Minimal async client for the PRTG HTTP API (GET reads + GET-style ``*.htm`` actions)."""

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

    def _merged(self, params: dict[str, Any] | None) -> dict[str, Any]:
        q: dict[str, Any] = dict(params or {})
        q.update(self._settings.auth_params)
        return q

    async def get(self, endpoint: str, *, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        """GET a PRTG endpoint relative to ``/api`` (e.g. ``table.json``)."""
        url = f"{self._settings.api_base}/{endpoint.lstrip('/')}"
        return await self._request(url, params=params, as_text=as_text)

    async def action(self, endpoint: str, *, params: dict[str, Any]) -> dict[str, Any]:
        """Run a state-changing ``/api/<endpoint>`` call (e.g. ``pause.htm``) and check it worked.

        Redirects are not followed: ``/error.htm`` → the PRTG error message, a login page → auth
        error, anything else → error (the outcome is unknown). A 200 whose body is a PRTG error
        block or the login page is also an error. Returns the status and a short body snippet.
        """
        url = f"{self._settings.api_base}/{endpoint.lstrip('/')}"
        client = await self._http()
        try:
            resp = await client.get(
                url, params=self._merged(params), headers=self._settings.auth_headers, follow_redirects=False
            )
        except httpx.HTTPError as exc:
            raise PrtgError(f"Network error calling PRTG {url}: {exc}") from exc

        if resp.is_redirect:
            raise PrtgError(_redirect_error(resp), status=resp.status_code)
        if resp.status_code >= 400:
            raise PrtgError(_format_error(resp.status_code, resp), status=resp.status_code)
        body = resp.text or ""
        if 'class="errormsg"' in body:
            raise PrtgError(f"PRTG refused {endpoint}: {_strip_html(body)[:300]}", status=resp.status_code)
        if _looks_like_login(body):
            raise PrtgError(_AUTH_MSG, status=resp.status_code)
        return {"http_status": resp.status_code, "response": _strip_html(body)[:200]}

    async def get_raw(self, endpoint: str, *, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        """Escape hatch: GET an arbitrary ``/api/...`` endpoint (or absolute URL on the same host)."""
        if endpoint.startswith(("http://", "https://")):
            if not endpoint.startswith(self._settings.base_origin):
                raise ValueError(
                    f"prtg_get only allows the configured host ({self._settings.base_origin})."
                )
            url = endpoint
        else:
            ep = endpoint.lstrip("/")
            if ep.startswith("api/"):
                ep = ep[len("api/") :]
            url = f"{self._settings.api_base}/{ep}"
        name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
        if name.startswith(_ACTION_PREFIXES):
            raise ValueError(
                f"prtg_get is read-only and refuses state-changing endpoints like {name!r}; use the "
                "dedicated write tools (pause_object, resume_object, acknowledge_alarm, scan_now)."
            )
        return await self._request(url, params=params, as_text=as_text)

    async def _request(self, url: str, *, params: dict[str, Any] | None = None, as_text: bool = False) -> Any:
        client = await self._http()
        try:
            resp = await client.get(url, params=self._merged(params), headers=self._settings.auth_headers)
        except httpx.HTTPError as exc:
            raise PrtgError(f"Network error calling PRTG {url}: {exc}") from exc

        if resp.status_code >= 400:
            raise PrtgError(_format_error(resp.status_code, resp), status=resp.status_code)
        if as_text:
            return resp.text
        try:
            return resp.json()
        except ValueError:
            ctype = resp.headers.get("content-type", "")
            snippet = resp.text[:200].strip().replace("\n", " ")
            raise PrtgError(
                f"PRTG did not return JSON (content-type {ctype!r}). This usually means an auth error "
                f"or an XML-only endpoint (use prtg_get with as_text). Body: {snippet}"
            )


_AUTH_MSG = (
    "PRTG authentication failed (redirected to the login page). Check PRTG_API_TOKEN (or "
    "PRTG_USERNAME / PRTG_PASSHASH)."
)


def _strip_html(text: str) -> str:
    """Collapse an HTML/XML body to plain text for an error message or result snippet."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


def _looks_like_login(body: str) -> bool:
    low = body.lower()
    return "/public/login.htm" in low or 'id="loginform"' in low or 'name="loginform"' in low


def _redirect_error(resp: httpx.Response) -> str:
    """Explain a redirect from a PRTG action call (PRTG signals failures this way)."""
    location = urljoin(str(resp.request.url), resp.headers.get("location", ""))
    parts = urlsplit(location)
    path = parts.path.lower()
    if path.endswith("/error.htm"):
        msg = (parse_qs(parts.query).get("errormsg") or [""])[0]
        return f"PRTG refused the request: {_strip_html(msg) or 'no error message given'}"
    if "login" in path:
        return _AUTH_MSG
    return (
        f"PRTG answered with an unexpected redirect (HTTP {resp.status_code} to {parts.path or location!r}); "
        "the action may not have run — check the object's state."
    )


def _format_error(status: int, resp: httpx.Response) -> str:
    snippet = resp.text[:200].strip().replace("\n", " ") if resp.text else ""
    if status == 400:
        # PRTG puts the reason in an XML <error> element on a bad request.
        match = re.search(r"<error>(.*?)</error>", resp.text or "", re.S)
        if match:
            return f"PRTG 400 — {_strip_html(match.group(1))}"
    if status == 401:
        return (
            "PRTG 401 — authentication failed. Check PRTG_API_TOKEN (or PRTG_USERNAME / "
            "PRTG_PASSHASH) and that the account/key has read access."
        )
    if status == 403:
        return (
            "PRTG 403 — the account/API key lacks permission for this object (writes need write access "
            "on the object and a key with write/acknowledge access)."
        )
    if status == 404:
        return "PRTG 404 — no such endpoint or object id."
    detail = f" {snippet}" if snippet else ""
    return f"PRTG HTTP {status}.{detail}".rstrip()
