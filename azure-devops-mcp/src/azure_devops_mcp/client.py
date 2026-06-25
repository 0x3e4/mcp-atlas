"""Async Azure DevOps Server (on-prem) REST API client.

A single ``httpx.AsyncClient`` is shared across all tools. Authentication is a Personal Access Token
sent via HTTP Basic (empty username, PAT as password) plus ``Accept: application/json``. The required
``api-version`` query param is applied automatically. Reads are GET (plus WIQL POST); optional writes
(work items via JSON-Patch, wiki pages via PUT) are gated by ``AZDO_ALLOW_WRITE`` at the tool layer.

Responses are validated; a failure — including the Azure DevOps quirk of returning an HTML sign-in
page (or a 30x redirect) instead of a clean 401 when the PAT is bad — becomes a clean ``AzdoError``
so tools never leak tracebacks to the model.
"""

from __future__ import annotations

import base64
import json as _jsonlib
from typing import Any
from urllib.parse import quote

import httpx

from .config import Settings


class AzdoError(RuntimeError):
    """A clean, user-facing error for a failed Azure DevOps API request."""

    def __init__(self, message: str, *, status: int | None = None, ado_message: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.ado_message = ado_message


class AzdoClient:
    """Minimal async client for the on-prem Azure DevOps Server REST API."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._auth = base64.b64encode(f":{settings.pat}".encode("utf-8")).decode("ascii")

    @property
    def settings(self) -> Settings:
        return self._settings

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            # follow_redirects stays off so a 30x to the sign-in page surfaces as an auth error.
            self._client = httpx.AsyncClient(
                timeout=self._settings.timeout,
                verify=self._settings.httpx_verify,
                follow_redirects=False,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Basic {self._auth}", "Accept": "application/json"}

    def _url(self, path: str, project: str | None) -> str:
        root = self._settings.base_url
        if project:
            root = f"{root}/{quote(project, safe='')}"
        return f"{root}/{path.lstrip('/')}"

    def _with_version(self, params: dict[str, Any] | None) -> dict[str, Any]:
        q: dict[str, Any] = dict(params or {})
        q.setdefault("api-version", self._settings.api_version)
        return q

    # ---- core transport -------------------------------------------------

    async def _send(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        content: str | bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        headers = self._auth_headers()
        if extra_headers:
            headers.update(extra_headers)
        client = await self._http()
        try:
            resp = await client.request(
                method, url, params=self._with_version(params), json=json, content=content, headers=headers
            )
        except httpx.HTTPError as exc:
            raise AzdoError(f"Network error calling Azure DevOps {url}: {exc}") from exc

        ctype = resp.headers.get("content-type", "").lower()
        # A redirect or HTML body means we hit the sign-in page → the PAT/URL is the problem.
        if 300 <= resp.status_code < 400 or "text/html" in ctype:
            raise AzdoError(
                "Azure DevOps returned a sign-in page instead of JSON — the PAT is likely "
                "invalid/expired, lacks scope, or AZDO_BASE_URL (collection) is wrong. "
                "Check AZDO_PAT and AZDO_BASE_URL.",
                status=resp.status_code,
            )
        if resp.status_code >= 400:
            data = _try_json(resp)
            raise AzdoError(
                _format_error(resp.status_code, data, resp),
                status=resp.status_code,
                ado_message=(data.get("message", "") if isinstance(data, dict) else ""),
            )
        return resp

    def _json(self, resp: httpx.Response) -> Any:
        data = _try_json(resp)
        if data is None:
            ctype = resp.headers.get("content-type", "")
            raise AzdoError(
                f"Expected JSON from Azure DevOps but got content-type {ctype!r} (HTTP {resp.status_code})."
            )
        return data

    # ---- reads ----------------------------------------------------------

    async def get(self, path: str, *, project: str | None = None, params: dict[str, Any] | None = None) -> Any:
        """GET a resource; ``path`` is relative to the collection (e.g. ``_apis/projects``)."""
        return self._json(await self._send("GET", self._url(path, project), params=params))

    async def post(
        self, path: str, *, project: str | None = None, params: dict[str, Any] | None = None, json: Any | None = None
    ) -> Any:
        """POST a read-only query (e.g. WIQL) and return the parsed JSON body."""
        return self._json(await self._send("POST", self._url(path, project), params=params, json=json))

    async def get_raw(self, path: str, *, project: str | None = None, params: dict[str, Any] | None = None) -> Any:
        """Escape hatch: GET an arbitrary ``_apis/...`` path (or absolute URL on the same host)."""
        if path.startswith(("http://", "https://")):
            if not path.startswith(self._settings.base_origin):
                raise ValueError(
                    f"azdo_get only allows the configured host ({self._settings.base_origin})."
                )
            url = path
        else:
            url = self._url(path, project)
        return self._json(await self._send("GET", url, params=params))

    async def get_with_etag(
        self, path: str, *, project: str | None = None, params: dict[str, Any] | None = None
    ) -> tuple[Any, str | None]:
        """GET a resource and also return its ETag header (used for wiki page If-Match updates)."""
        resp = await self._send("GET", self._url(path, project), params=params)
        return self._json(resp), resp.headers.get("ETag")

    # ---- writes (gated at the tool layer by AZDO_ALLOW_WRITE) -----------

    async def json_patch(
        self, method: str, path: str, ops: list[dict[str, Any]], *, project: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Send a JSON-Patch body (``application/json-patch+json``) — used for work item create/update."""
        resp = await self._send(
            method,
            self._url(path, project),
            params=params,
            content=_jsonlib.dumps(ops),
            extra_headers={"Content-Type": "application/json-patch+json"},
        )
        return self._json(resp)

    async def put_json(
        self, path: str, body: Any, *, project: str | None = None, params: dict[str, Any] | None = None,
        if_match: str | None = None,
    ) -> tuple[Any, str | None]:
        """PUT a JSON body (optionally with an ``If-Match`` ETag); returns (data, new ETag)."""
        extra = {"If-Match": if_match} if if_match else None
        resp = await self._send("PUT", self._url(path, project), params=params, json=body, extra_headers=extra)
        return self._json(resp), resp.headers.get("ETag")


def _try_json(resp: httpx.Response) -> Any:
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        return None


def _format_error(status: int, data: Any, resp: httpx.Response) -> str:
    msg = data.get("message", "") if isinstance(data, dict) else ""
    if status == 401:
        return (
            "Azure DevOps 401 — authentication failed. Check AZDO_PAT and that it has the needed "
            "scopes (reads: Code/Work Items/Build, Project & Team; writes: Work Items 'Read & write', Wiki 'Read & write')."
        )
    if status == 403:
        return f"Azure DevOps 403 — the PAT lacks permission for this resource. {msg}".rstrip()
    if status == 404:
        return (
            "Azure DevOps 404 — not found. Check the project/repository names and that AZDO_BASE_URL "
            f"includes the right collection. {msg}".rstrip()
        )
    if status == 400:
        return (
            "Azure DevOps 400 — bad request. Often a wrong AZDO_API_VERSION for this server "
            f"(2019=5.0, 2020=6.0, 2022=7.0), or invalid WIQL/parameters. {msg}".rstrip()
        )
    if status == 409:
        return f"Azure DevOps 409 — conflict (e.g. the wiki page changed since you read it). {msg}".rstrip()
    if status == 412:
        return f"Azure DevOps 412 — precondition failed (stale wiki page version/ETag). {msg}".rstrip()
    detail = msg or (resp.text[:300] if resp.text else "")
    detail = f": {detail}" if detail else ""
    return f"Azure DevOps API {status}{detail}".rstrip()
