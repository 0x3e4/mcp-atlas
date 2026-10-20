"""Async Microsoft Graph client with a cached bearer token.

A single ``httpx.AsyncClient`` is shared across all tools. The bearer token comes from client
credentials (``DEFENDER_AUTH=app``) or from a signed-in user's refresh token (``delegated``; the user
signs in once with ``device_login``). It is cached and transparently re-fetched on expiry or on a 401
(retried once). All HTTP failures are converted to ``GraphError`` with a short, actionable message so
tools never leak tracebacks to the model.
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Callable
from typing import Any

import httpx

from . import tokencache
from .config import Settings

_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
LOGIN_HINT = (
    "run `defender-mcp login` in the server's container "
    "(e.g. `docker compose exec <service> defender-mcp login`)"
)


class GraphError(RuntimeError):
    """A clean, user-facing error for a failed Graph or Entra token request."""


class GraphClient:
    """Minimal async client for the Microsoft Graph security API."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._user: dict[str, Any] = {}
        self._lock = asyncio.Lock()

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def username(self) -> str | None:
        """UPN of the signed-in user (delegated mode, after the first token), else None."""
        return self._user.get("username") or None

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
        async with self._lock:
            if not force and self._token and time.monotonic() < self._token_expiry:
                return self._token  # refreshed by a concurrent call meanwhile
            if self._settings.delegated:
                payload = await self._refresh_user_token()
            else:
                # httpx form-encodes (and URL-encodes) the body, including the secret.
                payload = await self._token_request({
                    "grant_type": "client_credentials",
                    "client_id": self._settings.client_id,
                    "client_secret": self._settings.client_secret,
                    "scope": self._settings.scope,
                })
            token = payload.get("access_token")
            if not token:
                raise GraphError("Entra token response did not contain an access_token.")
            self._set_token(token, payload)
            return token

    def _set_token(self, token: str, payload: dict[str, Any]) -> None:
        # Refresh a minute early; never cache for less than 30s.
        expires_in = float(payload.get("expires_in", 3600))
        self._token = token
        self._token_expiry = time.monotonic() + max(expires_in - 60.0, 30.0)

    async def _token_request(self, data: dict[str, str]) -> dict[str, Any]:
        client = await self._http()
        try:
            resp = await client.post(self._settings.token_url, data=data)
        except httpx.HTTPError as exc:
            raise GraphError(f"Network error contacting the Entra token endpoint: {exc}") from exc
        if resp.status_code != 200:
            raise GraphError(_format_token_error(resp, delegated=self._settings.delegated))
        return resp.json()

    async def _refresh_user_token(self) -> dict[str, Any]:
        """Redeem the stored refresh token. Re-reads the cache file every time, so a `login` run in
        the container while the server is up takes effect on the next call."""
        s = self._settings
        entry = tokencache.load(s.token_cache, tenant_id=s.tenant_id, client_id=s.client_id)
        if entry is None:
            raise GraphError(f"Not signed in (DEFENDER_AUTH=delegated): {LOGIN_HINT}, then retry.")
        try:
            payload = await self._token_request({
                "grant_type": "refresh_token",
                "client_id": s.client_id,
                "refresh_token": entry["refresh_token"],
                "scope": s.delegated_scope,
            })
        except GraphError as exc:
            who = entry.get("username") or "the stored user"
            raise GraphError(f"Sign-in of {who} can't be renewed: {exc}. Fix that, then {LOGIN_HINT}.") from exc
        self._store_sign_in(payload, previous=entry)
        return payload

    def _store_sign_in(self, payload: dict[str, Any], previous: dict[str, Any] | None = None) -> dict[str, Any]:
        """Persist the (rotated) refresh token and remember who it belongs to."""
        s = self._settings
        claims = tokencache.jwt_claims(payload.get("id_token")) or tokencache.jwt_claims(payload.get("access_token"))
        prev = previous or {}
        entry = {
            "tenant_id": s.tenant_id,
            "client_id": s.client_id,
            "refresh_token": payload.get("refresh_token") or prev.get("refresh_token"),
            "username": claims.get("preferred_username") or claims.get("upn") or prev.get("username"),
            "name": claims.get("name") or prev.get("name"),
            "oid": claims.get("oid") or prev.get("oid"),
        }
        self._user = entry
        if entry["refresh_token"]:
            try:
                tokencache.save(s.token_cache, entry)
            except OSError as exc:
                # The old refresh token stays valid for a while; warn instead of failing the call.
                print(f"defender-mcp: could not write {s.token_cache}: {exc}", file=sys.stderr)
        return entry

    async def device_login(self, show: Callable[[str], None] = print) -> dict[str, Any]:
        """Sign a user in with the device code flow and store the refresh token (delegated mode).

        ``show`` receives the "go to ... and enter code ..." prompt. Blocks until the user finishes,
        declines, or the code expires (~15 min).
        """
        s = self._settings
        if not s.delegated:
            raise GraphError("Sign-in is only used with DEFENDER_AUTH=delegated.")
        client = await self._http()
        try:
            resp = await client.post(s.device_code_url, data={"client_id": s.client_id, "scope": s.delegated_scope})
        except httpx.HTTPError as exc:
            raise GraphError(f"Network error contacting the Entra device code endpoint: {exc}") from exc
        if resp.status_code != 200:
            raise GraphError(_format_token_error(resp, delegated=True))
        flow = resp.json()
        show(flow.get("message") or f"Open {flow.get('verification_uri')} and enter the code {flow.get('user_code')}.")

        interval = float(flow.get("interval", 5))
        deadline = time.monotonic() + float(flow.get("expires_in", 900))
        while time.monotonic() < deadline:
            await asyncio.sleep(interval)
            try:
                resp = await client.post(s.token_url, data={
                    "grant_type": _DEVICE_GRANT, "client_id": s.client_id, "device_code": flow["device_code"],
                })
            except httpx.HTTPError as exc:
                raise GraphError(f"Network error contacting the Entra token endpoint: {exc}") from exc
            if resp.status_code == 200:
                payload = resp.json()
                if not payload.get("refresh_token"):
                    raise GraphError("Sign-in returned no refresh token (offline_access was not granted).")
                entry = self._store_sign_in(payload)
                if payload.get("access_token"):
                    self._set_token(payload["access_token"], payload)
                return {k: entry.get(k) for k in ("username", "name", "oid")}
            error = _json_error(resp)
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            raise GraphError(_format_token_error(resp, delegated=True))
        raise GraphError("The sign-in code expired before it was used; run login again.")

    async def whoami(self) -> dict[str, Any]:
        """Which identity the tools act as, and the Graph permissions its current token carries."""
        token = await self._ensure_token()
        claims = tokencache.jwt_claims(token)
        if self._settings.delegated:
            return {
                "auth": "delegated",
                "user": self.username or claims.get("upn"),
                "name": self._user.get("name") or claims.get("name"),
                "scopes": sorted((claims.get("scp") or "").split()),
            }
        return {
            "auth": "app",
            "client_id": self._settings.client_id,
            "app": claims.get("app_displayname"),
            "roles": sorted(claims.get("roles") or []),
        }

    # ---- requests -------------------------------------------------------

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET ``path`` (relative to the Graph base URL, or an absolute Graph URL)."""
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json: Any) -> Any:
        """POST ``json`` to ``path``."""
        return await self._request("POST", path, json=json)

    async def patch(self, path: str, json: Any) -> Any:
        """PATCH ``json`` to ``path`` (only the given properties change)."""
        return await self._request("PATCH", path, json=json)

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
                raise GraphError(_format_graph_error(resp, delegated=self._settings.delegated))
            if resp.status_code == 204 or not resp.content:
                return None
            return resp.json()
        # Loop always returns or raises above.
        raise GraphError("Graph request failed after retry.")  # pragma: no cover

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return f"{self._settings.graph_base_url}/{path.lstrip('/')}"


def _json_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return ""
    return str(body.get("error", "")) if isinstance(body, dict) else ""


def _format_token_error(resp: httpx.Response, *, delegated: bool = False) -> str:
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
    elif "AADSTS7000218" in desc:
        hint = " (delegated sign-in needs 'Allow public client flows' = Yes on the app registration)"
    elif "AADSTS700016" in desc or error == "unauthorized_client":
        hint = " (check the client/tenant id)"
    elif "AADSTS65001" in desc:
        hint = " (admin consent has not been granted)"
    elif "AADSTS53003" in desc:
        hint = " (blocked by Conditional Access; device code flow may be disallowed in this tenant)"
    elif "AADSTS50105" in desc:
        hint = " (the user isn't assigned to the enterprise app)"
    elif error == "authorization_declined":
        hint = " (the user declined the sign-in)"
    elif error == "expired_token":
        hint = " (the sign-in code expired; run login again)"
    elif delegated and error in ("invalid_grant", "interaction_required"):
        hint = " (the sign-in expired, was revoked, or now needs MFA/consent)"
    return f"Entra token error '{error}' (HTTP {resp.status_code}): {first_line}{hint}"


def _format_graph_error(resp: httpx.Response, *, delegated: bool = False) -> str:
    status = resp.status_code
    code = ""
    message = ""
    details: list[str] = []
    try:
        body = resp.json()
        err = body.get("error", {})
        if isinstance(err, dict):
            code = err.get("code", "") or ""
            message = err.get("message", "") or ""
            # Bad-request errors may list per-field problems in error.details[].
            for d in err.get("details") or []:
                if isinstance(d, dict) and d.get("message"):
                    target = d.get("target")
                    details.append(f"{target}: {d['message']}" if target else str(d["message"]))
        elif isinstance(err, str):
            code = err
            message = body.get("error_description", "") or ""
    except ValueError:
        message = resp.text[:300]

    if status == 403 or code == "Authorization_RequestDenied":
        kind = "delegated" if delegated else "application"
        if _is_write(resp):
            perms = (
                "CaseManagement.ReadWrite.All (cases, case comments and tasks)"
                if "/caseManagement" in _request_path(resp)
                else "SecurityIncident.ReadWrite.All (update/comment incidents) or "
                "SecurityAlert.ReadWrite.All (update/comment alerts)"
            )
            msg = (
                "Graph 403 Authorization_RequestDenied — the app registration is missing an "
                f"admin-consented {kind} write permission for this call: {perms}. "
                "Grant the permission in Entra and click 'Grant admin consent', then retry."
            )
        else:
            msg = (
                "Graph 403 Authorization_RequestDenied — the app registration is missing an "
                f"admin-consented {kind} permission for this call. Read-only permissions needed: "
                "ThreatHunting.Read.All (advanced hunting / devices / vulnerabilities), "
                "SecurityAlert.Read.All (alerts), SecurityIncident.Read.All (incidents), "
                "CaseManagement.Read.All (cases). "
                "Grant the permission in Entra and click 'Grant admin consent', then retry."
            )
        if delegated:
            msg += (
                " As a signed-in user you also need a Defender role that allows it (writes: Security "
                "Operator / Security Administrator or a matching Defender XDR RBAC role), and a "
                "sign-in made before the consent needs `defender-mcp login` again."
            )
        return msg
    if status == 401:
        what = (
            "Sign in again (`defender-mcp login`)." if delegated
            else "Verify DEFENDER_TENANT_ID / DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET."
        )
        return f"Graph 401 — bearer token rejected ({code or 'InvalidAuthenticationToken'}). {what}"
    if status == 429:
        retry_after = resp.headers.get("Retry-After")
        hint = f" Retry-After={retry_after}s." if retry_after else ""
        return (
            "Graph 429 — throttled (or advanced-hunting CPU/rate limit reached). "
            f"Back off and retry.{hint}"
        )
    detail = f" {code}: {message}".rstrip() if (code or message) else ""
    if details:
        detail += " (" + "; ".join(details) + ")"
    return f"Graph {status} error.{detail}".strip()


def _is_write(resp: httpx.Response) -> bool:
    """True when the failed request was a write (PATCH, or POST other than the hunting query)."""
    try:
        req = resp.request
    except RuntimeError:  # a bare Response built without a request (tests)
        return False
    if req.method == "PATCH":
        return True
    return req.method == "POST" and not req.url.path.endswith("/runHuntingQuery")


def _request_path(resp: httpx.Response) -> str:
    try:
        return resp.request.url.path
    except RuntimeError:
        return ""
