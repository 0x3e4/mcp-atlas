"""Client for the Wazuh Manager REST API (port 55000).

Auth flow: HTTP Basic against ``/security/user/authenticate`` returns a short-lived JWT,
which is then sent as a Bearer token. The token is cached and transparently refreshed on 401.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import Settings, WazuhError, short


class ManagerClient:
    def __init__(self, settings: Settings) -> None:
        if not (settings.manager_url and settings.manager_user and settings.manager_pass):
            raise WazuhError(
                "Manager API not configured — set WAZUH_MANAGER_URL, WAZUH_USER, WAZUH_PASS"
            )
        self._s = settings
        self._client = httpx.AsyncClient(
            base_url=settings.manager_url,
            verify=settings.httpx_verify,
            timeout=settings.request_timeout,
        )
        self._token: str | None = None

    async def _authenticate(self) -> None:
        try:
            resp = await self._client.post(
                "/security/user/authenticate",
                auth=(self._s.manager_user, self._s.manager_pass),
            )
        except httpx.HTTPError as exc:
            raise WazuhError(
                f"Cannot reach Wazuh Manager at {self._s.manager_url}: {exc}"
            ) from exc
        if resp.status_code == 401:
            raise WazuhError("Manager auth failed (401) — check WAZUH_USER / WAZUH_PASS")
        if resp.status_code >= 400:
            raise WazuhError(
                f"Manager auth -> {resp.status_code}: {short(resp.text)}"
            )
        self._token = resp.json()["data"]["token"]

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        """GET a Manager API path and return the parsed JSON envelope."""
        if self._token is None:
            await self._authenticate()

        resp = await self._send(path, params)
        if resp.status_code == 401:
            # Token likely expired — re-authenticate once and retry.
            await self._authenticate()
            resp = await self._send(path, params)

        if resp.status_code >= 400:
            raise WazuhError(f"Manager API GET {path} -> {resp.status_code}: {short(resp.text)}")
        return resp.json()

    async def _send(self, path: str, params: dict[str, Any] | None) -> httpx.Response:
        try:
            return await self._client.get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            raise WazuhError(
                f"Cannot reach Wazuh Manager at {self._s.manager_url}: {exc}"
            ) from exc

    async def aclose(self) -> None:
        await self._client.aclose()
