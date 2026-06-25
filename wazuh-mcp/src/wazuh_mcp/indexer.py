"""Client for the Wazuh Indexer (OpenSearch, port 9200).

This is where the actual events live: alerts (``wazuh-alerts-*``), the full event archive
(``wazuh-archives-*``), and vulnerability state (``wazuh-states-vulnerabilities-*``).
Auth is HTTP Basic over HTTPS on every request.
"""

from __future__ import annotations

import httpx

from .config import Settings, WazuhError, short


class IndexerClient:
    def __init__(self, settings: Settings) -> None:
        if not (settings.indexer_url and settings.indexer_user and settings.indexer_pass):
            raise WazuhError(
                "Indexer not configured — set WAZUH_INDEXER_URL, "
                "WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS"
            )
        self._s = settings
        self._client = httpx.AsyncClient(
            base_url=settings.indexer_url,
            verify=settings.httpx_verify,
            timeout=settings.request_timeout,
            auth=(settings.indexer_user, settings.indexer_pass),
        )

    async def search(self, index_pattern: str, body: dict) -> dict:
        """POST a Query DSL ``body`` to ``/<index_pattern>/_search`` and return parsed JSON."""
        try:
            resp = await self._client.post(f"/{index_pattern}/_search", json=body)
        except httpx.HTTPError as exc:
            raise WazuhError(
                f"Cannot reach Wazuh Indexer at {self._s.indexer_url}: {exc}"
            ) from exc
        if resp.status_code == 401:
            raise WazuhError(
                "Indexer auth failed (401) — check WAZUH_INDEXER_USER / WAZUH_INDEXER_PASS"
            )
        if resp.status_code >= 400:
            raise WazuhError(
                f"Indexer _search {index_pattern} -> {resp.status_code}: {short(resp.text)}"
            )
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()
