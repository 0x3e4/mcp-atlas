"""Configuration loaded from environment variables, plus shared error helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass


class WazuhError(RuntimeError):
    """Raised for any upstream Wazuh problem; surfaced to the agent as a clean tool error."""


def short(text: str, limit: int = 300) -> str:
    """Collapse an upstream error body to a single short line for tool error messages."""
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _url(value: str | None) -> str | None:
    return value.rstrip("/") if value else None


@dataclass
class Settings:
    """All runtime config. Created once from the process environment at startup."""

    manager_url: str | None
    manager_user: str | None
    manager_pass: str | None
    indexer_url: str | None
    indexer_user: str | None
    indexer_pass: str | None
    verify_ssl: bool
    ca_bundle: str | None
    transport: str
    host: str
    port: int
    time_field: str
    alerts_index: str
    archives_index: str
    vulns_index: str
    request_timeout: float

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            manager_url=_url(os.getenv("WAZUH_MANAGER_URL")),
            manager_user=os.getenv("WAZUH_USER"),
            manager_pass=os.getenv("WAZUH_PASS"),
            indexer_url=_url(os.getenv("WAZUH_INDEXER_URL")),
            indexer_user=os.getenv("WAZUH_INDEXER_USER"),
            indexer_pass=os.getenv("WAZUH_INDEXER_PASS"),
            verify_ssl=_bool(os.getenv("WAZUH_VERIFY_SSL"), True),
            ca_bundle=os.getenv("WAZUH_CA_BUNDLE") or None,
            transport=os.getenv("MCP_TRANSPORT", "stdio").strip() or "stdio",
            host=os.getenv("MCP_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_PORT", "8000")),
            time_field=os.getenv("WAZUH_TIME_FIELD", "timestamp"),
            alerts_index=os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*"),
            archives_index=os.getenv("WAZUH_ARCHIVES_INDEX", "wazuh-archives-*"),
            vulns_index=os.getenv("WAZUH_VULNS_INDEX", "wazuh-states-vulnerabilities-*"),
            request_timeout=float(os.getenv("WAZUH_TIMEOUT", "30")),
        )

    @property
    def httpx_verify(self):
        """Value for httpx's ``verify`` arg: False (skip), a CA bundle path, or True."""
        if not self.verify_ssl:
            return False
        if self.ca_bundle:
            return self.ca_bundle
        return True
