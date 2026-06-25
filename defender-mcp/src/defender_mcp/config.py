"""Configuration for the Defender XDR MCP server, loaded from environment variables.

Secrets are never hardcoded; everything comes from the process environment (typically supplied
via ``--env-file`` for Docker or a local ``.env`` exported into the shell).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")

_REQUIRED = ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    tenant_id: str
    client_id: str
    client_secret: str
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    graph_base_url: str = "https://graph.microsoft.com/v1.0"
    login_base_url: str = "https://login.microsoftonline.com"
    timeout: float = 180.0
    max_rows: int = 200

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        """Build settings from ``env`` (defaults to ``os.environ``).

        Raises ``ConfigError`` with a clear message when required variables are missing or a value
        is invalid, so the failure surfaces cleanly instead of as a traceback at first use.
        """
        env = os.environ if env is None else env

        missing = [name for name in _REQUIRED if not env.get(name)]
        if missing:
            raise ConfigError(
                "Missing required environment variable(s): "
                + ", ".join(missing)
                + ". Set them (e.g. via --env-file ./defender.env) before starting the server."
            )

        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(
                f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}."
            )

        return cls(
            tenant_id=env["DEFENDER_TENANT_ID"].strip(),
            client_id=env["DEFENDER_CLIENT_ID"].strip(),
            client_secret=env["DEFENDER_CLIENT_SECRET"],
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
            graph_base_url=env.get("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0").rstrip("/"),
            login_base_url=env.get("LOGIN_BASE_URL", "https://login.microsoftonline.com").rstrip("/"),
            timeout=_float_env(env, "DEFENDER_TIMEOUT", 180.0),
            max_rows=_int_env(env, "DEFENDER_MAX_ROWS", 200),
        )

    @property
    def token_url(self) -> str:
        """OAuth2 v2.0 token endpoint for this tenant."""
        return f"{self.login_base_url}/{self.tenant_id}/oauth2/v2.0/token"

    @property
    def graph_origin(self) -> str:
        """Scheme + host of the Graph base URL (e.g. ``https://graph.microsoft.com``)."""
        parts = urlsplit(self.graph_base_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def scope(self) -> str:
        """Client-credentials scope: ``<graph-origin>/.default`` (works for Gov clouds too)."""
        return f"{self.graph_origin}/.default"


def _int_env(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer; got {raw!r}.") from exc


def _float_env(env: dict[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number; got {raw!r}.") from exc
