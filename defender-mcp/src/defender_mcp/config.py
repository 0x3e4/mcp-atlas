"""Configuration for the Defender XDR MCP server, loaded from environment variables.

Secrets are never hardcoded; everything comes from the process environment (typically supplied
via ``--env-file`` for Docker or a local ``.env`` exported into the shell). Writes are opt-in via
``DEFENDER_ALLOW_WRITE``; each write then needs the user's confirmation unless
``DEFENDER_CONFIRM_WRITE=false``. ``DEFENDER_AUTH`` picks the identity: ``app`` (client credentials,
default) or ``delegated`` (a signed-in user via device code, refresh token kept in ``DEFENDER_TOKEN_CACHE``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")
VALID_AUTH = ("app", "delegated")

_REQUIRED = ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID")
_DEFAULT_TOKEN_CACHE = "~/.defender-mcp/token.json"


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    tenant_id: str
    client_id: str
    client_secret: str = ""
    auth: str = "app"
    token_cache: str = os.path.expanduser(_DEFAULT_TOKEN_CACHE)
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    graph_base_url: str = "https://graph.microsoft.com/v1.0"
    login_base_url: str = "https://login.microsoftonline.com"
    timeout: float = 180.0
    max_rows: int = 200
    allow_write: bool = False
    confirm_write: bool = True

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        """Build settings from ``env`` (defaults to ``os.environ``).

        Raises ``ConfigError`` with a clear message when required variables are missing or a value
        is invalid, so the failure surfaces cleanly instead of as a traceback at first use.
        """
        env = os.environ if env is None else env

        auth = env.get("DEFENDER_AUTH", "app").strip().lower() or "app"
        if auth not in VALID_AUTH:
            raise ConfigError(f"DEFENDER_AUTH must be one of {VALID_AUTH}; got {auth!r}.")

        # Delegated sign-in is a public client (device code): no secret.
        required = _REQUIRED if auth == "delegated" else (*_REQUIRED, "DEFENDER_CLIENT_SECRET")
        missing = [name for name in required if not env.get(name)]
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
            client_secret=env.get("DEFENDER_CLIENT_SECRET", "") if auth == "app" else "",
            auth=auth,
            token_cache=os.path.expanduser(
                env.get("DEFENDER_TOKEN_CACHE", "").strip() or _DEFAULT_TOKEN_CACHE
            ),
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
            graph_base_url=env.get("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0").rstrip("/"),
            login_base_url=env.get("LOGIN_BASE_URL", "https://login.microsoftonline.com").rstrip("/"),
            timeout=_float_env(env, "DEFENDER_TIMEOUT", 180.0),
            max_rows=_int_env(env, "DEFENDER_MAX_ROWS", 200),
            allow_write=_bool_env(env, "DEFENDER_ALLOW_WRITE", False),
            confirm_write=_bool_env(env, "DEFENDER_CONFIRM_WRITE", True),
        )

    @property
    def delegated(self) -> bool:
        """True when tools act as a signed-in user instead of the app registration."""
        return self.auth == "delegated"

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
    def device_code_url(self) -> str:
        """OAuth2 v2.0 device authorization endpoint for this tenant."""
        return f"{self.login_base_url}/{self.tenant_id}/oauth2/v2.0/devicecode"

    @property
    def graph_beta_url(self) -> str:
        """Graph beta base URL on the configured host (case management is beta-only)."""
        return f"{self.graph_origin}/beta"

    @property
    def scope(self) -> str:
        """Client-credentials scope: ``<graph-origin>/.default`` (works for Gov clouds too)."""
        return f"{self.graph_origin}/.default"

    @property
    def delegated_scope(self) -> str:
        """Delegated scope: every admin-consented delegated Graph permission, plus a refresh token
        (offline_access) and an id_token naming the user (openid profile)."""
        return f"openid profile offline_access {self.graph_origin}/.default"


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


def _bool_env(env: dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
