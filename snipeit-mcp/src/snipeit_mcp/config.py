"""Configuration for the Snipe-IT MCP server, loaded from environment variables.

Authentication is a Snipe-IT personal API token (Bearer). The token inherits the permissions of the
user it was created for — there is no read-only token — so write tools are additionally gated by
``SNIPEIT_ALLOW_WRITE``. Secrets are never hardcoded; everything comes from the process environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")

_REQUIRED = ("SNIPEIT_BASE_URL", "SNIPEIT_TOKEN")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    base_url: str
    token: str
    allow_write: bool = False
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    timeout: float = 30.0
    max_rows: int = 50
    verify_ssl: bool = True
    ca_bundle: str = ""

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
                + ". Set them (e.g. via --env-file ./snipeit.env) before starting the server."
            )

        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(
                f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}."
            )

        return cls(
            base_url=env["SNIPEIT_BASE_URL"].strip().rstrip("/"),
            token=env["SNIPEIT_TOKEN"],
            allow_write=_bool_env(env, "SNIPEIT_ALLOW_WRITE", False),
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
            timeout=_float_env(env, "SNIPEIT_TIMEOUT", 30.0),
            max_rows=_int_env(env, "SNIPEIT_MAX_ROWS", 50),
            verify_ssl=_bool_env(env, "SNIPEIT_VERIFY_SSL", True),
            ca_bundle=env.get("SNIPEIT_CA_BUNDLE", "").strip(),
        )

    @property
    def base_origin(self) -> str:
        """Scheme + host of the base URL (e.g. ``https://snipe.example.com``)."""
        parts = urlsplit(self.base_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def api_base(self) -> str:
        """Base path for Snipe-IT REST API requests (``<base_url>/api/v1``)."""
        return f"{self.base_url}/api/v1"

    @property
    def auth_headers(self) -> dict[str, str]:
        """Bearer auth + JSON Accept (Snipe-IT returns an HTML login page without Accept: json)."""
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

    @property
    def httpx_verify(self) -> str | bool:
        """Value for httpx ``verify=``: a CA bundle path if set, else the verify_ssl bool."""
        return self.ca_bundle or self.verify_ssl


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
