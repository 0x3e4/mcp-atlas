"""Configuration for the NetScaler ADC MCP server, loaded from environment variables.

Secrets are never hardcoded; everything comes from the process environment (typically supplied
via ``--env-file`` for Docker, or a local ``.env`` exported into the shell).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")
VALID_AUTH_MODES = ("session", "stateless")

# User/password are needed in both auth modes, so all three are required.
_REQUIRED = ("NETSCALER_BASE_URL", "NETSCALER_USER", "NETSCALER_PASSWORD")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    base_url: str
    user: str
    password: str
    auth_mode: str = "session"
    session_timeout: int = 900
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    timeout: float = 30.0
    max_rows: int = 200
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
                + ". Set them (e.g. via --env-file ./netscaler.env) before starting the server."
            )

        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(
                f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}."
            )

        auth_mode = env.get("NETSCALER_AUTH_MODE", "session").strip().lower()
        if auth_mode not in VALID_AUTH_MODES:
            raise ConfigError(
                f"NETSCALER_AUTH_MODE must be one of {VALID_AUTH_MODES}; got {auth_mode!r}."
            )

        return cls(
            base_url=env["NETSCALER_BASE_URL"].strip().rstrip("/"),
            user=env["NETSCALER_USER"].strip(),
            password=env["NETSCALER_PASSWORD"],
            auth_mode=auth_mode,
            session_timeout=_int_env(env, "NETSCALER_SESSION_TIMEOUT", 900),
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
            timeout=_float_env(env, "NETSCALER_TIMEOUT", 30.0),
            max_rows=_int_env(env, "NETSCALER_MAX_ROWS", 200),
            verify_ssl=_bool_env(env, "NETSCALER_VERIFY_SSL", True),
            ca_bundle=env.get("NETSCALER_CA_BUNDLE", "").strip(),
        )

    @property
    def base_origin(self) -> str:
        """Scheme + host of the base URL (e.g. ``https://10.0.0.10``)."""
        parts = urlsplit(self.base_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def nitro_base(self) -> str:
        """Base path for NITRO v1 requests (``<base_url>/nitro/v1``)."""
        return f"{self.base_url}/nitro/v1"

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
