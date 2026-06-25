"""Configuration for the <NAME> MCP server, loaded from environment variables.

Secrets are never hardcoded; everything comes from the process environment (typically supplied
via ``--env-file`` for Docker, or a local ``.env`` exported into the shell).

When adapting the template: rename ``TEMPLATE_*`` to your prefix, set ``_REQUIRED`` to the vars
your API actually needs, and add/remove ``Settings`` fields to match.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")

# The env vars that must be present, or startup fails with a clear message.
_REQUIRED = ("TEMPLATE_BASE_URL", "TEMPLATE_API_KEY")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    base_url: str
    api_key: str
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
                + ". Set them (e.g. via --env-file ./template.env) before starting the server."
            )

        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(
                f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}."
            )

        return cls(
            base_url=env["TEMPLATE_BASE_URL"].strip().rstrip("/"),
            api_key=env["TEMPLATE_API_KEY"],
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
            timeout=_float_env(env, "TEMPLATE_TIMEOUT", 30.0),
            max_rows=_int_env(env, "TEMPLATE_MAX_ROWS", 200),
            verify_ssl=_bool_env(env, "TEMPLATE_VERIFY_SSL", True),
            ca_bundle=env.get("TEMPLATE_CA_BUNDLE", "").strip(),
        )

    @property
    def base_origin(self) -> str:
        """Scheme + host of the base URL (e.g. ``https://api.example.com``)."""
        parts = urlsplit(self.base_url)
        return f"{parts.scheme}://{parts.netloc}"

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
