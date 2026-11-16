"""Configuration for the AudioCodes SBC MCP server, loaded from environment variables.

Secrets are never hardcoded; everything comes from the process environment (typically supplied via
``--env-file`` for Docker). Writes are opt-in via ``AUDIOCODES_ALLOW_WRITE``; each write then needs
the user's confirmation unless ``AUDIOCODES_CONFIRM_WRITE=false``. Disruptive actions (reset, full
configuration replace, firmware), TLS identity changes and license changes each need a switch of
their own on top.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")

_REQUIRED = ("AUDIOCODES_BASE_URL", "AUDIOCODES_USERNAME", "AUDIOCODES_PASSWORD")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    base_url: str
    username: str
    password: str
    allow_write: bool = False
    allow_reset: bool = False      # reset, full configuration replace, firmware upgrade (always confirmed)
    allow_tls: bool = False        # TLS: certificates, trusted roots, key / self-signed generation
    allow_license: bool = False    # install a license key (always confirmed)
    confirm_write: bool = True
    file_dir: str = ""             # folder (inside the container) firmware files are read from
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    timeout: float = 60.0
    max_rows: int = 200
    verify_ssl: bool = True
    ca_bundle: str = ""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        """Build settings from ``env`` (defaults to ``os.environ``); ``ConfigError`` on bad values."""
        env = os.environ if env is None else env

        missing = [name for name in _REQUIRED if not env.get(name)]
        if missing:
            raise ConfigError(
                "Missing required environment variable(s): "
                + ", ".join(missing)
                + ". Set them (e.g. via --env-file ./audiocodes.env) before starting the server."
            )

        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}.")

        base_url = env["AUDIOCODES_BASE_URL"].strip().rstrip("/")
        if base_url.endswith("/api/v1"):
            base_url = base_url[: -len("/api/v1")]
        if not base_url.startswith(("https://", "http://")):
            raise ConfigError("AUDIOCODES_BASE_URL must start with https:// (e.g. https://sbc.example.com).")

        return cls(
            base_url=base_url,
            username=env["AUDIOCODES_USERNAME"],
            password=env["AUDIOCODES_PASSWORD"],
            allow_write=_bool_env(env, "AUDIOCODES_ALLOW_WRITE", False),
            allow_reset=_bool_env(env, "AUDIOCODES_ALLOW_RESET", False),
            allow_tls=_bool_env(env, "AUDIOCODES_ALLOW_TLS", False),
            allow_license=_bool_env(env, "AUDIOCODES_ALLOW_LICENSE", False),
            confirm_write=_bool_env(env, "AUDIOCODES_CONFIRM_WRITE", True),
            file_dir=env.get("AUDIOCODES_FILE_DIR", "").strip(),
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
            timeout=_float_env(env, "AUDIOCODES_TIMEOUT", 60.0),
            max_rows=_int_env(env, "AUDIOCODES_MAX_ROWS", 200),
            verify_ssl=_bool_env(env, "AUDIOCODES_VERIFY_SSL", True),
            ca_bundle=env.get("AUDIOCODES_CA_BUNDLE", "").strip(),
        )

    @property
    def api_base(self) -> str:
        """``<base_url>/api/v1``."""
        return f"{self.base_url}/api/v1"

    @property
    def base_origin(self) -> str:
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
