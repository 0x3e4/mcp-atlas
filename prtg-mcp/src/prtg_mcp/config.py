"""Configuration for the PRTG MCP server, loaded from environment variables.

Authentication is either a PRTG **API token** (recommended — create a read-only API key in
Setup → API Keys; works on PRTG 23.x+) or the legacy **username + passhash** (or username +
password). Secrets are never hardcoded; everything comes from the process environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    base_url: str
    api_token: str = ""
    username: str = ""
    passhash: str = ""
    password: str = ""
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

        base_url = (env.get("PRTG_BASE_URL") or "").strip().rstrip("/")
        if not base_url:
            raise ConfigError(
                "Missing required environment variable PRTG_BASE_URL. "
                "Set it (e.g. via --env-file ./prtg.env) before starting the server."
            )

        api_token = env.get("PRTG_API_TOKEN", "")
        username = env.get("PRTG_USERNAME", "").strip()
        passhash = env.get("PRTG_PASSHASH", "")
        password = env.get("PRTG_PASSWORD", "")
        if not api_token and not (username and (passhash or password)):
            raise ConfigError(
                "No PRTG credentials. Provide PRTG_API_TOKEN (recommended), or PRTG_USERNAME plus "
                "PRTG_PASSHASH (or PRTG_PASSWORD)."
            )

        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(
                f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}."
            )

        return cls(
            base_url=base_url,
            api_token=api_token,
            username=username,
            passhash=passhash,
            password=password,
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
            timeout=_float_env(env, "PRTG_TIMEOUT", 30.0),
            max_rows=_int_env(env, "PRTG_MAX_ROWS", 200),
            verify_ssl=_bool_env(env, "PRTG_VERIFY_SSL", True),
            ca_bundle=env.get("PRTG_CA_BUNDLE", "").strip(),
        )

    @property
    def base_origin(self) -> str:
        """Scheme + host of the base URL (e.g. ``https://prtg.example.com``)."""
        parts = urlsplit(self.base_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def api_base(self) -> str:
        """Base path for PRTG HTTP API requests (``<base_url>/api``)."""
        return f"{self.base_url}/api"

    @property
    def auth_params(self) -> dict[str, str]:
        """Query-string auth params (token, or username + passhash/password)."""
        if self.api_token:
            return {"apitoken": self.api_token}
        params = {"username": self.username}
        if self.passhash:
            params["passhash"] = self.passhash
        else:
            params["password"] = self.password
        return params

    @property
    def auth_headers(self) -> dict[str, str]:
        """Bearer header for API-token auth (newer PRTG); empty for username/passhash."""
        return {"Authorization": f"Bearer {self.api_token}"} if self.api_token else {}

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
