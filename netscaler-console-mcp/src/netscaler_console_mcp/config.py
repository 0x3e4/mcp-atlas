"""Configuration for the NetScaler Console MCP server, loaded from environment variables.

Two modes:

- **on-prem** (default): ``NETSCALER_CONSOLE_BASE_URL`` + ``_USERNAME`` / ``_PASSWORD`` (a Console
  user; sent as the documented ``X-NITRO-USER`` / ``X-NITRO-PASS`` headers).
- **cloud** (NetScaler Console service): ``_CUSTOMER_ID`` + ``_CLIENT_ID`` / ``_CLIENT_SECRET`` (a
  Citrix Cloud API client) and ``_CLOUD_REGION`` (``us``, ``eu``, ``ap-s`` …); the base URL defaults to
  ``https://adm.cloud.com``.

Writes are opt-in (``NETSCALER_CONSOLE_ALLOW_WRITE``); changing ADC entities through the Console
needs ``NETSCALER_CONSOLE_ALLOW_INSTANCE_WRITE`` on top.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

VALID_TRANSPORTS = ("stdio", "streamable-http")
P = "NETSCALER_CONSOLE_"


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    """Resolved server configuration."""

    base_url: str
    username: str = ""
    password: str = ""
    customer_id: str = ""          # cloud mode when set
    client_id: str = ""
    client_secret: str = ""
    cloud_region: str = "us"
    instance_username: str = ""    # optional ADC credentials for proxied calls (else the Console's instance profile)
    instance_password: str = ""
    allow_write: bool = False
    allow_instance_write: bool = False
    confirm_write: bool = True
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    timeout: float = 60.0
    max_rows: int = 200
    verify_ssl: bool = True
    ca_bundle: str = ""

    @property
    def cloud(self) -> bool:
        return bool(self.customer_id)

    @property
    def nitro_base(self) -> str:
        """Base for Console resources: ``<base>/nitro/v2/config`` (cloud: ``<base>/massvc/<customer>/nitro/v2/config``)."""
        if self.cloud:
            return f"{self.base_url}/massvc/{self.customer_id}/nitro/v2/config"
        return f"{self.base_url}/nitro/v2/config"

    @property
    def httpx_verify(self) -> str | bool:
        return self.ca_bundle or self.verify_ssl

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        g = lambda name, default="": env.get(P + name, default).strip()  # noqa: E731
        cloud = bool(g("CUSTOMER_ID"))
        required = ("CUSTOMER_ID", "CLIENT_ID", "CLIENT_SECRET") if cloud else ("BASE_URL", "USERNAME", "PASSWORD")
        if missing := [P + n for n in required if not env.get(P + n)]:
            raise ConfigError(
                "Missing required environment variable(s): " + ", ".join(missing)
                + ". On-prem needs BASE_URL + USERNAME + PASSWORD; the cloud service needs CUSTOMER_ID + "
                "CLIENT_ID + CLIENT_SECRET (see .env.example)."
            )
        base = (g("BASE_URL") or ("https://adm.cloud.com" if cloud else "")).rstrip("/")
        if not base.startswith(("https://", "http://")):
            raise ConfigError(f"{P}BASE_URL must start with https:// (e.g. https://console.example.com).")
        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}.")
        return cls(
            base_url=base,
            username=env.get(P + "USERNAME", ""),
            password=env.get(P + "PASSWORD", ""),
            customer_id=g("CUSTOMER_ID"),
            client_id=env.get(P + "CLIENT_ID", ""),
            client_secret=env.get(P + "CLIENT_SECRET", ""),
            cloud_region=g("CLOUD_REGION", "us") or "us",
            instance_username=env.get(P + "INSTANCE_USERNAME", ""),
            instance_password=env.get(P + "INSTANCE_PASSWORD", ""),
            allow_write=_bool(env, P + "ALLOW_WRITE", False),
            allow_instance_write=_bool(env, P + "ALLOW_INSTANCE_WRITE", False),
            confirm_write=_bool(env, P + "CONFIRM_WRITE", True),
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int(env, "MCP_PORT", 8000),
            timeout=_float(env, P + "TIMEOUT", 60.0),
            max_rows=_int(env, P + "MAX_ROWS", 200),
            verify_ssl=_bool(env, P + "VERIFY_SSL", True),
            ca_bundle=g("CA_BUNDLE"),
        )


def _int(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer; got {raw!r}.") from exc


def _float(env: dict[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number; got {raw!r}.") from exc


def _bool(env: dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
