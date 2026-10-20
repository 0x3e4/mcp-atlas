"""Configuration for the NetScaler ADC MCP server, loaded from environment variables.

Secrets are never hardcoded; everything comes from the process environment (typically supplied
via ``--env-file`` for Docker, or a local ``.env`` exported into the shell). WAF write tools are
opt-in via ``NETSCALER_ALLOW_WRITE`` and, unless ``NETSCALER_CONFIRM_WRITE=false``, need a confirm code
from their preview before they apply; ``NETSCALER_EXPORT_DIR`` enables file-based export/import.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")
VALID_AUTH_MODES = ("session", "stateless")

# User/password are needed in both auth modes, so all three are required.
_REQUIRED = ("NETSCALER_BASE_URL", "NETSCALER_USER", "NETSCALER_PASSWORD")

# Name of the only instance when NETSCALER_INSTANCES is unset.
DEFAULT_INSTANCE = "default"
# Appliance settings an instance may override with NETSCALER_<NAME>_<KEY>. Transport, host, port and
# the row cap belong to the server and stay shared.
INSTANCE_KEYS = (
    "BASE_URL", "USER", "PASSWORD", "AUTH_MODE", "SESSION_TIMEOUT", "TIMEOUT", "VERIFY_SSL",
    "CA_BUNDLE", "ALLOW_WRITE", "CONFIRM_WRITE", "EXPORT_DIR",
)
_INSTANCE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
# Every NETSCALER_* variable the server reads itself; an instance prefix must not produce one of them.
_GLOBAL_KEYS = frozenset(INSTANCE_KEYS) | {"INSTANCES", "DEFAULT_INSTANCE", "MAX_ROWS"}


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
    allow_write: bool = False
    confirm_write: bool = True
    export_dir: str = ""
    name: str = DEFAULT_INSTANCE

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
            allow_write=_bool_env(env, "NETSCALER_ALLOW_WRITE", False),
            confirm_write=_bool_env(env, "NETSCALER_CONFIRM_WRITE", True),
            export_dir=env.get("NETSCALER_EXPORT_DIR", "").strip(),
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


def load_instances(env: dict[str, str] | None = None) -> tuple[dict[str, Settings], str]:
    """Resolve every configured appliance: ``({name: Settings}, default name)``.

    Without ``NETSCALER_INSTANCES`` this is the single ``NETSCALER_BASE_URL`` appliance under the name
    ``default``. With it, each listed instance needs its own ``NETSCALER_<NAME>_BASE_URL``; other
    ``INSTANCE_KEYS`` fall back to the shared ``NETSCALER_<KEY>``. ``NETSCALER_DEFAULT_INSTANCE`` picks
    the instance tools use when none is named (default: the first listed).
    """
    env = os.environ if env is None else env
    raw = env.get("NETSCALER_INSTANCES", "").strip()
    if not raw:
        single = Settings.from_env(env)
        return {single.name: single}, single.name

    names = list(dict.fromkeys(n.strip().lower() for n in raw.split(",") if n.strip()))
    prefixes: dict[str, str] = {}
    for name in names:
        if not _INSTANCE_NAME.fullmatch(name):
            raise ConfigError(
                f"NETSCALER_INSTANCES: {name!r} is not a valid instance name (start with a letter; "
                "letters, digits, '_' and '-'; at most 32 characters)."
            )
        key = name.upper().replace("-", "_")
        if key in prefixes:
            raise ConfigError(
                f"NETSCALER_INSTANCES: {prefixes[key]!r} and {name!r} share the variable prefix "
                f"NETSCALER_{key}_; rename one."
            )
        clash = sorted(f"{key}_{k}" for k in INSTANCE_KEYS if f"{key}_{k}" in _GLOBAL_KEYS)
        if clash:
            raise ConfigError(
                f"NETSCALER_INSTANCES: the name {name!r} would read the shared NETSCALER_{clash[0]} as its "
                "own setting; rename the instance."
            )
        prefixes[key] = name

    out: dict[str, Settings] = {}
    for key, name in prefixes.items():
        prefix = f"NETSCALER_{key}_"
        if not env.get(prefix + "BASE_URL", "").strip():
            raise ConfigError(
                f"Instance {name!r}: set {prefix}BASE_URL (every instance in NETSCALER_INSTANCES needs "
                "its own appliance URL)."
            )
        view = dict(env)
        for setting in INSTANCE_KEYS:
            value = env.get(prefix + setting)
            if value is not None and value.strip() != "":
                view["NETSCALER_" + setting] = value
        try:
            settings = Settings.from_env(view)
        except ConfigError as exc:
            raise ConfigError(
                f"Instance {name!r}: {exc} Per-instance values use {prefix}<KEY>; NETSCALER_<KEY> is the "
                "shared fallback."
            ) from exc
        out[name] = replace(settings, name=name)

    default = env.get("NETSCALER_DEFAULT_INSTANCE", "").strip().lower() or names[0]
    if default not in out:
        raise ConfigError(
            f"NETSCALER_DEFAULT_INSTANCE={default!r} is not in NETSCALER_INSTANCES ({', '.join(out)})."
        )
    return out, default


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
