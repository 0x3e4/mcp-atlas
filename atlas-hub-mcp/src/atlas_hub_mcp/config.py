"""Configuration for atlas-hub-mcp, loaded from environment variables.

``ATLAS_HUB_UPSTREAMS`` lists the MCP servers behind the hub as ``name=url`` pairs (streamable HTTP), e.g.
``netscaler=http://netscaler-mcp:8000/mcp,zammad=http://zammad-mcp:8000/mcp`` or a single gateway
``jungle=http://mcpjungle:8080/mcp``. Each upstream's bearer token comes from ``ATLAS_HUB_<NAME>_TOKEN``
(or ``ATLAS_HUB_TOKEN`` for all); ``<VAR>_FILE`` works for both through the shared guard.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

VALID_TRANSPORTS = ("stdio", "streamable-http")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Upstream:
    """One MCP server (or gateway) behind the hub."""

    name: str
    url: str
    token: str = ""


@dataclass(frozen=True)
class Settings:
    """Resolved hub configuration."""

    upstreams: dict[str, Upstream]
    allow_write: bool = False
    refresh_seconds: int = 300
    timeout: float = 60.0
    verify_ssl: bool = True
    ca_bundle: str = ""
    tools: tuple[str, ...] = ()
    hidden_tools: tuple[str, ...] = ()
    max_results: int = 8
    embed_url: str = ""
    embed_model: str = ""
    embed_key: str = field(default="", repr=False)
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        raw = (env.get("ATLAS_HUB_UPSTREAMS") or "").strip()
        if not raw:
            raise ConfigError(
                "Missing ATLAS_HUB_UPSTREAMS: list the MCP servers behind the hub as name=url pairs, e.g. "
                "netscaler=http://netscaler-mcp:8000/mcp,zammad=http://zammad-mcp:8000/mcp."
            )
        shared_token = (env.get("ATLAS_HUB_TOKEN") or "").strip()
        upstreams: dict[str, Upstream] = {}
        for part in (p.strip() for p in raw.split(",") if p.strip()):
            name, sep, url = part.partition("=")
            name, url = name.strip().lower(), url.strip()
            if not sep or not _NAME.fullmatch(name):
                raise ConfigError(
                    f"ATLAS_HUB_UPSTREAMS entry {part!r}: expected name=url with a name like 'netscaler' "
                    "(lowercase letters, digits, '-' or '_')."
                )
            if urlsplit(url).scheme not in ("http", "https") or not urlsplit(url).netloc:
                raise ConfigError(f"ATLAS_HUB_UPSTREAMS entry {name!r}: {url!r} is not an http(s) URL.")
            if name in upstreams:
                raise ConfigError(f"ATLAS_HUB_UPSTREAMS lists {name!r} twice.")
            key = f"ATLAS_HUB_{name.upper().replace('-', '_')}_TOKEN"
            upstreams[name] = Upstream(name, url, (env.get(key) or "").strip() or shared_token)

        transport = env.get("MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in VALID_TRANSPORTS:
            raise ConfigError(f"MCP_TRANSPORT must be one of {VALID_TRANSPORTS}; got {transport!r}.")
        embed_url = (env.get("ATLAS_HUB_EMBED_URL") or "").strip().rstrip("/")
        embed_model = (env.get("ATLAS_HUB_EMBED_MODEL") or "").strip()
        if bool(embed_url) != bool(embed_model):
            raise ConfigError("Set both ATLAS_HUB_EMBED_URL and ATLAS_HUB_EMBED_MODEL, or neither.")
        max_results = _int_env(env, "ATLAS_HUB_MAX_RESULTS", 8)
        if not 1 <= max_results <= 50:
            raise ConfigError(f"ATLAS_HUB_MAX_RESULTS must be 1-50; got {max_results}.")
        return cls(
            upstreams=upstreams,
            allow_write=_bool_env(env, "ATLAS_HUB_ALLOW_WRITE", False),
            refresh_seconds=max(0, _int_env(env, "ATLAS_HUB_REFRESH", 300)),
            timeout=_float_env(env, "ATLAS_HUB_TIMEOUT", 60.0),
            verify_ssl=_bool_env(env, "ATLAS_HUB_VERIFY_SSL", True),
            ca_bundle=(env.get("ATLAS_HUB_CA_BUNDLE") or "").strip(),
            tools=_csv(env.get("ATLAS_HUB_TOOLS")),
            hidden_tools=_csv(env.get("ATLAS_HUB_HIDDEN_TOOLS")),
            max_results=max_results,
            embed_url=embed_url,
            embed_model=embed_model,
            embed_key=(env.get("ATLAS_HUB_EMBED_KEY") or "").strip(),
            transport=transport,
            host=env.get("MCP_HOST", "127.0.0.1").strip(),
            port=_int_env(env, "MCP_PORT", 8000),
        )

    @property
    def httpx_verify(self) -> str | bool:
        return self.ca_bundle or self.verify_ssl


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(p.strip() for p in (value or "").split(",") if p.strip())


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
