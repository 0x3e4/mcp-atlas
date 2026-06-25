"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import pytest

from snipeit_mcp import server
from snipeit_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_assets",
    "get_asset",
    "list_users",
    "get_user_assets",
    "list_objects",
    "snipeit_get",
    "checkout_asset",
    "checkin_asset",
    "update_asset",
    "create_asset",
    "audit_asset",
}


def _tools() -> dict[str, object]:
    listed = asyncio.run(server.mcp.list_tools())
    return {t.name: t for t in listed}


def test_all_tools_registered():
    tools = _tools()
    assert EXPECTED_TOOLS <= set(tools)


def test_tools_have_descriptions_and_schemas():
    for name, tool in _tools().items():
        if name not in EXPECTED_TOOLS:
            continue
        assert tool.description and tool.description.strip(), f"{name} missing description"
        assert tool.inputSchema and "properties" in tool.inputSchema, f"{name} missing schema"


def test_required_params_present():
    tools = _tools()
    assert "path" in tools["snipeit_get"].inputSchema["properties"]
    assert "kind" in tools["list_objects"].inputSchema["properties"]
    assert "user_id" in tools["get_user_assets"].inputSchema["properties"]
    for p in ("asset_id", "to_type", "to_id"):
        assert p in tools["checkout_asset"].inputSchema["properties"]
    for p in ("asset_tag", "model_id", "status_id"):
        assert p in tools["create_asset"].inputSchema["properties"]
    assert "asset_tag" in tools["audit_asset"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {"SNIPEIT_BASE_URL": "https://snipe.example.com/", "SNIPEIT_TOKEN": "tok123"}


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.base_url == "https://snipe.example.com"
    assert s.base_origin == "https://snipe.example.com"
    assert s.api_base == "https://snipe.example.com/api/v1"
    assert s.auth_headers == {"Authorization": "Bearer tok123", "Accept": "application/json"}
    assert s.allow_write is False
    assert s.httpx_verify is True


def test_missing_token_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"SNIPEIT_BASE_URL": "https://snipe.example.com"})


def test_allow_write_flag_parses():
    env = _base_env()
    env["SNIPEIT_ALLOW_WRITE"] = "true"
    assert Settings.from_env(env).allow_write is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["SNIPEIT_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["SNIPEIT_CA_BUNDLE"] = "/etc/ssl/snipe.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/snipe.pem"
