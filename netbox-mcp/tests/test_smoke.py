"""Static smoke tests: the server imports and all tools register with sane schemas (no network)."""

from __future__ import annotations

import asyncio

import pytest

from netbox_mcp import server
from netbox_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_devices",
    "get_device",
    "list_interfaces",
    "list_ip_addresses",
    "list_prefixes",
    "list_virtual_machines",
    "list_objects",
    "netbox_get",
}


def _tools() -> dict[str, object]:
    listed = asyncio.run(server.mcp.list_tools())
    return {t.name: t for t in listed}


def test_all_tools_registered():
    assert EXPECTED_TOOLS <= set(_tools())


def test_tools_have_descriptions_and_schemas():
    for name, tool in _tools().items():
        if name not in EXPECTED_TOOLS:
            continue
        assert tool.description and tool.description.strip(), f"{name} missing description"
        assert tool.inputSchema and "properties" in tool.inputSchema, f"{name} missing schema"


def test_required_params_present():
    tools = _tools()
    assert "path" in tools["netbox_get"].inputSchema["properties"]
    assert "kind" in tools["list_objects"].inputSchema["properties"]
    assert "device_id" in tools["get_device"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {"NETBOX_BASE_URL": "https://netbox.example.com/", "NETBOX_TOKEN": "0123456789abcdef"}


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.base_url == "https://netbox.example.com"
    assert s.base_origin == "https://netbox.example.com"
    assert s.api_base == "https://netbox.example.com/api"
    assert s.auth_headers == {"Authorization": "Token 0123456789abcdef"}
    assert s.httpx_verify is True


def test_v2_token_uses_bearer():
    env = _base_env()
    env["NETBOX_TOKEN"] = "nbt_abc.def"
    assert Settings.from_env(env).auth_headers == {"Authorization": "Bearer nbt_abc.def"}


def test_missing_token_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"NETBOX_BASE_URL": "https://netbox.example.com"})


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["NETBOX_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False
    env = _base_env()
    env["NETBOX_CA_BUNDLE"] = "/etc/ssl/netbox.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/netbox.pem"
