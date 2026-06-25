"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import pytest

from fortigate_mcp import server
from fortigate_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_policies",
    "list_addresses",
    "list_services",
    "list_vips",
    "list_interfaces",
    "list_static_routes",
    "system_info",
    "system_resources",
    "ha_status",
    "interface_status",
    "policy_stats",
    "vpn_status",
    "routing_table",
    "fortios_get",
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
    assert "tree" in tools["fortios_get"].inputSchema["properties"]
    assert "path" in tools["fortios_get"].inputSchema["properties"]
    assert "ipv6" in tools["list_policies"].inputSchema["properties"]
    assert "groups" in tools["list_addresses"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "FORTIGATE_BASE_URL": "https://192.0.2.1/",
        "FORTIGATE_API_TOKEN": "abc123",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.vdom == "root"
    assert s.base_url == "https://192.0.2.1"
    assert s.base_origin == "https://192.0.2.1"
    assert s.api_base == "https://192.0.2.1/api/v2"
    assert s.httpx_verify is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["FORTIGATE_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["FORTIGATE_CA_BUNDLE"] = "/etc/ssl/fgt-ca.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/fgt-ca.pem"


def test_custom_vdom():
    env = _base_env()
    env["FORTIGATE_VDOM"] = "VDOM-DMZ"
    assert Settings.from_env(env).vdom == "VDOM-DMZ"
