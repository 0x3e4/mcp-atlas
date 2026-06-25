"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import pytest

from netscaler_mcp import server
from netscaler_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_lb_vservers",
    "list_cs_vservers",
    "list_gslb_vservers",
    "list_services",
    "list_servers",
    "list_certificates",
    "ha_status",
    "system_health",
    "vserver_stats",
    "system_info",
    "list_gslb_services",
    "list_gslb_sites",
    "list_dns_records",
    "list_dns_zones",
    "list_dns_nameservers",
    "list_waf_profiles",
    "list_waf_policies",
    "waf_stats",
    "list_bot_profiles",
    "list_bot_policies",
    "bot_stats",
    "nitro_get",
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
    assert "tree" in tools["nitro_get"].inputSchema["properties"]
    assert "resourcetype" in tools["nitro_get"].inputSchema["properties"]
    assert "expiring_within_days" in tools["list_certificates"].inputSchema["properties"]
    assert "kind" in tools["vserver_stats"].inputSchema["properties"]
    assert "record_type" in tools["list_dns_records"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "NETSCALER_BASE_URL": "https://10.0.0.10/",
        "NETSCALER_USER": "ro",
        "NETSCALER_PASSWORD": "secret",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.auth_mode == "session"
    assert s.base_url == "https://10.0.0.10"
    assert s.base_origin == "https://10.0.0.10"
    assert s.nitro_base == "https://10.0.0.10/nitro/v1"
    assert s.httpx_verify is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_invalid_auth_mode_rejected():
    env = _base_env()
    env["NETSCALER_AUTH_MODE"] = "magic"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["NETSCALER_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["NETSCALER_CA_BUNDLE"] = "/etc/ssl/ns-ca.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/ns-ca.pem"
