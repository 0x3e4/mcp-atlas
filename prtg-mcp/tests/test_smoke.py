"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import pytest

from prtg_mcp import server
from prtg_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_sensors",
    "list_devices",
    "list_groups",
    "list_probes",
    "list_channels",
    "get_sensor",
    "server_status",
    "system_health",
    "list_messages",
    "historic_data",
    "prtg_get",
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
    assert "endpoint" in tools["prtg_get"].inputSchema["properties"]
    assert "sensor_id" in tools["list_channels"].inputSchema["properties"]
    assert "sensor_id" in tools["get_sensor"].inputSchema["properties"]
    for p in ("sensor_id", "start", "end"):
        assert p in tools["historic_data"].inputSchema["properties"]


def test_settings_requires_base_url():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def test_settings_requires_some_credential():
    with pytest.raises(ConfigError):
        Settings.from_env({"PRTG_BASE_URL": "https://prtg.example.com"})


def test_settings_with_api_token():
    s = Settings.from_env({"PRTG_BASE_URL": "https://prtg.example.com/", "PRTG_API_TOKEN": "tok"})
    assert s.base_url == "https://prtg.example.com"
    assert s.api_base == "https://prtg.example.com/api"
    assert s.base_origin == "https://prtg.example.com"
    assert s.auth_params == {"apitoken": "tok"}
    assert s.auth_headers == {"Authorization": "Bearer tok"}
    assert s.httpx_verify is True


def test_settings_with_username_passhash():
    s = Settings.from_env(
        {"PRTG_BASE_URL": "https://prtg.example.com", "PRTG_USERNAME": "ro", "PRTG_PASSHASH": "12345"}
    )
    assert s.auth_params == {"username": "ro", "passhash": "12345"}
    assert s.auth_headers == {}


def test_username_without_secret_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"PRTG_BASE_URL": "https://prtg.example.com", "PRTG_USERNAME": "ro"})


def test_invalid_transport_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env(
            {"PRTG_BASE_URL": "https://prtg.example.com", "PRTG_API_TOKEN": "t", "MCP_TRANSPORT": "carrier-pigeon"}
        )


def test_verify_ssl_and_ca_bundle():
    base = {"PRTG_BASE_URL": "https://prtg.example.com", "PRTG_API_TOKEN": "t"}
    assert Settings.from_env({**base, "PRTG_VERIFY_SSL": "false"}).httpx_verify is False
    assert Settings.from_env({**base, "PRTG_CA_BUNDLE": "/etc/ssl/prtg.pem"}).httpx_verify == "/etc/ssl/prtg.pem"
