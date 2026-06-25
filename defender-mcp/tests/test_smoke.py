"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import pytest

from defender_mcp import server
from defender_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "advanced_hunting",
    "list_incidents",
    "get_incident",
    "list_alerts",
    "get_alert",
    "list_devices",
    "get_vulnerabilities",
    "graph_get",
    "graph_hunt",
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
    assert "query" in tools["advanced_hunting"].inputSchema["properties"]
    assert "incident_id" in tools["get_incident"].inputSchema["properties"]
    assert "alert_id" in tools["get_alert"].inputSchema["properties"]
    assert "kql" in tools["graph_hunt"].inputSchema["properties"]
    assert "path" in tools["graph_get"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def test_settings_from_env_and_derived_urls():
    s = Settings.from_env(
        {
            "DEFENDER_TENANT_ID": "tenant-123",
            "DEFENDER_CLIENT_ID": "client-456",
            "DEFENDER_CLIENT_SECRET": "secret",
        }
    )
    assert s.transport == "stdio"
    assert s.token_url == "https://login.microsoftonline.com/tenant-123/oauth2/v2.0/token"
    assert s.scope == "https://graph.microsoft.com/.default"
    assert s.graph_origin == "https://graph.microsoft.com"


def test_invalid_transport_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env(
            {
                "DEFENDER_TENANT_ID": "t",
                "DEFENDER_CLIENT_ID": "c",
                "DEFENDER_CLIENT_SECRET": "s",
                "MCP_TRANSPORT": "carrier-pigeon",
            }
        )
