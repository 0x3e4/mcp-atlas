"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls. Keep ``EXPECTED_TOOLS`` in sync with the
tools you define in ``server.py``.
"""

from __future__ import annotations

import asyncio

import pytest

from template_mcp import server
from template_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "search_items",
    "get_item",
    "api_get",
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
    assert "item_id" in tools["get_item"].inputSchema["properties"]
    assert "path" in tools["api_get"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def test_settings_from_env_and_derived():
    s = Settings.from_env(
        {
            "TEMPLATE_BASE_URL": "https://api.example.com/",
            "TEMPLATE_API_KEY": "secret",
        }
    )
    assert s.transport == "stdio"
    assert s.base_url == "https://api.example.com"
    assert s.base_origin == "https://api.example.com"
    assert s.httpx_verify is True


def test_invalid_transport_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env(
            {
                "TEMPLATE_BASE_URL": "https://api.example.com",
                "TEMPLATE_API_KEY": "secret",
                "MCP_TRANSPORT": "carrier-pigeon",
            }
        )
