"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import pytest

from bookstack_mcp import server
from bookstack_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_shelves",
    "list_books",
    "list_chapters",
    "list_pages",
    "get_book",
    "get_chapter",
    "get_page",
    "search",
    "export_content",
    "list_attachments",
    "system_info",
    "bookstack_get",
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
    assert "path" in tools["bookstack_get"].inputSchema["properties"]
    assert "query" in tools["search"].inputSchema["properties"]
    assert "id" in tools["get_page"].inputSchema["properties"]
    assert "kind" in tools["export_content"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "BOOKSTACK_BASE_URL": "https://docs.example.com/",
        "BOOKSTACK_TOKEN_ID": "tid",
        "BOOKSTACK_TOKEN_SECRET": "tsecret",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.base_url == "https://docs.example.com"
    assert s.base_origin == "https://docs.example.com"
    assert s.api_base == "https://docs.example.com/api"
    assert s.httpx_verify is True


def test_settings_missing_one_secret():
    env = _base_env()
    del env["BOOKSTACK_TOKEN_SECRET"]
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["BOOKSTACK_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["BOOKSTACK_CA_BUNDLE"] = "/etc/ssl/bs-ca.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/bs-ca.pem"
