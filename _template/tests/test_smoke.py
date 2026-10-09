"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls. Keep ``EXPECTED_TOOLS`` in sync with the
tools you define in ``server.py``.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from template_mcp import server
from template_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "search_items",
    "get_item",
    "api_get",
    "update_item",
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


def _write_env() -> dict[str, str]:
    return {"TEMPLATE_BASE_URL": "https://api.example.com", "TEMPLATE_API_KEY": "k", "TEMPLATE_ALLOW_WRITE": "true"}


def test_write_flags_default_to_off_and_confirm():
    s = Settings.from_env({"TEMPLATE_BASE_URL": "https://api.example.com", "TEMPLATE_API_KEY": "k"})
    assert s.allow_write is False and s.confirm_write is True
    assert "confirm" in _tools()["update_item"].inputSchema["properties"]


def test_write_refused_without_allow_write():
    server._client = server.ApiClient(Settings.from_env({"TEMPLATE_BASE_URL": "https://api.example.com", "TEMPLATE_API_KEY": "k"}))
    try:
        with pytest.raises(ValueError, match="TEMPLATE_ALLOW_WRITE"):
            asyncio.run(server.update_item("7", name="x"))
    finally:
        server._client = None


def test_writes_need_a_matching_confirm_code():
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.method)
        return httpx.Response(200, json={"id": "7", "name": "x"})

    client = server.ApiClient(Settings.from_env(_write_env()))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client

    async def calls():
        preview = await server.update_item("7", name="x")
        assert preview["status"] == "confirmation_required" and preview["change"] == {"item_id": "7", "name": "x"}
        code = preview["confirm_code"]
        assert (await server.update_item("7", name="y", confirm=code))["status"] == "confirmation_required"
        assert sent == []
        assert (await server.update_item("7", name="x", confirm=code))["name"] == "x"

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == ["PATCH"]
