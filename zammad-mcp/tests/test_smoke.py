"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from zammad_mcp import server
from zammad_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_tickets",
    "get_ticket",
    "search_tickets",
    "get_ticket_articles",
    "get_article",
    "list_users",
    "search_users",
    "whoami",
    "list_organizations",
    "list_reference",
    "zammad_get",
    "add_note",
    "update_ticket",
    "create_ticket",
    "tag_ticket",
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
    assert "path" in tools["zammad_get"].inputSchema["properties"]
    assert "query" in tools["search_tickets"].inputSchema["properties"]
    assert "ticket_id" in tools["get_ticket"].inputSchema["properties"]
    assert "kind" in tools["list_reference"].inputSchema["properties"]
    # write tools (always registered; gated at call time by ZAMMAD_ALLOW_WRITE)
    for p in ("ticket_id", "body"):
        assert p in tools["add_note"].inputSchema["properties"]
    for p in ("ticket_id", "pending_time"):
        assert p in tools["update_ticket"].inputSchema["properties"]
    for p in ("ticket_id", "add", "remove"):
        assert p in tools["tag_ticket"].inputSchema["properties"]
    for p in ("title", "group", "customer", "body"):
        assert p in tools["create_ticket"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {"ZAMMAD_BASE_URL": "https://zammad.example.com/", "ZAMMAD_TOKEN": "tok123"}


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.base_url == "https://zammad.example.com"
    assert s.base_origin == "https://zammad.example.com"
    assert s.api_base == "https://zammad.example.com/api/v1"
    assert s.auth_headers == {"Authorization": "Token token=tok123"}
    assert s.allow_write is False
    assert s.httpx_verify is True


def test_missing_token_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"ZAMMAD_BASE_URL": "https://zammad.example.com"})


def test_allow_write_flag_parses():
    env = _base_env()
    env["ZAMMAD_ALLOW_WRITE"] = "true"
    assert Settings.from_env(env).allow_write is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["ZAMMAD_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["ZAMMAD_CA_BUNDLE"] = "/etc/ssl/zammad.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/zammad.pem"


def test_write_tools_refuse_without_allow_write():
    server._client = server.ZammadClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="ZAMMAD_ALLOW_WRITE"):
            asyncio.run(server.tag_ticket(42, add=["vpn"]))
        with pytest.raises(ValueError, match="ZAMMAD_ALLOW_WRITE"):
            asyncio.run(server.update_ticket(42, state="closed"))
    finally:
        server._client = None


def test_tag_and_pending_payloads_match_the_zammad_api():
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path + ("?" + request.url.query.decode() if request.url.query else ""), body))
        if request.url.path.endswith("/tags"):
            return httpx.Response(200, json={"tags": ["vpn", "escalated"]})
        if request.url.path.startswith("/api/v1/tags/"):
            return httpx.Response(201, json=True)
        return httpx.Response(200, json={"id": 42, "state": "pending reminder"})

    env = _base_env()
    env["ZAMMAD_ALLOW_WRITE"] = "true"
    client = server.ZammadClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client

    async def calls():
        out = await server.tag_ticket(42, add=["vpn", "escalated"], remove=["new"])
        assert out == {"ticket_id": 42, "tags": ["vpn", "escalated"]}
        await server.update_ticket(42, state="pending reminder", pending_time="2026-10-12T08:00:00Z")
        with pytest.raises(ValueError, match="Nothing to do"):
            await server.tag_ticket(42)

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    assert seen == [
        ("POST", "/api/v1/tags/add", {"item": "vpn", "object": "Ticket", "o_id": 42}),
        ("POST", "/api/v1/tags/add", {"item": "escalated", "object": "Ticket", "o_id": 42}),
        ("DELETE", "/api/v1/tags/remove", {"item": "new", "object": "Ticket", "o_id": 42}),
        ("GET", "/api/v1/tags?object=Ticket&o_id=42", None),
        ("PUT", "/api/v1/tickets/42?expand=true", {"state": "pending reminder", "pending_time": "2026-10-12T08:00:00Z"}),
    ]
