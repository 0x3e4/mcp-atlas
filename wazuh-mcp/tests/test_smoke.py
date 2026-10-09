"""Static smoke tests: the server imports, all tools register, and the opt-in write tools send
exactly the Manager API requests they should (mocked with httpx.MockTransport, no network).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from wazuh_mcp import server
from wazuh_mcp.config import Settings, WazuhError
from wazuh_mcp.manager import ManagerClient

READ_TOOLS = {
    "search_alerts", "search_archives", "alerts_summary", "get_vulnerabilities", "indexer_search",
    "list_agents", "get_agent_inventory", "get_sca", "search_rules", "manager_status", "manager_api_get",
}
WRITE_TOOLS = {"restart_agents", "add_agent_to_group", "remove_agent_from_group", "run_active_response"}

MANAGER_URL = "https://wazuh.test.corp:55000"


def _tools() -> dict[str, object]:
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_all_tools_registered_with_descriptions():
    tools = _tools()
    assert READ_TOOLS | WRITE_TOOLS <= set(tools)
    for name in READ_TOOLS | WRITE_TOOLS:
        assert tools[name].description and tools[name].description.strip(), name
        assert "properties" in tools[name].inputSchema, name


def test_write_tools_take_a_confirm_code():
    tools = _tools()
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].inputSchema["properties"], name
    assert "agent_ids" in tools["restart_agents"].inputSchema["properties"]
    for p in ("agent_id", "group_id", "exclusive"):
        assert p in tools["add_agent_to_group"].inputSchema["properties"]
    for p in ("agent_ids", "command", "arguments", "alert_data"):
        assert p in tools["run_active_response"].inputSchema["properties"]


def _settings(monkeypatch, **env: str) -> Settings:
    for name in ("WAZUH_ALLOW_WRITE", "WAZUH_CONFIRM_WRITE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WAZUH_MANAGER_URL", MANAGER_URL + "/")
    monkeypatch.setenv("WAZUH_USER", "mcp-api")
    monkeypatch.setenv("WAZUH_PASS", "secret")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings.from_env()


def test_write_flags_default_and_parse(monkeypatch):
    s = _settings(monkeypatch)
    assert s.allow_write is False and s.confirm_write is True
    s = _settings(monkeypatch, WAZUH_ALLOW_WRITE="true", WAZUH_CONFIRM_WRITE="false")
    assert s.allow_write is True and s.confirm_write is False
    # a blank value keeps the safe default instead of silently turning confirmation off
    assert _settings(monkeypatch, WAZUH_CONFIRM_WRITE="").confirm_write is True


def _use(monkeypatch, settings: Settings, handler=None) -> None:
    monkeypatch.setattr(server, "settings", settings)
    client = ManagerClient(settings)
    if handler is not None:
        client._client = httpx.AsyncClient(base_url=settings.manager_url,
                                           transport=httpx.MockTransport(handler))
    monkeypatch.setattr(server, "_manager", client)


def test_write_tools_refuse_without_allow_write(monkeypatch):
    _use(monkeypatch, _settings(monkeypatch))
    with pytest.raises(ValueError, match="WAZUH_ALLOW_WRITE"):
        asyncio.run(server.restart_agents(["001"]))
    with pytest.raises(ValueError, match="WAZUH_ALLOW_WRITE"):
        asyncio.run(server.add_agent_to_group("1", "webservers"))
    with pytest.raises(ValueError, match="WAZUH_ALLOW_WRITE"):
        asyncio.run(server.remove_agent_from_group("1", "webservers"))
    with pytest.raises(ValueError, match="WAZUH_ALLOW_WRITE"):
        asyncio.run(server.run_active_response(["001"], "!firewall-drop"))


def _handler(seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        assert request.headers["Authorization"] == "Bearer jwt"
        body = json.loads(request.content) if request.content else None
        query = request.url.query.decode()
        seen.append((request.method, request.url.path + (f"?{query}" if query else ""), body))
        if request.method == "DELETE":
            return httpx.Response(200, json={"message": "Agent '004' removed from 'dmz'.", "error": 0})
        return httpx.Response(200, json={
            "data": {"affected_items": ["001", "005"], "total_affected_items": 2,
                     "total_failed_items": 0, "failed_items": []},
            "message": "Restart command was sent to all agents", "error": 0,
        })
    return handler


def test_write_requests_match_the_wazuh_api(monkeypatch):
    seen: list[tuple[str, str, object]] = []
    _use(monkeypatch, _settings(monkeypatch, WAZUH_ALLOW_WRITE="true", WAZUH_CONFIRM_WRITE="false"),
         _handler(seen))

    async def calls():
        out = await server.restart_agents(["1", "005, 1"])
        assert out == {"total": 2, "count": 2, "results": ["001", "005"],
                       "message": "Restart command was sent to all agents"}
        await server.add_agent_to_group("3", "webservers")
        await server.add_agent_to_group("3", "dmz", exclusive=True)
        out = await server.remove_agent_from_group("004", "dmz")
        assert out == {"message": "Agent '004' removed from 'dmz'."}
        await server.run_active_response(["001"], "!firewall-drop", alert_data={"srcip": "10.0.0.10"})
        await server.run_active_response(["002"], "restart-wazuh0", arguments=["-", "null"])
        # never let an empty list through: the API would target ALL agents
        with pytest.raises(ValueError, match="ALL agents"):
            await server.restart_agents([])
        with pytest.raises(ValueError, match="manager itself"):
            await server.restart_agents(["000"])
        with pytest.raises(ValueError, match="Invalid agent id"):
            await server.restart_agents(["all"])
        with pytest.raises(ValueError, match="Invalid group name"):
            await server.add_agent_to_group("1", "../etc")
        with pytest.raises(ValueError, match="Invalid active-response command"):
            await server.run_active_response(["001"], "rm -rf /")

    asyncio.run(calls())

    assert seen == [
        ("PUT", "/agents/restart?agents_list=001%2C005", None),
        ("PUT", "/agents/003/group/webservers", None),
        ("PUT", "/agents/003/group/dmz?force_single_group=true", None),
        ("DELETE", "/agents/004/group/dmz", None),
        ("PUT", "/active-response?agents_list=001",
         {"command": "!firewall-drop", "alert": {"data": {"srcip": "10.0.0.10"}}}),
        ("PUT", "/active-response?agents_list=002",
         {"command": "restart-wazuh0", "arguments": ["-", "null"]}),
    ]


def test_api_errors_include_detail_and_remediation(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        return httpx.Response(403, json={"title": "Permission Denied",
                                         "detail": "Permission denied: Resource type: agent:id",
                                         "remediation": "Check the user's RBAC role", "error": 4000})

    _use(monkeypatch, _settings(monkeypatch, WAZUH_ALLOW_WRITE="true", WAZUH_CONFIRM_WRITE="false"), handler)
    with pytest.raises(WazuhError, match=r"PUT /agents/restart -> 403: Permission Denied: .*agent:id \(Check"):
        asyncio.run(server.restart_agents(["001"]))


def test_writes_need_a_matching_confirm_code(monkeypatch):
    seen: list[tuple[str, str, object]] = []
    _use(monkeypatch, _settings(monkeypatch, WAZUH_ALLOW_WRITE="true"), _handler(seen))

    async def calls():
        preview = await server.run_active_response(["001"], "!firewall-drop", alert_data={"srcip": "10.0.0.10"})
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert preview["change"] == {"agents_list": ["001"], "command": "!firewall-drop",
                                     "alert": {"data": {"srcip": "10.0.0.10"}}}
        assert "block IPs" in preview["summary"]
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.run_active_response(["001"], "!firewall-drop",
                                                 alert_data={"srcip": "10.0.0.11"}, confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert seen == []
        done = await server.run_active_response(["001"], "!firewall-drop",
                                                alert_data={"srcip": "10.0.0.10"}, confirm=code)
        assert done.get("status") != "confirmation_required"

    asyncio.run(calls())
    assert [(m, p) for m, p, _ in seen] == [("PUT", "/active-response?agents_list=001")]
