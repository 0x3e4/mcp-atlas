"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from defender_mcp import server
from defender_mcp.config import ConfigError, Settings
from defender_mcp.graph import GraphError

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
    "update_incident",
    "add_incident_comment",
    "update_alert",
    "add_alert_comment",
}

WRITE_TOOLS = {"update_incident", "add_incident_comment", "update_alert", "add_alert_comment"}


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
    for p in ("incident_id", "status", "assigned_to", "classification", "determination", "custom_tags"):
        assert p in tools["update_incident"].inputSchema["properties"]
    for p in ("alert_id", "status", "assigned_to", "classification", "determination"):
        assert p in tools["update_alert"].inputSchema["properties"]
    assert "comment" in tools["add_incident_comment"].inputSchema["properties"]
    assert "comment" in tools["add_alert_comment"].inputSchema["properties"]
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].inputSchema["properties"], name


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


# ---- write tools (opt-in) -----------------------------------------------

def _base_env() -> dict[str, str]:
    return {"DEFENDER_TENANT_ID": "t", "DEFENDER_CLIENT_ID": "c", "DEFENDER_CLIENT_SECRET": "s"}


def test_allow_write_defaults_off_and_confirm_defaults_on():
    s = Settings.from_env(_base_env())
    assert s.allow_write is False and s.confirm_write is True
    env = _base_env() | {"DEFENDER_ALLOW_WRITE": "true", "DEFENDER_CONFIRM_WRITE": "false"}
    s = Settings.from_env(env)
    assert s.allow_write is True and s.confirm_write is False


def test_write_tools_refuse_without_allow_write():
    server._client = server.GraphClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="DEFENDER_ALLOW_WRITE"):
            asyncio.run(server.update_incident("29", status="resolved"))
        with pytest.raises(ValueError, match="DEFENDER_ALLOW_WRITE"):
            asyncio.run(server.add_alert_comment("da123", "checked"))
    finally:
        server._client = None


def _write_client(handler, *, confirm_write: bool = False) -> server.GraphClient:
    """A GraphClient on a MockTransport; the token endpoint is answered here, Graph calls by ``handler``."""
    env = _base_env() | {
        "DEFENDER_ALLOW_WRITE": "true",
        "DEFENDER_CONFIRM_WRITE": "true" if confirm_write else "false",
    }

    def route(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return handler(request)

    client = server.GraphClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(route))
    return client


def test_write_payloads_match_the_graph_api():
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer tok"
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body))
        if request.url.path.endswith("/comments"):
            return httpx.Response(200, json={"value": [
                {"comment": "older", "createdByDisplayName": "API-App", "createdDateTime": "2026-10-01T08:00:00Z"},
                {"comment": "Contained on vm-42", "createdByDisplayName": "API-App", "createdDateTime": "2026-10-09T08:00:00Z"},
            ]})
        if "/incidents/" in request.url.path:
            return httpx.Response(200, json={"id": "29", "status": "resolved", "classification": "truePositive",
                                             "determination": "malware", "customTags": ["ir-2026-10"],
                                             "resolvingComment": "Reimaged.", "comments": []})
        return httpx.Response(200, json={"id": "da123", "status": "inProgress", "assignedTo": None,
                                         "classification": "falsePositive", "determination": "notMalicious",
                                         "evidence": [{}]})

    server._client = _write_client(handler)

    async def calls():
        inc = await server.update_incident(
            "29", status="resolved", assigned_to="soc@app.test.corp", classification="truePositive",
            determination="malware", custom_tags=["ir-2026-10", " ir-2026-10 ", ""], resolving_comment="Reimaged.",
        )
        assert inc["status"] == "resolved" and inc["resolvingComment"] == "Reimaged."
        alert = await server.update_alert("da123", status="inProgress", assigned_to="",
                                          classification="falsePositive", determination="notMalicious")
        assert alert["determination"] == "notMalicious" and alert["evidenceCount"] == 1
        c = await server.add_incident_comment("29", "Contained on vm-42")
        assert c["commentCount"] == 2 and c["latest"]["comment"] == "Contained on vm-42"
        await server.add_alert_comment("da123", "Benign admin script")
        with pytest.raises(ValueError, match="Nothing to update"):
            await server.update_alert("da123")
        with pytest.raises(ValueError, match="status must be one of"):
            await server.update_incident("29", status="redirected")
        with pytest.raises(ValueError, match="notEnoughDataToValidate"):
            await server.update_alert("da123", determination="clean")
        with pytest.raises(ValueError, match="plain id"):
            await server.update_incident("../alerts_v2/x", status="active")

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    comment = {"@odata.type": "microsoft.graph.security.alertComment"}
    assert seen == [
        ("PATCH", "/v1.0/security/incidents/29", {
            "status": "resolved", "assignedTo": "soc@app.test.corp", "classification": "truePositive",
            "determination": "malware", "customTags": ["ir-2026-10"], "resolvingComment": "Reimaged."}),
        ("PATCH", "/v1.0/security/alerts_v2/da123", {
            "status": "inProgress", "assignedTo": None, "classification": "falsePositive",
            "determination": "notMalicious"}),
        ("POST", "/v1.0/security/incidents/29/comments", {**comment, "comment": "Contained on vm-42"}),
        ("POST", "/v1.0/security/alerts_v2/da123/comments", {**comment, "comment": "Benign admin script"}),
    ]


def test_write_errors_surface_details_and_write_permissions():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/29"):
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied", "message": "denied"}})
        return httpx.Response(400, json={"error": {"code": "BadRequest", "message": "Invalid request",
                                                   "details": [{"target": "status", "message": "Unknown value"}]}})

    server._client = _write_client(handler)
    try:
        with pytest.raises(GraphError, match="SecurityIncident.ReadWrite.All"):
            asyncio.run(server.update_incident("29", status="active"))
        with pytest.raises(GraphError, match="status: Unknown value"):
            asyncio.run(server.update_alert("da123", status="new"))
    finally:
        server._client = None


def test_writes_need_a_matching_confirm_code():
    sent: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path))
        return httpx.Response(200, json={"id": "29", "status": "resolved"})

    server._client = _write_client(handler, confirm_write=True)

    async def calls():
        preview = await server.update_incident("29", status="resolved", classification="falsePositive")
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert preview["change"] == {"incident_id": "29", "status": "resolved", "classification": "falsePositive"}
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.update_incident("29", status="resolved", classification="truePositive", confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert sent == []
        done = await server.update_incident("29", status="resolved", classification="falsePositive", confirm=code)
        assert done["id"] == "29" and done["status"] == "resolved"

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == [("PATCH", "/v1.0/security/incidents/29")]
