"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls (writes use httpx.MockTransport).
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from prtg_mcp import server
from prtg_mcp.client import PrtgError
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
    # write tools (always registered; gated at call time by PRTG_ALLOW_WRITE)
    "pause_object",
    "resume_object",
    "acknowledge_alarm",
    "scan_now",
}

WRITE_TOOLS = {"pause_object", "resume_object", "acknowledge_alarm", "scan_now"}

_BASE = {"PRTG_BASE_URL": "https://prtg.test.corp", "PRTG_API_TOKEN": "tok"}


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
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].inputSchema["properties"], name


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


def test_allow_write_defaults_off_and_parses():
    assert Settings.from_env(_BASE).allow_write is False
    assert Settings.from_env(_BASE).confirm_write is True
    s = Settings.from_env({**_BASE, "PRTG_ALLOW_WRITE": "true", "PRTG_CONFIRM_WRITE": "false"})
    assert s.allow_write is True and s.confirm_write is False


def test_write_tools_refuse_without_allow_write():
    server._client = server.PrtgClient(Settings.from_env(_BASE))
    try:
        with pytest.raises(ValueError, match="PRTG_ALLOW_WRITE"):
            asyncio.run(server.pause_object(2040))
        with pytest.raises(ValueError, match="PRTG_ALLOW_WRITE"):
            asyncio.run(server.acknowledge_alarm(2143, message="on it"))
    finally:
        server._client = None


def test_prtg_get_refuses_state_changing_endpoints():
    server._client = server.PrtgClient(Settings.from_env(_BASE))
    try:
        for ep in ("pause.htm", "/api/acknowledgealarm.htm", "setobjectproperty.htm", "deleteobject.htm",
                   "https://prtg.test.corp/api/scannow.htm"):
            with pytest.raises(ValueError, match="read-only"):
                asyncio.run(server.prtg_get(ep, params={"id": 1}))
    finally:
        server._client = None


def _write_client(handler, *, confirm_write: bool = False) -> server.PrtgClient:
    env = {**_BASE, "PRTG_ALLOW_WRITE": "true", "PRTG_CONFIRM_WRITE": "true" if confirm_write else "false"}
    client = server.PrtgClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def test_write_requests_match_the_prtg_api():
    seen: list[tuple[str, str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, dict(request.url.params)))
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, text="<HTML><BODY>OK</BODY></HTML>")

    server._client = _write_client(handler)

    async def calls():
        out = await server.pause_object(2040, message="patching vm-42")
        assert out["ok"] is True and out["endpoint"] == "/api/pause.htm" and out["response"] == "OK"
        await server.pause_object(2040, duration_minutes=60)
        await server.resume_object(2040)
        await server.acknowledge_alarm(2143, message="on it", duration_minutes=15)
        await server.acknowledge_alarm(2143)
        await server.scan_now(2143)

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    auth = {"apitoken": "tok"}
    assert seen == [
        ("GET", "/api/pause.htm", {"id": "2040", "action": "0", "pausemsg": "patching vm-42", **auth}),
        ("GET", "/api/pauseobjectfor.htm", {"id": "2040", "duration": "60", **auth}),
        ("GET", "/api/pause.htm", {"id": "2040", "action": "1", **auth}),
        ("GET", "/api/acknowledgealarm.htm", {"id": "2143", "ackmsg": "on it", "duration": "15", **auth}),
        ("GET", "/api/acknowledgealarm.htm", {"id": "2143", **auth}),
        ("GET", "/api/scannow.htm", {"id": "2143", **auth}),
    ]


@pytest.mark.parametrize(
    ("response", "match"),
    [
        (httpx.Response(302, headers={"location": "/error.htm?errormsg=Sorry%2C+the+selected+object+cannot+be+used+here."}),
         "selected object cannot be used here"),
        (httpx.Response(302, headers={"location": "/public/login.htm?loginurl=%2Fapi%2Fpause.htm&errormsg="}),
         "authentication failed"),
        (httpx.Response(302, headers={"location": "/welcome.htm"}), "unexpected redirect"),
        (httpx.Response(200, text='<html><form id="loginform" action="/public/checklogin.htm"></form></html>'),
         "authentication failed"),
        (httpx.Response(200, text='<div class="errormsg"><h3>Error</h3><p>Access denied.</p></div>'), "Access denied"),
        (httpx.Response(400, text="<?xml version='1.0'?><prtg><error>Object not found</error></prtg>"),
         "Object not found"),
        (httpx.Response(401, text="Unauthorized"), "401"),
    ],
)
def test_write_failures_are_not_reported_as_success(response, match):
    server._client = _write_client(lambda request: response)
    try:
        with pytest.raises(PrtgError, match=match):
            asyncio.run(server.scan_now(2143))
    finally:
        server._client = None


def test_writes_need_a_matching_confirm_code():
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        return httpx.Response(200, text="OK")

    server._client = _write_client(handler, confirm_write=True)

    async def calls():
        preview = await server.pause_object(2040, message="maintenance", duration_minutes=30)
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert preview["change"] == {"endpoint": "pauseobjectfor.htm", "id": 2040, "duration": 30,
                                     "pausemsg": "maintenance"}
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.pause_object(2040, message="maintenance", duration_minutes=600, confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert sent == []
        done = await server.pause_object(2040, message="maintenance", duration_minutes=30, confirm=code)
        assert done["ok"] is True

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == ["/api/pauseobjectfor.htm"]
