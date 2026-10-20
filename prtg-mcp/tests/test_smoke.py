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
    "get_object_property",
    # write tools (always registered; gated at call time by PRTG_ALLOW_WRITE)
    "pause_object",
    "resume_object",
    "acknowledge_alarm",
    "scan_now",
    "rename_object",
    "update_object",
    "set_channel_limits",
    "clone_object",
    "move_object",
    "add_group",
    "add_device",
    "discover_now",
}

WRITE_TOOLS = {
    "pause_object", "resume_object", "acknowledge_alarm", "scan_now", "rename_object", "update_object",
    "set_channel_limits", "clone_object", "move_object", "add_group", "add_device", "discover_now",
}

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
        with pytest.raises(ValueError, match="PRTG_ALLOW_WRITE"):
            asyncio.run(server.clone_object(2040, "web-02", 50, host="10.0.0.11"))
    finally:
        server._client = None


def test_prtg_get_refuses_state_changing_endpoints():
    server._client = server.PrtgClient(Settings.from_env(_BASE))
    try:
        for ep in ("pause.htm", "/api/acknowledgealarm.htm", "setobjectproperty.htm", "deleteobject.htm",
                   "https://prtg.test.corp/api/scannow.htm", "duplicateobject.htm", "rename.htm",
                   "https://prtg.test.corp/moveobjectnow.htm", "adddevice2.htm", "discovernow.htm"):
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


def _prop(value: str) -> httpx.Response:
    return httpx.Response(200, text=f"<?xml version='1.0'?><prtg><version>24.1</version><result>{value}</result></prtg>")


def test_get_object_property_reads_the_raw_value():
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        assert request.url.path == "/api/getobjectproperty.htm"
        return _prop("linux web &amp; prod")

    server._client = _write_client(handler)
    try:
        out = asyncio.run(server.get_object_property(2040, "tags_"))
        assert out == {"object_id": 2040, "property": "tags", "value": "linux web & prod"}
        out = asyncio.run(server.get_object_property(2143, "limitmaxerror", channel_id=2))
        assert out["channel_id"] == 2
    finally:
        server._client = None
    assert seen[0] == {"id": "2040", "name": "tags", "show": "nohtmlencode", "apitoken": "tok"}
    assert seen[1]["subtype"] == "channel" and seen[1]["subid"] == "2"


def test_new_write_requests_match_the_prtg_api():
    seen: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        params.pop("apitoken")
        seen.append((request.url.path, params))
        if request.url.path == "/api/getobjectproperty.htm":
            return _prop("linux old")
        if request.url.path == "/api/duplicateobject.htm":
            return httpx.Response(302, headers={"location": "/device.htm?id=4711&tabid=1"})
        if request.url.path in ("/api/rename.htm", "/moveobjectnow.htm", "/api/setposition.htm"):
            return httpx.Response(302, headers={"location": "/device.htm?id=2040"})
        return httpx.Response(200, text="<HTML>OK</HTML>")

    server._client = _write_client(handler)

    async def calls():
        await server.rename_object(2040, " web-01 ")
        out = await server.update_object(2040, add_tags=["web", "prod"], remove_tags=["old"], priority=4,
                                         location="Room 1", interval_seconds=300)
        assert out["ok"] is True and len(out["applied"]) == 5
        await server.set_channel_limits(2143, 0, upper_error=90, upper_warning=80.5, enabled=True)
        clone = await server.clone_object(2040, "web-02", 50, host="10.0.0.11", resume=True)
        assert clone["new_id"] == 4711 and clone["paused"] is False
        await server.move_object(2040, target_id=60, position="top")
        await server.discover_now(2040, templates=["Linux SNMP.odt"])

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    assert seen == [
        ("/api/rename.htm", {"id": "2040", "value": "web-01"}),
        ("/api/getobjectproperty.htm", {"id": "2040", "name": "tags", "show": "nohtmlencode"}),
        ("/api/setobjectproperty.htm", {"id": "2040", "name": "tags", "value": "linux web prod"}),
        ("/api/setpriority.htm", {"id": "2040", "prio": "4"}),
        ("/api/setobjectproperty.htm", {"id": "2040", "name": "location", "value": "Room 1"}),
        ("/api/setobjectproperty.htm", {"id": "2040", "name": "intervalgroup_", "value": "0"}),
        ("/api/setobjectproperty.htm", {"id": "2040", "name": "interval", "value": "300|5 minutes"}),
        ("/api/setobjectproperty.htm", {"id": "2143", "subtype": "channel", "subid": "0", "name": "limitmaxerror", "value": "90"}),
        ("/api/setobjectproperty.htm", {"id": "2143", "subtype": "channel", "subid": "0", "name": "limitmaxwarning", "value": "80.5"}),
        ("/api/setobjectproperty.htm", {"id": "2143", "subtype": "channel", "subid": "0", "name": "limitmode", "value": "1"}),
        ("/api/duplicateobject.htm", {"id": "2040", "name": "web-02", "targetid": "50", "host": "10.0.0.11"}),
        ("/api/pause.htm", {"id": "4711", "action": "1"}),
        ("/moveobjectnow.htm", {"id": "2040", "targetid": "60"}),
        ("/api/setposition.htm", {"id": "2040", "newpos": "top"}),
        ("/api/discovernow.htm", {"id": "2040", "template": '"Linux SNMP.odt"'}),
    ]


def test_interval_values():
    assert server._interval(30) == "30|30 seconds"
    assert server._interval(60) == "60|60 seconds"
    assert server._interval(90) == "90|90 seconds"
    assert server._interval(600) == "600|10 minutes"
    assert server._interval(3600) == "3600|1 hour"
    assert server._interval(86400) == "86400|24 hours"


def test_add_device_finds_the_new_id():
    tables = [
        {"devices": [{"objid": 3001, "name": "web-03"}]},
        {"devices": [{"objid": 3001, "name": "web-03"}, {"objid": 3050, "name": "web-03"}, {"objid": 3051, "name": "web-03b"}]},
    ]
    seen: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        params.pop("apitoken")
        seen.append((request.url.path, params))
        if request.url.path == "/api/table.json":
            return httpx.Response(200, json=tables.pop(0))
        return httpx.Response(302, headers={"location": "/device.htm?id=50"})

    server._client = _write_client(handler)
    try:
        out = asyncio.run(server.add_device(50, "web-03", "10.0.0.13", tags=["web"]))
    finally:
        server._client = None
    assert out["new_id"] == 3050 and out["endpoint"] == "/adddevice2.htm"
    assert seen[1] == ("/adddevice2.htm", {"id": "50", "name_": "web-03", "host_": "10.0.0.13", "ipversion_": "0",
                                           "discoverytype_": "0", "discoveryschedule_": "0", "tags_": "web"})
    assert seen[0][1]["filter_parentid"] == "50"


def test_clone_without_new_id_is_an_error():
    server._client = _write_client(lambda r: httpx.Response(302, headers={"location": "/api/duplicateobject.htm?id=2040"}))
    try:
        with pytest.raises(PrtgError, match="instead of the new object's page"):
            asyncio.run(server.clone_object(2040, "web-02", 50))
    finally:
        server._client = None


def test_failed_step_reports_what_was_applied():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.params["name"] if "name" in request.url.params else request.url.path)
        if len(calls) == 2:
            return httpx.Response(302, headers={"location": "/error.htm?errormsg=Invalid+value"})
        return httpx.Response(200, text="OK")

    server._client = _write_client(handler)
    try:
        with pytest.raises(PrtgError, match=r"Invalid value.*already applied: tags"):
            asyncio.run(server.update_object(2040, tags=["a"], comments="x", location="y"))
    finally:
        server._client = None
    assert len(calls) == 2


def test_update_object_validation():
    server._client = _write_client(lambda r: httpx.Response(200, text="OK"))
    try:
        with pytest.raises(ValueError, match="not both"):
            asyncio.run(server.update_object(2040, tags=["a"], add_tags=["b"]))
        with pytest.raises(ValueError, match="no spaces"):
            asyncio.run(server.update_object(2040, tags=["two words"]))
        with pytest.raises(ValueError, match="Nothing to update"):
            asyncio.run(server.update_object(2040))
        with pytest.raises(ValueError, match="position"):
            asyncio.run(server.move_object(2040, position="sideways"))
    finally:
        server._client = None


def test_tag_merge_is_bound_into_the_confirm_code():
    current = {"value": "linux"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/getobjectproperty.htm":
            return _prop(current["value"])
        return httpx.Response(200, text="OK")

    server._client = _write_client(handler, confirm_write=True)

    async def calls():
        preview = await server.update_object(2040, add_tags=["web"])
        assert "Tags become: linux web" in preview["summary"]
        current["value"] = "linux db"  # someone else changed the tags in between
        again = await server.update_object(2040, add_tags=["web"], confirm=preview["confirm_code"])
        assert again["status"] == "confirmation_required" and "linux db web" in again["summary"]

    try:
        asyncio.run(calls())
    finally:
        server._client = None
