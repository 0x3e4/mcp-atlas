"""Static smoke tests: the server imports and all tools register with sane schemas (no network)."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from vcenter_mcp import server
from vcenter_mcp.client import VCenterError
from vcenter_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_vms",
    "get_vm",
    "get_vm_power",
    "list_hosts",
    "list_clusters",
    "list_datastores",
    "list_networks",
    "list_datacenters",
    "list_resource_pools",
    "appliance_version",
    "appliance_health",
    "vcenter_get",
    "vm_power",
    "vm_guest_power",
}

WRITE_TOOLS = {"vm_power", "vm_guest_power"}


def _tools() -> dict[str, object]:
    listed = asyncio.run(server.mcp.list_tools())
    return {t.name: t for t in listed}


def test_all_tools_registered():
    assert EXPECTED_TOOLS <= set(_tools())


def test_tools_have_descriptions_and_schemas():
    for name, tool in _tools().items():
        if name not in EXPECTED_TOOLS:
            continue
        assert tool.description and tool.description.strip(), f"{name} missing description"
        assert tool.inputSchema and "properties" in tool.inputSchema, f"{name} missing schema"


def test_required_params_present():
    tools = _tools()
    assert "path" in tools["vcenter_get"].inputSchema["properties"]
    assert "vm" in tools["get_vm"].inputSchema["properties"]
    assert "vm" in tools["get_vm_power"].inputSchema["properties"]
    # write tools (always registered; gated at call time by VCENTER_ALLOW_WRITE)
    for name in WRITE_TOOLS:
        props = tools[name].inputSchema["properties"]
        assert {"vm", "action", "confirm"} <= set(props), name


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "VCENTER_BASE_URL": "https://vcenter.example.com/",
        "VCENTER_USERNAME": "administrator@vsphere.local",
        "VCENTER_PASSWORD": "secret",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.base_url == "https://vcenter.example.com"
    assert s.base_origin == "https://vcenter.example.com"
    assert s.api_base == "https://vcenter.example.com/api"
    assert s.httpx_verify is True


def test_missing_password_rejected():
    env = _base_env()
    del env["VCENTER_PASSWORD"]
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["VCENTER_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False
    env = _base_env()
    env["VCENTER_CA_BUNDLE"] = "/etc/ssl/vcenter.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/vcenter.pem"


def test_allow_write_defaults_off_and_parses():
    assert Settings.from_env(_base_env()).allow_write is False
    assert Settings.from_env(_base_env()).confirm_write is True
    env = _base_env()
    env["VCENTER_ALLOW_WRITE"] = "true"
    env["VCENTER_CONFIRM_WRITE"] = "false"
    s = Settings.from_env(env)
    assert s.allow_write is True and s.confirm_write is False


def test_write_tools_refuse_without_allow_write():
    server._client = server.VCenterClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="VCENTER_ALLOW_WRITE"):
            asyncio.run(server.vm_power("vm-42", "stop"))
        with pytest.raises(ValueError, match="VCENTER_ALLOW_WRITE"):
            asyncio.run(server.vm_guest_power("vm-42", "shutdown"))
    finally:
        server._client = None


def _write_client(handler, *, confirm_write: bool = False) -> server.VCenterClient:
    env = _base_env()
    env["VCENTER_ALLOW_WRITE"] = "true"
    env["VCENTER_CONFIRM_WRITE"] = "true" if confirm_write else "false"
    client = server.VCenterClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client._session_id = "sid-test"  # skip the login round trip
    return client


def _vm_handler(seen: list[tuple[str, str, str]]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.url.query.decode()))
        assert request.headers["vmware-api-session-id"] == "sid-test"
        if request.method == "GET":
            return httpx.Response(200, json={"name": "app01", "power_state": "POWERED_ON", "cpu": {"count": 2}})
        return httpx.Response(204)
    return handler


def test_write_requests_match_the_vcenter_api():
    seen: list[tuple[str, str, str]] = []
    server._client = _write_client(_vm_handler(seen))

    async def calls():
        out = await server.vm_guest_power("vm-42", "shutdown")
        assert out["requested"] is True and out["previous_state"] == "POWERED_ON" and out["name"] == "app01"
        out = await server.vm_power("vm-42", "reset")
        assert out["done"] is True
        with pytest.raises(ValueError, match="action must be one of"):
            await server.vm_power("vm-42", "destroy")
        with pytest.raises(ValueError, match="action must be one of"):
            await server.vm_guest_power("vm-42", "stop")

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    assert seen == [
        ("GET", "/api/vcenter/vm/vm-42", ""),
        ("POST", "/api/vcenter/vm/vm-42/guest/power", "action=shutdown"),
        ("GET", "/api/vcenter/vm/vm-42", ""),
        ("POST", "/api/vcenter/vm/vm-42/power", "action=reset"),
    ]


def test_api_errors_name_the_error_type():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"name": "app01", "power_state": "POWERED_OFF"})
        return httpx.Response(400, json={"error_type": "ALREADY_IN_DESIRED_STATE",
                                         "messages": [{"id": "x", "default_message": "Virtual machine is already powered off."}]})

    server._client = _write_client(handler)
    try:
        with pytest.raises(VCenterError, match=r"400 \(ALREADY_IN_DESIRED_STATE\): Virtual machine is already powered off"):
            asyncio.run(server.vm_power("vm-42", "stop"))
    finally:
        server._client = None


def test_writes_need_a_matching_confirm_code():
    seen: list[tuple[str, str, str]] = []
    server._client = _write_client(_vm_handler(seen), confirm_write=True)

    async def calls():
        preview = await server.vm_power("vm-42", "stop")
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert preview["change"] == {"vm": "vm-42", "action": "stop"}
        assert "HARD power off" in preview["summary"] and "app01" in preview["summary"]
        assert "POWERED_ON" in preview["summary"]
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.vm_power("vm-42", "reset", confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert [m for m, _, _ in seen] == ["GET", "GET"]  # previews only read
        done = await server.vm_power("vm-42", "stop", confirm=code)
        assert done["done"] is True

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert [r for r in seen if r[0] == "POST"] == [("POST", "/api/vcenter/vm/vm-42/power", "action=stop")]
