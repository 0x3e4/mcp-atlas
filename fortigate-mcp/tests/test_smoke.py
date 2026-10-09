"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls (write tests use httpx.MockTransport).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from fortigate_mcp import server
from fortigate_mcp.client import FortiError
from fortigate_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_policies",
    "list_addresses",
    "list_services",
    "list_vips",
    "list_interfaces",
    "list_static_routes",
    "system_info",
    "system_resources",
    "ha_status",
    "interface_status",
    "policy_stats",
    "vpn_status",
    "routing_table",
    "fortios_get",
}
WRITE_TOOLS = {
    "create_address",
    "update_address",
    "add_to_address_group",
    "remove_from_address_group",
    "set_policy_status",
}
EXPECTED_TOOLS |= WRITE_TOOLS


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
    assert "tree" in tools["fortios_get"].inputSchema["properties"]
    assert "path" in tools["fortios_get"].inputSchema["properties"]
    assert "ipv6" in tools["list_policies"].inputSchema["properties"]
    assert "groups" in tools["list_addresses"].inputSchema["properties"]
    # write tools (always registered; gated at call time by FORTIGATE_ALLOW_WRITE)
    for p in ("name", "subnet", "fqdn", "start_ip", "end_ip", "comment", "vdom"):
        assert p in tools["create_address"].inputSchema["properties"]
        assert p in tools["update_address"].inputSchema["properties"]
    for name in ("add_to_address_group", "remove_from_address_group"):
        for p in ("group", "members", "vdom"):
            assert p in tools[name].inputSchema["properties"]
    for p in ("policy_id", "enabled", "comment", "vdom"):
        assert p in tools["set_policy_status"].inputSchema["properties"]
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].inputSchema["properties"], name


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "FORTIGATE_BASE_URL": "https://192.0.2.1/",
        "FORTIGATE_API_TOKEN": "abc123",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.vdom == "root"
    assert s.base_url == "https://192.0.2.1"
    assert s.base_origin == "https://192.0.2.1"
    assert s.api_base == "https://192.0.2.1/api/v2"
    assert s.httpx_verify is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["FORTIGATE_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["FORTIGATE_CA_BUNDLE"] = "/etc/ssl/fgt-ca.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/fgt-ca.pem"


def test_custom_vdom():
    env = _base_env()
    env["FORTIGATE_VDOM"] = "VDOM-DMZ"
    assert Settings.from_env(env).vdom == "VDOM-DMZ"


def test_allow_write_defaults_off_and_parses():
    assert Settings.from_env(_base_env()).allow_write is False
    assert Settings.from_env(_base_env()).confirm_write is True
    env = _base_env()
    env["FORTIGATE_ALLOW_WRITE"] = "true"
    env["FORTIGATE_CONFIRM_WRITE"] = "false"
    s = Settings.from_env(env)
    assert s.allow_write is True and s.confirm_write is False


def test_write_tools_refuse_without_allow_write():
    server._client = server.FortiClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="FORTIGATE_ALLOW_WRITE"):
            asyncio.run(server.create_address("srv-app", subnet="10.0.0.10"))
        with pytest.raises(ValueError, match="FORTIGATE_ALLOW_WRITE"):
            asyncio.run(server.add_to_address_group("grp-web", ["srv-app"]))
        with pytest.raises(ValueError, match="FORTIGATE_ALLOW_WRITE"):
            asyncio.run(server.set_policy_status(12, False))
    finally:
        server._client = None


def _write_client(handler, *, confirm_write: bool = False) -> server.FortiClient:
    env = _base_env()
    env["FORTIGATE_ALLOW_WRITE"] = "true"
    env["FORTIGATE_CONFIRM_WRITE"] = "true" if confirm_write else "false"
    client = server.FortiClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def _ok(method: str, mkey: object = None) -> httpx.Response:
    return httpx.Response(200, json={"http_method": method, "revision": "abc", "mkey": mkey,
                                     "status": "success", "http_status": 200, "vdom": "root",
                                     "serial": "FGVM00000000", "version": "v7.4.4", "build": 2662})


def test_write_payloads_match_the_fortios_api():
    seen: list[tuple[str, str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.raw_path.decode().split("?")[0],
                     request.url.params.get("vdom"), body))
        if request.method == "GET":  # group edits read the current member list first
            return httpx.Response(200, json={"status": "success", "http_status": 200, "results": [
                {"name": "grp web/dmz", "member": [{"name": "srv-a", "q_origin_key": "srv-a"},
                                                   {"name": "srv-b", "q_origin_key": "srv-b"}]}]})
        return _ok(request.method, "srv-app")

    server._client = _write_client(handler)

    async def calls():
        out = await server.create_address("srv-app", subnet="10.0.0.0/24", comment="app tier")
        assert out["status"] == "success" and out["mkey"] == "srv-app" and "serial" not in out
        await server.create_address("app-fqdn", fqdn="app.test.corp", vdom="VDOM-DMZ")
        await server.create_address("pool", start_ip="10.0.0.10", end_ip="10.0.0.20")
        await server.update_address("srv a/1", subnet="10.0.0.10 255.255.255.255", comment="")
        added = await server.add_to_address_group("grp web/dmz", ["srv-b", "srv-c", "srv-c"])
        assert added["added"] == ["srv-c"] and added["members"] == ["srv-a", "srv-b", "srv-c"]
        removed = await server.remove_from_address_group("grp web/dmz", ["srv-a", "srv-x"])
        assert removed["members"] == ["srv-b"] and removed["not_members"] == ["srv-x"]
        await server.set_policy_status(12, False, comment="disabled for change CHG-1")
        await server.set_policy_status(12, True)
        with pytest.raises(ValueError, match="one kind of address"):
            await server.create_address("x", subnet="10.0.0.1", fqdn="a.test.corp")
        with pytest.raises(ValueError, match="both start_ip and end_ip"):
            await server.create_address("x", start_ip="10.0.0.1")
        with pytest.raises(ValueError, match="IPv4"):
            await server.create_address("x", subnet="10.0.0.300/24")
        with pytest.raises(ValueError, match="Nothing to update"):
            await server.update_address("srv-app")
        with pytest.raises(ValueError, match="already in group"):
            await server.add_to_address_group("grp web/dmz", ["srv-a"])
        with pytest.raises(ValueError, match="Refusing to empty"):
            await server.remove_from_address_group("grp web/dmz", ["srv-a", "srv-b"])

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    grp = "/api/v2/cmdb/firewall/addrgrp/grp%20web%2Fdmz"
    assert seen == [
        ("POST", "/api/v2/cmdb/firewall/address", "root",
         {"name": "srv-app", "type": "ipmask", "subnet": "10.0.0.0 255.255.255.0", "comment": "app tier"}),
        ("POST", "/api/v2/cmdb/firewall/address", "VDOM-DMZ",
         {"name": "app-fqdn", "type": "fqdn", "fqdn": "app.test.corp"}),
        ("POST", "/api/v2/cmdb/firewall/address", "root",
         {"name": "pool", "type": "iprange", "start-ip": "10.0.0.10", "end-ip": "10.0.0.20"}),
        ("PUT", "/api/v2/cmdb/firewall/address/srv%20a%2F1", "root",
         {"type": "ipmask", "subnet": "10.0.0.10 255.255.255.255", "comment": ""}),
        ("GET", grp, "root", None),
        ("PUT", grp, "root", {"member": [{"name": "srv-a"}, {"name": "srv-b"}, {"name": "srv-c"}]}),
        ("GET", grp, "root", None),
        ("PUT", grp, "root", {"member": [{"name": "srv-b"}]}),
        ("PUT", "/api/v2/cmdb/firewall/policy/12", "root",
         {"status": "disable", "comments": "disabled for change CHG-1"}),
        ("PUT", "/api/v2/cmdb/firewall/policy/12", "root", {"status": "enable"}),
        ("GET", grp, "root", None),
        ("GET", grp, "root", None),
    ]


def test_fortios_error_code_and_cli_error_surface():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"http_method": "POST", "status": "error", "http_status": 500,
                                         "error": -5, "cli_error": "entry already exists\n",
                                         "vdom": "root"})

    server._client = _write_client(handler)
    try:
        with pytest.raises(FortiError, match=r"error -5 \(a duplicate entry already exists\); cli_error: entry already exists"):
            asyncio.run(server.create_address("srv-app", subnet="10.0.0.10"))
    finally:
        server._client = None


def test_writes_need_a_matching_confirm_code():
    sent: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path))
        return _ok(request.method, 12)

    server._client = _write_client(handler, confirm_write=True)

    async def calls():
        preview = await server.set_policy_status(12, False)
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert preview["change"] == {"policy_id": 12, "vdom": None, "status": "disable"}
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.set_policy_status(12, True, confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert sent == []
        done = await server.set_policy_status(12, False, confirm=code)
        assert done["status"] == "success" and done["policy"] == {"policyid": 12, "status": "disable"}

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == [("PUT", "/api/v2/cmdb/firewall/policy/12")]
