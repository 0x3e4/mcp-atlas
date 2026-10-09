"""Static smoke tests: the server imports and all tools register with sane schemas (no network)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from netbox_mcp import server
from netbox_mcp.client import NetBoxError
from netbox_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_devices",
    "get_device",
    "list_interfaces",
    "list_ip_addresses",
    "list_prefixes",
    "list_virtual_machines",
    "list_objects",
    "netbox_get",
    "create_ip_address",
    "update_ip_address",
    "assign_next_ip",
    "update_device",
    "add_journal_entry",
}

WRITE_TOOLS = {"create_ip_address", "update_ip_address", "assign_next_ip", "update_device", "add_journal_entry"}


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
    assert "path" in tools["netbox_get"].inputSchema["properties"]
    assert "kind" in tools["list_objects"].inputSchema["properties"]
    assert "device_id" in tools["get_device"].inputSchema["properties"]
    # write tools (always registered; gated at call time by NETBOX_ALLOW_WRITE)
    assert "prefix_id" in tools["assign_next_ip"].inputSchema["properties"]
    assert "object_type" in tools["add_journal_entry"].inputSchema["properties"]
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].inputSchema["properties"], name


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {"NETBOX_BASE_URL": "https://netbox.example.com/", "NETBOX_TOKEN": "0123456789abcdef"}


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.base_url == "https://netbox.example.com"
    assert s.base_origin == "https://netbox.example.com"
    assert s.api_base == "https://netbox.example.com/api"
    assert s.auth_headers == {"Authorization": "Token 0123456789abcdef"}
    assert s.httpx_verify is True


def test_v2_token_uses_bearer():
    env = _base_env()
    env["NETBOX_TOKEN"] = "nbt_abc.def"
    assert Settings.from_env(env).auth_headers == {"Authorization": "Bearer nbt_abc.def"}


def test_missing_token_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"NETBOX_BASE_URL": "https://netbox.example.com"})


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["NETBOX_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False
    env = _base_env()
    env["NETBOX_CA_BUNDLE"] = "/etc/ssl/netbox.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/netbox.pem"


def test_allow_write_defaults_off_and_parses():
    assert Settings.from_env(_base_env()).allow_write is False
    assert Settings.from_env(_base_env()).confirm_write is True
    env = _base_env()
    env["NETBOX_ALLOW_WRITE"] = "true"
    env["NETBOX_CONFIRM_WRITE"] = "false"
    s = Settings.from_env(env)
    assert s.allow_write is True and s.confirm_write is False


def test_write_tools_refuse_without_allow_write():
    server._client = server.NetBoxClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="NETBOX_ALLOW_WRITE"):
            asyncio.run(server.create_ip_address("10.0.0.10/24"))
        with pytest.raises(ValueError, match="NETBOX_ALLOW_WRITE"):
            asyncio.run(server.update_device(7, status="offline"))
    finally:
        server._client = None


def _write_client(handler, *, confirm_write: bool = False) -> server.NetBoxClient:
    env = _base_env()
    env["NETBOX_ALLOW_WRITE"] = "true"
    env["NETBOX_CONFIRM_WRITE"] = "true" if confirm_write else "false"
    client = server.NetBoxClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def test_write_payloads_match_the_netbox_api():
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body))
        if "journal-entries" in request.url.path:
            return httpx.Response(201, json={"id": 3, "assigned_object_type": "dcim.device", "assigned_object_id": 7,
                                             "kind": {"value": "warning", "label": "Warning"},
                                             "display_url": "https://netbox.example.com/extras/journal-entries/3/"})
        if "devices" in request.url.path:
            return httpx.Response(200, json={"id": 7, "name": "vm-42", "status": {"value": "offline"},
                                             "display_url": "https://netbox.example.com/dcim/devices/7/"})
        return httpx.Response(201, json={"id": 11, "address": "10.0.0.10/24", "status": {"value": "active"},
                                         "dns_name": "app.test.corp", "custom_fields": {"big": "x"},
                                         "display_url": "https://netbox.example.com/ipam/ip-addresses/11/"})

    server._client = _write_client(handler)

    async def calls():
        ip = await server.create_ip_address(" 10.0.0.10/24 ", dns_name="app.test.corp", tenant_id=2,
                                            assigned_interface_id=5)
        assert ip["id"] == 11 and ip["url"].endswith("/ipam/ip-addresses/11/") and "custom_fields" not in ip
        await server.update_ip_address(11, status="deprecated", unassign=True)
        nxt = await server.assign_next_ip(4, description="vm-42", assigned_interface_id=9,
                                          interface_type="virtualization.vminterface")
        assert nxt["address"] == "10.0.0.10/24"
        dev = await server.update_device(7, status="offline", primary_ip4_id=11)
        assert dev["status.value"] == "offline"
        entry = await server.add_journal_entry("DCIM.Device", 7, "PSU swapped.", kind="warning")
        assert entry["kind.value"] == "warning"
        with pytest.raises(ValueError, match="Nothing to update"):
            await server.update_device(7)
        with pytest.raises(ValueError, match="not both"):
            await server.update_ip_address(11, assigned_interface_id=5, unassign=True)
        with pytest.raises(ValueError, match="app_label.model"):
            await server.add_journal_entry("device", 7, "x")

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    assert seen == [
        ("POST", "/api/ipam/ip-addresses/", {"address": "10.0.0.10/24", "dns_name": "app.test.corp", "tenant": 2,
                                             "assigned_object_type": "dcim.interface", "assigned_object_id": 5}),
        ("PATCH", "/api/ipam/ip-addresses/11/", {"status": "deprecated", "assigned_object_type": None,
                                                 "assigned_object_id": None}),
        ("POST", "/api/ipam/prefixes/4/available-ips/", {"description": "vm-42",
                                                         "assigned_object_type": "virtualization.vminterface",
                                                         "assigned_object_id": 9}),
        ("PATCH", "/api/dcim/devices/7/", {"status": "offline", "primary_ip4": 11}),
        ("POST", "/api/extras/journal-entries/", {"assigned_object_type": "dcim.device", "assigned_object_id": 7,
                                                  "kind": "warning", "comments": "PSU swapped."}),
    ]


def test_validation_errors_name_the_fields():
    def handler(request: httpx.Request) -> httpx.Response:
        if "available-ips" in request.url.path:
            return httpx.Response(409, json={"detail": "Insufficient resources are available to satisfy the request"})
        return httpx.Response(400, json={"address": ["Duplicate IP address found in global table: 10.0.0.10/24"],
                                         "status": ["\"bogus\" is not a valid choice."]})

    server._client = _write_client(handler)
    try:
        with pytest.raises(NetBoxError, match="400 — validation failed. address: Duplicate IP address") as exc:
            asyncio.run(server.create_ip_address("10.0.0.10/24"))
        assert "status: \"bogus\" is not a valid choice." in str(exc.value)
        with pytest.raises(NetBoxError, match="409 — conflict. Insufficient resources"):
            asyncio.run(server.assign_next_ip(4))
    finally:
        server._client = None


def test_positional_validation_errors_are_flattened():
    from netbox_mcp.client import _flatten

    body = {"detail": "1 of 2 objects failed validation.", "errors": [{"index": 1, "errors": {"slug": ["This field may not be blank."]}}]}
    assert _flatten(body) == ["[1] slug: This field may not be blank."]
    assert _flatten([{}, {"name": ["required"]}]) == ["name: required"]
    assert _flatten({"non_field_errors": ["bad combo"]}) == ["bad combo"]


def test_writes_need_a_matching_confirm_code():
    sent: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path))
        return httpx.Response(201, json={"id": 12, "address": "10.0.0.11/24"})

    server._client = _write_client(handler, confirm_write=True)

    async def calls():
        preview = await server.assign_next_ip(4, dns_name="vm-42.test.corp")
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert preview["change"] == {"prefix_id": 4, "dns_name": "vm-42.test.corp"}
        assert "next free address in prefix 4" in preview["summary"]
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.assign_next_ip(5, dns_name="vm-42.test.corp", confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert sent == []
        done = await server.assign_next_ip(4, dns_name="vm-42.test.corp", confirm=code)
        assert done["address"] == "10.0.0.11/24"

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == [("POST", "/api/ipam/prefixes/4/available-ips/")]
