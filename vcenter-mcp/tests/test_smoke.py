"""Static smoke tests: the server imports and all tools register with sane schemas (no network)."""

from __future__ import annotations

import asyncio

import pytest

from vcenter_mcp import server
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
}


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
