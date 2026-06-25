"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import pytest

from azure_devops_mcp import server
from azure_devops_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_projects",
    "list_teams",
    "list_repositories",
    "list_branches",
    "list_commits",
    "list_pull_requests",
    "query_work_items",
    "get_work_items",
    "list_build_definitions",
    "list_builds",
    "list_releases",
    "list_wikis",
    "get_wiki_page",
    "create_work_item",
    "update_work_item",
    "create_or_update_wiki_page",
    "azdo_get",
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
    assert "path" in tools["azdo_get"].inputSchema["properties"]
    assert "wiql" in tools["query_work_items"].inputSchema["properties"]
    assert "ids" in tools["get_work_items"].inputSchema["properties"]
    assert "repository" in tools["list_branches"].inputSchema["properties"]
    # write tools (always registered; gated at call time by AZDO_ALLOW_WRITE)
    assert "work_item_type" in tools["create_work_item"].inputSchema["properties"]
    assert "title" in tools["create_work_item"].inputSchema["properties"]
    assert "id" in tools["update_work_item"].inputSchema["properties"]
    for p in ("wiki", "path", "content"):
        assert p in tools["create_or_update_wiki_page"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "AZDO_BASE_URL": "https://devops.contoso.com/DefaultCollection/",
        "AZDO_PAT": "secrettoken",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.api_version == "7.0"
    assert s.project == ""
    assert s.base_url == "https://devops.contoso.com/DefaultCollection"
    assert s.base_origin == "https://devops.contoso.com"
    assert s.httpx_verify is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["AZDO_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["AZDO_CA_BUNDLE"] = "/etc/ssl/ado-ca.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/ado-ca.pem"


def test_custom_api_version_and_project():
    env = _base_env()
    env["AZDO_API_VERSION"] = "6.0"
    env["AZDO_PROJECT"] = "Platform"
    s = Settings.from_env(env)
    assert s.api_version == "6.0"
    assert s.project == "Platform"


def test_allow_write_flag_defaults_off_and_parses():
    assert Settings.from_env(_base_env()).allow_write is False
    env = _base_env()
    env["AZDO_ALLOW_WRITE"] = "true"
    assert Settings.from_env(env).allow_write is True
