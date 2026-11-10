"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio

import httpx
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
    "delete_work_items",
    "delete_wiki_page",
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
        assert tool.input_schema and "properties" in tool.input_schema, f"{name} missing schema"


def test_required_params_present():
    tools = _tools()
    assert "path" in tools["azdo_get"].input_schema["properties"]
    assert "wiql" in tools["query_work_items"].input_schema["properties"]
    assert "ids" in tools["get_work_items"].input_schema["properties"]
    assert "repository" in tools["list_branches"].input_schema["properties"]
    # write tools (always registered; gated at call time by AZDO_ALLOW_WRITE)
    assert "work_item_type" in tools["create_work_item"].input_schema["properties"]
    assert "title" in tools["create_work_item"].input_schema["properties"]
    assert "id" in tools["update_work_item"].input_schema["properties"]
    for p in ("wiki", "path", "content"):
        assert p in tools["create_or_update_wiki_page"].input_schema["properties"]


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


CONFIRM_TOOLS = {'update_work_item', 'create_work_item', 'create_or_update_wiki_page', 'delete_work_items',
                 'delete_wiki_page'}


def test_write_tools_take_a_confirm_code_and_confirm_defaults_on():
    tools = _tools()
    for name in CONFIRM_TOOLS:
        assert "confirm" in tools[name].input_schema["properties"], name
    assert Settings.from_env(_base_env()).confirm_write is True
    env = _base_env()
    env["AZDO_CONFIRM_WRITE"] = "false"
    assert Settings.from_env(env).confirm_write is False


def test_writes_need_a_matching_confirm_code():
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.method)
        return httpx.Response(200, json={"id": 7, "rev": 3})

    env = _base_env()
    env["AZDO_ALLOW_WRITE"] = "true"
    client = server.AzdoClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client

    async def calls():
        preview = await server.update_work_item(7, state="Resolved")
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.update_work_item(7, state="Closed", confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert sent == []
        done = await server.update_work_item(7, state="Resolved", confirm=code)
        assert done.get("status") != "confirmation_required"

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == ["PATCH"]


def test_version_is_reported():
    """pyproject, __version__ and the MCP handshake's serverInfo.version agree."""
    import pathlib
    import tomllib

    from azure_devops_mcp import __version__, server as srv

    pyproject = tomllib.loads((pathlib.Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == pyproject["project"]["version"]
    assert srv.mcp.version == __version__


# ---- deletes ------------------------------------------------------------------

def _delete_client(handler, **flags) -> server.AzdoClient:
    env = _base_env()
    env.update({"AZDO_ALLOW_WRITE": "true", "AZDO_ALLOW_DELETE": "true", "AZDO_CONFIRM_WRITE": "false", **flags})
    client = server.AzdoClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def test_allow_delete_defaults_off_and_needs_write_too():
    assert Settings.from_env(_base_env()).allow_delete is False
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.method)
        return httpx.Response(200, json={})

    for flags, missing in (({"AZDO_ALLOW_DELETE": "false"}, "AZDO_ALLOW_DELETE"),
                           ({"AZDO_ALLOW_WRITE": "false"}, "AZDO_ALLOW_WRITE")):
        server._client = _delete_client(handler, **flags)
        try:
            with pytest.raises(ValueError, match=missing):
                asyncio.run(server.delete_work_items([7]))
            with pytest.raises(ValueError, match=missing):
                asyncio.run(server.delete_wiki_page("wiki1", "/Old", project="Platform"))
        finally:
            server._client = None
    assert sent == []


def test_delete_work_items_always_confirms_and_names_the_items():
    sent: list[tuple[str, str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path, dict(request.url.params)))
        if request.method == "GET":
            return httpx.Response(200, json={"count": 2, "value": [
                {"id": 7, "fields": {"System.Title": "Old bug", "System.WorkItemType": "Bug", "System.State": "New",
                                     "System.TeamProject": "Platform"}}, None]})
        return httpx.Response(200, json={"id": 7})

    server._client = _delete_client(handler)  # AZDO_CONFIRM_WRITE=false: deletes still ask

    async def calls():
        preview = await server.delete_work_items([7, 8], destroy=True)
        assert preview["status"] == "confirmation_required" and preview["not_found"] == [8]
        assert "PERMANENTLY" in preview["summary"] and "'Old bug'" in preview["summary"]
        done = await server.delete_work_items([7, 8], destroy=True, confirm=preview["confirm_code"])
        assert done["deleted"][0]["result"] == "destroyed" and done["not_found"] == [8]

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    deletes = [s for s in sent if s[0] == "DELETE"]
    assert len(deletes) == 1 and deletes[0][1].endswith("/_apis/wit/workitems/7")
    assert deletes[0][2]["destroy"] == "true"


def test_delete_wiki_page_lists_subpages_and_binds_the_version():
    state = {"etag": '"v1"'}
    sent: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, dict(request.url.params)))
        if request.method == "GET":
            return httpx.Response(200, headers={"ETag": state["etag"]}, json={
                "path": "/Old", "subPages": [{"path": "/Old/A", "subPages": [{"path": "/Old/A/1"}]}]})
        return httpx.Response(200, json={})

    server._client = _delete_client(handler)

    async def calls():
        preview = await server.delete_wiki_page("wiki1", "/Old", project="Platform")
        assert preview["subpages"] == ["/Old/A", "/Old/A/1"] and "2 sub-page(s)" in preview["summary"]
        state["etag"] = '"v2"'  # edited after the preview
        again = await server.delete_wiki_page("wiki1", "/Old", project="Platform", confirm=preview["confirm_code"])
        assert again["status"] == "confirmation_required" and "did not match" in again["note"]
        done = await server.delete_wiki_page("wiki1", "/Old", project="Platform", confirm=again["confirm_code"])
        assert done == {"deleted": True, "path": "/Old", "subpages_deleted": ["/Old/A", "/Old/A/1"]}
        with pytest.raises(ValueError, match="root"):
            await server.delete_wiki_page("wiki1", "/", project="Platform")

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert [m for m, _ in sent].count("DELETE") == 1
    assert sent[-1] == ("DELETE", {"path": "/Old", "api-version": "7.0"})
