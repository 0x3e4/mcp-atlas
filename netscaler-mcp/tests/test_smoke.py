"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio
import re

import httpx
import pytest

from netscaler_mcp import server, waf
from netscaler_mcp.client import _encode_query, _format_nitro_error
from netscaler_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_lb_vservers",
    "list_cs_vservers",
    "list_gslb_vservers",
    "list_services",
    "list_servers",
    "list_certificates",
    "ha_status",
    "system_health",
    "vserver_stats",
    "system_info",
    "list_gslb_services",
    "list_gslb_sites",
    "list_dns_records",
    "list_dns_zones",
    "list_dns_nameservers",
    "list_waf_profiles",
    "list_waf_policies",
    "waf_stats",
    "list_bot_profiles",
    "list_bot_policies",
    "bot_stats",
    "nitro_get",
    # WAF rollout (reads always on; writes gated at call time by NETSCALER_ALLOW_WRITE)
    "list_waf_rules",
    "list_waf_learned_rules",
    "list_waf_urls",
    "export_waf_profile",
    "add_waf_rule",
    "remove_waf_rule",
    "deploy_waf_learned_rules",
    "discard_waf_learned_rules",
    "set_waf_check_actions",
    "import_waf_profile",
    "rehost_waf_profile",
    "save_config",
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
    assert "tree" in tools["nitro_get"].inputSchema["properties"]
    assert "resourcetype" in tools["nitro_get"].inputSchema["properties"]
    assert "expiring_within_days" in tools["list_certificates"].inputSchema["properties"]
    assert "kind" in tools["vserver_stats"].inputSchema["properties"]
    assert "record_type" in tools["list_dns_records"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "NETSCALER_BASE_URL": "https://10.0.0.10/",
        "NETSCALER_USER": "ro",
        "NETSCALER_PASSWORD": "secret",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.auth_mode == "session"
    assert s.base_url == "https://10.0.0.10"
    assert s.base_origin == "https://10.0.0.10"
    assert s.nitro_base == "https://10.0.0.10/nitro/v1"
    assert s.httpx_verify is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_invalid_auth_mode_rejected():
    env = _base_env()
    env["NETSCALER_AUTH_MODE"] = "magic"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["NETSCALER_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["NETSCALER_CA_BUNDLE"] = "/etc/ssl/ns-ca.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/ns-ca.pem"


def test_allow_write_and_export_dir_default_off_and_parse():
    s = Settings.from_env(_base_env())
    assert s.allow_write is False
    assert s.export_dir == ""

    env = _base_env()
    env["NETSCALER_ALLOW_WRITE"] = "true"
    env["NETSCALER_EXPORT_DIR"] = "/exports"
    s = Settings.from_env(env)
    assert s.allow_write is True
    assert s.export_dir == "/exports"


# ---- NITRO query encoding + WAF helpers (pure, no network) ----------------

def test_nitro_query_encoding():
    # Plain params encode exactly as httpx did before; args keep literal separators (SDK style).
    assert _encode_query({"attrs": "name,curstate", "pagesize": 50}) == "attrs=name%2Ccurstate&pagesize=50"
    assert (
        _encode_query({"args": {"profilename": "pr_app", "starturl": r"^https://a\.b/x,y$"}})
        == "args=profilename:pr_app,starturl:%5Ehttps%3A%2F%2Fa%5C.b%2Fx%2Cy%24"
    )


def test_url_regex_shapes():
    assert waf.url_regex("app.example.com") == r"^https://app\.example\.com/.*$"
    assert waf.url_regex("app.example.com", "/api") == r"^https://app\.example\.com/api([/?].*)?$"
    assert (
        waf.url_regex("app.example.com", "/login.php", match="exact")
        == r"^https://app\.example\.com/login\.php(\?.*)?$"
    )
    assert (
        waf.url_regex("*", "/static/", extensions=["css", ".js"], scheme="any")
        == r"^https?://[^/]+/static/.*\.(css|js)(\?.*)?$"
    )
    assert waf.url_regex("https://App.Example.com:8443/x") == r"^https://app\.example\.com:8443/.*$"
    with pytest.raises(ValueError):
        waf.url_regex("bad host!")
    with pytest.raises(ValueError):
        waf.url_regex("app.example.com", "/x", match="exact", extensions=["js"])


def test_url_regex_matching():
    rx = re.compile(waf.url_regex("app.example.com", "/api"))
    assert rx.match("https://app.example.com/api")
    assert rx.match("https://app.example.com/api/v1/x")
    assert rx.match("https://app.example.com/api?x=1")
    assert not rx.match("https://app.example.com/apiary")
    assert not rx.match("https://evil.example/api")


def test_parse_url_pattern():
    assert waf.parse_url_pattern(r"^https://app\.example\.com/login\.php$") == {
        "scheme": "https", "host": "app.example.com", "path": "/login.php",
    }
    assert waf.parse_url_pattern(r"^https?://[^/]+/static/.*$")["host"] == "*"
    assert waf.parse_url_pattern("/error.html") == {"scheme": "", "host": "", "path": "/error.html"}


def test_host_rewriter_forms_and_boundaries():
    rw = waf.HostRewriter({"app.dev.corp": "app.corp"})
    assert rw(r"^https://app\.dev\.corp/x\.php$") == r"^https://app\.corp/x\.php$"
    assert rw("https://app.dev.corp/x") == "https://app.corp/x"
    assert rw(r"^https://APP\.DEV\.CORP:8443/$") == r"^https://app\.corp:8443/$"

    rw = waf.HostRewriter({"dev.corp": "prod.corp"})
    assert rw(r"^https://app\.dev\.corp/x$") == r"^https://app\.dev\.corp/x$"  # subdomain untouched
    assert rw(r"^https://dev\.corp\.evil/") == r"^https://dev\.corp\.evil/"  # longer domain untouched
    assert rw("https://mydev.corp/") == "https://mydev.corp/"

    rw = waf.HostRewriter({"a.corp": "b.corp", "b.corp": "c.corp"})
    assert rw("https://a.corp/ https://b.corp/") == "https://b.corp/ https://c.corp/"  # no chaining


def test_group_urls_suggests_prefix_rules():
    groups = waf.group_urls([
        r"^https://app\.corp/app/a\.php$",
        r"^https://app\.corp/app/b\.php$",
        r"^https://app\.corp/app/sub/c\.php$",
        r"^https://app\.corp/index\.html$",
    ])
    top = groups[0]
    assert (top["host"], top["prefix"], top["count"]) == ("app.corp", "/app/", 3)
    assert top["suggested_rule"] == r"^https://app\.corp/app/.*$"


def test_learned_mapping_and_csrf_inversion():
    sql = waf.RULE_TYPES["sql_injection"]
    learned = {"name": "q", "url": r"^https://a\.b/s$", "value_type": "Keyword", "value": "or", "hits": "3"}
    assert waf.learned_rule(sql, learned) == {
        "sqlinjection": "q", "formactionurl_sql": r"^https://a\.b/s$",
        "as_value_type_sql": "Keyword", "as_value_expr_sql": "or",
    }
    # csrftag means the form ORIGIN URL on the binding but the form ACTION URL in learned data.
    csrf = waf.RULE_TYPES["csrf_tag"]
    row = waf.learned_rule(csrf, {"url": "ACTION", "name": "ORIGIN"})
    assert row == {"csrftag": "ORIGIN", "csrfformactionurl": "ACTION"}
    assert waf.learned_delete_args(csrf, row) == {"csrfformoriginurl": "ORIGIN", "csrftag": "ACTION"}


def test_plan_bindings_merge_vs_replace():
    desired = {"start_url": [{"starturl": "A"}, {"starturl": "B", "comment": "new"}]}
    current = {"start_url": [
        {"name": "p", "starturl": "B", "comment": "old", "ruletype": "ALLOW", "resourceid": "1"},
        {"name": "p", "starturl": "C", "ruletype": "ALLOW"},
    ]}
    merge = waf.plan_bindings(desired, current, replace=False)["start_url"]
    assert (merge["add"], merge["update"], merge["remove"]) == ([{"starturl": "A"}], [], [])
    replace = waf.plan_bindings(desired, current, replace=True)["start_url"]
    assert [u["desired"]["starturl"] for u in replace["update"]] == ["B"]
    assert replace["remove"] == [{"starturl": "C", "ruletype": "ALLOW"}]


def test_document_host_map_and_validation():
    rules, other = waf.split_bindings({
        "name": "p",
        "appfwprofile_starturl_binding": [{"name": "p", "starturl": r"^https://app\.test\.corp/.*$"}],
    })
    doc = waf.build_document(
        profile="p", appliance="https://ns", exported_at="t", learning_settings={}, rules=rules,
        other_bindings=other, settings={"name": "p", "state": "ENABLED", "errorurl": "https://app.test.corp/e"},
    )
    assert waf.check_document(doc) is doc
    assert doc["settings"] == {"errorurl": "https://app.test.corp/e"}  # read-only 'state' dropped
    moved, replacements = waf.apply_host_map(doc, {"app.test.corp": "app.corp"})
    assert replacements == 2
    assert moved["rules"]["start_url"][0]["starturl"] == r"^https://app\.corp/.*$"
    assert moved["hosts"] == {"app.corp": 1}
    with pytest.raises(ValueError):
        waf.check_document({"format": "something-else"})


def test_check_actions_go_live():
    assert waf.new_actions("start_url", ["learn", "log", "stats"], add=["block"], remove=["learn"]) == [
        "block", "log", "stats",
    ]
    assert waf.new_actions("deny_url", ["none"], add=["learn"], strict=False) == ["none"]
    with pytest.raises(ValueError):
        waf.new_actions("deny_url", ["block"], add=["learn"])


def test_waf_tool_params_present():
    tools = _tools()
    assert "dry_run" in tools["add_waf_rule"].inputSchema["properties"]
    assert "host_map" in tools["import_waf_profile"].inputSchema["properties"]
    assert "from_host" in tools["rehost_waf_profile"].inputSchema["properties"]
    assert "min_hits" in tools["deploy_waf_learned_rules"].inputSchema["properties"]


def test_write_tools_refuse_without_allow_write():
    server._client = server.NitroClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
            asyncio.run(server.save_config())
        with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
            asyncio.run(server.add_waf_rule("pr_app", "allow_url", host="app.example.com", dry_run=False))
    finally:
        server._client = None


def test_export_path_confined_to_export_dir(tmp_path):
    env = _base_env()
    env["NETSCALER_EXPORT_DIR"] = str(tmp_path)
    server._client = server.NitroClient(Settings.from_env(env))
    try:
        assert server._export_path("pr_app-test") == tmp_path / "pr_app-test.json"
        for bad in ("../evil", "sub/x.json", ".hidden.json", "a..b.json", "C:\\x.json"):
            with pytest.raises(ValueError):
                server._export_path(bad)
    finally:
        server._client = None


def test_nitro_get_sends_args_like_the_nitro_reference():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode())
        return httpx.Response(200, json={"errorcode": 0, "message": "Done"})

    env = _base_env()
    env["NETSCALER_AUTH_MODE"] = "stateless"  # no login request in the log
    client = server.NitroClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client

    async def calls():
        await server.nitro_get("config", "appfwlearningdata", args="profilename:pr_app,securitycheck:startURL")
        await server.nitro_get("config", "systemfile", args={"filelocation": "/nsconfig/ssl"}, pagesize=10, pageno=1)
        with pytest.raises(ValueError, match="key:value"):
            await server.nitro_get("config", "appfwlearningdata", args="profilename")

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert seen == [
        "/nitro/v1/config/appfwlearningdata?args=profilename:pr_app,securitycheck:startURL",
        "/nitro/v1/config/systemfile?args=filelocation:%2Fnsconfig%2Fssl&pagesize=10&pageno=1",
    ]
    assert "args" in _tools()["nitro_get"].inputSchema["properties"]


def test_missing_lookup_argument_errors_point_to_args():
    missing = _format_nitro_error({"errorcode": 1095, "message": "Required argument missing [profileName]"})
    assert "profileName" in missing and "args" in missing
    assert "args" in _format_nitro_error({"errorcode": 1090, "message": "No such argument [arguid]"})
    # a write missing a body attribute isn't an args problem
    assert "args" not in _format_nitro_error({"errorcode": 1095, "message": "Required argument missing [name]"}, write=True)
