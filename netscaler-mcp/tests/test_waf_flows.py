"""WAF tool flows against the fake NITRO appliance (tests/fake_netscaler.py) — no network.

The fake and the ``ns`` fixture are shared with test_bot_flows.py; see fake_netscaler.py for the NITRO
behaviour it reproduces.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from fake_netscaler import STATIC
from netscaler_mcp import server


def test_previews_work_read_only_and_writes_refuse(ns):
    ns.use(allow_write=False)

    async def scenario():
        preview = await server.add_waf_rule("pr_app", "allow_url", host="app.test.corp", path="/portal/")
        assert preview["results"] == [{"profile": "pr_app", "status": "would add"}]
        with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
            await server.add_waf_rule("pr_app", "allow_url", host="app.test.corp", path="/portal/", dry_run=False)
        with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
            await server.set_waf_check_actions("pr_app", ["all"], add_actions=["block"], dry_run=False)
        with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
            await server.import_waf_profile(document=await server.export_waf_profile("pr_app"), dry_run=False)

    asyncio.run(scenario())
    assert ns.writes == []


def test_url_inventory_and_learned_rules(ns):
    async def scenario():
        rules = await server.list_waf_rules("pr_app")
        assert rules["counts"] == {"start_url": 2, "sql_injection": 1}
        assert rules["other_bindings"] == {"appfwprofile_logexpression_binding": 1}
        assert "resourceid" not in rules["rules"]["start_url"][0]

        learned = await server.list_waf_learned_rules("pr_app", "startURL", min_hits=2)
        assert [e["hits"] for e in learned["entries"]] == [30, 12, 2]
        assert [(g["prefix"], g["count"]) for g in learned["groups"]] == [("/portal/", 2), ("/app/", 1)]

        urls = await server.list_waf_urls("pr_app")
        assert urls["hosts"] == {"app.test.corp": {"start_urls": 1, "rule_urls": 1, "learned": 4}}
        assert {e["path"]: e["covered"] for e in urls["learned"]} == {
            "/portal/b.php": False, "/app/a.php": True, "/portal/c,d.php": False, "/wp-login.php": False,
        }
        assert urls["uncovered_groups"][0]["suggested_rule"] == r"^https://app\.test\.corp/portal/.*$"

    asyncio.run(scenario())


def test_deploy_discard_and_regex_values_with_commas(ns):
    comma_url = r"^https://app\.test\.corp/portal/c,d\.php$"

    async def scenario():
        discarded = await server.discard_waf_learned_rules("pr_app", "start_url", contains="wp-login", dry_run=False)
        assert discarded["summary"] == {"removed": 1}

        deployed = await server.deploy_waf_learned_rules("pr_app", "start_url", contains="c,d", dry_run=False)
        assert (deployed["summary"], deployed["results"][0]["learned"]) == ({"added": 1}, "removed")
        assert comma_url in ns.start_urls("pr_app")
        removed = await server.remove_waf_rule("pr_app", "start_url", {"starturl": comma_url}, dry_run=False)
        assert removed["results"][0]["status"] == "removed"

        added = await server.add_waf_rule(
            "pr_app, pr_missing", "allow_url", host="app.test.corp", path="/portal/", dry_run=False
        )
        assert [(r["profile"], r["status"][:5]) for r in added["results"]] == [("pr_app", "added"), ("pr_missing", "error")]
        again = await server.add_waf_rule("pr_app", "allow_url", host="app.test.corp", path="/portal/", dry_run=False)
        assert again["results"][0]["status"] == "exists"

        # /app/ and /portal/ prefix rules already match the remaining learned URLs: cleared, not bound.
        covered = await server.deploy_waf_learned_rules("pr_app", "start_url", dry_run=False)
        assert covered["summary"] == {"covered": 2}
        assert ns.learned["pr_app"]["startURL"] == []

        sql = await server.deploy_waf_learned_rules("pr_app", "sql_injection", dry_run=False)
        assert sql["summary"] == {"added": 1}

    asyncio.run(scenario())
    row = next(r for r in ns.bindings["pr_app"]["appfwprofile_sqlinjection_binding"] if r["sqlinjection"] == "comment")
    assert (row["formactionurl_sql"], row["as_value_type_sql"], row["as_value_expr_sql"]) == (
        r"^https://app\.test\.corp/post$", "SpecialString", "'",
    )
    assert ns.learned["pr_app"]["SQLInjection"] == []


def test_go_live_switches_learn_to_block_and_saves(ns):
    async def scenario():
        result = await server.set_waf_check_actions(
            "pr_app", ["all"], add_actions=["block"], remove_actions=["learn"], dry_run=False
        )
        assert result["changed"] == 3
        with pytest.raises(ValueError, match="learn"):
            await server.set_waf_check_actions("pr_app", ["deny_url"], add_actions=["learn"])
        assert await server.save_config() == {"saved": True}

    asyncio.run(scenario())
    assert ns.profiles["pr_app"]["starturlaction"] == ["block", "log", "stats"]
    assert ns.profiles["pr_app"]["denyurlaction"] == ["block"]
    assert ns.saved


def test_export_import_to_new_profile_with_host_switch(ns):
    host_map = {"app.test.corp": "app.corp"}

    async def scenario():
        saved = await server.export_waf_profile("pr_app", save_as="pr_app-test")
        assert saved["rules"] == {"start_url": 2, "sql_injection": 1}
        with pytest.raises(ValueError, match="bare name"):
            await server.export_waf_profile("pr_app", save_as="../evil")

        preview = await server.import_waf_profile(file="pr_app-test.json", target_profile="pr_app_prod", host_map=host_map)
        assert preview["profile"] == "would create"
        assert "pr_app_prod" not in ns.profiles

        applied = await server.import_waf_profile(
            file="pr_app-test.json", target_profile="pr_app_prod", host_map=host_map, dry_run=False
        )
        assert (applied["profile"], applied["errors"]) == ("created", [])
        again = await server.import_waf_profile(file="pr_app-test.json", target_profile="pr_app_prod", host_map=host_map)
        assert again["rules"] == {}

        # merge never removes; replace removes rules the document doesn't have
        ns.bindings["pr_app_prod"]["appfwprofile_denyurl_binding"] = [
            ns.row("pr_app_prod", "appfwprofile_denyurl_binding", {"denyurl": r"^https://app\.corp/admin/.*$"})
        ]
        doc = await server.export_waf_profile("pr_app")
        merge = await server.import_waf_profile(document=json.dumps(doc), target_profile="pr_app_prod", host_map=host_map)
        assert merge["rules"] == {}
        replace = await server.import_waf_profile(
            document=doc, target_profile="pr_app_prod", host_map=host_map, mode="replace", dry_run=False
        )
        assert replace["applied"] == {"deny_url": {"removed": 1}}

    asyncio.run(scenario())
    assert ns.writes[0][:2] == ("POST", "appfwprofile")  # profile created before settings and rules
    prod = ns.profiles["pr_app_prod"]
    assert (prod["starturlaction"], prod["errorurl"]) == (["learn", "log", "stats"], "https://app.corp/error.html")
    assert ns.learning_settings["pr_app_prod"]["starturlminthreshold"] == 5
    assert ns.start_urls("pr_app_prod") == sorted([r"^https://app\.corp/app/.*$", STATIC])
    assert "appfwprofile_logexpression_binding" not in ns.bindings["pr_app_prod"]


def test_rehost_in_place_binds_before_unbinding(ns):
    async def scenario():
        missing = await server.rehost_waf_profile("pr_app", "nope.corp", "x.corp")
        assert "nothing to switch" in missing["message"]
        return await server.rehost_waf_profile("pr_app", "app.test.corp", "app.stage.corp", dry_run=False)

    result = asyncio.run(scenario())
    binds = [i for i, w in enumerate(ns.writes) if w[0] == "PUT" and w[1].endswith("_binding")]
    unbinds = [i for i, w in enumerate(ns.writes) if w[0] == "DELETE" and w[1].endswith("_binding")]
    assert (len(binds), len(unbinds), result["errors"]) == (2, 2, [])
    assert max(binds) < min(unbinds)
    assert not any("test" in url for url in ns.start_urls("pr_app"))
    assert STATIC in ns.start_urls("pr_app")  # host '*' rule untouched
    assert ns.profiles["pr_app"]["errorurl"] == "https://app.stage.corp/error.html"


def test_tools_through_the_mcp_protocol_layer(ns):
    def text(result: Any) -> str:
        return json.dumps(result, default=lambda o: getattr(o, "text", str(o)))

    async def scenario():
        added = await server.mcp.call_tool(
            "add_waf_rule",
            {"profile": "pr_app", "rule": "allow_static", "host": "*", "scheme": "any", "extensions": ["css", "js"]},
        )
        doc = await server.export_waf_profile("pr_app")
        imported = await server.mcp.call_tool("import_waf_profile", {"document": doc, "target_profile": "pr_app"})
        return text(added), text(imported)

    added, imported = asyncio.run(scenario())
    assert "would add" in added and "(css|js)" in added
    assert "exists" in imported
