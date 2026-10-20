"""apply_batch against the fake appliance: several write-tool steps, one preview, one confirm code."""

from __future__ import annotations

import asyncio

import pytest

from netscaler_mcp import server

ADD = {"tool": "add_waf_rule", "args": {"profile": "pr_app", "rule": "allow_url", "host": "app.test.corp", "path": "/portal/"}}
BLOCK_SQL = {"tool": "set_waf_check_actions", "args": {"profile": "pr_app", "checks": ["sql_injection"], "add_actions": ["block"]}}
BOT_ALLOW = {"tool": "add_bot_rule", "args": {"profile": "bot_app", "rule": "allow_ip", "value": "10.0.0.0/24"}}


def test_one_confirmation_for_several_changes(ns):
    ns.use(confirm_write=True)

    async def scenario():
        preview = await server.apply_batch([ADD, BLOCK_SQL, BOT_ALLOW], save=True)
        assert preview["status"] == "confirmation_required" and preview["dry_run"] is True
        assert [s["tool"] for s in preview["steps"]] == ["add_waf_rule", "set_waf_check_actions", "add_bot_rule"]
        assert all("confirm_code" not in s for s in preview["steps"])  # only the batch carries a code
        assert "3 step(s)" in preview["summary"] and "save" in preview["summary"]
        assert ns.writes == []

        code = preview["confirm_code"]
        result = await server.apply_batch([ADD, BLOCK_SQL, BOT_ALLOW], save=True, dry_run=False, confirm=code)
        assert result["saved"] is True
        assert [s["results"][0]["status"] for s in (result["steps"][0], result["steps"][2])] == ["added", "added"]
        assert set(result["steps"][1]["checks"]["sql_injection"]["after"]) == {"block", "learn", "log", "stats"}

    asyncio.run(scenario())
    assert [w[1] for w in ns.writes][-1] == "nsconfig" and len(ns.writes) == 4 and ns.saved  # 3 changes + save
    assert any("portal" in u for u in ns.start_urls("pr_app"))


def test_code_must_match_the_whole_batch(ns):
    ns.use(confirm_write=True)

    async def scenario():
        code = (await server.apply_batch([ADD, BLOCK_SQL]))["confirm_code"]
        other = await server.apply_batch([ADD], dry_run=False, confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]

    asyncio.run(scenario())
    assert ns.writes == []


def test_a_step_whose_plan_moved_is_not_applied(ns):
    async def scenario():
        regex = (await server.add_waf_rule(**ADD["args"]))["rule"]["starturl"]
        remove = {"tool": "remove_waf_rule", "args": {"profile": "pr_app", "rule_type": "start_url", "rule": {"starturl": regex}}}
        ns.use(confirm_write=True)
        # previewed before the add ran, the remove finds nothing; after the add it would remove the new rule
        preview = await server.apply_batch([ADD, remove, BLOCK_SQL], save=True)
        assert preview["steps"][1]["matched"] == 0
        result = await server.apply_batch([ADD, remove, BLOCK_SQL], save=True, dry_run=False, confirm=preview["confirm_code"])
        assert result["steps"][0]["results"][0]["status"] == "added"
        assert "differs from the confirmed preview" in result["steps"][1]["error"]
        assert result["steps"][2] == {"step": 3, "tool": "set_waf_check_actions", "status": "not run"}
        assert result["saved"] is False and "Not saved" in result["note"]

    asyncio.run(scenario())
    assert [w[1] for w in ns.writes] == ["appfwprofile_starturl_binding"] and not ns.saved


def test_bad_steps_fail_before_anything_runs(ns):
    async def scenario():
        with pytest.raises(ValueError, match="tool must be one of"):
            await server.apply_batch([{"tool": "save_config", "args": {}}])
        with pytest.raises(ValueError, match="leave \\['dry_run'\\] out"):
            await server.apply_batch([{"tool": "add_waf_rule", "args": {**ADD["args"], "dry_run": False}}])
        broken = {"tool": "set_waf_check_actions", "args": {"profile": "pr_app", "checks": ["sql_injection"]}}
        missing = {"tool": "add_bot_rule", "args": {"rule": "allow_ip"}}
        for bad in (broken, missing):
            result = await server.apply_batch([ADD, bad], dry_run=False)
            assert "Nothing was applied" in result["error"] and "confirm_code" not in result
            assert "error" in result["steps"][1]

    asyncio.run(scenario())
    assert ns.writes == []


def test_batch_preview_works_read_only(ns):
    ns.use(allow_write=False)

    async def scenario():
        preview = await server.apply_batch([ADD, BLOCK_SQL])
        assert preview["steps"][0]["results"] == [{"profile": "pr_app", "status": "would add"}]
        with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
            await server.apply_batch([ADD, BLOCK_SQL], dry_run=False)

    asyncio.run(scenario())
    assert ns.writes == []
