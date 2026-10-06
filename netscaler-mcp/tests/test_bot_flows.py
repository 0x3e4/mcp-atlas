"""Bot management and cross-feature tool flows against the fake NITRO appliance — no network.

The fake and the ``ns`` fixture are shared with test_waf_flows.py; see fake_netscaler.py for the NITRO
behaviour it reproduces.
"""

from __future__ import annotations

import asyncio

import pytest

from netscaler_mcp import server


def test_bot_rules_and_detections(ns):
    async def scenario():
        rules = await server.list_bot_rules("bot_app")
        assert rules["counts"] == {"deny_list": 1, "rate_limit": 1}
        assert rules["rules"]["deny_list"][0]["bot_blacklist_value"] == "10.9.9.9"

        detections = await server.list_bot_detections("bot_app")
        assert detections["detections"]["deny_list"] == {
            "enabled": "ON", "action": "per entry (list_bot_rules)", "entries": 1,
        }
        assert detections["detections"]["device_fingerprint"] == {"enabled": "OFF", "action": ["NONE"]}
        # counters come from stat/botprofile, bucketed per detection and outcome
        assert detections["caught"]["blacklist"] == {"total": 4, "drop": 4}
        assert detections["traffic"]["requests"] == 900
        assert detections["configured"] == {"blacklist": 1, "whitelist": 1}

        appliance = await server.list_bot_detections()
        assert appliance["scope"] == "appliance"
        assert appliance["caught"]["whitelist"] == {"total": 10, "log": 10}

    asyncio.run(scenario())


def test_add_and_remove_bot_entries(ns):
    async def scenario():
        ns.use(allow_write=False)
        preview = await server.add_bot_rule("bot_app", "allow_ip", value="10.0.0.0/24")
        assert preview["rule"]["bot_whitelist_type"] == "SUBNET"  # classified from the value
        assert preview["results"] == [{"profile": "bot_app", "status": "would add"}]
        with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
            await server.add_bot_rule("bot_app", "allow_ip", value="10.0.0.0/24", dry_run=False)
        assert ns.writes == []

        ns.use(allow_write=True)
        added = await server.add_bot_rule(
            "bot_app", "allow_ip", value="10.0.0.0/24", comment="monitoring", dry_run=False
        )
        assert added["results"][0]["status"] == "added"
        assert added["rule"]["bot_bind_comment"] == "monitoring"  # bot comments have their own attribute
        again = await server.add_bot_rule("bot_app", "allow_ip", value="10.0.0.0/24", dry_run=False)
        assert again["results"][0]["status"] == "exists"

        blocked = await server.add_bot_rule(
            "bot_app", "block_ip", value="203.0.113.7", actions=["DROP", "LOG"], dry_run=False
        )
        assert blocked["rule"]["bot_blacklist_action"] == ["DROP", "LOG"]
        limited = await server.add_bot_rule(
            "bot_app", "rate_limit_geo", country="de", rate=50,
            actions=["RESPOND_STATUS_TOO_MANY_REQUESTS"], dry_run=False,
        )
        assert (limited["rule"]["countrycode"], limited["rule"]["rate"]) == ("DE", 50)

        with pytest.raises(ValueError, match="not an IP address"):
            await server.add_bot_rule("bot_app", "allow_ip", value="not-an-ip")
        with pytest.raises(ValueError, match="category must be"):
            await server.add_bot_rule("bot_app", "ip_reputation", category="NOPE")
        with pytest.raises(ValueError, match="carry no action"):
            await server.add_bot_rule("bot_app", "allow_ip", value="10.1.0.0/16", actions=["DROP"])

        removed = await server.remove_bot_rule(
            "bot_app", "allow_list", {"bot_whitelist": True, "bot_whitelist_value": "10.0.0.0/24"}, dry_run=False
        )
        assert removed["results"][0]["status"] == "removed"

    asyncio.run(scenario())
    assert ns.entries("bot_app", "botprofile_whitelist_binding") == []
    assert [e["bot_blacklist_value"] for e in ns.entries("bot_app", "botprofile_blacklist_binding")] == [
        "10.9.9.9", "203.0.113.7",
    ]
    # the boolean selector survives the round trip through ?args= as a lowercase JSON boolean
    assert any(w[0] == "DELETE" and w[3].get("bot_whitelist") == "true" for w in ns.writes)


def test_set_bot_detections(ns):
    async def scenario():
        preview = await server.set_bot_detections("bot_app", ["device_fingerprint"], enable=True, actions=["LOG"])
        assert preview["detections"]["device_fingerprint"]["action"] == {"before": ["NONE"], "after": ["LOG"]}
        assert preview["changed"] == 2
        assert ns.bot_profiles["bot_app"]["devicefingerprint"] == "OFF"  # preview wrote nothing

        applied = await server.set_bot_detections(
            "bot_app", ["device_fingerprint", "trap"], enable=True, actions=["LOG", "DROP"], dry_run=False
        )
        assert applied["changed"] == 4
        assert ns.bot_profiles["bot_app"]["trapaction"] == ["LOG", "DROP"]

        with pytest.raises(ValueError, match="per entry"):
            await server.set_bot_detections("bot_app", ["allow_list"], actions=["DROP"])
        with pytest.raises(ValueError, match="invalid"):
            await server.set_bot_detections("bot_app", ["device_fingerprint"], actions=["CHECKLAST"])

        everything = await server.set_bot_detections("bot_app", ["all"], enable=True, actions=["LOG"], dry_run=False)
        assert everything["detections"]["allow_list"]["action"] == "per entry (add_bot_rule)"
        assert everything["detections"]["signature_multiple_user_agent"]["enabled"] == "always on (no switch)"
        await server.set_bot_detections("bot_app", ["device_fingerprint"], signature="bot_sig", dry_run=False)

    asyncio.run(scenario())
    profile = ns.bot_profiles["bot_app"]
    # detections=['all'] with actions=['LOG'] deliberately levels every profile-level action to log-only
    assert (profile["devicefingerprint"], profile["trapaction"]) == ("ON", ["LOG"])
    assert profile["bot_enable_white_list"] == "ON"  # switched on by detections=['all']
    assert profile["signature"] == "bot_sig"


def test_export_import_bot_profile(ns):
    async def scenario():
        saved = await server.export_bot_profile("bot_app", save_as="bot_app-test")
        assert saved["rules"] == {"deny_list": 1, "rate_limit": 1}
        doc = await server.export_bot_profile("bot_app")
        assert doc["format"] == "netscaler-mcp/bot-profile"
        assert "learning_settings" not in doc  # bot has no learning thresholds
        with pytest.raises(ValueError, match="WAF profile export"):
            await server.import_waf_profile(document=doc, target_profile="pr_app")  # wrong family

        preview = await server.import_bot_profile(file="bot_app-test.json", target_profile="bot_app_prod")
        assert preview["profile"] == "would create"
        assert "bot_app_prod" not in ns.bot_profiles

        applied = await server.import_bot_profile(
            file="bot_app-test.json", target_profile="bot_app_prod", dry_run=False
        )
        assert (applied["profile"], applied["errors"]) == ("created", [])
        again = await server.import_bot_profile(file="bot_app-test.json", target_profile="bot_app_prod")
        assert again["rules"] == {}

    asyncio.run(scenario())
    assert ns.bot_profiles["bot_app_prod"]["bot_enable_black_list"] == "ON"  # settings copied on create
    assert [e["bot_blacklist_value"] for e in ns.entries("bot_app_prod", "botprofile_blacklist_binding")] == [
        "10.9.9.9",
    ]
    assert ns.entries("bot_app_prod", "botprofile_ratelimit_binding")[0]["bot_rate_limit_url"] == "/login"


def test_enforcement_signatures_and_violations(ns):
    async def scenario():
        enforcement = await server.list_enforcement()
        policies = {p["name"]: p for p in enforcement["waf"]["policies"]}
        assert policies["pol_app"]["enforced"] is True
        assert policies["pol_app"]["bindings"][0] == {
            "bound_to_type": "lbvserver", "boundto": "vs_app", "priority": "100", "activepolicy": 1,
        }
        assert policies["pol_spare"]["enforced"] is False  # a policy bound nowhere does nothing
        assert enforcement["bot"]["policies"][0]["bindings"][0]["bound_to_type"] == "csvserver"
        assert enforcement["waf"]["profiles_without_policy"] == []

        signatures = await server.list_signatures()
        assert signatures["waf"]["signatures"][0]["encryptedversion"] == 97
        assert signatures["waf"]["settings"]["signatureautoupdate"] == "OFF"
        assert signatures["bot"]["signatures"][0]["name"] == "bot_sig"

        preview = await server.update_signatures("waf", "sig_default")
        assert preview["dry_run"] is True
        assert ns.signature_updates == []
        applied = await server.update_signatures("waf", "sig_default", merge_default=True, dry_run=False)
        assert applied["updated"] == "sig_default"

        violations = await server.waf_violations("pr_app")
        assert violations["checks"]["start_url"] == {"violations": 5, "logged": 5}
        assert violations["checks"]["sql_injection"] == {"violations": 2, "logged": 2}
        assert violations["checks"]["xml_dos"] == {"violations": 1}
        assert violations["checks"]["signatures"] == {"logged": 3}
        assert "cross_site_scripting" not in violations["checks"]  # zero counters are hidden
        assert violations["traffic"]["requests"] == 1500

        lines = await server.recent_security_violations()
        assert lines["by_check"] == {"APPFW_STARTURL": 1, "APPFW_SQL": 1, "BOT_BLACKLIST": 1}
        first = lines["messages"][0]
        assert (first["check"], first["profile"], first["client_ip"], first["blocked"]) == (
            "APPFW_STARTURL", "pr_app", "10.1.2.3", True,
        )
        assert lines["messages"][1]["blocked"] is False  # "<not blocked>" is not a block
        assert [m["check"] for m in (await server.recent_security_violations(feature="bot"))["messages"]] == [
            "BOT_BLACKLIST",
        ]

    asyncio.run(scenario())
    assert ns.signature_updates == [("appfwsignatures", {"name": "sig_default", "mergedefault": True})]
