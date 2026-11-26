"""Rule writes in parallel / as NITRO bulk binds, rule states, signature rules and auto-update (1.3.0)."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from netscaler_mcp import server, waf
from netscaler_mcp.config import ConfigError, Settings


def _slow_transport(ns) -> None:
    """Make the fake answer asynchronously with a short delay, so parallel requests really overlap."""

    async def handler(request: httpx.Request) -> httpx.Response:
        ns.in_flight += 1
        ns.max_in_flight = max(ns.max_in_flight, ns.in_flight)
        try:
            await asyncio.sleep(0.005)
            return ns(request)
        finally:
            ns.in_flight -= 1

    server._clients["default"]._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _keyword_doc(count: int) -> dict:
    return {
        "format": waf.WAF.doc_format, "version": waf.DOC_VERSION, "settings": {},
        "rules": {"block_keyword": [
            {"blockkeyword": f"kw{i}", "as_blockkeyword_formurl": r"^https://app\.test\.corp/form$", "fieldname": "q"}
            for i in range(count)
        ]},
    }


def test_concurrency_setting_is_validated():
    base = {"NETSCALER_BASE_URL": "https://ns", "NETSCALER_USER": "u", "NETSCALER_PASSWORD": "p"}
    assert Settings.from_env(base).write_concurrency == 4
    assert Settings.from_env(base).bulk_bind is False
    assert Settings.from_env({**base, "NETSCALER_WRITE_CONCURRENCY": "1"}).write_concurrency == 1
    with pytest.raises(ConfigError, match="1-16"):
        Settings.from_env({**base, "NETSCALER_WRITE_CONCURRENCY": "0"})


def test_import_binds_new_rule_types_in_parallel(ns):
    ns.use(write_concurrency=4)
    _slow_transport(ns)

    async def scenario():
        return await server.import_waf_profile(document=_keyword_doc(12), target_profile="pr_app", dry_run=False)

    out = asyncio.run(scenario())
    assert out["applied"] == {"block_keyword": {"added": 12}} and out["errors"] == []
    assert len(ns.bindings["pr_app"]["appfwprofile_blockkeyword_binding"]) == 12
    assert 1 < ns.max_in_flight <= 4


def test_concurrency_one_writes_one_after_another(ns):
    ns.use(write_concurrency=1)
    _slow_transport(ns)
    asyncio.run(server.import_waf_profile(document=_keyword_doc(5), target_profile="pr_app", dry_run=False))
    assert ns.max_in_flight == 1


def test_bulk_bind_one_request_per_chunk_with_per_rule_status(ns):
    ns.use(bulk_bind=True)
    ns.bindings["pr_app"]["appfwprofile_blockkeyword_binding"] = [ns.row(
        "pr_app", "appfwprofile_blockkeyword_binding",
        {"blockkeyword": "kw3", "as_blockkeyword_formurl": r"^https://app\.test\.corp/form$", "fieldname": "q"},
    )]
    doc = _keyword_doc(6)

    async def scenario():
        # a merge plan skips kw3 (already bound); bind the rest in one bulk request
        return await server.import_waf_profile(document=doc, target_profile="pr_app", dry_run=False)

    out = asyncio.run(scenario())
    assert out["applied"] == {"block_keyword": {"added": 5}}
    assert ns.bulk_requests == 1

    rows = [{"blockkeyword": "kw3", "as_blockkeyword_formurl": r"^https://app\.test\.corp/form$", "fieldname": "q"},
            {"blockkeyword": "kw99", "as_blockkeyword_formurl": r"^https://app\.test\.corp/form$", "fieldname": "q"}]
    spec = waf.RULE_TYPES["block_keyword"]
    statuses = asyncio.run(server._bind_many(spec, "pr_app", rows))
    assert statuses == ["exists", "added"]


def test_bulk_bind_falls_back_when_the_appliance_rejects_arrays(ns):
    ns.use(bulk_bind=True)
    ns.bulk_supported = False
    out = asyncio.run(server.import_waf_profile(document=_keyword_doc(4), target_profile="pr_app", dry_run=False))
    assert out["applied"] == {"block_keyword": {"added": 4}} and ns.bulk_requests == 0


def test_rule_state_parks_and_restores_a_rule(ns):
    url = r"^https://app\.test\.corp/app/.*$"

    async def scenario():
        preview = await server.set_waf_rule_state("pr_app", "start_url", "DISABLED", rule={"starturl": url})
        assert preview["results"][0]["status"] == "would set DISABLED"
        assert all(r["state"] == "ENABLED" for r in ns.entries("pr_app", "appfwprofile_starturl_binding"))
        parked = await server.set_waf_rule_state("pr_app", "start_url", "disabled", rule={"starturl": url}, dry_run=False)
        assert parked["summary"] == {"updated": 1}
        again = await server.set_waf_rule_state("pr_app", "start_url", "DISABLED", rule={"starturl": url}, dry_run=False)
        assert (again["already"], again.get("summary")) == (1, {})
        with pytest.raises(ValueError, match="2 rules match"):
            await server.set_waf_rule_state("pr_app", "start_url", "ENABLED", contains="^http", dry_run=False)
        back = await server.set_waf_rule_state("pr_app", "start_url", "ENABLED", contains="^http", all_matches=True, dry_run=False)
        assert back["summary"] == {"updated": 1} and back["already"] == 1

    asyncio.run(scenario())
    rows = ns.entries("pr_app", "appfwprofile_starturl_binding")
    assert len(rows) == 2 and all(r["state"] == "ENABLED" for r in rows)


def test_rule_state_validates_input(ns):
    with pytest.raises(ValueError, match="state must be"):
        asyncio.run(server.set_waf_rule_state("pr_app", "start_url", "OFF", contains="x"))
    with pytest.raises(ValueError, match="Pass rule"):
        asyncio.run(server.set_waf_rule_state("pr_app", "start_url", "DISABLED"))


def test_signature_rules(ns):
    async def scenario():
        preview = await server.set_signature_rules("sig_default", rule_ids=[999982, 999981, 999981], enabled=False)
        assert preview["body"] == {"name": "sig_default", "ruleid": [999981, 999982], "enabled": "OFF"}
        assert ns.signature_sets == []
        await server.set_signature_rules("sig_default", category="web-php", enabled=True, actions=["Block", "log"], dry_run=False)
        await server.set_signature_rules("sig_default", auto_enable_new=False, dry_run=False)

    asyncio.run(scenario())
    assert ns.signature_sets == [
        {"name": "sig_default", "category": "web-php", "enabled": "ON", "action": ["block", "log"]},
        {"name": "sig_default", "autoenablenewsignatures": "OFF"},
    ]
    for bad in ({"rule_ids": [1], "category": "x", "enabled": True}, {"enabled": True}, {"rule_ids": [1]},
                {"rule_ids": [1], "actions": ["drop"]}, {}):
        with pytest.raises(ValueError):
            asyncio.run(server.set_signature_rules("sig_default", **bad))


def test_signature_auto_update(ns):
    async def scenario():
        preview = await server.set_signature_auto_update("both", enabled=True)
        assert preview["changes"] == {"waf": {"signatureautoupdate": "ON"}}  # bot is already on
        assert preview["current"]["bot"] == {"signatureautoupdate": "ON"}
        out = await server.set_signature_auto_update("waf", enabled=True, proxy_server="10.0.0.5", proxy_port=3128, dry_run=False)
        assert out["errors"] == []
        with pytest.raises(ValueError, match="https"):
            await server.set_signature_auto_update("waf", url="http://sig.example/x.xml")

    asyncio.run(scenario())
    settings = ns.settings["appfwsettings"]
    assert (settings["signatureautoupdate"], settings["proxyserver"], settings["proxyport"]) == ("ON", "10.0.0.5", 3128)
