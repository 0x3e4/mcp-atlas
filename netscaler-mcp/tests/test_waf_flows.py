"""WAF tool flows against a stateful fake NITRO appliance (httpx.MockTransport) — no network.

The fake follows the NetScaler 14.1 NITRO reference: bindings are added with PUT and removed with
DELETE ?args=, read-only attributes are rejected, duplicates return AppFw's per-check codes, and args
are parsed SDK-style (split on literal ',' and ':' first, then percent-decode each value).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from netscaler_mcp import server
from netscaler_mcp.config import Settings

BINDING_IDENTITY = {
    "appfwprofile_starturl_binding": ("starturl", "ruletype"),
    "appfwprofile_denyurl_binding": ("denyurl", "ruletype"),
    "appfwprofile_sqlinjection_binding": (
        "sqlinjection", "formactionurl_sql", "as_scan_location_sql", "as_value_type_sql", "as_value_expr_sql", "ruletype",
    ),
}
EXISTS_CODE = {"appfwprofile_starturl_binding": 3121, "appfwprofile_denyurl_binding": 3123,
               "appfwprofile_sqlinjection_binding": 3131}
PROFILE_READ_ONLY = {"state", "learning", "csrftag", "builtin", "_nextgenapiresource", "__count", "defaults"}
BINDING_READ_ONLY = {"alertonly", "resourceid", "__count", "_nextgenapiresource"}
LEARNED_FIELD = {"starturl": "url", "sqlinjection": "name", "formactionurl_sql": "url",
                 "as_value_type_sql": "value_type", "as_value_expr_sql": "value"}
STATIC = r"^https?://[^/]+/static/.*$"


def _reply(status: int = 200, errorcode: int = 0, message: str = "Done", **payload: Any) -> httpx.Response:
    return httpx.Response(status, json={"errorcode": errorcode, "message": message, **payload})


class FakeNetScaler:
    """Just enough of the NITRO appfw API, with state, to drive every WAF tool."""

    def __init__(self) -> None:
        self.seq = 0
        self.saved = False
        self.writes: list[tuple[str, str, str | None, dict[str, str], Any]] = []
        self.profiles = {"pr_app": self.profile(
            "pr_app", learning="ON", starturlaction=["learn", "log", "stats"],
            sqlinjectionaction=["learn", "log", "stats"], errorurl="https://app.test.corp/error.html",
        )}
        self.learning_settings = {"pr_app": {"profilename": "pr_app", "starturlminthreshold": 5}}
        self.bindings = {"pr_app": {
            "appfwprofile_starturl_binding": [
                self.row("pr_app", "appfwprofile_starturl_binding", {"starturl": r"^https://app\.test\.corp/app/.*$"}),
                self.row("pr_app", "appfwprofile_starturl_binding", {"starturl": STATIC}),
            ],
            "appfwprofile_sqlinjection_binding": [self.row(
                "pr_app", "appfwprofile_sqlinjection_binding",
                {"sqlinjection": "q", "formactionurl_sql": r"^https://app\.test\.corp/search$"},
            )],
            "appfwprofile_logexpression_binding": [{"name": "pr_app", "logexpression": "le1"}],
        }}
        self.learned = {"pr_app": {
            "startURL": [
                {"url": r"^https://app\.test\.corp/app/a\.php$", "hits": "12"},
                {"url": r"^https://app\.test\.corp/portal/b\.php$", "hits": "30"},
                {"url": r"^https://app\.test\.corp/portal/c,d\.php$", "hits": "2"},
                {"url": r"^https://app\.test\.corp/wp-login\.php$", "hits": "1"},
            ],
            "SQLInjection": [{"name": "comment", "url": r"^https://app\.test\.corp/post$",
                              "value_type": "SpecialString", "value": "'", "hits": "4"}],
        }}

    @staticmethod
    def profile(name: str, **attrs: Any) -> dict[str, Any]:
        return {"name": name, "state": "ENABLED", "learning": "OFF", "builtin": ["MODIFIABLE"], "type": ["HTML"],
                "starturlaction": ["none"], "sqlinjectionaction": ["none"], "denyurlaction": ["none"], **attrs}

    def row(self, profile: str, binding: str, attrs: dict[str, Any]) -> dict[str, Any]:
        """A binding as the appliance stores it: defaults filled in, a resourceid assigned."""
        self.seq += 1
        row = {"name": profile, "state": "ENABLED", "ruletype": "ALLOW", "alertonly": "OFF", **attrs,
               "resourceid": f"res{self.seq}"}
        if binding == "appfwprofile_sqlinjection_binding":
            row.setdefault("as_scan_location_sql", "FORMFIELD")
        return row

    def start_urls(self, profile: str) -> list[str]:
        return sorted(r["starturl"] for r in self.bindings[profile].get("appfwprofile_starturl_binding", []))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, _, query = request.url.raw_path.decode().partition("?")
        resource, _, name = path.split("/nitro/v1/config/", 1)[1].partition("/")
        name = unquote(name) or None
        params = dict(p.partition("=")[::2] for p in query.split("&")) if query else {}
        args = {k: unquote(v) for k, _, v in (i.partition(":") for i in params.get("args", "").split(",") if i)}
        body = json.loads(request.content) if request.content else {}
        if resource == "login":
            return httpx.Response(201, json={"errorcode": 0, "sessionid": "s1"})
        if request.method != "GET":
            self.writes.append((request.method, resource, name, args, body))
        if resource == "nsconfig":
            self.saved = params.get("action") == "save"
            return _reply()
        if resource == "appfwprofile":
            return self._profile_api(request.method, name, body.get(resource) or {})
        if resource == "appfwlearningsettings":
            if request.method == "GET":
                return _reply(appfwlearningsettings=[self.learning_settings[name]])
            self.learning_settings[body[resource]["profilename"]].update(body[resource])
            return _reply()
        if resource == "appfwlearningdata":
            return self._learning_api(request.method, args)
        if resource == "appfwprofile_binding":
            if name not in self.profiles:
                return _reply(404, 3190, "No such profile.")
            return _reply(appfwprofile_binding=[{"name": name, **self.bindings[name]}])
        return self._binding_api(request.method, resource, name, args, body.get(resource) or {})

    def _profile_api(self, method: str, name: str | None, obj: dict[str, Any]) -> httpx.Response:
        if method == "GET":
            return _reply(appfwprofile=[self.profiles[name]]) if name in self.profiles else _reply(404, 258, "No such resource")
        if set(obj) & PROFILE_READ_ONLY:
            return _reply(400, 278, f"Invalid argument [{sorted(set(obj) & PROFILE_READ_ONLY)[0]}]")
        if method == "POST":
            self.profiles[obj["name"]] = self.profile(**obj)
            self.bindings[obj["name"]] = {}
            self.learning_settings[obj["name"]] = {"profilename": obj["name"], "starturlminthreshold": 1}
            return _reply(201)
        self.profiles[obj["name"]].update(obj)
        return _reply()

    def _binding_api(self, method: str, binding: str, name: str | None, args: dict[str, str], obj: dict[str, Any]) -> httpx.Response:
        profile = name or obj.get("name")
        if profile not in self.profiles:
            return _reply(404, 3190, "No such profile.")
        rows = self.bindings[profile].setdefault(binding, [])
        if method == "GET":
            return _reply(**({binding: rows} if rows else {}))
        if method == "PUT":
            if set(obj) & BINDING_READ_ONLY:
                return _reply(400, 278, "Invalid argument")
            new = self.row(profile, binding, {k: v for k, v in obj.items() if k != "name"})
            ident = lambda r: tuple(str(r.get(a, "")) for a in BINDING_IDENTITY[binding])  # noqa: E731
            if any(ident(r) == ident(new) for r in rows):
                return _reply(409, EXISTS_CODE[binding], "Rule already exists")
            rows.append(new)
            return _reply(201)
        keep = [r for r in rows if not all(str(r.get(k, "")) == v for k, v in args.items())]
        if len(keep) == len(rows):
            return _reply(404, 3120, "No such rule")
        self.bindings[profile][binding] = keep
        return _reply()

    def _learning_api(self, method: str, args: dict[str, str]) -> httpx.Response:
        checks = self.learned.get(args["profilename"], {})
        if method == "GET":
            return _reply(appfwlearningdata=checks.get(args["securitycheck"], []))
        wanted = {LEARNED_FIELD[k]: v for k, v in args.items() if k != "profilename"}
        for check, rows in checks.items():
            keep = [r for r in rows if not all(str(r.get(k, "")) == v for k, v in wanted.items())]
            if len(keep) != len(rows):
                checks[check] = keep
                return _reply()
        return _reply(404, 258, "No such resource")


@pytest.fixture
def ns(tmp_path):
    """A fresh fake appliance wired into the server; ns.use(allow_write=False) flips the write flag."""
    fake = FakeNetScaler()

    def use(allow_write: bool = True) -> None:
        env = {"NETSCALER_BASE_URL": "https://ns", "NETSCALER_USER": "u", "NETSCALER_PASSWORD": "p",
               "NETSCALER_ALLOW_WRITE": str(allow_write).lower(), "NETSCALER_EXPORT_DIR": str(tmp_path)}
        client = server.NitroClient(Settings.from_env(env))
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
        server._client = client

    fake.use = use
    use()
    yield fake
    server._client = None


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
