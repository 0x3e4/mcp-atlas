"""Several appliances in one server: NETSCALER_INSTANCES parsing, per-call routing, 'all' fan-out,
instance-bound confirm codes, list_instances and compare_instances — against fakes, no network."""

from __future__ import annotations

import asyncio
from typing import Any, Callable

import httpx
import pytest

from fake_netscaler import FakeNetScaler, reply
from netscaler_mcp import server
from netscaler_mcp.config import ConfigError, load_instances


def _env(*names: str, **extra: str) -> dict[str, str]:
    env = {"NETSCALER_INSTANCES": ",".join(names), "NETSCALER_USER": "u", "NETSCALER_PASSWORD": "p"}
    for name in names:
        env[f"NETSCALER_{name.upper().replace('-', '_')}_BASE_URL"] = f"https://{name}.test.corp"
    return {**env, **extra}


@pytest.fixture
def wire():
    """wire({name: handler}, **env) points the server at one MockTransport per instance."""

    def use(handlers: dict[str, Callable[[httpx.Request], httpx.Response]], **extra: str) -> None:
        env = _env(*handlers, NETSCALER_ALLOW_WRITE="true", NETSCALER_CONFIRM_WRITE="false")
        settings, default = load_instances({**env, **extra})
        clients = {}
        for name, s in settings.items():
            client = server.NitroClient(s)
            client._client = httpx.AsyncClient(transport=httpx.MockTransport(handlers[name]))
            clients[name] = client
        server._clients, server._default_instance = clients, default

    yield use
    server._clients, server._default_instance = {}, "default"


# ---- configuration -------------------------------------------------------

def test_single_appliance_without_instances_list():
    settings, default = load_instances(
        {"NETSCALER_BASE_URL": "https://10.0.0.10", "NETSCALER_USER": "u", "NETSCALER_PASSWORD": "p"}
    )
    assert default == "default" and list(settings) == ["default"]
    assert settings["default"].base_url == "https://10.0.0.10"


def test_instances_share_settings_and_override_per_instance():
    env = _env(
        "dc1", "dc-2",
        NETSCALER_DC_2_USER="other", NETSCALER_DC_2_ALLOW_WRITE="true", NETSCALER_VERIFY_SSL="false",
        NETSCALER_DEFAULT_INSTANCE="DC-2",
    )
    settings, default = load_instances(env)
    assert default == "dc-2" and list(settings) == ["dc1", "dc-2"]
    dc1, dc2 = settings["dc1"], settings["dc-2"]
    assert (dc1.name, dc1.base_url, dc1.user, dc1.allow_write) == ("dc1", "https://dc1.test.corp", "u", False)
    assert (dc2.name, dc2.base_url, dc2.user, dc2.allow_write) == ("dc-2", "https://dc-2.test.corp", "other", True)
    assert dc1.verify_ssl is False and dc2.verify_ssl is False  # shared fallback


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"NETSCALER_INSTANCES": "dc1", "NETSCALER_BASE_URL": "https://x", "NETSCALER_USER": "u",
          "NETSCALER_PASSWORD": "p"}, "NETSCALER_DC1_BASE_URL"),
        (_env("1dc"), "not a valid instance name"),
        (_env("dc_a", "dc-a"), "share the variable prefix"),
        (_env("session"), "NETSCALER_SESSION_TIMEOUT"),
        (_env("dc1", NETSCALER_DEFAULT_INSTANCE="dc9"), "NETSCALER_DEFAULT_INSTANCE"),
        ({**_env("dc1"), "NETSCALER_PASSWORD": ""}, "Instance 'dc1'.*NETSCALER_PASSWORD"),
    ],
)
def test_instance_config_errors(env, message):
    with pytest.raises(ConfigError, match=message):
        load_instances(env)


def test_every_appliance_tool_takes_an_instance():
    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
    for name, tool in tools.items():
        props = tool.inputSchema["properties"]
        if name in ("list_instances", "compare_instances"):
            assert "instance" not in props
            continue
        assert "instance" in props, f"{name} missing instance"
        write = "confirm" in props
        assert ("'all'" in props["instance"]["description"]) is not write, name


# ---- routing -------------------------------------------------------------

def test_calls_go_to_the_named_instance_and_all_fans_out(wire):
    dc1, dc2 = FakeNetScaler(), FakeNetScaler()
    dc2.profiles["pr_dc2"] = dc2.profile("appfwprofile", "pr_dc2")
    wire({"dc1": dc1, "dc2": dc2})

    async def scenario():
        default = await server.list_waf_profiles()
        assert [p["name"] for p in default["appfwprofile"]] == ["pr_app"]  # dc1 is the first listed
        named = await server.list_waf_profiles(instance="DC2")
        assert [p["name"] for p in named["appfwprofile"]] == ["pr_app", "pr_dc2"]
        both = await server.list_waf_profiles(instance="all")
        assert {n: r["count"] for n, r in both["instances"].items()} == {"dc1": 1, "dc2": 2}
        with pytest.raises(ValueError, match="Unknown NetScaler instance 'dc9'.*dc1, dc2"):
            await server.list_waf_profiles(instance="dc9")

    asyncio.run(scenario())


def test_all_reports_a_failing_instance_without_failing_the_call(wire):
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable")

    wire({"dc1": FakeNetScaler(), "dc2": down})
    result = asyncio.run(server.list_waf_profiles(instance="all"))
    assert result["instances"]["dc1"]["count"] == 1
    assert "Network error" in result["instances"]["dc2"]["error"]


def test_writes_need_one_named_instance(wire):
    dc1, dc2 = FakeNetScaler(), FakeNetScaler()
    wire({"dc1": dc1, "dc2": dc2})
    add = dict(profile="pr_app", rule="allow_url", host="app.test.corp", path="/portal/", dry_run=False)

    async def scenario():
        with pytest.raises(ValueError, match="explicit instance"):
            await server.add_waf_rule(**add)
        with pytest.raises(ValueError, match="one named instance"):
            await server.add_waf_rule(**add, instance="all")
        result = await server.add_waf_rule(**add, instance="dc2")
        assert result["results"][0]["status"] == "added"

    asyncio.run(scenario())
    assert dc1.writes == [] and len(dc2.writes) == 1


def test_per_instance_write_flag(wire):
    dc1, dc2 = FakeNetScaler(), FakeNetScaler()
    wire({"dc1": dc1, "dc2": dc2}, NETSCALER_DC1_ALLOW_WRITE="false")
    with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
        asyncio.run(server.save_config(instance="dc1"))
    asyncio.run(server.save_config(instance="dc2"))
    assert not dc1.saved and dc2.saved


def test_confirm_code_is_bound_to_the_instance(wire):
    dc1, dc2 = FakeNetScaler(), FakeNetScaler()
    wire({"dc1": dc1, "dc2": dc2}, NETSCALER_CONFIRM_WRITE="true")
    add = dict(profile="pr_app", rule="allow_url", host="app.test.corp", path="/portal/")

    async def scenario():
        preview = await server.add_waf_rule(**add, instance="dc1")
        assert preview["instance"] == "dc1" and preview["status"] == "confirmation_required"
        code = preview["confirm_code"]
        elsewhere = await server.add_waf_rule(**add, dry_run=False, confirm=code, instance="dc2")
        assert elsewhere["status"] == "confirmation_required" and elsewhere["instance"] == "dc2"
        assert dc2.writes == []
        applied = await server.add_waf_rule(**add, dry_run=False, confirm=code, instance="dc1")
        assert applied["results"][0]["status"] == "added"
        pending = await server.save_config(instance="dc2")
        assert pending["instance"] == "dc2" and not dc2.saved

    asyncio.run(scenario())
    assert len(dc1.writes) == 1 and dc2.writes == []


# ---- list_instances / compare_instances ------------------------------------

def _box(**resources: Any) -> Callable[[httpx.Request], httpx.Response]:
    """A read-only fake answering config GETs from ``resources`` (gslbvserver_binding keyed by vserver)."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/config/login"):
            return httpx.Response(201, json={"errorcode": 0, "sessionid": "s1"})
        rt, _, name = path.split("/nitro/v1/config/", 1)[1].partition("/")
        if rt == "gslbvserver_binding":
            return reply(gslbvserver_binding=[{"name": name, **resources[rt].get(name, {})}])
        if rt in resources:
            return reply(**{rt: resources[rt]})
        return reply(599, 1067, "Feature(s) not enabled [GSLB]")

    return handler


def _gslb(local: str, lbmethod: str = "RTT", services: tuple[str, ...] = ("a", "b"), ttl: int = 5) -> Any:
    sites = [
        {"sitename": f"site_{s}", "sitetype": "LOCAL" if s == local else "REMOTE",
         "siteipaddress": f"10.0.{i}.10", "metricexchange": "ENABLED"}
        for i, s in enumerate(("a", "b"))
    ]
    return _box(
        gslbsite=sites,
        gslbvserver=[{"name": "gv_app", "servicetype": "SSL", "lbmethod": lbmethod, "curstate": "UP"}],
        gslbservice=[
            {"servicename": f"gs_app_{s}", "ipaddress": f"10.0.{i}.20", "port": 443, "sitename": f"site_{s}"}
            for i, s in enumerate(("a", "b")) if s in services
        ],
        gslbvserver_binding={"gv_app": {
            "gslbvserver_gslbservice_binding": [
                {"name": "gv_app", "servicename": f"gs_app_{s}", "weight": 1, "curstate": "UP"} for s in services
            ],
            "gslbvserver_domain_binding": [{"name": "gv_app", "domainname": "app.test.corp", "ttl": ttl}],
        }},
    )


def test_compare_gslb_peers(wire):
    wire({"dc1": _gslb("a"), "dc2": _gslb("b", lbmethod="ROUNDROBIN", services=("a",)), "dc3": _box()})
    result = asyncio.run(server.compare_instances())
    assert result["instances"] == ["dc1", "dc2", "dc3"]
    assert "not enabled" in result["errors"]["dc3"]
    assert result["in_sync"] is False
    assert result["local_sites"] == {"dc1": ["site_a"], "dc2": ["site_b"]}
    res = result["resources"]
    assert res["gslbsite"] == {"objects": 2, "identical": 2}  # sitetype differs by design
    assert res["gslbvserver"]["different"] == [
        {"key": "gv_app", "attrs": {"lbmethod": {"dc1": "RTT", "dc2": "ROUNDROBIN"}}}
    ]
    assert res["gslbservice"]["missing_on"] == {"dc2": ["gs_app_b"]}
    assert res["gslbvserver_gslbservice_binding"]["missing_on"] == {"dc2": ["gv_app -> gs_app_b"]}
    assert res["gslbvserver_domain_binding"] == {"objects": 1, "identical": 1}


def test_compare_gslb_in_sync_and_double_local_site(wire):
    wire({"dc1": _gslb("a"), "dc2": _gslb("b")})
    result = asyncio.run(server.compare_instances(instances="dc1,dc2"))
    assert result["in_sync"] is True and "warnings" not in result

    wire({"dc1": _gslb("a"), "dc2": _gslb("a"), "dc3": _gslb("none")})
    result = asyncio.run(server.compare_instances())
    assert result["in_sync"] is False
    assert result["warnings"] == ["dc3 has no LOCAL GSLB site.", "GSLB site site_a is LOCAL on dc1, dc2."]


def test_compare_any_resource_skips_runtime_attributes(wire):
    def lb(ip: str, state: str) -> Any:
        return _box(lbvserver=[{"name": "vs_app", "ipv46": ip, "port": 443, "curstate": state, "statechangetimesec": "x"}])

    wire({"dc1": lb("10.0.0.30", "UP"), "dc2": lb("10.0.1.30", "DOWN")})
    result = asyncio.run(server.compare_instances("lbvserver"))
    assert result["resources"]["lbvserver"]["different"] == [
        {"key": "vs_app", "attrs": {"ipv46": {"dc1": "10.0.0.30", "dc2": "10.0.1.30"}}}
    ]
    same = asyncio.run(server.compare_instances("lbvserver", attrs="port"))
    assert same["in_sync"] is True
    with pytest.raises(ValueError, match="at least two"):
        asyncio.run(server.compare_instances(instances="dc1"))


def test_list_instances_with_probe(wire):
    standalone = _box(
        nsversion=[{"version": "NetScaler NS14.1: Build 1.1.nc"}],
        hanode=[{"id": "0", "ipaddress": "10.0.0.10", "masterstate": "Primary"}],
    )
    wire({"dc1": standalone, "dc2": _box()}, NETSCALER_DC2_ALLOW_WRITE="true", NETSCALER_ALLOW_WRITE="false")
    plain = asyncio.run(server.list_instances())
    assert plain["default"] == "dc1" and plain["count"] == 2
    assert plain["instances"]["dc1"] == {
        "url": "https://dc1.test.corp", "default": True, "auth_mode": "session",
        "allow_write": False, "confirm_write": False,
    }
    assert plain["instances"]["dc2"]["allow_write"] is True
    probed = asyncio.run(server.list_instances(probe=True))["instances"]
    assert probed["dc1"]["reachable"] is True and probed["dc1"]["ha_peers"] == []
    assert probed["dc1"]["version"].startswith("NetScaler NS14.1")
    assert probed["dc2"]["reachable"] is False and "error" in probed["dc2"]
