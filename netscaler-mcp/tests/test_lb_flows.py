"""Load balancing / content switching tools against the fake appliance: reads, add/update/state/bindings."""

from __future__ import annotations

import asyncio

import pytest

from netscaler_mcp import lb, server


def run(coro):
    return asyncio.run(coro)


def test_cs_vserver_shows_routes_in_priority_order(ns):
    out = run(server.get_object("cs_vserver", "cs_app"))
    assert out["csvserver"]["ipv46"] == "10.0.0.10"
    assert [(r["priority"], r["policy"], r["target"]) for r in out["routes"]] == [
        ("100", "cp_api", "vs_api"), ("200", "cp_static", "vs_web"),
    ]
    assert out["routes"][0]["rule"] == 'HTTP.REQ.URL.STARTSWITH("/api")'
    assert out["default_lb_vserver"] == "vs_web"


def test_service_group_shows_members_and_monitors(ns):
    out = run(server.get_object("service_group", "sg_web"))
    members = out["bindings"]["servicegroup_servicegroupmember_binding"]
    assert [(m["servername"], m["port"]) for m in members] == [("srv_web1", 80), ("srv_web2", 80)]
    assert "servicegroupname" not in members[0]
    assert out["bindings"]["servicegroup_lbmonitor_binding"][0]["monitor_name"] == "mon_http"
    lbv = run(server.get_object("lb_vserver", "vs_web"))
    assert lbv["bindings"]["lbvserver_servicegroup_binding"] == [{"servicegroupname": "sg_web"}]
    with pytest.raises(ValueError, match="No lb_vserver named"):
        run(server.get_object("lb_vserver", "vs_nope"))


def test_list_reads(ns):
    assert run(server.list_cs_policies())["count"] == 2
    assert run(server.list_cs_actions(name="ca_api"))["csaction"][0]["targetlbvserver"] == "vs_api"
    assert run(server.list_lb_monitors())["lbmonitor"][0]["type"] == "HTTP"


def test_add_object_previews_then_adds_and_skips_existing(ns):
    settings = {"servicetype": "HTTP", "ipv46": "10.0.0.21", "port": 80, "lbmethod": "LEASTCONNECTION"}
    preview = run(server.add_object("lb_vserver", "vs_new", settings))
    assert preview["result"] == "would add" and ns.writes == []
    assert preview["nitro"] == {"lbvserver": {"name": "vs_new", **settings}}
    done = run(server.add_object("lb_vserver", "vs_new", settings, dry_run=False))
    assert done["result"] == "added" and ns.lb["lbvserver"]["vs_new"]["lbmethod"] == "LEASTCONNECTION"
    again = run(server.add_object("lb_vserver", "vs_new", settings, dry_run=False))
    assert again["result"].startswith("exists") and len(ns.writes) == 1
    with pytest.raises(ValueError, match="servicetype"):
        run(server.add_object("lb_vserver", "vs_x", {"ipv46": "10.0.0.22"}))
    with pytest.raises(ValueError, match="exactly one of ip, servername"):
        run(server.add_object("service", "svc_x", {"servicetype": "HTTP", "port": 80}))
    with pytest.raises(ValueError, match="kind must be one of"):
        run(server.add_object("gslb_vserver", "x", {}))


def test_update_object_sends_only_changes_and_unsets(ns):
    out = run(server.update_object("lb_vserver", "vs_web", {"lbmethod": "LEASTCONNECTION", "port": 80},
                                   unset=["persistencetype"], dry_run=False))
    assert out["changes"]["lbmethod"] == {"before": "ROUNDROBIN", "after": "LEASTCONNECTION"}
    assert out["unchanged"] == ["port"] and "error" not in out
    assert [(w[0], w[1], w[4]["lbvserver"]) for w in ns.writes] == [
        ("PUT", "lbvserver", {"name": "vs_web", "lbmethod": "LEASTCONNECTION"}),
        ("POST", "lbvserver", {"name": "vs_web", "persistencetype": True}),
    ]
    assert "persistencetype" not in ns.lb["lbvserver"]["vs_web"]


def test_update_object_reports_rejected_attributes(ns):
    out = run(server.update_object("service_group", "sg_web", {"servicetype": "SSL", "comment": "web pool"},
                                   dry_run=False))
    assert "servicetype" in out["error"] and ns.lb["servicegroup"]["sg_web"]["comment"] == "web pool"


def test_monitor_update_carries_its_type(ns):
    run(server.update_object("monitor", "mon_http", {"interval": 10}, dry_run=False))
    assert ns.writes[-1][4]["lbmonitor"] == {"monitorname": "mon_http", "type": "HTTP", "interval": 10}
    assert ns.lb["lbmonitor"]["mon_http"]["interval"] == 10


def test_set_object_state_servers_and_members(ns):
    preview = run(server.set_object_state("server", ["srv_web1"], enabled=False, graceful=True, delay_seconds=30))
    assert preview["targets"] == [{"name": "srv_web1", "delay": 30, "graceful": "YES",
                                   "state_now": "ENABLED", "result": "would disable"}]
    run(server.set_object_state("server", ["srv_web1"], enabled=False, graceful=True, delay_seconds=30, dry_run=False))
    assert ns.lb["server"]["srv_web1"]["state"] == "DISABLED"
    assert ns.writes[-1][4]["server"] == {"name": "srv_web1", "delay": 30, "graceful": "YES"}

    out = run(server.set_object_state("service_group", ["sg_web"], enabled=False, members=["srv_web2:80"],
                                      dry_run=False))
    assert out["targets"][0]["result"] == "disabled"
    assert ns.writes[-1][4]["servicegroup"] == {"servicegroupname": "sg_web", "servername": "srv_web2", "port": 80}
    assert ns.lb_rows("servicegroup_servicegroupmember_binding", "sg_web")[1]["state"] == "DISABLED"

    run(server.set_object_state("lb_vserver", ["vs_web"], enabled=False, dry_run=False))
    assert ns.lb["lbvserver"]["vs_web"]["curstate"] == "OUT OF SERVICE"
    with pytest.raises(ValueError, match="graceful"):
        run(server.set_object_state("lb_vserver", ["vs_web"], enabled=False, graceful=True))
    with pytest.raises(ValueError, match="kind must be one of"):
        run(server.set_object_state("cs_policy", ["cp_api"], enabled=False))


def test_change_bindings_binds_skips_rebinds_and_unbinds(ns):
    out = run(server.change_bindings(
        "lb_vserver_service", "vs_api",
        add=[{"servicename": "svc_web1", "weight": 3}], dry_run=False,
    ))
    assert out["counts"] == {"bind": 0, "rebind": 1, "unbind": 0}
    assert out["steps"][0]["status"] == "rebound"
    assert [w[0] for w in ns.writes] == ["DELETE", "PUT"]  # unbind, then bind with the new weight
    assert ns.lb_rows("lbvserver_service_binding", "vs_api")[0]["weight"] == 3

    out = run(server.change_bindings("service_group_member", "sg_web",
                                     add=["srv_web2:80", "10.0.0.33:8080"], remove=["srv_web1:80"], dry_run=False))
    assert [s["status"] for s in out["steps"]] == ["bound", "unbound", "already bound"]
    rows = ns.lb_rows("servicegroup_servicegroupmember_binding", "sg_web")
    assert sorted((r["servername"], str(r["port"])) for r in rows) == [("10.0.0.33", "8080"), ("srv_web2", "80")]
    assert ns.writes[-2][4]["servicegroup_servicegroupmember_binding"] == {
        "servicegroupname": "sg_web", "ip": "10.0.0.33", "port": 8080}
    assert ns.writes[-1][3] == {"servername": "srv_web1", "port": "80"}


def test_cs_default_is_replaced_and_policies_need_priority(ns):
    out = run(server.change_bindings("cs_vserver_default", "cs_app", add=["vs_api"], dry_run=False))
    assert [s["status"] for s in out["steps"]] == ["unbound", "bound"]
    assert ns.lb_rows("csvserver_lbvserver_binding", "cs_app") == [{"name": "cs_app", "lbvserver": "vs_api"}]
    with pytest.raises(ValueError, match="priority"):
        run(server.change_bindings("cs_vserver_policy", "cs_app", add=["cp_api"]))
    out = run(server.change_bindings("cs_vserver_policy", "cs_app", remove=["cp_static"], dry_run=False))
    assert [r["policyname"] for r in ns.lb_rows("csvserver_cspolicy_binding", "cs_app")] == ["cp_api"]


def test_writes_refuse_without_allow_write(ns):
    ns.use(allow_write=False)
    assert run(server.add_object("server", "srv_x", {"ipaddress": "10.0.0.40"}))["result"] == "would add"
    with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
        run(server.add_object("server", "srv_x", {"ipaddress": "10.0.0.40"}, dry_run=False))
    with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
        run(server.change_bindings("lb_vserver_service", "vs_web", add=["svc_web1"], dry_run=False))
    assert ns.writes == []


def test_confirm_code_then_apply(ns):
    ns.use(confirm_write=True)
    preview = run(server.set_object_state("server", ["srv_web2"], enabled=False, dry_run=False))
    assert preview["status"] == "confirmation_required" and ns.writes == []
    run(server.set_object_state("server", ["srv_web2"], enabled=False, dry_run=False, confirm=preview["confirm_code"]))
    assert ns.lb["server"]["srv_web2"]["state"] == "DISABLED"


def test_whole_setup_in_one_batch(ns):
    """Server → service group + member → LB vserver → CS policy, previewed and confirmed once."""
    ns.use(confirm_write=True)
    steps = [
        {"tool": "add_object", "args": {"kind": "server", "name": "srv_app1", "settings": {"ipaddress": "10.0.0.51"}}},
        {"tool": "add_object", "args": {"kind": "service_group", "name": "sg_app", "settings": {"servicetype": "HTTP"}}},
        {"tool": "change_bindings", "args": {"binding": "service_group_member", "name": "sg_app", "add": ["srv_app1:8080"]}},
        {"tool": "add_object", "args": {"kind": "lb_vserver", "name": "vs_app", "settings": {"servicetype": "HTTP"}}},
        {"tool": "change_bindings", "args": {"binding": "lb_vserver_service_group", "name": "vs_app", "add": ["sg_app"]}},
        {"tool": "add_object", "args": {"kind": "cs_action", "name": "ca_app", "settings": {"targetlbvserver": "vs_app"}}},
        {"tool": "add_object", "args": {"kind": "cs_policy", "name": "cp_app", "settings": {
            "rule": 'HTTP.REQ.HOSTNAME.EQ("app.example.com")', "action": "ca_app"}}},
        {"tool": "change_bindings", "args": {"binding": "cs_vserver_policy", "name": "cs_app",
                                             "add": [{"policyname": "cp_app", "priority": 50}]}},
    ]
    preview = run(server.apply_batch(steps, save=True))
    assert preview["status"] == "confirmation_required" and ns.writes == []
    result = run(server.apply_batch(steps, save=True, dry_run=False, confirm=preview["confirm_code"]))
    assert result["saved"] is True, result
    routes = run(server.get_object("cs_vserver", "cs_app"))["routes"]
    assert routes[0] == {**routes[0], "policy": "cp_app", "target": "vs_app"}
    assert ns.lb_rows("servicegroup_servicegroupmember_binding", "sg_app")[0]["port"] == 8080


def test_plan_helpers():
    b = lb.BINDINGS["service_group_member"]
    assert lb.entry(b, "[fd00::5]:443") == {"ip": "fd00::5", "port": 443}
    with pytest.raises(ValueError, match="server or IP"):
        lb.entry(b, "srv_web1")
    with pytest.raises(ValueError, match="both add and remove"):
        lb.plan_bindings(b, [], [{"servername": "a", "port": 80}], [{"servername": "a", "port": 80}])


# ---- deletes ----------------------------------------------------------------

def delete(kind, names):
    """delete_object as the user would run it: preview with code, then confirm (deletes always ask)."""
    pending = run(server.delete_object(kind, names, dry_run=False))
    assert pending["status"] == "confirmation_required"
    return run(server.delete_object(kind, names, dry_run=False, confirm=pending["confirm_code"]))


def test_delete_previews_references_and_deletes(ns):
    preview = run(server.delete_object("cs_policy", ["cp_static", "cp_nope"]))
    assert preview["targets"][0] == {"name": "cp_static", "bound": {}, "result": "would delete"}
    assert preview["targets"][1]["result"] == "not found" and ns.writes == []
    # still bound to cs_app: the appliance refuses until it is unbound
    refused = delete("cs_policy", ["cp_static"])
    assert refused["targets"][0]["result"].startswith("error") and "error" in refused
    run(server.change_bindings("cs_vserver_policy", "cs_app", remove=["cp_static"], dry_run=False))
    done = delete("cs_policy", ["cp_static"])
    assert done["targets"][0]["result"] == "deleted" and "cp_static" not in ns.lb["cspolicy"]


def test_delete_shows_what_is_bound_and_monitor_carries_its_type(ns):
    preview = run(server.delete_object("service_group", ["sg_web"]))
    assert preview["targets"][0]["bound"] == {
        "servicegroup_servicegroupmember_binding": 2, "servicegroup_lbmonitor_binding": 1}
    delete("monitor", ["mon_http"])
    assert ns.writes[-1][:4] == ("DELETE", "lbmonitor", "mon_http", {"type": "HTTP"})


def test_delete_needs_its_own_flag(ns):
    ns.use(allow_delete=False)
    assert run(server.delete_object("server", ["srv_web2"]))["targets"][0]["result"] == "would delete"
    with pytest.raises(ValueError, match="NETSCALER_ALLOW_DELETE"):
        run(server.delete_object("server", ["srv_web2"], dry_run=False))
    ns.use(allow_write=False)
    with pytest.raises(ValueError, match="NETSCALER_ALLOW_WRITE"):
        run(server.delete_object("server", ["srv_web2"], dry_run=False))
    assert ns.writes == []


def test_delete_always_asks_even_with_confirmation_off(ns):
    # the fixture runs with NETSCALER_CONFIRM_WRITE=false: other writes apply directly, deletes don't
    pending = run(server.delete_object("server", ["srv_web2"], dry_run=False))
    assert pending["status"] == "confirmation_required" and ns.writes == []
    run(server.delete_object("server", ["srv_web2"], dry_run=False, confirm=pending["confirm_code"]))
    assert "srv_web2" not in ns.lb["server"]


def test_batch_with_a_delete_always_asks(ns):
    steps = [
        {"tool": "change_bindings", "args": {"binding": "cs_vserver_policy", "name": "cs_app", "remove": ["cp_static"]}},
        {"tool": "delete_object", "args": {"kind": "cs_policy", "names": ["cp_static"]}},
        {"tool": "delete_object", "args": {"kind": "cs_action", "names": ["ca_web"]}},
    ]
    pending = run(server.apply_batch(steps, dry_run=False))
    assert pending["status"] == "confirmation_required" and ns.writes == []
    result = run(server.apply_batch(steps, dry_run=False, confirm=pending["confirm_code"]))
    assert [s.get("error") for s in result["steps"]] == [None, None, None], result
    assert "cp_static" not in ns.lb["cspolicy"] and "ca_web" not in ns.lb["csaction"]
