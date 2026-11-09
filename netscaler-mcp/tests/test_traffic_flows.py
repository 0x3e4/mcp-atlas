"""SSL, policy bindings, policy data, GSLB / DNS, diagnosis, cloning and multi-instance batches against the fake."""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest

from fake_netscaler import FakeNetScaler
from netscaler_mcp import server
from netscaler_mcp.config import Settings

TMPL = "tmpl.example.com"
PEM_CERT = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
PEM_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----\n"


def run(coro):
    return asyncio.run(coro)


def confirmed(tool, *args, **kwargs):
    """Run a write the way the user would: preview with code, then confirm."""
    pending = run(tool(*args, **kwargs, dry_run=False))
    if pending.get("status") != "confirmation_required":
        return pending
    return run(tool(*args, **kwargs, dry_run=False, confirm=pending["confirm_code"]))


# ---- SSL ----------------------------------------------------------------------

def test_certkey_add_masks_the_password_and_renewal_uses_update(ns):
    settings = {"cert": "app.pfx", "inform": "PFX", "passplain": "s3cret-pass", "expirymonitor": "ENABLED",
                "notificationperiod": 30}
    preview = run(server.add_object("ssl_certkey", "cert_app", settings))
    assert preview["nitro"]["sslcertkey"]["passplain"] == "***"
    done = run(server.add_object("ssl_certkey", "cert_app", settings, dry_run=False))
    assert done["result"] == "added" and "s3cret-pass" not in json.dumps(done)
    assert ns.lb["sslcertkey"]["cert_app"]["passplain"] == "s3cret-pass"  # the appliance got it

    # renewal keeps the file names: still sent, through 'update ssl certKey'
    out = run(server.update_object("ssl_certkey", "cert_wild", {"cert": "wild.pem", "key": "wild.key"}, dry_run=False))
    assert out["changes"]["cert"]["via"] == "update (reload)" and "error" not in out
    assert ns.actions[-1] == ("sslcertkey", "update", {"certkey": "cert_wild", "cert": "wild.pem", "key": "wild.key"})


def test_certkey_link_to_ca(ns):
    out = run(server.change_bindings("ssl_certkey_link", "cert_wild", add=["ca_root"], dry_run=False))
    assert out["steps"][0]["status"] == "bound" and ns.lb["sslcertkey"]["cert_wild"]["linkcertkeyname"] == "ca_root"
    again = run(server.change_bindings("ssl_certkey_link", "cert_wild", add=["ca_root"]))
    assert again["steps"][0]["status"] == "already bound"
    run(server.change_bindings("ssl_certkey_link", "cert_wild", remove=["ca_root"], dry_run=False))
    assert ns.actions[-1] == ("sslcertkey", "unlink", {"certkey": "cert_wild"})


def test_upload_ssl_file_only_to_nsconfig_ssl(ns, tmp_path):
    preview = run(server.upload_ssl_file("app.key", text=PEM_KEY))
    assert preview["result"] == "would upload" and preview["filelocation"] == "/nsconfig/ssl"
    assert preview["contains"] == ["private key"] and "MIIEfake" not in json.dumps(preview)
    run(server.upload_ssl_file("app.key", text=PEM_KEY, dry_run=False))
    assert ns.files["app.key"] == PEM_KEY.encode()
    same = run(server.upload_ssl_file("app.key", text=PEM_KEY, dry_run=False))
    assert same["result"].startswith("identical") and ns.writes[-1][1] == "systemfile"  # no new write
    writes = len(ns.writes)
    other = run(server.upload_ssl_file("app.key", text=PEM_CERT, dry_run=False))
    assert "overwrite=true" in other["result"] and len(ns.writes) == writes
    replaced = run(server.upload_ssl_file("app.key", text=PEM_CERT, overwrite=True, dry_run=False))
    assert replaced["result"] == "replaced" and ns.files["app.key"] == PEM_CERT.encode()
    for bad in ("../etc/passwd", "/nsconfig/ssl/x.pem", "a b.pem"):
        with pytest.raises(ValueError, match="bare name"):
            run(server.upload_ssl_file(bad, text=PEM_CERT))
    (tmp_path / "chain.pem").write_bytes(PEM_CERT.encode())
    from_dir = run(server.upload_ssl_file("chain.pem", file="chain.pem", dry_run=False))
    assert from_dir["result"] == "uploaded" and ns.files["chain.pem"] == PEM_CERT.encode()


def test_sni_certificate_and_ssl_profiles(ns):
    out = run(server.change_bindings("ssl_vserver_certkey", "cs_ssl",
                                     add=[{"certkeyname": "cert_app", "snicert": True}], dry_run=False))
    assert out["steps"][0]["status"] == "bound"
    assert ns.writes[-1][4]["sslvserver_sslcertkey_binding"] == {
        "vservername": "cs_ssl", "certkeyname": "cert_app", "snicert": True}
    run(server.change_bindings("ssl_vserver_certkey", "cs_ssl", remove=["cert_app"], dry_run=False))
    assert ns.writes[-1][:4] == ("DELETE", "sslvserver_sslcertkey_binding", "cs_ssl",
                                 {"certkeyname": "cert_app", "snicert": "true"})

    run(server.add_object("ssl_profile", "prof_tls13", {"sslprofiletype": "BackEnd", "tls12": "DISABLED",
                                                        "tls13": "ENABLED"}, dry_run=False))
    run(server.change_bindings("ssl_profile_cipher", "prof_backend",
                               add=[{"ciphername": "TLS1.3-AES256-GCM-SHA384", "cipherpriority": 1}],
                               remove=["DEFAULT_BACKEND"], dry_run=False))
    assert [r["ciphername"] for r in ns.lb_rows("sslprofile_sslcipher_binding", "prof_backend")] == [
        "TLS1.3-AES256-GCM-SHA384"]
    sg = f"svg_{TMPL}"
    out = run(server.update_object("ssl_service_group", sg, {"sslprofile": "prof_tls13"}, dry_run=False))
    assert out["changes"]["sslprofile"] == {"before": "prof_backend", "after": "prof_tls13"}
    assert ns.lb["sslservicegroup"][sg]["sslprofile"] == "prof_tls13"
    with pytest.raises(ValueError, match="kind must be one of"):
        run(server.add_object("ssl_vserver", "cs_ssl", {}))


# ---- policy bindings ------------------------------------------------------------

def test_feature_policies_and_analytics_on_vservers(ns):
    run(server.change_bindings("lb_vserver_rewrite_policy", "vs_web", add=[
        {"policyname": "rw_404", "priority": 100, "bindpoint": "RESPONSE", "gotopriorityexpression": "NEXT"},
        {"policyname": "rw_500", "priority": 110, "bindpoint": "RESPONSE"},
    ], dry_run=False))
    run(server.change_bindings("lb_vserver_responder_policy", "vs_web",
                               add=[{"policyname": "log_req", "priority": 100, "bindpoint": "REQUEST"}], dry_run=False))
    run(server.change_bindings("lb_vserver_analytics_profile", "vs_web", add=["ana_web"], dry_run=False))
    assert [r["policyname"] for r in ns.lb_rows("lbvserver_rewritepolicy_binding", "vs_web")] == ["rw_404", "rw_500"]
    assert ns.lb_rows("lbvserver_analyticsprofile_binding", "vs_web")[0]["analyticsprofile"] == "ana_web"

    # a new priority re-binds, unbinding with the live row's bindpoint and priority
    out = run(server.change_bindings("lb_vserver_rewrite_policy", "vs_web",
                                     add=[{"policyname": "rw_500", "priority": 120, "bindpoint": "RESPONSE"}],
                                     dry_run=False))
    assert out["steps"][0]["status"] == "rebound"
    unbind = next(w for w in reversed(ns.writes) if w[0] == "DELETE")
    assert unbind[3] == {"policyname": "rw_500", "bindpoint": "RESPONSE", "priority": "110"}
    with pytest.raises(ValueError, match="priority"):
        run(server.change_bindings("lb_vserver_rewrite_policy", "vs_web", add=["rw_404"]))


def test_global_rewrite_binding_has_no_name(ns):
    with pytest.raises(ValueError, match="global"):
        run(server.change_bindings("rewrite_global_policy", "vs_web", add=[{"policyname": "x", "priority": 1}]))
    out = run(server.change_bindings("rewrite_global_policy", remove=["rw_404"], dry_run=False))
    assert out["scope"] == "global" and out["steps"][0]["status"] == "unbound"
    assert ns.writes[-1][:4] == ("DELETE", "rewriteglobal_rewritepolicy_binding", None,
                                 {"policyname": "rw_404", "type": "RES_DEFAULT", "priority": "500"})


def test_rewrite_objects_and_html_page_import(ns):
    run(server.add_object("rewrite_action", "rwa_hdr", {"type": "insert_http_header", "target": "X-App",
                                                        "stringbuilderexpr": '"1"'}, dry_run=False))
    run(server.add_object("rewrite_policy", "rwp_hdr", {"rule": "true", "action": "rwa_hdr"}, dry_run=False))
    assert ns.lb["rewritepolicy"]["rwp_hdr"]["action"] == "rwa_hdr"
    run(server.add_object("responder_htmlpage", "page_maint", {"src": "http://10.0.0.5/maint.html"}, dry_run=False))
    assert ns.actions[-1][:2] == ("responderhtmlpage", "Import")
    with pytest.raises(ValueError, match="kind must be one of"):
        run(server.update_object("responder_htmlpage", "page_maint", {"comment": "x"}))


# ---- pattern sets / data sets / expressions -----------------------------------------

def test_search_policy_objects_finds_names_values_and_expressions(ns):
    found = run(server.search_policy_objects("internal"))
    by = {(m["kind"], m["name"]): m for m in found["matches"]}
    assert by[("policy_patset", "ps_internal")]["match"] == "name"
    assert [v["String"] for v in by[("policy_patset", "ps_internal")]["values"]] == ["internal", "intranet"]
    assert by[("policy_patset", "ps_other")]["match"] == "value"
    assert by[("policy_expression", "ex_lan")]["match"] == "expression"
    assert found["searched"]["policy_dataset"] == 1
    run(server.change_bindings("policy_patset_pattern", "ps_internal", add=["vpn"], remove=["intranet"], dry_run=False))
    assert [r["String"] for r in ns.lb_rows("policypatset_pattern_binding", "ps_internal")] == ["internal", "vpn"]


# ---- GSLB / DNS ------------------------------------------------------------------

def test_dns_records_are_told_apart_by_value(ns):
    assert run(server.add_object("dns_a", "app.example.com", {"ipaddress": "10.0.0.50"}))["result"].startswith("exists")
    run(server.add_object("dns_a", "app.example.com", {"ipaddress": "10.0.0.52", "ttl": 300}, dry_run=False))
    assert run(server.get_object("dns_a", "app.example.com"))["count"] == 3
    one = confirmed(server.delete_object, "dns_a", [{"hostname": "app.example.com", "ipaddress": "10.0.0.51"}])
    assert [t["result"] for t in one["targets"]] == ["deleted"]
    assert ns.writes[-1][3] == {"ipaddress": "10.0.0.51"}
    rest = confirmed(server.delete_object, "dns_a", ["app.example.com"])
    assert [t["result"] for t in rest["targets"]] == ["deleted", "deleted"]


def test_gslb_objects_bindings_and_sync(ns):
    run(server.add_object("gslb_service", "gs_app_a", {"servicetype": "HTTP", "ip": "10.0.1.10", "port": 80,
                                                       "sitename": "site_a"}, dry_run=False))
    run(server.add_object("gslb_vserver", "gv_app", {"servicetype": "HTTP"}, dry_run=False))
    run(server.change_bindings("gslb_vserver_service", "gv_app", add=[{"servicename": "gs_app_a", "weight": 1}],
                               dry_run=False))
    assert ns.lb_rows("gslbvserver_gslbservice_binding", "gv_app")[0]["servicename"] == "gs_app_a"
    preview = run(server.sync_gslb_config())
    assert [t["sitename"] for t in preview["targets"]] == ["site_b"] and preview["result"] == "would sync"
    done = run(server.sync_gslb_config(save_on_sites=True, dry_run=False))
    assert done["result"] == "synced"
    assert ns.actions[-1] == ("gslbconfig", "sync", {"nowarn": True, "saveconfig": True})
    with pytest.raises(ValueError, match="remote sites"):
        run(server.sync_gslb_config(force_site="site_a"))


# ---- diagnosis -------------------------------------------------------------------

def test_vserver_diagnose_warns_about_idle_members_and_tcp_only_monitors(ns):
    out = run(server.vserver_diagnose("cs_ssl"))
    assert [lb["name"] for lb in out["lb_vservers"]] == [f"lb_{TMPL}", "vs_api"]
    member = out["lb_vservers"][0]["service_groups"][0]["members"][0]
    assert member["primaryipaddress"] == "10.0.0.61"
    assert any("handled no requests" in w for w in out["warnings"])
    assert not any("TLS handshake" in w for w in out["warnings"])  # an HTTPS monitor is bound

    ns.lb_bindings["servicegroup_lbmonitor_binding"][f"svg_{TMPL}"] = []  # falls back to tcp-default
    out = run(server.vserver_diagnose(f"lb_{TMPL}"))
    assert any("TLS handshake" in w and "tcp-default" in w for w in out["warnings"])
    with pytest.raises(ValueError, match="No CS or LB vserver"):
        run(server.vserver_diagnose("nope"))


# ---- cloning an app ------------------------------------------------------------------

def test_clone_app_setup_copies_the_template(ns):
    ns.use(confirm_write=True)
    kwargs = dict(template_lb_vserver=f"lb_{TMPL}", template_hostname=TMPL, new_hostname="new.example.com",
                  backends=["srv_new1=10.0.0.71:443", "10.0.0.72:443"], certkey="cert_wild",
                  ssl_profile="prof_backend", save=True)
    preview = run(server.clone_app_setup(**kwargs))
    assert preview["status"] == "confirmation_required" and ns.writes == []
    assert preview["new"]["cs_policy"] == "cp_new.example.com" and preview["new"]["priority"] == 302
    assert preview["new"]["rule"] == 'HTTP.REQ.HOSTNAME.EQ("new.example.com")'
    done = run(server.clone_app_setup(**kwargs, dry_run=False, confirm=preview["confirm_code"]))
    assert done["saved"] is True, done

    new_lb, new_sg = "lb_new.example.com", "svg_new.example.com"
    assert ns.lb["lbvserver"][new_lb]["lbmethod"] == "LEASTCONNECTION" and ns.lb["lbvserver"][new_lb]["clttimeout"] == 180
    assert ns.lb["servicegroup"][new_sg]["cipheader"] == "X-Forwarded-For"
    assert ns.lb["server"]["srv_new1"]["ipaddress"] == "10.0.0.71"
    members = ns.lb_rows("servicegroup_servicegroupmember_binding", new_sg)
    assert sorted((m["servername"], m["port"]) for m in members) == [("10.0.0.72", 443), ("srv_new1", 443)]
    assert ns.lb_rows("servicegroup_lbmonitor_binding", new_sg)[0]["monitor_name"] == "mon_https"
    assert ns.lb["sslservicegroup"][new_sg]["sslprofile"] == "prof_backend"
    rewrites = ns.lb_rows("lbvserver_rewritepolicy_binding", new_lb)
    assert [(r["policyname"], str(r["priority"]), r["bindpoint"]) for r in rewrites] == [
        ("rw_404", "100", "RESPONSE"), ("rw_500", "110", "RESPONSE")]
    assert ns.lb_rows("lbvserver_responderpolicy_binding", new_lb)[0]["policyname"] == "log_req"
    assert ns.lb_rows("lbvserver_analyticsprofile_binding", new_lb)[0]["analyticsprofile"] == "ana_web"
    assert ns.lb["csaction"]["ca_new.example.com"]["targetlbvserver"] == new_lb
    routes = run(server.get_object("cs_vserver", "cs_ssl"))["routes"]
    assert ("302", "cp_new.example.com", new_lb) in [(str(r["priority"]), r["policy"], r["target"]) for r in routes]
    sni = [r for r in ns.lb_rows("sslvserver_sslcertkey_binding", "cs_ssl") if r.get("snicert")]
    assert sni == [{"vservername": "cs_ssl", "certkeyname": "cert_wild", "snicert": True}]


def test_clone_needs_names_it_can_derive(ns):
    with pytest.raises(ValueError, match="does not contain"):
        run(server.clone_app_setup(template_lb_vserver="vs_web", template_hostname=TMPL,
                                   new_hostname="new.example.com", backends=["10.0.0.72:443"]))


# ---- one batch on several instances -------------------------------------------------------

@pytest.fixture
def pair():
    """Two fake appliances configured as instances dc1 and dc2, with confirmation on."""
    fakes = {"dc1": FakeNetScaler(), "dc2": FakeNetScaler()}
    clients = {}
    for name, fake in fakes.items():
        env = {"NETSCALER_BASE_URL": f"https://{name}", "NETSCALER_USER": "u", "NETSCALER_PASSWORD": "p",
               "NETSCALER_ALLOW_WRITE": "true", "NETSCALER_CONFIRM_WRITE": "true"}
        client = server.NitroClient(Settings.from_env(env))
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
        clients[name] = client
    saved = server._default_instance
    server._clients, server._default_instance = clients, "dc1"
    yield fakes
    server._clients, server._default_instance = {}, saved


STEPS = [
    {"tool": "add_object", "args": {"kind": "server", "name": "srv_app1", "settings": {"ipaddress": "10.0.0.81"}}},
    {"tool": "add_object", "args": {"kind": "service_group", "name": "sg_app", "settings": {"servicetype": "HTTP"}}},
    {"tool": "change_bindings", "args": {"binding": "service_group_member", "name": "sg_app", "add": ["srv_app1:80"]}},
    {"tool": "change_bindings", "args": {"binding": "lb_vserver_service_group", "name": "vs_web", "add": ["sg_app"]}},
]


def test_one_batch_on_two_instances_with_one_confirmation(pair):
    preview = run(server.apply_batch(STEPS, instances=["dc1", "dc2"], save=True))
    assert preview["status"] == "confirmation_required" and set(preview["instances"]) == {"dc1", "dc2"}
    assert "on each of dc1, dc2" in preview["summary"]
    assert all(f.writes == [] for f in pair.values())
    done = run(server.apply_batch(STEPS, instances=["dc1", "dc2"], save=True, dry_run=False,
                                  confirm=preview["confirm_code"]))
    assert all(done["instances"][n]["saved"] for n in ("dc1", "dc2")), done
    assert all("sg_app" in f.lb["servicegroup"] for f in pair.values())
    assert done["comparison"]["identical"] is True


def test_a_failure_on_the_first_instance_stops_all(pair):
    del pair["dc1"].lb["lbvserver"]["vs_web"]  # the last step fails on dc1 only
    preview = run(server.apply_batch(STEPS, instances=["dc1", "dc2"]))
    done = run(server.apply_batch(STEPS, instances=["dc1", "dc2"], dry_run=False, confirm=preview["confirm_code"]))
    assert "error" in done["instances"]["dc1"]["steps"][-1]
    assert done["instances"]["dc2"]["status"] == "not run" and pair["dc2"].writes == []
    assert "comparison" not in done
