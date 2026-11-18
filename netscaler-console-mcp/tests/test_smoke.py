"""Smoke and flow tests against a small fake Console (httpx MockTransport router, no network)."""

from __future__ import annotations

import asyncio
import json
import re
import time

import httpx
import pytest

from mcp.server.mcpserver.exceptions import ToolError

from netscaler_console_mcp import server
from netscaler_console_mcp.client import ConsoleError
from netscaler_console_mcp.config import ConfigError, Settings

V2 = "/nitro/v2/config"


class Fake:
    """Routes (method, path regex) to a JSON body or handler; later routes win. Records requests."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern[str], object, int]] = []
        self.sent: list[dict[str, object]] = []
        # Console login for the API proxy (tests may override with a later route)
        self.on("POST", r"^/nitro/v1/config/login$", {"errorcode": 0, "message": "Done", "login": [{"sessionid": "##S1"}]})

    def on(self, method: str, pattern: str, body: object = None, status: int = 200) -> "Fake":
        self.routes.append((method, re.compile(pattern), body, status))
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        try:
            body = json.loads(request.content) if request.content else None
        except ValueError:
            body = request.content.decode()
        self.sent.append({"method": request.method, "path": request.url.path, "params": dict(request.url.params),
                          "headers": dict(request.headers), "body": body})
        for method, rx, body, status in reversed(self.routes):
            if method == request.method and rx.search(request.url.path):
                if callable(body):
                    return body(request)
                return httpx.Response(status, json=body if body is not None else {"errorcode": 0, "message": "Done"})
        return httpx.Response(404, json={"errorcode": 404, "message": "Resource not found"})

    def writes(self):
        return [s for s in self.sent if s["method"] != "GET" and not s["path"].endswith("/config/login")]

    def logins(self):
        return [s for s in self.sent if s["path"].endswith("/config/login")]


def use(fake: Fake, **flags: str) -> None:
    env = {"NETSCALER_CONSOLE_BASE_URL": "https://console.example.com", "NETSCALER_CONSOLE_USERNAME": "api",
           "NETSCALER_CONSOLE_PASSWORD": "pw", "NETSCALER_CONSOLE_ALLOW_WRITE": "true",
           "NETSCALER_CONSOLE_CONFIRM_WRITE": "false", **flags}
    client = server.ConsoleClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    server._client = client


@pytest.fixture(autouse=True)
def _reset():
    yield
    server._client = None


def run(coro):
    return asyncio.run(coro)


def ok(resource: str, rows: list[dict]) -> dict:
    return {"errorcode": 0, "message": "Done", "severity": "NONE", resource: rows}


# ---- config / registration ------------------------------------------------------------------

def test_settings_on_prem_and_cloud():
    with pytest.raises(ConfigError, match="BASE_URL"):
        Settings.from_env({})
    s = Settings.from_env({"NETSCALER_CONSOLE_BASE_URL": "https://console.example.com/", "NETSCALER_CONSOLE_USERNAME": "u",
                           "NETSCALER_CONSOLE_PASSWORD": "p"})
    assert s.nitro_base == "https://console.example.com/nitro/v2/config" and not s.cloud
    assert (s.allow_write, s.allow_instance_write, s.confirm_write) == (False, False, True)
    c = Settings.from_env({"NETSCALER_CONSOLE_CUSTOMER_ID": "cust1", "NETSCALER_CONSOLE_CLIENT_ID": "id",
                           "NETSCALER_CONSOLE_CLIENT_SECRET": "sec", "NETSCALER_CONSOLE_CLOUD_REGION": "eu"})
    assert c.cloud and c.nitro_base == "https://adm.cloud.com/massvc/cust1/nitro/v2/config" and c.cloud_region == "eu"
    with pytest.raises(ConfigError, match="CLIENT_SECRET"):
        Settings.from_env({"NETSCALER_CONSOLE_CUSTOMER_ID": "x", "NETSCALER_CONSOLE_CLIENT_ID": "id"})


WRITE_TOOLS = {"clear_events", "refresh_inventory", "set_entity_state"}


def test_tools_registered_and_versions_agree():
    import pathlib
    import tomllib

    from netscaler_console_mcp import __version__

    tools = {t.name: t for t in run(server.mcp.list_tools())}
    assert {"list_instances", "list_applications", "list_events", "search_syslog", "waf_violation_logs",
            "security_violations", "waf_learned_rules", "ssl_certificates", "config_audit", "list_config_jobs",
            "vserver_diagnose", "waf_profile_status", "instance_get", "instance_running_config", "console_get",
            "performance_report", "app_anomalies", "license_status"} | WRITE_TOOLS <= set(tools)
    for name, tool in tools.items():
        assert tool.description and "properties" in tool.input_schema, name
        assert ("confirm" in tool.input_schema["properties"]) == (name in WRITE_TOOLS), name
    pyproject = tomllib.loads((pathlib.Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == pyproject["project"]["version"] == server.mcp.version


# ---- client ---------------------------------------------------------------------------------

def test_on_prem_headers_errorcode_and_proxy_headers():
    fake = (Fake().on("GET", rf"{V2}/ns_event_summary$", ok("ns_event_summary", []))
            .on("GET", rf"{V2}/managed_device$", {"errorcode": 351, "message": "Permission denied"}, status=200)
            .on("GET", r"/nitro/v1/stat/lbvserver/web$", ok("lbvserver", [{"name": "web", "state": "UP"}])))
    use(fake)
    with pytest.raises(ConsoleError, match="Permission denied"):
        run(server.list_instances())
    assert fake.sent[0]["headers"]["x-nitro-user"] == "api" and fake.sent[0]["headers"]["x-nitro-pass"] == "pw"
    run(server.instance_get("192.0.2.10", "stat/lbvserver/web"))
    h = fake.sent[-1]["headers"]
    assert h["mps-api-proxy-managed-instance-ip"] == "192.0.2.10" and h["_mps_api_proxy_managed_instance_ip"] == "192.0.2.10"
    # the API proxy needs a session, not X-NITRO-USER / -PASS
    assert fake.logins()[0]["body"] == {"login": {"username": "api", "password": "pw"}}
    assert h["sessid"] == "##S1" and "SESSID=##S1" in h["cookie"] and "x-nitro-user" not in h
    run(server.instance_get("adc-lab", "stat/lbvserver/web"))
    assert fake.sent[-1]["headers"]["mps-api-proxy-managed-instance-name"] == "adc-lab"
    assert len(fake.logins()) == 1  # session reused
    with pytest.raises(ToolError, match="config/"):
        run(server.instance_get("adc-lab", "../etc"))
    with pytest.raises(ToolError, match="instance_running_config"):
        run(server.instance_get("adc-lab", "config/nsrunningconfig"))


def test_proxy_session_renewed_once_on_401_and_parallel_calls_share_it():
    sessions = iter(["##S1", "##S2"])

    def login(request):
        return httpx.Response(200, json={"errorcode": 0, "sessionid": next(sessions)})

    def stat(request):
        if request.headers.get("sessid") == "##S1":
            return httpx.Response(401, json={"errorcode": 401, "message": "Invalid Session ID in APIProxy request:/nitro/v1/stat/ns"})
        return httpx.Response(200, json=ok("ns", [{"cpuusagepcnt": 3}]))

    fake = Fake().on("POST", r"/nitro/v1/config/login$", login).on("GET", r"/nitro/v1/stat/ns$", stat)
    use(fake)
    out = run(server.instance_get("192.0.2.10", "stat/ns"))
    assert out["ns"] == [{"cpuusagepcnt": 3}] and len(fake.logins()) == 2

    always = Fake().on("GET", r"/nitro/v1/stat/ns$", {"errorcode": 401, "message": "Invalid Session ID in APIProxy request"}, status=401)
    use(always)
    with pytest.raises(ConsoleError, match="Prompt Credentials for Instance Login"):
        run(server.instance_get("192.0.2.10", "stat/ns"))
    assert len(always.logins()) == 2

    par = Fake().on("GET", r"/nitro/v1/.*", ok("lbvserver", [{"name": "web-lb", "curstate": "UP"}]))
    use(par)
    run(server.vserver_diagnose("192.0.2.10", "web-lb"))
    assert len(par.logins()) == 1


def test_console_error_reaches_the_model_as_tool_error():
    fake = Fake().on("GET", rf"{V2}/ns_ssl_certkey$", {"errorcode": 351, "message": "Permission denied"})
    use(fake)
    from mcp.server.mcpserver.exceptions import UnexpectedToolError

    # a ToolError (not UnexpectedToolError) keeps its message for the model instead of "Error executing tool …"
    with pytest.raises(ToolError, match="Permission denied") as exc_info:
        run(server.mcp.call_tool("ssl_certificates", {}))
    assert not isinstance(exc_info.value, UnexpectedToolError)


def test_performance_report_sends_args_and_tries_key_variants():
    def report(request):
        args = request.url.params.get("args", "")
        if args.startswith("device_ip_address:192.0.2.10,vsvrName:web-lb"):
            return httpx.Response(200, json=ok("perf_lb_vserver_report", [
                {"vsvrName": "web-lb", "timestamp": 1_763_460_000_000, "hitsrate": 5},
                {"vsvrName": "web-lb", "timestamp": 1_763_463_600_000, "hitsrate": 9}]))
        return httpx.Response(200, json={"errorcode": 10006, "message": "Either IP Address or vSvrName is missing"})

    fake = Fake().on("GET", rf"{V2}/perf_lb_vserver_report$", report)
    use(fake)
    out = run(server.performance_report("192.0.2.10", "web-lb"))
    assert [s["params"]["args"] for s in fake.sent if "perf_" in s["path"]] == [
        "ip_address:192.0.2.10,vsvrName:web-lb", "device_ip_address:192.0.2.10,vsvrName:web-lb"]
    assert [r["hitsrate"] for r in out["rows"]] == [9, 5] and out["rows"][0]["timestamp"].endswith("+00:00")

    nothing = Fake().on("GET", rf"{V2}/perf_lb_servicegroup_report$", {"errorcode": 10006, "message": "Either IP Address or name is missing"})
    use(nothing)
    with pytest.raises(ToolError, match="console_get"):
        run(server.performance_report("192.0.2.10", "sg-web", kind="lb_servicegroup"))
    ok_get = Fake().on("GET", rf"{V2}/perf_lb_servicegroup_report$", ok("perf_lb_servicegroup_report", []))
    use(ok_get)
    run(server.console_get("perf_lb_servicegroup_report", args="ip_address:192.0.2.10,name:sg-web"))
    assert ok_get.sent[-1]["params"]["args"] == "ip_address:192.0.2.10,name:sg-web"


def test_cloud_token_and_bearer():
    calls = []

    def token(request):
        calls.append(request.url.host)
        return httpx.Response(200, json={"access_token": "tok1", "expires_in": 3600})

    fake = (Fake().on("POST", r"/cctrustoauth2/root/tokens/clients$", token)
            .on("GET", r"/massvc/cust1/nitro/v2/config/ns_ssl_certkey$", ok("ns_ssl_certkey", [])))
    env = {"NETSCALER_CONSOLE_CUSTOMER_ID": "cust1", "NETSCALER_CONSOLE_CLIENT_ID": "id", "NETSCALER_CONSOLE_CLIENT_SECRET": "sec",
           "NETSCALER_CONSOLE_CLOUD_REGION": "eu"}
    client = server.ConsoleClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    server._client = client
    run(server.ssl_certificates())
    assert calls == ["api-eu.cloud.com"]
    assert fake.sent[-1]["headers"]["authorization"] == "CwsAuth bearer=tok1" and fake.sent[-1]["headers"]["iscloud"] == "true"


# ---- reads ----------------------------------------------------------------------------------

def test_list_instances_merges_event_counts_and_filters_problems():
    fake = (Fake().on("GET", rf"{V2}/managed_device$", ok("managed_device", [
        {"ip_address": "192.0.2.10", "hostname": "adc-a", "instance_state": "Up", "version": "NS14.1", "ha_master_state": "Primary"},
        {"ip_address": "192.0.2.11", "hostname": "adc-b", "instance_state": "Down"}]))
            .on("GET", rf"{V2}/ns_event_summary$", ok("ns_event_summary", [{"ip_address": "192.0.2.11", "total_critical_events": 3}])))
    use(fake)
    out = run(server.list_instances(problems_only=True))
    assert out["instances"] == [{"ip_address": "192.0.2.11", "hostname": "adc-b", "instance_state": "Down", "total_critical_events": 3}]


def test_list_applications_problems_sorted_worst_first():
    fake = Fake().on("GET", rf"{V2}/adc_application_summary$", ok("adc_application_summary", [
        {"appname": "shop", "curr_state": "UP", "health_score": "95", "issues_detected": "0"},
        {"appname": "crm", "curr_state": "UP", "health_score": "40", "issues_detected": "2"},
        {"appname": "intranet", "curr_state": "DOWN", "health_score": "70"}]))
    use(fake)
    out = run(server.list_applications(problems_only=True))
    assert [a["appname"] for a in out["applications"]] == ["crm", "intranet"]


def test_events_newest_first_with_filters():
    now = int(time.time())
    fake = Fake().on("GET", rf"{V2}/active_event$", ok("active_event", [
        {"id": "1", "timestamp": now - 7200, "severity": "Critical", "category": "entityofs", "hostname": "adc-a", "entity": "svc-web1"},
        {"id": "2", "timestamp": now - 60, "severity": "Critical", "category": "entityofs", "hostname": "adc-a", "entity": "svc-web2"},
        {"id": "3", "timestamp": now - 30, "severity": "Critical", "category": "cpuUtilization", "hostname": "adc-b"}]))
    use(fake)
    out = run(server.list_events(severity="Critical", category="entityofs", hours=1))
    assert [e["id"] for e in out["events"]] == ["2"] and out["events"][0]["time"].endswith("+00:00")
    assert fake.sent[0]["params"]["filter"] == "severity:Critical"


APPFW_MSG = ("Nov 18 10:01:02 <local0.info> 192.0.2.10 11/18/2026:10:01:02 GMT adc-a 0-PPE-0 : default APPFW APPFW_SQL 4711 0 : "
             "203.0.113.66 1234-PPE0 abcdTxn web-fw https://shop.example.com/search?q=1 SQL Keyword check failed for field q=\"' or 1=1\" <blocked>")


def test_waf_violation_logs_parse_appfw_syslog():
    fake = Fake().on("GET", rf"{V2}/syslog_generic$", ok("syslog_generic", [
        {"id": 1, "ttime": time.time(), "host_name": "adc-a", "module": "APPFW", "severity": "INFO", "full_message": APPFW_MSG},
        {"id": 2, "ttime": time.time() - 10, "host_name": "adc-a", "module": "APPFW", "full_message": APPFW_MSG.replace("203.0.113.66", "198.51.100.7")}]))
    use(fake)
    out = run(server.waf_violation_logs(client_ip="203.0.113.66"))
    v = out["violations"][0]
    assert (v["violation"], v["client_ip"], v["profile"], v["url"], v["action"]) == (
        "SQL", "203.0.113.66", "web-fw", "https://shop.example.com/search?q=1", "blocked")
    assert out["count"] == 1 and out["by_violation"] == {"SQL": 1}
    assert fake.sent[0]["params"]["filter"] == "module:APPFW"


def test_ssl_certificates_soonest_first_and_learned_rules():
    fake = (Fake().on("GET", rf"{V2}/ns_ssl_certkey$", ok("ns_ssl_certkey", [
        {"certkeypair_name": "a", "days_to_expiry": "120"}, {"certkeypair_name": "b", "days_to_expiry": "5"},
        {"certkeypair_name": "c", "days_to_expiry": "-2"}]))
            .on("GET", rf"{V2}/af_waf_relaxation_rules$", ok("af_waf_relaxation_rules", [
                {"id": "1", "profile_name": "web-fw", "is_deployed": 0, "no_of_violations": 4, "field_name": "q"},
                {"id": "2", "profile_name": "web-fw", "is_deployed": 1, "no_of_violations": 40}])))
    use(fake)
    certs = run(server.ssl_certificates(expiring_within_days=30))
    assert [c["certkeypair_name"] for c in certs["certificates"]] == ["c", "b"]
    rules = run(server.waf_learned_rules(profile="web-fw", state="ready"))
    assert [r["id"] for r in rules["rules"]] == ["1"] and fake.sent[-1]["params"]["filter"] == "profile_name:web-fw"


def test_vserver_diagnose_finds_what_is_down():
    fake = (Fake().on("GET", r"/nitro/v1/config/lbvserver/web-lb$", ok("lbvserver", [{"name": "web-lb", "curstate": "UP", "ipv46": "198.51.100.20", "port": 443}]))
            .on("GET", r"/nitro/v1/stat/lbvserver/web-lb$", ok("lbvserver", [{"name": "web-lb", "actsvcs": "1", "inactsvcs": "1"}]))
            .on("GET", r"/nitro/v1/config/lbvserver_binding/web-lb$", {"errorcode": 0, "lbvserver_binding": [{
                "lbvserver_service_binding": [{"servicename": "svc-a", "ipv46": "10.0.0.5", "port": 443, "curstate": "DOWN"}],
                "lbvserver_servicegroup_binding": [{"servicegroupname": "sg-web"}]}]})
            .on("GET", r"/nitro/v1/config/servicegroup_servicegroupmember_binding/sg-web$", ok("servicegroup_servicegroupmember_binding", [
                {"servername": "web1", "port": 443, "svrstate": "UP"}, {"servername": "web2", "port": 443, "svrstate": "DOWN"}])))
    use(fake)
    out = run(server.vserver_diagnose("192.0.2.10", "web-lb"))
    assert out["problems"] == ["service svc-a (10.0.0.5:443) is DOWN", "servicegroup sg-web member web2:443 is DOWN"]


def test_vserver_diagnose_reads_nested_binding_lists():
    """NITRO returns <res>_binding as a list holding one object with the per-type lists."""
    rows = server._rows({"lbvserver_binding": [{"lbvserver_service_binding": [{"servicename": "x"}]}]}, "lbvserver_binding")
    assert rows[0]["lbvserver_service_binding"][0]["servicename"] == "x"


def test_running_config_masks_secrets():
    cfg = ('add server web1 10.0.0.5\nadd authentication ldapAction ldap1 -serverIP 10.0.0.9 -ldapBindDn svc '
           '-ldapBindDnPassword 1a2b3c -encrypted -encryptmethod ENCMTHD_3\nset ns rpcNode 192.0.2.10 -password 9f8e -encrypted')
    fake = Fake().on("GET", r"/nitro/v1/config/nsrunningconfig$", {"errorcode": 0, "nsrunningconfig": {"response": cfg}})
    use(fake)
    out = run(server.instance_running_config("192.0.2.10"))
    assert "1a2b3c" not in out["config"] and "9f8e" not in out["config"] and "add server web1" in out["config"]
    assert run(server.instance_running_config("192.0.2.10", grep="web1"))["config"] == "add server web1 10.0.0.5"


# ---- writes ---------------------------------------------------------------------------------

def test_writes_are_gated_and_confirmed():
    fake = Fake().on("POST", r"/nitro/v1/config/servicegroup$", {"errorcode": 0, "message": "Done"}).on("DELETE", rf"{V2}/active_event/7$")
    use(fake, NETSCALER_CONSOLE_ALLOW_WRITE="false", NETSCALER_CONSOLE_ALLOW_INSTANCE_WRITE="true")
    with pytest.raises(ToolError, match="NETSCALER_CONSOLE_ALLOW_WRITE"):
        run(server.clear_events(["7"]))
    use(fake)
    with pytest.raises(ToolError, match="NETSCALER_CONSOLE_ALLOW_INSTANCE_WRITE"):
        run(server.set_entity_state("192.0.2.10", "servicegroup", "sg-web", False))
    use(fake, NETSCALER_CONSOLE_ALLOW_INSTANCE_WRITE="true", NETSCALER_CONSOLE_CONFIRM_WRITE="true")
    preview = run(server.set_entity_state("192.0.2.10", "servicegroup", "sg-web", False, member="web2:443", delay_seconds=60))
    assert preview["status"] == "confirmation_required" and "graceful, 60 s" in preview["summary"]
    assert fake.writes() == []
    run(server.set_entity_state("192.0.2.10", "servicegroup", "sg-web", False, member="web2:443", delay_seconds=60,
                                confirm=preview["confirm_code"]))
    w = fake.writes()[0]
    assert w["path"] == "/nitro/v1/config/servicegroup" and w["params"] == {"action": "disable"}
    assert w["body"] == {"servicegroup": {"servicegroupname": "sg-web", "servername": "web2", "port": 443, "delay": 60, "graceful": "YES"}}
    assert w["headers"]["mps-api-proxy-managed-instance-ip"] == "192.0.2.10"
    with pytest.raises(ToolError, match="member"):
        run(server.set_entity_state("192.0.2.10", "service", "svc", False, member="x:1"))
    cleared = run(server.clear_events(["7"]))
    assert cleared["status"] == "confirmation_required"
