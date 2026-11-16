"""Flows of the 1.1.0 tools against a small fake FortiGate (httpx MockTransport router, no network)."""

from __future__ import annotations

import asyncio
import json
import re

import httpx
import pytest

from fortigate_mcp import server
from fortigate_mcp.config import Settings

API = "/api/v2"


def env_ok(results=None, **extra) -> dict:
    return {"status": "success", "http_status": 200, "vdom": "root", "results": results, **extra}


class Fake:
    """Routes (method, raw path regex) to a JSON body or a handler; later routes win. Records requests."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern[str], object, int]] = []
        self.sent: list[tuple[str, str, dict[str, str], object]] = []

    def on(self, method: str, pattern: str, body: object = None, status: int = 200) -> "Fake":
        self.routes.append((method, re.compile(pattern), body, status))
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content) if request.content else None
        path = request.url.raw_path.decode().split("?")[0]
        params = dict(request.url.params)
        self.sent.append((request.method, path, params, payload))
        for method, rx, body, status in reversed(self.routes):
            if method == request.method and rx.search(path):
                if callable(body):
                    return body(request, params, payload)
                if isinstance(body, str):
                    return httpx.Response(status, text=body)
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"status": "error", "http_status": 404, "error": -3})

    def writes(self):
        return [s for s in self.sent if s[0] != "GET"]


def use(fake: Fake, **flags: str) -> None:
    env = {"FORTIGATE_BASE_URL": "https://192.0.2.1", "FORTIGATE_API_TOKEN": "tok",
           "FORTIGATE_ALLOW_WRITE": "true", "FORTIGATE_CONFIRM_WRITE": "false", **flags}
    client = server.FortiClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    server._client = client


@pytest.fixture(autouse=True)
def _reset():
    yield
    server._client = None


def run(coro):
    return asyncio.run(coro)


NEW_WRITE = {"add_object", "update_object", "delete_object", "create_policy", "move_policy", "ban_ips",
             "unban_ips", "deauth_users"}
NEW_READ = {"list_kinds", "list_objects", "get_object", "policy_lookup", "route_lookup", "live_table",
            "list_sessions", "search_logs", "config_backup"}


def test_switches_default_off_and_tools_registered():
    base = {"FORTIGATE_BASE_URL": "https://x", "FORTIGATE_API_TOKEN": "t"}
    s = Settings.from_env(base)
    assert s.allow_delete is False and s.allow_user_actions is False
    assert Settings.from_env({**base, "FORTIGATE_ALLOW_DELETE": "true"}).allow_delete is True
    assert Settings.from_env({**base, "FORTIGATE_ALLOW_USER_ACTIONS": "yes"}).allow_user_actions is True
    tools = {t.name: t for t in run(server.mcp.list_tools())}
    assert NEW_WRITE | NEW_READ <= set(tools)
    for name in NEW_WRITE:
        assert "confirm" in tools[name].input_schema["properties"], name
    assert "zone" in json.dumps(tools["delete_object"].input_schema)


def test_list_services_uses_the_dotted_cmdb_path():
    fake = Fake().on("GET", r"/cmdb/firewall\.service/(custom|group)$", env_ok([{"name": "HTTPS", "tcp-portrange": "443"}]))
    use(fake)
    run(server.list_services())
    run(server.list_services(groups=True))
    assert [s[1] for s in fake.sent] == [f"{API}/cmdb/firewall.service/custom", f"{API}/cmdb/firewall.service/group"]


def test_delete_object_needs_its_switch_and_always_confirms():
    fake = (Fake().on("GET", r"/cmdb/firewall/address/old%20srv$", env_ok([{"name": "old srv", "subnet": "10.0.0.9 255.255.255.255", "q_ref": 2}]))
            .on("DELETE", r"/cmdb/firewall/address/old%20srv$", env_ok(mkey="old srv")))
    use(fake)
    with pytest.raises(ValueError, match="FORTIGATE_ALLOW_DELETE"):
        run(server.delete_object("address", "old srv"))
    use(fake, FORTIGATE_ALLOW_DELETE="true")  # FORTIGATE_CONFIRM_WRITE=false: deletes still ask
    preview = run(server.delete_object("address", "old srv"))
    assert preview["status"] == "confirmation_required" and preview["references"] == 2
    assert "referenced 2 time(s)" in preview["summary"]
    assert fake.writes() == []
    run(server.delete_object("address", "old srv", confirm=preview["confirm_code"]))
    assert fake.writes() == [("DELETE", f"{API}/cmdb/firewall/address/old%20srv", {"vdom": "root"}, None)]
    assert fake.sent[0][2]["with_meta"] == "1"
    gone = run(server.delete_object("address", "nope"))
    assert gone["deleted"] is False


def test_add_object_builds_tables_and_refuses_duplicates():
    fake = (Fake().on("GET", r"/cmdb/system/zone/dmz$", status=404, body={"status": "error", "http_status": 404})
            .on("GET", r"/cmdb/system/zone/lan$", env_ok([{"name": "lan"}]))
            .on("POST", r"/cmdb/system/zone$", env_ok(mkey="dmz")))
    use(fake)
    run(server.add_object("zone", {"name": "dmz", "interface": ["port3", "port4"], "intrazone": "deny"}))
    assert fake.writes()[0][3] == {"name": "dmz", "interface": [{"interface-name": "port3"}, {"interface-name": "port4"}],
                                   "intrazone": "deny"}
    with pytest.raises(ValueError, match="exists already"):
        run(server.add_object("zone", {"name": "lan"}))
    with pytest.raises(ValueError, match="key attribute 'name'"):
        run(server.add_object("ippool", {"startip": "192.0.2.10"}))


def test_update_object_shows_from_and_to_and_ties_the_code_to_the_current_value():
    state = {"comments": "old"}
    fake = (Fake().on("GET", r"/cmdb/firewall/policy/7$", lambda r, p, b: httpx.Response(200, json=env_ok([{"policyid": 7, **state}])))
            .on("PUT", r"/cmdb/firewall/policy/7$", env_ok(mkey=7)))
    use(fake, FORTIGATE_CONFIRM_WRITE="true")
    preview = run(server.update_object("policy", "7", {"comments": "new", "srcaddr": ["lan"]}))
    assert preview["change"]["diff"]["comments"] == {"from": "old", "to": "new"}
    state["comments"] = "changed meanwhile"
    again = run(server.update_object("policy", "7", {"comments": "new", "srcaddr": ["lan"]}, confirm=preview["confirm_code"]))
    assert again["status"] == "confirmation_required" and "did not match" in again["note"]
    run(server.update_object("policy", "7", {"comments": "new", "srcaddr": ["lan"]}, confirm=again["confirm_code"]))
    assert fake.writes()[0][3] == {"comments": "new", "srcaddr": [{"name": "lan"}]}
    with pytest.raises(ValueError, match="must be a number"):
        run(server.update_object("policy", "abc", {"comments": "x"}))


def test_create_policy_posts_then_moves_it():
    fake = (Fake().on("POST", r"/cmdb/firewall/policy$", env_ok(mkey=42))
            .on("PUT", r"/cmdb/firewall/policy/42$", env_ok(mkey=42)))
    use(fake)
    out = run(server.create_policy("web-in", ["wan1"], ["dmz"], ["all"], ["vip-web"], ["HTTPS"], before=3))
    assert out["policy"]["policyid"] == 42 and out["moved"] == {"action": "move", "before": 3}
    post, move = fake.writes()
    assert post[3]["srcintf"] == [{"name": "wan1"}] and post[3]["policyid"] == 0 and post[3]["nat"] == "disable"
    assert move[2] == {"action": "move", "before": "3", "vdom": "root"} and move[3] is None
    with pytest.raises(ValueError, match="exactly one"):
        run(server.move_policy(5))


def test_policy_lookup_and_route_lookup_send_the_documented_params():
    fake = (Fake().on("GET", r"/monitor/firewall/policy-lookup$", env_ok({"success": True, "policy_id": 12}))
            .on("GET", r"/monitor/router/lookup$", env_ok({"interface": "wan1", "gateway": "198.51.100.1"})))
    use(fake)
    out = run(server.policy_lookup("port1", "10.0.0.5", "203.0.113.10", dest_port=443))
    assert out["result"]["policy_id"] == 12
    assert fake.sent[0][2] == {"srcintf": "port1", "sourceip": "10.0.0.5", "dest": "203.0.113.10", "protocol": "tcp",
                               "destport": "443", "vdom": "root"}
    assert run(server.route_lookup("203.0.113.10"))["result"]["interface"] == "wan1"


def test_live_table_flattens_named_results_and_masks_secrets():
    fake = Fake().on("GET", r"/monitor/virtual-wan/health-check$", env_ok({"ping-isp": {"wan1": {"status": "up"}}}))
    use(fake)
    out = run(server.live_table("sdwan_health"))
    assert out["results"] == [{"name": "ping-isp", "wan1": {"status": "up"}}]
    fake.on("GET", r"/cmdb/vpn\.ipsec/phase1-interface/hq$", env_ok([{"name": "hq", "psksecret": "ENC abc", "remote-gw": "198.51.100.7"}]))
    obj = run(server.get_object("ipsec_phase1", "hq"))
    assert obj["psksecret"] == "<masked>" and obj["remote-gw"] == "198.51.100.7"


CONFIG = """config system global
    set hostname "fgt-lab"
end
config firewall address
    edit "srv"
        set subnet 10.0.0.10 255.255.255.255
    next
end
config user local
    edit "svc"
        set passwd ENC SGVsbG8gV29ybGQ=
    next
end
config vpn certificate local
    edit "cert"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIabc
-----END ENCRYPTED PRIVATE KEY-----"
    next
end
"""


def test_config_backup_masks_secrets_and_cuts_a_section():
    fake = Fake().on("GET", r"/monitor/system/config/backup$", CONFIG)
    use(fake)
    whole = run(server.config_backup())["config"]
    assert "SGVsbG8" not in whole and "ENC <masked>" in whole
    assert "MIIabc" not in whole and "<private key masked>" in whole
    part = run(server.config_backup(section="firewall address"))["config"]
    assert part.startswith("config firewall address") and part.endswith("end") and "hostname" not in part
    assert fake.sent[0][2]["scope"] == "global"
    with pytest.raises(ValueError, match="No top-level"):
        run(server.config_backup(section="router bgp"))


def test_search_logs_and_sessions():
    fake = (Fake().on("GET", r"/log/disk/traffic/forward$", env_ok([{"srcip": "10.0.0.5", "action": "deny"}], total_lines=1))
            .on("GET", r"/monitor/firewall/session$", env_ok({"details": [{"saddr": "10.0.0.5", "dport": 443, "x": 1}], "total": 9})))
    use(fake)
    logs = run(server.search_logs(filter="srcip==10.0.0.5", rows=10))
    assert logs["path"] == "disk/traffic/forward" and logs["count"] == 1
    assert fake.sent[0][2] == {"rows": "10", "filter": "srcip==10.0.0.5", "vdom": "root"}
    sessions = run(server.list_sessions(source="10.0.0.5", count=5))
    assert sessions["total"] == 9 and sessions["results"][0]["saddr"] == "10.0.0.5" and "x" not in sessions["results"][0]


def test_ban_ips_needs_the_user_actions_switch():
    fake = Fake().on("POST", r"/monitor/user/banned/(add_users|clear_all)$", env_ok())
    use(fake)
    with pytest.raises(ValueError, match="FORTIGATE_ALLOW_USER_ACTIONS"):
        run(server.ban_ips(["203.0.113.66"]))
    use(fake, FORTIGATE_ALLOW_USER_ACTIONS="true")
    with pytest.raises(ValueError, match="Not an IP"):
        run(server.ban_ips(["nope"]))
    run(server.ban_ips(["203.0.113.66", "203.0.113.66"], expiry_seconds=3600))
    run(server.unban_ips(all=True))
    assert [(w[1], w[3]) for w in fake.writes()] == [
        (f"{API}/monitor/user/banned/add_users", {"ip_addresses": ["203.0.113.66"], "expiry": 3600}),
        (f"{API}/monitor/user/banned/clear_all", {}),
    ]
