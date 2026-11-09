"""A stateful fake NITRO appliance for the WAF / Bot flow tests (httpx.MockTransport) — no network.

It follows the NetScaler 14.1 NITRO reference: profiles and policies are added with POST, bindings with
PUT and removed with DELETE ?args=, read-only attributes are rejected, duplicate bindings answer with the
AppFw / Bot per-check codes, booleans are lowercase on the wire, and ``args=`` is parsed SDK-style (split
on literal ',' and ':' first, then percent-decode each value).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

import httpx

STATIC = r"^https?://[^/]+/static/.*$"
TEST_HOST = "app.test.corp"

# What a NITRO DELETE needs to identify one binding (AppFw adds ruletype, bot a boolean selector).
BINDING_IDENTITY = {
    "appfwprofile_starturl_binding": ("starturl", "ruletype"),
    "appfwprofile_denyurl_binding": ("denyurl", "ruletype"),
    "appfwprofile_sqlinjection_binding": (
        "sqlinjection", "formactionurl_sql", "as_scan_location_sql", "as_value_type_sql",
        "as_value_expr_sql", "ruletype",
    ),
    "botprofile_whitelist_binding": ("bot_whitelist", "bot_whitelist_value"),
    "botprofile_blacklist_binding": ("bot_blacklist", "bot_blacklist_value"),
    "botprofile_ratelimit_binding": (
        "bot_ratelimit", "bot_rate_limit_type", "bot_rate_limit_url", "cookiename", "countrycode", "condition",
    ),
    "botprofile_tps_binding": ("bot_tps", "bot_tps_type"),
    "botprofile_captcha_binding": ("captcharesource", "bot_captcha_url"),
    "botprofile_ipreputation_binding": ("bot_ipreputation", "category"),
    "botprofile_trapinsertionurl_binding": ("trapinsertionurl", "bot_trap_url"),
}
EXISTS_CODE = {
    "appfwprofile_starturl_binding": 3121,
    "appfwprofile_denyurl_binding": 3123,
    "appfwprofile_sqlinjection_binding": 3131,
}
PROFILE_READ_ONLY = {
    "appfwprofile": {"state", "learning", "csrftag", "builtin", "feature", "_nextgenapiresource", "__count", "defaults"},
    "botprofile": {"builtin", "feature", "_nextgenapiresource", "__count"},
}
BINDING_READ_ONLY = {"alertonly", "resourceid", "__count", "_nextgenapiresource"}
LEARNED_FIELD = {
    "starturl": "url", "sqlinjection": "name", "formactionurl_sql": "url",
    "as_value_type_sql": "value_type", "as_value_expr_sql": "value",
}

APPFW_STATS = {
    "appfirewallrequests": "1500", "appfirewallresponses": "1480", "appfirewallrequestsrate": "9",
    "appfirewalltotalviol": "7", "appfirewalltotallog": "7", "appfirewallaborts": "0",
    "appfirewallviolstarturl": "5", "appfirewalllogstarturl": "5",
    "appfirewallviolsql": "2", "appfirewalllogsql": "2", "appfirewallviolxss": "0",
    "appfirewallviolxdosviolations": "1", "appfirewallsignaturelogs": "3",
    "appfirewallcfgstarturlclosure": "1", "appfirewalldhtcursess": "4",
}
BOT_STATS = {
    "botrequests": "900", "botrequestsrate": "3", "bottotaldrop": "4", "bottotallog": "16",
    "botviolblacklist": "4", "botviolblacklistdrop": "4",
    "botviolratelimit": "2", "botviolratelimitlog": "2",
    "botviolwhitelist": "10", "botviolwhitelistlog": "10",
    "botvioldevicefingerprint": "0", "botcfgblacklist": "1", "botcfgwhitelist": "1",
}
AUDIT_MESSAGES = [
    "10/06/2026:12:00:01 GMT ns 0-PPE-0 : default APPFW APPFW_STARTURL 1001 0 : 10.1.2.3 11-PPE0 - "
    f"pr_app https://{TEST_HOST}/admin Disallow Illegal URL: /admin <blocked>",
    "10/06/2026:12:00:02 GMT ns 0-PPE-0 : default APPFW APPFW_SQL 1002 0 : 10.1.2.4 12-PPE0 - "
    f"pr_app https://{TEST_HOST}/search SQL Keyword check failed <not blocked>",
    "10/06/2026:12:00:03 GMT ns 0-PPE-0 : default BOT BOT_BLACKLIST 1003 0 : 10.9.9.9 13-PPE0 - "
    "bot_app /login Blacklist binding matched <blocked>",
    "10/06/2026:12:00:04 GMT ns 0-PPE-0 : default SSLVPN LOGIN 1004 0 : someone logged in",
]

# Load balancing / content switching: resource -> key attribute, binding -> (parent, parent attr, identity).
LB_OBJECTS = {
    "lbvserver": "name", "csvserver": "name", "service": "name", "servicegroup": "servicegroupname",
    "server": "name", "cspolicy": "policyname", "csaction": "name", "lbmonitor": "monitorname",
    "sslcertkey": "certkey", "sslvserver": "vservername", "sslservice": "servicename",
    "sslservicegroup": "servicegroupname", "sslprofile": "name", "sslpolicy": "name", "sslaction": "name",
    "rewritepolicy": "name", "rewriteaction": "name", "rewritepolicylabel": "labelname",
    "responderpolicy": "name", "responderaction": "name", "responderpolicylabel": "labelname",
    "responderhtmlpage": "name", "policypatset": "name", "policydataset": "name", "policystringmap": "name",
    "policyexpression": "name", "gslbvserver": "name", "gslbservice": "servicename", "gslbsite": "sitename",
    "dnsaddrec": "hostname", "dnscnamerec": "aliasname", "dnstxtrec": "domain", "dnsnsrec": "domain",
    "dnssoarec": "domain", "dnsaaaarec": "hostname",
}
# Record types that keep several records under one name: resource -> attribute telling them apart.
LB_MULTI = {"dnsaddrec": "ipaddress", "dnsaaaarec": "ipv6address", "dnstxtrec": "recordid", "dnsnsrec": "nameserver"}
LB_BINDINGS = {
    "lbvserver_service_binding": ("lbvserver", "name", ("servicename",)),
    "lbvserver_servicegroup_binding": ("lbvserver", "name", ("servicegroupname",)),
    "servicegroup_servicegroupmember_binding": ("servicegroup", "servicegroupname", ("servername", "port")),
    "service_lbmonitor_binding": ("service", "name", ("monitor_name",)),
    "servicegroup_lbmonitor_binding": ("servicegroup", "servicegroupname", ("monitor_name",)),
    "csvserver_cspolicy_binding": ("csvserver", "name", ("policyname",)),
    "csvserver_lbvserver_binding": ("csvserver", "name", ("lbvserver",)),
    "lbvserver_rewritepolicy_binding": ("lbvserver", "name", ("policyname",)),
    "lbvserver_responderpolicy_binding": ("lbvserver", "name", ("policyname",)),
    "lbvserver_analyticsprofile_binding": ("lbvserver", "name", ("analyticsprofile",)),
    "csvserver_responderpolicy_binding": ("csvserver", "name", ("policyname",)),
    "sslvserver_sslcertkey_binding": ("sslvserver", "vservername", ("certkeyname", "snicert")),
    "sslservicegroup_sslcertkey_binding": ("sslservicegroup", "servicegroupname", ("certkeyname", "snicert")),
    "sslvserver_sslpolicy_binding": ("sslvserver", "vservername", ("policyname",)),
    "sslprofile_sslcipher_binding": ("sslprofile", "name", ("ciphername",)),
    "rewriteglobal_rewritepolicy_binding": (None, None, ("policyname",)),
    "policypatset_pattern_binding": ("policypatset", "name", ("String",)),
    "policydataset_value_binding": ("policydataset", "name", ("value",)),
    "policystringmap_pattern_binding": ("policystringmap", "name", ("key",)),
    "gslbvserver_gslbservice_binding": ("gslbvserver", "name", ("servicename",)),
}
# Where enable/disable shows: (attribute, enabled value, disabled value).
LB_STATE = {
    "lbvserver": ("curstate", "UP", "OUT OF SERVICE"), "csvserver": ("curstate", "UP", "OUT OF SERVICE"),
    "service": ("svrstate", "UP", "OUT OF SERVICE"), "servicegroup": ("state", "ENABLED", "DISABLED"),
    "server": ("state", "ENABLED", "DISABLED"), "gslbvserver": ("curstate", "UP", "OUT OF SERVICE"),
}
LB_NOT_SETTABLE = {"servicetype"}


def as_arg(value: Any) -> str:
    """Render a stored value the way it arrives in a NITRO ``args=`` pair."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def reply(status: int = 200, errorcode: int = 0, message: str = "Done", **payload: Any) -> httpx.Response:
    return httpx.Response(status, json={"errorcode": errorcode, "message": message, **payload})


def per_profile(stats: dict[str, str]) -> dict[str, str]:
    """The per-profile twin of a global counter set (traffic gets 'perprofile', the rest 'profile')."""
    out = {}
    for key, value in stats.items():
        if key.endswith("rate"):
            out[key] = value
        elif "viol" in key or key.startswith(("appfirewallcfg", "botcfg")):
            out[key + "profile"] = value
        else:
            out[key + "perprofile"] = value
    return out


class FakeNetScaler:
    """Just enough of the NITRO appfw/bot API, with state, to drive every WAF and Bot tool."""

    def __init__(self) -> None:
        self.seq = 0
        self.saved = False
        self.writes: list[tuple[str, str, str | None, dict[str, str], Any]] = []
        self.signature_updates: list[tuple[str, Any]] = []
        self.profiles = {"pr_app": self.profile(
            "appfwprofile", "pr_app", learning="ON", starturlaction=["learn", "log", "stats"],
            sqlinjectionaction=["learn", "log", "stats"], errorurl=f"https://{TEST_HOST}/error.html",
        )}
        self.bot_profiles = {"bot_app": self.profile("botprofile", "bot_app", bot_enable_black_list="ON")}
        self.learning_settings = {"pr_app": {"profilename": "pr_app", "starturlminthreshold": 5}}
        self.bindings: dict[str, dict[str, list[dict[str, Any]]]] = {
            "pr_app": {
                "appfwprofile_starturl_binding": [
                    self.row("pr_app", "appfwprofile_starturl_binding", {"starturl": rf"^https://app\.test\.corp/app/.*$"}),
                    self.row("pr_app", "appfwprofile_starturl_binding", {"starturl": STATIC}),
                ],
                "appfwprofile_sqlinjection_binding": [self.row(
                    "pr_app", "appfwprofile_sqlinjection_binding",
                    {"sqlinjection": "q", "formactionurl_sql": rf"^https://app\.test\.corp/search$", "isregex_sql": "NOTREGEX"},
                )],
                "appfwprofile_logexpression_binding": [{"name": "pr_app", "logexpression": "le1"}],
            },
            "bot_app": {
                "botprofile_blacklist_binding": [self.row("bot_app", "botprofile_blacklist_binding", {
                    "bot_blacklist": True, "bot_blacklist_type": "IPv4", "bot_blacklist_value": "10.9.9.9",
                    "bot_blacklist_action": ["DROP"], "bot_blacklist_enabled": "ON",
                })],
                "botprofile_ratelimit_binding": [self.row("bot_app", "botprofile_ratelimit_binding", {
                    "bot_ratelimit": True, "bot_rate_limit_type": "URL", "bot_rate_limit_url": "/login",
                    "rate": 100, "timeslice": 1000, "bot_rate_limit_action": ["LOG"], "bot_rate_limit_enabled": "ON",
                })],
            },
        }
        self.learned = {"pr_app": {
            "startURL": [
                {"url": rf"^https://app\.test\.corp/app/a\.php$", "hits": "12"},
                {"url": rf"^https://app\.test\.corp/portal/b\.php$", "hits": "30"},
                {"url": rf"^https://app\.test\.corp/portal/c,d\.php$", "hits": "2"},
                {"url": rf"^https://app\.test\.corp/wp-login\.php$", "hits": "1"},
            ],
            "SQLInjection": [{"name": "comment", "url": rf"^https://app\.test\.corp/post$",
                              "value_type": "SpecialString", "value": "'", "hits": "4"}],
        }}
        self.policies = {
            "appfwpolicy": [
                {"name": "pol_app", "rule": "true", "profilename": "pr_app", "hits": "42", "undefhits": "0"},
                {"name": "pol_spare", "rule": "true", "profilename": "pr_app", "hits": "0"},
            ],
            "botpolicy": [{"name": "bpol_app", "rule": "true", "profilename": "bot_app", "hits": "7"}],
        }
        self.policy_bindings = {
            "pol_app": {"appfwpolicy_lbvserver_binding": [
                {"name": "pol_app", "boundto": "vs_app", "priority": "100", "activepolicy": 1}
            ]},
            "pol_spare": {},
            "bpol_app": {"botpolicy_csvserver_binding": [
                {"name": "bpol_app", "boundto": "cs_app", "priority": "110", "activepolicy": 1}
            ]},
        }
        self.signatures = {
            "appfwsignatures": [{"name": "sig_default", "src": "https://sig.example/waf.xml", "encryptedversion": 97}],
            "botsignature": [{"name": "bot_sig", "src": "https://sig.example/bot.json", "comment": ""}],
        }
        self.lb = {
            "lbvserver": {
                "vs_web": {"name": "vs_web", "servicetype": "HTTP", "ipv46": "10.0.0.20", "port": 80,
                           "lbmethod": "ROUNDROBIN", "persistencetype": "NONE", "curstate": "UP"},
                "vs_api": {"name": "vs_api", "servicetype": "HTTP", "ipv46": "0.0.0.0", "port": 0,
                           "lbmethod": "LEASTCONNECTION", "curstate": "UP"},
            },
            "csvserver": {"cs_app": {"name": "cs_app", "servicetype": "HTTP", "ipv46": "10.0.0.10", "port": 80,
                                     "curstate": "UP"}},
            "service": {"svc_web1": {"name": "svc_web1", "servername": "srv_web1", "ipaddress": "10.0.0.31",
                                     "port": 80, "servicetype": "HTTP", "svrstate": "UP"}},
            "servicegroup": {"sg_web": {"servicegroupname": "sg_web", "servicetype": "HTTP", "state": "ENABLED"}},
            "server": {
                "srv_web1": {"name": "srv_web1", "ipaddress": "10.0.0.31", "state": "ENABLED"},
                "srv_web2": {"name": "srv_web2", "ipaddress": "10.0.0.32", "state": "ENABLED"},
            },
            "cspolicy": {
                "cp_api": {"policyname": "cp_api", "rule": 'HTTP.REQ.URL.STARTSWITH("/api")', "action": "ca_api",
                           "hits": "12"},
                "cp_static": {"policyname": "cp_static", "rule": 'HTTP.REQ.URL.STARTSWITH("/static")',
                              "action": "ca_web"},
            },
            "csaction": {
                "ca_api": {"name": "ca_api", "targetlbvserver": "vs_api"},
                "ca_web": {"name": "ca_web", "targetlbvserver": "vs_web"},
            },
            "lbmonitor": {
                "mon_http": {"monitorname": "mon_http", "type": "HTTP", "interval": 5, "respcode": ["200"]},
                "mon_https": {"monitorname": "mon_https", "type": "HTTP", "secure": "YES", "respcode": ["200"]},
            },
        }
        tmpl = "tmpl.example.com"
        self.lb["csvserver"]["cs_ssl"] = {"name": "cs_ssl", "servicetype": "SSL", "ipv46": "10.0.0.11", "port": 443,
                                          "curstate": "UP"}
        self.lb["lbvserver"][f"lb_{tmpl}"] = {
            "name": f"lb_{tmpl}", "servicetype": "HTTP", "ipv46": "0.0.0.0", "port": 0, "lbmethod": "LEASTCONNECTION",
            "persistencetype": "NONE", "curstate": "UP", "effectivestate": "UP", "clttimeout": 180}
        self.lb["servicegroup"][f"svg_{tmpl}"] = {"servicegroupname": f"svg_{tmpl}", "servicetype": "SSL",
                                                  "state": "ENABLED", "usip": "NO", "cip": "ENABLED",
                                                  "cipheader": "X-Forwarded-For"}
        self.lb["cspolicy"][f"cp_{tmpl}"] = {"policyname": f"cp_{tmpl}", "rule": f'HTTP.REQ.HOSTNAME.EQ("{tmpl}")',
                                             "action": f"ca_{tmpl}"}
        self.lb["csaction"][f"ca_{tmpl}"] = {"name": f"ca_{tmpl}", "targetlbvserver": f"lb_{tmpl}"}
        self.lb.update({
            "sslcertkey": {
                "cert_wild": {"certkey": "cert_wild", "cert": "wild.pem", "key": "wild.key", "inform": "PEM",
                              "status": "Valid", "daystoexpiration": "31"},
                "ca_root": {"certkey": "ca_root", "cert": "root.pem", "inform": "PEM", "status": "Valid"},
            },
            "sslvserver": {"cs_ssl": {"vservername": "cs_ssl", "sslprofile": "ns_default_ssl_profile_frontend"}},
            "sslservice": {},
            "sslservicegroup": {f"svg_{tmpl}": {"servicegroupname": f"svg_{tmpl}", "sslprofile": "prof_backend"}},
            "sslprofile": {"prof_backend": {"name": "prof_backend", "sslprofiletype": "BackEnd", "tls12": "ENABLED",
                                            "tls13": "DISABLED"}},
            "sslpolicy": {}, "sslaction": {},
            "rewritepolicy": {"rw_404": {"name": "rw_404", "rule": "HTTP.RES.STATUS.EQ(404)", "action": "rwa_404"}},
            "rewriteaction": {}, "rewritepolicylabel": {}, "responderpolicy": {}, "responderaction": {},
            "responderpolicylabel": {}, "responderhtmlpage": {},
            "policypatset": {"ps_internal": {"name": "ps_internal"}, "ps_other": {"name": "ps_other"}},
            "policydataset": {"ds_nets": {"name": "ds_nets", "type": "ipv4"}},
            "policystringmap": {}, "policyexpression": {
                "ex_lan": {"name": "ex_lan", "value": 'CLIENT.IP.SRC.IN_SUBNET(10.0.0.0/8) || "internal"'}},
            "gslbvserver": {}, "gslbservice": {},
            "gslbsite": {"site_a": {"sitename": "site_a", "sitetype": "LOCAL", "siteipaddress": "10.0.1.1"},
                         "site_b": {"sitename": "site_b", "sitetype": "REMOTE", "siteipaddress": "10.0.2.1"}},
            "dnsaddrec": {"app.example.com": [
                {"hostname": "app.example.com", "ipaddress": "10.0.0.50", "ttl": 300},
                {"hostname": "app.example.com", "ipaddress": "10.0.0.51", "ttl": 300}]},
            "dnsaaaarec": {}, "dnscnamerec": {}, "dnstxtrec": {}, "dnsnsrec": {}, "dnssoarec": {},
        })
        self.files: dict[str, bytes] = {}
        self.actions: list[tuple[str, str, dict[str, Any]]] = []
        self.lb_stats = {
            "lbvserver": {f"lb_{tmpl}": {"name": f"lb_{tmpl}", "state": "UP", "vslbhealth": "100", "totalrequests": "120"}},
            "csvserver": {"cs_ssl": {"name": "cs_ssl", "state": "UP", "totalrequests": "130"}},
            "servicegroup": {f"svg_{tmpl}": {"servicegroupname": f"svg_{tmpl}", "servicegroupmember": [
                {"servername": "10.0.0.61", "primaryipaddress": "10.0.0.61", "primaryport": 443, "state": "UP",
                 "totalrequests": "0", "svrestablishedconn": "0"}]}},
        }
        self.lb_bindings: dict[str, dict[str, list[dict[str, Any]]]] = {
            "lbvserver_servicegroup_binding": {"vs_web": [
                {"name": "vs_web", "servicegroupname": "sg_web", "stateflag": "1"}]},
            "lbvserver_service_binding": {"vs_api": [
                {"name": "vs_api", "servicename": "svc_web1", "weight": "1", "curstate": "UP"}]},
            "servicegroup_servicegroupmember_binding": {"sg_web": [
                {"servicegroupname": "sg_web", "servername": "srv_web1", "ip": "10.0.0.31", "port": 80,
                 "weight": "1", "state": "ENABLED", "svrstate": "UP"},
                {"servicegroupname": "sg_web", "servername": "srv_web2", "ip": "10.0.0.32", "port": 80,
                 "weight": "1", "state": "ENABLED", "svrstate": "UP"},
            ]},
            "servicegroup_lbmonitor_binding": {"sg_web": [
                {"servicegroupname": "sg_web", "monitor_name": "mon_http", "weight": "1"}]},
            "csvserver_cspolicy_binding": {"cs_app": [
                {"name": "cs_app", "policyname": "cp_static", "priority": "200", "gotopriorityexpression": "END",
                 "hits": "3"},
                {"name": "cs_app", "policyname": "cp_api", "priority": "100", "gotopriorityexpression": "END",
                 "hits": "12"},
            ]},
            "csvserver_lbvserver_binding": {"cs_app": [{"name": "cs_app", "lbvserver": "vs_web"}]},
        }
        self.lb_bindings["csvserver_cspolicy_binding"]["cs_ssl"] = [
            {"name": "cs_ssl", "policyname": f"cp_{tmpl}", "priority": "300", "gotopriorityexpression": "END"},
            {"name": "cs_ssl", "policyname": "cp_api", "priority": "301", "gotopriorityexpression": "END"},
        ]
        self.lb_bindings["lbvserver_servicegroup_binding"][f"lb_{tmpl}"] = [
            {"name": f"lb_{tmpl}", "servicegroupname": f"svg_{tmpl}"}]
        self.lb_bindings["servicegroup_servicegroupmember_binding"][f"svg_{tmpl}"] = [
            {"servicegroupname": f"svg_{tmpl}", "servername": "10.0.0.61", "ip": "10.0.0.61", "port": 443,
             "state": "ENABLED", "svrstate": "UP"}]
        self.lb_bindings["servicegroup_lbmonitor_binding"][f"svg_{tmpl}"] = [
            {"servicegroupname": f"svg_{tmpl}", "monitor_name": "mon_https"}]
        self.lb_bindings.update({
            "lbvserver_rewritepolicy_binding": {f"lb_{tmpl}": [
                {"name": f"lb_{tmpl}", "policyname": "rw_404", "priority": "100", "bindpoint": "RESPONSE",
                 "gotopriorityexpression": "NEXT", "hits": "4"},
                {"name": f"lb_{tmpl}", "policyname": "rw_500", "priority": "110", "bindpoint": "RESPONSE",
                 "gotopriorityexpression": "END"}]},
            "lbvserver_responderpolicy_binding": {f"lb_{tmpl}": [
                {"name": f"lb_{tmpl}", "policyname": "log_req", "priority": "100", "bindpoint": "REQUEST",
                 "gotopriorityexpression": "NEXT"}]},
            "lbvserver_analyticsprofile_binding": {f"lb_{tmpl}": [{"name": f"lb_{tmpl}", "analyticsprofile": "ana_web"}]},
            "sslvserver_sslcertkey_binding": {"cs_ssl": [{"vservername": "cs_ssl", "certkeyname": "cert_wild"}]},
            "sslprofile_sslcipher_binding": {"prof_backend": [
                {"name": "prof_backend", "ciphername": "DEFAULT_BACKEND", "cipherpriority": "1"}]},
            "rewriteglobal_rewritepolicy_binding": {"": [
                {"policyname": "rw_404", "priority": "500", "type": "RES_DEFAULT", "gotopriorityexpression": "END"}]},
            "policypatset_pattern_binding": {"ps_internal": [
                {"name": "ps_internal", "String": "internal", "index": "1"},
                {"name": "ps_internal", "String": "intranet", "index": "2"}],
                "ps_other": [{"name": "ps_other", "String": "corp-internal-app", "index": "1"}]},
            "policydataset_value_binding": {"ds_nets": [{"name": "ds_nets", "value": "10.0.0.0/8", "index": "1"}]},
        })
        self.settings = {
            "appfwsettings": {"signatureautoupdate": "OFF", "signatureurl": "https://sig.example/waf.xml",
                              "learning": "ON", "sessiontimeout": 900, "builtin": ["MODIFIABLE"]},
            "botsettings": {"signatureautoupdate": "ON", "signatureurl": "https://sig.example/bot.json",
                            "defaultprofile": "BOT_BYPASS", "sessiontimeout": 900},
        }

    # ---- seed helpers

    @staticmethod
    def profile(resource: str, name: str, **attrs: Any) -> dict[str, Any]:
        if resource == "appfwprofile":
            base = {"name": name, "state": "ENABLED", "learning": "OFF", "builtin": ["MODIFIABLE"],
                    "type": ["HTML"], "starturlaction": ["none"], "sqlinjectionaction": ["none"],
                    "denyurlaction": ["none"]}
        else:
            base = {"name": name, "builtin": ["MODIFIABLE"], "bot_enable_white_list": "OFF",
                    "bot_enable_black_list": "OFF", "bot_enable_rate_limit": "OFF", "bot_enable_tps": "OFF",
                    "bot_enable_ip_reputation": "OFF", "devicefingerprint": "OFF",
                    "devicefingerprintaction": ["NONE"], "trap": "OFF", "trapaction": ["NONE"],
                    "kmdetection": "OFF", "headlessbrowserdetection": "OFF",
                    "signaturenouseragentheaderaction": ["DROP"], "spoofedreqaction": ["LOG", "DROP"]}
        return {**base, **attrs}

    def row(self, profile: str, binding: str, attrs: dict[str, Any]) -> dict[str, Any]:
        """A binding as the appliance stores it: defaults filled in, a resourceid for AppFw bindings."""
        self.seq += 1
        row = {"name": profile, **attrs}
        if binding.startswith("appfwprofile_"):
            row.setdefault("state", "ENABLED")
            row.setdefault("ruletype", "ALLOW")
            row.setdefault("alertonly", "OFF")
            row["resourceid"] = f"res{self.seq}"
            if binding == "appfwprofile_sqlinjection_binding":
                row.setdefault("as_scan_location_sql", "FORMFIELD")
        return row

    def start_urls(self, profile: str) -> list[str]:
        return sorted(r["starturl"] for r in self.bindings[profile].get("appfwprofile_starturl_binding", []))

    def entries(self, profile: str, binding: str) -> list[dict[str, Any]]:
        return self.bindings.get(profile, {}).get(binding, [])

    def _profiles(self, resource: str) -> dict[str, dict[str, Any]]:
        return self.profiles if resource == "appfwprofile" else self.bot_profiles

    def _ident(self, binding: str, row: dict[str, Any]) -> tuple[str, ...]:
        return tuple(as_arg(row.get(a, "")) for a in BINDING_IDENTITY[binding])

    # ---- dispatch

    def __call__(self, request: httpx.Request) -> httpx.Response:
        target, _, query = request.url.raw_path.decode().partition("?")
        params = dict(p.partition("=")[::2] for p in query.split("&")) if query else {}
        args = {k: unquote(v) for k, _, v in (i.partition(":") for i in params.get("args", "").split(",") if i)}
        body = json.loads(request.content) if request.content else {}
        method = request.method
        if target.endswith("/config/login"):
            return httpx.Response(201, json={"errorcode": 0, "sessionid": "s1"})
        if "/nitro/v1/stat/" in target:
            resource, _, name = target.split("/nitro/v1/stat/", 1)[1].partition("/")
            return self._stat_api(resource, unquote(name) or args.get("name"))
        resource, _, name = target.split("/nitro/v1/config/", 1)[1].partition("/")
        name = unquote(name) or None
        if method != "GET":
            self.writes.append((method, resource, name, args, body))
        if resource == "nsconfig":
            self.saved = params.get("action") == "save"
            return reply()
        if resource == "systemfile":
            return self._file_api(method, args, body.get("systemfile") or {})
        if resource == "gslbconfig":
            self.actions.append(("gslbconfig", params.get("action"), body.get("gslbconfig") or {}))
            return reply()
        if resource in ("appfwprofile", "botprofile"):
            return self._profile_api(method, resource, name, body.get(resource) or {})
        if resource == "appfwlearningsettings":
            if method == "GET":
                return reply(appfwlearningsettings=[self.learning_settings[name]])
            self.learning_settings[body[resource]["profilename"]].update(body[resource])
            return reply()
        if resource == "appfwlearningdata":
            return self._learning_api(method, args)
        if resource in ("appfwprofile_binding", "botprofile_binding"):
            profiles = self._profiles(resource.removesuffix("_binding"))
            if name not in profiles:
                return reply(404, 3190, "No such profile.")
            return reply(**{resource: [{"name": name, **self.bindings.get(name, {})}]})
        if resource in ("appfwsignatures", "botsignature"):
            if params.get("action") == "update":
                self.signature_updates.append((resource, body.get(resource)))
                return reply()
            return reply(**{resource: self.signatures[resource]})
        if resource in ("appfwsettings", "botsettings"):
            return reply(**{resource: [self.settings[resource]]})
        if resource in ("appfwpolicy", "botpolicy"):
            return reply(**{resource: self.policies[resource]})
        if resource in ("appfwpolicy_binding", "botpolicy_binding"):
            return reply(**{resource: [{"name": name, **self.policy_bindings.get(name or "", {})}]})
        if resource == "auditmessages":
            count = int(args.get("numofmesgs") or 20)
            return reply(auditmessages=[{"value": line} for line in AUDIT_MESSAGES[:count]])
        if resource in LB_OBJECTS:
            return self._lb_object_api(method, resource, name, params.get("action"), body.get(resource) or {}, args)
        if resource in LB_BINDINGS or resource.removesuffix("_binding") in LB_OBJECTS:
            return self._lb_binding_api(method, resource, name, args, body.get(resource) or {})
        return self._binding_api(method, resource, name, args, body.get(resource) or {})

    def _stat_api(self, resource: str, name: str | None) -> httpx.Response:
        if resource == "appfw":
            return reply(appfw=[APPFW_STATS])
        if resource == "bot":
            return reply(bot=[BOT_STATS])
        if resource == "appfwprofile":
            return reply(appfwprofile=[{"name": name, **per_profile(APPFW_STATS)}])
        if resource == "botprofile":
            return reply(botprofile=[{"name": name, **per_profile(BOT_STATS)}])
        if resource in self.lb_stats:
            row = self.lb_stats[resource].get(name)
            return reply(**{resource: [row]}) if row else reply(**{resource: [{"name": name, "state": "UP"}]})
        return reply(404, 258, f"unhandled stat {resource}")

    def _profile_api(self, method: str, resource: str, name: str | None, obj: dict[str, Any]) -> httpx.Response:
        profiles = self._profiles(resource)
        if method == "GET":
            if name is None:
                return reply(**{resource: list(profiles.values())})
            return reply(**{resource: [profiles[name]]}) if name in profiles else reply(404, 258, "No such resource")
        bad = sorted(set(obj) & PROFILE_READ_ONLY[resource])
        if bad:
            return reply(400, 278, f"Invalid argument [{bad[0]}]")
        if method == "POST":
            profiles[obj["name"]] = self.profile(resource, **obj)
            self.bindings[obj["name"]] = {}
            if resource == "appfwprofile":
                self.learning_settings[obj["name"]] = {"profilename": obj["name"], "starturlminthreshold": 1}
            return reply(201)
        profiles[obj["name"]].update(obj)
        return reply()

    def _binding_api(
        self, method: str, binding: str, name: str | None, args: dict[str, str], obj: dict[str, Any]
    ) -> httpx.Response:
        profile = name or obj.get("name")
        family = "appfwprofile" if binding.startswith("appfwprofile_") else "botprofile"
        if profile not in self._profiles(family):
            return reply(404, 3190, "No such profile.")
        rows = self.bindings.setdefault(profile, {}).setdefault(binding, [])
        if method == "GET":
            return reply(**({binding: rows} if rows else {}))
        if method == "PUT":
            if set(obj) & BINDING_READ_ONLY:
                return reply(400, 278, "Invalid argument")
            new = self.row(profile, binding, {k: v for k, v in obj.items() if k != "name"})
            if any(self._ident(binding, r) == self._ident(binding, new) for r in rows):
                return reply(409, EXISTS_CODE.get(binding, 1703 if family == "botprofile" else 273), "already bound")
            rows.append(new)
            return reply(201)
        keep = [r for r in rows if not all(as_arg(r.get(k, "")) == v for k, v in args.items())]
        if len(keep) == len(rows):
            return reply(404, 3120, "No such rule")
        self.bindings[profile][binding] = keep
        return reply()

    def _learning_api(self, method: str, args: dict[str, str]) -> httpx.Response:
        checks = self.learned.get(args["profilename"], {})
        if method == "GET":
            return reply(appfwlearningdata=checks.get(args["securitycheck"], []))
        wanted = {LEARNED_FIELD[k]: v for k, v in args.items() if k != "profilename"}
        for check, rows in checks.items():
            keep = [r for r in rows if not all(str(r.get(k, "")) == v for k, v in wanted.items())]
            if len(keep) != len(rows):
                checks[check] = keep
                return reply()
        return reply(404, 258, "No such resource")

    # ---- load balancing / content switching

    def lb_rows(self, binding: str, parent: str) -> list[dict[str, Any]]:
        return self.lb_bindings.get(binding, {}).get(parent, [])

    def _lb_object_api(
        self, method: str, resource: str, name: str | None, action: str | None, obj: dict[str, Any],
        args: dict[str, str] | None = None,
    ) -> httpx.Response:
        store, key = self.lb[resource], LB_OBJECTS[resource]
        if resource in LB_MULTI:
            return self._records_api(method, resource, name, obj, args or {})
        if method == "GET":
            if name is None:
                return reply(**{resource: list(store.values())})
            return reply(**{resource: [store[name]]}) if name in store else reply(404, 258, "No such resource")
        if action in ("update", "link", "unlink", "Import"):
            self.actions.append((resource, action, dict(obj)))
            if action == "Import":
                store[obj[key]] = {k: v for k, v in obj.items() if k != "src"}
                return reply(201)
            if obj.get(key) not in store:
                return reply(404, 258, "No such resource")
            target = store[obj[key]]
            if action == "update":
                target.update({k: v for k, v in obj.items() if k not in ("password", "passplain")})
            elif action == "link":
                if obj.get("linkcertkeyname") not in store:
                    return reply(404, 1540, "Certificate does not exist")
                target["linkcertkeyname"] = obj["linkcertkeyname"]
            else:
                target.pop("linkcertkeyname", None)
            return reply()
        if method == "DELETE":
            if name not in store:
                return reply(404, 258, "No such resource")
            if resource == "lbmonitor" and (args or {}).get("type") != store[name]["type"]:
                return reply(400, 1092, "Required argument missing [type]")
            if self._lb_in_use(resource, name):
                return reply(409, 2083, "Cannot remove, the entity is in use")
            del store[name]
            for binding, (parent, _, _) in LB_BINDINGS.items():
                if parent == resource:
                    self.lb_bindings.get(binding, {}).pop(name, None)
            return reply()
        target = store.get(obj.get(key))
        if action in ("enable", "disable"):
            if target is None:
                return reply(404, 258, "No such resource")
            field, on, off = LB_STATE[resource]
            if obj.get("servername"):
                rows = self.lb_rows("servicegroup_servicegroupmember_binding", obj[key])
                row = next((r for r in rows if r["servername"] == obj["servername"]
                            and str(r["port"]) == str(obj["port"])), None)
                if row is None:
                    return reply(404, 258, "No such member")
                row["state"] = "ENABLED" if action == "enable" else "DISABLED"
            else:
                target[field] = on if action == "enable" else off
            return reply()
        if action == "unset":
            if target is None:
                return reply(404, 258, "No such resource")
            for attr, flag in obj.items():
                if flag is True:
                    target.pop(attr, None)
            return reply()
        if method == "POST":
            if target is not None:
                return reply(409, 273, "Resource already exists")
            new = dict(obj)
            if resource in LB_STATE:
                field, on, _ = LB_STATE[resource]
                new.setdefault(field, on)
            store[obj[key]] = new
            ssl_side = {"lbvserver": "sslvserver", "csvserver": "sslvserver", "service": "sslservice",
                        "servicegroup": "sslservicegroup"}.get(resource)
            if ssl_side and str(obj.get("servicetype", "")).upper().startswith("SSL"):
                side_key = LB_OBJECTS[ssl_side]
                self.lb[ssl_side][obj[key]] = {side_key: obj[key], "sslprofile": "ns_default_ssl_profile_backend"
                                               if ssl_side != "sslvserver" else "ns_default_ssl_profile_frontend"}
            return reply(201)
        if target is None:
            return reply(404, 258, "No such resource")
        if resource == "lbmonitor" and "type" not in obj:
            return reply(400, 1092, "Required argument missing [type]")
        if bad := sorted(set(obj) & LB_NOT_SETTABLE):
            return reply(400, 278, f"Invalid argument [{bad[0]}]")
        target.update(obj)
        return reply()

    def _lb_binding_api(
        self, method: str, binding: str, name: str | None, args: dict[str, str], obj: dict[str, Any]
    ) -> httpx.Response:
        if binding not in LB_BINDINGS:  # aggregate <resource>_binding/<name>
            parent = binding.removesuffix("_binding")
            if name not in self.lb[parent]:
                return reply(404, 258, "No such resource")
            arrays = {b: self.lb_rows(b, name) for b, (p, _, _) in LB_BINDINGS.items()
                      if p == parent and self.lb_rows(b, name)}
            return reply(**{binding: [{LB_OBJECTS[parent]: name, **arrays}]})
        parent, attr, ident = LB_BINDINGS[binding]
        owner = "" if parent is None else (name or obj.get(attr))
        if parent is not None and owner not in self.lb[parent]:
            return reply(404, 258, "No such resource")
        rows = self.lb_bindings.setdefault(binding, {}).setdefault(owner, [])
        if method == "GET":
            return reply(**({binding: rows} if rows else {}))
        if method == "PUT":
            new = dict(obj)
            if binding == "servicegroup_servicegroupmember_binding":
                new.setdefault("servername", new.get("ip"))
                new.setdefault("state", "ENABLED")
            key = tuple(as_arg(new.get(a, "")) for a in ident)
            if any(tuple(as_arg(r.get(a, "")) for a in ident) == key for r in rows):
                return reply(409, 273, "Resource already exists")
            rows.append(new)
            return reply(201)
        keep = [r for r in rows if not all(as_arg(r.get(k, "")) == v for k, v in args.items())]
        if len(keep) == len(rows):
            return reply(404, 258, "No such resource")
        self.lb_bindings[binding][owner] = keep
        return reply()

    def _lb_in_use(self, resource: str, name: str) -> bool:
        """Whether another object still refers to this one (the appliance refuses the delete then)."""
        if resource == "cspolicy":
            return any(r["policyname"] == name for rows in self.lb_bindings.get("csvserver_cspolicy_binding", {}).values()
                       for r in rows)
        if resource == "csaction":
            return any(p.get("action") == name for p in self.lb["cspolicy"].values())
        return False

    def _records_api(
        self, method: str, resource: str, name: str | None, obj: dict[str, Any], args: dict[str, str]
    ) -> httpx.Response:
        """DNS-style records: several under one name, told apart by LB_MULTI[resource]."""
        store, key, value = self.lb[resource], LB_OBJECTS[resource], LB_MULTI[resource]
        if method == "GET":
            if name is None:
                return reply(**{resource: [r for rows in store.values() for r in rows]})
            return reply(**{resource: store[name]}) if store.get(name) else reply(404, 258, "No such resource")
        if method == "POST":
            rows = store.setdefault(obj[key], [])
            if resource == "dnstxtrec":
                obj = {**obj, "recordid": len(rows) + 1}
            elif any(as_arg(r.get(value)) == as_arg(obj.get(value)) for r in rows):
                return reply(409, 273, "Resource already exists")
            rows.append(dict(obj))
            return reply(201)
        rows = store.get(name or "", [])
        keep = [r for r in rows if not all(as_arg(r.get(k, "")) == v for k, v in args.items())] if args else []
        if len(keep) == len(rows):
            return reply(404, 258, "No such resource")
        store[name] = keep
        return reply()

    def _file_api(self, method: str, args: dict[str, str], obj: dict[str, Any]) -> httpx.Response:
        """systemfile, limited to what the tools use: /nsconfig/ssl files as base64."""
        import base64

        if method == "GET":
            data = self.files.get(args.get("filename", ""))
            if data is None:
                return reply(404, 258, "No such resource")
            return reply(systemfile=[{"filename": args["filename"], "filelocation": args.get("filelocation"),
                                      "filecontent": base64.b64encode(data).decode()}])
        if method == "POST":
            if obj.get("filelocation") != "/nsconfig/ssl":
                return reply(400, 278, "Invalid argument [filelocation]")
            if obj["filename"] in self.files:
                return reply(409, 273, "File already exists")
            self.files[obj["filename"]] = base64.b64decode(obj["filecontent"])
            return reply(201)
        if args.get("filename") not in self.files:
            return reply(404, 258, "No such resource")
        del self.files[args["filename"]]
        return reply()
