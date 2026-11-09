"""Traffic-management objects for the generic config tools (no network, no MCP).

``KINDS`` maps the tool-facing kind names (``lb_vserver``, ``ssl_certkey``, ``rewrite_policy`` …) onto NITRO
resources: the key attribute, what an add needs, the trimmed view, how enable/disable is addressed and
which operations the resource supports. ``BINDINGS`` does the same for the bind/unbind relations
(vserver ← service, group ← member, vserver ← policy per feature, certificate ↔ vserver, global policy
bindings …). ``plan_bindings`` turns a requested add/remove list plus the live rows into ordered
bind/unbind steps. server.py only orchestrates the NITRO calls.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from .waf import settings_changes

# Attributes whose values are secrets: never shown in previews or results.
SECRET_ATTRS = frozenset({"passplain", "passcrypt", "password"})


@dataclass(frozen=True)
class Kind:
    """One configurable object type."""

    name: str  # tool-facing name, e.g. 'lb_vserver'
    resource: str  # NITRO resource type, e.g. 'lbvserver'
    key: str  # identifying attribute: name / servicegroupname / policyname / monitorname / certkey …
    fields: tuple[str, ...]  # trimmed view
    required: tuple[str, ...] = ()  # an add needs these besides the key
    one_of: tuple[str, ...] = ()  # … and exactly one of these
    ident_extra: tuple[str, ...] = ()  # attributes set/unset need besides the key (lbmonitor: type)
    state_field: str | None = None  # where GET shows the run/admin state; None = no enable/disable
    graceful: bool = False  # disable takes delay + graceful
    addable: bool = True  # False: exists implicitly (the SSL side of a vserver / service)
    updatable: bool = True
    deletable: bool = True
    add_action: str | None = None  # add is POST ?action=<this> instead of a plain POST (html page Import)
    update_action_attrs: frozenset[str] = frozenset()  # sent with POST ?action=update, always (cert reload)
    multi: tuple[str, ...] = ()  # several records share the key; these attributes tell them apart (DNS)
    delete_by: tuple[str, ...] = ()  # DELETE ?args= taken from the live object (monitor type, record values)

    @property
    def aggregate(self) -> str:
        return f"{self.resource}_binding"

    def can(self, operation: str) -> bool:
        return {"add": self.addable, "update": self.updatable, "delete": self.deletable}[operation]


_POLICY_FIELDS = ("name", "rule", "action", "undefaction", "hits", "comment")
_CERT_UPDATE = frozenset({"cert", "key", "password", "passplain", "inform", "nodomaincheck", "fipskey", "hsmkey"})

KINDS: dict[str, Kind] = {k.name: k for k in (
    # load balancing / content switching
    Kind("lb_vserver", "lbvserver", "name",
         ("name", "ipv46", "port", "servicetype", "curstate", "effectivestate", "lbmethod", "persistencetype",
          "timeout", "comment"),
         required=("servicetype",), state_field="curstate"),
    Kind("cs_vserver", "csvserver", "name",
         ("name", "ipv46", "port", "servicetype", "curstate", "targettype", "comment"),
         required=("servicetype",), state_field="curstate"),
    Kind("service", "service", "name",
         ("name", "servername", "ipaddress", "port", "servicetype", "svrstate", "comment"),
         required=("servicetype", "port"), one_of=("ip", "servername"), state_field="svrstate", graceful=True),
    Kind("service_group", "servicegroup", "servicegroupname",
         ("servicegroupname", "servicetype", "state", "servicegroupeffectivestate", "comment"),
         required=("servicetype",), state_field="state", graceful=True),
    Kind("server", "server", "name", ("name", "ipaddress", "domain", "state", "comment"),
         one_of=("ipaddress", "domain"), state_field="state", graceful=True),
    Kind("cs_policy", "cspolicy", "policyname", ("policyname", "rule", "action", "logaction", "hits"),
         required=("rule",)),
    Kind("cs_action", "csaction", "name",
         ("name", "targetlbvserver", "targetvserver", "targetvserverexpr", "hits", "referencecount", "comment"),
         one_of=("targetlbvserver", "targetvserver", "targetvserverexpr")),
    Kind("monitor", "lbmonitor", "monitorname",
         ("monitorname", "type", "interval", "resptimeout", "retries", "destport", "httprequest", "respcode",
          "send", "recv", "secure", "state"),
         required=("type",), ident_extra=("type",), delete_by=("type",)),
    # SSL
    Kind("ssl_certkey", "sslcertkey", "certkey",
         ("certkey", "cert", "key", "inform", "status", "daystoexpiration", "subject", "issuer",
          "clientcertnotafter", "expirymonitor", "notificationperiod", "linkcertkeyname"),
         required=("cert",), update_action_attrs=_CERT_UPDATE),
    Kind("ssl_vserver", "sslvserver", "vservername",
         ("vservername", "sslprofile", "snienable", "clientauth", "ssl3", "tls1", "tls11", "tls12", "tls13"),
         addable=False, deletable=False),
    Kind("ssl_service", "sslservice", "servicename",
         ("servicename", "sslprofile", "snienable", "serverauth", "commonname", "tls1", "tls11", "tls12", "tls13"),
         addable=False, deletable=False),
    Kind("ssl_service_group", "sslservicegroup", "servicegroupname",
         ("servicegroupname", "sslprofile", "snienable", "serverauth", "commonname", "tls1", "tls11", "tls12",
          "tls13"),
         addable=False, deletable=False),
    Kind("ssl_profile", "sslprofile", "name",
         ("name", "sslprofiletype", "ssl3", "tls1", "tls11", "tls12", "tls13", "snienable", "serverauth",
          "commonname", "hsts", "maxage", "denysslreneg", "sessreuse", "ecccurvebindings")),
    Kind("ssl_policy", "sslpolicy", "name", ("name", "rule", "action", "reqaction", "hits", "comment"),
         required=("rule",)),
    Kind("ssl_action", "sslaction", "name",
         ("name", "clientauth", "clientcertverification", "clientcert", "certheader", "clientcertissuer",
          "clientcertsubject", "ssllogprofile", "forward", "comment")),
    # rewrite / responder
    Kind("rewrite_policy", "rewritepolicy", "name", _POLICY_FIELDS, required=("rule", "action")),
    Kind("rewrite_action", "rewriteaction", "name",
         ("name", "type", "target", "stringbuilderexpr", "search", "refinesearch", "hits", "comment"),
         required=("type",)),
    Kind("rewrite_policylabel", "rewritepolicylabel", "labelname", ("labelname", "transform", "numpol", "comment"),
         required=("transform",)),
    Kind("responder_policy", "responderpolicy", "name", _POLICY_FIELDS, required=("rule", "action")),
    Kind("responder_action", "responderaction", "name",
         ("name", "type", "target", "htmlpage", "responsestatuscode", "reasonphrase", "hits", "comment"),
         required=("type",)),
    Kind("responder_policylabel", "responderpolicylabel", "labelname",
         ("labelname", "policylabeltype", "numpol", "comment")),
    Kind("responder_htmlpage", "responderhtmlpage", "name", ("name", "comment"),
         required=("src",), add_action="Import", updatable=False),
    # pattern sets, data sets, string maps, named expressions
    Kind("policy_patset", "policypatset", "name", ("name", "indextype", "comment")),
    Kind("policy_dataset", "policydataset", "name", ("name", "type", "indextype", "comment"), required=("type",)),
    Kind("policy_stringmap", "policystringmap", "name", ("name", "comment")),
    Kind("policy_expression", "policyexpression", "name", ("name", "value", "description", "comment", "type"),
         required=("value",)),
    # GSLB
    Kind("gslb_vserver", "gslbvserver", "name",
         ("name", "servicetype", "curstate", "lbmethod", "iptype", "persistencetype", "comment"),
         required=("servicetype",), state_field="curstate"),
    Kind("gslb_service", "gslbservice", "servicename",
         ("servicename", "servicetype", "ipaddress", "servername", "port", "sitename", "state", "publicip",
          "publicport", "comment"),
         required=("servicetype", "port", "sitename"), one_of=("ip", "servername")),
    Kind("gslb_site", "gslbsite", "sitename",
         ("sitename", "sitetype", "siteipaddress", "publicip", "metricexchange", "parentsite", "status"),
         required=("siteipaddress",)),
    # DNS records (several records may share a name; multi tells them apart)
    Kind("dns_a", "dnsaddrec", "hostname", ("hostname", "ipaddress", "ttl", "type"),
         required=("ipaddress",), multi=("ipaddress",), delete_by=("ipaddress",), updatable=False),
    Kind("dns_aaaa", "dnsaaaarec", "hostname", ("hostname", "ipv6address", "ttl", "type"),
         required=("ipv6address",), multi=("ipv6address",), delete_by=("ipv6address",), updatable=False),
    Kind("dns_cname", "dnscnamerec", "aliasname", ("aliasname", "canonicalname", "ttl", "type"),
         required=("canonicalname",), updatable=False),
    Kind("dns_txt", "dnstxtrec", "domain", ("domain", "String", "ttl", "recordid"),
         required=("String",), multi=("String",), delete_by=("recordid",), updatable=False),
    Kind("dns_ns", "dnsnsrec", "domain", ("domain", "nameserver", "ttl", "type"),
         required=("nameserver",), multi=("nameserver",), delete_by=("nameserver",), updatable=False),
    Kind("dns_soa", "dnssoarec", "domain",
         ("domain", "originserver", "contact", "serial", "refresh", "retry", "expire", "minimum", "ttl"),
         required=("originserver", "contact")),
)}

# Settings clone_app_setup copies from a template (configuration, not identity or runtime state).
COPY_ATTRS = {
    "lb_vserver": ("servicetype", "lbmethod", "persistencetype", "timeout", "persistencebackup",
                   "backuppersistencetimeout", "cookiename", "clttimeout", "httpprofilename", "tcpprofilename",
                   "netprofile", "appflowlog", "downstateflush", "rhistate", "backuplbmethod"),
    "service_group": ("servicetype", "cip", "cipheader", "usip", "useproxyport", "sp", "clttimeout", "svrtimeout",
                      "cka", "tcpb", "cmp", "maxclient", "maxreq", "healthmonitor", "downstateflush", "appflowlog",
                      "httpprofilename", "tcpprofilename", "netprofile", "autoscale"),
}


@dataclass(frozen=True)
class Binding:
    """One bind/unbind relation: ``parent`` kind ← entries identified by ``identity``."""

    name: str  # tool-facing name, e.g. 'lb_vserver_service'
    resource: str  # NITRO binding resource
    parent: str | None  # Kind name of the object the entries are bound to; None = global binding
    identity: tuple[str, ...]  # attributes that identify one bound entry (also the DELETE args)
    fields: tuple[str, ...]  # trimmed view of a bound row
    required: tuple[str, ...] = ()  # a bind needs these besides the identity
    single: bool = False  # at most one entry (a new one replaces the old)
    shortcut: str = ""  # how a plain string entry reads, for the error messages
    delete_extra: tuple[str, ...] = ()  # more DELETE args, taken from the live row when set (bindpoint …)
    link: bool = False  # not a binding resource: POST <parent>?action=link / unlink (certificate chain)

    @property
    def parent_attr(self) -> str:
        return KINDS[self.parent].key if self.parent else ""


_POLICY_BIND_FIELDS = ("policyname", "priority", "gotopriorityexpression", "bindpoint", "invoke", "labeltype",
                       "labelname")
_CERT_BIND_FIELDS = ("certkeyname", "snicert", "ca", "crlcheck", "ocspcheck", "skipcaname")
# Policy features that bind to LB / CS vservers as <vserver>_<feature>policy_binding.
FEATURES = ("responder", "rewrite", "appfw", "bot", "cache", "cmp", "transform")


def _policy_binding(name: str, resource: str, parent: str | None, extra: tuple[str, ...]) -> Binding:
    return Binding(name, resource, parent, ("policyname",), _POLICY_BIND_FIELDS + extra, required=("priority",),
                   delete_extra=("bindpoint", "type", "priority"),
                   shortcut="'<policy>' (needs priority, so pass an object)")


BINDINGS: dict[str, Binding] = {b.name: b for b in (
    Binding("lb_vserver_service", "lbvserver_service_binding", "lb_vserver", ("servicename",),
            ("servicename", "ipv46", "port", "servicetype", "curstate", "weight"), shortcut="'<service>'"),
    Binding("lb_vserver_service_group", "lbvserver_servicegroup_binding", "lb_vserver", ("servicegroupname",),
            ("servicegroupname", "weight"), shortcut="'<service group>'"),
    Binding("service_group_member", "servicegroup_servicegroupmember_binding", "service_group",
            ("servername", "port"), ("servername", "ip", "port", "weight", "state", "svrstate"),
            required=("port",), shortcut="'<server or IP>:<port>'"),
    Binding("service_monitor", "service_lbmonitor_binding", "service", ("monitor_name",),
            ("monitor_name", "monstate", "weight"), shortcut="'<monitor>'"),
    Binding("service_group_monitor", "servicegroup_lbmonitor_binding", "service_group", ("monitor_name",),
            ("monitor_name", "monstate", "weight"), shortcut="'<monitor>'"),
    Binding("cs_vserver_policy", "csvserver_cspolicy_binding", "cs_vserver", ("policyname",),
            ("policyname", "priority", "targetlbvserver", "gotopriorityexpression", "bindpoint", "hits"),
            required=("priority",), delete_extra=("bindpoint",),
            shortcut="'<policy>' (needs priority, so pass an object)"),
    Binding("cs_vserver_default", "csvserver_lbvserver_binding", "cs_vserver", ("lbvserver",),
            ("lbvserver",), single=True, shortcut="'<lb vserver>'"),
    # policies per feature on LB / CS vservers, analytics profiles
    *(_policy_binding(f"lb_vserver_{f}_policy", f"lbvserver_{f}policy_binding", "lb_vserver", ("hits",))
      for f in FEATURES),
    *(_policy_binding(f"cs_vserver_{f}_policy", f"csvserver_{f}policy_binding", "cs_vserver", ("hits",))
      for f in FEATURES),
    Binding("lb_vserver_analytics_profile", "lbvserver_analyticsprofile_binding", "lb_vserver",
            ("analyticsprofile",), ("analyticsprofile",), shortcut="'<analytics profile>'"),
    Binding("cs_vserver_analytics_profile", "csvserver_analyticsprofile_binding", "cs_vserver",
            ("analyticsprofile",), ("analyticsprofile",), shortcut="'<analytics profile>'"),
    # SSL
    # snicert is part of the identity: one certificate may be bound both as default and as SNI certificate
    Binding("ssl_vserver_certkey", "sslvserver_sslcertkey_binding", "ssl_vserver", ("certkeyname", "snicert"),
            _CERT_BIND_FIELDS, delete_extra=("ca", "crlcheck", "ocspcheck"), shortcut="'<certkey>'"),
    Binding("ssl_service_certkey", "sslservice_sslcertkey_binding", "ssl_service", ("certkeyname", "snicert"),
            _CERT_BIND_FIELDS, delete_extra=("ca", "crlcheck", "ocspcheck"), shortcut="'<certkey>'"),
    Binding("ssl_service_group_certkey", "sslservicegroup_sslcertkey_binding", "ssl_service_group",
            ("certkeyname", "snicert"), _CERT_BIND_FIELDS, delete_extra=("ca", "crlcheck", "ocspcheck"),
            shortcut="'<certkey>'"),
    _policy_binding("ssl_vserver_policy", "sslvserver_sslpolicy_binding", "ssl_vserver", ("type",)),
    Binding("ssl_profile_cipher", "sslprofile_sslcipher_binding", "ssl_profile", ("ciphername",),
            ("ciphername", "cipherpriority", "description"), shortcut="'<cipher or cipher group>'"),
    Binding("ssl_certkey_link", "sslcertkey", "ssl_certkey", ("linkcertkeyname",), ("linkcertkeyname",),
            single=True, link=True, shortcut="'<CA certkey>'"),
    # global bindings and policy labels
    _policy_binding("rewrite_global_policy", "rewriteglobal_rewritepolicy_binding", None, ("type",)),
    _policy_binding("responder_global_policy", "responderglobal_responderpolicy_binding", None, ("type",)),
    _policy_binding("rewrite_policylabel_policy", "rewritepolicylabel_rewritepolicy_binding",
                    "rewrite_policylabel", ()),
    _policy_binding("responder_policylabel_policy", "responderpolicylabel_responderpolicy_binding",
                    "responder_policylabel", ()),
    # pattern sets, data sets, string maps
    Binding("policy_patset_pattern", "policypatset_pattern_binding", "policy_patset", ("String",),
            ("String", "index", "charset", "comment"), shortcut="'<pattern>'"),
    Binding("policy_dataset_value", "policydataset_value_binding", "policy_dataset", ("value",),
            ("value", "index", "endrange", "comment"), shortcut="'<value>'"),
    Binding("policy_stringmap_pattern", "policystringmap_pattern_binding", "policy_stringmap", ("key",),
            ("key", "value", "comment"), required=("value",), shortcut="{'key': ..., 'value': ...}"),
    # GSLB
    Binding("gslb_vserver_service", "gslbvserver_gslbservice_binding", "gslb_vserver", ("servicename",),
            ("servicename", "weight", "order", "curstate", "ipaddress", "port"), shortcut="'<gslb service>'"),
    Binding("gslb_vserver_domain", "gslbvserver_domain_binding", "gslb_vserver", ("domainname",),
            ("domainname", "ttl", "backupip", "cookiedomain", "cookietimeout", "sitedomainttl"),
            shortcut="'<domain>'"),
)}
BINDING_BY_RESOURCE = {b.resource: b for b in BINDINGS.values() if not b.link}

# Row attributes that are internal bookkeeping, not configuration.
NOISE = frozenset({"stateflag", "__count", "_nextgenapiresource", "vserverid", "hashid", "serverid", "customserverid"})


def kind(name: str, *, stateful: bool = False, operation: str | None = None) -> Kind:
    k = KINDS.get((name or "").strip().lower())
    ok = k is not None and (not stateful or k.state_field) and (operation is None or k.can(operation))
    if not ok:
        valid = [n for n, v in KINDS.items()
                 if (v.state_field or not stateful) and (operation is None or v.can(operation))]
        raise ValueError(f"kind must be one of {valid}; got {name!r}.")
    return k


def binding(name: str) -> Binding:
    b = BINDINGS.get((name or "").strip().lower())
    if b is None:
        raise ValueError(f"binding must be one of {list(BINDINGS)}; got {name!r}.")
    return b


def mask(value: Any) -> Any:
    """A copy of a body / row / table with secret values replaced (booleans such as password=true stay)."""
    if isinstance(value, dict):
        return {k: ("***" if k.lower() in SECRET_ATTRS and isinstance(v, str) and v else mask(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v) for v in value]
    return value


def add_body(k: Kind, name: str, settings: dict[str, Any] | None) -> dict[str, Any]:
    """The NITRO body that adds object ``name``; checks what an add needs."""
    settings = dict(settings or {})
    if not (name or "").strip():
        raise ValueError("name is required.")
    if settings.pop(k.key, name) != name:
        raise ValueError(f"settings.{k.key} differs from name; leave it out.")
    missing = [a for a in k.required if settings.get(a) in (None, "", [])]
    if missing:
        raise ValueError(f"Adding a {k.name} needs {', '.join(missing)} in settings.")
    if k.one_of and sum(settings.get(a) not in (None, "") for a in k.one_of) != 1:
        raise ValueError(f"Adding a {k.name} needs exactly one of {', '.join(k.one_of)} in settings.")
    return {k.key: name, **settings}


def same_record(k: Kind, row: dict[str, Any], body: dict[str, Any]) -> bool:
    """Whether a live record of a multi kind is the one ``body`` describes (all multi attributes equal)."""
    return all(_norm(row.get(a)) == _norm(body.get(a)) for a in k.multi)


def _norm(value: Any) -> Any:
    if isinstance(value, list):
        return sorted(_norm(v) for v in value)
    return str(value).strip().lower() if value is not None else None


def update_plan(
    k: Kind, current: dict[str, Any], settings: dict[str, Any] | None, unset: list[str] | None
) -> tuple[dict[str, Any], dict[str, Any], list[str], dict[str, Any]]:
    """(attributes to set, attributes for the update action, attributes to unset, before/after table).

    Update-action attributes (a certificate's cert/key files) are always sent: the file behind an
    unchanged name may have been replaced.
    """
    settings = dict(settings or {})
    unset = list(dict.fromkeys(a.strip() for a in unset or [] if a and a.strip()))
    if k.key in settings or k.key in unset:
        raise ValueError(f"{k.key} identifies the {k.name}; renaming is not supported here.")
    if both := sorted(set(settings) & set(unset)):
        raise ValueError(f"{both} are both set and unset; pick one.")
    action = {a: v for a, v in settings.items() if a in k.update_action_attrs}
    if action and "cert" not in action:
        action["cert"] = current.get("cert")
    if action and "key" not in action and current.get("key"):
        action["key"] = current.get("key")
    changes = settings_changes({a: v for a, v in settings.items() if a not in k.update_action_attrs}, current)
    table = {a: {"before": current.get(a), "after": v} for a, v in changes.items()}
    table.update({a: {"before": current.get(a), "after": v, "via": "update (reload)"} for a, v in action.items()})
    table.update({a: {"before": current.get(a), "after": "(default)"} for a in unset})
    return changes, action, unset, mask(table)


def _host_entry(value: str) -> dict[str, Any]:
    """'srv1:80' / '10.0.0.5:80' / '[fd00::5]:80' → servername or ip + port."""
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not host:
        raise ValueError(f"A service group member is '<server or IP>:<port>' or an object; got {value!r}.")
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return {"servername": host, "port": int(port)}
    return {"ip": host, "port": int(port)}


def entry(b: Binding, raw: Any) -> dict[str, Any]:
    """A requested entry as NITRO attributes; a plain string is shorthand for the identity."""
    if isinstance(raw, str):
        if b.name == "service_group_member":
            return _host_entry(raw.strip())
        if b.required:
            raise ValueError(f"{b.name} entries need {', '.join(b.required)}: pass objects, e.g. "
                             f"{{{b.identity[0]!r}: ..., {b.required[0]!r}: ...}}.")
        return {b.identity[0]: raw.strip()}
    if not isinstance(raw, dict):
        raise ValueError(f"{b.name} entries are objects or {b.shortcut}; got {raw!r}.")
    out = {k: v for k, v in raw.items() if not b.parent_attr or k != b.parent_attr}
    if b.name == "service_group_member" and "servername" not in out and "ip" not in out:
        raise ValueError("A service group member needs servername or ip, and port.")
    if missing := [a for a in b.identity if a not in out and not (a == "servername" and "ip" in out)]:
        raise ValueError(f"{b.name} entry {raw!r} lacks {', '.join(missing)}.")
    return out


def removal(b: Binding, raw: Any) -> dict[str, Any]:
    """An entry to unbind: a plain string is the identity (no other attributes needed)."""
    if isinstance(raw, str) and b.name != "service_group_member":
        return {b.identity[0]: raw.strip()}
    return entry(b, raw) if not isinstance(raw, dict) else {
        k: v for k, v in raw.items() if not b.parent_attr or k != b.parent_attr}


def _same(a: Any, b: Any) -> bool:
    return str(a).strip().lower() == str(b).strip().lower()


def _set(value: Any) -> bool:
    return value not in (None, "", False) and str(value).lower() not in ("false", "no")


def identity(b: Binding, item: dict[str, Any]) -> dict[str, Any]:
    """The identifying attributes of an entry or a live row (a member's server may be given as ip)."""
    out = {}
    for attr in b.identity:
        value = item.get(attr)
        if value in (None, "") and attr == "servername":
            value = item.get("ip")
        out[attr] = value
    return out


def unbind_args(b: Binding, row: dict[str, Any]) -> dict[str, Any]:
    """What unbinding a live row needs: its identity plus the extra DELETE args it carries (bindpoint …)."""
    return {**identity(b, row), **{a: row[a] for a in b.delete_extra if _set(row.get(a))}}


def _ident_value(value: Any) -> str:
    """Identity values compared loosely: an unset flag equals false (a non-SNI binding has no snicert)."""
    if value in (None, "", False) or str(value).lower() in ("false", "no"):
        return ""
    return "true" if value is True else str(value).strip().lower()


def matches(b: Binding, row: dict[str, Any], item: dict[str, Any], *, partial: bool = False) -> bool:
    """Whether a live row is the entry ``item`` names; partial: only the identity attributes item gives."""
    wanted = identity(b, item)
    for attr, value in wanted.items():
        if partial and attr not in item and not (attr == "servername" and "ip" in item):
            continue
        candidates = [row.get(attr)] + ([row.get("ip")] if attr == "servername" else [])
        if not any(_ident_value(c) == _ident_value(value) for c in candidates):
            return False
    return True


def differences(b: Binding, row: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    """Requested attributes the live row shows with another value (attributes the row omits are not compared)."""
    skip = set(b.identity) | {"ip"} | ({b.parent_attr} if b.parent_attr else set())
    return {a: {"before": row[a], "after": v} for a, v in item.items()
            if a not in skip and a in row and not _same(row[a], v)}


def plan_bindings(
    b: Binding, rows: list[dict[str, Any]], add: list[dict[str, Any]], remove: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Ordered steps for change_bindings, each {op, entry, status[, unbind, changes]}.

    op is 'bind', 'rebind' (unbind + bind, for a changed weight/priority …), 'unbind', or None for an
    entry that needs nothing. Unbinds carry the live row's DELETE args. Order keeps traffic flowing: a
    single-entry replacement (CS default, certificate link) first, then new binds, then rebinds,
    unbinds last.
    """
    for a in add:
        if any(matches(b, a, r, partial=True) for r in remove):
            raise ValueError(f"{identity(b, a)} is in both add and remove.")
    replace, binds, rebinds, unbinds, nothing = [], [], [], [], []
    if b.single and len(add) > 1:
        raise ValueError(f"{b.name} holds one entry; add only one.")
    for item in add:
        found = [r for r in rows if matches(b, r, item)]
        if found:
            diff = differences(b, found[0], item)
            if diff:
                rebinds.append({"op": "rebind", "entry": item, "unbind": unbind_args(b, found[0]),
                                "status": "would rebind", "changes": diff})
            else:
                nothing.append({"op": None, "entry": item, "status": "already bound"})
            continue
        if b.single and rows:
            replace += [{"op": "unbind", "entry": unbind_args(b, r), "status": "would unbind (replaced)"}
                        for r in rows]
        (replace if b.single else binds).append({"op": "bind", "entry": item, "status": "would bind"})
    for item in remove:
        found = [r for r in rows if matches(b, r, item, partial=True)]
        if found:
            unbinds += [{"op": "unbind", "entry": unbind_args(b, r), "status": "would unbind"} for r in found]
        else:
            nothing.append({"op": None, "entry": item, "status": "not bound"})
    return replace + binds + rebinds + unbinds + nothing


def delete_args(b: Binding, item: dict[str, Any]) -> dict[str, Any]:
    """DELETE ?args= for one bound entry (a member added by IP carries the IP as its server name).

    Booleans go on the wire lower case (snicert:true), as NITRO expects.
    """
    return {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in item.items() if v not in (None, "")}


def trim_row(row: dict[str, Any], fields: tuple[str, ...] | None, parent_attr: str) -> dict[str, Any]:
    """A bound row without bookkeeping; projected to ``fields`` when the binding is modelled."""
    if fields:
        return {f: row[f] for f in fields if f in row}
    return {k: v for k, v in row.items() if k not in NOISE and k != parent_attr}
