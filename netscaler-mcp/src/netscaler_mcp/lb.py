"""Load balancing and content switching objects for the generic config tools (no network, no MCP).

``KINDS`` maps the tool-facing kind names (``lb_vserver``, ``service_group``, ``cs_policy`` …) onto NITRO
resources: the key attribute, what an add needs, the trimmed view and how enable/disable is addressed.
``BINDINGS`` does the same for the bind/unbind relations between them (vserver ↔ service, group ↔
member, CS vserver ↔ policy …). ``plan_bindings`` turns a requested add/remove list plus the live rows
into ordered bind/unbind steps. server.py only orchestrates the NITRO calls.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from .waf import settings_changes


@dataclass(frozen=True)
class Kind:
    """One configurable object type."""

    name: str  # tool-facing name, e.g. 'lb_vserver'
    resource: str  # NITRO resource type, e.g. 'lbvserver'
    key: str  # identifying attribute: name / servicegroupname / policyname / monitorname
    fields: tuple[str, ...]  # trimmed view
    required: tuple[str, ...] = ()  # an add needs these besides the key
    one_of: tuple[str, ...] = ()  # … and exactly one of these
    ident_extra: tuple[str, ...] = ()  # attributes set/unset need besides the key (lbmonitor: type)
    state_field: str | None = None  # where GET shows the run/admin state; None = no enable/disable
    graceful: bool = False  # disable takes delay + graceful

    @property
    def aggregate(self) -> str:
        return f"{self.resource}_binding"


KINDS: dict[str, Kind] = {k.name: k for k in (
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
         required=("type",), ident_extra=("type",)),
)}


@dataclass(frozen=True)
class Binding:
    """One bind/unbind relation: ``parent`` kind ← entries identified by ``identity``."""

    name: str  # tool-facing name, e.g. 'lb_vserver_service'
    resource: str  # NITRO binding resource
    parent: str  # Kind name of the object the entries are bound to
    identity: tuple[str, ...]  # attributes that identify one bound entry (also the DELETE args)
    fields: tuple[str, ...]  # trimmed view of a bound row
    required: tuple[str, ...] = ()  # a bind needs these besides the identity
    single: bool = False  # at most one entry (a new one replaces the old)
    shortcut: str = ""  # how a plain string entry reads, for the error messages

    @property
    def parent_attr(self) -> str:
        return KINDS[self.parent].key


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
            required=("priority",), shortcut="'<policy>' (needs priority, so pass an object)"),
    Binding("cs_vserver_default", "csvserver_lbvserver_binding", "cs_vserver", ("lbvserver",),
            ("lbvserver",), single=True, shortcut="'<lb vserver>'"),
)}
BINDING_BY_RESOURCE = {b.resource: b for b in BINDINGS.values()}

# Row attributes that are internal bookkeeping, not configuration.
NOISE = frozenset({"stateflag", "__count", "_nextgenapiresource", "vserverid", "hashid", "serverid", "customserverid"})


def kind(name: str, *, stateful: bool = False) -> Kind:
    k = KINDS.get((name or "").strip().lower())
    if k is None or (stateful and k.state_field is None):
        valid = [n for n, v in KINDS.items() if v.state_field or not stateful]
        raise ValueError(f"kind must be one of {valid}; got {name!r}.")
    return k


def binding(name: str) -> Binding:
    b = BINDINGS.get((name or "").strip().lower())
    if b is None:
        raise ValueError(f"binding must be one of {list(BINDINGS)}; got {name!r}.")
    return b


def add_body(k: Kind, name: str, settings: dict[str, Any] | None) -> dict[str, Any]:
    """The NITRO body that adds object ``name``; checks what an add needs."""
    settings = dict(settings or {})
    if not (name or "").strip():
        raise ValueError("name is required.")
    if settings.pop(k.key, name) != name:
        raise ValueError(f"settings.{k.key} differs from name; leave it out.")
    missing = [a for a in k.required if settings.get(a) in (None, "")]
    if missing:
        raise ValueError(f"Adding a {k.name} needs {', '.join(missing)} in settings.")
    if k.one_of and sum(settings.get(a) not in (None, "") for a in k.one_of) != 1:
        raise ValueError(f"Adding a {k.name} needs exactly one of {', '.join(k.one_of)} in settings.")
    return {k.key: name, **settings}


def update_plan(
    k: Kind, current: dict[str, Any], settings: dict[str, Any] | None, unset: list[str] | None
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    """(attributes to set, attributes to unset, before/after table) for update_object."""
    settings = dict(settings or {})
    unset = list(dict.fromkeys(a.strip() for a in unset or [] if a and a.strip()))
    if k.key in settings or k.key in unset:
        raise ValueError(f"{k.key} identifies the {k.name}; renaming is not supported here.")
    if both := sorted(set(settings) & set(unset)):
        raise ValueError(f"{both} are both set and unset; pick one.")
    changes = settings_changes(settings, current)
    table = {a: {"before": current.get(a), "after": v} for a, v in changes.items()}
    table.update({a: {"before": current.get(a), "after": "(default)"} for a in unset})
    return changes, unset, table


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
    out = {k: v for k, v in raw.items() if k != b.parent_attr}
    if b.name == "service_group_member" and "servername" not in out and "ip" not in out:
        raise ValueError("A service group member needs servername or ip, and port.")
    if missing := [a for a in b.identity if a not in out and not (a == "servername" and "ip" in out)]:
        raise ValueError(f"{b.name} entry {raw!r} lacks {', '.join(missing)}.")
    return out


def _same(a: Any, b: Any) -> bool:
    return str(a).strip().lower() == str(b).strip().lower()


def identity(b: Binding, item: dict[str, Any]) -> dict[str, Any]:
    """The identifying attributes of an entry or a live row (a member's server may be given as ip)."""
    out = {}
    for attr in b.identity:
        value = item.get(attr)
        if value in (None, "") and attr == "servername":
            value = item.get("ip")
        out[attr] = value
    return out


def matches(b: Binding, row: dict[str, Any], item: dict[str, Any]) -> bool:
    wanted = identity(b, item)
    for attr, value in wanted.items():
        candidates = [row.get(attr)] + ([row.get("ip")] if attr == "servername" else [])
        if not any(c is not None and _same(c, value) for c in candidates):
            return False
    return True


def differences(b: Binding, row: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    """Requested attributes the live row shows with another value (attributes the row omits are not compared)."""
    skip = set(b.identity) | {"ip", b.parent_attr}
    return {a: {"before": row[a], "after": v} for a, v in item.items()
            if a not in skip and a in row and not _same(row[a], v)}


def plan_bindings(
    b: Binding, rows: list[dict[str, Any]], add: list[dict[str, Any]], remove: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Ordered steps for change_bindings, each {op, entry, status[, before/after]}.

    op is 'bind', 'rebind' (unbind + bind, for a changed weight/priority …), 'unbind', or None for an
    entry that needs nothing. Order keeps traffic flowing: a single-entry replacement (CS default)
    first, then new binds, then rebinds, unbinds last.
    """
    for a in add:
        if any(matches(b, r, a) for r in remove):
            raise ValueError(f"{identity(b, a)} is in both add and remove.")
    replace, binds, rebinds, unbinds, nothing = [], [], [], [], []
    if b.single and len(add) > 1:
        raise ValueError(f"{b.name} holds one entry; add only one.")
    for item in add:
        found = [r for r in rows if matches(b, r, item)]
        if found:
            diff = differences(b, found[0], item)
            if diff:
                rebinds.append({"op": "rebind", "entry": item, "status": "would rebind", "changes": diff})
            else:
                nothing.append({"op": None, "entry": item, "status": "already bound"})
            continue
        if b.single and rows:
            replace += [{"op": "unbind", "entry": identity(b, r), "status": "would unbind (replaced)"} for r in rows]
        (replace if b.single else binds).append({"op": "bind", "entry": item, "status": "would bind"})
    for item in remove:
        found = [r for r in rows if matches(b, r, item)]
        if found:
            unbinds += [{"op": "unbind", "entry": identity(b, r), "status": "would unbind"} for r in found]
        else:
            nothing.append({"op": None, "entry": item, "status": "not bound"})
    return replace + binds + rebinds + unbinds + nothing


def delete_args(b: Binding, item: dict[str, Any]) -> dict[str, Any]:
    """DELETE ?args= for one bound entry (a member added by IP carries the IP as its server name)."""
    return {k: v for k, v in identity(b, item).items() if v not in (None, "")}


def trim_row(row: dict[str, Any], fields: tuple[str, ...] | None, parent_attr: str) -> dict[str, Any]:
    """A bound row without bookkeeping; projected to ``fields`` when the binding is modelled."""
    if fields:
        return {f: row[f] for f in fields if f in row}
    return {k: v for k, v in row.items() if k not in NOISE and k != parent_attr}
