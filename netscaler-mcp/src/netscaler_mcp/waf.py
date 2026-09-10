"""Pure helpers behind the WAF (AppFw) rollout tools — no network, no MCP.

- **URL regexes:** build anchored AppFw URL patterns from plain host/path input (``url_regex``) and
  turn learned/bound patterns back into readable scheme/host/path (``parse_url_pattern``).
- **Host switching:** rewrite hostnames inside rules in both literal and regex-escaped (``\\.``)
  form (``HostRewriter``), so a profile tuned on one environment can move to another.
- **Rule types:** which NITRO binding carries each rule, which attributes identify one binding,
  which hold URLs, and how learned data maps onto it (``RULE_TYPES``).
- **Plans:** diff an exported profile document against the live profile (``plan_bindings``).

server.py turns these into tools; tests/test_smoke.py exercises them directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

# PCRE metacharacters. NetScaler's learning engine escapes these (dots become ``\.``) and leaves
# ``/``, ``:`` and ``-`` literal, so hand-built rules follow the same convention.
_REGEX_META = frozenset("\\.^$|?*+()[]{}")

URL_MATCHES = ("prefix", "exact", "regex")
SCHEMES = ("https", "http", "any")
STATIC_EXTENSIONS = (
    "css", "js", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff", "woff2", "ttf",
)

_HOST_RE = re.compile(r"(\*|[a-z0-9_]([a-z0-9_\-.]*[a-z0-9_])?)(:\d{1,5})?")


def regex_escape(text: str) -> str:
    """Escape PCRE metacharacters the way NetScaler-learned rules do (``/ : -`` stay literal)."""
    return "".join("\\" + ch if ch in _REGEX_META else ch for ch in text)


def _unescape(text: str) -> str:
    """Undo simple metacharacter escapes for display (``\\.`` → ``.``); real classes like ``\\d`` stay."""
    return re.sub(r"\\([\\.^$|?*+()\[\]{}/:\-])", r"\1", text)


def normalize_host(host: str) -> str:
    """Accept ``app.example.com``, ``app.example.com:8443`` or a pasted URL; return lowercase host[:port]."""
    value = (host or "").strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].strip().lower()
    if not _HOST_RE.fullmatch(value):
        raise ValueError(
            f"Not a valid hostname: {host!r} (expected e.g. 'app.example.com' or 'app.example.com:8443')."
        )
    return value


def url_regex(
    host: str,
    path: str = "/",
    *,
    match: str = "prefix",
    scheme: str = "https",
    extensions: list[str] | tuple[str, ...] | None = None,
) -> str:
    """Build an anchored AppFw URL regex from plain input.

    ``host='*'`` matches any host (an environment-agnostic rule); ``scheme='any'`` matches http and
    https. ``match``: 'prefix' = the path and everything below it, 'exact' = just that URL, 'regex' =
    ``path`` is already a regex fragment. ``extensions`` narrows a prefix rule to those file types.
    Exact and extension rules tolerate a query string, so they hold whether or not the appliance
    strips it before matching.
    """
    if match not in URL_MATCHES:
        raise ValueError(f"match must be one of {URL_MATCHES}; got {match!r}.")
    if scheme not in SCHEMES:
        raise ValueError(f"scheme must be one of {SCHEMES}; got {scheme!r}.")
    host = normalize_host(host)
    path = (path or "/").strip()
    if not path.startswith("/"):
        path = "/" + path

    if match == "regex":
        if extensions:
            raise ValueError("extensions only apply to match='prefix'.")
        path_rx = path
    elif match == "exact":
        if extensions:
            raise ValueError("extensions only apply to match='prefix'.")
        path_rx = regex_escape(path) + r"(\?.*)?"
    elif extensions:
        exts = [regex_escape(e.strip().lstrip(".").lower()) for e in extensions if e.strip().lstrip(".")]
        if not exts:
            raise ValueError("extensions is empty.")
        base = regex_escape(path if path.endswith("/") else path + "/")
        path_rx = f"{base}.*\\.({'|'.join(exts)})(\\?.*)?"
    elif path.endswith("/"):
        path_rx = regex_escape(path) + ".*"
    else:
        # '/api' covers /api, /api/..., /api?... but not /apiary.
        path_rx = regex_escape(path) + "([/?].*)?"

    host_rx = "[^/]+" if host == "*" else regex_escape(host)
    scheme_rx = "https?" if scheme == "any" else scheme
    pattern = f"^{scheme_rx}://{host_rx}{path_rx}$"
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Built an invalid regex {pattern!r}: {exc}") from exc
    return pattern


def parse_url_pattern(pattern: str) -> dict[str, str]:
    """Best-effort split of an AppFw URL regex into scheme / host / path for display and grouping.

    ``^https://app\\.example\\.com/login\\.php$`` → https, app.example.com, /login.php. Regex parts
    that aren't simple escapes (``.*``, groups) stay verbatim in the path; a ``[^/]+`` host is '*'.
    Relative values (no scheme) come back with an empty scheme and host.
    """
    s = (pattern or "").strip().replace("\\/", "/")
    if s.startswith("^"):
        s = s[1:]
    if s.endswith("$") and not s.endswith("\\$"):
        s = s[:-1]
    m = re.match(r"(?P<scheme>https\?|https|http)://(?P<rest>.*)$", s, re.IGNORECASE)
    if not m:
        return {"scheme": "", "host": "", "path": _unescape(s)}
    rest = m.group("rest")
    if rest.startswith("[^/]+"):
        host, path = "*", rest[len("[^/]+"):]
    else:
        idx = rest.find("/")
        host, path = (rest, "") if idx < 0 else (rest[:idx], rest[idx:])
    scheme = m.group("scheme").lower()
    return {
        "scheme": "any" if scheme == "https?" else scheme,
        "host": _unescape(host).lower(),
        "path": _unescape(path) or "/",
    }


def group_urls(patterns: list[str], *, examples: int = 3) -> list[dict[str, Any]]:
    """Group URL patterns by scheme/host/first path segment, with a suggested prefix rule per group.

    Turns hundreds of learned exact URLs into a handful of candidate 'allow everything under /app/'
    rules. Groups are sorted biggest first.
    """
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for pattern in patterns:
        url = parse_url_pattern(pattern)
        parts = url["path"].split("/")
        segment = parts[1] if len(parts) > 2 else ""
        prefix = f"/{segment}/" if segment and not set(segment) & _REGEX_META else "/"
        key = (url["scheme"], url["host"], prefix)
        group = groups.setdefault(
            key,
            {"scheme": url["scheme"], "host": url["host"], "prefix": prefix, "count": 0, "examples": []},
        )
        group["count"] += 1
        if len(group["examples"]) < examples:
            group["examples"].append(url["path"])
    for group in groups.values():
        if group["host"]:
            try:
                group["suggested_rule"] = url_regex(group["host"], group["prefix"], scheme=group["scheme"])
            except ValueError:
                pass
    return sorted(groups.values(), key=lambda g: (-g["count"], g["host"], g["prefix"]))


class HostRewriter:
    """Replace hostnames inside URL strings and URL regexes, in literal and regex-escaped form.

    ``{"app.dev.corp": "app.corp"}`` turns ``^https://app\\.dev\\.corp/x$`` into
    ``^https://app\\.corp/x$`` and ``https://app.dev.corp/x`` into ``https://app.corp/x``. Matches
    respect host boundaries (``dev.corp`` hits neither ``app.dev.corp`` nor ``dev.corp.evil``), a port
    after the host is kept unless it is part of the mapping, and all mappings apply in one pass (so
    ``a→b, b→c`` never chains).
    """

    def __init__(self, host_map: dict[str, str] | None) -> None:
        pairs = [(normalize_host(src), normalize_host(dst)) for src, dst in (host_map or {}).items()]
        if any("*" in pair for pair in pairs):
            raise ValueError("host_map entries must be concrete hostnames, not '*'.")
        pairs.sort(key=lambda pair: -len(pair[0]))
        self.host_map = dict(pairs)
        self.replacements = 0
        self._targets: dict[str, str] = {}
        alternatives: list[str] = []
        for i, (src, dst) in enumerate(pairs):
            alternatives.append(f"(?P<e{i}>{re.escape(regex_escape(src))})")
            alternatives.append(f"(?P<p{i}>{re.escape(src)})")
            self._targets[f"e{i}"] = regex_escape(dst)
            self._targets[f"p{i}"] = dst
        self._rx = (
            re.compile(
                r"(?<![A-Za-z0-9_\-.])(?:" + "|".join(alternatives) + r")(?![A-Za-z0-9_\-])(?!\\?\.[A-Za-z0-9])",
                re.IGNORECASE,
            )
            if alternatives
            else None
        )

    def __bool__(self) -> bool:
        return self._rx is not None

    def __call__(self, text: str) -> str:
        if self._rx is None or not isinstance(text, str):
            return text

        def _sub(m: re.Match[str]) -> str:
            self.replacements += 1
            return self._targets[m.lastgroup or ""]

        return self._rx.sub(_sub, text)


def rewrite_strings(obj: Any, fn: Callable[[str], str], *, skip_keys: frozenset[str] = frozenset()) -> Any:
    """Apply ``fn`` to every string inside nested dicts/lists, leaving ``skip_keys`` values untouched."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [rewrite_strings(v, fn, skip_keys=skip_keys) for v in obj]
    if isinstance(obj, dict):
        return {
            k: (v if k in skip_keys else rewrite_strings(v, fn, skip_keys=skip_keys)) for k, v in obj.items()
        }
    return obj


# ---- rule types (attribute names per the NetScaler 14.1 NITRO reference) ------

@dataclass(frozen=True)
class RuleType:
    """One kind of AppFw rule and how NITRO stores it."""

    binding: str  # NITRO binding resource (added with PUT, removed with DELETE ?args=)
    identity: tuple[str, ...]  # DELETE args that identify one binding; ``ruletype`` is always added
    url_attrs: tuple[str, ...] = ()  # attributes holding URLs / URL regexes
    check: str | None = None  # appfwlearningdata ``securitycheck`` when the check learns
    # binding attr <- learned attrs to read it from, first non-empty wins. The documented GET returns
    # generic url/name/value_type/value fields; per-check names are tried first in case a build sends them.
    learned: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # appfwlearningdata DELETE arg <- binding attr carrying its value (default: same-named identity attrs).
    learned_delete: tuple[tuple[str, str], ...] = ()


def _field_rule(binding: str, field: str, suffix: str, check: str | None = None) -> RuleType:
    """SQL / XSS / command-injection relaxations share one shape: field + form action URL + location/value."""
    identity = (field, f"formactionurl_{suffix}", f"as_scan_location_{suffix}", f"as_value_type_{suffix}",
                f"as_value_expr_{suffix}")
    learned = (
        (field, (field, "name")),
        (f"formactionurl_{suffix}", (f"formactionurl_{suffix}", "url")),
        (f"as_scan_location_{suffix}", (f"as_scan_location_{suffix}",)),
        (f"as_value_type_{suffix}", (f"as_value_type_{suffix}", "value_type")),
        (f"as_value_expr_{suffix}", (f"as_value_expr_{suffix}", "value")),
    )
    return RuleType(binding, identity, (f"formactionurl_{suffix}",), check, learned if check else ())


def _json_rule(kind: str) -> RuleType:
    url = f"json{kind}url"
    return RuleType(
        f"appfwprofile_{url}_binding",
        (url, f"keyname_json_{kind}", f"as_value_type_json_{kind}", f"as_value_expr_json_{kind}"),
        (url,),
    )


RULE_TYPES: dict[str, RuleType] = {
    "start_url": RuleType(
        "appfwprofile_starturl_binding", ("starturl",), ("starturl",), "startURL",
        learned=(("starturl", ("starturl", "url", "name")),),
    ),
    "deny_url": RuleType("appfwprofile_denyurl_binding", ("denyurl",), ("denyurl",)),
    "sql_injection": _field_rule("appfwprofile_sqlinjection_binding", "sqlinjection", "sql", "SQLInjection"),
    "cross_site_scripting": _field_rule(
        "appfwprofile_crosssitescripting_binding", "crosssitescripting", "xss", "crossSiteScripting"
    ),
    "cmd_injection": _field_rule("appfwprofile_cmdinjection_binding", "cmdinjection", "cmd"),
    "field_consistency": RuleType(
        "appfwprofile_fieldconsistency_binding", ("fieldconsistency", "formactionurl_ffc"), ("formactionurl_ffc",),
        "fieldConsistency",
        learned=(("fieldconsistency", ("fieldconsistency", "name")), ("formactionurl_ffc", ("formactionurl_ffc", "url"))),
    ),
    "cookie_consistency": RuleType(
        "appfwprofile_cookieconsistency_binding", ("cookieconsistency",), (), "cookieConsistency",
        learned=(("cookieconsistency", ("cookieconsistency", "name")),),
    ),
    # The names are inverted between the resources: the binding's csrftag is the form ORIGIN URL and
    # csrfformactionurl the action URL; in learned data csrftag is the ACTION URL, csrfformoriginurl the origin.
    "csrf_tag": RuleType(
        "appfwprofile_csrftag_binding", ("csrftag", "csrfformactionurl"), ("csrftag", "csrfformactionurl"), "CSRFtag",
        learned=(("csrftag", ("csrfformoriginurl", "name")), ("csrfformactionurl", ("csrftag", "url"))),
        learned_delete=(("csrfformoriginurl", "csrftag"), ("csrftag", "csrfformactionurl")),
    ),
    "field_format": RuleType(
        "appfwprofile_fieldformat_binding", ("fieldformat", "formactionurl_ff"), ("formactionurl_ff",), "fieldFormat",
        learned=(
            ("fieldformat", ("fieldformat", "name")),
            ("formactionurl_ff", ("formactionurl_ff", "url")),
            ("fieldtype", ("fieldtype",)),
            ("fieldformatminlength", ("fieldformatminlength",)),
            ("fieldformatmaxlength", ("fieldformatmaxlength",)),
        ),
    ),
    "content_type": RuleType(
        "appfwprofile_contenttype_binding", ("contenttype",), (), "ContentType",
        learned=(("contenttype", ("contenttype", "name", "value")),),
    ),
    "credit_card": RuleType(
        "appfwprofile_creditcardnumber_binding", ("creditcardnumber", "creditcardnumberurl"), ("creditcardnumberurl",),
        "creditCardNumber",
        learned=(
            ("creditcardnumber", ("creditcardnumber", "name")),
            ("creditcardnumberurl", ("creditcardnumberurl", "creditcardnumberuri", "url")),
        ),
    ),
    "safe_object": RuleType("appfwprofile_safeobject_binding", ("safeobject",)),
    "trusted_learning_client": RuleType("appfwprofile_trustedlearningclients_binding", ("trustedlearningclients",)),
    "xml_dos_url": RuleType("appfwprofile_xmldosurl_binding", ("xmldosurl",), ("xmldosurl",)),
    "xml_wsi_url": RuleType("appfwprofile_xmlwsiurl_binding", ("xmlwsiurl",), ("xmlwsiurl",)),
    "xml_attachment_url": RuleType("appfwprofile_xmlattachmenturl_binding", ("xmlattachmenturl",), ("xmlattachmenturl",)),
    "json_dos_url": RuleType("appfwprofile_jsondosurl_binding", ("jsondosurl",), ("jsondosurl",)),
    "json_sql_url": _json_rule("sql"),
    "json_xss_url": _json_rule("xss"),
    "json_cmd_url": _json_rule("cmd"),
}

# Learned checks without a deployable rule mapping (listed only).
LIST_ONLY_CHECKS = {"xml_dos": "XMLDoSCheck", "xml_wsi": "XMLWSICheck", "xml_attachment": "XMLAttachmentCheck"}

# AppFw answers a duplicate / missing binding with a per-check code rather than only 273 / 258.
EXISTS_CODES = frozenset({
    273, 3198, 3121, 3123, 3125, 3127, 3129, 3131, 3133, 3135, 3229, 3173, 3183, 3218, 3292, 3332, 3364,
    2549, 3582, 3448,
})
MISSING_CODES = frozenset({
    258, 461, 462, 3190, 3201, 3120, 3122, 3124, 3126, 3128, 3130, 3132, 3134, 3228, 3175, 3184, 3219,
    3291, 3316, 3363, 2554, 2553, 3450, 2986,
})


def rule_type(name: str | None) -> str:
    """Validate a rule type name (case-insensitive) and return its key."""
    key = (name or "").strip().lower()
    if key not in RULE_TYPES:
        raise ValueError(f"rule_type must be one of {tuple(RULE_TYPES)}; got {name!r}.")
    return key


def resolve_check(name: str) -> tuple[str | None, str]:
    """Map a rule type or a NITRO securitycheck name to (rule type or None, securitycheck)."""
    key = (name or "").strip().lower()
    for k, rule in RULE_TYPES.items():
        if rule.check and key in (k, rule.check.lower()):
            return k, rule.check
    for k, check in LIST_ONLY_CHECKS.items():
        if key in (k, check.lower()):
            return None, check
    learnable = tuple(k for k, r in RULE_TYPES.items() if r.check) + tuple(LIST_ONLY_CHECKS)
    raise ValueError(f"Not a learned check: {name!r}. Use one of {learnable} or 'all'.")


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---- binding rows ----------------------------------------------------------

# On GET rows but not accepted when binding, or meaningless on another profile/appliance.
_BINDING_DROP = frozenset({"name", "alertonly", "resourceid", "__count", "_nextgenapiresource"})
# Not worth re-binding a rule over (how the rule was created, not what it does).
_COMPARE_IGNORE = frozenset({"isautodeployed"})
_ENUM_ATTR = re.compile(r"ruletype|as_scan_location_\w+|as_value_type_\w+")


def _norm(attr: str, value: Any) -> str:
    """Normalise one identity value: enums compare case-insensitively with NetScaler's defaults applied."""
    text = "" if value is None else str(value).strip()
    if _ENUM_ATTR.fullmatch(attr):
        text = text.lower()
        if not text and attr == "ruletype":
            return "allow"
        if not text and attr.startswith("as_scan_location_"):
            return "formfield"
    return text


def _norm_setting(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, list):
        return sorted(str(v).strip().lower() for v in value)
    return str(value).strip().lower()


def clean_binding(row: dict[str, Any]) -> dict[str, Any]:
    """A binding row's settable, non-empty attributes — what export writes and import binds."""
    return {k: v for k, v in row.items() if k not in _BINDING_DROP and v not in (None, "", [])}


def binding_key(rule: RuleType, row: dict[str, Any]) -> tuple[str, ...]:
    """Identity of a binding (its DELETE args + ruletype), normalised so equal rules compare equal."""
    return tuple(_norm(attr, row.get(attr)) for attr in rule.identity + ("ruletype",))


def row_matches(rule: RuleType, row: dict[str, Any], given: dict[str, Any]) -> bool:
    """True when ``row`` agrees with every identifying attribute in ``given``."""
    return all(
        _norm(attr, row.get(attr)) == _norm(attr, value)
        for attr, value in given.items()
        if attr in rule.identity + ("ruletype",)
    )


def delete_args(rule: RuleType, row: dict[str, Any]) -> dict[str, str]:
    """DELETE args for a binding row as read from the appliance."""
    return {
        attr: str(row[attr]) for attr in rule.identity + ("ruletype",) if row.get(attr) not in (None, "")
    }


def split_bindings(aggregate: dict[str, Any]) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """Split an ``appfwprofile_binding`` object into modelled rule types and other binding arrays."""
    by_binding = {rule.binding: key for key, rule in RULE_TYPES.items()}
    rules: dict[str, list[dict]] = {}
    other: dict[str, list[dict]] = {}
    for attr, rows in aggregate.items():
        if not attr.endswith("_binding"):
            continue
        rows = rows if isinstance(rows, list) else [rows]
        if attr in by_binding:
            rules[by_binding[attr]] = rows
        elif rows:
            other[attr] = rows
    return rules, other


def hosts_in(rules: dict[str, list[dict]]) -> dict[str, int]:
    """Count the hostnames referenced by rule URLs ('*' and relative URLs skipped), most used first."""
    counts: dict[str, int] = {}
    for key, rows in rules.items():
        rule = RULE_TYPES.get(key)
        for row in rows if rule else ():
            for attr in rule.url_attrs:
                host = parse_url_pattern(str(row.get(attr) or ""))["host"]
                if host and host != "*":
                    counts[host] = counts.get(host, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    """Compile AppFw regexes with Python's engine, skipping PCRE-only syntax it can't parse."""
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error:
            continue
    return compiled


def is_covered(pattern: str, allow: list[re.Pattern[str]]) -> bool | None:
    """Whether a learned start URL is already matched by a configured start URL (None = can't tell).

    Samples the concrete URL behind an exact learned pattern; learned patterns that are themselves
    wildcards can't be sampled.
    """
    url = parse_url_pattern(pattern)
    if url["scheme"] not in ("http", "https") or not url["host"] or set(url["path"]) & set("*+[](){}|"):
        return None
    sample = f"{url['scheme']}://{url['host']}{url['path']}"
    return any(rx.match(sample) for rx in allow)


# ---- learned data ------------------------------------------------------------

_LEARNED_DROP = frozenset({"profilename", "securitycheck", "hits", "__count", "_nextgenapiresource"})


def clean_learned(entry: dict[str, Any]) -> dict[str, Any]:
    """The informative, non-empty attributes of a learned entry."""
    return {k: v for k, v in entry.items() if k not in _LEARNED_DROP and v not in (None, "", [])}


def learned_rule(rule: RuleType, entry: dict[str, Any]) -> dict[str, Any]:
    """The binding row a learned entry deploys as ({} when the entry lacks the rule's main value)."""
    row: dict[str, Any] = {}
    for attr, sources in rule.learned:
        for source in sources:
            if entry.get(source) not in (None, ""):
                row[attr] = entry[source]
                break
    return row if row.get(rule.identity[0]) else {}


def learned_delete_args(rule: RuleType, row: dict[str, Any]) -> dict[str, str]:
    """appfwlearningdata DELETE args (besides profilename) for the entry behind a deployed ``row``."""
    pairs = rule.learned_delete or tuple((attr, attr) for attr, _ in rule.learned if attr in rule.identity)
    return {arg: str(row[attr]) for arg, attr in pairs if row.get(attr) not in (None, "")}


# ---- easy rules ---------------------------------------------------------------

EASY_RULES = (
    "allow_url", "allow_static", "deny_url", "allow_sql_field", "allow_xss_field", "allow_cmd_field",
    "allow_field_consistency", "allow_cookie", "allow_csrf", "allow_content_type", "trusted_learning_client",
)
_FIELD_RULES = {
    "allow_sql_field": ("sql_injection", "sqlinjection", "sql"),
    "allow_xss_field": ("cross_site_scripting", "crosssitescripting", "xss"),
    "allow_cmd_field": ("cmd_injection", "cmdinjection", "cmd"),
}
LOCATIONS = ("FORMFIELD", "HEADER", "COOKIE")


def easy_rule(
    rule: str,
    *,
    host: str | None = None,
    path: str = "/",
    match: str = "prefix",
    scheme: str = "https",
    extensions: list[str] | None = None,
    field: str | None = None,
    field_is_regex: bool = False,
    location: str = "FORMFIELD",
    value: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Translate a plain-language rule preset into (rule type, binding row) with correct regexes."""
    if rule not in EASY_RULES:
        raise ValueError(f"rule must be one of {EASY_RULES} or 'raw'; got {rule!r}.")

    def _url() -> str:
        if not host:
            raise ValueError(f"{rule} needs host ('app.example.com', or '*' for any host).")
        exts = extensions or (list(STATIC_EXTENSIONS) if rule == "allow_static" else None)
        return url_regex(host, path, match="prefix" if rule == "allow_static" else match, scheme=scheme, extensions=exts)

    def _field() -> tuple[str, str]:
        name = (field or "").strip()
        if not name:
            raise ValueError(f"{rule} needs field (a form field / cookie name, or '*' for all).")
        if name == "*":
            return ".*", "REGEX"
        return name, "REGEX" if field_is_regex else "NOTREGEX"

    def _value(what: str) -> str:
        if not (value or "").strip():
            raise ValueError(f"{rule} needs value ({what}).")
        return value.strip()

    if rule in ("allow_url", "allow_static"):
        return "start_url", {"starturl": _url()}
    if rule == "deny_url":
        return "deny_url", {"denyurl": _url()}
    if rule in _FIELD_RULES:
        key, attr, suffix = _FIELD_RULES[rule]
        loc = (location or "FORMFIELD").strip().upper()
        if loc not in LOCATIONS:
            raise ValueError(f"location must be one of {LOCATIONS}; got {location!r}.")
        name, regex = _field()
        return key, {
            attr: name, f"formactionurl_{suffix}": _url(), f"isregex_{suffix}": regex,
            f"as_scan_location_{suffix}": loc,
        }
    if rule == "allow_field_consistency":
        name, regex = _field()
        return "field_consistency", {"fieldconsistency": name, "formactionurl_ffc": _url(), "isregex_ffc": regex}
    if rule == "allow_cookie":
        name, regex = _field()
        return "cookie_consistency", {"cookieconsistency": name, "isregex": regex}
    if rule == "allow_csrf":
        origin = _url()
        return "csrf_tag", {"csrftag": origin, "csrfformactionurl": (value or "").strip() or origin}
    if rule == "allow_content_type":
        return "content_type", {"contenttype": _value("a content-type regex, e.g. '^application/json$'")}
    return "trusted_learning_client", {"trustedlearningclients": _value("an IP or CIDR, e.g. '10.0.0.0/24'")}


# ---- check actions --------------------------------------------------------------

CHECK_ACTION_ATTRS = {
    "start_url": "starturlaction", "deny_url": "denyurlaction", "content_type": "contenttypeaction",
    "cookie_consistency": "cookieconsistencyaction", "cookie_hijacking": "cookiehijackingaction",
    "field_consistency": "fieldconsistencyaction", "csrf_tag": "csrftagaction",
    "cross_site_scripting": "crosssitescriptingaction", "sql_injection": "sqlinjectionaction",
    "cmd_injection": "cmdinjectionaction", "field_format": "fieldformataction",
    "buffer_overflow": "bufferoverflowaction", "credit_card": "creditcardaction",
    "file_upload_types": "fileuploadtypesaction", "block_keyword": "blockkeywordaction",
    "xml_dos": "xmldosaction", "xml_format": "xmlformataction", "xml_sql_injection": "xmlsqlinjectionaction",
    "xml_xss": "xmlxssaction", "xml_wsi": "xmlwsiaction", "xml_attachment": "xmlattachmentaction",
    "xml_validation": "xmlvalidationaction", "json_dos": "jsondosaction",
    "json_sql_injection": "jsonsqlinjectionaction", "json_cmd_injection": "jsoncmdinjectionaction",
    "json_xss": "jsonxssaction", "json_block_keyword": "jsonblockkeywordaction",
}
# Checks whose action list may include 'learn' (the rest take none / block / log / stats).
LEARNABLE_CHECKS = frozenset({
    "start_url", "content_type", "cookie_consistency", "field_consistency", "csrf_tag", "cross_site_scripting",
    "sql_injection", "field_format", "credit_card", "xml_dos", "xml_xss", "xml_wsi", "xml_attachment",
})
ACTIONS = ("none", "block", "learn", "log", "stats")


def new_actions(
    check: str,
    current: Any,
    *,
    set_to: list[str] | None = None,
    add: list[str] | None = None,
    remove: list[str] | None = None,
    strict: bool = True,
) -> list[str]:
    """Compute a check's new action list. Non-strict silently drops 'learn' where the check can't learn."""
    def _clean(values: list[str] | None) -> list[str]:
        out = [v.strip().lower() for v in values or [] if v and v.strip()]
        bad = [v for v in out if v not in ACTIONS]
        if bad:
            raise ValueError(f"Unknown action(s) {bad}; use {ACTIONS}.")
        return out

    if set_to is not None:
        result = _clean(set_to)
    else:
        existing = current if isinstance(current, list) else ([current] if current else [])
        result = [a for a in _clean(existing) if a != "none"]
        result += [a for a in _clean(add) if a not in result]
        dropped = set(_clean(remove))
        result = [a for a in result if a not in dropped]
    if "learn" in result and check not in LEARNABLE_CHECKS:
        if strict:
            raise ValueError(f"'{check}' does not support the learn action.")
        result.remove("learn")
    if "none" in result and len(result) > 1:
        raise ValueError("'none' can't be combined with other actions.")
    result = sorted(set(result) or {"none"}, key=ACTIONS.index)
    return result


# ---- export documents & import plans -----------------------------------------------

DOC_FORMAT = "netscaler-mcp/waf-profile"
DOC_VERSION = 1

# appfwprofile attributes GET returns that add/update don't accept (read-only, add-only, restore-only).
_PROFILE_DROP = frozenset({
    "name", "state", "learning", "csrftag", "builtin", "feature", "_nextgenapiresource", "__count", "defaults",
    "archivename", "relaxationrules", "importprofilename", "matchurlstring", "replaceurlstring", "overwrite",
    "augment",
})
_LEARNING_DROP = frozenset({"profilename", "_nextgenapiresource", "__count"})


def clean_settings(obj: dict[str, Any], *, learning: bool = False) -> dict[str, Any]:
    """Settable, non-empty attributes of an appfwprofile (or appfwlearningsettings) object."""
    drop = _LEARNING_DROP if learning else _PROFILE_DROP
    return {k: v for k, v in obj.items() if k not in drop and v not in (None, "", [])}


def settings_changes(desired: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Desired attributes whose value differs from the live object (lists compare order-insensitively)."""
    return {k: v for k, v in desired.items() if _norm_setting(v) != _norm_setting(current.get(k))}


def build_document(
    *,
    profile: str,
    appliance: str,
    exported_at: str,
    settings: dict[str, Any],
    learning_settings: dict[str, Any],
    rules: dict[str, list[dict]],
    other_bindings: dict[str, list[dict]],
) -> dict[str, Any]:
    """Assemble the portable export document for one profile."""
    return {
        "format": DOC_FORMAT,
        "version": DOC_VERSION,
        "exported_at": exported_at,
        "source": {"appliance": appliance, "profile": profile},
        "hosts": hosts_in(rules),
        "settings": clean_settings(settings),
        "learning_settings": clean_settings(learning_settings, learning=True),
        "rules": {k: [clean_binding(r) for r in rows] for k, rows in rules.items() if rows},
        "other_bindings": {k: [clean_binding(r) for r in rows] for k, rows in other_bindings.items() if rows},
    }


def check_document(doc: Any) -> dict[str, Any]:
    """Validate an export document's envelope; returns it unchanged."""
    if not isinstance(doc, dict) or doc.get("format") != DOC_FORMAT:
        raise ValueError(f"Not a netscaler-mcp WAF profile export (expected format {DOC_FORMAT!r}).")
    if doc.get("version") != DOC_VERSION:
        raise ValueError(f"Unsupported document version {doc.get('version')!r} (this server reads {DOC_VERSION}).")
    rules = doc.get("rules")
    if not isinstance(rules, dict) or not all(
        isinstance(rows, list) and all(isinstance(r, dict) for r in rows) for rows in rules.values()
    ):
        raise ValueError("document 'rules' must map rule types to lists of rule objects.")
    unknown = sorted(set(rules) - set(RULE_TYPES))
    if unknown:
        raise ValueError(f"document has unknown rule types {unknown}.")
    return doc


def apply_host_map(doc: dict[str, Any], host_map: dict[str, str]) -> tuple[dict[str, Any], int]:
    """Rewrite hostnames across a document's settings and rules; returns (new doc, replacements made)."""
    rewriter = HostRewriter(host_map)
    out = dict(doc)
    for section in ("settings", "rules", "other_bindings"):
        if section in doc:
            out[section] = rewrite_strings(doc[section], rewriter)
    out["hosts"] = hosts_in(out.get("rules") or {})
    out["host_map_applied"] = {**doc.get("host_map_applied", {}), **rewriter.host_map}
    return out, rewriter.replacements


def plan_bindings(
    desired: dict[str, list[dict]], current: dict[str, list[dict]], *, replace: bool
) -> dict[str, dict[str, Any]]:
    """Diff rules per type into add / update / remove (update and remove only when ``replace``).

    ``desired`` rows are export rows, ``current`` rows raw GET rows. A rule on both sides whose
    settings (state, comment, limits, …) differ is an update; only the desired side's attributes are
    compared, so an import never churns on attributes the document doesn't carry.
    """
    plan: dict[str, dict[str, Any]] = {}
    for key, rule in RULE_TYPES.items():
        want = {binding_key(rule, row): clean_binding(row) for row in desired.get(key, [])}
        have = {binding_key(rule, row): clean_binding(row) for row in current.get(key, [])}
        add = [row for k, row in want.items() if k not in have]
        update: list[dict[str, Any]] = []
        remove: list[dict[str, Any]] = []
        if replace:
            skip = set(rule.identity) | {"ruletype"} | _COMPARE_IGNORE
            for k, row in want.items():
                if k in have and any(
                    _norm_setting(v) != _norm_setting(have[k].get(attr)) for attr, v in row.items() if attr not in skip
                ):
                    update.append({"current": have[k], "desired": row})
            remove = [row for k, row in have.items() if k not in want]
        unchanged = len(want) - len(add) - len(update)
        if add or update or remove:
            plan[key] = {"add": add, "update": update, "remove": remove, "unchanged": unchanged}
    return plan
