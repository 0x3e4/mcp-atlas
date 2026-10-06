"""Bot management (NITRO ``botprofile``) tables and presets — the Bot twin of waf.py.

A bot profile carries its detections two ways: profile-level switches/action lists (device fingerprint,
trap, the signature header checks, spoofed requests) and child bindings holding the entries of the
list-style detections (allow/deny lists, rate limiting, TPS, CAPTCHA, IP-reputation categories, log and
KM expressions, trap URLs). The shared rule/document/plan machinery lives in waf.py; this module only
describes Bot:

- ``RULE_TYPES`` / ``BOT``: the nine child bindings, the attributes a NITRO DELETE needs to identify one
  (bot bindings are keyed by a boolean selector plus the entry value, and have no ``ruletype``), and
  which attributes hold URLs, so export/import and hostname switching work for bot too.
- ``easy_rule``: presets turning plain input (an IP, a CIDR, a URL, a country) into a binding row.
- ``DETECTIONS``: each detection's enable flag, profile-level action attribute and allowed actions.
- ``detection_config`` / ``stat_summary``: shape the config and the flat stat counters for reporting.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from .waf import ProfileKind, RuleType, as_int

# ---- rule types (attribute names per the NetScaler 14.1 NITRO reference) ------


def _rule(binding: str, selector: str, *identity: str, urls: tuple[str, ...] = ()) -> RuleType:
    """A bot child binding: the boolean selector plus the attributes its DELETE args need."""
    return RuleType(
        binding,
        (selector, *identity),
        urls,
        ident_extra=(),  # bot bindings have no ruletype
        comment_attr="bot_bind_comment",
    )


RULE_TYPES: dict[str, RuleType] = {
    "allow_list": _rule("botprofile_whitelist_binding", "bot_whitelist", "bot_whitelist_value"),
    "deny_list": _rule("botprofile_blacklist_binding", "bot_blacklist", "bot_blacklist_value"),
    "rate_limit": _rule(
        "botprofile_ratelimit_binding", "bot_ratelimit", "bot_rate_limit_type", "bot_rate_limit_url",
        "cookiename", "countrycode", "condition", urls=("bot_rate_limit_url",),
    ),
    "tps": _rule("botprofile_tps_binding", "bot_tps", "bot_tps_type"),
    "captcha": _rule(
        "botprofile_captcha_binding", "captcharesource", "bot_captcha_url", urls=("bot_captcha_url",)
    ),
    "ip_reputation": _rule("botprofile_ipreputation_binding", "bot_ipreputation", "category"),
    "log_expression": _rule("botprofile_logexpression_binding", "logexpression", "bot_log_expression_name"),
    "km_expression": _rule("botprofile_kmdetectionexpr_binding", "kmdetectionexpr", "bot_km_expression_name"),
    "trap_url": _rule(
        "botprofile_trapinsertionurl_binding", "trapinsertionurl", "bot_trap_url", urls=("bot_trap_url",)
    ),
}

# Per rule type: the attribute switching one entry on, and its action attribute with allowed values.
ENABLED_ATTRS = {
    "allow_list": "bot_whitelist_enabled",
    "deny_list": "bot_blacklist_enabled",
    "rate_limit": "bot_rate_limit_enabled",
    "tps": "bot_tps_enabled",
    "captcha": "bot_captcha_enabled",
    "ip_reputation": "bot_iprep_enabled",
    "log_expression": "bot_log_expression_enabled",
    "km_expression": "bot_km_detection_enabled",
    "trap_url": "bot_trap_url_insertion_enabled",
}
ENTRY_ACTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "deny_list": ("bot_blacklist_action", ("NONE", "LOG", "DROP", "RESET", "REDIRECT")),
    "rate_limit": (
        "bot_rate_limit_action",
        ("NONE", "LOG", "DROP", "REDIRECT", "RESET", "RESPOND_STATUS_TOO_MANY_REQUESTS"),
    ),
    "tps": ("bot_tps_action", ("NONE", "LOG", "DROP", "REDIRECT", "RESET", "MITIGATION")),
    "captcha": ("bot_captcha_action", ("NONE", "LOG", "DROP", "REDIRECT", "RESET")),
    "ip_reputation": ("bot_iprep_action", ("NONE", "LOG", "DROP", "REDIRECT", "RESET", "MITIGATION")),
}

# botprofile attributes a GET returns but add/update reject.
_PROFILE_DROP = frozenset({"name", "builtin", "feature", "_nextgenapiresource", "__count"})

BOT = ProfileKind(
    key="bot",
    label="Bot",
    profile="botprofile",
    aggregate="botprofile_binding",
    policy="botpolicy",
    types=RULE_TYPES,
    doc_format="netscaler-mcp/bot-profile",
    profile_drop=_PROFILE_DROP,
)

IP_LIST_TYPES = ("IPv4", "IPv6", "SUBNET", "IPv6_SUBNET", "EXPRESSION")
RATE_LIMIT_TYPES = ("SESSION", "SOURCE_IP", "URL", "GEOLOCATION", "JA3_FINGERPRINT")
TPS_TYPES = ("SOURCE_IP", "GEOLOCATION", "REQUEST_URL", "Host")
IP_REPUTATION_CATEGORIES = (
    "IP", "BOTNETS", "SPAM_SOURCES", "SCANNERS", "DOS", "REPUTATION", "PHISHING", "PROXY", "NETWORK",
    "MOBILE_THREATS", "WINDOWS_EXPLOITS", "WEB_ATTACKS", "TOR_PROXY", "CLOUD", "CLOUD_AWS", "CLOUD_GCP",
    "CLOUD_AZURE", "CLOUD_ORACLE", "CLOUD_IBM", "CLOUD_SALESFORCE",
)


def ip_list_type(value: str) -> str:
    """Classify an allow/deny list value as IPv4 / IPv6 / SUBNET / IPv6_SUBNET (rejects non-addresses)."""
    text = (value or "").strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(
            f"{text!r} is not an IP address or CIDR; use allow_expression / block_expression for a "
            f"policy expression. ({exc})"
        ) from exc
    subnet = "/" in text
    if network.version == 6:
        return "IPv6_SUBNET" if subnet else "IPv6"
    return "SUBNET" if subnet else "IPv4"


# ---- easy rules ---------------------------------------------------------------

EASY_RULES = (
    "allow_ip", "allow_expression", "block_ip", "block_expression", "rate_limit_url",
    "rate_limit_source_ip", "rate_limit_session", "rate_limit_geo", "tps_source_ip", "tps_url", "tps_geo",
    "tps_host", "captcha", "ip_reputation", "trap_url", "log_expression", "km_expression",
)
_LIST_RULES = {
    "allow_ip": ("allow_list", "bot_whitelist", False),
    "allow_expression": ("allow_list", "bot_whitelist", True),
    "block_ip": ("deny_list", "bot_blacklist", False),
    "block_expression": ("deny_list", "bot_blacklist", True),
}
_RATE_LIMIT_RULES = {
    "rate_limit_url": "URL",
    "rate_limit_source_ip": "SOURCE_IP",
    "rate_limit_session": "SESSION",
    "rate_limit_geo": "GEOLOCATION",
}
_TPS_RULES = {"tps_source_ip": "SOURCE_IP", "tps_url": "REQUEST_URL", "tps_geo": "GEOLOCATION", "tps_host": "Host"}


def entry_actions(key: str, actions: list[str] | None, default: tuple[str, ...]) -> dict[str, Any]:
    """Validate an entry's action list against its rule type (empty → the preset's default)."""
    if key not in ENTRY_ACTIONS:
        if actions:
            raise ValueError(f"{key} entries carry no action; it is set per detection on the profile.")
        return {}
    attr, allowed = ENTRY_ACTIONS[key]
    chosen = [a.strip().upper() for a in (actions or default) if a and a.strip()]
    bad = [a for a in chosen if a not in allowed]
    if bad:
        raise ValueError(f"{key} action(s) {bad} invalid; use {allowed}.")
    if "NONE" in chosen and len(chosen) > 1:
        raise ValueError("'NONE' can't be combined with other actions.")
    return {attr: chosen}


def easy_rule(
    rule: str,
    *,
    value: str | None = None,
    url: str | None = None,
    expression: str | None = None,
    name: str | None = None,
    country: str | None = None,
    cookie: str | None = None,
    category: str | None = None,
    actions: list[str] | None = None,
    rate: int | None = None,
    timeslice: int | None = None,
    threshold: int | None = None,
    percentage: int | None = None,
    log: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Translate a plain-language bot rule preset into (rule type, binding row)."""
    if rule not in EASY_RULES:
        raise ValueError(f"rule must be one of {EASY_RULES} or 'raw'; got {rule!r}.")

    def _need(what: str, given: str | None) -> str:
        if not (given or "").strip():
            raise ValueError(f"{rule} needs {what}.")
        return given.strip()

    def _path(what: str, given: str | None) -> str:
        text = _need(what, given)
        if not text.startswith(("/", "^")) and "://" not in text:
            raise ValueError(f"{rule}: {what} should be a path starting with '/' (got {text!r}).")
        return text

    if rule in _LIST_RULES:
        key, selector, is_expression = _LIST_RULES[rule]
        if is_expression:
            entry, kind = _need("expression (a NetScaler policy expression)", expression or value), "EXPRESSION"
        else:
            entry = _need("value (an IP address or CIDR)", value)
            kind = ip_list_type(entry)
        prefix = selector  # bot_whitelist / bot_blacklist
        row: dict[str, Any] = {
            selector: True,
            f"{prefix}_type": kind,
            f"{prefix}_value": entry,
            ENABLED_ATTRS[key]: "ON",
        }
        if key == "allow_list":
            row["log"] = "ON" if log else "OFF"
        row.update(entry_actions(key, actions, ("DROP",)))
        return key, row

    if rule in _RATE_LIMIT_RULES:
        kind = _RATE_LIMIT_RULES[rule]
        row = {
            "bot_ratelimit": True,
            "bot_rate_limit_type": kind,
            "rate": int(rate) if rate is not None else 100,
            "timeslice": int(timeslice) if timeslice is not None else 1000,
            ENABLED_ATTRS["rate_limit"]: "ON",
        }
        if kind == "URL":
            row["bot_rate_limit_url"] = _path("url (the URL to limit)", url or value)
        elif kind == "SESSION":
            row["cookiename"] = _need("cookie (the session cookie name)", cookie or value)
        elif kind == "GEOLOCATION":
            row["countrycode"] = _need("country (an ISO country code)", country or value).upper()
        row.update(entry_actions("rate_limit", actions, ("DROP",)))
        return "rate_limit", row

    if rule in _TPS_RULES:
        row = {
            "bot_tps": True,
            "bot_tps_type": _TPS_RULES[rule],
            ENABLED_ATTRS["tps"]: "ON",
        }
        if threshold is None and percentage is None:
            raise ValueError(f"{rule} needs threshold (requests per second) and/or percentage (rise over average).")
        if threshold is not None:
            row["threshold"] = int(threshold)
        if percentage is not None:
            row["percentage"] = int(percentage)
        row.update(entry_actions("tps", actions, ("LOG",)))
        return "tps", row

    if rule == "captcha":
        row = {
            "captcharesource": True,
            "bot_captcha_url": _path("url (the URL to protect with a CAPTCHA)", url or value),
            ENABLED_ATTRS["captcha"]: "ON",
        }
        row.update(entry_actions("captcha", actions, ("DROP",)))
        return "captcha", row

    if rule == "ip_reputation":
        chosen = _need("category", category or value).strip().upper()
        if chosen not in IP_REPUTATION_CATEGORIES:
            raise ValueError(f"category must be one of {IP_REPUTATION_CATEGORIES}; got {chosen!r}.")
        row = {"bot_ipreputation": True, "category": chosen, ENABLED_ATTRS["ip_reputation"]: "ON"}
        row.update(entry_actions("ip_reputation", actions, ("DROP",)))
        return "ip_reputation", row

    if rule == "trap_url":
        return "trap_url", {
            "trapinsertionurl": True,
            "bot_trap_url": _path("url (the trap URL, e.g. '/trap')", url or value),
            ENABLED_ATTRS["trap_url"]: "ON",
        }

    key = "log_expression" if rule == "log_expression" else "km_expression"
    prefix = "bot_log_expression" if key == "log_expression" else "bot_km_expression"
    selector = "logexpression" if key == "log_expression" else "kmdetectionexpr"
    return key, {
        selector: True,
        f"{prefix}_name": _need("name (a name for the expression)", name or value),
        f"{prefix}_value": _need("expression", expression),
        ENABLED_ATTRS[key]: "ON",
    }


# ---- detections --------------------------------------------------------------


@dataclass(frozen=True)
class Detection:
    """One bot detection: its profile switch, its profile-level action list (if any) and its entries."""

    enable: str | None  # profile attribute switching it ON/OFF
    action: str | None  # profile attribute holding the action list
    actions: tuple[str, ...] = ()  # allowed action values
    rule_type: str | None = None  # rule type whose bindings hold this detection's entries


_ACT = ("NONE", "LOG", "DROP", "REDIRECT", "RESET")
DETECTIONS: dict[str, Detection] = {
    "allow_list": Detection("bot_enable_white_list", None, (), "allow_list"),
    "deny_list": Detection("bot_enable_black_list", None, (), "deny_list"),
    "rate_limit": Detection("bot_enable_rate_limit", None, (), "rate_limit"),
    "tps": Detection("bot_enable_tps", None, (), "tps"),
    "ip_reputation": Detection("bot_enable_ip_reputation", None, (), "ip_reputation"),
    "device_fingerprint": Detection("devicefingerprint", "devicefingerprintaction", (*_ACT, "MITIGATION")),
    "trap": Detection("trap", "trapaction", _ACT, "trap_url"),
    "km_detection": Detection("kmdetection", None, (), "km_expression"),
    "headless_browser": Detection("headlessbrowserdetection", None, ()),
    "signature_no_user_agent": Detection(None, "signaturenouseragentheaderaction", _ACT),
    "signature_multiple_user_agent": Detection(
        None, "signaturemultipleuseragentheaderaction", ("CHECKLAST", "LOG", "DROP", "REDIRECT", "RESET")
    ),
    "spoofed_request": Detection(None, "spoofedreqaction", _ACT),
}


def detection(name: str | None) -> str:
    """Validate a detection name (case-insensitive) and return its key."""
    key = (name or "").strip().lower()
    if key not in DETECTIONS:
        raise ValueError(f"detection must be one of {tuple(DETECTIONS)} or 'all'; got {name!r}.")
    return key


def detection_actions(name: str, actions: list[str]) -> list[str]:
    """Validate an action list against one detection's allowed values."""
    spec = DETECTIONS[name]
    if not spec.action:
        raise ValueError(
            f"'{name}' has no profile-level action; its action is set per entry with add_bot_rule."
        )
    chosen = [a.strip().upper() for a in actions if a and a.strip()]
    bad = [a for a in chosen if a not in spec.actions]
    if bad:
        raise ValueError(f"'{name}' action(s) {bad} invalid; use {spec.actions}.")
    if "NONE" in chosen and len(chosen) > 1:
        raise ValueError("'NONE' can't be combined with other actions.")
    return chosen or ["NONE"]


def detection_config(settings: dict[str, Any], entries: dict[str, int]) -> dict[str, dict[str, Any]]:
    """Per detection: its switch, its action list (or where the action lives) and how many entries it has."""
    out: dict[str, dict[str, Any]] = {}
    for key, spec in DETECTIONS.items():
        row: dict[str, Any] = {}
        if spec.enable:
            row["enabled"] = settings.get(spec.enable)
        if spec.action:
            row["action"] = settings.get(spec.action)
        elif spec.rule_type:
            row["action"] = "per entry (list_bot_rules)"
        if spec.rule_type:
            row["entries"] = entries.get(spec.rule_type, 0)
        out[key] = row
    return out


# ---- statistics ---------------------------------------------------------------

_TRAFFIC_COUNTERS = {
    "botrequests": "requests", "botreqbytes": "request_bytes", "botresponses": "responses",
    "botresbytes": "response_bytes", "bottotallog": "total_logged", "bottotaldrop": "total_dropped",
    "bottotalredirect": "total_redirected", "bottotalreset": "total_reset",
}
_DETECTION_COUNTER = re.compile(
    r"^botviol(?P<detection>devicefingerprint|ipreputation|whitelist|blacklist|ratelimit|staticsignature"
    r"|tps|captcha|trap)(?P<outcome>log|drop|redirect|reset|captcha|exceededresponse)?$"
)


def stat_summary(stats: dict[str, Any]) -> dict[str, Any]:
    """Bucket the flat ``stat bot`` / ``stat botprofile`` counters for reporting.

    Both resources use the same counter names with a ``profile`` / ``perprofile`` suffix per profile, and
    every counter has a ``…rate`` twin that is skipped here. Zero detection counters are dropped so the
    result shows what is actually firing.
    """
    traffic: dict[str, int] = {}
    detections: dict[str, dict[str, int]] = {}
    configured: dict[str, int] = {}
    for key, value in stats.items():
        if key.endswith("rate"):
            continue
        count = as_int(value)
        if count is None:
            continue
        base = key.removesuffix("perprofile").removesuffix("profile")
        if base in _TRAFFIC_COUNTERS:
            traffic[_TRAFFIC_COUNTERS[base]] = count
            continue
        if base.startswith("botcfg"):
            configured[base.removeprefix("botcfg")] = count
            continue
        match = _DETECTION_COUNTER.match(base)
        if match and count:
            detections.setdefault(match["detection"], {})[match["outcome"] or "total"] = count
    return {
        "traffic": traffic,
        "detections": dict(sorted(detections.items(), key=lambda kv: -max(kv[1].values(), default=0))),
        "configured": {k: v for k, v in sorted(configured.items()) if v},
    }
