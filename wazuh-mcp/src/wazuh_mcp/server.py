"""FastMCP server exposing Wazuh tools over stdio (or streamable-http).

Events (alerts/archives/vulnerabilities) are queried from the Wazuh Indexer; agents,
inventory, rules, SCA and status come from the Manager REST API. Two raw escape-hatch
tools (``indexer_search``, ``manager_api_get``) make anything else reachable (read-only).

Write tools (restart agents, assign/unassign agent groups, run an active-response command)
go to the Manager API only, never the Indexer, and are **opt-in**: they refuse unless
``WAZUH_ALLOW_WRITE=true`` and the API user's RBAC role allows the action. Unless
``WAZUH_CONFIRM_WRITE=false``, every write first returns a preview plus a confirm code and
only runs when called again with that code, after the user has confirmed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from contextlib import asynccontextmanager
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .config import Settings, WazuhError
from .indexer import IndexerClient
from .manager import ManagerClient

settings = Settings.from_env()

_manager: ManagerClient | None = None
_indexer: IndexerClient | None = None


def manager() -> ManagerClient:
    global _manager
    if _manager is None:
        _manager = ManagerClient(settings)
    return _manager


def indexer() -> IndexerClient:
    global _indexer
    if _indexer is None:
        _indexer = IndexerClient(settings)
    return _indexer


@asynccontextmanager
async def lifespan(_server: FastMCP):
    try:
        yield {}
    finally:
        if _manager is not None:
            await _manager.aclose()
        if _indexer is not None:
            await _indexer.aclose()


mcp = FastMCP(
    "wazuh",
    instructions=(
        "Write tools (restart_agents, add_agent_to_group, remove_agent_from_group, run_active_response) "
        "need the user's confirmation: the first call changes nothing and returns a preview with a "
        "confirm_code. Show the user a short overview of what will change, end with 'Confirm it?', and "
        "only after they say yes repeat the call with confirm=<code>."
    ),
    lifespan=lifespan,
    host=settings.host,
    port=settings.port,
)


# --------------------------------------------------------------------------- helpers

MAX_LIMIT = 500

# Default trimmed field sets, kept compact so large event docs don't flood the agent.
ALERT_FIELDS = [
    "timestamp", "agent.id", "agent.name", "rule.id", "rule.level",
    "rule.description", "rule.groups", "location", "decoder.name", "full_log",
]
ARCHIVE_FIELDS = [
    "timestamp", "agent.id", "agent.name", "decoder.name", "location",
    "program_name", "full_log", "data",
]
VULN_FIELDS = [
    "agent.id", "agent.name", "vulnerability.id", "vulnerability.severity",
    "vulnerability.score.base", "package.name", "package.version", "vulnerability.published",
]


def _clamp(value: int, default: int = 50, cap: int = MAX_LIMIT) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, cap))


def _aid(agent_id: str) -> str:
    """Normalise an agent id: numeric ids are zero-padded to 3 digits (1 -> 001)."""
    a = str(agent_id).strip()
    return a.zfill(3) if a.isdigit() else a


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _range(start: str, end: str) -> dict:
    return {"range": {settings.time_field: {"gte": start or "now-24h", "lte": end or "now"}}}


def _text(query: str) -> dict:
    # simple_query_string tolerates arbitrary user input without throwing on bad syntax.
    return {"simple_query_string": {"query": query, "default_operator": "and"}}


def _agent_filter(agent: str) -> dict:
    agent = agent.strip()
    if agent.isdigit():
        return {"term": {"agent.id": agent.zfill(3)}}
    return {
        "bool": {
            "should": [
                {"term": {"agent.id": agent}},
                {"match": {"agent.name": agent}},
            ],
            "minimum_should_match": 1,
        }
    }


def _pick(source: dict, fields: list[str]) -> dict:
    """Project a (possibly nested) ``_source`` down to the given dotted field paths."""
    out: dict[str, Any] = {}
    for field in fields:
        cur: Any = source
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur is not None:
            out[field] = cur
    return out


def _hits(resp: dict, fields: list[str], full: bool) -> dict:
    hits = resp.get("hits", {}).get("hits", [])
    total = resp.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value")
    results = [h.get("_source", {}) if full else _pick(h.get("_source", {}), fields) for h in hits]
    return {"total": total, "count": len(results), "results": results}


def _affected(data: dict) -> dict:
    """Unwrap the Manager API ``{"data": {"affected_items": [...]}}`` envelope."""
    d = data.get("data", {})
    out = {
        "total": d.get("total_affected_items"),
        "count": len(d.get("affected_items", [])),
        "results": d.get("affected_items", []),
    }
    if d.get("failed_items"):
        out["failed"] = d["failed_items"]
    return out


async def _indexer_search(index: str, filters: list[dict], must: list[dict] | None,
                          size: int, aggs: dict | None = None, sort: bool = True) -> dict:
    bool_query: dict[str, Any] = {"filter": filters}
    if must:
        bool_query["must"] = must
    body: dict[str, Any] = {"query": {"bool": bool_query}, "size": 0 if aggs else size}
    if aggs:
        body["aggs"] = aggs
    elif sort:
        body["sort"] = [{settings.time_field: {"order": "desc"}}]
    return await indexer().search(index, body)


# ----------------------------------------------------------------- event tools (Indexer)


@mcp.tool()
async def search_alerts(query: str = "", agent: str = "", rule_level_min: int = 0,
                        groups: str = "", start: str = "", end: str = "",
                        limit: int = 50, full: bool = False) -> dict:
    """Search Wazuh ALERTS (rule-triggered security events) in wazuh-alerts-*.

    query: free text matched across alert fields (an IP, username, keyword, ...).
    agent: agent id ("001") or name to filter by.
    rule_level_min: only alerts whose rule.level is >= this value.
    groups: comma-separated rule groups (e.g. "authentication,sshd").
    start/end: time window, ISO8601 or relative like "now-1h" (default: last 24h).
    limit: max results (default 50, max 500). full: return raw documents when true.
    """
    filters = [_range(start, end)]
    if agent:
        filters.append(_agent_filter(agent))
    if rule_level_min:
        filters.append({"range": {"rule.level": {"gte": int(rule_level_min)}}})
    if groups:
        filters.append({"terms": {"rule.groups": _csv(groups)}})
    must = [_text(query)] if query else None
    resp = await _indexer_search(settings.alerts_index, filters, must, _clamp(limit))
    return _hits(resp, ALERT_FIELDS, full)


@mcp.tool()
async def search_archives(query: str = "", agent: str = "", decoder: str = "",
                          location: str = "", start: str = "", end: str = "",
                          limit: int = 50, full: bool = False) -> dict:
    """Search the Wazuh ARCHIVES in wazuh-archives-*: ALL collected events, including
    those that did NOT trigger any rule/alert. This is the full event firehose.

    query: free text across event fields. agent: id or name. decoder: decoder.name to filter.
    location: log source (e.g. "/var/log/auth.log"). start/end: time window (ISO8601 or
    relative like "now-1h", default last 24h). limit: max (default 50, max 500).
    full: return raw documents when true.
    """
    filters = [_range(start, end)]
    if agent:
        filters.append(_agent_filter(agent))
    if decoder:
        filters.append({"term": {"decoder.name": decoder}})
    if location:
        filters.append({"match_phrase": {"location": location}})
    must = [_text(query)] if query else None
    resp = await _indexer_search(settings.archives_index, filters, must, _clamp(limit))
    return _hits(resp, ARCHIVE_FIELDS, full)


@mcp.tool()
async def alerts_summary(by: str = "rule", start: str = "", end: str = "", top: int = 20) -> dict:
    """Aggregate alerts over a time window to see what is noisy.

    by: "rule" (top rule descriptions), "agent" (top agents), or "level" (counts per level).
    start/end: time window (default last 24h). top: number of buckets (default 20).
    """
    field = {"rule": "rule.description", "agent": "agent.name", "level": "rule.level"}.get(by)
    if field is None:
        raise ValueError('by must be one of: "rule", "agent", "level"')
    aggs = {"summary": {"terms": {"field": field, "size": _clamp(top, 20, 100)}}}
    resp = await _indexer_search(settings.alerts_index, [_range(start, end)], None, 0, aggs=aggs)
    buckets = resp.get("aggregations", {}).get("summary", {}).get("buckets", [])
    return {
        "by": by,
        "field": field,
        "buckets": [{"key": b["key"], "count": b["doc_count"]} for b in buckets],
    }


@mcp.tool()
async def get_vulnerabilities(agent: str = "", severity: str = "", cve: str = "",
                              limit: int = 50, full: bool = False) -> dict:
    """List detected vulnerabilities from wazuh-states-vulnerabilities-* (Wazuh 4.8+).

    agent: id or name. severity: "Critical", "High", "Medium", or "Low" (case-sensitive).
    cve: a CVE id (e.g. "CVE-2021-44228"). limit: max (default 50). full: raw docs when true.
    """
    filters: list[dict] = []
    if agent:
        filters.append(_agent_filter(agent))
    if severity:
        filters.append({"term": {"vulnerability.severity": severity}})
    if cve:
        filters.append({"term": {"vulnerability.id": cve}})
    if not filters:
        filters.append({"match_all": {}})
    body = {"query": {"bool": {"filter": filters}}, "size": _clamp(limit)}
    resp = await indexer().search(settings.vulns_index, body)
    return _hits(resp, VULN_FIELDS, full)


@mcp.tool()
async def indexer_search(index_pattern: str, dsl: dict) -> dict:
    """Run a raw OpenSearch Query DSL request against any Wazuh index (escape hatch).

    index_pattern: e.g. "wazuh-alerts-*", "wazuh-archives-*", "wazuh-states-vulnerabilities-*".
    dsl: a full search body, e.g. {"query": {...}, "size": 20, "aggs": {...}}.
    Returns the raw OpenSearch response. Note the 10,000 max_result_window limit per search.
    """
    if not isinstance(dsl, dict):
        raise ValueError("dsl must be a JSON object (an OpenSearch search body)")
    return await indexer().search(index_pattern, dsl)


# ---------------------------------------------------- management tools (Manager API)


@mcp.tool()
async def list_agents(status: str = "", name: str = "", os: str = "", limit: int = 100) -> dict:
    """List Wazuh agents with connection status and basic info.

    status: "active", "disconnected", "never_connected", or "pending" (comma-separate to combine).
    name: substring search on agent name. os: filter by OS platform (e.g. "ubuntu", "windows").
    limit: max agents (default 100, max 500).
    """
    params: dict[str, Any] = {
        "limit": _clamp(limit, 100),
        "select": "id,name,ip,status,os.platform,os.name,os.version,version,"
                  "lastKeepAlive,node_name,group",
        "sort": "id",
    }
    if status:
        params["status"] = ",".join(_csv(status))
    if name:
        params["search"] = name
    if os:
        params["os.platform"] = os
    return _affected(await manager().get("/agents", params=params))


_SYSCOLLECTOR = ("packages", "ports", "processes", "hardware", "os",
                 "netaddr", "netiface", "hotfixes")


@mcp.tool()
async def get_agent_inventory(agent_id: str, kind: str = "packages", limit: int = 100) -> dict:
    """Get syscollector inventory for one agent.

    agent_id: e.g. "001". kind: one of packages, ports, processes, hardware, os,
    netaddr, netiface, hotfixes. limit: max rows for list kinds (default 100).
    """
    if kind not in _SYSCOLLECTOR:
        raise ValueError(f"kind must be one of: {', '.join(_SYSCOLLECTOR)}")
    params = {"limit": _clamp(limit, 100)}
    data = await manager().get(f"/syscollector/{_aid(agent_id)}/{kind}", params=params)
    return _affected(data)


@mcp.tool()
async def get_sca(agent_id: str, policy: str = "", limit: int = 100) -> dict:
    """Security Configuration Assessment (SCA) results for one agent.

    agent_id: e.g. "001". policy: a policy id (e.g. "cis_debian10") to list its individual
    checks; omit to list the agent's policies and pass/fail scores. limit: max (default 100).
    """
    aid = _aid(agent_id)
    params = {"limit": _clamp(limit, 100)}
    path = f"/sca/{aid}/checks/{policy}" if policy else f"/sca/{aid}"
    return _affected(await manager().get(path, params=params))


@mcp.tool()
async def search_rules(query: str = "", level: int = 0, group: str = "", limit: int = 50) -> dict:
    """Search the Wazuh ruleset.

    query: text search across rule fields. level: exact rule level to filter.
    group: a rule group (e.g. "sshd"). limit: max rules (default 50).
    """
    params: dict[str, Any] = {"limit": _clamp(limit), "sort": "id"}
    if query:
        params["search"] = query
    if level:
        params["level"] = int(level)
    if group:
        params["group"] = group
    return _affected(await manager().get("/rules", params=params))


@mcp.tool()
async def manager_status() -> dict:
    """Overall health: manager daemon status, manager info/version, and cluster health."""
    out: dict[str, Any] = {
        "daemons": (await manager().get("/manager/status")).get("data", {}).get("affected_items", []),
        "info": (await manager().get("/manager/info")).get("data", {}).get("affected_items", []),
    }
    try:
        out["cluster"] = (await manager().get("/cluster/healthcheck")).get("data", {})
    except WazuhError:
        out["cluster"] = "cluster disabled or unavailable"
    return out


@mcp.tool()
async def manager_api_get(path: str, params: dict | None = None) -> dict:
    """Raw GET against any Wazuh Manager API endpoint (escape hatch for anything not covered).

    path: API path starting with "/", e.g. "/agents/summary/status", "/decoders",
    "/mitre/techniques", "/manager/logs". params: optional query parameters as a dict.
    Returns the raw JSON. Reference: https://documentation.wazuh.com/current/user-manual/api/reference.html
    """
    if not path.startswith("/"):
        path = "/" + path
    return await manager().get(path, params=params or None)


# ------------------------------------- write tools (Manager API, opt-in via WAZUH_ALLOW_WRITE)


def _require_write() -> None:
    """Gate write tools behind the opt-in WAZUH_ALLOW_WRITE flag."""
    if not settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set WAZUH_ALLOW_WRITE=true (and give the Manager API user a "
            "role that allows the action) to restart agents, change agent groups or run active responses."
        )


# Per-process key: confirm codes are bound to one tool + its exact arguments and die with a restart.
_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(tool: str, change: dict[str, Any], summary: str, code: str | None) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when WAZUH_CONFIRM_WRITE=false, or when ``code`` matches this exact
    tool + change (so what runs is what the user saw).
    """
    if not settings.confirm_write:
        return None
    raw = json.dumps([tool, change], sort_keys=True, default=str).encode()
    expected = hmac.new(_CONFIRM_KEY, raw, hashlib.sha256).hexdigest()[:12]
    if code and hmac.compare_digest(code.strip(), expected):
        return None
    out: dict[str, Any] = {
        "status": "confirmation_required",
        "changed": False,
        "summary": summary,
        "change": change,
        "confirm_code": expected,
        "next": (
            "Show the user a short overview of this change and end with 'Confirm it?'. Only after they "
            f"confirm, call {tool} again with the same arguments and confirm='{expected}'."
        ),
    }
    if code:
        out["note"] = "The confirm code did not match these arguments (changed, expired or restarted) — confirm again."
    return out


# Wazuh's group_names format: a-z, A-Z, 0-9, '_', '-', '.' (max 128; '.' and '..' are reserved).
_GROUP_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
# Active-response command: a command name from the manager's ar.conf (e.g. "firewall-drop0") or "!<script>".
_AR_COMMAND_RE = re.compile(r"^!?[A-Za-z0-9_.-]{1,128}$")


def _agent_ids(agent_ids: list[str], *, allow_manager: bool = False) -> list[str]:
    """Validate + normalise explicit agent ids. Never empty: an omitted agents_list means ALL agents."""
    ids: list[str] = []
    for item in agent_ids or []:
        for raw in _csv(str(item)):
            aid = _aid(raw)
            if not aid.isdigit():
                raise ValueError(f"Invalid agent id {raw!r}: use numeric ids like '001' (see list_agents).")
            if aid == "000" and not allow_manager:
                raise ValueError("Agent 000 is the Wazuh manager itself, not an agent — leave it out.")
            if aid not in ids:
                ids.append(aid)
    if not ids:
        raise ValueError("Give at least one agent id (the API would otherwise target ALL agents).")
    return ids


def _group(group_id: str) -> str:
    group_id = (group_id or "").strip()
    if not _GROUP_RE.match(group_id) or group_id in (".", ".."):
        raise ValueError(f"Invalid group name {group_id!r}: use letters, digits, '_', '-', '.' (max 128).")
    return group_id


def _written(data: dict) -> dict:
    """Trim a Manager write response: affected/failed items (if any) plus the API message."""
    out = _affected(data) if isinstance(data.get("data"), dict) else {}
    if data.get("message"):
        out["message"] = data["message"]
    return out


@mcp.tool()
async def restart_agents(
    agent_ids: Annotated[list[str], Field(description="Agent ids to restart, e.g. ['001', '005']. Required, never empty.")],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict:
    """Restart the Wazuh agent service on one or more agents (WRITE — requires WAZUH_ALLOW_WRITE).

    PUTs /agents/restart?agents_list=... . Restarts the agent daemon only (not the host), e.g. to
    apply a changed group config. Only active agents can be restarted; others come back under
    "failed". Needs RBAC action agent:restart.
    """
    _require_write()
    ids = _agent_ids(agent_ids)
    params = {"agents_list": ",".join(ids)}
    if preview := _confirm("restart_agents", {"agents_list": ids},
                           f"Restart the Wazuh agent service on agent(s) {', '.join(ids)}.", confirm):
        return preview
    return _written(await manager().put("/agents/restart", params=params))


@mcp.tool()
async def add_agent_to_group(
    agent_id: Annotated[str, Field(description="Agent id, e.g. '001'.")],
    group_id: Annotated[str, Field(description="Existing group name, e.g. 'webservers' (the group must already exist).")],
    exclusive: Annotated[bool, Field(description="Remove the agent from all its other groups first (move instead of add).")] = False,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict:
    """Assign an agent to a group (WRITE — requires WAZUH_ALLOW_WRITE).

    PUTs /agents/{agent_id}/group/{group_id} (with force_single_group=true when exclusive). The
    agent then pulls that group's shared config (agent.conf). The group must already exist.
    Undo with remove_agent_from_group. Needs RBAC actions agent:modify_group + group:modify_assignments.
    """
    _require_write()
    aid = _agent_ids([agent_id])[0]
    group = _group(group_id)
    params = {"force_single_group": "true"} if exclusive else None
    change: dict[str, Any] = {"agent_id": aid, "group_id": group}
    if exclusive:
        change["force_single_group"] = True
    summary = (f"Move agent {aid} into group '{group}' only (removing it from its other groups)."
               if exclusive else f"Add agent {aid} to group '{group}'.")
    if preview := _confirm("add_agent_to_group", change, summary, confirm):
        return preview
    return _written(await manager().put(f"/agents/{aid}/group/{group}", params=params))


@mcp.tool()
async def remove_agent_from_group(
    agent_id: Annotated[str, Field(description="Agent id, e.g. '001'.")],
    group_id: Annotated[str, Field(description="Group name to unassign the agent from.")],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict:
    """Unassign an agent from one group (WRITE — requires WAZUH_ALLOW_WRITE).

    DELETEs /agents/{agent_id}/group/{group_id}. Deletes nothing: the agent and the group stay;
    only this assignment is removed (other groups are kept). If it was the agent's last group,
    Wazuh reassigns it to 'default'. Needs RBAC actions agent:modify_group + group:modify_assignments.
    """
    _require_write()
    aid = _agent_ids([agent_id])[0]
    group = _group(group_id)
    if preview := _confirm("remove_agent_from_group", {"agent_id": aid, "group_id": group},
                           f"Remove agent {aid} from group '{group}' (agent and group are kept).", confirm):
        return preview
    return _written(await manager().delete(f"/agents/{aid}/group/{group}"))


@mcp.tool()
async def run_active_response(
    agent_ids: Annotated[list[str], Field(description="Agent ids to run the command on, e.g. ['001']. Required, never empty.")],
    command: Annotated[str, Field(description="A command name from the manager's active-response config as listed in ar.conf (e.g. 'firewall-drop0'), or '!<script>' to run an AR script by name (e.g. '!firewall-drop').")],
    arguments: Annotated[list[str] | None, Field(description="Extra arguments passed to the script (extra_args).")] = None,
    alert_data: Annotated[dict[str, Any] | None, Field(description="Alert fields the script reads, sent as alert.data, e.g. {'srcip': '10.0.0.10'} for firewall-drop / host-deny.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict:
    """Run an active-response command on agents (WRITE — requires WAZUH_ALLOW_WRITE). PUTs /active-response.

    DANGER: this executes a script on the endpoint(s). Depending on the command it can block an IP
    in the host firewall (firewall-drop, host-deny, netsh, route-null), disable an account, kill
    processes or restart Wazuh. Stateful commands are undone only by their timeout or by hand.
    The agent must be active with active response enabled. Needs RBAC action active-response:command.
    """
    _require_write()
    ids = _agent_ids(agent_ids, allow_manager=True)
    command = (command or "").strip()
    if not _AR_COMMAND_RE.match(command):
        raise ValueError(f"Invalid active-response command {command!r}: e.g. 'firewall-drop0' or '!firewall-drop'.")
    if alert_data is not None and not isinstance(alert_data, dict):
        raise ValueError("alert_data must be a JSON object, e.g. {'srcip': '10.0.0.10'}.")
    body: dict[str, Any] = {"command": command}
    if arguments:
        body["arguments"] = [str(a) for a in arguments]
    if alert_data:
        body["alert"] = {"data": alert_data}
    params = {"agents_list": ",".join(ids)}
    extra = []
    if arguments:
        extra.append(f"arguments {body['arguments']}")
    if alert_data:
        extra.append(f"alert data {json.dumps(alert_data, sort_keys=True)}")
    summary = (
        f"Run active-response command '{command}' on agent(s) {', '.join(ids)}"
        + (f" with {' and '.join(extra)}" if extra else "")
        + ". This executes on the endpoint and can block IPs, kill processes or disable accounts."
    )
    if preview := _confirm("run_active_response", {"agents_list": ids, **body}, summary, confirm):
        return preview
    return _written(await manager().put("/active-response", params=params, json=body))


def main() -> None:
    transport = "streamable-http" if settings.transport == "streamable-http" else "stdio"
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
