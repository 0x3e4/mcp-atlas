"""FastMCP server exposing Azure DevOps Server (on-prem) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools are GET requests (plus WIQL, a read-only POST) and cover projects,
repos/PRs/commits, work items, builds and the wiki; the raw ``azdo_get`` escape hatch reaches anything
else.

Write tools (work items: create/update/comment; wiki: create-or-update page) are **opt-in**: they
refuse unless ``AZDO_ALLOW_WRITE=true``, and need a PAT with the matching write scopes. With the flag
off the server is effectively read-only.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import AzdoClient, AzdoError
from .config import ConfigError, Settings

mcp = FastMCP("azure-devops-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: AzdoClient | None = None


def _get_client() -> AzdoClient:
    global _client
    if _client is None:
        _client = AzdoClient(Settings.from_env())
    return _client


def _proj(project: str | None) -> str:
    """Resolve the project for a project-scoped tool (arg, else AZDO_PROJECT default)."""
    p = (project or "").strip() or _get_client().settings.project
    if not p:
        raise ValueError("A project is required: pass project=... or set AZDO_PROJECT.")
    return p


def _require_write() -> None:
    """Gate write tools behind the opt-in AZDO_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set AZDO_ALLOW_WRITE=true (and use a PAT with write scopes) "
            "to enable work-item and wiki writes."
        )


# ---- curated field projections (dotted paths reach into nested objects) --
_PROJECT_FIELDS = ("id", "name", "state", "visibility", "description", "lastUpdateTime")
_TEAM_FIELDS = ("id", "name", "projectName", "description")
_REPO_FIELDS = ("id", "name", "defaultBranch", "size", "remoteUrl", "webUrl", "project.name")
_REF_FIELDS = ("name", "objectId", "creator.displayName", "isLocked")
_COMMIT_FIELDS = ("commitId", "author.name", "author.email", "author.date", "comment")
_PR_FIELDS = (
    "pullRequestId", "title", "status", "isDraft", "createdBy.displayName", "creationDate",
    "sourceRefName", "targetRefName", "mergeStatus",
)
_BUILD_DEF_FIELDS = ("id", "name", "path", "type", "queueStatus", "revision")
_BUILD_FIELDS = (
    "id", "buildNumber", "status", "result", "queueTime", "startTime", "finishTime",
    "sourceBranch", "definition.name", "requestedFor.displayName", "reason",
)
_RELEASE_FIELDS = (
    "id", "name", "status", "reason", "createdOn", "createdBy.displayName", "releaseDefinition.name",
)
_WORKITEM_FIELDS_DEFAULT = (
    "System.Id", "System.Title", "System.WorkItemType", "System.State", "System.AssignedTo",
    "System.AreaPath", "System.IterationPath",
)
_WIKI_FIELDS = ("id", "name", "type", "mappedPath", "remoteUrl", "repositoryId")
_WIKI_PAGE_FIELDS = ("id", "path", "content", "gitItemPath", "isParentPage", "order")


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 500) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Project a dict down to ``fields`` (supports dotted paths like ``a.b.c``)."""
    out: dict[str, Any] = {}
    for field in fields:
        cur: Any = obj
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        out[field] = cur
    return out


def _csv(value: str | None) -> str:
    return ",".join(v.strip() for v in value.split(",") if v.strip()) if value else ""


def _results(data: Any) -> list[Any]:
    if isinstance(data, dict) and "value" in data:
        return data["value"] or []
    if isinstance(data, list):
        return data
    return [data] if data else []


async def _get_list(
    path: str,
    fields: tuple[str, ...],
    *,
    project: str | None = None,
    params: dict[str, Any] | None = None,
    limit: int = 50,
    full: bool = False,
) -> dict[str, Any]:
    """Fetch a list endpoint, project to ``fields`` (unless ``full``), and cap to ``limit``."""
    data = await _get_client().get(path, project=project, params=params)
    rows = _results(data)[: _clamp(limit)]
    if not full:
        rows = [_pick(r, fields) if isinstance(r, dict) else r for r in rows]
    return {"count": len(rows), "value": rows}


# ---- tools: core --------------------------------------------------------

@mcp.tool()
async def list_projects(
    limit: Annotated[int, Field(description="Max projects to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List team projects in the collection (_apis/projects)."""
    return await _get_list("_apis/projects", _PROJECT_FIELDS, params={"$top": _clamp(limit, 100, 500)}, limit=limit, full=full)


@mcp.tool()
async def list_teams(
    project: Annotated[str | None, Field(description="Limit to one project's teams; omit for all teams in the collection.")] = None,
    limit: Annotated[int, Field(description="Max teams to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List teams — collection-wide (_apis/teams), or for one project when project is given."""
    if project:
        path = f"_apis/projects/{project}/teams"
    else:
        path = "_apis/teams"
    return await _get_list(path, _TEAM_FIELDS, params={"$top": _clamp(limit, 100, 500)}, limit=limit, full=full)


# ---- tools: git (code) --------------------------------------------------

@mcp.tool()
async def list_repositories(
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    limit: Annotated[int, Field(description="Max repositories to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List Git repositories in a project ({project}/_apis/git/repositories)."""
    return await _get_list("_apis/git/repositories", _REPO_FIELDS, project=_proj(project), limit=limit, full=full)


@mcp.tool()
async def list_branches(
    repository: Annotated[str, Field(description="Repository name or id.")],
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    limit: Annotated[int, Field(description="Max branches to return.", ge=1, le=500)] = 200,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List branches of a repository (git refs under refs/heads/)."""
    path = f"_apis/git/repositories/{repository}/refs"
    return await _get_list(
        path, _REF_FIELDS, project=_proj(project), params={"filter": "heads/", "$top": _clamp(limit, 200, 500)}, limit=limit, full=full,
    )


@mcp.tool()
async def list_commits(
    repository: Annotated[str, Field(description="Repository name or id.")],
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    branch: Annotated[str | None, Field(description="Branch name (e.g. 'main') to scope the history.")] = None,
    author: Annotated[str | None, Field(description="Filter by author email.")] = None,
    limit: Annotated[int, Field(description="Max commits to return.", ge=1, le=500)] = 30,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List commits in a repository ({project}/_apis/git/repositories/{repo}/commits).

    Capped to 'limit' (commit history is large); never includes per-file change lists.
    """
    params: dict[str, Any] = {"searchCriteria.$top": _clamp(limit, 30, 500)}
    if branch:
        params["searchCriteria.itemVersion.version"] = branch
        params["searchCriteria.itemVersion.versionType"] = "branch"
    if author:
        params["searchCriteria.author"] = author
    path = f"_apis/git/repositories/{repository}/commits"
    return await _get_list(path, _COMMIT_FIELDS, project=_proj(project), params=params, limit=limit, full=full)


@mcp.tool()
async def list_pull_requests(
    repository: Annotated[str, Field(description="Repository name or id.")],
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    status: Annotated[str | None, Field(description="Filter by status: active, completed, abandoned, all.")] = None,
    limit: Annotated[int, Field(description="Max pull requests to return.", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List pull requests for a repository ({project}/_apis/git/repositories/{repo}/pullrequests)."""
    if status is not None and status not in ("active", "completed", "abandoned", "all"):
        raise ValueError("status must be one of: active, completed, abandoned, all.")
    params: dict[str, Any] = {"$top": _clamp(limit, 50, 500)}
    if status:
        params["searchCriteria.status"] = status
    path = f"_apis/git/repositories/{repository}/pullrequests"
    return await _get_list(path, _PR_FIELDS, project=_proj(project), params=params, limit=limit, full=full)


# ---- tools: work items --------------------------------------------------

@mcp.tool()
async def query_work_items(
    wiql: Annotated[str, Field(description="A WIQL query, e.g. \"SELECT [System.Id] FROM WorkItems WHERE [System.WorkItemType]='Bug' AND [System.State]='Active'\".")],
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    limit: Annotated[int, Field(description="Max work items to hydrate with fields.", ge=1, le=200)] = 50,
) -> dict[str, Any]:
    """Run a WIQL query and return the matching work items with their key fields.

    WIQL returns only IDs, so this hydrates the first 'limit' results via the work-items batch.
    """
    client = _get_client()
    result = await client.post("_apis/wit/wiql", project=_proj(project), json={"query": wiql})
    refs = result.get("workItems") or []
    ids = [str(w.get("id")) for w in refs if isinstance(w, dict) and w.get("id") is not None]
    ids = ids[: _clamp(limit, 50, 200)]
    out: dict[str, Any] = {"as_of": result.get("asOf"), "matched": len(refs), "returned": len(ids), "work_items": []}
    if ids:
        data = await client.get(
            "_apis/wit/workitems",
            params={"ids": ",".join(ids), "fields": ",".join(_WORKITEM_FIELDS_DEFAULT)},
        )
        out["work_items"] = [_pick(w, ("id", "rev", "fields")) for w in _results(data)]
    return out


@mcp.tool()
async def get_work_items(
    ids: Annotated[str, Field(description="Comma-separated work item ids, e.g. '101,102,103' (max 200).")],
    fields: Annotated[str | None, Field(description="Comma-separated field reference names; omit for a sensible default set.")] = None,
    full: Annotated[bool, Field(description="Return all returned fields (ignores the field projection).")] = False,
) -> dict[str, Any]:
    """Get one or more work items by id with selected fields (_apis/wit/workitems?ids=...)."""
    id_list = [i.strip() for i in ids.split(",") if i.strip()][:200]
    if not id_list:
        raise ValueError("Provide at least one work item id.")
    field_list = _csv(fields) or ",".join(_WORKITEM_FIELDS_DEFAULT)
    data = await _get_client().get(
        "_apis/wit/workitems", params={"ids": ",".join(id_list), "fields": field_list}
    )
    rows = _results(data)
    if not full:
        rows = [_pick(w, ("id", "rev", "fields")) for w in rows if isinstance(w, dict)]
    return {"count": len(rows), "value": rows}


# ---- tools: build & release ---------------------------------------------

@mcp.tool()
async def list_build_definitions(
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    name: Annotated[str | None, Field(description="Filter by definition name (substring).")] = None,
    limit: Annotated[int, Field(description="Max definitions to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List build/pipeline definitions in a project ({project}/_apis/build/definitions)."""
    params: dict[str, Any] = {"$top": _clamp(limit, 100, 500)}
    if name:
        params["name"] = name
    return await _get_list("_apis/build/definitions", _BUILD_DEF_FIELDS, project=_proj(project), params=params, limit=limit, full=full)


@mcp.tool()
async def list_builds(
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    definition_id: Annotated[int | None, Field(description="Filter to a single build definition id.")] = None,
    status: Annotated[str | None, Field(description="statusFilter, e.g. 'completed', 'inProgress', 'notStarted'.")] = None,
    result: Annotated[str | None, Field(description="resultFilter, e.g. 'succeeded', 'failed', 'canceled'.")] = None,
    limit: Annotated[int, Field(description="Max builds to return (most recent first).", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List builds / pipeline runs in a project ({project}/_apis/build/builds), newest first."""
    params: dict[str, Any] = {"$top": _clamp(limit, 50, 500), "queryOrder": "finishTimeDescending"}
    if definition_id is not None:
        params["definitions"] = definition_id
    if status:
        params["statusFilter"] = status
    if result:
        params["resultFilter"] = result
    return await _get_list("_apis/build/builds", _BUILD_FIELDS, project=_proj(project), params=params, limit=limit, full=full)


@mcp.tool()
async def list_releases(
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    definition_id: Annotated[int | None, Field(description="Filter to a single release definition id.")] = None,
    status: Annotated[str | None, Field(description="statusFilter, e.g. 'active', 'abandoned', 'draft'.")] = None,
    limit: Annotated[int, Field(description="Max releases to return (most recent first).", ge=1, le=500)] = 50,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List releases in a project ({project}/_apis/release/releases), newest first.

    On-prem Release Management lives on the same server (no separate vsrm host). Not all
    deployments use Releases — an empty result or 404 simply means none/not enabled.
    """
    params: dict[str, Any] = {"$top": _clamp(limit, 50, 500), "queryOrder": "descending"}
    if definition_id is not None:
        params["definitionId"] = definition_id
    if status:
        params["statusFilter"] = status
    return await _get_list("_apis/release/releases", _RELEASE_FIELDS, project=_proj(project), params=params, limit=limit, full=full)


# ---- tools: wiki (read) -------------------------------------------------

@mcp.tool()
async def list_wikis(
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List wikis in a project ({project}/_apis/wiki/wikis)."""
    return await _get_list("_apis/wiki/wikis", _WIKI_FIELDS, project=_proj(project), full=full)


@mcp.tool()
async def get_wiki_page(
    wiki: Annotated[str, Field(description="Wiki id or name.")],
    path: Annotated[str, Field(description="Page path, e.g. '/Home' or '/Runbooks/Deploy'.")],
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    include_content: Annotated[bool, Field(description="Include the page's markdown content.")] = True,
    full: Annotated[bool, Field(description="Return the full page object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get a wiki page (path, content) from a project wiki ({project}/_apis/wiki/wikis/{wiki}/pages)."""
    data = await _get_client().get(
        f"_apis/wiki/wikis/{wiki}/pages",
        project=_proj(project),
        params={"path": path, "includeContent": "true" if include_content else "false"},
    )
    return data if full else _pick(data, _WIKI_PAGE_FIELDS)


# ---- tools: work items (write — gated by AZDO_ALLOW_WRITE) ---------------

@mcp.tool()
async def create_work_item(
    work_item_type: Annotated[str, Field(description="Work item type, e.g. 'Bug', 'Task', 'User Story'.")],
    title: Annotated[str, Field(description="Title (System.Title).")],
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
    description: Annotated[str | None, Field(description="Description (System.Description, HTML/text).")] = None,
    assigned_to: Annotated[str | None, Field(description="Assignee (System.AssignedTo) — a user's unique name/email or display name.")] = None,
    area_path: Annotated[str | None, Field(description="Area path (System.AreaPath).")] = None,
    iteration_path: Annotated[str | None, Field(description="Iteration path (System.IterationPath).")] = None,
    fields: Annotated[dict[str, Any] | None, Field(description="Extra fields by reference name, e.g. {\"Microsoft.VSTS.Common.Priority\": 2}.")] = None,
) -> dict[str, Any]:
    """Create a work item (WRITE — requires AZDO_ALLOW_WRITE).

    Builds a JSON-Patch document and POSTs to {project}/_apis/wit/workitems/$<type>.
    """
    _require_write()
    ops: list[dict[str, Any]] = [{"op": "add", "path": "/fields/System.Title", "value": title}]
    extras = {
        "System.Description": description,
        "System.AssignedTo": assigned_to,
        "System.AreaPath": area_path,
        "System.IterationPath": iteration_path,
    }
    for ref, value in extras.items():
        if value is not None:
            ops.append({"op": "add", "path": f"/fields/{ref}", "value": value})
    for ref, value in (fields or {}).items():
        ops.append({"op": "add", "path": f"/fields/{ref}", "value": value})
    path = f"_apis/wit/workitems/${quote(work_item_type, safe='')}"
    data = await _get_client().json_patch("POST", path, ops, project=_proj(project))
    return _pick(data, ("id", "rev", "fields", "url"))


@mcp.tool()
async def update_work_item(
    id: Annotated[int, Field(description="Work item id to update.")],
    title: Annotated[str | None, Field(description="New title (System.Title).")] = None,
    state: Annotated[str | None, Field(description="New state (System.State), e.g. 'Active', 'Resolved', 'Closed'.")] = None,
    assigned_to: Annotated[str | None, Field(description="New assignee (System.AssignedTo).")] = None,
    comment: Annotated[str | None, Field(description="Add a discussion comment (recorded in System.History).")] = None,
    fields: Annotated[dict[str, Any] | None, Field(description="Other fields to set by reference name.")] = None,
) -> dict[str, Any]:
    """Update a work item's fields and/or add a comment (WRITE — requires AZDO_ALLOW_WRITE).

    PATCHes _apis/wit/workitems/{id} with a JSON-Patch document. Pass only a comment to add a
    discussion entry without changing fields.
    """
    _require_write()
    ops: list[dict[str, Any]] = []
    named = {"System.Title": title, "System.State": state, "System.AssignedTo": assigned_to}
    for ref, value in named.items():
        if value is not None:
            ops.append({"op": "add", "path": f"/fields/{ref}", "value": value})
    for ref, value in (fields or {}).items():
        ops.append({"op": "add", "path": f"/fields/{ref}", "value": value})
    if comment:
        ops.append({"op": "add", "path": "/fields/System.History", "value": comment})
    if not ops:
        raise ValueError("Nothing to update: provide title, state, assigned_to, fields, and/or comment.")
    data = await _get_client().json_patch("PATCH", f"_apis/wit/workitems/{id}", ops)
    return _pick(data, ("id", "rev", "fields", "url"))


# ---- tools: wiki (write — gated by AZDO_ALLOW_WRITE) ---------------------

@mcp.tool()
async def create_or_update_wiki_page(
    wiki: Annotated[str, Field(description="Wiki id or name.")],
    path: Annotated[str, Field(description="Page path, e.g. '/Runbooks/Deploy'. Parent pages must exist.")],
    content: Annotated[str, Field(description="The page's markdown content (replaces existing content).")],
    project: Annotated[str | None, Field(description="Project name/id; omit to use AZDO_PROJECT.")] = None,
) -> dict[str, Any]:
    """Create a wiki page, or replace its content if it exists (WRITE — requires AZDO_ALLOW_WRITE).

    Reads the current page first to obtain its version ETag and uses If-Match on update (so a
    concurrent edit fails cleanly with 412 rather than silently clobbering). PUTs to
    {project}/_apis/wiki/wikis/{wiki}/pages?path=...
    """
    _require_write()
    proj = _proj(project)
    client = _get_client()
    page_path = f"_apis/wiki/wikis/{wiki}/pages"
    etag: str | None = None
    existed = False
    try:
        _existing, etag = await client.get_with_etag(page_path, project=proj, params={"path": path})
        existed = True
    except AzdoError as exc:
        if exc.status != 404:
            raise  # a real error (auth, etc.), not "page absent"
    result, new_etag = await client.put_json(
        page_path, {"content": content}, project=proj, params={"path": path},
        if_match=etag if existed else None,
    )
    out = {"action": "updated" if existed else "created", "path": path, "etag": new_etag}
    if isinstance(result, dict):
        out["page"] = _pick(result, ("id", "path", "gitItemPath", "order"))
    return out


# ---- tool: raw escape hatch ---------------------------------------------

@mcp.tool()
async def azdo_get(
    path: Annotated[str, Field(description="API path relative to the collection, e.g. '_apis/git/repositories' or '{project}/_apis/build/builds'.")],
    project: Annotated[str | None, Field(description="Optional project to scope the path under.")] = None,
    params: Annotated[dict[str, Any] | None, Field(description="Optional query params, e.g. {\"$top\": 5}. api-version is added automatically.")] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only GET against any Azure DevOps ``_apis/...`` resource.

    The required api-version is applied automatically (override by passing it in params). Use for
    resources without a dedicated tool. Returns the raw JSON envelope.
    """
    data = await _get_client().get_raw(path, project=project, params=params)
    return data if isinstance(data, dict) else {"value": data}


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"azure-devops-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = AzdoClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
