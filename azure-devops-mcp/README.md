# azure-devops-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to an **on-prem Azure DevOps Server** (formerly TFS) through its REST API. Ask about your
projects in natural language — repositories, branches, commits, pull requests, work items (WIQL),
builds/pipelines, releases and the wiki — and, opt-in, **create/update work items and wiki pages**.

- One shared `httpx.AsyncClient`; **PAT** auth over HTTP Basic, `Accept: application/json`.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `AZDO_ALLOW_WRITE` (see below).
- A raw escape-hatch tool (`azdo_get`) so any `_apis/...` resource stays reachable.

Targets **on-prem** Azure DevOps Server (the base URL includes a **collection**), not cloud
`dev.azure.com`. The required `api-version` is set to match your server (2019→5.0, 2020→6.0,
2022→7.0).

## Tools

| Tool | What it does |
|---|---|
| `list_projects(limit?, full?)` | Team projects in the collection. |
| `list_teams(project?, limit?, full?)` | Teams collection-wide, or for one project. |
| `list_repositories(project?, limit?, full?)` | Git repositories in a project. |
| `list_branches(repository, project?, limit?, full?)` | Branches (refs under `refs/heads/`). |
| `list_commits(repository, project?, branch?, author?, limit?, full?)` | Commit history (capped; no file diffs). |
| `list_pull_requests(repository, project?, status?, limit?, full?)` | Pull requests by status. |
| `query_work_items(wiql, project?, limit?)` | Run a WIQL query and hydrate the results' key fields. |
| `get_work_items(ids, fields?, full?)` | Fetch work items by id with selected fields. |
| `list_build_definitions(project?, name?, limit?, full?)` | Build/pipeline definitions. |
| `list_builds(project?, definition_id?, status?, result?, limit?, full?)` | Build/pipeline runs, newest first. |
| `list_releases(project?, definition_id?, status?, limit?, full?)` | Releases, newest first. |
| `list_wikis(project?, full?)` | Wikis in a project. |
| `get_wiki_page(wiki, path, project?, include_content?, full?)` | A wiki page's path + markdown content. |
| `azdo_get(path, project?, params?)` | Escape hatch: raw read-only GET against any `_apis/...` path. |

Results are trimmed to the useful fields by default; pass `full=true` for raw objects, and lists are
capped (`AZDO_MAX_ROWS`, default 200) unless `full`. Project-scoped tools use `project=…` or the
`AZDO_PROJECT` default.

### Write tools (opt-in)

These mutate Azure DevOps and only work when **`AZDO_ALLOW_WRITE=true`** (otherwise they refuse with a
clear message). The PAT also needs the matching **write** scopes. With the flag off, the server is
effectively read-only.

| Tool | What it does |
|---|---|
| `create_work_item(work_item_type, title, project?, description?, assigned_to?, area_path?, iteration_path?, fields?)` | Create a work item (Bug/Task/User Story/…) via JSON-Patch. |
| `update_work_item(id, title?, state?, assigned_to?, comment?, fields?)` | Update fields and/or add a discussion comment (`System.History`). Pass only `comment` to just comment. |
| `create_or_update_wiki_page(wiki, path, content, project?)` | Create a wiki page, or replace its content if it exists (uses the page's ETag with `If-Match`, so a concurrent edit fails cleanly instead of clobbering). |

## 1. Create a PAT

In the web portal (`https://<server>/<collection>`): **User settings → Personal Access Tokens →
New Token**. For read-only use, scope it to *Code (Read)*, *Work Items (Read)*, *Build (Read)*,
*Project and Team (Read)*. If you enable writes (below), use *Work Items (Read & write)* and
*Wiki (Read & write)* as well. Copy the token — it's `AZDO_PAT`.

> Azure DevOps requires **HTTPS** for PAT auth. On a bad token the server returns an HTML sign-in
> page rather than a clean 401; this server detects that and reports an auth error.

## 2. Configure

```bash
cp .env.example azure-devops.env
# edit azure-devops.env: AZDO_BASE_URL, AZDO_PAT, AZDO_API_VERSION
```

- **`AZDO_BASE_URL`** — the **collection** URL, e.g. `https://devops.contoso.com/DefaultCollection`
  (some installs use a `/tfs/` virtual dir: `https://devops.contoso.com/tfs/DefaultCollection`).
- **`AZDO_API_VERSION`** — match the server: **2019 → 5.0**, **2020 → 6.0**, **2022 → 7.0**
  (2022.1 → 7.1). Too new an api-version yields a 400/404.
- **`AZDO_PROJECT`** — optional default project so project-scoped tools can omit `project=`.
- **TLS** — for an internal CA set `AZDO_CA_BUNDLE`, or (lab only) `AZDO_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t azure-devops-mcp .
claude mcp add azuredevops -- docker run -i --rm --env-file ./azure-devops.env azure-devops-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from azure-devops.env into your shell first, then:
claude mcp add azuredevops -- poetry run azure-devops-mcp
```

### Always-on HTTP (optional)

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

## 4. Verify

In Claude Code, run `/mcp` to confirm the `azuredevops` server connected, then ask things like:

- "List the projects on this server."
- "Show active pull requests in the `api` repo of project Platform."
- "Run a WIQL query for active bugs assigned to me."
- "What were the last 10 builds for project Platform and did any fail?"
- "List branches of the `web` repository."

With `AZDO_ALLOW_WRITE=true` you can also:

- "Create a Bug titled 'Login 500 on submit' in project Platform, assigned to me."
- "Add a comment to work item 1423 saying the fix is deployed, and set its state to Resolved."
- "Update the wiki page /Runbooks/Deploy in the Platform wiki with this content: …"

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `AZDO_ALLOW_WRITE=true` and the PAT carries the matching write scopes. Leave the flag unset for a
  read-only deployment. No delete tools are provided.
- **api-version** is global (`AZDO_API_VERSION`); a single tool can override it via
  `azdo_get(..., params={"api-version": "6.0"})`.
- **Large lists** (commits, builds, work items) are capped — widen with `limit` or filter (branch,
  author, status, WIQL) rather than fetching everything.
- **Releases** may be unused on a given server; an empty result or 404 just means none/not enabled.
- The newer `_apis/pipelines` API is partial/absent on older on-prem servers — this server uses the
  stable `_apis/build` API; reach pipelines via `azdo_get` if your server supports it.
