# azure-devops-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to an **on-prem Azure DevOps Server** (formerly TFS) through its REST API. Ask about your
projects in natural language — repositories (files, commits, diffs, branches, tags), pull requests
(threads, files, votes), work items (WIQL, links, history), builds and their logs, releases, the wiki
and search — and, opt-in, **work with them**: create and edit work items of any type (PBI, Bug,
Issue, Task …) and link them, write and move wiki pages, open, review, comment on and merge pull
requests, create branches and push commits, queue builds and deploy releases.

- One shared `httpx.AsyncClient`; **PAT** auth over HTTP Basic, `Accept: application/json`.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default**; write tools are **opt-in** behind `AZDO_ALLOW_WRITE`, and the sensitive
  ones (deletes, pushes, merges, votes, pipelines, releases) each behind a switch of their own (see
  below). Every write shows a preview and asks first.
- A raw escape-hatch tool (`azdo_get`) so any `_apis/...` resource stays reachable.

Targets **on-prem** Azure DevOps Server (the base URL includes a **collection**), not cloud
`dev.azure.com`. The required `api-version` is set to match your server (2019→5.0, 2020→6.0,
2022→7.0).

## Tools

### Read

| Tool | What it does |
|---|---|
| `server_info()` | The PAT's user, collection, api-version and which write switches are on. |
| `list_projects(limit?, full?)` | Team projects in the collection. |
| `list_teams(project?, limit?, full?)` | Teams collection-wide, or for one project. |
| `list_repositories(project?, limit?, full?)` | Git repositories in a project. |
| `list_branches(repository, project?, limit?, full?)` | Branches (refs under `refs/heads/`). |
| `list_tags(repository, project?, limit?)` | Tags with the commit each points at. |
| `list_files(repository, path?, version?, version_type?, recursive?, project?, limit?)` | Files and folders at a branch / tag / commit. |
| `get_file(repository, path, version?, version_type?, project?, max_chars?)` | A text file's content (binary files: metadata only). |
| `list_commits(repository, project?, branch?, author?, limit?, full?)` | Commit history (capped). |
| `get_commit(repository, commit_id, project?, include_changes?, limit?)` | One commit with the files it changed. |
| `compare_versions(repository, base, target, base_type?, target_type?, path?, project?, limit?)` | Two branches / tags / commits compared like a PR (from the merge base): ahead / behind, changed files, and a unified diff of one file with `path`. |
| `search(text, kind?, project?, repository?, branch?, path?, limit?)` | Full-text search over `code`, `wiki` or `work_items` (needs Search configured on the server). |
| `list_pull_requests(repository?, project?, status?, mine?, target_branch?, source_branch?, limit?, full?)` | Pull requests of one repository or the whole project; `mine="created"` / `"reviewing"`. |
| `get_pull_request(pull_request_id, repository?, project?, include_threads?, include_files?, include_commits?, include_system_comments?)` | A PR in full: description, reviewers and votes, linked work items, comment threads (file + line), changed files, commits. |
| `query_work_items(wiql, project?, limit?)` | Run a WIQL query and hydrate the results' key fields. |
| `get_work_items(ids, fields?, full?)` | Fetch work items by id with selected fields. |
| `get_work_item(id, include_history?, history_limit?)` | One work item in full: all fields, links (parent, children, related, PRs, commits, branches, attachments) and the discussion. |
| `list_work_item_types(project?)` | The project's work item types (depends on the process) and their states. |
| `list_iterations(project?, team?, timeframe?, depth?)` | Iteration paths / sprints with dates; with `team`, that team's sprints (`timeframe="current"`). |
| `list_areas(project?, depth?)` | Area paths. |
| `list_build_definitions(project?, name?, limit?, full?)` | Build/pipeline definitions. |
| `list_builds(project?, definition_id?, status?, result?, limit?, full?)` | Build/pipeline runs, newest first. |
| `get_build(build_id, project?, include_logs?, log_lines?)` | A run with its errors, failed tasks and the tail of their logs. |
| `list_releases(project?, definition_id?, status?, limit?, full?)` | Releases, newest first. |
| `list_wikis(project?, full?)` | Wikis in a project. |
| `list_wiki_pages(wiki, path?, project?, limit?)` | The page tree of a wiki (or below one page). |
| `get_wiki_page(wiki, path, project?, include_content?, full?)` | A wiki page's path + markdown content. |
| `azdo_get(path, project?, params?)` | Escape hatch: raw read-only GET against any `_apis/...` path. |

Results are trimmed to the useful fields by default; pass `full=true` for raw objects, and lists are
capped (`AZDO_MAX_ROWS`, default 200) unless `full`. Project-scoped tools use `project=…` or the
`AZDO_PROJECT` default. People (reviewers) can be given as email, account name, display name or `me`.

### Write tools (opt-in)

These mutate Azure DevOps and only work when **`AZDO_ALLOW_WRITE=true`** (otherwise they refuse with a
clear message). The PAT also needs the matching **write** scopes. With the flag off, the server is
effectively read-only.

| Tool | What it does |
|---|---|
| `create_work_item(work_item_type, title, project?, description?, assigned_to?, area_path?, iteration_path?, parent_id?, tags?, fields?)` | Create a work item of any type (Product Backlog Item, Bug, Issue, Task, User Story, Feature, Epic …), optionally as a child of `parent_id`. |
| `update_work_item(id, title?, state?, assigned_to?, description?, area_path?, iteration_path?, add_tags?, remove_tags?, comment?, fields?)` | Update fields and/or add a discussion comment (`System.History`). Pass only `comment` to just comment. |
| `link_work_items(id, add?, remove?)` | Add / remove links: parent, child, related, predecessor, successor, duplicate, tests, pull request, commit, branch, hyperlink. Existing links are skipped; tied to the item's revision. |
| `add_work_item_attachment(id, file_name, content? \| content_base64?, comment?)` | Attach a file (text or base64, up to 20 MB). |
| `restore_work_items(ids, project?)` | Restore deleted work items from the Recycle Bin. |
| `create_or_update_wiki_page(wiki, path, content, project?, comment?)` | Create a wiki page, or replace its content if it exists (uses the page's ETag with `If-Match`, so a concurrent edit fails cleanly instead of clobbering). |
| `move_wiki_page(wiki, path, new_path, project?, comment?)` | Move or rename a page with its sub-pages (links in other pages are not rewritten). |
| `create_pull_request(repository, source_branch, title, target_branch?, description?, reviewers?, required_reviewers?, work_item_ids?, draft?, project?)` | Open a PR (target defaults to the default branch). |
| `update_pull_request(pull_request_id, repository?, title?, description?, status?, draft?, target_branch?, project?)` | Edit, publish a draft, retarget, abandon or reactivate a PR. |
| `set_pull_request_reviewers(pull_request_id, repository?, add?, add_required?, remove?, project?)` | Add / remove reviewers (existing reviewers keep their vote). |
| `comment_pull_request(pull_request_id, content?, repository?, thread_id?, file_path?, line?, thread_status?, project?)` | Start a thread (optionally on a file and line), reply, or resolve / reopen a thread. |
| `create_branch(repository, name, source, project?)` | Create a branch from a branch, tag or commit. |

Sensitive writes need **a second switch** on top of `AZDO_ALLOW_WRITE` (all default `false`):

| Switch | Tools | Always confirmed |
|---|---|---|
| `AZDO_ALLOW_DELETE` | `delete_work_items(ids, destroy?)` (Recycle Bin, or permanently with `destroy=true`), `delete_wiki_page(wiki, path, project?, comment?)` (with all sub-pages), `delete_branch(repository, name, project?)` (never the default branch) | yes |
| `AZDO_ALLOW_PUSH` | `commit_files(repository, branch, message, changes, create_branch_from?, project?)` — one commit of adds / edits / deletes / renames, pushed without a local clone; the preview shows a diff of every edited file. Pushes to any branch **except** the default branch. | no |
| `AZDO_ALLOW_PUSH_DEFAULT_BRANCH` | `commit_files` may also push to the repository's default branch (otherwise: commit to a new branch and open a PR). | yes |
| `AZDO_ALLOW_PR_MERGE` | `complete_pull_request(pull_request_id, repository?, merge_strategy?, delete_source_branch?, transition_work_items?, merge_commit_message?, auto_complete?, …)` — merge now or set auto-complete; `delete_source_branch` also needs `AZDO_ALLOW_DELETE`. | yes |
| `AZDO_ALLOW_POLICY_BYPASS` | `complete_pull_request(bypass_policy=true, bypass_reason=…)` — merge despite failing branch policies (also needs the server's *Bypass policies* permission). | yes |
| `AZDO_ALLOW_PR_VOTE` | `vote_pull_request(pull_request_id, vote, …)` — approve, approve with suggestions, wait for author, reject, reset — as the PAT's user. | no |
| `AZDO_ALLOW_PIPELINES` | `queue_build(definition_id, branch?, parameters?, project?)`, `cancel_build(build_id, project?)` | no |
| `AZDO_ALLOW_RELEASES` | `create_release(definition_id, description?, artifacts?, project?)`, `deploy_release_stage(release_id, stage, comment?, project?)` (approvals and gates still apply) | deploys: yes |

"Always confirmed" means the tool asks even with `AZDO_CONFIRM_WRITE=false`. Every switch is read
from the instance's env file, so they can be on for one user's instance and off for everyone else
(see [Multiple instances](#multiple-instances-one-image-several-env-files)). Branch policies,
permissions and approvals configured on the server still apply on top.

**Confirmation before every write** (`AZDO_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments — and, where it matters, to the live state shown in the preview
(a branch's commit, a PR's source commit, a wiki page's version) — so a changed request or a change in
between needs a fresh confirmation (codes also expire when the server restarts). Set
`AZDO_CONFIRM_WRITE=false` to let the other writes run directly.

## 1. Create a PAT

In the web portal (`https://<server>/<collection>`): **User settings → Personal Access Tokens →
New Token**. For read-only use, scope it to *Code (Read)*, *Work Items (Read)*, *Build (Read)*,
*Release (Read)*, *Wiki (Read)*, *Project and Team (Read)* (and *Identity (Read)* to name reviewers).
For writes add only what you enable:

| Enabled | PAT scope |
|---|---|
| work items, links, attachments, restore | *Work Items (Read & write)* |
| deleting work items | *Work Items (Read, write, & manage)* |
| wiki pages | *Wiki (Read & write)* |
| branches, pull requests, comments, votes, merges, pushes | *Code (Read & write)* |
| queue / cancel builds | *Build (Read & execute)* |
| releases | *Release (Read, write, & execute)* |

Copy the token — it's `AZDO_PAT`. The PAT acts as its user: everything the server does (comments,
votes, commits, merges) shows up under that user's name, within that user's permissions.

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

Run the server as a long-lived `streamable-http` service instead of per-session stdio.
[`compose.yml`](compose.yml) already sets `MCP_TRANSPORT=streamable-http` and binds `0.0.0.0:8000`:

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

Point any HTTP MCP client at `http://<host>:8000/mcp` (also the only mode remote clients like
OpenAI support). **On localhost this works as-is — nothing else to change.**

#### Behind an MCP gateway (shared Docker network)

A gateway (e.g. [mcpjungle](https://github.com/mcpjungle/MCPJungle)) fronts many servers behind one
endpoint. Running several atlas servers next to a gateway on one host changes two things:

- The published **`8000:8000` host port collides** once more than one server uses it. Drop the host
  port and let the gateway reach the server **by its compose service name** over a shared Docker
  network (or, if you must publish, give each server a distinct host port like `"8001:8000"`).
- Put the **gateway and the servers on one shared network**, so `http://azure-devops-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  azure-devops-mcp:
    build: .
    image: azure-devops-mcp
    env_file: ./azure-devops.env
    environment:
      MCP_TRANSPORT: streamable-http
      MCP_HOST: 0.0.0.0
      MCP_PORT: "8000"
    # no `ports:` — only the gateway reaches it, over atlas-net
    networks: [atlas-net]
    restart: unless-stopped

networks:
  atlas-net:
    external: true
```

With the gateway also on `atlas-net`, register this server at `http://azure-devops-mcp:8000/mcp`
(`mcpjungle register --name azure-devops --url http://azure-devops-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
PAT, or one container per collection or server.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-azure-devops: &azure-devops
  image: ghcr.io/0x3e4/azure-devops-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  azure-devops-mcp:                    # existing shared read-only instance
    <<: *azure-devops
    container_name: azure-devops-mcp
    env_file: ./azure-devops.env

  azure-devops-mcp-instance-a:         # write access with instance a's PAT
    <<: *azure-devops
    container_name: azure-devops-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's PAT and `AZDO_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `AZDO_CONFIRM_WRITE=false`. The sensitive switches go per instance too — e.g. `AZDO_ALLOW_DELETE`,
  `AZDO_ALLOW_PUSH`, `AZDO_ALLOW_PR_MERGE` only in the env file of the user who should have them;
  deletes, merges, default-branch pushes and deploys always ask first. `*.env` is gitignored, so it
  stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name azure-devops --url http://azure-devops-mcp:8000/mcp
  mcpjungle register --name azure-devops-instance-a --url http://azure-devops-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add azuredevops-instance-a -- docker run -i --rm --env-file ./env/instance_a.env azure-devops-mcp`

## 4. Verify

In Claude Code, run `/mcp` to confirm the `azuredevops` server connected, then ask things like:

- "List the projects on this server."
- "Show active pull requests in the `api` repo of project Platform."
- "Run a WIQL query for active bugs assigned to me."
- "What were the last 10 builds for project Platform and did any fail?"
- "List branches of the `web` repository."
- "Show PR 57 with its open comments and changed files."
- "What changed between `main` and `feature/login`? Show me the diff of `src/auth.py`."
- "Why did build 1234 fail?"
- "Which PBIs are in the current sprint of team Web?"

With `AZDO_ALLOW_WRITE=true` you can also:

- "Create a Bug titled 'Login 500 on submit' in project Platform, assigned to me."
- "Create three Tasks under PBI 1200 for backend, frontend and tests, in the current sprint."
- "Add a comment to work item 1423 saying the fix is deployed, and set its state to Resolved."
- "Link PR 57 in the `api` repo to work item 1423."
- "Update the wiki page /Runbooks/Deploy in the Platform wiki with this content: …"
- "Open a PR from `feature/login` with Dev Two as required reviewer and link work item 1423."
- "Reply on PR 57's thread about the timeout and resolve it."
- "Fix the typo in README.md on a new branch `fix/readme-typo` and open a PR." (with `AZDO_ALLOW_PUSH=true`)
- "Approve PR 57." (with `AZDO_ALLOW_PR_VOTE=true`) · "Squash-merge PR 57." (with `AZDO_ALLOW_PR_MERGE=true`)
- "Run the api-ci pipeline on `feature/login`." (with `AZDO_ALLOW_PIPELINES=true`)
- "Delete work items 1501 and 1502, they were test entries." (with `AZDO_ALLOW_DELETE=true`)

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `AZDO_ALLOW_WRITE=true` and the PAT carries the matching write scopes. Leave the flag unset for a
  read-only deployment. Deletes, pushes, merges, votes, pipelines and releases additionally need their
  own switch (see [Write tools](#write-tools-opt-in)).
- **Content is data.** File contents, PR comments, work item text and wiki pages are written by other
  people; the server tells the agent to treat them as data, and every write still needs your
  confirmation.
- **Search** (`search`) needs Search installed and configured on Azure DevOps Server (code search: the
  Code Search extension). Without it, use WIQL (`query_work_items`) for work items.
- **Preview APIs:** search, release stages, wiki page moves, the Recycle Bin and identity lookups are
  called with `<AZDO_API_VERSION>-preview`, which Azure DevOps Server 2019–2022 accepts.
- **api-version** is global (`AZDO_API_VERSION`); a single tool can override it via
  `azdo_get(..., params={"api-version": "6.0"})`.
- **Large lists** (commits, builds, work items) are capped — widen with `limit` or filter (branch,
  author, status, WIQL) rather than fetching everything.
- **Releases** may be unused on a given server; an empty result or 404 just means none/not enabled.
- The newer `_apis/pipelines` API is partial/absent on older on-prem servers — this server uses the
  stable `_apis/build` API; reach pipelines via `azdo_get` if your server supports it.
