# Changelog

All notable changes to azure-devops-mcp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-11-10

### Added

- Repository reads: `list_files`, `get_file`, `get_commit` (with changed files), `compare_versions`
  (ahead / behind, changed files, unified diff of one file, from the merge base), `list_tags`.
- `search` over code, wiki and work items (needs Search on the server).
- Pull requests: `get_pull_request` (reviewers and votes, linked work items, comment threads with file
  and line, changed files, commits); `list_pull_requests` without a repository (whole project), with
  `mine`, `target_branch` and `source_branch` filters. Writes: `create_pull_request`,
  `update_pull_request` (edit, publish draft, retarget, abandon / reactivate),
  `set_pull_request_reviewers`, `comment_pull_request` (new thread on a file / line, reply, resolve).
- Branches and pushes: `create_branch`, `delete_branch`, `commit_files` (one commit of adds / edits /
  deletes / renames without a clone; the preview shows a diff of each edited file).
- Work items: `get_work_item` (all fields, links, discussion), `list_work_item_types`,
  `list_iterations` (also a team's current sprint), `list_areas`, `link_work_items` (parent / child,
  related, dependencies, duplicates, tests, PRs, commits, branches, hyperlinks),
  `add_work_item_attachment`, `restore_work_items`; `create_work_item` takes `parent_id` and `tags`,
  `update_work_item` takes `description`, `area_path`, `iteration_path`, `add_tags`, `remove_tags`.
- Wiki: `list_wiki_pages`, `move_wiki_page`; `create_or_update_wiki_page` takes a `comment`.
- Builds and releases: `get_build` (errors, failed tasks and their log tail), `queue_build`,
  `cancel_build`, `create_release`, `deploy_release_stage`.
- `server_info`: the PAT's user and which write switches are on.
- New switches for the sensitive writes, each on top of `AZDO_ALLOW_WRITE`, all off by default and read
  per instance: `AZDO_ALLOW_PUSH`, `AZDO_ALLOW_PUSH_DEFAULT_BRANCH`, `AZDO_ALLOW_PR_MERGE`,
  `AZDO_ALLOW_POLICY_BYPASS`, `AZDO_ALLOW_PR_VOTE`, `AZDO_ALLOW_PIPELINES`, `AZDO_ALLOW_RELEASES`;
  `delete_branch` uses `AZDO_ALLOW_DELETE`. Merges, policy bypasses, pushes to a default branch and
  release deployments always ask for confirmation; their codes are tied to the live state (the PR's
  source commit, the branch's commit).

### Fixed

- `create_work_item` failed with `NameError: name 'quote' is not defined` once confirmed (missing
  import since it was added); it is covered by a test now.

## [1.1.0] - 2026-11-10

### Added

- `delete_work_items` (to the Recycle Bin, or permanently with `destroy=true`) and `delete_wiki_page`
  (with its sub-pages, listed in the preview). Both need the new `AZDO_ALLOW_DELETE=true` on top of
  `AZDO_ALLOW_WRITE`, so deletes can be switched on per instance / user, and both always ask for
  confirmation, even with `AZDO_CONFIRM_WRITE=false`.

## [1.0.1] - 2026-11-09

### Changed

- Dependencies only move to releases that are at least 7 days old. pydantic 2.14.3 → 2.14.2,
  pydantic-core 2.50.4 → 2.50.2 and typing-inspection 0.4.5 → 0.4.4 went back to the newest
  releases that meet this; the newer ones follow once they are old enough.

## [1.0.0] - 2026-11-05

First versioned release.

### Added

- Read tools for an on-prem Azure DevOps Server (projects, repos, pull requests, work items, builds, releases, wiki) and opt-in writes for work items and wiki pages.

### Changed

- Moved to MCP SDK 2.x (`MCPServer`). Tools, parameters and env vars are unchanged; the server now
  reports its own version as `serverInfo.version`. `FASTMCP_HOST` is no longer read: the HTTP daemon
  binds to `MCP_HOST`.
- All dependencies updated; Docker images use Poetry 2.5.1.

### Security

- mcp 1.30+ / 2.x: CVE-2026-59950, CVE-2026-59951, CVE-2026-116684, CVE-2026-116685,
  CVE-2026-116686.
- pyjwt 2.15.1, anyio 4.16.0, cryptography 50.0.2 (CVE-2026-69247) and certifi 2026.10.23 fix the
  advisories pip-audit reported for the earlier locks.
