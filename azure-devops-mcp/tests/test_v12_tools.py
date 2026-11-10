"""Flows of the 1.2.0 tools against a small fake Azure DevOps (httpx MockTransport router, no network)."""

from __future__ import annotations

import asyncio
import json
import re

import httpx
import pytest

from azure_devops_mcp import server
from azure_devops_mcp.config import Settings

MAIN = "a" * 40
FEATURE = "b" * 40
BASE = "/DefaultCollection/Platform"
REPO = {"id": "r1", "name": "api", "defaultBranch": "refs/heads/main", "project": {"id": "p1"}}


class Fake:
    """Routes (method, path regex) to a JSON body or a handler; later routes win. Records every request."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern[str], object, int]] = []
        self.sent: list[tuple[str, str, dict[str, str], object]] = []

    def on(self, method: str, pattern: str, body: object = None, status: int = 200) -> "Fake":
        self.routes.append((method, re.compile(pattern), body, status))
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        payload: object = None
        if request.content:
            try:
                payload = json.loads(request.content)
            except ValueError:
                payload = request.content
        params = dict(request.url.params)
        self.sent.append((request.method, request.url.path, params, payload))
        for method, rx, body, status in reversed(self.routes):
            if method == request.method and rx.search(request.url.path):
                if callable(body):
                    return body(request, params, payload)
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"message": f"no route {request.method} {request.url.path}"})

    def writes(self) -> list[tuple[str, str, dict[str, str], object]]:
        return [s for s in self.sent if s[0] != "GET" and not s[1].endswith(("/wiql", "searchresults"))]


def use(fake: Fake, **flags: str) -> None:
    env = {"AZDO_BASE_URL": "https://devops.contoso.com/DefaultCollection", "AZDO_PAT": "secrettoken",
           "AZDO_PROJECT": "Platform", "AZDO_ALLOW_WRITE": "true", "AZDO_CONFIRM_WRITE": "false", **flags}
    client = server.AzdoClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    server._client = client


@pytest.fixture(autouse=True)
def _reset():
    yield
    server._client = None


def run(coro):
    return asyncio.run(coro)


def refs(known: dict[str, str]):
    """refs?filter=heads/x → the ref if known."""
    def handler(request, params, payload):
        name = "refs/" + params.get("filter", "")
        rows = [{"name": name, "objectId": known[name]}] if name in known else []
        return httpx.Response(200, json={"count": len(rows), "value": rows})
    return handler


def repo_fake(known_refs: dict[str, str] | None = None) -> Fake:
    return (Fake().on("GET", r"/_apis/git/repositories/api$", REPO)
            .on("GET", r"/_apis/git/repositories/r1/refs$", refs(known_refs or {"refs/heads/main": MAIN})))


# ---- config / registration ------------------------------------------------------

SWITCHES = ("AZDO_ALLOW_PUSH", "AZDO_ALLOW_PUSH_DEFAULT_BRANCH", "AZDO_ALLOW_PR_MERGE", "AZDO_ALLOW_PR_VOTE",
            "AZDO_ALLOW_POLICY_BYPASS", "AZDO_ALLOW_PIPELINES", "AZDO_ALLOW_RELEASES")


def test_new_switches_default_off_and_parse():
    base = {"AZDO_BASE_URL": "https://x/c", "AZDO_PAT": "t"}
    s = Settings.from_env(base)
    for env in SWITCHES:
        attr = env.removeprefix("AZDO_").lower()
        assert getattr(s, attr) is False, env
        assert getattr(Settings.from_env({**base, env: "true"}), attr) is True, env


NEW_WRITE_TOOLS = {
    "create_pull_request", "update_pull_request", "set_pull_request_reviewers", "comment_pull_request",
    "vote_pull_request", "complete_pull_request", "create_branch", "delete_branch", "commit_files",
    "link_work_items", "add_work_item_attachment", "restore_work_items", "move_wiki_page", "queue_build",
    "cancel_build", "create_release", "deploy_release_stage",
}
NEW_READ_TOOLS = {
    "server_info", "list_files", "get_file", "get_commit", "compare_versions", "list_tags", "search",
    "get_pull_request", "get_work_item", "list_work_item_types", "list_iterations", "list_areas",
    "list_wiki_pages", "get_build",
}


def test_new_tools_registered_and_writes_take_a_confirm_code():
    tools = {t.name: t for t in run(server.mcp.list_tools())}
    assert NEW_WRITE_TOOLS | NEW_READ_TOOLS <= set(tools)
    for name in NEW_WRITE_TOOLS:
        assert "confirm" in tools[name].input_schema["properties"], name
    for name in NEW_READ_TOOLS:
        assert "confirm" not in tools[name].input_schema["properties"], name


def test_every_write_tool_refuses_without_allow_write():
    fake = Fake()
    use(fake, AZDO_ALLOW_WRITE="false", **{k: "true" for k in SWITCHES})
    calls = [
        server.create_pull_request("api", "feature/x", "t"), server.commit_files("api", "x", "m", [{"path": "/a", "content": "1"}]),
        server.complete_pull_request(1), server.vote_pull_request(1, "approve"), server.queue_build(1),
        server.deploy_release_stage(1, "PROD"), server.link_work_items(1, add=[{"type": "related", "work_item_id": 2}]),
        server.create_branch("api", "x", "main"), server.move_wiki_page("w", "/a", "/b"),
    ]
    for call in calls:
        with pytest.raises(ValueError, match="AZDO_ALLOW_WRITE"):
            run(call)
    assert fake.sent == []


def test_server_info_reports_user_and_switches():
    fake = Fake().on("GET", r"/_apis/connectionData$", {"authenticatedUser": {"id": "u1", "providerDisplayName": "Dev One"}})
    use(fake, AZDO_ALLOW_PUSH="true")
    info = run(server.server_info())
    assert info["user"] == {"id": "u1", "name": "Dev One"}
    assert info["switches"]["AZDO_ALLOW_PUSH"] is True and info["switches"]["AZDO_ALLOW_PR_MERGE"] is False
    assert "secrettoken" not in json.dumps(info)
    assert fake.sent[0][2]["api-version"] == "7.0-preview"


# ---- work items -----------------------------------------------------------------

def test_create_work_item_any_type_with_parent_and_tags():
    """Also covers the missing `quote` import 1.1.0 shipped with (create_work_item raised NameError)."""
    fake = Fake().on("POST", r"/_apis/wit/workitems/", {"id": 99, "rev": 1, "fields": {}})
    use(fake)
    out = run(server.create_work_item("Product Backlog Item", "Login page", parent_id=1200, tags=["web", " ux "]))
    assert out["id"] == 99
    method, path, _params, ops = fake.writes()[0]
    assert path.endswith("/_apis/wit/workitems/$Product Backlog Item")
    assert {"op": "add", "path": "/fields/System.Tags", "value": "web; ux"} in ops
    assert {"op": "add", "path": "/relations/-", "value": {
        "rel": "System.LinkTypes.Hierarchy-Reverse",
        "url": "https://devops.contoso.com/DefaultCollection/_apis/wit/workItems/1200"}} in ops


def test_update_work_item_merges_tags():
    fake = (Fake().on("GET", r"/_apis/wit/workitems/7$", {"id": 7, "fields": {"System.Tags": "web; Old"}})
            .on("PATCH", r"/_apis/wit/workitems/7$", {"id": 7, "rev": 4}))
    use(fake)
    run(server.update_work_item(7, add_tags=["api", "WEB"], remove_tags=["old"], iteration_path="Platform\\Sprint 3"))
    ops = fake.writes()[0][3]
    assert {"op": "add", "path": "/fields/System.Tags", "value": "web; api"} in ops
    assert {"op": "add", "path": "/fields/System.IterationPath", "value": "Platform\\Sprint 3"} in ops


def test_link_work_items_adds_skips_and_removes_against_the_revision():
    item = {"id": 7, "rev": 12, "fields": {"System.Title": "Login"}, "relations": [
        {"rel": "System.LinkTypes.Related", "url": "https://devops.contoso.com/DefaultCollection/_apis/wit/workItems/5"},
        {"rel": "System.LinkTypes.Hierarchy-Reverse", "url": "https://devops.contoso.com/DefaultCollection/_apis/wit/workItems/1"},
    ]}
    fake = (Fake().on("GET", r"/_apis/wit/workitems/7$", item)
            .on("GET", r"/_apis/git/repositories/api$", REPO)
            .on("PATCH", r"/_apis/wit/workitems/7$", {"id": 7, "rev": 13, "relations": []}))
    use(fake)
    out = run(server.link_work_items(7, add=[
        {"type": "related", "work_item_id": 5},                                  # exists → skipped
        {"type": "parent", "work_item_id": 1200},
        {"type": "pull_request", "repository": "api", "pull_request_id": 57},
        {"type": "branch", "repository": "api", "branch": "feature/login"},
    ], remove=[{"type": "parent", "work_item_id": 1}, {"type": "child", "work_item_id": 3}]))
    assert out["skipped"] == ["related #5"] and out["not_found"] == ["child #3"]
    ops = fake.writes()[0][3]
    assert ops[0] == {"op": "test", "path": "/rev", "value": 12}
    urls = [o["value"]["url"] for o in ops if o["op"] == "add"]
    assert urls == ["https://devops.contoso.com/DefaultCollection/_apis/wit/workItems/1200",
                    "vstfs:///Git/PullRequestId/p1%2Fr1%2F57", "vstfs:///Git/Ref/p1%2Fr1%2FGBfeature%2Flogin"]
    assert ops[-1] == {"op": "remove", "path": "/relations/1"}


def test_restore_work_items_previews_and_patches_the_recycle_bin():
    def bin_item(request, params, payload):
        if request.url.path.endswith("/8"):
            return httpx.Response(404, json={"message": "not in recycle bin"})
        return httpx.Response(200, json={"id": 7, "name": "Old bug", "type": "Bug", "deletedDate": "2026-11-01"})

    fake = Fake().on("GET", r"/_apis/wit/recyclebin/\d+$", bin_item).on("PATCH", r"/_apis/wit/recyclebin/7$", {"id": 7})
    use(fake, AZDO_CONFIRM_WRITE="true")
    preview = run(server.restore_work_items([7, 8]))
    assert preview["status"] == "confirmation_required" and preview["not_found"] == [8]
    done = run(server.restore_work_items([7, 8], confirm=preview["confirm_code"]))
    assert done["restored"][0]["result"] == "restored"
    method, path, params, body = fake.writes()[0]
    assert path == f"{BASE}/_apis/wit/recyclebin/7" and body == {"IsDeleted": False} and params["api-version"] == "7.0-preview"


def test_get_work_item_shapes_links_and_discussion():
    fake = (Fake().on("GET", r"/_apis/wit/workitems/7$", {"id": 7, "rev": 3, "fields": {"System.Title": "x"}, "relations": [
        {"rel": "System.LinkTypes.Hierarchy-Forward", "url": "https://h/c/_apis/wit/workItems/8"},
        {"rel": "ArtifactLink", "url": "vstfs:///Git/PullRequestId/p%2Fr%2F5", "attributes": {"name": "Pull Request"}},
        {"rel": "AttachedFile", "url": "https://h/c/_apis/wit/attachments/1", "attributes": {"name": "log.txt"}}]})
            .on("GET", r"/_apis/wit/workitems/7/updates$", {"value": [
                {"revisedBy": {"displayName": "A"}, "fields": {"System.History": {"newValue": "first"}}},
                {"revisedBy": {"displayName": "B"}, "fields": {"System.State": {"newValue": "Active"}}},
                {"revisedBy": {"displayName": "C"}, "fields": {"System.History": {"newValue": "second"}}}]}))
    use(fake)
    out = run(server.get_work_item(7))
    assert [r["type"] for r in out["relations"]] == ["child", "pull_request", "attachment"]
    assert out["relations"][0]["work_item_id"] == 8
    assert [c["text"] for c in out["comments"]] == ["first", "second"]


def test_list_iterations_returns_field_paths():
    fake = Fake().on("GET", r"/_apis/wit/classificationnodes/iterations$", {"name": "Platform", "children": [
        {"name": "Sprint 1", "attributes": {"startDate": "2026-11-02", "finishDate": "2026-11-13"}},
        {"name": "2027", "children": [{"name": "Sprint 2"}]}]})
    use(fake)
    rows = run(server.list_iterations())["value"]
    assert [r["path"] for r in rows] == ["Platform", "Platform\\Sprint 1", "Platform\\2027", "Platform\\2027\\Sprint 2"]
    assert rows[1]["start"] == "2026-11-02"


# ---- repos: branches and pushes ----------------------------------------------------

def items(files: dict[str, str]):
    def handler(request, params, payload):
        path = params.get("path")
        if path not in files:
            return httpx.Response(404, json={"message": "TF401174: item not found"})
        return httpx.Response(200, json={"path": path, "objectId": "o1", "gitObjectType": "blob", "content": files[path]})
    return handler


def test_commit_files_keeps_off_the_default_branch_unless_allowed():
    fake = repo_fake()
    use(fake, AZDO_ALLOW_PUSH="true")
    with pytest.raises(ValueError, match="AZDO_ALLOW_PUSH_DEFAULT_BRANCH"):
        run(server.commit_files("api", "main", "fix", [{"path": "/a.txt", "content": "x"}]))
    use(fake)
    with pytest.raises(ValueError, match="AZDO_ALLOW_PUSH"):
        run(server.commit_files("api", "feature/x", "fix", [{"path": "/a.txt", "content": "x"}], create_branch_from="main"))
    assert fake.writes() == []


def test_commit_files_creates_the_branch_and_pushes_one_commit():
    fake = (repo_fake().on("GET", r"/_apis/git/repositories/r1/items$", items({"/README.md": "old\n", "/old.txt": "bye"}))
            .on("POST", r"/_apis/git/repositories/r1/refs$", {"value": [{"name": "refs/heads/feature/x", "success": True}]})
            .on("POST", r"/_apis/git/repositories/r1/pushes$", {"pushId": 5, "commits": [{"commitId": "c" * 40}]}))
    use(fake, AZDO_ALLOW_PUSH="true", AZDO_CONFIRM_WRITE="true")
    changes = [{"path": "README.md", "content": "new\n"}, {"path": "/docs/new.md", "content": "hi"},
               {"path": "/old.txt", "action": "delete"}]
    preview = run(server.commit_files("api", "feature/x", "Docs", changes, create_branch_from="main"))
    assert preview["status"] == "confirmation_required"
    assert [f["action"] for f in preview["files"]] == ["edit", "add", "delete"]
    assert "-old" in preview["files"][0]["diff"] and "+new" in preview["files"][0]["diff"]
    assert "diff" not in json.dumps(preview["change"])
    assert fake.writes() == []
    done = run(server.commit_files("api", "feature/x", "Docs", changes, create_branch_from="main", confirm=preview["confirm_code"]))
    assert done["pushed"] and done["created_branch"] and done["commit_id"] == "c" * 40
    ref_update, push = fake.writes()
    assert ref_update[3] == [{"name": "refs/heads/feature/x", "oldObjectId": "0" * 40, "newObjectId": MAIN}]
    assert push[3]["refUpdates"] == [{"name": "refs/heads/feature/x", "oldObjectId": MAIN}]
    assert [c["changeType"] for c in push[3]["commits"][0]["changes"]] == ["edit", "add", "delete"]


def test_commit_files_to_the_default_branch_always_confirms():
    fake = (repo_fake().on("GET", r"/_apis/git/repositories/r1/items$", items({}))
            .on("POST", r"/_apis/git/repositories/r1/pushes$", {"pushId": 6, "commits": [{"commitId": "d" * 40}]}))
    use(fake, AZDO_ALLOW_PUSH="true", AZDO_ALLOW_PUSH_DEFAULT_BRANCH="true")  # AZDO_CONFIRM_WRITE=false
    preview = run(server.commit_files("api", "main", "Add", [{"path": "/n.txt", "content": "1"}]))
    assert preview["status"] == "confirmation_required" and "DEFAULT branch" in preview["summary"]
    run(server.commit_files("api", "main", "Add", [{"path": "/n.txt", "content": "1"}], confirm=preview["confirm_code"]))
    assert [w[1].rsplit("/", 1)[-1] for w in fake.writes()] == ["pushes"]


def test_commit_files_validates_through_the_mcp_schema():
    fake = repo_fake().on("GET", r"/_apis/git/repositories/r1/items$", items({}))
    use(fake, AZDO_ALLOW_PUSH="true", AZDO_CONFIRM_WRITE="true")
    result = run(server.mcp.call_tool("commit_files", {
        "repository": "api", "branch": "feature/y", "message": "m", "create_branch_from": "main",
        "changes": [{"path": "/x.txt", "content": "1"}]}))
    text = result.content[0].text if hasattr(result, "content") else result[0].text
    assert json.loads(text)["status"] == "confirmation_required"


def test_branches_create_and_delete():
    fake = (repo_fake({"refs/heads/main": MAIN, "refs/heads/old": FEATURE})
            .on("POST", r"/_apis/git/repositories/r1/refs$", {"value": [{"success": True}]}))
    use(fake, AZDO_ALLOW_DELETE="true")
    run(server.create_branch("api", "feature/z", "main"))
    with pytest.raises(ValueError, match="default branch"):
        run(server.delete_branch("api", "main"))
    preview = run(server.delete_branch("api", "old"))  # always confirmed
    assert preview["status"] == "confirmation_required"
    run(server.delete_branch("api", "old", confirm=preview["confirm_code"]))
    create, delete = [w[3][0] for w in fake.writes()]
    assert create == {"name": "refs/heads/feature/z", "oldObjectId": "0" * 40, "newObjectId": MAIN}
    assert delete == {"name": "refs/heads/old", "oldObjectId": FEATURE, "newObjectId": "0" * 40}


def test_compare_versions_diffs_one_file_from_the_merge_base():
    def item(request, params, payload):
        content = {"m" * 40: "a\nb\n", "feature/x": "a\nc\n"}[params["versionDescriptor.version"]]
        return httpx.Response(200, json={"path": params["path"], "content": content})

    fake = (Fake().on("GET", r"/diffs/commits$", {"aheadCount": 2, "behindCount": 0, "commonCommit": "m" * 40,
                                                   "changes": [{"item": {"path": "/f.txt"}, "changeType": "edit"},
                                                               {"item": {"path": "/src", "isFolder": True}, "changeType": "edit"}]})
            .on("GET", r"/items$", item))
    use(fake)
    out = run(server.compare_versions("api", "main", "feature/x", path="/f.txt"))
    assert out["changes"] == [{"path": "/f.txt", "change": "edit"}]
    assert "-b" in out["file"]["diff"] and "+c" in out["file"]["diff"]
    assert fake.sent[0][2]["diffCommonCommit"] == "true"


def test_get_file_and_list_files():
    fake = (Fake().on("GET", r"/_apis/git/repositories/api/items$", lambda r, p, b: httpx.Response(200, json=(
        {"value": [{"path": "/", "isFolder": True}, {"path": "/src", "isFolder": True}, {"path": "/a.py", "objectId": "1"}]}
        if "scopePath" in p else {"path": p["path"], "content": "x" * 5000, "commitId": MAIN}))))
    use(fake)
    listed = run(server.list_files("api"))
    assert [r["path"] for r in listed["value"]] == ["/src", "/a.py"]
    got = run(server.get_file("api", "/a.py", version="main", max_chars=1000))
    assert len(got["content"]) == 1000 and "4000 more" in got["truncated"]
    assert fake.sent[-1][2]["versionDescriptor.versionType"] == "branch"


# ---- pull requests ------------------------------------------------------------------

def identities(request, params, payload):
    people = {"dev.two@contoso.com": [{"id": "u2", "providerDisplayName": "Dev Two"}],
              "lead": [{"id": "u3", "providerDisplayName": "Lead One"}, {"id": "u4", "providerDisplayName": "Lead Two"}],
              "dev": [{"id": "u5", "providerDisplayName": "Dev"}, {"id": "u6", "providerDisplayName": "Dev Ops"}]}
    rows = people.get(params.get("filterValue"), [])
    return httpx.Response(200, json={"count": len(rows), "value": rows})


def test_create_pull_request_defaults_to_the_default_branch_and_resolves_reviewers():
    fake = (repo_fake({"refs/heads/main": MAIN, "refs/heads/feature/x": FEATURE})
            .on("GET", r"/_apis/identities$", identities)
            .on("POST", r"/pullrequests$", {"pullRequestId": 57, "title": "Login", "reviewers": []}))
    use(fake)
    with pytest.raises(ValueError, match="several identities"):
        run(server.create_pull_request("api", "feature/x", "Login", reviewers=["lead"]))
    out = run(server.create_pull_request("api", "feature/x", "Login", reviewers=["dev"],  # exact display name wins
                                         required_reviewers=["dev.two@contoso.com"], work_item_ids=[7]))
    assert out["pullRequestId"] == 57
    body = fake.writes()[0][3]
    assert body["targetRefName"] == "refs/heads/main" and body["sourceRefName"] == "refs/heads/feature/x"
    assert body["reviewers"] == [{"id": "u5", "isRequired": False}, {"id": "u2", "isRequired": True}]
    assert body["workItemRefs"] == [{"id": "7"}]


PR = {"pullRequestId": 57, "title": "Login", "status": "active", "isDraft": False, "mergeStatus": "succeeded",
      "sourceRefName": "refs/heads/feature/x", "targetRefName": "refs/heads/main", "repository": {"id": "r1"},
      "lastMergeSourceCommit": {"commitId": FEATURE}, "reviewers": [{"id": "u9", "displayName": "Rev", "vote": -10}]}


def pr_fake(pr: dict | None = None) -> Fake:
    return (Fake().on("GET", r"/_apis/git/pullrequests/57$", pr or PR)
            .on("GET", r"/_apis/git/repositories/r1/pullrequests/57$", pr or PR)
            .on("GET", r"/_apis/connectionData$", {"authenticatedUser": {"id": "u1", "providerDisplayName": "Dev One"}})
            .on("PATCH", r"/pullrequests/57$", {**(pr or PR), "status": "completed"})
            .on("PUT", r"/reviewers/u1$", {"displayName": "Dev One", "vote": 10}))


def test_complete_pull_request_gates_and_always_confirms():
    fake = pr_fake()
    use(fake)
    with pytest.raises(ValueError, match="AZDO_ALLOW_PR_MERGE"):
        run(server.complete_pull_request(57))
    use(fake, AZDO_ALLOW_PR_MERGE="true")
    with pytest.raises(ValueError, match="AZDO_ALLOW_POLICY_BYPASS"):
        run(server.complete_pull_request(57, bypass_policy=True, bypass_reason="hotfix"))
    with pytest.raises(ValueError, match="AZDO_ALLOW_DELETE"):
        run(server.complete_pull_request(57, delete_source_branch=True))
    preview = run(server.complete_pull_request(57, merge_strategy="squash"))  # AZDO_CONFIRM_WRITE=false
    assert preview["status"] == "confirmation_required" and "Rejected by: Rev." in preview["warnings"]
    assert fake.writes() == []
    run(server.complete_pull_request(57, merge_strategy="squash", confirm=preview["confirm_code"]))
    body = fake.writes()[0][3]
    assert body["status"] == "completed" and body["lastMergeSourceCommit"] == {"commitId": FEATURE}
    assert body["completionOptions"]["mergeStrategy"] == "squash"


def test_complete_pull_request_code_dies_with_a_new_push():
    fake = pr_fake()
    use(fake, AZDO_ALLOW_PR_MERGE="true")
    preview = run(server.complete_pull_request(57))
    fake.on("GET", r"/_apis/git/pullrequests/57$", {**PR, "lastMergeSourceCommit": {"commitId": "e" * 40}})
    again = run(server.complete_pull_request(57, confirm=preview["confirm_code"]))
    assert again["status"] == "confirmation_required" and "did not match" in again["note"]
    assert fake.writes() == []


def test_vote_needs_its_switch_and_votes_as_the_pat_user():
    fake = pr_fake()
    use(fake)
    with pytest.raises(ValueError, match="AZDO_ALLOW_PR_VOTE"):
        run(server.vote_pull_request(57, "approve"))
    use(fake, AZDO_ALLOW_PR_VOTE="true")
    out = run(server.vote_pull_request(57, "approve"))
    assert out["vote"] == "approved"
    method, path, _params, body = fake.writes()[0]
    assert method == "PUT" and path.endswith("/_apis/git/repositories/r1/pullRequests/57/reviewers/u1") and body == {"vote": 10}


def test_comment_pull_request_on_a_line_and_resolve_a_thread():
    fake = (pr_fake().on("POST", r"/threads$", {"id": 3, "status": "active", "comments": [{"id": 1}]})
            .on("PATCH", r"/threads/3$", {"id": 3, "status": "fixed"}))
    use(fake)
    run(server.comment_pull_request(57, "Typo here", file_path="src/app.py", line=12))
    run(server.comment_pull_request(57, thread_id=3, thread_status="fixed"))
    new, resolve = fake.writes()
    assert new[3]["threadContext"] == {"filePath": "/src/app.py", "rightFileStart": {"line": 12, "offset": 1},
                                       "rightFileEnd": {"line": 12, "offset": 1}}
    assert resolve[3] == {"status": "fixed"}


def test_get_pull_request_collects_threads_files_and_work_items():
    fake = (pr_fake()
            .on("GET", r"/pullRequests/57/workitems$", {"value": [{"id": "7"}]})
            .on("GET", r"/pullRequests/57/threads$", {"value": [
                {"id": 1, "comments": [{"id": 1, "commentType": "system", "content": "voted"}]},
                {"id": 2, "status": "active", "threadContext": {"filePath": "/a.py", "rightFileStart": {"line": 4}},
                 "comments": [{"id": 1, "commentType": "text", "content": "why?", "author": {"displayName": "Rev"}}]}]})
            .on("GET", r"/pullRequests/57/iterations$", {"value": [{"id": 1}, {"id": 2}]})
            .on("GET", r"/pullRequests/57/iterations/2/changes$", {"changeEntries": [
                {"item": {"path": "/a.py"}, "changeType": "edit"}]}))
    use(fake)
    out = run(server.get_pull_request(57))
    assert out["work_items"] == [7] and out["iteration"] == 2
    assert out["threads"] == [{"id": 2, "status": "active", "file": "/a.py", "line": 4,
                               "comments": [{"id": 1, "author": "Rev", "date": None, "content": "why?"}]}]
    assert out["files"] == [{"path": "/a.py", "change": "edit"}]
    assert out["reviewers"] == [{"name": "Rev", "vote": "rejected", "required": False}]


# ---- search, wiki, builds, releases --------------------------------------------------

def test_search_uses_the_preview_version_and_explains_a_missing_search():
    fake = Fake().on("POST", r"/_apis/search/workitemsearchresults$", {"count": 1, "results": [
        {"fields": {"system.id": "7", "system.title": "Login"}, "hits": [{"highlights": ["<em>login</em>"]}]}]})
    use(fake)
    out = run(server.search("login", kind="work_items"))
    assert out["results"][0]["id"] == "7" and out["results"][0]["highlights"] == ["<em>login</em>"]
    method, path, params, body = fake.sent[0]
    assert path == f"{BASE}/_apis/search/workitemsearchresults" and params["api-version"] == "7.0-preview"
    assert body["filters"] == {"System.TeamProject": ["Platform"]}
    with pytest.raises(server.AzdoError, match="install and configure Search"):
        run(server.search("x"))


def test_move_wiki_page_checks_both_paths():
    def page(request, params, payload):
        if params["path"] == "/Old":
            return httpx.Response(200, headers={"ETag": '"v1"'}, json={"path": "/Old", "subPages": [{"path": "/Old/A"}]})
        return httpx.Response(404, json={"message": "page not found"})

    fake = Fake().on("GET", r"/_apis/wiki/wikis/w/pages$", page).on("POST", r"/pagemoves$", {"page": {"path": "/New"}})
    use(fake)
    out = run(server.move_wiki_page("w", "/Old", "/New", comment="tidy"))
    assert out == {"moved": True, "from": "/Old", "to": "/New", "subpages_moved": 1}
    method, path, params, body = fake.writes()[0]
    assert body == {"path": "/Old", "newPath": "/New"} and params["comment"] == "tidy"
    with pytest.raises(ValueError, match="No page"):
        run(server.move_wiki_page("w", "/Missing", "/X"))


def test_get_build_shows_failed_tasks_with_their_log_tail():
    fake = (Fake().on("GET", r"/_apis/build/builds/9$", {"id": 9, "result": "failed"})
            .on("GET", r"/_apis/build/builds/9/timeline$", {"records": [
                {"type": "Task", "name": "Build", "result": "failed", "log": {"id": 4},
                 "issues": [{"type": "error", "message": "CS1002: ; expected"}]},
                {"type": "Task", "name": "Checkout", "result": "succeeded", "log": {"id": 2}}]})
            .on("GET", r"/_apis/build/builds/9/logs$", {"value": [{"id": 4, "lineCount": 100}]})
            .on("GET", r"/_apis/build/builds/9/logs/4$", {"count": 3, "value": ["l98", "l99", "error CS1002"]}))
    use(fake)
    out = run(server.get_build(9, log_lines=3))
    assert out["issues"] == [{"type": "error", "task": "Build", "message": "CS1002: ; expected"}]
    assert out["failed_tasks"] == [{"name": "Build", "log_id": 4, "log_tail": ["l98", "l99", "error CS1002"]}]
    assert fake.sent[-1][2]["startLine"] == "98" and fake.sent[-1][2]["endLine"] == "100"


def test_queue_build_needs_the_pipelines_switch():
    fake = (Fake().on("GET", r"/_apis/build/definitions/3$", {"id": 3, "name": "api-ci"})
            .on("POST", r"/_apis/build/builds$", {"id": 11, "status": "notStarted"}))
    use(fake)
    with pytest.raises(ValueError, match="AZDO_ALLOW_PIPELINES"):
        run(server.queue_build(3))
    use(fake, AZDO_ALLOW_PIPELINES="true")
    run(server.queue_build(3, branch="feature/x", parameters={"Env": "test"}))
    body = fake.writes()[0][3]
    assert body == {"definition": {"id": 3}, "sourceBranch": "refs/heads/feature/x", "parameters": '{"Env": "test"}'}


def test_deploy_release_stage_by_name_always_confirms():
    fake = (Fake().on("GET", r"/_apis/release/releases/45$", {"id": 45, "name": "Release-2", "environments": [
        {"id": 101, "name": "TEST", "status": "succeeded"}, {"id": 102, "name": "PROD", "status": "notStarted"}]})
            .on("PATCH", r"/_apis/release/releases/45/environments/102$", {"name": "PROD", "status": "queued"}))
    use(fake)
    with pytest.raises(ValueError, match="AZDO_ALLOW_RELEASES"):
        run(server.deploy_release_stage(45, "prod"))
    use(fake, AZDO_ALLOW_RELEASES="true")
    with pytest.raises(ValueError, match="TEST \\(id 101"):
        run(server.deploy_release_stage(45, "STAGING"))
    preview = run(server.deploy_release_stage(45, "prod"))
    assert preview["status"] == "confirmation_required"
    out = run(server.deploy_release_stage(45, "prod", confirm=preview["confirm_code"]))
    assert out == {"release": "Release-2", "stage": "PROD", "status": "queued"}
    assert fake.writes()[0][3]["status"] == "inProgress"
