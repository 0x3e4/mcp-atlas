"""Case management (Graph beta) tools: request paths, payloads, status/custom-field validation.

Graph is answered by an httpx MockTransport routing on method + path; no network, no credentials.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from defender_mcp import server
from defender_mcp.config import Settings

NS = "#microsoft.graph.security.caseManagement"
BETA = "/beta/security/caseManagement"
STATUSES = {"value": [
    {"id": "s1", "displayName": "Active", "sortOrder": 1,
     "customStatuses": [{"customStatusId": "c1", "displayName": "Triage", "sortOrder": 1, "isFinal": False}]},
    {"id": "s2", "displayName": "Resolved", "sortOrder": 2,
     "customStatuses": [{"customStatusId": "c2", "displayName": "Closed - Fixed", "sortOrder": 1, "isFinal": True}]},
]}
FIELDS = {"value": [
    {"@odata.type": f"{NS}.stringCustomFieldDefinition", "displayName": "Customer impact", "isRequired": False},
    {"@odata.type": f"{NS}.optionsCustomFieldDefinition", "displayName": "Region", "options": ["EU", "US"]},
    {"@odata.type": f"{NS}.numberCustomFieldDefinition", "displayName": "Users affected"},
    {"@odata.type": f"{NS}.dateTimeCustomFieldDefinition", "displayName": "Detected at"},
    {"@odata.type": f"{NS}.stringCustomFieldDefinition", "displayName": "Legacy", "isDisabled": True},
]}
INCIDENT_CASE = {"@odata.type": f"{NS}.incidentCase", "id": "ic-1", "displayName": "Phish wave", "incidentId": 29}
GENERIC_CASE = {"@odata.type": f"{NS}.genericCase", "id": "gc-1", "displayName": "Insider review", "status": "Active"}


def _install(*, confirm_write: bool = False):
    """Point server._client at a mocked Graph; returns the list of (method, path, query, body) sent."""
    sent: list[tuple[str, str, dict, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else None
        sent.append((method, path, dict(request.url.params), body))
        if path.endswith("/statuses"):
            return httpx.Response(200, json=STATUSES)
        if path.endswith("/customFields"):
            return httpx.Response(200, json=FIELDS)
        if method == "GET" and path == f"{BETA}/cases/ic-1":
            return httpx.Response(200, json=INCIDENT_CASE)
        if method == "GET" and path == f"{BETA}/cases/gc-1":
            return httpx.Response(200, json=GENERIC_CASE)
        if method == "GET" and path.endswith("/tasks"):
            return httpx.Response(200, json={"value": [{"id": "t1", "displayName": "Reset creds", "status": "new"}]})
        if method == "GET" and path.endswith("/activities"):
            return httpx.Response(200, json={"value": [
                {"@odata.type": f"{NS}.comment", "id": "a1", "message": "looking", "createdBy": "x"},
                {"@odata.type": f"{NS}.auditLog", "id": "a2", "action": "update"},
            ]})
        if method == "GET":
            return httpx.Response(200, json={"value": [INCIDENT_CASE, GENERIC_CASE]})
        if method == "PATCH" and path == f"{BETA}/cases/ic-1":
            return httpx.Response(202)
        if method == "PATCH" and "/tasks/" in path:
            return httpx.Response(204)
        if method == "PATCH":
            return httpx.Response(200, json={**GENERIC_CASE, **(body or {})})
        return httpx.Response(201, json={"id": "new-1", **(body or {})})

    env = {
        "DEFENDER_TENANT_ID": "t", "DEFENDER_CLIENT_ID": "c", "DEFENDER_CLIENT_SECRET": "s",
        "DEFENDER_ALLOW_WRITE": "true", "DEFENDER_CONFIRM_WRITE": "true" if confirm_write else "false",
    }
    client = server.GraphClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client
    return sent


@pytest.fixture
def graph():
    sent = _install()
    yield sent
    server._client = None


def run(coro):
    return asyncio.run(coro)


# ---- reads --------------------------------------------------------------

def test_list_cases_casts_by_type_and_filters(graph):
    out = run(server.list_cases(case_type="incident", status="Active", assigned_to="soc@app.test.corp", top=10))
    method, path, params, _ = graph[-1]
    assert path == f"{BETA}/cases/microsoft.graph.security.caseManagement.incidentCase"
    assert params == {"$top": "10", "$orderby": "createdDateTime desc",
                      "$filter": "status eq 'Active' and assignedTo eq 'soc@app.test.corp'"}
    assert out["cases"][0] == {"id": "ic-1", "displayName": "Phish wave", "incidentId": 29, "caseType": "incidentCase"}
    with pytest.raises(ValueError, match="case_type"):
        run(server.list_cases(assigned_to="soc@app.test.corp"))
    with pytest.raises(ValueError, match="case_type must be one of"):
        run(server.list_cases(case_type="generik"))


def test_get_case_returns_tasks_and_comments(graph):
    out = run(server.get_case("gc-1"))
    assert out["caseType"] == "genericCase"
    assert out["tasks"] == [{"id": "t1", "displayName": "Reset creds", "status": "new"}]
    assert out["comments"] == [{"id": "a1", "message": "looking", "createdBy": "x", "createdDateTime": None}]
    assert "auditLog" not in out
    assert len(run(server.get_case("gc-1", include_audit=True))["auditLog"]) == 1


def test_get_case_type_config(graph):
    out = run(server.get_case_type_config("generic"))
    assert out["statuses"][0] == {"displayName": "Active", "customStatuses": [{"displayName": "Triage", "isFinal": False}]}
    assert {"displayName": "Region", "options": ["EU", "US"], "type": "options"} in out["customFields"]
    assert graph[0][1] == f"{BETA}/caseTypeConfigurations/genericCase/statuses"


# ---- writes -------------------------------------------------------------

def test_create_case_wraps_custom_fields_and_normalises_status(graph):
    run(server.create_case(
        "Insider review", status="triage", priority="high", assigned_to="soc@app.test.corp",
        custom_fields={"Customer impact": "3 mailboxes", "Region": "EU", "Users affected": 3,
                       "Detected at": "2026-10-20T08:00:00Z"},
    ))
    method, path, _, body = graph[-1]
    assert (method, path) == ("POST", f"{BETA}/cases")
    assert body == {
        "@odata.type": f"{NS}.genericCase", "displayName": "Insider review", "status": "Triage",
        "assignedTo": "soc@app.test.corp", "priority": "high",
        "customFields": {
            "Customer impact": {"@odata.type": f"{NS}.customFieldStringValue", "value": "3 mailboxes"},
            "Region": {"@odata.type": f"{NS}.customFieldOptionsValue", "values": ["EU"]},
            "Users affected": {"@odata.type": f"{NS}.customFieldNumberValue", "value": 3},
            "Detected at": {"@odata.type": f"{NS}.customFieldDateTimeValue", "valueDateTime": "2026-10-20T08:00:00Z"},
        },
    }


def test_create_case_rejects_bad_status_and_fields(graph):
    with pytest.raises(ValueError, match="Active.*Triage.*Resolved"):
        run(server.create_case("x", status="Open"))
    with pytest.raises(ValueError, match="Unknown custom field"):
        run(server.create_case("x", status="Active", custom_fields={"Nope": "1"}))
    with pytest.raises(ValueError, match="only takes"):
        run(server.create_case("x", status="Active", custom_fields={"Region": ["APAC"]}))
    with pytest.raises(ValueError, match="whole number"):
        run(server.create_case("x", status="Active", custom_fields={"Users affected": "many"}))
    with pytest.raises(ValueError, match="disabled"):
        run(server.create_case("x", status="Active", custom_fields={"Legacy": "y"}))
    assert not [s for s in graph if s[0] != "GET"]


def test_update_incident_case_is_accepted_async(graph):
    out = run(server.update_case("ic-1", status="Resolved", classification="truePositive", determination="phishing"))
    assert out == {"id": "ic-1", "accepted": True,
                   "note": "Mirrored to the Defender incident; can take a few minutes to show on the case."}
    method, path, _, body = graph[-1]
    assert (method, path) == ("PATCH", f"{BETA}/cases/ic-1")
    assert body == {"@odata.type": f"{NS}.incidentCase", "classification": "truePositive",
                    "determination": "phishing", "status": "Resolved"}


def test_update_case_checks_fields_against_the_case_type(graph):
    with pytest.raises(ValueError, match=r"incidentCase can't set \['priority'\]"):
        run(server.update_case("ic-1", priority="high"))
    with pytest.raises(ValueError, match=r"genericCase can't set \['severity'\]"):
        run(server.update_case("gc-1", severity="high"))
    with pytest.raises(ValueError, match="Nothing to update"):
        run(server.update_case("gc-1"))
    out = run(server.update_case("gc-1", assigned_to="", due_date_time="", closing_notes="done"))
    assert graph[-1][3] == {"@odata.type": f"{NS}.genericCase", "closingNotes": "done",
                            "assignedTo": None, "dueDateTime": None}
    assert out["id"] == "gc-1" and out["caseType"] == "genericCase"


def test_case_comment_and_tasks(graph):
    c = run(server.add_case_comment("gc-1", "Escalated to IR"))
    assert graph[-1][1:] == ("/beta/security/caseManagement/cases/gc-1/activities", {},
                             {"@odata.type": f"{NS}.comment", "message": "Escalated to IR"})
    assert c["caseId"] == "gc-1" and c["message"] == "Escalated to IR"

    run(server.add_case_task("gc-1", "Reset creds", category="contain", priority="high"))
    assert graph[-1][3] == {"@odata.type": f"{NS}.task", "displayName": "Reset creds", "status": "new",
                            "priority": "high", "category": "contain"}

    out = run(server.update_case_task("gc-1", "t1", status="completed", closing_notes="done"))
    assert graph[-1][:2] == ("PATCH", f"{BETA}/cases/gc-1/tasks/t1")
    assert graph[-1][3] == {"status": "completed", "closingNotes": "done"}
    assert out == {"caseId": "gc-1", "id": "t1", "updated": True}

    with pytest.raises(ValueError, match="category must be one of"):
        run(server.add_case_task("gc-1", "x", category="hunt"))
    with pytest.raises(ValueError, match="plain id"):
        run(server.update_case_task("gc-1", "../../x", status="new"))


def test_case_writes_need_allow_write_and_confirmation():
    sent = _install(confirm_write=True)
    try:
        preview = run(server.add_case_comment("gc-1", "hi"))
        assert preview["status"] == "confirmation_required"
        run(server.add_case_comment("gc-1", "hi", confirm=preview["confirm_code"]))
        assert [s[0] for s in sent] == ["POST"]
        server._client = server.GraphClient(Settings(tenant_id="t", client_id="c", client_secret="s"))
        with pytest.raises(ValueError, match="DEFENDER_ALLOW_WRITE"):
            run(server.create_case("x", status="Active"))
    finally:
        server._client = None
