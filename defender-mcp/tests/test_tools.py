"""Offline functional tests: query/filter construction, KQL escaping, result shaping, error mapping.

A FakeClient stands in for GraphClient, recording the path/params/KQL each tool produces and returning
canned data. No network and no credentials are required.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from defender_mcp import server
from defender_mcp.config import Settings
from defender_mcp.graph import GraphClient, _format_graph_error, _format_token_error


class FakeClient:
    """Records calls and returns OData/hunting-shaped canned data."""

    def __init__(self) -> None:
        self.settings = Settings(tenant_id="t", client_id="c", client_secret="s")
        self.calls: list[tuple[str, dict | None]] = []
        self.hunts: list[tuple[str, str | None]] = []

    async def get(self, path, params=None):
        self.calls.append((path, params))
        return {
            "value": [
                {
                    "id": "1",
                    "displayName": "incident",
                    "title": "alert",
                    "severity": "high",
                    "status": "active",
                    "assignedTo": "a@x.com",
                    "categories": ["Malware"],
                    "evidence": [{}, {}],
                    "alerts": [{}, {}, {}],
                }
            ]
        }

    async def run_hunting_query(self, query, timespan=None):
        self.hunts.append((query, timespan))
        return {
            "schema": [
                {"name": "DeviceId", "type": "String"},
                {"name": "DeviceName", "type": "String"},
            ],
            "results": [{"DeviceId": f"d{i}", "DeviceName": "host01"} for i in range(5)],
        }


@pytest.fixture
def fake(monkeypatch):
    fc = FakeClient()
    monkeypatch.setattr(server, "_client", fc)
    return fc


def run(coro):
    return asyncio.run(coro)


# ---- incidents ----------------------------------------------------------

def test_list_incidents_builds_filter_and_trims(fake):
    out = run(server.list_incidents(status="active", severity="high", assigned_to="me@x.com", top=5))
    path, params = fake.calls[-1]
    assert path == "/security/incidents"
    assert params["$top"] == 5
    assert params["$filter"] == "status eq 'active' and severity eq 'high' and assignedTo eq 'me@x.com'"
    inc = out["incidents"][0]
    assert inc["alertCount"] == 3
    assert "displayName" in inc and "id" in inc


def test_list_incidents_quotes_escaping(fake):
    run(server.list_incidents(assigned_to="o'brien@x.com"))
    _, params = fake.calls[-1]
    assert params["$filter"] == "assignedTo eq 'o''brien@x.com'"


def test_get_incident_expands_alerts(fake):
    run(server.get_incident("29"))
    path, params = fake.calls[-1]
    assert path == "/security/incidents/29"
    assert params == {"$expand": "alerts"}


def test_invalid_incident_status_rejected(fake):
    with pytest.raises(ValueError):
        run(server.list_incidents(status="bogus"))


# ---- alerts -------------------------------------------------------------

def test_list_alerts_server_filter_and_client_category(fake):
    out = run(server.list_alerts(severity="high", status="new", category="malware", top=10))
    path, params = fake.calls[-1]
    assert path == "/security/alerts_v2"
    assert params["$filter"] == "severity eq 'high' and status eq 'new'"
    assert out["count"] == 1  # "Malware" matches "malware" client-side


def test_list_alerts_category_no_match(fake):
    out = run(server.list_alerts(category="phishing"))
    assert out["count"] == 0


def test_invalid_alert_status_rejected(fake):
    with pytest.raises(ValueError):
        run(server.list_alerts(status="redirected"))  # valid for incidents, not alerts


# ---- devices & vulnerabilities -----------------------------------------

def test_list_devices_query_and_escaping(fake):
    run(server.list_devices(filter='host"01', top=7))
    query, _ = fake.hunts[-1]
    assert query.startswith("DeviceInfo")
    assert "arg_max(Timestamp, *) by DeviceId" in query
    assert "| take 7" in query
    assert '"host\\"01"' in query  # double-quote escaped in the KQL literal


def test_get_vulnerabilities_query(fake):
    run(server.get_vulnerabilities(device="host01", severity="Critical", cve="CVE-2024-1", top=3))
    query, _ = fake.hunts[-1]
    assert "DeviceTvmSoftwareVulnerabilities" in query
    assert 'DeviceName has "host01"' in query
    assert 'VulnerabilitySeverityLevel == "Critical"' in query
    assert 'CveId == "CVE-2024-1"' in query
    assert "| take 3" in query


def test_advanced_hunting_shapes(fake):
    out = run(server.advanced_hunting("DeviceInfo | take 5"))
    assert out["columns"] == ["DeviceId", "DeviceName"]
    assert out["row_count"] == 5
    assert out["truncated"] is False


# ---- escape hatches -----------------------------------------------------

def test_graph_get_rejects_foreign_host(fake):
    with pytest.raises(ValueError):
        run(server.graph_get("https://evil.example.com/x"))


def test_graph_get_allows_relative(fake):
    run(server.graph_get("/security/incidents", params={"$top": 1}))
    path, params = fake.calls[-1]
    assert path == "/security/incidents" and params == {"$top": 1}


# ---- result shaping -----------------------------------------------------

def test_shape_hunt_truncation():
    data = {"schema": [{"name": "A", "type": "String"}], "results": [{"A": i} for i in range(10)]}
    shaped = server._shape_hunt(data, full=False, limit=3)
    assert shaped["row_count"] == 10 and shaped["returned"] == 3 and shaped["truncated"] is True
    assert shaped["columns"] == ["A"]
    full = server._shape_hunt(data, full=True, limit=3)
    assert full["returned"] == 10 and full["truncated"] is False


# ---- GraphClient internals (no network) ---------------------------------

def test_run_hunting_query_uses_pascalcase_body():
    gc = GraphClient(Settings(tenant_id="t", client_id="c", client_secret="x"))
    captured: dict = {}

    async def fake_post(path, json):
        captured["path"] = path
        captured["json"] = json
        return {"schema": [], "results": []}

    gc.post = fake_post  # type: ignore[assignment]
    run(gc.run_hunting_query("DeviceInfo | take 1", timespan="P7D"))
    assert captured["path"] == "/security/runHuntingQuery"
    assert captured["json"] == {"Query": "DeviceInfo | take 1", "Timespan": "P7D"}


def test_graph_url_join():
    gc = GraphClient(Settings(tenant_id="t", client_id="c", client_secret="x"))
    assert gc._url("/security/incidents") == "https://graph.microsoft.com/v1.0/security/incidents"
    assert gc._url("https://graph.microsoft.com/v1.0/x") == "https://graph.microsoft.com/v1.0/x"


def test_gov_cloud_scope():
    s = Settings.from_env(
        {
            "DEFENDER_TENANT_ID": "t",
            "DEFENDER_CLIENT_ID": "c",
            "DEFENDER_CLIENT_SECRET": "x",
            "GRAPH_BASE_URL": "https://graph.microsoft.us/v1.0",
        }
    )
    assert s.scope == "https://graph.microsoft.us/.default"
    assert s.graph_origin == "https://graph.microsoft.us"


# ---- error mapping ------------------------------------------------------

def test_format_graph_error_403_mentions_consent():
    r = httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied", "message": "denied"}})
    msg = _format_graph_error(r)
    assert "403" in msg and "consent" in msg.lower()


def test_format_graph_error_429_surfaces_retry_after():
    r = httpx.Response(429, json={"error": {"code": "TooManyRequests"}}, headers={"Retry-After": "30"})
    msg = _format_graph_error(r)
    assert "429" in msg and "30" in msg


def test_format_token_error_includes_aadsts_hint():
    r = httpx.Response(400, json={"error": "invalid_grant", "error_description": "AADSTS65001: needs consent"})
    msg = _format_token_error(r)
    assert "invalid_grant" in msg and "consent" in msg.lower()
