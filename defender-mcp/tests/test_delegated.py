"""Delegated (signed-in user) mode: settings, device code sign-in, refresh-token rotation, 'me'.

Entra and Graph are answered by an httpx MockTransport; the token cache lives in pytest's tmp_path.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys

import httpx
import pytest

from defender_mcp import graph, server, tokencache
from defender_mcp.config import ConfigError, Settings
from defender_mcp.graph import GraphClient, GraphError, _format_graph_error

UPN = "analyst@app.test.corp"


def _jwt(claims: dict) -> str:
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def _env(tmp_path, **extra: str) -> dict[str, str]:
    return {
        "DEFENDER_TENANT_ID": "t",
        "DEFENDER_CLIENT_ID": "c",
        "DEFENDER_AUTH": "delegated",
        "DEFENDER_TOKEN_CACHE": str(tmp_path / "cache" / "token.json"),
        **extra,
    }


def _client(settings: Settings, handler) -> GraphClient:
    client = GraphClient(settings)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def _token_payload(rt: str) -> dict:
    return {
        "access_token": _jwt({"upn": UPN, "scp": "SecurityIncident.ReadWrite.All SecurityAlert.Read.All"}),
        "refresh_token": rt,
        "id_token": _jwt({"preferred_username": UPN, "name": "Test Analyst", "oid": "oid-1"}),
        "expires_in": 3600,
    }


# ---- settings -----------------------------------------------------------

def test_delegated_needs_no_secret_but_app_does(tmp_path):
    s = Settings.from_env(_env(tmp_path))
    assert s.delegated and s.client_secret == ""
    assert s.delegated_scope == "openid profile offline_access https://graph.microsoft.com/.default"
    assert s.device_code_url == "https://login.microsoftonline.com/t/oauth2/v2.0/devicecode"
    assert s.graph_beta_url == "https://graph.microsoft.com/beta"
    with pytest.raises(ConfigError, match="DEFENDER_CLIENT_SECRET"):
        Settings.from_env({"DEFENDER_TENANT_ID": "t", "DEFENDER_CLIENT_ID": "c"})
    with pytest.raises(ConfigError, match="DEFENDER_AUTH"):
        Settings.from_env(_env(tmp_path, DEFENDER_AUTH="certificate"))
    # a secret set alongside delegated mode is ignored, not sent
    assert Settings.from_env(_env(tmp_path, DEFENDER_CLIENT_SECRET="s")).client_secret == ""


# ---- token cache --------------------------------------------------------

def test_token_cache_is_private_and_bound_to_the_app(tmp_path):
    path = str(tmp_path / "d" / "token.json")
    tokencache.save(path, {"tenant_id": "t", "client_id": "c", "refresh_token": "rt"})
    assert tokencache.load(path, tenant_id="t", client_id="c")["refresh_token"] == "rt"
    assert tokencache.load(path, tenant_id="t", client_id="other-app") is None
    if sys.platform != "win32":
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert tokencache.clear(path) and not tokencache.clear(path)
    assert tokencache.load(path, tenant_id="t", client_id="c") is None


def test_jwt_claims_tolerates_garbage():
    assert tokencache.jwt_claims("not-a-jwt") == {}
    assert tokencache.jwt_claims(None) == {}
    assert tokencache.jwt_claims(_jwt({"upn": UPN}))["upn"] == UPN


# ---- device code sign-in ------------------------------------------------

def test_device_login_polls_and_stores_the_refresh_token(tmp_path, monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(graph.asyncio, "sleep", no_sleep)
    polls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode()))
        if request.url.path.endswith("/devicecode"):
            assert form["scope"].startswith("openid profile offline_access")
            assert "client_secret" not in form
            return httpx.Response(200, json={"device_code": "dc", "user_code": "ABCD-EFGH", "interval": 1,
                                             "expires_in": 900, "verification_uri": "https://microsoft.com/devicelogin",
                                             "message": "To sign in, enter ABCD-EFGH"})
        polls.append(form)
        if len(polls) == 1:
            return httpx.Response(400, json={"error": "authorization_pending"})
        if len(polls) == 2:
            return httpx.Response(400, json={"error": "slow_down"})
        return httpx.Response(200, json=_token_payload("rt-1"))

    settings = Settings.from_env(_env(tmp_path))
    shown: list[str] = []
    user = asyncio.run(_client(settings, handler).device_login(show=shown.append))
    assert shown == ["To sign in, enter ABCD-EFGH"]
    assert user == {"username": UPN, "name": "Test Analyst", "oid": "oid-1"}
    assert polls[-1]["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
    stored = tokencache.load(settings.token_cache, tenant_id="t", client_id="c")
    assert stored["refresh_token"] == "rt-1" and stored["username"] == UPN


def test_device_login_reports_conditional_access_block(tmp_path, monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr(graph.asyncio, "sleep", no_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/devicecode"):
            return httpx.Response(200, json={"device_code": "dc", "user_code": "X", "interval": 1, "expires_in": 60})
        return httpx.Response(400, json={"error": "invalid_grant",
                                         "error_description": "AADSTS53003: Access has been blocked by Conditional Access policies."})

    with pytest.raises(GraphError, match="Conditional Access"):
        asyncio.run(_client(Settings.from_env(_env(tmp_path)), handler).device_login(show=lambda _: None))


def test_device_login_explains_missing_public_client_setting(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_client", "error_description":
                                         "AADSTS7000218: The request body must contain client_assertion or client_secret."})

    with pytest.raises(GraphError, match="Allow public client flows"):
        asyncio.run(_client(Settings.from_env(_env(tmp_path)), handler).device_login(show=lambda _: None))


# ---- refresh + Graph calls as the user ----------------------------------

def test_calls_use_and_rotate_the_stored_refresh_token(tmp_path):
    settings = Settings.from_env(_env(tmp_path))
    tokencache.save(settings.token_cache, {"tenant_id": "t", "client_id": "c", "refresh_token": "rt-old", "username": UPN})
    refreshes: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            refreshes.append(dict(httpx.QueryParams(request.content.decode())))
            return httpx.Response(200, json=_token_payload("rt-new"))
        assert request.headers["Authorization"].startswith("Bearer ")
        return httpx.Response(200, json={"value": []})

    client = _client(settings, handler)

    async def calls():
        await client.get("/security/incidents")
        await client.get("/security/alerts_v2")  # cached access token, no second refresh
        return await client.whoami()

    info = asyncio.run(calls())
    assert len(refreshes) == 1
    assert refreshes[0]["grant_type"] == "refresh_token" and refreshes[0]["refresh_token"] == "rt-old"
    assert "client_secret" not in refreshes[0]
    assert tokencache.load(settings.token_cache, tenant_id="t", client_id="c")["refresh_token"] == "rt-new"
    assert info == {"auth": "delegated", "user": UPN, "name": "Test Analyst",
                    "scopes": ["SecurityAlert.Read.All", "SecurityIncident.ReadWrite.All"]}


def test_not_signed_in_and_expired_sign_in_say_how_to_fix(tmp_path):
    settings = Settings.from_env(_env(tmp_path))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant",
                                         "error_description": "AADSTS700082: The refresh token has expired due to inactivity."})

    with pytest.raises(GraphError, match="Not signed in.*defender-mcp login"):
        asyncio.run(_client(settings, handler).get("/security/incidents"))
    tokencache.save(settings.token_cache, {"tenant_id": "t", "client_id": "c", "refresh_token": "rt", "username": UPN})
    with pytest.raises(GraphError, match=f"Sign-in of {UPN} can't be renewed.*AADSTS700082.*defender-mcp login"):
        asyncio.run(_client(settings, handler).get("/security/incidents"))


def test_delegated_403_mentions_the_users_role():
    req = httpx.Request("PATCH", "https://graph.microsoft.com/v1.0/security/incidents/29")
    r = httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}}, request=req)
    msg = _format_graph_error(r, delegated=True)
    assert "delegated write permission" in msg and "Security Operator" in msg
    req = httpx.Request("POST", "https://graph.microsoft.com/beta/security/caseManagement/cases")
    r = httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}}, request=req)
    assert "CaseManagement.ReadWrite.All" in _format_graph_error(r)


# ---- 'me' in write tools ------------------------------------------------

def test_assigned_to_me_resolves_to_the_signed_in_user(tmp_path):
    settings = Settings.from_env(_env(tmp_path, DEFENDER_ALLOW_WRITE="true", DEFENDER_CONFIRM_WRITE="false"))
    tokencache.save(settings.token_cache, {"tenant_id": "t", "client_id": "c", "refresh_token": "rt"})
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json=_token_payload("rt-2"))
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "29", "assignedTo": UPN})

    server._client = _client(settings, handler)
    try:
        asyncio.run(server.update_incident("29", assigned_to="me", status="inProgress"))
    finally:
        server._client = None
    assert sent == [{"status": "inProgress", "assignedTo": UPN}]


def test_assigned_to_me_needs_delegated_mode():
    server._client = GraphClient(Settings(tenant_id="t", client_id="c", client_secret="s", allow_write=True))
    try:
        with pytest.raises(ValueError, match="DEFENDER_AUTH=delegated"):
            asyncio.run(server.update_alert("da1", assigned_to="Me"))
    finally:
        server._client = None


# ---- CLI ----------------------------------------------------------------

def test_cli_status_and_logout(tmp_path, capsys):
    settings = Settings.from_env(_env(tmp_path))
    assert server._cli(settings, "status") == 1
    assert "Not signed in" in capsys.readouterr().out
    tokencache.save(settings.token_cache, {"tenant_id": "t", "client_id": "c", "refresh_token": "rt"})
    assert server._cli(settings, "logout") == 0
    assert "Signed out" in capsys.readouterr().out
    assert tokencache.load(settings.token_cache, tenant_id="t", client_id="c") is None
    assert server._cli(settings, "frobnicate") == 2


def test_cli_login_refuses_in_app_mode(capsys):
    settings = Settings(tenant_id="t", client_id="c", client_secret="s")
    assert server._cli(settings, "login") == 1
    assert "DEFENDER_AUTH=delegated" in capsys.readouterr().err
