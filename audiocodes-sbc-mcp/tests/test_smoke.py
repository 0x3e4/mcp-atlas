"""Smoke and flow tests: registration, config, masking, certificate parsing and every write gate, against a
small fake device (httpx MockTransport router, no network)."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone

import httpx
import pytest

from audiocodes_sbc_mcp import server
from audiocodes_sbc_mcp.client import SbcError
from audiocodes_sbc_mcp.config import ConfigError, Settings

API = "/api/v1"
TEST_CERT = """-----BEGIN CERTIFICATE-----
MIICRjCCAa+gAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwPjEYMBYGA1UEAwwPc2Jj
LmV4YW1wbGUuY29tMRUwEwYDVQQKDAxFeGFtcGxlIENvcnAxCzAJBgNVBAYTAkFU
MB4XDTI2MTExNjE5NDgyOVoXDTI2MTIxNjE5NDgyOVowPjEYMBYGA1UEAwwPc2Jj
LmV4YW1wbGUuY29tMRUwEwYDVQQKDAxFeGFtcGxlIENvcnAxCzAJBgNVBAYTAkFU
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/uZmOlz1Vbpg8stOB6UTXnD5p
vPYpPoLZxDec4zaiVWxb8YMoLzNkPTI2JrHnHJ7uqepWqc44A7uBPreiCVu0EcI+
DbqOnLe02uioZIs0EKVA70UntF5Cnj2MPoH/pDjNYFMhp+qJ8Pc2n3M4Ruzv20jm
fAyPlqCsRpnvC0PCsQIDAQABo1MwUTAdBgNVHQ4EFgQUR1EaPiq0b8v/+Xkkz8oa
cJZxeAYwHwYDVR0jBBgwFoAUR1EaPiq0b8v/+Xkkz8oacJZxeAYwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQAQObxMX7Dlbein2wSHwL7KYLixEAVi
hfT+wvKDhOOuMu1BAtlxt/lOZukg5D3qN+ZSkrFCfWpN7BUvUtbAY0f8W+LK/K2v
wQRrb3u0IZPrfvr7lpZGYDcwqU3/ppt07poGid3+uYyBam/2F46uHHmRzqidPXUO
Mdct7nZKDXeR1g==
-----END CERTIFICATE-----
"""
STATUS = {"productType": "Mediant VE SBC", "versionID": "7.40A.500.000", "ipAddress": "192.0.2.10",
          "highAvailability": "Not Operational", "saveNeeded": True, "resetNeeded": False}


class Fake:
    """Routes (method, path regex) to a JSON body, text or a handler; later routes win. Records requests."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern[str], object, int]] = []
        self.sent: list[dict[str, object]] = []

    def on(self, method: str, pattern: str, body: object = None, status: int = 200) -> "Fake":
        self.routes.append((method, re.compile(pattern), body, status))
        return self

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.sent.append({"method": request.method, "path": request.url.path, "params": dict(request.url.params),
                          "body": request.content, "headers": dict(request.headers)})
        for method, rx, body, status in reversed(self.routes):
            if method == request.method and rx.search(request.url.path):
                if callable(body):
                    return body(request)
                if isinstance(body, str):
                    return httpx.Response(status, content=body.encode(), headers={"content-type": "application/octet-stream"})
                if body is None:
                    return httpx.Response(status)
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"description": "not found"})

    def writes(self) -> list[dict[str, object]]:
        return [s for s in self.sent if s["method"] != "GET" and not (s["method"] == "PUT" and b"show " in s["body"] and b"configure" not in s["body"])]


def use(fake: Fake, **flags: str) -> None:
    env = {"AUDIOCODES_BASE_URL": "https://sbc.example.com", "AUDIOCODES_USERNAME": "api", "AUDIOCODES_PASSWORD": "pw",
           "AUDIOCODES_ALLOW_WRITE": "true", "AUDIOCODES_CONFIRM_WRITE": "false", **flags}
    client = server.SbcClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(fake), auth=httpx.BasicAuth("api", "pw"))
    server._client = client


@pytest.fixture(autouse=True)
def _reset():
    yield
    server._client = None


def run(coro):
    return asyncio.run(coro)


# ---- config / registration ------------------------------------------------------------

def test_settings_required_normalised_and_switches_off():
    with pytest.raises(ConfigError):
        Settings.from_env({})
    base = {"AUDIOCODES_BASE_URL": "https://sbc.example.com/api/v1/", "AUDIOCODES_USERNAME": "u", "AUDIOCODES_PASSWORD": "p"}
    s = Settings.from_env(base)
    assert s.base_url == "https://sbc.example.com" and s.api_base == "https://sbc.example.com/api/v1"
    assert (s.allow_write, s.allow_reset, s.allow_tls, s.allow_license, s.confirm_write) == (False, False, False, False, True)
    with pytest.raises(ConfigError, match="https://"):
        Settings.from_env({**base, "AUDIOCODES_BASE_URL": "sbc.example.com"})
    with pytest.raises(ConfigError):
        Settings.from_env({**base, "MCP_TRANSPORT": "fax"})
    assert Settings.from_env({**base, "AUDIOCODES_ALLOW_RESET": "true"}).allow_reset is True


WRITE_TOOLS = {"apply_cli_script", "apply_ini", "save_configuration", "start_test_call", "sip_recording",
               "reset_device", "replace_configuration", "upgrade_firmware", "create_csr", "upload_certificate",
               "add_trusted_root", "generate_private_key", "generate_self_signed", "install_license"}
READ_TOOLS = {"device_status", "list_alarms", "get_alarm", "kpi", "kpi_intervals", "sbc_call_stats", "get_configuration",
              "run_show_commands", "list_files", "license_info", "list_tls_contexts", "get_tls_context", "get_test_call", "sbc_get"}


def test_tools_registered_with_descriptions_and_confirm_on_writes():
    tools = {t.name: t for t in run(server.mcp.list_tools())}
    assert WRITE_TOOLS | READ_TOOLS | {"drop_test_call"} <= set(tools)
    for name, tool in tools.items():
        assert tool.description and "properties" in tool.input_schema, name
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].input_schema["properties"], name
    for name in READ_TOOLS:
        assert "confirm" not in tools[name].input_schema["properties"], name


def test_version_is_reported():
    import pathlib
    import tomllib

    from audiocodes_sbc_mcp import __version__

    pyproject = tomllib.loads((pathlib.Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == pyproject["project"]["version"]
    assert server.mcp.version == __version__


# ---- helpers ---------------------------------------------------------------------------

def test_certificate_parsing():
    info = server._cert_infos(TEST_CERT + TEST_CERT, now=datetime(2026, 11, 26, tzinfo=timezone.utc))
    assert len(info) == 2
    assert info[0]["subject"] == "CN=sbc.example.com, O=Example Corp, C=AT" == info[0]["issuer"]
    assert info[0]["not_after"] == "2026-12-16T19:48:29+00:00" and info[0]["days_left"] == 20
    assert info[0]["serial"] == "1234"
    assert server._cert_infos("no pem here") == []


CLI = """configure system
 snmp settings
  ro-community-string "public1"
 exit
exit
configure voip
 sip-definition proxy-set 1
  proxy-name "ITSP"
  proxy-ip 0
   proxy-address "203.0.113.5:5060"
  exit
 exit
 sip-definition account 0
  user-name "trunk"
  password "s3cret!"
 exit
 ip-group 1
  name "ITSP"
 exit
exit
"""

INI = """;Board: Mediant VE SBC
RadiusSharedSecret = 'abc'
SNMPReadOnlyCommunityString = 'public1'
SyslogServerIP = 192.0.2.50

[ Account ]
FORMAT Account_Index = Account_ServedIPGroupName, Account_UserName, Account_Password, Account_HostName;
Account 0 = "PBX", "trunk", "s3cret!", "itsp.example.com";
[ \\Account ]

[ IPGroup ]
FORMAT IPGroup_Index = IPGroup_Name, IPGroup_ProxySetName;
IPGroup 1 = "ITSP", "ITSP";
[ \\IPGroup ]
"""


def test_masking_and_grep():
    cli = server._mask_cli(CLI)
    assert "s3cret" not in cli and "public1" not in cli and 'password "<masked>"' in cli
    assert 'proxy-address "203.0.113.5:5060"' in cli
    block = server._cli_blocks(cli, "proxy-set")
    assert block.startswith(" sip-definition proxy-set 1") and "proxy-address" in block and "account" not in block
    ini = server._mask_ini(INI)
    assert "s3cret" not in ini and "'abc'" not in ini and "public1" not in ini
    assert '"trunk"' in ini and "SyslogServerIP = 192.0.2.50" in ini
    section = server._ini_blocks(ini, "ipgroup")
    assert section.startswith("[ IPGroup ]") and section.endswith("[ \\IPGroup ]") and "Account" not in section


# ---- reads ------------------------------------------------------------------------------

def test_list_alarms_fetches_details_and_pages():
    fake = (Fake().on("GET", r"/alarms/active$", {"alarms": [{"id": 3, "description": "Proxy lost", "url": "/api/v1/alarms/active/3"}],
                                                   "cursor": {"after": "3", "before": "-1"}})
            .on("GET", r"/alarms/active/3$", {"id": 3, "description": "Proxy lost", "severity": "Major", "source": "ProxySet#1", "date": "2026-11-16 10:00:00"})
            .on("GET", r"/alarms/active/lastChange$", {"lastChange": "2026-11-16 10:00:00+01:00"}))
    use(fake)
    out = run(server.list_alarms(limit=5))
    assert out["alarms"] == [{"id": 3, "description": "Proxy lost", "severity": "Major", "source": "ProxySet#1", "date": "2026-11-16 10:00:00"}]
    assert out["cursor"] == {"after": "3"} and out["last_change"].startswith("2026-11-16")
    assert fake.sent[0]["params"] == {"limit": "5"}
    assert fake.sent[0]["headers"]["authorization"].startswith("Basic ")
    fake.on("GET", r"/alarms/history$", None, status=204)
    assert run(server.list_alarms(kind="history"))["alarms"] == []


def test_get_configuration_masks_and_needs_a_match():
    fake = Fake().on("GET", r"/files/cliScript$", CLI).on("GET", r"/files/ini$", INI)
    use(fake)
    out = run(server.get_configuration(grep="account"))
    assert "s3cret" not in out["text"] and "user-name" in out["text"]
    assert "s3cret" not in run(server.get_configuration(format="ini"))["text"]
    with pytest.raises(ValueError, match="Nothing"):
        run(server.get_configuration(grep="bgp"))


def test_run_show_commands_only_accepts_show():
    fake = Fake().on("PUT", r"/files/cliScript/incremental$", {"description": "loaded", "output": "Active calls: 3\npassword \"x\""})
    use(fake)
    for bad in ("configure voip", "show voip\nreload now", "reload now"):
        with pytest.raises(ValueError, match="show"):
            run(server.run_show_commands([bad]))
    out = run(server.run_show_commands(["show voip calls statistics sbc"]))
    assert "Active calls: 3" in out["text"] and 'password "<masked>"' in out["text"]
    sent = fake.sent[-1]
    assert sent["headers"]["content-type"].startswith("multipart/form-data") and b'name="file"' in sent["body"]
    assert b"show voip calls statistics sbc\n" in sent["body"]


def test_get_tls_context_reports_expiry_and_license_key_is_masked():
    fake = (Fake().on("GET", r"/files/tls/0/privateKey$", {"size": 2048, "valid": True})
            .on("GET", r"/files/tls/0/certificate$", TEST_CERT)
            .on("GET", r"/files/tls/0/trustedRoot$", TEST_CERT)
            .on("GET", r"/license$", {"serialNumber": "1234567", "key": "ABCDEFGHIJKLMNOP", "keyDescription": "SBC 100"}))
    use(fake)
    out = run(server.get_tls_context(0))
    assert out["private_key"] == {"size": 2048, "valid": True}
    assert out["certificate"]["subject"].startswith("CN=sbc.example.com") and len(out["trusted_roots_expiring_90d"]) == 1
    assert run(server.license_info())["key"] == "…KLMNOP"


def test_errors_are_clean_and_sbc_get_keeps_off_config_files():
    fake = Fake().on("GET", r"/status$", {"description": "Forbidden"}, status=403)
    use(fake)
    with pytest.raises(SbcError, match="privilege level"):
        run(server.device_status())
    with pytest.raises(ValueError, match="get_configuration"):
        run(server.sbc_get("files/cliScript"))
    with pytest.raises(ValueError, match="under /api/v1"):
        run(server.sbc_get("../../etc"))


# ---- writes -------------------------------------------------------------------------------

def test_every_write_refuses_without_allow_write():
    fake = Fake()
    use(fake, AUDIOCODES_ALLOW_WRITE="false", AUDIOCODES_ALLOW_RESET="true", AUDIOCODES_ALLOW_TLS="true", AUDIOCODES_ALLOW_LICENSE="true")
    for call in (server.apply_cli_script("configure voip\nexit"), server.save_configuration(), server.reset_device(),
                 server.start_test_call("100", "200", dest_ip_group="1"), server.generate_private_key(0),
                 server.install_license("KEY"), server.replace_configuration("x" * 30)):
        with pytest.raises(ValueError, match="AUDIOCODES_ALLOW_WRITE"):
            run(call)
    assert fake.sent == []


def test_apply_cli_script_confirms_refuses_resets_and_saves():
    fake = (Fake().on("PUT", r"/files/cliScript/incremental$", {"description": "Incremental CLI Script file was loaded.", "output": "ok"})
            .on("POST", r"/actions/saveConfiguration$", {"description": "saved"})
            .on("GET", r"/status$", {**STATUS, "saveNeeded": False}))
    use(fake, AUDIOCODES_CONFIRM_WRITE="true")
    with pytest.raises(ValueError, match="not allowed"):
        run(server.apply_cli_script("configure system\n write factory\nexit"))
    script = 'configure voip\n sip-definition account 0\n  password "n3w"\n exit\nexit'
    preview = run(server.apply_cli_script(script, save=True))
    assert preview["status"] == "confirmation_required" and "n3w" not in preview["script_preview"]
    assert fake.sent == []
    done = run(server.apply_cli_script(script, save=True, confirm=preview["confirm_code"]))
    assert done["applied"] and done["saved"] and done["saveNeeded"] is False
    put, save = [s for s in fake.sent if s["method"] != "GET"]
    assert b"sip-definition account 0" in put["body"]
    assert save["headers"].get("content-length") == "0"


def test_reset_needs_its_switch_always_confirms_and_maps_graceful():
    fake = Fake().on("GET", r"/status$", STATUS).on("POST", r"/actions/reset$", {"description": "Device will reset now"})
    use(fake)
    with pytest.raises(ValueError, match="AUDIOCODES_ALLOW_RESET"):
        run(server.reset_device())
    use(fake, AUDIOCODES_ALLOW_RESET="true")  # AUDIOCODES_CONFIRM_WRITE=false: still asks
    preview = run(server.reset_device(wait_for_calls=True, max_wait_seconds=300))
    assert preview["status"] == "confirmation_required" and "at most 300 s" in preview["summary"]
    run(server.reset_device(wait_for_calls=True, max_wait_seconds=300, confirm=preview["confirm_code"]))
    assert json.loads(fake.writes()[0]["body"]) == {"saveConfiguration": True, "gracefulTimeout": 300}
    now = run(server.reset_device(wait_for_calls=False))
    assert now["change"] == {"saveConfiguration": True, "gracefulTimeout": 0} and "dropping active calls" in now["summary"]


def test_replace_configuration_previews_a_masked_diff():
    fake = Fake().on("GET", r"/files/cliScript$", CLI).on("PUT", r"/files/cliScript$", {"description": "Device will reset now"})
    use(fake, AUDIOCODES_ALLOW_RESET="true")
    new = CLI.replace('name "ITSP"', 'name "ITSP-2"')
    preview = run(server.replace_configuration(new))
    assert '+  name "ITSP-2"' in preview["diff"] and "s3cret" not in preview["diff"]
    run(server.replace_configuration(new, confirm=preview["confirm_code"]))
    assert fake.writes()[0]["path"] == f"{API}/files/cliScript"


def test_upgrade_firmware_reads_only_from_the_file_dir(tmp_path):
    (tmp_path / "SBC_7.40A.cmp").write_bytes(b"\x00" * 2048)
    fake = Fake().on("GET", r"/status$", STATUS).on("PUT", r"/files/software$", {"description": "Device will reset now"})
    use(fake, AUDIOCODES_ALLOW_RESET="true")
    with pytest.raises(ValueError, match="AUDIOCODES_FILE_DIR"):
        run(server.upgrade_firmware("SBC_7.40A.cmp"))
    use(fake, AUDIOCODES_ALLOW_RESET="true", AUDIOCODES_FILE_DIR=str(tmp_path))
    for bad in ("../secret.cmp", "missing.cmp"):
        with pytest.raises(ValueError, match="No file"):
            run(server.upgrade_firmware(bad))
    with pytest.raises(ValueError, match="HA"):
        run(server.upgrade_firmware("SBC_7.40A.cmp", hitless=True))
    preview = run(server.upgrade_firmware("SBC_7.40A.cmp"))
    assert "RESETS" in preview["summary"]
    run(server.upgrade_firmware("SBC_7.40A.cmp", confirm=preview["confirm_code"]))
    assert fake.writes()[0]["path"] == f"{API}/files/software"


def test_tls_and_license_switches():
    fake = (Fake().on("GET", r"/files/tls/0/certificate$", TEST_CERT)
            .on("PUT", r"/files/tls/0/certificate$", {"description": "Certificate was successfully changed"})
            .on("POST", r"/files/tls/0/privateKey/generate$", {"description": "ok"})
            .on("GET", r"/license$", {"serialNumber": "1234567", "keyDescription": "SBC 100"})
            .on("PUT", r"/license$", {"description": "ok"}))
    use(fake)
    with pytest.raises(ValueError, match="AUDIOCODES_ALLOW_TLS"):
        run(server.upload_certificate(0, TEST_CERT))
    with pytest.raises(ValueError, match="AUDIOCODES_ALLOW_LICENSE"):
        run(server.install_license("KEY"))
    use(fake, AUDIOCODES_ALLOW_TLS="true", AUDIOCODES_ALLOW_LICENSE="true")
    with pytest.raises(ValueError, match="no readable certificate"):
        run(server.upload_certificate(0, "garbage"))
    run(server.upload_certificate(0, TEST_CERT))  # CONFIRM_WRITE=false: a certificate upload runs directly
    key = run(server.generate_private_key(0, size=4096))
    assert key["status"] == "confirmation_required" and "breaks" in key["summary"]
    lic = run(server.install_license("NEWKEY123456", description="SBC 200"))
    assert lic["status"] == "confirmation_required" and "…123456" in lic["summary"]
    run(server.install_license("NEWKEY123456", description="SBC 200", confirm=lic["confirm_code"]))
    assert json.loads(fake.writes()[-1]["body"]) == {"licenseVersion": 1, "key": "NEWKEY123456", "keyDescription": "SBC 200"}


def test_start_test_call_validates_and_builds_the_body():
    fake = Fake().on("POST", r"/sipTestCall/dial$", {"sessionId": "abc", "statusURL": "/api/v1/sipTestCall/getStatus?sessionId=abc"}, status=202)
    use(fake)
    with pytest.raises(ValueError, match="one of them"):
        run(server.start_test_call("100", "200"))
    with pytest.raises(ValueError, match="only apply"):
        run(server.start_test_call("100", "200", dest_ip_group="ITSP", transport="TLS"))
    out = run(server.start_test_call("100", "200", dest_address="198.51.100.9:5061", transport="TLS", timeout=10))
    assert out["session_id"] == "abc"
    assert json.loads(fake.writes()[0]["body"]) == {"calledNumber": "100", "callingNumber": "200", "timeout": 10,
                                                    "destAddress": "198.51.100.9:5061", "transportType": "TLS"}
