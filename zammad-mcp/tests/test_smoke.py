"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio
import base64
import json
from email.message import EmailMessage

import httpx
import pytest

from zammad_mcp import attachments, server
from zammad_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_tickets",
    "get_ticket",
    "search_tickets",
    "get_ticket_articles",
    "get_article",
    "list_users",
    "search_users",
    "whoami",
    "list_organizations",
    "list_reference",
    "zammad_get",
    "add_note",
    "update_ticket",
    "create_ticket",
    "tag_ticket",
    "reply_email",
    "get_attachment",
}


def _tools() -> dict[str, object]:
    listed = asyncio.run(server.mcp.list_tools())
    return {t.name: t for t in listed}


def test_all_tools_registered():
    tools = _tools()
    assert EXPECTED_TOOLS <= set(tools)


def test_tools_have_descriptions_and_schemas():
    for name, tool in _tools().items():
        if name not in EXPECTED_TOOLS:
            continue
        assert tool.description and tool.description.strip(), f"{name} missing description"
        assert tool.inputSchema and "properties" in tool.inputSchema, f"{name} missing schema"


def test_required_params_present():
    tools = _tools()
    assert "path" in tools["zammad_get"].inputSchema["properties"]
    assert "query" in tools["search_tickets"].inputSchema["properties"]
    assert "ticket_id" in tools["get_ticket"].inputSchema["properties"]
    assert "kind" in tools["list_reference"].inputSchema["properties"]
    # write tools (always registered; gated at call time by ZAMMAD_ALLOW_WRITE)
    for p in ("ticket_id", "body"):
        assert p in tools["add_note"].inputSchema["properties"]
    for p in ("ticket_id", "pending_time"):
        assert p in tools["update_ticket"].inputSchema["properties"]
    for p in ("ticket_id", "add", "remove"):
        assert p in tools["tag_ticket"].inputSchema["properties"]
    for p in ("title", "group", "customer", "body"):
        assert p in tools["create_ticket"].inputSchema["properties"]


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {"ZAMMAD_BASE_URL": "https://zammad.example.com/", "ZAMMAD_TOKEN": "tok123"}


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.base_url == "https://zammad.example.com"
    assert s.base_origin == "https://zammad.example.com"
    assert s.api_base == "https://zammad.example.com/api/v1"
    assert s.auth_headers == {"Authorization": "Token token=tok123"}
    assert s.allow_write is False
    assert s.httpx_verify is True


def test_missing_token_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"ZAMMAD_BASE_URL": "https://zammad.example.com"})


def test_allow_write_flag_parses():
    env = _base_env()
    env["ZAMMAD_ALLOW_WRITE"] = "true"
    assert Settings.from_env(env).allow_write is True


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["ZAMMAD_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["ZAMMAD_CA_BUNDLE"] = "/etc/ssl/zammad.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/zammad.pem"


def test_write_tools_refuse_without_allow_write():
    server._client = server.ZammadClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="ZAMMAD_ALLOW_WRITE"):
            asyncio.run(server.tag_ticket(42, add=["vpn"]))
        with pytest.raises(ValueError, match="ZAMMAD_ALLOW_WRITE"):
            asyncio.run(server.update_ticket(42, state="closed"))
    finally:
        server._client = None


def test_tag_and_pending_payloads_match_the_zammad_api():
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path + ("?" + request.url.query.decode() if request.url.query else ""), body))
        if request.url.path.endswith("/tags"):
            return httpx.Response(200, json={"tags": ["vpn", "escalated"]})
        if request.url.path.startswith("/api/v1/tags/"):
            return httpx.Response(201, json=True)
        return httpx.Response(200, json={"id": 42, "state": "pending reminder"})

    env = _base_env()
    env["ZAMMAD_ALLOW_WRITE"] = "true"
    env["ZAMMAD_CONFIRM_WRITE"] = "false"
    client = server.ZammadClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client

    async def calls():
        out = await server.tag_ticket(42, add=["vpn", "escalated"], remove=["new"])
        assert out == {"ticket_id": 42, "tags": ["vpn", "escalated"]}
        await server.update_ticket(42, state="pending reminder", pending_time="2026-10-12T08:00:00Z")
        with pytest.raises(ValueError, match="Nothing to do"):
            await server.tag_ticket(42)

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    assert seen == [
        ("POST", "/api/v1/tags/add", {"item": "vpn", "object": "Ticket", "o_id": 42}),
        ("POST", "/api/v1/tags/add", {"item": "escalated", "object": "Ticket", "o_id": 42}),
        ("DELETE", "/api/v1/tags/remove", {"item": "new", "object": "Ticket", "o_id": 42}),
        ("GET", "/api/v1/tags?object=Ticket&o_id=42", None),
        ("PUT", "/api/v1/tickets/42?expand=true", {"state": "pending reminder", "pending_time": "2026-10-12T08:00:00Z"}),
    ]


CONFIRM_TOOLS = {'create_ticket', 'update_ticket', 'add_note', 'tag_ticket', 'reply_email'}


def test_write_tools_take_a_confirm_code_and_confirm_defaults_on():
    tools = _tools()
    for name in CONFIRM_TOOLS:
        assert "confirm" in tools[name].inputSchema["properties"], name
    assert Settings.from_env(_base_env()).confirm_write is True
    env = _base_env()
    env["ZAMMAD_CONFIRM_WRITE"] = "false"
    assert Settings.from_env(env).confirm_write is False


def test_writes_need_a_matching_confirm_code():
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.method)
        return httpx.Response(200, json={"id": 9, "ticket_id": 42})

    env = _base_env()
    env["ZAMMAD_ALLOW_WRITE"] = "true"
    client = server.ZammadClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client

    async def calls():
        preview = await server.add_note(42, "Called the user.")
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.add_note(42, "Something else.", confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert sent == []
        done = await server.add_note(42, "Called the user.", confirm=code)
        assert done.get("status") != "confirmation_required"

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == ["POST"]


def _reply_env_client(handler) -> None:
    env = _base_env()
    env["ZAMMAD_ALLOW_WRITE"] = "true"
    env["ZAMMAD_CONFIRM_WRITE"] = "false"
    client = server.ZammadClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client


_ARTICLES = [
    {"id": 1, "ticket_id": 42, "type": "email", "sender": "Customer", "internal": False,
     "from": "Jane Doe <jane@customer.test>", "to": "support@helpdesk.test",
     "cc": "boss@customer.test, Support <support@helpdesk.test>", "subject": "VPN down",
     "message_id": "<m1@customer.test>", "created_by_id": 7},
    {"id": 2, "ticket_id": 42, "type": "note", "sender": "Agent", "internal": True, "body": "checking"},
    {"id": 3, "ticket_id": 42, "type": "email", "sender": "Customer", "internal": False,
     "from": "Bob <bob@customer.test>", "reply_to": None,
     "to": "support@helpdesk.test, jane@customer.test", "cc": "agent@helpdesk.test, ops@customer.test",
     "subject": "RE: [Ticket#1001] VPN down", "message_id": "<m3@customer.test>", "created_by_id": 8},
]


def _reply_handler(posted: list):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST":
            posted.append(json.loads(request.content))
            return httpx.Response(201, json={"id": 99, **posted[-1]})
        if path == "/api/v1/tickets/42":
            return httpx.Response(200, json={"id": 42, "title": "VPN down", "customer_id": 7})
        if path == "/api/v1/ticket_articles/by_ticket/42":
            return httpx.Response(200, json=_ARTICLES)
        if path == "/api/v1/email_addresses":
            return httpx.Response(200, json=[{"id": 1, "email": "Support@helpdesk.test"}])
        if path == "/api/v1/users/me":
            return httpx.Response(200, json={"id": 3, "email": "agent@helpdesk.test"})
        if path == "/api/v1/users/7":
            return httpx.Response(200, json={"id": 7, "email": "Jane@customer.test"})
        return httpx.Response(404, json={"error": "not found"})
    return handler


def test_reply_email_to_customer_threads_on_the_last_email():
    posted: list = []
    _reply_env_client(_reply_handler(posted))
    try:
        asyncio.run(server.reply_email(42, "Fixed, please retry.", cc=["lead@customer.test"]))
    finally:
        server._client = None
    assert posted == [{
        "ticket_id": 42, "type": "email", "internal": False, "sender": "Agent",
        "to": "jane@customer.test", "cc": "lead@customer.test",
        "subject": "RE: [Ticket#1001] VPN down", "body": "Fixed, please retry.",
        "content_type": "text/plain", "subtype": "reply", "in_reply_to": "<m3@customer.test>",
    }]


def test_reply_email_all_drops_zammad_and_own_addresses():
    posted: list = []
    _reply_env_client(_reply_handler(posted))
    try:
        asyncio.run(server.reply_email(42, "Fixed.", recipients="all"))
        with pytest.raises(ValueError, match="'customer' or 'all'"):
            asyncio.run(server.reply_email(42, "x", recipients="everyone"))
    finally:
        server._client = None
    assert posted[0]["to"] == "bob@customer.test, jane@customer.test"
    assert posted[0]["cc"] == "ops@customer.test"
    assert posted[0]["in_reply_to"] == "<m3@customer.test>"


def test_reply_email_all_on_an_agent_email_goes_to_its_recipients():
    article = {"id": 5, "ticket_id": 42, "type": "email", "sender": "Agent", "internal": False,
               "from": "Agent A via Support <support@helpdesk.test>", "to": "jane@customer.test",
               "cc": "", "subject": "VPN down", "message_id": "<m5@helpdesk.test>", "created_by_id": 3}
    to, cc = asyncio.run(server._reply_all_recipients(None, article, {"support@helpdesk.test"}))
    assert (to, cc) == (["jane@customer.test"], [])


# ---- attachments --------------------------------------------------------

_PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 24


def _attachment_client() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/ticket_articles/by_ticket/42":
            return httpx.Response(200, json=[{
                "id": 9, "ticket_id": 42, "type": "email", "body": '<img src="/api/v1/ticket_attachment/42/9/5?view=inline">',
                "attachments": [
                    {"id": 5, "filename": "image001.png", "size": "32",
                     "preferences": {"Content-Type": "image/png", "Content-ID": "image001@01DA", "Content-Disposition": "inline"}},
                    {"id": 6, "filename": "vpn.log", "size": "11", "preferences": {"Content-Type": "text/plain"}},
                ],
            }])
        if path == "/api/v1/ticket_attachment/42/9/5":
            return httpx.Response(200, content=_PNG, headers={"content-type": "image/png"})
        if path == "/api/v1/ticket_attachment/42/9/6":
            return httpx.Response(200, content="fehler: ä".encode("latin-1"), headers={"content-type": "text/plain; charset=ISO-8859-1"})
        if path == "/api/v1/ticket_attachment/42/9/7":
            return httpx.Response(200, content=_pdf("Hallo VPN Fehler 809 beim Verbinden"), headers={
                "content-type": "application/octet-stream", "content-disposition": 'attachment; filename="report.pdf"'})
        return httpx.Response(403, json={"error": "The file does not belong to the specified article."})

    client = server.ZammadClient(Settings.from_env(_base_env()))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client


def test_articles_list_their_attachments():
    _attachment_client()
    try:
        out = asyncio.run(server.get_ticket_articles(42))
    finally:
        server._client = None
    assert out["items"][0]["attachments"] == [
        {"id": 5, "filename": "image001.png", "size": 32, "content_type": "image/png", "inline": True},
        {"id": 6, "filename": "vpn.log", "size": 11, "content_type": "text/plain", "inline": False},
    ]


def test_get_attachment_returns_images_as_image_content():
    _attachment_client()
    try:
        result = asyncio.run(server.mcp.call_tool("get_attachment", {"ticket_id": 42, "article_id": 9, "attachment_id": 5}))
        blocks = result[0] if isinstance(result, tuple) else result
        kinds = [b.type for b in blocks]
        assert kinds == ["text", "image"]
        assert blocks[1].mimeType == "image/png"
        assert base64.b64decode(blocks[1].data) == _PNG

        text = asyncio.run(server.get_attachment(42, 9, 6))[0]
        assert text["text"] == "fehler: ä" and text["truncated"] is False
        pdf = asyncio.run(server.get_attachment(42, 9, 7))
        assert pdf[0]["filename"] == "report.pdf" and pdf[0]["kind"] == "pdf" and pdf[0]["pages"] == 1
        assert "Fehler 809" in pdf[0]["content"][0]["text"] and len(pdf) == 1
        with pytest.raises(server.ZammadError, match="403"):
            asyncio.run(server.get_attachment(42, 9, 8))
    finally:
        server._client = None


def _pdf(text: str | None) -> bytes:
    """A minimal one-page PDF; text=None gives a page without a text layer (like a scan)."""
    stream = f"BT /F1 18 Tf 40 700 Td ({text}) Tj ET".encode() if text else b"0 0 1 rg 40 600 200 100 re f"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def test_scanned_pdf_pages_come_back_as_images():
    blocks = attachments.read(_pdf(None), "application/pdf", "scan.pdf")
    meta, image = blocks
    assert meta["content"] == [{"page": 1, "image": 1}]
    png = image.data
    assert png.startswith(b"\x89PNG") and image._mime_type == "image/png"
    import struct
    assert struct.unpack(">IIBB", png[16:26]) == (893, 1263, 8, 2)  # A4 at 1.5x, 8-bit RGB
    import zlib
    raw = zlib.decompress(png[png.index(b"IDAT") + 4 : png.index(b"IEND") - 8])
    assert len(raw) == 1263 * (1 + 893 * 3)
    row = raw[288 * (1 + 893 * 3) + 1 :][: 893 * 3]  # through the blue box (PDF y 600-700 = image rows 213-363)
    assert row[180 * 3 : 180 * 3 + 3] == b"\x00\x00\xff" and row[:3] == b"\xff\xff\xff"


def test_eml_lists_its_attachments_and_opens_them():
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "Jane <jane@customer.test>", "support@helpdesk.test", "Fehlerbericht"
    msg.set_content("Hallo,\nim Anhang der Bericht.")
    msg.add_alternative("<p>Hallo,<br>im Anhang <b>der</b> Bericht.</p>", subtype="html")
    msg.add_attachment(_pdf("Fehler 809 beim VPN Verbindungsaufbau"), maintype="application", subtype="pdf", filename="bericht.pdf")
    msg.add_attachment(b"\x89PNG\r\n\x1a\n" + b"\0" * 8, maintype="image", subtype="png", filename="shot.png")
    raw = msg.as_bytes()

    summary = attachments.read(raw, "message/rfc822", "mail.eml")
    assert len(summary) == 1
    s = summary[0]
    assert s["subject"] == "Fehlerbericht" and s["from"] == "Jane <jane@customer.test>"
    assert s["body"] == "Hallo,\nim Anhang der Bericht."
    assert [(a["part"], a["filename"], a["content_type"]) for a in s["attachments"]] == [
        (1, "bericht.pdf", "application/pdf"), (2, "shot.png", "image/png")]

    pdf = attachments.read(raw, "message/rfc822", "mail.eml", part=1)
    assert pdf[0]["from_mail_part"] == 1 and "Fehler 809" in pdf[0]["content"][0]["text"]
    shot = attachments.read(raw, "application/octet-stream", "Weiterleitung.eml", part=2)
    assert shot[0]["kind"] == "image" and len(shot) == 2
    with pytest.raises(ValueError, match="part must be 1..2"):
        attachments.read(raw, "message/rfc822", "mail.eml", part=3)
    with pytest.raises(ValueError, match="only applies to e-mail"):
        attachments.read(b"x", "text/plain", "a.txt", part=1)


class _FakeOle:
    """Stand-in for olefile.OleFileIO with the stream layout of an Outlook .msg."""

    def __init__(self, streams: dict[str, bytes]) -> None:
        self.streams = streams

    def exists(self, path: str) -> bool:
        return path in self.streams

    def openstream(self, path: str):
        import io
        return io.BytesIO(self.streams[path])

    def listdir(self, streams: bool = True, storages: bool = False):
        return [path.split("/") for path in self.streams]


def test_msg_properties_body_and_attachments():
    u = lambda s: s.encode("utf-16-le")  # noqa: E731
    ole = _FakeOle({
        "__substg1.0_0037001F": u("Druckerproblem"),
        "__substg1.0_0C1A001F": u("Jane Doe"),
        "__substg1.0_5D01001F": u("jane@customer.test"),
        "__substg1.0_0E04001F": u("Support"),
        "__substg1.0_007D001F": u("Date: Mon, 19 Oct 2026 08:15:00 +0200\r\nSubject: Druckerproblem\r\n"),
        "__substg1.0_10130102": b"<html><body><p>Drucker <b>druckt</b> nicht.</p><style>p{}</style></body></html>",
        "__attach_version1.0_#00000000/__substg1.0_3707001F": u("fehler.png"),
        "__attach_version1.0_#00000000/__substg1.0_370E001F": u("image/png"),
        "__attach_version1.0_#00000000/__substg1.0_37010102": b"\x89PNG\r\n\x1a\n",
        "__attach_version1.0_#00000001/__substg1.0_3707001F": u("weitergeleitet.msg"),
    })
    mail = attachments.parse_msg(b"", ole=ole)
    s = mail.summary()
    assert s["from"] == "Jane Doe <jane@customer.test>" and s["subject"] == "Druckerproblem"
    assert s["date"] == "Mon, 19 Oct 2026 08:15:00 +0200" and s["cc"] is None
    assert s["body"] == "Drucker druckt nicht."
    assert s["attachments"][0] == {"part": 1, "filename": "fehler.png", "content_type": "image/png", "size": 8}
    assert s["attachments"][1]["size"] is None and "embedded" in s["attachments"][1]["note"]
    with pytest.raises(ValueError, match="no OLE header"):
        attachments.parse_msg(b"not an ole file")


def test_zammad_get_reads_attachment_links_instead_of_failing_on_non_json():
    _attachment_client()
    try:
        # the agent copies the image link straight out of an article body
        result = asyncio.run(server.mcp.call_tool(
            "zammad_get", {"path": "/api/v1/ticket_attachment/42/9/5?view=inline"}))
        blocks = result[0] if isinstance(result, tuple) else result
        assert [b.type for b in blocks] == ["text", "image"] and blocks[1].mimeType == "image/png"
        assert json.loads(blocks[0].text)["path"] == "/api/v1/ticket_attachment/42/9/5?view=inline"

        pdf = asyncio.run(server.zammad_get("ticket_attachment/42/9/7"))
        assert pdf[0]["kind"] == "pdf" and "Fehler 809" in pdf[0]["content"][0]["text"]
        articles = asyncio.run(server.zammad_get("ticket_articles/by_ticket/42"))
        assert isinstance(articles, list) and articles[0]["id"] == 9  # JSON stays JSON
    finally:
        server._client = None
