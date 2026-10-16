"""Static smoke tests: the server imports and all tools register with sane schemas.

These run with no credentials and make no network calls.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from bookstack_mcp import server
from bookstack_mcp.client import BookStackError
from bookstack_mcp import drawio
from bookstack_mcp.config import ConfigError, Settings

EXPECTED_TOOLS = {
    "list_shelves",
    "list_books",
    "list_chapters",
    "list_pages",
    "get_book",
    "get_chapter",
    "get_page",
    "search",
    "export_content",
    "list_attachments",
    "system_info",
    "bookstack_get",
    "create_page",
    "update_page",
    "create_chapter",
    "update_chapter",
    "create_book",
    "update_book",
    "create_shelf",
    "update_shelf",
    "add_comment",
    "get_drawing",
    "create_drawing",
    "update_drawing",
}


WRITE_TOOLS = {
    "create_page", "update_page", "create_chapter", "update_chapter", "create_book", "update_book",
    "create_shelf", "update_shelf", "add_comment", "create_drawing", "update_drawing",
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
    assert "path" in tools["bookstack_get"].inputSchema["properties"]
    assert "query" in tools["search"].inputSchema["properties"]
    assert "id" in tools["get_page"].inputSchema["properties"]
    assert "kind" in tools["export_content"].inputSchema["properties"]
    # write tools (always registered; gated at call time by BOOKSTACK_ALLOW_WRITE)
    for p in ("name", "book_id", "chapter_id", "markdown", "html", "tags"):
        assert p in tools["create_page"].inputSchema["properties"]
    for p in ("id", "move_to_book_id", "move_to_chapter_id", "changelog"):
        assert p in tools["update_page"].inputSchema["properties"]
    for p in ("add_book_ids", "remove_book_ids"):
        assert p in tools["update_shelf"].inputSchema["properties"]
    for p in ("page_id", "body", "reply_to"):
        assert p in tools["add_comment"].inputSchema["properties"]
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].inputSchema["properties"], name


def test_settings_requires_credentials():
    with pytest.raises(ConfigError):
        Settings.from_env({})


def _base_env() -> dict[str, str]:
    return {
        "BOOKSTACK_BASE_URL": "https://docs.example.com/",
        "BOOKSTACK_TOKEN_ID": "tid",
        "BOOKSTACK_TOKEN_SECRET": "tsecret",
    }


def test_settings_from_env_and_derived():
    s = Settings.from_env(_base_env())
    assert s.transport == "stdio"
    assert s.base_url == "https://docs.example.com"
    assert s.base_origin == "https://docs.example.com"
    assert s.api_base == "https://docs.example.com/api"
    assert s.httpx_verify is True


def test_settings_missing_one_secret():
    env = _base_env()
    del env["BOOKSTACK_TOKEN_SECRET"]
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_invalid_transport_rejected():
    env = _base_env()
    env["MCP_TRANSPORT"] = "carrier-pigeon"
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_verify_ssl_and_ca_bundle():
    env = _base_env()
    env["BOOKSTACK_VERIFY_SSL"] = "false"
    assert Settings.from_env(env).httpx_verify is False

    env = _base_env()
    env["BOOKSTACK_CA_BUNDLE"] = "/etc/ssl/bs-ca.pem"
    assert Settings.from_env(env).httpx_verify == "/etc/ssl/bs-ca.pem"


def test_allow_write_defaults_off_and_parses():
    assert Settings.from_env(_base_env()).allow_write is False
    assert Settings.from_env(_base_env()).confirm_write is True
    env = _base_env()
    env["BOOKSTACK_ALLOW_WRITE"] = "true"
    assert Settings.from_env(env).allow_write is True


def test_write_tools_refuse_without_allow_write():
    server._client = server.BookStackClient(Settings.from_env(_base_env()))
    try:
        with pytest.raises(ValueError, match="BOOKSTACK_ALLOW_WRITE"):
            asyncio.run(server.create_page("Runbook", book_id=1, markdown="# hi"))
        with pytest.raises(ValueError, match="BOOKSTACK_ALLOW_WRITE"):
            asyncio.run(server.update_shelf(3, add_book_ids=[9]))
    finally:
        server._client = None


def _write_client(handler, *, confirm_write: bool = False) -> server.BookStackClient:
    env = _base_env()
    env["BOOKSTACK_ALLOW_WRITE"] = "true"
    env["BOOKSTACK_CONFIRM_WRITE"] = "true" if confirm_write else "false"
    client = server.BookStackClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def test_write_payloads_match_the_bookstack_api():
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body))
        if request.method == "GET":  # update_shelf reads the current book list first
            return httpx.Response(200, json={"id": 3, "books": [{"id": 1}, {"id": 2}, {"id": 5}]})
        if request.url.path.endswith("/comments"):
            return httpx.Response(200, json={"id": 40, "local_id": 2, "commentable_id": 12, "parent_id": 1})
        return httpx.Response(200, json={"id": 12, "name": "Runbook", "slug": "runbook", "book_slug": "ops",
                                         "html": "<p>big</p>", "markdown": "big"})

    server._client = _write_client(handler)

    async def calls():
        page = await server.create_page("Runbook", chapter_id=7, markdown="# Steps", tags={"team": "ops", "draft": ""})
        assert page["url"] == "https://docs.example.com/link/12" and "html" not in page
        chapter = await server.update_chapter(4, name="Ops", move_to_book_id=2)
        assert chapter["url"] == "https://docs.example.com/books/ops/chapter/runbook"
        shelf = await server.update_shelf(3, add_book_ids=[9, 2], remove_book_ids=[1])
        assert shelf["book_ids"] == [2, 5, 9]
        comment = await server.add_comment(12, "Looks good <b>\r\nship it\n\nthanks", reply_to=1)
        assert comment["local_id"] == 2
        with pytest.raises(ValueError, match="exactly one body"):
            await server.create_page("x", book_id=1)
        with pytest.raises(ValueError, match="Nothing to update"):
            await server.update_page(12, changelog="noop")

    try:
        asyncio.run(calls())
    finally:
        server._client = None

    assert seen == [
        ("POST", "/api/pages", {"name": "Runbook", "chapter_id": 7, "markdown": "# Steps",
                                "tags": [{"name": "team", "value": "ops"}, {"name": "draft", "value": ""}]}),
        ("PUT", "/api/chapters/4", {"name": "Ops", "book_id": 2}),
        ("GET", "/api/shelves/3", None),
        ("PUT", "/api/shelves/3", {"books": [2, 5, 9]}),
        ("POST", "/api/comments", {"page_id": 12, "reply_to": 1,
                                   "html": "<p>Looks good &lt;b&gt;<br>ship it</p><p>thanks</p>"}),
    ]


def test_validation_errors_name_the_fields():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"error": {"code": 422, "message": "The given data was invalid.",
                                                   "validation": {"name": ["The name field is required."]}}})

    server._client = _write_client(handler)
    try:
        with pytest.raises(BookStackError, match="name: The name field is required"):
            asyncio.run(server.create_book("x"))
    finally:
        server._client = None


def test_writes_need_a_matching_confirm_code():
    sent: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path))
        return httpx.Response(200, json={"id": 5, "name": "Ops", "slug": "ops"})

    server._client = _write_client(handler, confirm_write=True)

    async def calls():
        preview = await server.create_book("Ops", description="Runbooks")
        assert preview["status"] == "confirmation_required" and preview["changed"] is False
        assert preview["change"] == {"name": "Ops", "description": "Runbooks"}
        assert "Confirm it?" in preview["next"]
        code = preview["confirm_code"]
        # a code only fits the exact arguments it was issued for
        other = await server.create_book("Ops", description="Something else", confirm=code)
        assert other["status"] == "confirmation_required" and "did not match" in other["note"]
        assert sent == []
        done = await server.create_book("Ops", description="Runbooks", confirm=code)
        assert done["id"] == 5 and done["url"] == "https://docs.example.com/books/ops"

    try:
        asyncio.run(calls())
    finally:
        server._client = None
    assert sent == [("POST", "/api/books")]


# ---- draw.io drawings ---------------------------------------------------

_DIAGRAM = (
    '<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
    '<mxCell id="a" value="Firewall &amp; VPN" style="rounded=1;" vertex="1" parent="1">'
    '<mxGeometry x="20" y="20" width="120" height="60" as="geometry"/></mxCell>'
    '</root></mxGraphModel>'
)


def _tiny_png() -> bytes:
    import struct
    import zlib
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    return (drawio.PNG_SIGNATURE + drawio._chunk(b"IHDR", ihdr)
            + drawio._chunk(b"IDAT", zlib.compress(b"\0\0\0\0\0")) + drawio._chunk(b"IEND", b""))


def test_drawio_xml_round_trips_through_the_png():
    xml, cells = drawio.normalize_xml('<?xml version="1.0"?>' + _DIAGRAM)
    assert xml.startswith("<mxfile") and "<diagram" in xml and cells == 3
    png = drawio.embed_xml(_tiny_png(), xml)
    kinds = [k for k, *_ in drawio._chunks(png)]
    assert kinds == [b"IHDR", b"tEXt", b"IDAT", b"IEND"]  # draw.io stops reading at IDAT
    assert drawio.extract_xml(png) == xml
    # re-embedding replaces the old diagram instead of stacking a second one
    again = drawio.embed_xml(png, xml.replace("Firewall", "Router"))
    assert [k for k, *_ in drawio._chunks(again)].count(b"tEXt") == 1
    assert "Router &amp; VPN" in drawio.extract_xml(again)
    assert drawio.extract_xml(_tiny_png()) is None


def test_drawio_reads_compressed_chunks_and_rejects_junk():
    import zlib
    ztxt = drawio._chunk(b"zTXt", b"mxfile\0\0" + zlib.compress(b"<mxfile><diagram>x+y</diagram></mxfile>"))
    png = _tiny_png()
    png = png[:33] + ztxt + png[33:]
    assert drawio.extract_xml(png) == "<mxfile><diagram>x y</diagram></mxfile>"
    for bad in ("not xml", "<svg/>", "<mxfile/>"):
        with pytest.raises(ValueError):
            drawio.normalize_xml(bad)


def _drawing_client(handler, *, export_url: str = "http://drawio-export:8000/") -> server.BookStackClient:
    env = _base_env()
    env.update({"BOOKSTACK_ALLOW_WRITE": "true", "BOOKSTACK_CONFIRM_WRITE": "false",
                "BOOKSTACK_DRAWIO_EXPORT_URL": export_url})
    client = server.BookStackClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


_IMAGE = {
    "id": 77, "name": "net.png", "type": "drawio", "uploaded_to": 12,
    "path": "/uploads/images/drawio/2026-10/net.png",
    "url": "https://docs.example.com/uploads/images/drawio/2026-10/net.png",
    "content": {"html": '<div drawio-diagram="77"><img src="https://docs.example.com/uploads/images/drawio/2026-10/net.png"></div>'},
}


def _drawing_handler(seen: list, page: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        url, body = request.url, request.content.decode("latin-1")
        seen.append((request.method, url.host, url.path, body, request.headers.get("authorization")))
        if url.host == "drawio-export":
            return httpx.Response(200, content=_tiny_png(), headers={"content-type": "image/png"})
        if url.path in ("/api/image-gallery", "/api/image-gallery/77"):
            return httpx.Response(200, json=_IMAGE)
        if url.path == "/api/pages/12" and request.method == "GET":
            return httpx.Response(200, json=page)
        if url.path == "/api/pages/12":
            return httpx.Response(200, json={"id": 12, "name": "Net", **json.loads(request.content)})
        return httpx.Response(404, json={"error": {"message": "nope"}})
    return handler


def test_create_drawing_renders_uploads_and_appends_to_the_page():
    seen: list = []
    page = {"id": 12, "markdown": "", "html": "<p>rendered</p>", "raw_html": '<p id="bkmrk-x">Intro</p>'}
    server._client = _drawing_client(_drawing_handler(seen, page))
    try:
        out = asyncio.run(server.create_drawing(12, _DIAGRAM, name="net.png"))
    finally:
        server._client = None
    export, upload, get_page, put_page = seen
    assert export[:3] == ("POST", "drawio-export", "/") and export[4] is None  # no BookStack token leaks
    assert "format=png" in export[3] and "mxGraphModel" in export[3]
    assert upload[:3] == ("POST", "docs.example.com", "/api/image-gallery")
    assert 'name="type"\r\n\r\ndrawio' in upload[3] and 'name="uploaded_to"\r\n\r\n12' in upload[3]
    assert "tEXtmxfile" in upload[3]  # the uploaded PNG carries the diagram
    assert get_page[:3] == ("GET", "docs.example.com", "/api/pages/12")
    sent = json.loads(put_page[3])
    assert sent["html"] == '<p id="bkmrk-x">Intro</p>\n' + out["snippet"]  # raw_html, not the rendered html
    assert sent["changelog"] == "Added drawing net.png"
    assert out["drawing"]["id"] == 77 and out["page"]["url"] == "https://docs.example.com/link/12"


def test_create_drawing_on_a_markdown_page_and_without_insert():
    seen: list = []
    server._client = _drawing_client(_drawing_handler(seen, {"id": 12, "markdown": "# Net\n", "raw_html": "<h1>Net</h1>"}))
    try:
        out = asyncio.run(server.create_drawing(12, _DIAGRAM, position="start"))
        assert json.loads(seen[-1][3])["markdown"] == out["snippet"] + "\n\n# Net"
        seen.clear()
        out = asyncio.run(server.create_drawing(12, _DIAGRAM, position="none"))
        assert [s[2] for s in seen] == ["/", "/api/image-gallery"] and "page" not in out
    finally:
        server._client = None


def test_update_and_get_drawing():
    seen: list = []
    stored = drawio.embed_xml(_tiny_png(), drawio.normalize_xml(_DIAGRAM)[0])
    inner = _drawing_handler(seen, {})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/image-gallery/77/data":
            return httpx.Response(200, content=stored, headers={"content-type": "image/png"})
        return inner(request)

    server._client = _drawing_client(handler)
    try:
        got = asyncio.run(server.get_drawing(77))
        assert got["xml"] == drawio.normalize_xml(_DIAGRAM)[0] and got["uploaded_to"] == 12
        seen.clear()
        asyncio.run(server.update_drawing(77, got["xml"], name="net-v2.png"))
    finally:
        server._client = None
    meta, export, upload = seen
    assert meta[:3] == ("GET", "docs.example.com", "/api/image-gallery/77")
    assert export[1] == "drawio-export"
    assert upload[:3] == ("POST", "docs.example.com", "/api/image-gallery/77")
    assert 'name="_method"\r\n\r\nPUT' in upload[3] and 'name="name"\r\n\r\nnet-v2.png' in upload[3]


def test_drawing_tools_need_an_export_server():
    server._client = _drawing_client(lambda r: httpx.Response(500), export_url="")
    try:
        with pytest.raises(ValueError, match="BOOKSTACK_DRAWIO_EXPORT_URL"):
            asyncio.run(server.create_drawing(12, _DIAGRAM))
    finally:
        server._client = None


def test_create_drawing_confirm_code_is_stable_for_the_same_diagram():
    seen: list = []
    env = _base_env()
    env.update({"BOOKSTACK_ALLOW_WRITE": "true", "BOOKSTACK_DRAWIO_EXPORT_URL": "http://drawio-export:8000/"})
    client = server.BookStackClient(Settings.from_env(env))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(_drawing_handler(seen, {"id": 12, "raw_html": ""})))
    server._client = client
    try:
        first = asyncio.run(server.create_drawing(12, _DIAGRAM))
        assert first["status"] == "confirmation_required" and seen == []  # nothing rendered or sent yet
        done = asyncio.run(server.create_drawing(12, _DIAGRAM, confirm=first["confirm_code"]))
    finally:
        server._client = None
    assert done["drawing"]["id"] == 77
