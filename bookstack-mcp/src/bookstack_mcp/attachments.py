"""Turn a downloaded attachment or image into something the agent can read.

(Same module as zammad-mcp's attachments.py; keep the copies in sync.)

- Images → MCP image content.
- PDF → its text per page; pages without a text layer (scans) are rendered to PNG so the agent can
  read them visually.
- E-mails (.eml / message/rfc822 and Outlook .msg) → headers, body text and a numbered list of the
  mail's own attachments; ``part=N`` opens attachment N through this same pipeline.
- Text files → text.
- Anything else → metadata only.

Pure functions, no network: the server fetches the bytes and hands them over.
"""

from __future__ import annotations

import email
import email.policy
import struct
import zlib
from html.parser import HTMLParser
from typing import Any

from mcp.server.fastmcp import Image

IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
MAX_IMAGE_BYTES = 3_750_000  # ≈ 5 MB once base64-encoded, the API's per-image limit
TEXT_TYPES = ("text/", "application/json", "application/xml", "application/x-yaml", "image/svg+xml")
MAX_TEXT_CHARS = 100_000
MAX_PDF_PAGES = 30  # pages read per call; use pages='31-60' for more
MAX_RENDERED_PAGES = 5  # scanned pages turned into images per call
_PDF_SCALE = 1.5  # ≈ 108 dpi: readable scans without huge images
_EML_TYPES = ("message/rfc822",)
_MSG_TYPES = ("application/vnd.ms-outlook", "application/x-msg")


# ---- dispatch -----------------------------------------------------------

def kind_of(data: bytes, content_type: str, filename: str = "") -> str:
    """Classify an attachment: image, pdf, eml, msg, text or binary (header, extension, magic bytes)."""
    ctype = content_type.split(";", 1)[0].strip().lower()
    name = filename.lower()
    if ctype in IMAGE_TYPES:
        return "image"
    if ctype == "application/pdf" or name.endswith(".pdf") or data.startswith(b"%PDF-"):
        return "pdf"
    if ctype in _MSG_TYPES or name.endswith(".msg"):
        return "msg"
    if ctype in _EML_TYPES or name.endswith(".eml"):
        return "eml"
    if ctype.startswith(TEXT_TYPES) or name.endswith((".log", ".txt", ".csv", ".json", ".xml", ".yml", ".yaml", ".ini", ".conf")):
        return "text"
    if _looks_like_text(data):  # scripts, markdown, configs with no or a generic content type
        return "text"
    return "binary"


def _looks_like_text(data: bytes) -> bool:
    """UTF-8 without NUL bytes in the first 8 KB (a cut multi-byte char at the end is fine)."""
    head = data[:8192]
    if not head or b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        return len(head) == 8192 and exc.start >= len(head) - 3
    return True


def read(
    data: bytes,
    content_type: str,
    filename: str = "",
    *,
    part: int | None = None,
    pages: str | None = None,
) -> list[Any]:
    """Return MCP content for an attachment: ``[metadata dict, *images]``."""
    kind = kind_of(data, content_type, filename)
    meta: dict[str, Any] = {
        "filename": filename or None,
        "content_type": content_type.split(";", 1)[0].strip().lower(),
        "size": len(data),
        "kind": kind,
    }
    if part is not None and kind not in ("eml", "msg"):
        raise ValueError("part only applies to e-mail attachments (.eml / .msg).")
    if kind == "image":
        if len(data) > MAX_IMAGE_BYTES:
            meta["note"] = f"Image too large to pass on ({len(data)} bytes, limit {MAX_IMAGE_BYTES})."
            return [meta]
        return [meta, Image(data=data, format=meta["content_type"].split("/", 1)[1])]
    if kind == "pdf":
        return _pdf(data, meta, pages)
    if kind in ("eml", "msg"):
        mail = parse_eml(data) if kind == "eml" else parse_msg(data)
        if part is None:
            meta.update(mail.summary())
            return [meta]
        if not 1 <= part <= len(mail.parts):
            raise ValueError(f"part must be 1..{len(mail.parts)} (this mail has {len(mail.parts)} attachments).")
        p = mail.parts[part - 1]
        if p.data is None:
            raise ValueError(f"Attachment {part} ({p.filename}) can't be extracted ({p.note}).")
        inner = read(p.data, p.content_type, p.filename, pages=pages)
        inner[0]["from_mail_part"] = part
        return inner
    if kind == "text":
        text = data.decode(_charset(content_type), errors="replace")
        meta["truncated"] = len(text) > MAX_TEXT_CHARS
        meta["text"] = text[:MAX_TEXT_CHARS]
        return [meta]
    meta["note"] = "File type that can't be read here (images, PDF, e-mails and text files can)."
    return [meta]


def _charset(content_type: str) -> str:
    for piece in content_type.split(";")[1:]:
        key, _, value = piece.strip().partition("=")
        if key.lower() == "charset" and value:
            value = value.strip('"')
            try:
                "".encode(value)
                return value
            except LookupError:
                break
    return "utf-8"


# ---- PDF ----------------------------------------------------------------

def _page_range(pages: str | None, total: int) -> range:
    if not pages:
        return range(0, min(total, MAX_PDF_PAGES))
    first, _, last = pages.partition("-")
    try:
        start = int(first)
        end = int(last) if last else start
    except ValueError as exc:
        raise ValueError("pages must look like '3' or '2-10'.") from exc
    if start < 1 or end < start:
        raise ValueError("pages must look like '3' or '2-10' (1-based).")
    end = min(end, total, start + MAX_PDF_PAGES - 1)
    return range(start - 1, end)


def _pdf(data: bytes, meta: dict[str, Any], pages: str | None) -> list[Any]:
    import pypdfium2 as pdfium  # native PDFium; imported lazily so a missing wheel only hits PDFs

    try:
        doc = pdfium.PdfDocument(data)
    except pdfium.PdfiumError as exc:
        meta["note"] = f"Could not open the PDF ({exc}); it may be encrypted or damaged."
        return [meta]
    images: list[Image] = []
    try:
        total = len(doc)
        span = _page_range(pages, total)
        meta["pages"] = total
        meta["pages_read"] = f"{span.start + 1}-{span.stop}" if span else "none"
        out_pages: list[dict[str, Any]] = []
        chars = 0
        for index in span:
            page = doc[index]
            text = page.get_textpage().get_text_bounded().strip()
            entry: dict[str, Any] = {"page": index + 1}
            if len(text) >= 20:
                remaining = MAX_TEXT_CHARS - chars
                entry["text"] = text[:max(remaining, 0)]
                chars += len(entry["text"])
                if remaining < len(text):
                    entry["truncated"] = True
            elif len(images) < MAX_RENDERED_PAGES:
                png = _render_png(page)
                if len(png) <= MAX_IMAGE_BYTES:
                    images.append(Image(data=png, format="png"))
                    entry["image"] = len(images)  # n-th image after this metadata
                else:
                    entry["note"] = "scanned page too large to render"
            else:
                entry["note"] = f"no text layer; only {MAX_RENDERED_PAGES} scanned pages are rendered per call — ask for pages='{index + 1}-…'"
            out_pages.append(entry)
        meta["content"] = out_pages
        if span.stop < total:
            meta["more"] = f"Pages {span.stop + 1}-{total} not read; call again with pages='{span.stop + 1}-{min(total, span.stop + MAX_PDF_PAGES)}'."
    finally:
        doc.close()
    return [meta, *images]


def _render_png(page: Any) -> bytes:
    """Render a PDF page to an RGB PNG without Pillow (PDFium bitmap → zlib-compressed scanlines)."""
    bitmap = page.render(scale=_PDF_SCALE, rev_byteorder=True, fill_color=(255, 255, 255, 255))
    width, height, stride, channels = bitmap.width, bitmap.height, bitmap.stride, bitmap.n_channels
    buf = bytes(bitmap.buffer)
    rows = bytearray()
    for y in range(height):
        row = bytearray(buf[y * stride : y * stride + width * channels])
        if channels == 4:
            del row[3::4]  # RGBx → RGB
        rows += b"\0" + row
    return _png(width, height, 0 if channels == 1 else 2, bytes(rows))


def _png(width: int, height: int, color_type: int, raw: bytes) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")


# ---- e-mail -------------------------------------------------------------

class _Part:
    def __init__(self, filename: str, content_type: str, data: bytes | None, note: str = "") -> None:
        self.filename = filename
        self.content_type = content_type
        self.data = data
        self.note = note


class _Mail:
    def __init__(self) -> None:
        self.headers: dict[str, str | None] = {}
        self.body = ""
        self.parts: list[_Part] = []

    def summary(self) -> dict[str, Any]:
        body = self.body.strip()
        return {
            **self.headers,
            "body": body[:MAX_TEXT_CHARS],
            "body_truncated": len(body) > MAX_TEXT_CHARS,
            "attachments": [
                {"part": i, "filename": p.filename, "content_type": p.content_type,
                 "size": len(p.data) if p.data is not None else None, **({"note": p.note} if p.note else {})}
                for i, p in enumerate(self.parts, 1)
            ],
            "hint": "Open a mail attachment with get_attachment(..., part=N)." if self.parts else None,
        }


def parse_eml(data: bytes) -> _Mail:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    mail = _Mail()
    mail.headers = {h: str(msg[h]) if msg[h] is not None else None for h in ("from", "to", "cc", "date", "subject")}
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    if plain is not None:
        mail.body = plain.get_content()
    elif html is not None:
        mail.body = html_to_text(html.get_content())
    for att in msg.iter_attachments():
        payload = att.get_payload(decode=True)
        if att.get_content_type() == "message/rfc822" and payload is None:
            inner = att.get_payload(0) if att.is_multipart() else None
            payload = inner.as_bytes() if inner is not None else None
        mail.parts.append(_Part(att.get_filename() or f"part-{len(mail.parts) + 1}", att.get_content_type(), payload))
    return mail


# MAPI property tags used by Outlook .msg files (MS-OXMSG / MS-OXPROPS).
_SUBJECT, _BODY, _HTML = "0037", "1000", "1013"
_SENDER_NAME, _SENDER_SMTP, _SENDER_EMAIL = "0C1A", "5D01", "0C1F"
_DISPLAY_TO, _DISPLAY_CC, _HEADERS = "0E04", "0E03", "007D"
_ATT_LONG_NAME, _ATT_NAME, _ATT_DATA, _ATT_MIME = "3707", "3704", "3701", "370E"


def parse_msg(data: bytes, *, ole: Any = None) -> _Mail:
    """Parse an Outlook .msg (OLE compound file) with olefile. ``ole`` lets tests pass a stand-in."""
    if ole is None:
        import io

        import olefile

        if not olefile.isOleFile(io.BytesIO(data)):
            raise ValueError("Not an Outlook .msg file (no OLE header).")
        ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        mail = _Mail()
        prop = lambda tag, prefix="": _msg_prop(ole, prefix, tag)  # noqa: E731
        sender = prop(_SENDER_NAME)
        address = prop(_SENDER_SMTP) or prop(_SENDER_EMAIL)
        transport = prop(_HEADERS)
        date = None
        if isinstance(transport, str):
            date = email.message_from_string(transport, policy=email.policy.default).get("date")
        mail.headers = {
            "from": f"{sender} <{address}>" if sender and address and sender != address else (address or sender),
            "to": prop(_DISPLAY_TO),
            "cc": prop(_DISPLAY_CC) or None,
            "date": str(date) if date else None,
            "subject": prop(_SUBJECT),
        }
        body = prop(_BODY)
        if not body:
            html = prop(_HTML)
            if isinstance(html, bytes):
                html = html.decode("utf-8", errors="replace")
            body = html_to_text(html or "")
        mail.body = body or ""
        storages = sorted({entry[0] for entry in ole.listdir(streams=True, storages=True) if entry and entry[0].startswith("__attach_version1.0_#")})
        for storage in storages:
            name = prop(_ATT_LONG_NAME, storage) or prop(_ATT_NAME, storage) or storage
            mime = prop(_ATT_MIME, storage) or "application/octet-stream"
            payload = prop(_ATT_DATA, storage)
            if isinstance(payload, bytes):
                mail.parts.append(_Part(name, mime, payload))
            else:
                mail.parts.append(_Part(name, mime, None, "embedded Outlook item or link — open the .msg in Outlook"))
        return mail
    finally:
        if hasattr(ole, "close"):
            ole.close()


def _msg_prop(ole: Any, prefix: str, tag: str) -> str | bytes | None:
    """Read property ``tag`` from the root (``prefix=''``) or an attachment storage."""
    base = f"{prefix}/" if prefix else ""
    for suffix, decode in (("001F", "utf-16-le"), ("001E", "cp1252"), ("0102", None)):
        path = f"{base}__substg1.0_{tag}{suffix}"
        if ole.exists(path):
            raw = ole.openstream(path).read()
            return raw.decode(decode, errors="replace").rstrip("\0") if decode else raw
    return None


class _TextExtractor(HTMLParser):
    _BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote"}

    def __init__(self) -> None:
        super().__init__()
        self.out: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in ("script", "style", "head"):
            self._skip += 1
        elif tag in self._BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head") and self._skip:
            self._skip -= 1
        elif tag in self._BLOCK:
            self.out.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.out.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    lines = [" ".join(line.split()) for line in "".join(parser.out).splitlines()]
    text = "\n".join(lines)
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text.strip()
