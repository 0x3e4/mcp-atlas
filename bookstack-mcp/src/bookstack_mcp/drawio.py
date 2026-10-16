"""draw.io diagram helpers: validate diagram XML and carry it inside the PNG BookStack stores.

BookStack keeps a drawing as a PNG image (image-gallery ``type=drawio``). Its draw.io editor reopens
a drawing by loading that PNG, so the diagram XML must sit in the PNG the way draw.io writes it: a
``tEXt`` chunk with keyword ``mxfile`` holding the URI-encoded XML, placed before the image data
(draw.io's ``Editor.extractGraphModelFromPng`` stops reading at the first ``IDAT``).
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from urllib.parse import quote, unquote
from xml.etree import ElementTree as ET

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_KEYWORDS = (b"mxfile", b"mxGraphModel")


def normalize_xml(xml: str) -> tuple[str, int]:
    """Check diagram XML and return it as an ``<mxfile>`` document plus its cell count.

    Accepts an ``<mxfile>`` (what draw.io saves) or a bare ``<mxGraphModel>``, which gets wrapped in
    an ``<mxfile><diagram>``. Raises ``ValueError`` for anything else.
    """
    text = (xml or "").strip()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"The diagram is not valid XML: {exc}.") from exc
    if root.tag == "mxGraphModel":
        if text.startswith("<?xml"):
            text = text[text.index("?>") + 2 :].strip()
        # id derived from the content: the same input gives the same file (confirm codes rely on it)
        diagram = f'<diagram id="{hashlib.sha256(text.encode()).hexdigest()[:16]}" name="Page-1">{text}</diagram>'
        text = f'<mxfile host="bookstack-mcp">{diagram}</mxfile>'
        root = ET.fromstring(text)
    elif root.tag != "mxfile":
        raise ValueError(f"The diagram must be an <mxfile> or <mxGraphModel> document, not <{root.tag}>.")
    if root.find("diagram") is None:
        raise ValueError("The <mxfile> has no <diagram> page.")
    return text, sum(1 for _ in root.iter("mxCell"))


def _chunks(png: bytes):
    """Yield ``(type, data, start, end)`` for every chunk of a PNG."""
    if not png.startswith(PNG_SIGNATURE):
        raise ValueError("Not a PNG image.")
    pos = len(PNG_SIGNATURE)
    while pos + 8 <= len(png):
        (length,) = struct.unpack(">I", png[pos : pos + 4])
        kind = png[pos + 4 : pos + 8]
        end = pos + 12 + length
        yield kind, png[pos + 8 : pos + 8 + length], pos, end
        pos = end


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def embed_xml(png: bytes, xml: str) -> bytes:
    """Return ``png`` with ``xml`` stored as draw.io's ``mxfile`` text chunk (replacing any old one)."""
    out = [PNG_SIGNATURE]
    for kind, data, start, end in _chunks(png):
        if kind in (b"tEXt", b"zTXt", b"iTXt") and data.split(b"\0", 1)[0] in _KEYWORDS:
            continue
        out.append(png[start:end])
        if kind == b"IHDR":
            out.append(_chunk(b"tEXt", b"mxfile\0" + quote(xml, safe="-_.!~*'()").encode("ascii")))
    return b"".join(out)


def extract_xml(png: bytes) -> str | None:
    """Read the diagram XML back out of a draw.io PNG (``None`` if it carries none)."""
    for kind, data, _, _ in _chunks(png):
        if kind == b"IDAT":
            break
        keyword, _, rest = data.partition(b"\0")
        if keyword not in _KEYWORDS:
            continue
        if kind == b"tEXt":
            text = rest.decode("latin-1")
        elif kind == b"zTXt":
            try:
                raw = zlib.decompress(rest[1:])
            except zlib.error:
                raw = zlib.decompress(rest[1:], -15)  # older draw.io wrote raw DEFLATE
            text = raw.decode("utf-8").replace("+", " ")
        else:  # iTXt: flag, method, language\0, translated keyword\0, text
            flag, rest = rest[0], rest[2:]
            text_bytes = rest.split(b"\0", 2)[2]
            text = (zlib.decompress(text_bytes) if flag else text_bytes).decode("utf-8")
        for _ in range(2):  # draw.io decodes up to twice (double-encoded content)
            if text.startswith("%"):
                text = unquote(text)
        return text
    return None
