"""The hub's tool catalog and its search: pure logic, no network, no MCP.

Every upstream tool becomes a ``ToolEntry`` with the id ``<upstream>.<tool>``. ``Catalog.search`` ranks
entries with BM25 over the tool name (weighted highest), the upstream name, the first paragraph of the
description and the parameter names. With embeddings configured, the keyword score is blended with the
cosine similarity of query and tool text, which also finds tools for queries in another language or with
other words ("park a WAF rule" → set_waf_rule_state).
"""

from __future__ import annotations

import fnmatch
import math
import re
from dataclasses import dataclass, field
from typing import Any

# Keyword weights per field: a hit in the tool name says far more than one in the description.
_WEIGHTS = {"name": 3.0, "server": 2.0, "params": 1.0, "text": 1.0}
_K1, _B = 1.2, 0.75
_STOP = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is", "it", "of", "on", "or",
    "the", "to", "with", "this", "that", "all", "any", "one", "via", "per", "its", "can", "into",
})


def tokens(text: str) -> list[str]:
    """Lowercase word tokens; snake_case and camelCase are split, simple plurals folded."""
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text or "")
    out = []
    for word in re.findall(r"[a-z0-9]+", text.lower()):
        if word in _STOP or len(word) < 2:
            continue
        if len(word) > 4 and word.endswith("ies"):
            word = word[:-3] + "y"
        elif len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
            word = word[:-1]
        out.append(word)
    return out


def first_paragraph(text: str | None) -> str:
    return " ".join((text or "").strip().split("\n\n", 1)[0].split())


def tool_kind(annotations: Any, schema: dict[str, Any]) -> str:
    """read / write / destructive from the upstream's annotations (no annotations → write, the safe side)."""
    read_only = getattr(annotations, "read_only_hint", None) if annotations is not None else None
    destructive = getattr(annotations, "destructive_hint", None) if annotations is not None else None
    if read_only is True and "confirm" not in (schema.get("properties") or {}):
        return "read"
    return "destructive" if destructive is True else "write"


@dataclass
class ToolEntry:
    """One upstream tool as the hub knows it."""

    server: str
    name: str
    description: str
    schema: dict[str, Any]
    kind: str  # read | write | destructive
    vector: list[float] | None = field(default=None, repr=False)

    @property
    def id(self) -> str:
        return f"{self.server}.{self.name}"

    @property
    def summary(self) -> str:
        return first_paragraph(self.description)

    @property
    def embed_text(self) -> str:
        return f"{self.name.replace('_', ' ')}: {self.summary}"

    def params(self) -> dict[str, str]:
        """Parameter name → short type, '*' marking required ones; enough to call simple tools directly."""
        props = self.schema.get("properties") or {}
        required = set(self.schema.get("required") or [])
        out = {}
        for pname, prop in props.items():
            kind = prop.get("type") or next(
                (a.get("type") for a in prop.get("anyOf", []) if a.get("type") not in (None, "null")), "any"
            )
            out[pname] = f"{kind}{'*' if pname in required else ''}"
        return out

    def fields(self) -> dict[str, list[str]]:
        return {
            "name": tokens(self.name),
            "server": tokens(self.server),
            "params": tokens(" ".join((self.schema.get("properties") or {}).keys())),
            "text": tokens(self.summary),
        }


def allowed(tool_id: str, include: tuple[str, ...], exclude: tuple[str, ...]) -> bool:
    if include and not any(fnmatch.fnmatch(tool_id, p) for p in include):
        return False
    return not any(fnmatch.fnmatch(tool_id, p) for p in exclude)


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class Catalog:
    """Search over ToolEntry objects (BM25F-style keyword scoring, optionally blended with embeddings)."""

    def __init__(self, entries: list[ToolEntry]) -> None:
        self.entries = entries
        self.by_id = {e.id: e for e in entries}
        self._fields = [e.fields() for e in entries]
        self._lengths = [sum(len(v) * _WEIGHTS[k] for k, v in f.items()) for f in self._fields]
        self._avg = (sum(self._lengths) / len(self._lengths)) if self._lengths else 1.0
        df: dict[str, int] = {}
        for f in self._fields:
            for term in {t for v in f.values() for t in v}:
                df[term] = df.get(term, 0) + 1
        n = len(entries)
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def _keyword(self, i: int, query: list[str]) -> float:
        f, length = self._fields[i], self._lengths[i] or 1.0
        score = 0.0
        for term in set(query):
            idf = self._idf.get(term)
            if idf is None:
                continue
            tf = sum(f[k].count(term) * w for k, w in _WEIGHTS.items())
            if tf:
                score += idf * tf * (_K1 + 1) / (tf + _K1 * (1 - _B + _B * length / self._avg))
        # A query word that is part of the tool name ("waf" in list_waf_rules) is a strong signal.
        name = self.entries[i].name.lower()
        score += sum(0.5 for term in set(query) if len(term) > 2 and term in name)
        return score

    def search(
        self,
        query: str,
        *,
        server: str | None = None,
        kind: str = "any",
        limit: int = 8,
        query_vector: list[float] | None = None,
    ) -> list[tuple[ToolEntry, float]]:
        """Best matches first. ``kind``: 'any', 'read' or 'write' (write includes destructive)."""
        if kind not in ("any", "read", "write"):
            raise ValueError("kind must be 'any', 'read' or 'write'.")
        q = tokens(query)
        candidates = [
            i for i, e in enumerate(self.entries)
            if (not server or e.server == server)
            and (kind == "any" or (e.kind == "read") == (kind == "read"))
        ]
        keyword = {i: self._keyword(i, q) for i in candidates}
        top = max(keyword.values(), default=0.0) or 1.0
        scored = []
        for i in candidates:
            score = keyword[i] / top
            vec = self.entries[i].vector
            if query_vector is not None and vec is not None:
                score = 0.5 * score + 0.5 * max(0.0, cosine(query_vector, vec))
            if score > 0:
                scored.append((self.entries[i], round(score, 3)))
        scored.sort(key=lambda pair: (-pair[1], pair[0].id))
        return scored[:limit]
