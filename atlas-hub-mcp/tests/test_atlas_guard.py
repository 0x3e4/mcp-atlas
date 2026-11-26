"""Guard checks every atlas server runs. Generated from _shared/server_test.py by scripts/sync_shared.py —
edit the source there, not the copies in <server>/tests/test_atlas_guard.py."""

from __future__ import annotations

import asyncio
import importlib
import pathlib

SRC = pathlib.Path(__file__).parents[1] / "src"
PKG = next(p.name for p in sorted(SRC.iterdir()) if (p / "server.py").exists())
server = importlib.import_module(f"{PKG}.server")
guard = importlib.import_module(f"{PKG}._atlas_guard")


def _tools():
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_every_tool_is_guarded_and_annotated():
    tools = _tools()
    assert tools
    for name, t in tools.items():
        a = t.annotations
        assert a is not None and a.open_world_hint is True, name
        if "confirm" in (t.input_schema.get("properties") or {}):
            assert a.read_only_hint is False, f"{name} takes a confirm code but is annotated read-only"
        if a.read_only_hint:
            assert a.destructive_hint is False, name
    for tool in server.mcp._tool_manager.list_tools():  # noqa: SLF001
        assert getattr(tool.fn, "__atlas_guarded__", False), f"{tool.name} is not wrapped by the guard"


def test_instructions_warn_about_untrusted_content():
    assert guard.UNTRUSTED_NOTICE in (server.mcp.instructions or "")


def test_read_tool_descriptions_warn_when_results_hold_foreign_text():
    if not server.GUARD["untrusted_keys"]:
        return  # this server returns no text other people write
    for name, t in _tools().items():
        if t.annotations.read_only_hint:
            assert (t.description or "").count(guard.UNTRUSTED_TOOL_NOTE) == 1, name


def test_guard_copy_matches_the_shared_source():
    shared = pathlib.Path(__file__).parents[2] / "_shared" / "atlas_guard.py"
    if shared.exists():  # inside the repo; the Docker build context has only the server folder
        assert (SRC / PKG / "_atlas_guard.py").read_bytes().replace(b"\r\n", b"\n") == shared.read_bytes().replace(b"\r\n", b"\n"), \
            "run: python scripts/sync_shared.py"


def test_http_transport_goes_through_the_guard():
    src = (SRC / PKG / "server.py").read_text(encoding="utf-8")
    assert "enable_dns_rebinding_protection=False" not in src
    assert "run_http(mcp" in src
