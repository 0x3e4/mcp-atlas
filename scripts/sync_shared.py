"""Copy the shared guard into every server (and the template); ``--check`` only verifies (used by CI).

    python scripts/sync_shared.py          # write src/<package>/_atlas_guard.py and tests/test_atlas_guard.py
    python scripts/sync_shared.py --check  # exit 1 if a copy is missing or differs
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = {
    "guard": ROOT / "_shared" / "atlas_guard.py",
    "test": ROOT / "_shared" / "server_test.py",
}


def targets() -> list[tuple[pathlib.Path, pathlib.Path]]:
    out = []
    for server in sorted([ROOT / "_template", *ROOT.glob("*-mcp")]):
        pkg = next((p for p in sorted((server / "src").iterdir()) if (p / "server.py").exists()), None)
        if pkg is None:
            continue
        out.append((SOURCES["guard"], pkg / "_atlas_guard.py"))
        out.append((SOURCES["test"], server / "tests" / "test_atlas_guard.py"))
    return out


def norm(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def main() -> int:
    check = "--check" in sys.argv
    stale = []
    for source, target in targets():
        want = norm(source.read_bytes())
        if target.exists() and norm(target.read_bytes()) == want:
            continue
        stale.append(target.relative_to(ROOT))
        if not check:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(want)
    if check and stale:
        print("Out of date (run python scripts/sync_shared.py):\n  " + "\n  ".join(map(str, stale)))
        return 1
    print(("checked" if check else "synced"), len(targets()), "files", f"({len(stale)} updated)" if not check else "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
