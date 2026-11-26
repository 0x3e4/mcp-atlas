"""Keep the Version column of the server table in README.md equal to each server's pyproject.toml.

    python scripts/sync_readme_versions.py          # update README.md
    python scripts/sync_readme_versions.py --check  # exit 1 if a version in the table is out of date (CI)
"""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROW = re.compile(r"^\| \[(?P<server>[\w-]+-mcp)\]\((?P=server)/\) \|(?: \[[^\]]*\]\([^)]*\) \|)?(?P<rest>.*)$")


def versions() -> dict[str, str]:
    out = {}
    for pyproject in sorted(ROOT.glob("*-mcp/pyproject.toml")):
        out[pyproject.parent.name] = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    return out


def render(text: str, known: dict[str, str]) -> tuple[str, list[str]]:
    lines, missing = [], set(known)
    for line in text.split("\n"):
        if line.startswith("| Server | What it does |"):
            line = "| Server | Version | What it does |"
        elif re.fullmatch(r"\|-+\|-+\|", line.strip()):
            line = "|--------|---------|--------------|"
        elif m := ROW.match(line):
            server = m.group("server")
            if server in known:
                missing.discard(server)
                line = f"| [{server}]({server}/) | [{known[server]}]({server}/CHANGELOG.md) |{m.group('rest')}"
        lines.append(line)
    return "\n".join(lines), sorted(missing)


def main() -> int:
    readme = ROOT / "README.md"
    raw = readme.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")
    new, missing = render(text, versions())
    if missing:
        print("No row in the README server table for: " + ", ".join(missing))
        return 1
    if new == text:
        print("README server table is up to date")
        return 0
    if "--check" in sys.argv:
        print("README server table is out of date: run python scripts/sync_readme_versions.py")
        return 1
    readme.write_bytes((new.replace("\n", "\r\n") if crlf else new).encode("utf-8"))
    print("README server table updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
