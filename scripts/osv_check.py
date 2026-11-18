"""Check every locked package of every server against the OSV vulnerability database (no dependencies).

    python scripts/osv_check.py      # exit 1 if any locked version has a known vulnerability
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = re.compile(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"')


def main() -> int:
    used: dict[tuple[str, str], list[str]] = {}
    for lock in sorted(ROOT.glob("*-mcp/poetry.lock")):
        for name, version in PKG.findall(lock.read_text(encoding="utf-8").replace("\r\n", "\n")):
            used.setdefault((name, version), []).append(lock.parent.name)
    pkgs = sorted(used)
    body = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pkgs]}
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        results = json.load(resp)["results"]
    found = {f"{n}=={v}": [x["id"] for x in r["vulns"]] for (n, v), r in zip(pkgs, results) if r.get("vulns")}
    print(f"{len(pkgs)} locked package versions checked against OSV")
    for pkg, ids in found.items():
        name, version = pkg.split("==")
        print(f"  VULNERABLE {pkg}: {', '.join(ids)}  (in {', '.join(used[(name, version)])})")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
