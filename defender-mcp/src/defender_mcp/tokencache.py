"""On-disk refresh-token store for delegated (signed-in user) mode.

Holds one user's refresh token plus who it belongs to, as JSON with owner-only permissions (0600 in a
0700 directory). Whoever can read this file can act as that user against the consented Graph scopes,
so keep it in a volume only the server container mounts. Access tokens are never written; the server
keeps them in memory.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any


def load(path: str, *, tenant_id: str, client_id: str) -> dict[str, Any] | None:
    """Return the stored sign-in, or None when there is none for this tenant + app registration."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("refresh_token"):
        return None
    # A cache written for another app registration or tenant must not be reused.
    if data.get("tenant_id") != tenant_id or data.get("client_id") != client_id:
        return None
    return data


def save(path: str, entry: dict[str, Any]) -> None:
    """Write ``entry`` atomically with mode 0600 (raises OSError if the path isn't writable)."""
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({**entry, "saved_at": int(time.time())}, fh)
    os.replace(tmp, target)


def clear(path: str) -> bool:
    """Delete the stored sign-in; True if there was one."""
    try:
        Path(path).unlink()
        return True
    except FileNotFoundError:
        return False


def jwt_claims(token: str | None) -> dict[str, Any]:
    """Decode a JWT payload WITHOUT verifying it — only for showing who is signed in / which scopes."""
    if not token or token.count(".") < 2:
        return {}
    payload = token.split(".")[1]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return claims if isinstance(claims, dict) else {}
