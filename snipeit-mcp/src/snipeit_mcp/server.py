"""FastMCP server exposing Snipe-IT (REST API) tools.

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools cover assets, users and the reference/inventory catalogs; the raw
``snipeit_get`` escape hatch reaches anything else. Write tools (check out / check in / update /
create / audit an asset) are **opt-in**: they refuse unless ``SNIPEIT_ALLOW_WRITE=true`` and need a
token whose user has the matching permissions. With the flag off the server is effectively read-only.
"""

from __future__ import annotations

import sys
from typing import Annotated, Any
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from .client import SnipeClient
from .config import ConfigError, Settings

mcp = FastMCP("snipeit-mcp")

# Lazily-built shared client so the module imports without credentials (e.g. for tests).
_client: SnipeClient | None = None


def _get_client() -> SnipeClient:
    global _client
    if _client is None:
        _client = SnipeClient(Settings.from_env())
    return _client


def _require_write() -> None:
    """Gate write tools behind the opt-in SNIPEIT_ALLOW_WRITE flag."""
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set SNIPEIT_ALLOW_WRITE=true (and use a token whose user has "
            "the matching permissions) to enable checkout/checkin/update/create/audit."
        )


# ---- curated field projections (dotted paths reach nested {id,name} objects) --
_ASSET_FIELDS = (
    "id", "asset_tag", "name", "serial", "model.name", "status_label.name", "category.name",
    "manufacturer.name", "assigned_to.name", "location.name", "company.name", "updated_at",
)
_ASSET_WRITE_FIELDS = ("id", "asset_tag", "name", "status_label.name", "assigned_to.name", "location.name")
_USER_FIELDS = ("id", "name", "username", "email", "employee_num", "department.name", "location.name", "assets_count")

# kind -> (path, projected fields) for the generic catalog lister
_OBJECT_KINDS = {
    "models": ("models", ("id", "name", "model_number", "manufacturer.name", "category.name")),
    "categories": ("categories", ("id", "name", "category_type")),
    "manufacturers": ("manufacturers", ("id", "name", "url")),
    "statuslabels": ("statuslabels", ("id", "name", "type")),
    "locations": ("locations", ("id", "name", "city", "country")),
    "companies": ("companies", ("id", "name")),
    "departments": ("departments", ("id", "name", "company.name", "location.name")),
    "suppliers": ("suppliers", ("id", "name", "city", "country")),
    "licenses": ("licenses", ("id", "name", "seats", "free_seats_count", "manufacturer.name", "expiration_date")),
    "accessories": ("accessories", ("id", "name", "qty", "remaining_qty", "category.name")),
    "consumables": ("consumables", ("id", "name", "qty", "remaining", "category.name")),
    "components": ("components", ("id", "name", "qty", "category.name")),
    "maintenances": ("maintenances", ("id", "asset.name", "title", "asset_maintenance_type", "start_date", "completion_date")),
}


# ---- helpers ------------------------------------------------------------

def _clamp(limit: int, default: int = 50, maximum: int = 500) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field in fields:
        cur: Any = obj
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        out[field] = cur
    return out


def _rows(data: Any) -> tuple[list[Any], int | None]:
    if isinstance(data, dict):
        rows = data.get("rows")
        if isinstance(rows, list):
            return rows, data.get("total")
        return [data], None
    if isinstance(data, list):
        return data, len(data)
    return [], None


async def _get_list(
    path: str,
    fields: tuple[str, ...],
    *,
    params: dict[str, Any] | None = None,
    limit: int = 50,
    offset: int = 0,
    full: bool = False,
) -> dict[str, Any]:
    """GET a list endpoint, project to ``fields`` (unless ``full``), and cap to ``limit``."""
    q: dict[str, Any] = {"limit": _clamp(limit), "offset": offset}
    if params:
        q.update({k: v for k, v in params.items() if v is not None})
    data = await _get_client().get(path, params=q)
    rows, total = _rows(data)
    if not full:
        rows = [_pick(r, fields) if isinstance(r, dict) else r for r in rows]
    return {"total": total, "count": len(rows), "rows": rows}


def _write_result(data: Any) -> dict[str, Any]:
    """Shape a Snipe-IT write envelope ({status, messages, payload}) into a compact result."""
    payload = data.get("payload") if isinstance(data, dict) else None
    out: dict[str, Any] = {
        "status": data.get("status") if isinstance(data, dict) else None,
        "messages": data.get("messages") if isinstance(data, dict) else None,
    }
    if isinstance(payload, dict):
        out["asset"] = _pick(payload, _ASSET_WRITE_FIELDS)
    return out


# ---- tools: read --------------------------------------------------------

@mcp.tool()
async def list_assets(
    search: Annotated[str | None, Field(description="Fuzzy search across asset fields (tag, name, serial, …).")] = None,
    status_id: Annotated[int | None, Field(description="Filter by status label id.")] = None,
    model_id: Annotated[int | None, Field(description="Filter by model id.")] = None,
    category_id: Annotated[int | None, Field(description="Filter by category id.")] = None,
    location_id: Annotated[int | None, Field(description="Filter by location id.")] = None,
    limit: Annotated[int, Field(description="Max assets to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List/search hardware assets (GET /hardware)."""
    params = {"search": search, "status_id": status_id, "model_id": model_id,
              "category_id": category_id, "location_id": location_id, "sort": "updated_at", "order": "desc"}
    return await _get_list("hardware", _ASSET_FIELDS, params=params, limit=limit, offset=offset, full=full)


@mcp.tool()
async def get_asset(
    asset_id: Annotated[int | None, Field(description="The asset's numeric id.")] = None,
    asset_tag: Annotated[str | None, Field(description="The asset tag (alternative to asset_id).")] = None,
    serial: Annotated[str | None, Field(description="The serial number (alternative to asset_id).")] = None,
    full: Annotated[bool, Field(description="Return the full object instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """Get one asset by id, asset tag, or serial (GET /hardware/{id} | /bytag | /byserial)."""
    if asset_id is not None:
        path = f"hardware/{asset_id}"
    elif asset_tag:
        path = f"hardware/bytag/{quote(str(asset_tag), safe='')}"
    elif serial:
        path = f"hardware/byserial/{quote(str(serial), safe='')}"
    else:
        raise ValueError("Provide one of asset_id, asset_tag, or serial.")
    data = await _get_client().get(path)
    rows, _ = _rows(data)  # byserial can return multiple
    if len(rows) == 1:
        return rows[0] if full else _pick(rows[0], _ASSET_FIELDS)
    return {"count": len(rows), "rows": rows if full else [_pick(r, _ASSET_FIELDS) for r in rows]}


@mcp.tool()
async def list_users(
    search: Annotated[str | None, Field(description="Fuzzy search (name/username/email).")] = None,
    limit: Annotated[int, Field(description="Max users to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List/search users (GET /users)."""
    return await _get_list("users", _USER_FIELDS, params={"search": search}, limit=limit, offset=offset, full=full)


@mcp.tool()
async def get_user_assets(
    user_id: Annotated[int, Field(description="The user's id.")],
    limit: Annotated[int, Field(description="Max assets to return.", ge=1, le=500)] = 100,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List the assets currently checked out to a user (GET /users/{id}/assets)."""
    return await _get_list(f"users/{user_id}/assets", _ASSET_FIELDS, limit=limit, full=full)


@mcp.tool()
async def list_objects(
    kind: Annotated[str, Field(description="Catalog to list: models, categories, manufacturers, statuslabels, locations, companies, departments, suppliers, licenses, accessories, consumables, components, maintenances.")],
    search: Annotated[str | None, Field(description="Fuzzy search where supported.")] = None,
    limit: Annotated[int, Field(description="Max rows to return.", ge=1, le=500)] = 50,
    offset: Annotated[int, Field(description="Pagination offset.", ge=0)] = 0,
    full: Annotated[bool, Field(description="Return full objects instead of a trimmed summary.")] = False,
) -> dict[str, Any]:
    """List a reference/inventory catalog — needed to resolve ids (status/model/location/…) for writes."""
    key = (kind or "").strip().lower()
    if key not in _OBJECT_KINDS:
        raise ValueError(f"kind must be one of {tuple(_OBJECT_KINDS)}; got {kind!r}.")
    path, fields = _OBJECT_KINDS[key]
    return await _get_list(path, fields, params={"search": search}, limit=limit, offset=offset, full=full)


@mcp.tool()
async def snipeit_get(
    path: Annotated[str, Field(description="API path relative to /api/v1, e.g. 'hardware/12', 'licenses/3/seats', 'version'.")],
    params: Annotated[dict[str, Any] | None, Field(description="Query params, e.g. {\"limit\": 10, \"search\": \"laptop\"}.")] = None,
) -> Any:
    """Escape hatch: raw read-only GET against any Snipe-IT ``/api/v1/...`` resource."""
    data = await _get_client().get_raw(path, params=params)
    return data if isinstance(data, (dict, list)) else {"data": data}


# ---- tools: writes (opt-in, gated by SNIPEIT_ALLOW_WRITE) ----------------

@mcp.tool()
async def checkout_asset(
    asset_id: Annotated[int, Field(description="The asset id to check out.")],
    to_type: Annotated[str, Field(description="Check out to a 'user', 'location' or 'asset'.")],
    to_id: Annotated[int, Field(description="The id of the user/location/asset to check out to.")],
    status_id: Annotated[int | None, Field(description="Status label id to set on checkout (optional).")] = None,
    expected_checkin: Annotated[str | None, Field(description="Expected check-in date 'YYYY-MM-DD' (optional).")] = None,
    note: Annotated[str | None, Field(description="Checkout note (optional).")] = None,
) -> dict[str, Any]:
    """Check out an asset to a user/location/asset (WRITE — requires SNIPEIT_ALLOW_WRITE).

    POSTs /hardware/{id}/checkout with checkout_to_type + the matching assigned_* field.
    """
    _require_write()
    field = {"user": "assigned_user", "location": "assigned_location", "asset": "assigned_asset"}.get(to_type)
    if field is None:
        raise ValueError("to_type must be one of: user, location, asset.")
    payload: dict[str, Any] = {"checkout_to_type": to_type, field: to_id}
    if status_id is not None:
        payload["status_id"] = status_id
    if expected_checkin:
        payload["expected_checkin"] = expected_checkin
    if note:
        payload["note"] = note
    return _write_result(await _get_client().post(f"hardware/{asset_id}/checkout", json=payload))


@mcp.tool()
async def checkin_asset(
    asset_id: Annotated[int, Field(description="The asset id to check in.")],
    status_id: Annotated[int | None, Field(description="Status label id to set on check-in (optional).")] = None,
    location_id: Annotated[int | None, Field(description="Location id to set on check-in (optional).")] = None,
    note: Annotated[str | None, Field(description="Check-in note (optional).")] = None,
) -> dict[str, Any]:
    """Check in an asset (WRITE — requires SNIPEIT_ALLOW_WRITE). POSTs /hardware/{id}/checkin."""
    _require_write()
    payload: dict[str, Any] = {}
    if status_id is not None:
        payload["status_id"] = status_id
    if location_id is not None:
        payload["location_id"] = location_id
    if note:
        payload["note"] = note
    return _write_result(await _get_client().post(f"hardware/{asset_id}/checkin", json=payload))


@mcp.tool()
async def update_asset(
    asset_id: Annotated[int, Field(description="The asset id to update.")],
    name: Annotated[str | None, Field(description="New asset name.")] = None,
    status_id: Annotated[int | None, Field(description="New status label id.")] = None,
    model_id: Annotated[int | None, Field(description="New model id.")] = None,
    asset_tag: Annotated[str | None, Field(description="New asset tag.")] = None,
    serial: Annotated[str | None, Field(description="New serial number.")] = None,
    notes: Annotated[str | None, Field(description="New notes.")] = None,
    location_id: Annotated[int | None, Field(description="New (default/RTD) location id.")] = None,
    company_id: Annotated[int | None, Field(description="New company id.")] = None,
) -> dict[str, Any]:
    """Update an asset's fields (WRITE — requires SNIPEIT_ALLOW_WRITE). PATCHes /hardware/{id}."""
    _require_write()
    payload: dict[str, Any] = {}
    for key, value in (
        ("name", name), ("status_id", status_id), ("model_id", model_id), ("asset_tag", asset_tag),
        ("serial", serial), ("notes", notes), ("rtd_location_id", location_id), ("company_id", company_id),
    ):
        if value is not None:
            payload[key] = value
    if not payload:
        raise ValueError("Nothing to update: provide at least one field.")
    return _write_result(await _get_client().patch(f"hardware/{asset_id}", json=payload))


@mcp.tool()
async def create_asset(
    asset_tag: Annotated[str, Field(description="Unique asset tag (required).")],
    model_id: Annotated[int, Field(description="Model id (required).")],
    status_id: Annotated[int, Field(description="Status label id (required).")],
    name: Annotated[str | None, Field(description="Asset name (optional).")] = None,
    serial: Annotated[str | None, Field(description="Serial number (optional).")] = None,
    notes: Annotated[str | None, Field(description="Notes (optional).")] = None,
    company_id: Annotated[int | None, Field(description="Company id (optional).")] = None,
) -> dict[str, Any]:
    """Create an asset (WRITE — requires SNIPEIT_ALLOW_WRITE). POSTs /hardware.

    Required: asset_tag, model_id, status_id.
    """
    _require_write()
    payload: dict[str, Any] = {"asset_tag": asset_tag, "model_id": model_id, "status_id": status_id}
    for key, value in (("name", name), ("serial", serial), ("notes", notes), ("company_id", company_id)):
        if value is not None:
            payload[key] = value
    return _write_result(await _get_client().post("hardware", json=payload))


@mcp.tool()
async def audit_asset(
    asset_tag: Annotated[str, Field(description="The asset tag to audit (required).")],
    location_id: Annotated[int | None, Field(description="Location id to record/update during the audit (optional).")] = None,
    note: Annotated[str | None, Field(description="Audit note (optional).")] = None,
    next_audit_date: Annotated[str | None, Field(description="Next audit date 'YYYY-MM-DD' (optional).")] = None,
) -> dict[str, Any]:
    """Record an audit of an asset (WRITE — requires SNIPEIT_ALLOW_WRITE). POSTs /hardware/audit."""
    _require_write()
    payload: dict[str, Any] = {"asset_tag": asset_tag}
    if location_id is not None:
        payload["location_id"] = location_id
    if note:
        payload["note"] = note
    if next_audit_date:
        payload["next_audit_date"] = next_audit_date
    data = await _get_client().post("hardware/audit", json=payload)
    return {
        "status": data.get("status") if isinstance(data, dict) else None,
        "messages": data.get("messages") if isinstance(data, dict) else None,
        "payload": data.get("payload") if isinstance(data, dict) else None,
    }


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"snipeit-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Share the configured client with the tools.
    global _client
    _client = SnipeClient(settings)

    # FastMCP.run() ignores host/port — they must be set on the instance settings.
    mcp.settings.host = settings.host
    mcp.settings.port = settings.port
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    )
    mcp.run(transport=settings.transport)


if __name__ == "__main__":
    main()
