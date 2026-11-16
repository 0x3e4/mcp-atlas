"""MCP server exposing AudioCodes Mediant SBC tools (device REST API, ``/api/v1``).

Transport defaults to ``stdio`` (for Claude Code); set ``MCP_TRANSPORT=streamable-http`` for an
always-on HTTP server. Read tools cover device status, active and historic alarms, performance
monitoring (KPIs), the configuration (CLI script or INI, secrets masked), CLI ``show`` commands, files,
TLS contexts with certificate expiry, the license and SIP test calls.

The device API has no per-table configuration endpoints: configuration changes go through an
incremental CLI script or INI file (applied live, no reset). Write tools are **opt-in** behind
``AUDIOCODES_ALLOW_WRITE``; the disruptive ones need a second switch (all off by default, read per
instance env file):

- ``AUDIOCODES_ALLOW_RESET``: reset, replace the whole configuration (resets), firmware (resets) —
  always confirmed
- ``AUDIOCODES_ALLOW_TLS``: TLS certificates, trusted roots, private key / self-signed generation
- ``AUDIOCODES_ALLOW_LICENSE``: install a license key — always confirmed
"""

from __future__ import annotations

import asyncio
import base64
import difflib
import hashlib
import hmac
import json
import pathlib
import re
import secrets
import sys
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field

from . import __version__
from .client import SbcClient, SbcError
from .config import ConfigError, Settings

mcp = MCPServer(
    "audiocodes-sbc-mcp",
    instructions=(
        "Write tools need the user's confirmation: the first call changes nothing and returns a preview "
        "with a confirm_code. Show the user a short overview of what will change, end with 'Confirm it?', "
        "and only after they say yes repeat the call with confirm=<code>. Resets, configuration replaces, "
        "firmware, TLS key/certificate generation and license installs always ask this way. Configuration "
        "changes are CLI script snippets (apply_cli_script); read the current configuration with "
        "get_configuration first and change only what is needed. Changes are live but not persistent "
        "until save_configuration (status shows saveNeeded)."
    ),
    version=__version__,
)

_client: SbcClient | None = None


def _get_client() -> SbcClient:
    global _client
    if _client is None:
        _client = SbcClient(Settings.from_env())
    return _client


def _require_write() -> None:
    if not _get_client().settings.allow_write:
        raise ValueError(
            "Write tools are disabled. Set AUDIOCODES_ALLOW_WRITE=true (and use a device user with the "
            "needed privilege level) to change the configuration, save it or place test calls."
        )


def _require_flag(attr: str, env: str, what: str) -> None:
    """A sensitive write: AUDIOCODES_ALLOW_WRITE plus its own switch (per instance env file)."""
    _require_write()
    if not getattr(_get_client().settings, attr):
        raise ValueError(
            f"{what} is disabled. Set {env}=true (in addition to AUDIOCODES_ALLOW_WRITE=true) in this "
            "instance's env file to allow it."
        )


_CONFIRM_KEY = secrets.token_bytes(16)
_CONFIRM_DESC = (
    "Confirm code from this tool's preview. Leave empty on the first call; pass it only after the user "
    "has seen the overview and confirmed."
)


def _confirm(
    tool: str, change: dict[str, Any], summary: str, code: str | None, *, always: bool = False
) -> dict[str, Any] | None:
    """Return a preview the agent must confirm with the user, or None when the write may run.

    Writes run straight away when AUDIOCODES_CONFIRM_WRITE=false (unless ``always``), or when ``code``
    matches this exact tool + change (so what runs is what the user saw).
    """
    if not always and not _get_client().settings.confirm_write:
        return None
    raw = json.dumps([tool, change], sort_keys=True, default=str).encode()
    expected = hmac.new(_CONFIRM_KEY, raw, hashlib.sha256).hexdigest()[:12]
    if code and hmac.compare_digest(code.strip(), expected):
        return None
    out: dict[str, Any] = {
        "status": "confirmation_required",
        "changed": False,
        "summary": summary,
        "change": change,
        "confirm_code": expected,
        "next": (
            "Show the user a short overview of this change and end with 'Confirm it?'. Only after they "
            f"confirm, call {tool} again with the same arguments and confirm='{expected}'."
        ),
    }
    if code:
        out["note"] = "The confirm code did not match these arguments (changed, expired or restarted) — confirm again."
    return out


# ---- helpers: secrets, configuration text, certificates ----------------------------------

_CLI_SECRET = re.compile(
    r"(?im)^(\s*(?:\S+-)?(?:password|passwd|secret|shared-secret|pre-shared-key|private-key|community[\w-]*|"
    r"auth-password|priv-password|md5-key|key)\b\s+)(\"[^\"]*\"|\S+)"
)
_INI_SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|sharedkey|presharedkey|privatekey|community)")


def _mask_cli(text: str) -> str:
    return _CLI_SECRET.sub(lambda m: f'{m.group(1)}"<masked>"', text)


def _mask_ini(text: str) -> str:
    """Mask secret parameters (``XyzPassword = …``) and secret columns of INI tables."""
    out: list[str] = []
    secret_cols: dict[str, list[int]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        fmt = re.match(r"(?i)FORMAT\s+(\w+?)_Index\s*=\s*(.*?);?\s*$", stripped)
        if fmt:
            cols = [c.strip() for c in fmt.group(2).split(",")]
            secret_cols[fmt.group(1)] = [i for i, c in enumerate(cols) if _INI_SECRET_KEY.search(c)]
            out.append(line)
            continue
        row = re.match(r"(\w+)\s+(\d+)\s*=\s*(.*?)(;?)\s*$", stripped)
        if row and secret_cols.get(row.group(1)):
            values = _split_row(row.group(3))
            for i in secret_cols[row.group(1)]:
                if i < len(values) and values[i] not in ("", '""', "''"):
                    values[i] = '"<masked>"'
            out.append(f"{row.group(1)} {row.group(2)} = " + ", ".join(values) + row.group(4))
            continue
        param = re.match(r"(\s*)(\w+)(\s*=\s*)(.*)$", line)
        if param and _INI_SECRET_KEY.search(param.group(2)) and param.group(4).strip() not in ("", "''", '""'):
            out.append(f"{param.group(1)}{param.group(2)}{param.group(3)}'<masked>'")
            continue
        out.append(line)
    return "\n".join(out)


def _split_row(text: str) -> list[str]:
    """Split an INI table row on commas outside quotes, keeping each value as written (quotes included)."""
    values, current, quoted = [], [], False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == "," and not quoted:
            values.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    values.append("".join(current).strip())
    return values


def _cli_blocks(text: str, grep: str) -> str:
    """Blocks of a CLI script whose header line contains ``grep``: the line plus everything indented below."""
    lines = text.splitlines()
    wanted = grep.lower()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if wanted in line.lower():
            indent = len(line) - len(line.lstrip())
            block = [line]
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
                block.append(lines[j])
                j += 1
            if j < len(lines) and lines[j].strip() == "exit" and len(lines[j]) - len(lines[j].lstrip()) == indent:
                block.append(lines[j])  # the block's own closing exit
                j += 1
            out += block + [""]
            i = j
        else:
            i += 1
    return "\n".join(out).strip("\n")


_INI_HEAD = re.compile(r"\s*\[\s*([^\\\]\s][^\]]*?)\s*\]")


def _ini_blocks(text: str, grep: str) -> str:
    """INI table sections whose name contains ``grep`` ('[ X ]' … '[ \\X ]'); if no section name
    matches, the single lines that contain it."""
    lines = text.splitlines()
    wanted = grep.lower()
    out: list[str] = []
    i = 0
    while i < len(lines):
        head = _INI_HEAD.match(lines[i])
        if head and wanted in head.group(1).lower():
            end = re.compile(rf"\s*\[\s*{re.escape(chr(92) + head.group(1))}\s*\]")
            j = i
            while j < len(lines):
                out.append(lines[j])
                if end.match(lines[j]):
                    break
                j += 1
            out.append("")
            i = j + 1
        else:
            i += 1
    if not out:
        out = [line for line in lines if wanted in line.lower()]
    return "\n".join(out).strip()


def _der(data: bytes, i: int) -> tuple[int, int, int]:
    """(tag, value start, value end) of the DER element at ``i``."""
    tag, length = data[i], data[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, i, i + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    while start < end:
        tag, s, e = _der(data, start)
        out.append((tag, s, e))
        start = e
    return out


_NAME_OIDS = {bytes.fromhex("550403"): "CN", bytes.fromhex("55040a"): "O", bytes.fromhex("55040b"): "OU",
              bytes.fromhex("550406"): "C"}


def _x500(data: bytes, start: int, end: int) -> str:
    parts = []
    for _t, ss, se in _children(data, start, end):
        for _t2, as_, ae in _children(data, ss, se):
            kids = _children(data, as_, ae)
            if len(kids) >= 2 and data[kids[0][1]:kids[0][2]] in _NAME_OIDS:
                parts.append(f"{_NAME_OIDS[data[kids[0][1]:kids[0][2]]]}={data[kids[1][1]:kids[1][2]].decode('utf-8', 'replace')}")
    return ", ".join(parts)


def _der_time(tag: int, raw: bytes) -> datetime:
    s = raw.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        s = ("19" if int(s[:2]) >= 50 else "20") + s
    return datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]), int(s[12:14]), tzinfo=timezone.utc)


_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)


def _cert_infos(pem: str, now: datetime | None = None) -> list[dict[str, Any]]:
    """Subject, issuer, validity and days left of every certificate in a PEM text."""
    now = now or datetime.now(timezone.utc)
    out = []
    for body in _PEM_CERT.findall(pem):
        try:
            der = base64.b64decode("".join(body.split()))
            _t, cs, ce = _der(der, 0)
            _t, ts, te = _der(der, cs)
            kids = _children(der, ts, te)
            if kids[0][0] == 0xA0:
                kids = kids[1:]
            serial, _alg, issuer, validity, subject = kids[:5]
            (nbt, nbs, nbe), (nat, nas, nae) = _children(der, validity[1], validity[2])[:2]
            not_after = _der_time(nat, der[nas:nae])
            out.append({"subject": _x500(der, subject[1], subject[2]), "issuer": _x500(der, issuer[1], issuer[2]),
                        "serial": der[serial[1]:serial[2]].hex(),
                        "not_before": _der_time(nbt, der[nbs:nbe]).isoformat(), "not_after": not_after.isoformat(),
                        "days_left": (not_after - now).days})
        except (ValueError, IndexError, UnicodeDecodeError):
            out.append({"error": "could not parse this certificate"})
    return out


def _cut(text: str, max_chars: int) -> dict[str, Any]:
    out: dict[str, Any] = {"text": text[:max_chars]}
    if len(text) > max_chars:
        out["truncated"] = f"{len(text) - max_chars} more characters (of {len(text)}); use grep to narrow it."
    return out


# ---- tools: status, alarms, KPIs --------------------------------------------------------

@mcp.tool()
async def device_status() -> dict[str, Any]:
    """Device status (GET /api/v1/status): product, firmware version, IP, serial, uptime, operational and HA
    state, and whether the configuration needs saving (saveNeeded) or a reset (resetNeeded)."""
    return await _get_client().get("status")


@mcp.tool()
async def list_alarms(
    kind: Annotated[Literal["active", "history"], Field(description="active = current alarms; history = since the last reboot.")] = "active",
    limit: Annotated[int, Field(description="Max alarms (the device pages them).", ge=1, le=200)] = 50,
    after: Annotated[str | None, Field(description="Paging cursor from a previous call's cursor.after.")] = None,
    detailed: Annotated[bool, Field(description="Fetch each alarm's severity, source and date (one request per alarm).")] = True,
) -> dict[str, Any]:
    """Active or historic alarms (GET /api/v1/alarms/active|history), with severity, source and date."""
    client = _get_client()
    params: dict[str, Any] = {"limit": limit, **({"after": after} if after else {})}
    data = await client.get(f"alarms/{kind}", params=params)
    alarms = [a for a in data.get("alarms") or [] if isinstance(a, dict)]
    if detailed and alarms:
        async def one(a: dict[str, Any]) -> dict[str, Any]:
            try:
                return await client.get(f"alarms/{kind}/{a.get('id')}")
            except SbcError as exc:
                return {**a, "error": str(exc)}
        alarms = list(await asyncio.gather(*(one(a) for a in alarms)))
    rows = [{k: v for k, v in a.items() if k != "url"} for a in alarms]
    out: dict[str, Any] = {"kind": kind, "count": len(rows), "alarms": rows}
    cursor = data.get("cursor")
    if isinstance(cursor, dict) and str(cursor.get("after", "-1")) != "-1":
        out["cursor"] = {"after": cursor.get("after")}
    if kind == "active":
        try:
            out["last_change"] = (await client.get("alarms/active/lastChange")).get("lastChange")
        except SbcError:
            pass
    return out


@mcp.tool()
async def get_alarm(
    alarm_id: Annotated[int, Field(description="Alarm id from list_alarms.")],
    kind: Annotated[Literal["active", "history"], Field(description="Where the alarm is.")] = "active",
    include_oid: Annotated[bool, Field(description="Add the SNMP trap OID.")] = False,
) -> dict[str, Any]:
    """One alarm with severity, source, date and description."""
    return await _get_client().get(f"alarms/{kind}/{alarm_id}", params={"oid": 1} if include_oid else None)


@mcp.tool()
async def kpi(
    path: Annotated[str, Field(description="Path under /api/v1/kpi. Browse from '' → 'current' → 'current/sbc' → 'current/sbc/callStats' → 'current/sbc/callStats/ipGroup' → 'current/sbc/callStats/ipGroup/<id>'; 'history/…' for past intervals, 'current/sbc/callStats/global' for device-wide counters.")] = "",
    interval: Annotated[str | None, Field(description="History only: interval index, 'last' or 'all' (see kpi_intervals).")] = None,
    kpi_name: Annotated[str | None, Field(description="Only this performance monitor (PM) name.")] = None,
    detailed: Annotated[bool, Field(description="Include values when listing entities / PMs.")] = True,
    limit: Annotated[int, Field(description="Max items per page.", ge=1, le=500)] = 100,
    after: Annotated[str | None, Field(description="Paging cursor from a previous call.")] = None,
) -> dict[str, Any]:
    """Performance monitoring (GET /api/v1/kpi/…): browse applications (sbc, media, gateway), groups (e.g.
    callStats), entities (global, ipGroup/<id>, …) and read PM values — active calls, call attempts,
    failures, per IP Group, now or in past intervals. The PM names are in AudioCodes' Performance
    Monitoring Reference Guide; browsing with detailed=true lists them."""
    params: dict[str, Any] = {"limit": limit, "detailed": "true" if detailed else "false"}
    for key, value in (("interval", interval), ("kpi", kpi_name), ("after", after)):
        if value:
            params[key] = value
    clean = path.strip().strip("/")
    if ".." in clean.split("/"):
        raise ValueError("path must stay under /kpi.")
    return await _get_client().get(f"kpi/{clean}" if clean else "kpi", params=params)


@mcp.tool()
async def kpi_intervals(
    limit: Annotated[int, Field(description="Max intervals.", ge=1, le=500)] = 20,
) -> dict[str, Any]:
    """The stored history intervals (GET /api/v1/kpi/interval): index, start and end of each."""
    return await _get_client().get("kpi/interval", params={"limit": limit})


@mcp.tool()
async def sbc_call_stats(
    ip_group: Annotated[str | None, Field(description="An IP Group id for its counters; omit for device-wide (global) SBC call statistics.")] = None,
) -> dict[str, Any]:
    """Current SBC call statistics — active calls, attempts, successes, failures (GET
    /api/v1/kpi/current/sbc/callStats/global or …/ipGroup/<id>). Use kpi to browse other groups."""
    path = f"kpi/current/sbc/callStats/ipGroup/{ip_group}" if ip_group else "kpi/current/sbc/callStats/global"
    return await _get_client().get(path, params={"detailed": "true"})


# ---- tools: configuration (read) ------------------------------------------------------------

@mcp.tool()
async def get_configuration(
    format: Annotated[Literal["cli", "ini"], Field(description="cli = the CLI script (show running-config form); ini = the INI file.")] = "cli",
    grep: Annotated[str | None, Field(description="Only the blocks / sections whose header contains this, e.g. 'proxy-set', 'ip-group', 'sip-interface', 'ip-to-ip-routing' (cli) or 'IPGroup', 'ProxySet' (ini).")] = None,
    max_chars: Annotated[int, Field(description="Cut the text after this many characters.", ge=1000, le=2_000_000)] = 200_000,
) -> dict[str, Any]:
    """The device configuration as CLI script or INI file (GET /api/v1/files/cliScript | ini), passwords and
    keys masked. Needs a Security Administrator user."""
    client = _get_client()
    if format == "cli":
        text = _mask_cli(await client.get_text("files/cliScript"))
        text = _cli_blocks(text, grep) if grep else text
    else:
        text = _mask_ini(await client.get_text("files/ini"))
        text = _ini_blocks(text, grep) if grep else text
    if grep and not text:
        raise ValueError(f"Nothing in the {format} configuration matches '{grep}'.")
    return {"format": format, "grep": grep, **_cut(text, max_chars)}


_SHOW_RE = re.compile(r"^show\s+[\w\-./: \"']+$")


@mcp.tool()
async def run_show_commands(
    commands: Annotated[list[str], Field(description="CLI show commands, e.g. ['show voip calls statistics sbc', 'show voip register db sbc list', 'show voip proxy sets status', 'show system uptime'].", min_length=1, max_length=20)],
    max_chars: Annotated[int, Field(description="Cut the output after this many characters.", ge=1000, le=1_000_000)] = 100_000,
) -> dict[str, Any]:
    """Run read-only CLI show commands and return their output — live call, registration, proxy and
    interface state the REST API has no resource for. Sent as an incremental CLI script (PUT
    /api/v1/files/cliScript/incremental), which needs a Security Administrator user; only 'show …'
    lines are accepted, so nothing can change."""
    lines = [c.strip() for c in commands]
    for c in lines:
        if not _SHOW_RE.match(c) or "\n" in c or "\r" in c:
            raise ValueError(f"Only single-line 'show …' commands are allowed; got {c!r}.")
    result = await _get_client().put_file("files/cliScript/incremental", ("\n".join(lines) + "\n").encode(), filename="show.txt")
    output = _mask_cli(str(result.get("output") or ""))
    return {"commands": lines, "description": result.get("description"), **_cut(output, max_chars)}


@mcp.tool()
async def list_files() -> dict[str, Any]:
    """The device's file resources (GET /api/v1/files): ini, cliScript, software, tls, … (Administrator)."""
    return await _get_client().get("files")


@mcp.tool()
async def license_info(
    show_key: Annotated[bool, Field(description="Return the whole license key instead of its last 6 characters.")] = False,
) -> dict[str, Any]:
    """The installed license (GET /api/v1/license): serial number, key description, MAC (Administrator)."""
    data = await _get_client().get("license")
    key = str(data.get("key") or "")
    if key and not show_key:
        data["key"] = f"…{key[-6:]}"
    return data


@mcp.tool()
async def list_tls_contexts() -> dict[str, Any]:
    """TLS contexts (GET /api/v1/files/tls): id and name of each (Security Administrator)."""
    return await _get_client().get("files/tls")


@mcp.tool()
async def get_tls_context(
    context_id: Annotated[int, Field(description="TLS context id (list_tls_contexts); 0 is the default context.", ge=0)],
    include_pem: Annotated[bool, Field(description="Also return the certificate PEM text.")] = False,
) -> dict[str, Any]:
    """A TLS context: private key size / validity, the device certificate (subject, issuer, expiry, days
    left) and every trusted root with its expiry."""
    client = _get_client()
    base = f"files/tls/{context_id}"
    out: dict[str, Any] = {"context_id": context_id}
    try:
        out["private_key"] = await client.get(f"{base}/privateKey")
    except SbcError as exc:
        out["private_key"] = {"error": str(exc)}
    try:
        pem = await client.get_text(f"{base}/certificate")
        out["certificate"] = (_cert_infos(pem) or [{"note": "no certificate"}])[0]
        if include_pem:
            out["certificate_pem"] = pem
    except SbcError as exc:
        out["certificate"] = {"error": str(exc)}
    try:
        roots = _cert_infos(await client.get_text(f"{base}/trustedRoot"))
        out["trusted_roots"] = roots
        out["trusted_roots_expiring_90d"] = [r for r in roots if isinstance(r.get("days_left"), int) and r["days_left"] < 90]
    except SbcError as exc:
        out["trusted_roots"] = {"error": str(exc)}
    return out


@mcp.tool()
async def get_test_call(
    session_id: Annotated[str | None, Field(description="Session id from start_test_call; omit to see the default test call settings.")] = None,
) -> dict[str, Any]:
    """Status of a SIP test call (connected / disconnected, release cause, MOS, jitter, packet loss) — or
    the default test call settings without a session id."""
    client = _get_client()
    if session_id:
        return await client.get("sipTestCall/getStatus", params={"sessionId": session_id})
    return await client.get("sipTestCall/show")


# ---- tools: writes (AUDIOCODES_ALLOW_WRITE) ---------------------------------------------------

_BLOCKED_CLI = re.compile(r"(?im)^\s*(do\s+)?(reload|write\s+factory|write-and-reload|copy|erase|delete\s+file)\b")


async def _status_flags() -> dict[str, Any]:
    try:
        st = await _get_client().get("status")
    except SbcError:
        return {}
    return {k: st.get(k) for k in ("saveNeeded", "resetNeeded") if k in st}


@mcp.tool()
async def apply_cli_script(
    script: Annotated[str, Field(description="CLI configuration commands as in 'show running-config', e.g. 'configure voip\\n sip-definition proxy-set 1\\n  proxy-name \"ITSP\"\\n  activate\\n exit\\nexit'. May also contain show commands; their output comes back.")],
    save: Annotated[bool, Field(description="Save the configuration to flash afterwards (otherwise it is lost on the next reset).")] = False,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change the configuration with an incremental CLI script — applied live, no reset (WRITE — requires
    AUDIOCODES_ALLOW_WRITE and a Security Administrator user). PUTs /api/v1/files/cliScript/incremental.

    Reload, copy, erase and 'write factory' lines are refused. There is no rollback: read the current
    block with get_configuration first, so it can be restored with another script.
    """
    _require_write()
    text = script.replace("\r\n", "\n").strip("\n") + "\n"
    if not text.strip():
        raise ValueError("script is empty.")
    if m := _BLOCKED_CLI.search(text):
        raise ValueError(f"'{m.group(0).strip()}' is not allowed here (reset / copy / erase commands are refused).")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    summary = f"Apply a CLI script ({len(lines)} line(s)) to the live configuration" + (" and save it." if save else " (not saved).")
    change = {"script": text, "save": save}
    if preview := _confirm("apply_cli_script", change, summary, confirm):
        return {**preview, "script_preview": _mask_cli(text)}
    client = _get_client()
    result = await client.put_file("files/cliScript/incremental", text.encode(), filename="incremental.txt")
    out: dict[str, Any] = {"applied": True, "description": result.get("description"),
                           "output": _mask_cli(str(result.get("output") or ""))[:50_000]}
    if save:
        await client.post("actions/saveConfiguration")
        out["saved"] = True
    out.update(await _status_flags())
    return out


@mcp.tool()
async def apply_ini(
    ini: Annotated[str, Field(description="Partial INI content: parameters ('Name = value') and/or table sections ('[ IPGroup ]' … '[ \\IPGroup ]').")],
    save: Annotated[bool, Field(description="Save the configuration to flash afterwards.")] = False,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Change the configuration with an incremental INI file — applied live, no reset (WRITE — requires
    AUDIOCODES_ALLOW_WRITE and a Security Administrator user). PUTs /api/v1/files/ini/incremental."""
    _require_write()
    text = ini.replace("\r\n", "\n").strip("\n") + "\n"
    if not text.strip():
        raise ValueError("ini is empty.")
    summary = f"Apply an incremental INI ({len([ln for ln in text.splitlines() if ln.strip()])} line(s)) to the live configuration" + (" and save it." if save else " (not saved).")
    if preview := _confirm("apply_ini", {"ini": text, "save": save}, summary, confirm):
        return {**preview, "ini_preview": _mask_ini(text)}
    client = _get_client()
    result = await client.put_file("files/ini/incremental", text.encode(), filename="incremental.ini")
    out: dict[str, Any] = {"applied": True, "description": result.get("description")}
    if save:
        await client.post("actions/saveConfiguration")
        out["saved"] = True
    out.update(await _status_flags())
    return out


@mcp.tool()
async def save_configuration(
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Save the running configuration to flash so it survives a reset (WRITE — requires AUDIOCODES_ALLOW_WRITE,
    Administrator). POSTs /api/v1/actions/saveConfiguration. Saves every unsaved change, not only yours."""
    _require_write()
    flags = await _status_flags()
    summary = "Save the running configuration to flash" + (" (status: saveNeeded=true)." if flags.get("saveNeeded") else
                                                          " (status says nothing is unsaved)." if flags else ".")
    if preview := _confirm("save_configuration", {}, summary, confirm):
        return {**preview, **flags}
    result = await _get_client().post("actions/saveConfiguration")
    return {"saved": True, "description": result.get("description")}


@mcp.tool()
async def start_test_call(
    called_number: Annotated[str, Field(description="Number to call.", max_length=61)],
    calling_number: Annotated[str, Field(description="Caller number to present.", max_length=61)],
    dest_ip_group: Annotated[str | None, Field(description="Destination IP Group (id or exact name).")] = None,
    dest_address: Annotated[str | None, Field(description="Or a destination address, e.g. '10.0.0.20:5060'.", max_length=50)] = None,
    transport: Annotated[Literal["UDP", "TCP", "TLS"] | None, Field(description="With dest_address only.")] = None,
    out_interface: Annotated[int | None, Field(description="With dest_address only: SIP interface index.")] = None,
    timeout: Annotated[int, Field(description="Seconds the call lasts.", ge=1, le=3600)] = 20,
    play_dtmf: Annotated[str | None, Field(description="DTMF digits to play (max 16).", max_length=16)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Place a real SIP test call from the SBC (WRITE — requires AUDIOCODES_ALLOW_WRITE). POSTs
    /api/v1/sipTestCall/dial; follow it with get_test_call(session_id) for status, MOS and jitter."""
    _require_write()
    if (dest_ip_group is None) == (dest_address is None):
        raise ValueError("Give dest_ip_group or dest_address — one of them.")
    if dest_ip_group is not None and (transport or out_interface is not None):
        raise ValueError("transport and out_interface only apply with dest_address.")
    body: dict[str, Any] = {"calledNumber": called_number, "callingNumber": calling_number, "timeout": timeout}
    if dest_ip_group is not None:
        body["destIpGroup"] = dest_ip_group
    else:
        body["destAddress"] = dest_address
        if transport:
            body["transportType"] = transport
        if out_interface is not None:
            body["outInterface"] = out_interface
    if play_dtmf:
        body["playDtmfString"] = play_dtmf
    summary = f"Call {called_number} from {calling_number} via {dest_ip_group or dest_address} for {timeout} s."
    if preview := _confirm("start_test_call", body, summary, confirm):
        return preview
    result = await _get_client().post("sipTestCall/dial", json=body)
    return {"session_id": result.get("sessionId"), **{k: v for k, v in result.items() if k != "sessionId"}}


@mcp.tool()
async def drop_test_call(
    session_id: Annotated[str, Field(description="Session id from start_test_call.")],
) -> dict[str, Any]:
    """End a running SIP test call (DELETE /api/v1/sipTestCall/drop). Only test calls placed via the API."""
    _require_write()
    return await _get_client().delete("sipTestCall/drop", params={"sessionId": session_id})


@mcp.tool()
async def sip_recording(
    command: Annotated[Literal["start", "stop", "pause", "resume"], Field(description="What to do with the recording.")],
    call_key: Annotated[str, Field(description="The call's key, as exposed by SIP message manipulation (Param.Call.HashKey).")],
    role: Annotated[str | None, Field(description="Recording server role from the SIP Recording Rules.", max_length=20)] = None,
    recording_dest_username: Annotated[str | None, Field(description="Override the recording server's destination username.", max_length=60)] = None,
    headers: Annotated[dict[str, str] | None, Field(description="start only: up to 10 extra SIP headers.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Start, stop, pause or resume SIP recording (SIPREC) of a live call (WRITE — requires
    AUDIOCODES_ALLOW_WRITE). POSTs /api/v1/sip/sipRecording."""
    _require_write()
    if headers and command != "start":
        raise ValueError("headers only apply to start.")
    if headers and len(headers) > 10:
        raise ValueError("At most 10 headers.")
    body: dict[str, Any] = {"command": command, "callKey": call_key}
    if role:
        body["role"] = role
    if recording_dest_username:
        body["callRecordingDestUsername"] = recording_dest_username
    if headers:
        body["headers"] = [{"name": k, "value": v} for k, v in headers.items()]
    if preview := _confirm("sip_recording", body, f"SIP recording: {command} for call {call_key}.", confirm):
        return preview
    return await _get_client().post("sip/sipRecording", json=body)


# ---- tools: disruptive (AUDIOCODES_ALLOW_RESET; always confirmed) ------------------------------

@mcp.tool()
async def reset_device(
    save_config: Annotated[bool, Field(description="Save the running configuration before the reset.")] = True,
    wait_for_calls: Annotated[bool, Field(description="Graceful: wait for active calls to end before resetting.")] = True,
    max_wait_seconds: Annotated[int | None, Field(description="With wait_for_calls: reset after at most this many seconds even if calls remain.", ge=2)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Reset (reboot) the device (WRITE — requires AUDIOCODES_ALLOW_WRITE and AUDIOCODES_ALLOW_RESET;
    always confirmed). POSTs /api/v1/actions/reset. Calls are dropped unless the reset waits for them."""
    _require_flag("allow_reset", "AUDIOCODES_ALLOW_RESET", "Resetting the device")
    graceful = (max_wait_seconds or 1) if wait_for_calls else 0
    body = {"saveConfiguration": save_config, "gracefulTimeout": graceful}
    status = await _get_client().get("status")
    when = ("immediately, dropping active calls" if graceful == 0 else
            "once all calls have ended" if graceful == 1 else f"after active calls end, at most {graceful} s")
    summary = (f"RESET the SBC {status.get('productType') or ''} ({status.get('ipAddress') or '?'}) {when}"
               + (", saving the configuration first." if save_config else ", WITHOUT saving unsaved changes.")
               + (" HA is operational: the standby takes over." if status.get("highAvailability") == "Operational" else ""))
    if preview := _confirm("reset_device", body, summary, confirm, always=True):
        return preview
    return await _get_client().post("actions/reset", json=body)


@mcp.tool()
async def replace_configuration(
    content: Annotated[str, Field(description="The COMPLETE new configuration (a full CLI script as from 'show running-config', or a full INI file).")],
    format: Annotated[Literal["cli", "ini"], Field(description="cli or ini.")] = "cli",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Replace the WHOLE configuration and reset the device to activate it (WRITE — requires
    AUDIOCODES_ALLOW_WRITE and AUDIOCODES_ALLOW_RESET, Security Administrator; always confirmed).
    PUTs /api/v1/files/cliScript or /files/ini. The preview shows a diff against the current
    configuration (secrets masked). For changes, prefer apply_cli_script (no reset)."""
    _require_flag("allow_reset", "AUDIOCODES_ALLOW_RESET", "Replacing the configuration (with a reset)")
    text = content.replace("\r\n", "\n").strip("\n") + "\n"
    if len(text.strip()) < 20:
        raise ValueError("content looks empty; replace_configuration needs the complete configuration.")
    client = _get_client()
    path, mask = ("files/cliScript", _mask_cli) if format == "cli" else ("files/ini", _mask_ini)
    current = await client.get_text(path)
    diff = list(difflib.unified_diff(mask(current).splitlines(), mask(text).splitlines(), "current", "new", lineterm=""))
    summary = (f"REPLACE the whole {format} configuration ({len(text.splitlines())} lines; {len(diff)} diff lines) "
               "and RESET the device to activate it.")
    change = {"format": format, "sha256": hashlib.sha256(text.encode()).hexdigest(),
              "current_sha256": hashlib.sha256(current.encode()).hexdigest()}
    if preview := _confirm("replace_configuration", change, summary, confirm, always=True):
        return {**preview, "diff": "\n".join(diff[:400]), **({"diff_truncated": len(diff) - 400} if len(diff) > 400 else {})}
    return await client.put_file(path, text.encode(), filename="config.txt" if format == "cli" else "config.ini")


@mcp.tool()
async def upgrade_firmware(
    file_name: Annotated[str, Field(description="A .cmp firmware file in AUDIOCODES_FILE_DIR (mounted into the container).")],
    hitless: Annotated[bool, Field(description="HA only: hitless upgrade by switchover, without interrupting service.")] = False,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Upload a firmware (.cmp) and activate it — the device resets (or switches over with hitless=true on HA)
    (WRITE — requires AUDIOCODES_ALLOW_WRITE and AUDIOCODES_ALLOW_RESET; always confirmed). PUTs
    /api/v1/files/software[/hitless]."""
    _require_flag("allow_reset", "AUDIOCODES_ALLOW_RESET", "Firmware upgrades")
    folder = _get_client().settings.file_dir
    if not folder:
        raise ValueError("Set AUDIOCODES_FILE_DIR to a folder (mounted into the container) that holds the .cmp file.")
    root = pathlib.Path(folder).resolve()
    path = (root / file_name).resolve()
    if root not in path.parents or not path.is_file():
        raise ValueError(f"No file {file_name!r} in AUDIOCODES_FILE_DIR.")
    if path.suffix.lower() != ".cmp":
        raise ValueError("Firmware files end in .cmp.")
    data = path.read_bytes()
    status = await _get_client().get("status")
    if hitless and status.get("highAvailability") != "Operational":
        raise ValueError("hitless needs an operational HA pair.")
    summary = (f"Upgrade the SBC from {status.get('versionID') or '?'} with {path.name} ({len(data) // 1024} KiB); "
               + ("HA switchover (hitless)." if hitless else "the device RESETS and drops calls."))
    change = {"file": path.name, "sha256": hashlib.sha256(data).hexdigest(), "hitless": hitless}
    if preview := _confirm("upgrade_firmware", change, summary, confirm, always=True):
        return preview
    return await _get_client().put_file("files/software/hitless" if hitless else "files/software", data, filename=path.name)


# ---- tools: TLS (AUDIOCODES_ALLOW_WRITE; identity changes need AUDIOCODES_ALLOW_TLS) ----------


def _subject(cn: str, organizational_unit: str | None, company: str | None, locality: str | None,
             state: str | None, country: str | None) -> dict[str, str]:
    body = {"subjectName": cn}
    for key, value in (("organizationalUnit", organizational_unit), ("companyName", company), ("localityName", locality),
                       ("state", state), ("countryCode", country)):
        if value:
            body[key] = value
    return body


@mcp.tool()
async def create_csr(
    context_id: Annotated[int, Field(description="TLS context id.", ge=0)],
    common_name: Annotated[str, Field(description="CN, e.g. the SBC's FQDN.")],
    organizational_unit: Annotated[str | None, Field(description="OU.")] = None,
    company: Annotated[str | None, Field(description="O.")] = None,
    locality: Annotated[str | None, Field(description="L.")] = None,
    state: Annotated[str | None, Field(description="ST.")] = None,
    country: Annotated[str | None, Field(description="C (two letters).", min_length=2, max_length=2)] = None,
    signature_algorithm: Annotated[Literal["sha256", "sha512", "sha1"], Field(description="Signature algorithm.")] = "sha256",
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Create a certificate signing request for a TLS context's current private key (WRITE — requires
    AUDIOCODES_ALLOW_WRITE). POSTs /api/v1/files/tls/<id>/certificate/request and returns the CSR PEM;
    nothing on the device changes."""
    _require_write()
    body = {**_subject(common_name, organizational_unit, company, locality, state, country), "signatureAlgorithm": signature_algorithm}
    if preview := _confirm("create_csr", {"context": context_id, **body}, f"Create a CSR for TLS context {context_id}, CN={common_name}.", confirm):
        return preview
    resp = await _get_client().post_raw(f"files/tls/{context_id}/certificate/request", json=body)
    return {"context_id": context_id, "csr": resp.content.decode("utf-8", errors="replace")}


@mcp.tool()
async def upload_certificate(
    context_id: Annotated[int, Field(description="TLS context id.", ge=0)],
    pem: Annotated[str, Field(description="The device certificate (PEM) signed for this context's private key; chain certificates may follow.")],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Replace a TLS context's device certificate (WRITE — requires AUDIOCODES_ALLOW_WRITE and AUDIOCODES_ALLOW_TLS).
    The preview compares the new certificate with the current one. PUTs /api/v1/files/tls/<id>/certificate."""
    _require_flag("allow_tls", "AUDIOCODES_ALLOW_TLS", "Changing TLS certificates")
    new = _cert_infos(pem)
    if not new or "error" in new[0]:
        raise ValueError("pem holds no readable certificate.")
    client = _get_client()
    try:
        old = (_cert_infos(await client.get_text(f"files/tls/{context_id}/certificate")) or [{}])[0]
    except SbcError:
        old = {}
    summary = (f"Replace the certificate of TLS context {context_id}: {old.get('subject') or '(none)'} (until {old.get('not_after') or '?'}) "
               f"→ {new[0]['subject']} (until {new[0]['not_after']}, issuer {new[0]['issuer']}).")
    if preview := _confirm("upload_certificate", {"context": context_id, "sha256": hashlib.sha256(pem.encode()).hexdigest(), "new": new[0]}, summary, confirm):
        return preview
    return await client.put_file(f"files/tls/{context_id}/certificate", pem.encode(), filename="certificate.pem")


@mcp.tool()
async def add_trusted_root(
    context_id: Annotated[int, Field(description="TLS context id.", ge=0)],
    pem: Annotated[str, Field(description="One CA certificate (PEM) to trust.")],
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Add a CA certificate to a TLS context's trusted roots, keeping the others (WRITE — requires
    AUDIOCODES_ALLOW_WRITE and AUDIOCODES_ALLOW_TLS). PUTs /api/v1/files/tls/<id>/trustedRoot/incremental."""
    _require_flag("allow_tls", "AUDIOCODES_ALLOW_TLS", "Changing TLS trusted roots")
    info = _cert_infos(pem)
    if len(info) != 1 or "error" in info[0]:
        raise ValueError("pem must hold exactly one readable certificate.")
    summary = f"Trust {info[0]['subject']} (issuer {info[0]['issuer']}, until {info[0]['not_after']}) in TLS context {context_id}."
    if preview := _confirm("add_trusted_root", {"context": context_id, "cert": info[0]}, summary, confirm):
        return preview
    return await _get_client().put_file(f"files/tls/{context_id}/trustedRoot/incremental", pem.encode(), filename="root.pem")


@mcp.tool()
async def generate_private_key(
    context_id: Annotated[int, Field(description="TLS context id.", ge=0)],
    size: Annotated[Literal[1024, 2048, 4096], Field(description="Key size in bits.")] = 2048,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Generate a NEW private key on the device for a TLS context — the current certificate stops matching
    until a new one is uploaded (WRITE — requires AUDIOCODES_ALLOW_WRITE and AUDIOCODES_ALLOW_TLS; always
    confirmed). POSTs /api/v1/files/tls/<id>/privateKey/generate."""
    _require_flag("allow_tls", "AUDIOCODES_ALLOW_TLS", "Generating TLS private keys")
    summary = (f"Generate a new {size}-bit private key for TLS context {context_id}. The current certificate no longer "
               "matches: TLS on this context breaks until a new certificate is installed (create_csr → upload_certificate).")
    if preview := _confirm("generate_private_key", {"context": context_id, "size": size}, summary, confirm, always=True):
        return preview
    return await _get_client().post(f"files/tls/{context_id}/privateKey/generate", json={"size": size})


@mcp.tool()
async def generate_self_signed(
    context_id: Annotated[int, Field(description="TLS context id.", ge=0)],
    common_name: Annotated[str, Field(description="CN.")],
    organizational_unit: Annotated[str | None, Field(description="OU.")] = None,
    company: Annotated[str | None, Field(description="O.")] = None,
    locality: Annotated[str | None, Field(description="L.")] = None,
    state: Annotated[str | None, Field(description="ST.")] = None,
    country: Annotated[str | None, Field(description="C (two letters).", min_length=2, max_length=2)] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Replace a TLS context's certificate with a self-signed one (WRITE — requires AUDIOCODES_ALLOW_WRITE and
    AUDIOCODES_ALLOW_TLS; always confirmed). POSTs /api/v1/files/tls/<id>/certificate/generate."""
    _require_flag("allow_tls", "AUDIOCODES_ALLOW_TLS", "Generating self-signed certificates")
    body = _subject(common_name, organizational_unit, company, locality, state, country)
    summary = f"Replace the certificate of TLS context {context_id} with a self-signed one for CN={common_name} (peers that check certificates will reject it)."
    if preview := _confirm("generate_self_signed", {"context": context_id, **body}, summary, confirm, always=True):
        return preview
    return await _get_client().post(f"files/tls/{context_id}/certificate/generate", json=body)


# ---- tools: license (AUDIOCODES_ALLOW_LICENSE; always confirmed) ---------------------------------

@mcp.tool()
async def install_license(
    key: Annotated[str, Field(description="The license key string for this device.")],
    description: Annotated[str | None, Field(description="Key description.")] = None,
    serial_number: Annotated[str | None, Field(description="The device serial the key is for; the device rejects a mismatch.")] = None,
    confirm: Annotated[str | None, Field(description=_CONFIRM_DESC)] = None,
) -> dict[str, Any]:
    """Install a license key (WRITE — requires AUDIOCODES_ALLOW_WRITE and AUDIOCODES_ALLOW_LICENSE, Security
    Administrator; always confirmed). PUTs /api/v1/license. HA pairs need a license file instead."""
    _require_flag("allow_license", "AUDIOCODES_ALLOW_LICENSE", "Installing licenses")
    current = await _get_client().get("license")
    body: dict[str, Any] = {"licenseVersion": 1, "key": key.strip()}
    if description:
        body["keyDescription"] = description
    if serial_number:
        body["serialNumber"] = serial_number
    summary = (f"Replace the license of device {current.get('serialNumber') or '?'} "
               f"(now: {current.get('keyDescription') or 'no description'}) with key …{key.strip()[-6:]}.")
    change = {"sha256": hashlib.sha256(key.strip().encode()).hexdigest(), "description": description, "serial": serial_number}
    if preview := _confirm("install_license", change, summary, confirm, always=True):
        return preview
    return await _get_client().put_json("license", json=body)


# ---- tool: raw escape hatch ---------------------------------------------------------------------

@mcp.tool()
async def sbc_get(
    path: Annotated[str, Field(description="Path under /api/v1, e.g. 'status', 'alarms/history', 'kpi/current/media'.")],
    params: Annotated[dict[str, Any] | None, Field(description="Optional query parameters.")] = None,
) -> dict[str, Any]:
    """Escape hatch: raw read-only GET of any /api/v1 JSON resource (not the configuration files — use
    get_configuration, which masks secrets)."""
    clean = path.strip().strip("/").removeprefix("api/v1/")
    if ".." in clean.split("/"):
        raise ValueError("path must stay under /api/v1.")
    if clean.startswith(("files/ini", "files/cliScript", "files/configurationPackage")):
        raise ValueError("Read configuration files with get_configuration (secrets are masked there).")
    return await _get_client().get(clean, params=params)


def main() -> None:
    """Console entry point: load settings, wire transport, and run the server."""
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"audiocodes-sbc-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2)

    global _client
    _client = SbcClient(settings)

    if settings.transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host=settings.host,
            port=settings.port,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
