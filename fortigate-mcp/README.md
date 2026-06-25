# fortigate-mcp

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to a **FortiGate** firewall through the **FortiOS REST API**. Ask about your
firewall in natural language — policies and their hit counters, address/service objects, VIPs,
interfaces, routing, IPsec VPN status, HA, and system/license health.

- One shared `httpx.AsyncClient`; static **API-token** auth (`Authorization: Bearer …`), no session.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — GET-only against the `cmdb` (config) and `monitor` (live) trees; pair with a
  read-only REST API admin profile.
- A raw escape-hatch tool (`fortios_get`) so any FortiOS resource stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_policies(policyid?, ipv6?, vdom?, limit?, full?)` | Firewall policies + action/state (cmdb firewall/policy). |
| `list_addresses(name?, groups?, vdom?, limit?, full?)` | Address objects, or address groups with `groups=true`. |
| `list_services(name?, groups?, vdom?, limit?, full?)` | Custom services, or service groups with `groups=true`. |
| `list_vips(name?, vdom?, limit?, full?)` | Virtual IPs / destination-NAT objects. |
| `list_interfaces(name?, vdom?, limit?, full?)` | Interface **configuration** (IP, allowaccess, status). |
| `list_static_routes(vdom?, limit?, full?)` | Configured IPv4 static routes. |
| `system_info()` | FortiOS version, serial, hostname/model, firmware & license status. |
| `system_resources()` | Live CPU / memory / session / disk usage. |
| `ha_status(full?)` | HA cluster members — role, sync state, CPU/mem. |
| `interface_status(name?, vdom?, limit?, full?)` | **Live** interface link/speed/traffic. |
| `policy_stats(policyid?, ipv6?, vdom?, limit?, full?)` | Live per-policy hit counters, bytes, sessions. |
| `vpn_status(name?, vdom?, limit?, full?)` | Live IPsec tunnel status + traffic (per-phase2 up/down). |
| `routing_table(ipv6?, vdom?, limit?, full?)` | Live routing table / RIB (capped). |
| `fortios_get(tree, path, vdom?, filter?, count?, start?)` | Escape hatch: raw read-only GET against any resource. |

Results are trimmed to the useful fields by default; pass `full=true` for raw objects, and list
results are capped (`FORTIGATE_MAX_ROWS`, default 200) unless `full`.

## 1. Create a read-only REST API admin

In FortiOS: **System → Administrators → Create New → REST API Admin**.

1. Create (or reuse) an **access profile** with **Read** permission on the groups you need
   (e.g. *Firewall*, *System*, *Network*, *Log & Report*) — read is enough for every tool here;
   write is never used.
2. Assign that profile to the REST API admin, set a **Trusted Host** to the IP the server runs from,
   and create the admin. FortiOS shows the **API token once** — copy it; it's `FORTIGATE_API_TOKEN`.

```
config system api-user
    edit "mcp-ro"
        set accprofile "read_only"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <server-ip> 255.255.255.255
            next
        end
    next
end
execute api-user generate-key mcp-ro
```

## 2. Configure

```bash
cp .env.example fortigate.env
# edit fortigate.env: FORTIGATE_BASE_URL, FORTIGATE_API_TOKEN
```

- **`FORTIGATE_BASE_URL`** — the appliance management URL (e.g. `https://192.0.2.1`). For HA, point
  at the cluster management IP.
- **`FORTIGATE_VDOM`** — default VDOM (`root` on single-VDOM boxes); any tool can override per call.
- **TLS** — appliances ship self-signed certs. Set `FORTIGATE_CA_BUNDLE` to the appliance CA PEM, or
  (lab only) `FORTIGATE_VERIFY_SSL=false`.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t fortigate-mcp .
claude mcp add fortigate -- docker run -i --rm --env-file ./fortigate.env fortigate-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from fortigate.env into your shell first, then:
claude mcp add fortigate -- poetry run fortigate-mcp
```

### Always-on HTTP (optional)

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

## 4. Verify

In Claude Code, run `/mcp` to confirm the `fortigate` server connected, then ask things like:

- "What FortiOS version and model is this, and is the support license valid?"
- "Which firewall policies allow traffic to the DMZ?"
- "Show the live hit counters for policy 12."
- "Are all IPsec tunnels up?"
- "What's the HA sync status and current CPU/memory?"

## Notes & scope

- **Read-only.** No configuration/write tools. If you add them, gate behind an explicit env flag
  (e.g. `FORTIGATE_ALLOW_WRITE`) and a separate tool group, and use a read-write API admin.
- **VDOMs** — multi-VDOM boxes scope most objects per VDOM; set `FORTIGATE_VDOM` or pass `vdom` per
  tool. Global resources (system status, license, HA) ignore it.
- **Secrets are never returned** by FortiOS (e.g. IPsec `preshared-key`), so they can't leak here.
- **`monitor/firewall/session`** can return tens of thousands of rows — it's intentionally not a
  curated tool. Reach it via `fortios_get("monitor", "firewall/session", filter=..., count=...)`.
