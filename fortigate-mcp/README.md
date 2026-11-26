# fortigate-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **FortiGate** firewall through the **FortiOS REST API**. Ask about your firewall in
natural language — policies and their hit counters, which policy a flow hits, address/service
objects and every other common config table, VIPs, interfaces, routing, IPsec / SSL-VPN, SD-WAN
health, sessions, logs, the configuration as CLI text, HA and system/license health — and, opt-in,
**create, change and delete objects and policies**, place policies, and ban IPs.

- One shared `httpx.AsyncClient`; static **API-token** auth (`Authorization: Bearer …`), no session.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default** — GET against the `cmdb` (config), `monitor` (live) and `log` trees;
  write tools are **opt-in** behind `FORTIGATE_ALLOW_WRITE`, deletes and user actions each behind a
  switch of their own (see below). Secrets (`ENC …` values, passwords, PSKs, private keys) are masked.
- A raw escape-hatch tool (`fortios_get`) so any FortiOS resource stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_policies(policyid?, ipv6?, vdom?, limit?, full?)` | Firewall policies + action/state (cmdb firewall/policy). |
| `list_addresses(name?, groups?, vdom?, limit?, full?)` | Address objects, or address groups with `groups=true`. |
| `list_services(name?, groups?, vdom?, limit?, full?)` | Custom services, or service groups with `groups=true`. |
| `list_kinds()` | The config tables the generic object tools cover (address, address6, groups, services, VIPs, IP pools, schedules, policies, local-in policies, static / policy routes, zones, interfaces, DHCP servers, users and user groups, IPsec phase 1/2, SSL-VPN portals, shapers, security profiles). |
| `list_objects(kind, filter?, vdom?, limit?, full?)` | List any of those tables, optionally filtered (`name=@web`). |
| `get_object(kind, name, vdom?)` | One object with all attributes and its reference count (`q_ref`). |
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
| `policy_lookup(srcintf, source_ip, dest, protocol?, dest_port?, source_port?, ipv6?, vdom?)` | Which policy a flow would hit — "may X reach Y on port Z?". |
| `route_lookup(destination, ipv6?, vdom?)` | Which route / interface traffic to a destination takes. |
| `list_sessions(source?, destination?, dest_port?, protocol?, policy_id?, srcintf?, dstintf?, count?, full?, vdom?)` | Current sessions, filtered and capped. |
| `live_table(topic, vdom?, limit?)` | Live tables: `arp`, `dhcp_leases`, `fqdn_addresses`, `sdwan_health`, `ssl_vpn_sessions`, `firewall_users`, `banned_ips`, `fortiguard`, `certificates`, `managed_switches`, `managed_aps`, `ha_checksums`, `license`. |
| `search_logs(log_type?, subtype?, filter?, source?, rows?, vdom?)` | Search traffic / event / UTM logs on disk, in memory, FortiAnalyzer or FortiCloud. |
| `config_backup(section?, scope?, vdom?, max_chars?)` | The configuration as CLI text, whole or one block (`firewall policy`), secrets masked. |
| `fortios_get(tree, path, vdom?, filter?, count?, start?)` | Escape hatch: raw read-only GET against any resource. |

Results are trimmed to the useful fields by default; pass `full=true` for raw objects, and list
results are capped (`FORTIGATE_MAX_ROWS`, default 200) unless `full`.

### Write tools (opt-in)

These change the FortiGate configuration and only work when **`FORTIGATE_ALLOW_WRITE=true`**
(otherwise they refuse with a clear message). The REST API admin also needs a **read-write** access
profile for *Firewall* (see section 1). Changes take effect immediately (there is no commit step), and
every tool takes `vdom` like the read tools. FortiOS errors come back with their numeric code and
`cli_error` text (e.g. `error -5 (a duplicate entry already exists)`).

| Tool | What it does |
|---|---|
| `create_address(name, subnet? \| fqdn? \| start_ip+end_ip?, comment?, vdom?)` | Create an IPv4 address object (`ipmask` / `fqdn` / `iprange`). `subnet` takes `10.0.0.10`, `10.0.0.0/24` or `10.0.0.0 255.255.255.0`. |
| `update_address(name, subnet? \| fqdn? \| start_ip+end_ip?, comment?, vdom?)` | Change an address object's value or comment; only the given fields change. Affects every policy/group that uses it. |
| `add_to_address_group(group, members, vdom?)` | Add existing addresses/groups to an address group, keeping the current members. |
| `remove_from_address_group(group, members, vdom?)` | Take members out of an address group, keeping the others (never empties a group; the objects stay). |
| `set_policy_status(policy_id, enabled, comment?, vdom?)` | Enable or disable a firewall policy. `comment` **replaces** the policy's comments. |
| `create_policy(name, srcintf, dstintf, srcaddr, dstaddr, service, action?, schedule?, nat?, logtraffic?, enabled?, comments?, extra?, before?, after?, vdom?)` | Create a firewall policy and place it before / after another (default: at the end). |
| `move_policy(policy_id, before? \| after?, vdom?)` | Change a policy's position (policies match top-down). |
| `add_object(kind, data, vdom?)` | Create an object in any covered table; lists of names become FortiOS tables. |
| `update_object(kind, name, data, vdom?)` | Change attributes; the preview shows each old → new value and the code is tied to the current values. Table attributes are replaced whole. |

Further writes need **a second switch** on top of `FORTIGATE_ALLOW_WRITE` (both default `false`,
read per instance env file, so per user):

| Switch | Tools |
|---|---|
| `FORTIGATE_ALLOW_DELETE` | `delete_object(kind, name, vdom?)` — **always confirmed**, even with `FORTIGATE_CONFIRM_WRITE=false`; the preview shows how often the object is referenced (FortiOS refuses to delete a referenced object). |
| `FORTIGATE_ALLOW_USER_ACTIONS` | `ban_ips(ips, expiry_seconds?)`, `unban_ips(ips? \| all?)` (quarantine), `deauth_users(ips? \| all?)` (log out authenticated firewall users). |

There is no raw write escape hatch, no reboot and no configuration restore.

**Confirmation before every write** (`FORTIGATE_CONFIRM_WRITE`, default `true`): a write tool's first
call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview
and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. The
code is tied to those exact arguments, so a changed request needs a fresh confirmation (codes also
expire when the server restarts). Set `FORTIGATE_CONFIRM_WRITE=false` to let writes run directly.

## 1. Create a REST API admin

In FortiOS: **System → Administrators → Create New → REST API Admin**.

1. Create (or reuse) an **access profile** with **Read** permission on the groups you need
   (e.g. *Firewall*, *System*, *Network*, *Log & Report*) — read is enough for every read tool.
   For the **write** tools (`FORTIGATE_ALLOW_WRITE=true`) the profile needs **Read/Write** on
   *Firewall* (at least *Address* and *Policy*; `fwgrp` with `address`/`policy` set to `read-write`
   under custom permissions) instead of read-only — plus *Network* / *VPN* / *User* / *Security
   Profile* for writes to those tables, and *User & Device* for the user actions. `config_backup`
   needs permission to back up the configuration (*System*). Prefer a separate write admin + token
   over upgrading the read-only one.
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
#   (set FORTIGATE_ALLOW_WRITE=true to enable writes)
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

Run the server as a long-lived `streamable-http` service instead of per-session stdio.
[`compose.yml`](compose.yml) already sets `MCP_TRANSPORT=streamable-http` and binds `0.0.0.0:8000`:

```bash
docker compose up -d        # serves MCP at http://localhost:8000/mcp (streamable-http)
```

Point any HTTP MCP client at `http://<host>:8000/mcp` (also the only mode remote clients like
OpenAI support). **On localhost this works as-is — nothing else to change.**

#### Behind an MCP gateway (shared Docker network)

A gateway (e.g. [mcpjungle](https://github.com/mcpjungle/MCPJungle)) fronts many servers behind one
endpoint. Running several atlas servers next to a gateway on one host changes two things:

- The published **`8000:8000` host port collides** once more than one server uses it. Drop the host
  port and let the gateway reach the server **by its compose service name** over a shared Docker
  network (or, if you must publish, give each server a distinct host port like `"8001:8000"`).
- Put the **gateway and the servers on one shared network**, so `http://fortigate-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  fortigate-mcp:
    build: .
    image: fortigate-mcp
    env_file: ./fortigate.env
    environment:
      MCP_TRANSPORT: streamable-http
      MCP_HOST: 0.0.0.0
      MCP_PORT: "8000"
    # no `ports:` — only the gateway reaches it, over atlas-net
    networks: [atlas-net]
    restart: unless-stopped

networks:
  atlas-net:
    external: true
```

With the gateway also on `atlas-net`, register this server at `http://fortigate-mcp:8000/mcp`
(`mcpjungle register --name fortigate --url http://fortigate-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
API token, or one container per FortiGate.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

```yaml
x-fortigate: &fortigate
  image: ghcr.io/0x3e4/fortigate-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  fortigate-mcp:                    # existing shared read-only instance
    <<: *fortigate
    container_name: fortigate-mcp
    env_file: ./fortigate.env

  fortigate-mcp-instance-a:         # write access with instance a's API token
    <<: *fortigate
    container_name: fortigate-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's API token and `FORTIGATE_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. Every write still asks for confirmation first unless
  `FORTIGATE_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name fortigate --url http://fortigate-mcp:8000/mcp
  mcpjungle register --name fortigate-instance-a --url http://fortigate-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add fortigate-instance-a -- docker run -i --rm --env-file ./env/instance_a.env fortigate-mcp`

## 4. Verify

In Claude Code, run `/mcp` to confirm the `fortigate` server connected, then ask things like:

- "What FortiOS version and model is this, and is the support license valid?"
- "Which firewall policies allow traffic to the DMZ?"
- "Show the live hit counters for policy 12."
- "Are all IPsec tunnels up?"
- "What's the HA sync status and current CPU/memory?"
- "Is 10.0.0.5 on port1 allowed to reach 203.0.113.10 on 443? Which policy matches?"
- "Show denied traffic from 10.0.0.5 in the last log lines."
- "Is the SD-WAN health check for the ISP links OK?"
- "Show me the `firewall vip` config block."

With `FORTIGATE_ALLOW_WRITE=true` you can also:

- "Create an address object srv-app-01 for 10.0.0.10 and add it to the grp-web group."
- "Change the address app-fqdn to point at app.test.corp."
- "Remove srv-old from the grp-web address group."
- "Disable policy 12 with the comment 'paused for change CHG-1', and re-enable it afterwards."
- "Create a policy web-in from wan1 to dmz for vip-web on HTTPS and put it before policy 3."
- "Create a zone dmz with port3 and port4."
- "Delete the address srv-old." (with `FORTIGATE_ALLOW_DELETE=true`)
- "Ban 203.0.113.66 for an hour." (with `FORTIGATE_ALLOW_USER_ACTIONS=true`)

## Security & hardening

This server uses the shared mcp-atlas guard (see the [repo README → Security](../README.md#security)):
writes are confirmed in the client's own dialog where the client supports it (`MCP_CONFIRM_MODE`), every
tool carries read-only / destructive hints, text other people wrote comes back marked as
`<untrusted>`, secrets are masked, writes that would carry secrets out are refused, and every write is
audited (stderr, GELF `MCP_AUDIT_GELF`, syslog `MCP_AUDIT_SYSLOG`). In HTTP mode set `MCP_AUTH_TOKEN` and
`MCP_ALLOWED_HOSTS`; the compose examples already run the container read-only and without capabilities.
Credentials can come from files (Docker / Kubernetes secrets) instead of the env file: set `FORTIGATE_API_TOKEN_FILE=/run/secrets/…` and leave `FORTIGATE_API_TOKEN` unset; this works for every password, secret, token, API key and user variable (`<VAR>_FILE`). The variables are in [`.env.example`](.env.example).

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `FORTIGATE_ALLOW_WRITE=true` and the REST API admin has a read-write Firewall profile. Leave the
  flag unset (and keep a read-only profile) for a read-only server. Deletes need
  `FORTIGATE_ALLOW_DELETE` and always ask first; banning IPs / logging out users needs
  `FORTIGATE_ALLOW_USER_ACTIONS`.
- **VDOMs** — multi-VDOM boxes scope most objects per VDOM; set `FORTIGATE_VDOM` or pass `vdom` per
  tool. Global resources (system status, license, HA) ignore it.
- **Secrets are masked**: FortiOS returns secrets only as `ENC …` blobs, and this server masks those,
  password / PSK attributes and private keys in every result (including `fortios_get` and
  `config_backup`).
- **Sessions** can number tens of thousands — `list_sessions` always filters and caps (`count`).
- **IPv6 policies:** FortiOS 7.x keeps IPv4 and IPv6 rules together in `firewall/policy`
  (`srcaddr6` / `dstaddr6`); `list_policies(ipv6=true)` reads the separate `firewall/policy6` table
  of FortiOS 6.x.
