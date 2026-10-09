# fortigate-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **FortiGate** firewall through the **FortiOS REST API**. Ask about your firewall in
natural language — policies and their hit counters, address/service objects, VIPs, interfaces,
routing, IPsec VPN status, HA, and system/license health — and, opt-in, **create/update address
objects, add/remove address-group members, and enable/disable firewall policies**.

- One shared `httpx.AsyncClient`; static **API-token** auth (`Authorization: Bearer …`), no session.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default** — GET against the `cmdb` (config) and `monitor` (live) trees; write tools
  are **opt-in** behind `FORTIGATE_ALLOW_WRITE` (see below).
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

There are no delete tools and no raw write escape hatch.

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
   under custom permissions) instead of read-only. Prefer a separate write admin + token over
   upgrading the read-only one.
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
      FASTMCP_HOST: 0.0.0.0
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

With `FORTIGATE_ALLOW_WRITE=true` you can also:

- "Create an address object srv-app-01 for 10.0.0.10 and add it to the grp-web group."
- "Change the address app-fqdn to point at app.test.corp."
- "Remove srv-old from the grp-web address group."
- "Disable policy 12 with the comment 'paused for change CHG-1', and re-enable it afterwards."

## Notes & scope

- **Writes are opt-in.** Reads are always available; the write tools refuse unless
  `FORTIGATE_ALLOW_WRITE=true` and the REST API admin has a read-write Firewall profile. Leave the
  flag unset (and keep a read-only profile) for a read-only server. The writes are reversible
  (re-enable a policy, re-add a member, set the old address value); there are no delete tools.
- **VDOMs** — multi-VDOM boxes scope most objects per VDOM; set `FORTIGATE_VDOM` or pass `vdom` per
  tool. Global resources (system status, license, HA) ignore it.
- **Secrets are never returned** by FortiOS (e.g. IPsec `preshared-key`), so they can't leak here.
- **`monitor/firewall/session`** can return tens of thousands of rows — it's intentionally not a
  curated tool. Reach it via `fortios_get("monitor", "firewall/session", filter=..., count=...)`.
