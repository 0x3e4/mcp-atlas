# netscaler-mcp

A **lightweight, read-only** [MCP](https://modelcontextprotocol.io) server that connects a local
agent (e.g. Claude Code) to a **NetScaler ADC** appliance (or HA pair) through the **NITRO REST API**.
Ask about your load balancers in natural language — vservers and their up/down state, backend
services/servers, SSL certificate expiry, HA status, and box CPU/memory/throughput.

- One shared `httpx.AsyncClient`; NITRO **session** login with a cached `NITRO_AUTH_TOKEN` cookie
  (transparently re-logs-in on expiry), or **stateless** `X-NITRO-USER`/`X-NITRO-PASS` per request.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only** — no configuration/write actions; pair the server with a `readonlypolicy` account.
- A raw escape-hatch tool (`nitro_get`) so any NITRO `config`/`stat` resource stays reachable.

## Tools

| Tool | What it does |
|---|---|
| `list_lb_vservers(name?, limit?, full?)` | LB virtual servers + state (`curstate`/`effectivestate`). |
| `list_cs_vservers(name?, limit?, full?)` | Content-switching virtual servers + state. |
| `list_gslb_vservers(name?, limit?, full?)` | GSLB virtual servers (needs the GSLB feature). |
| `list_gslb_services(name?, limit?, full?)` | GSLB services + state. |
| `list_gslb_sites(name?, limit?, full?)` | GSLB sites (LOCAL/REMOTE) + IPs. |
| `list_services(name?, servicegroup?, limit?, full?)` | Backend services, or service groups with `servicegroup=true`. |
| `list_servers(name?, limit?, full?)` | Backend server objects. |
| `list_certificates(expiring_within_days?, limit?, full?)` | SSL cert/key pairs + expiry; filter/sort by days-to-expiry. |
| `list_dns_records(record_type="A", limit?, full?)` | DNS records by type (A/AAAA/CNAME/NS/SOA/MX/TXT/SRV/PTR). |
| `list_dns_zones(name?, limit?, full?)` | Configured DNS zones. |
| `list_dns_nameservers(limit?, full?)` | Configured DNS name servers + state. |
| `list_waf_profiles(name?, limit?, full?)` | Application Firewall (WAF) profiles (needs AppFw). |
| `list_waf_policies(name?, limit?, full?)` | WAF policies + the profile each binds. |
| `waf_stats(name?, limit?, full?)` | Live WAF policy hit counters (stat `appfwpolicy`). |
| `list_bot_profiles(name?, limit?, full?)` | Bot management profiles (needs the Bot feature). |
| `list_bot_policies(name?, limit?, full?)` | Bot policies + the profile each binds. |
| `bot_stats(name?, limit?, full?)` | Live Bot policy hit counters (stat `botpolicy`). |
| `ha_status(full?)` | HA node status for the whole pair (`masterstate`, `hasync`). |
| `system_health(full?)` | Appliance CPU / memory / disk / uptime (stat `ns`). |
| `vserver_stats(kind="lb"\|"cs"\|"gslb", name?, limit?, full?)` | Live vserver traffic/health counters. |
| `system_info(full?)` | Version, hardware, license and HA summary in one call. |
| `nitro_get(tree, resourcetype, name?, attrs?, filter?, count?, pagesize?, pageno?)` | Escape hatch: raw read-only GET against any NITRO resource. |

Results are trimmed to the useful columns by default; pass `full=true` for the raw NITRO objects, and
list results are capped (`NETSCALER_MAX_ROWS`, default 200) unless `full`.

## 1. Create a read-only account

On the appliance, create a system user and bind the built-in **`readonlypolicy`** command policy —
that grants `show`/`stat`/GET-only access, which is all this server needs.

```
add system user nsmcp <password>
bind system user nsmcp readonlypolicy 100
```

(Or in the GUI: **System → User Administration → Users → Add**, then bind the `readonlypolicy`
command policy.) Use this account's credentials below.

## 2. Configure

```bash
cp .env.example netscaler.env
# edit netscaler.env: NETSCALER_BASE_URL, NETSCALER_USER, NETSCALER_PASSWORD
```

- **`NETSCALER_BASE_URL`** — the appliance management URL. For an **HA pair**, point at the HA
  management VIP if you have one, otherwise the **primary** node's NSIP (a secondary serves config
  but reports itself as not-serving and shows different stats). `ha_status` reflects both nodes
  regardless.
- **TLS** — appliances ship self-signed certs. Set `NETSCALER_CA_BUNDLE` to the appliance CA PEM,
  or (lab only) `NETSCALER_VERIFY_SSL=false`.
- **Auth** — `NETSCALER_AUTH_MODE=session` (default) is efficient; switch to `stateless` if session
  slots are scarce or the appliance sits behind a non-sticky load balancer.

## 3. Run & register with Claude Code

### Docker (recommended)

```bash
poetry lock          # first time only, generates poetry.lock
docker build -t netscaler-mcp .
claude mcp add netscaler -- docker run -i --rm --env-file ./netscaler.env netscaler-mcp
```

(`docker run -i` keeps stdin attached for the stdio transport; do **not** add `-t`.)

### Local (Poetry) — alternative

```bash
poetry install
# export the variables from netscaler.env into your shell first, then:
claude mcp add netscaler -- poetry run netscaler-mcp
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
- Put the **gateway and the servers on one shared network**, so `http://netscaler-mcp:8000/mcp` resolves.

Create the network once, then run this server attached to it — a gateway-flavoured `compose.yml`:

```bash
docker network create atlas-net     # once; shared by the gateway + every server
```

```yaml
# compose.yml — gateway variant: no host port, joins the shared network
services:
  netscaler-mcp:
    build: .
    image: netscaler-mcp
    env_file: ./netscaler.env
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

With the gateway also on `atlas-net`, register this server at `http://netscaler-mcp:8000/mcp`
(`mcpjungle register --name netscaler --url http://netscaler-mcp:8000/mcp`). See the repo-root
[README → *Behind an MCP gateway*](../README.md#behind-an-mcp-gateway-eg-mcpjungle) for the full
gateway walkthrough and client setup.

## 4. Verify

In Claude Code, run `/mcp` to confirm the `netscaler` server connected, then ask things like:

- "Which LB vservers are DOWN?"
- "List SSL certificates expiring within 30 days."
- "What's the HA status?"
- "Show CPU and memory usage."
- "Show the live request rate for lb vserver vs_web."

## Development

```bash
poetry install
poetry run pytest -q                            # static smoke tests (no network, no credentials)
poetry run mcp dev src/netscaler_mcp/server.py  # MCP Inspector to exercise tools
```

## Notes & scope

- **Compatibility.** Built and field-tuned against **NetScaler ADC 14.1**. The NITRO API and the
  attributes used here are stable across 13.0 / 13.1 / 14.1, so older builds work too — if a build
  lacks a projected attribute it simply comes back `null`; use `full=true` or `nitro_get` for the raw
  payload. (NITRO is served under a fixed `/nitro/v1` path — there is no api-version parameter.)
- **Read-only.** No write/config tools in this version. If you add them, gate behind an explicit env
  flag (e.g. `NETSCALER_ALLOW_WRITE`) and a separate tool group, and use a higher-privilege account.
- **Feature-gated resources** (GSLB, AppFW) return a clean "feature not enabled" error when the
  feature is off on the appliance.
- The whole-config resources `nsrunningconfig` / `nssavedconfig` are reachable via `nitro_get` but
  return very large payloads — prefer a targeted resource.
- The stat `Interface` resource is **capitalized** — query it via `nitro_get("stat", "Interface")`.
