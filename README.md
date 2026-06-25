# mcp-atlas

A collection of complete, drop-in [MCP](https://modelcontextprotocol.io) servers that connect a
local agent (e.g. [Claude Code](https://docs.claude.com/en/docs/claude-code)) to security and ops
systems. Each server is **self-contained** — its own source, tests, Dockerfile and README — and is
**read-only** by default: ask about your data in natural language, nothing writes back.

## Servers

| Server | What it does |
|--------|--------------|
| [defender-mcp](defender-mcp/) | Query **Microsoft Defender XDR** via the Microsoft Graph security API — advanced hunting (KQL), incidents, alerts, devices and vulnerabilities, plus raw `graph_get` / `graph_hunt` escape hatches. |
| [wazuh-mcp](wazuh-mcp/) | Query a **Wazuh** deployment — alerts, the full event **archive** (every collected event, not just rule hits), vulnerabilities, agents, inventory, rules, SCA and manager status, across the Indexer and Manager APIs. |
| [netscaler-mcp](netscaler-mcp/) | Query a **NetScaler ADC** appliance (or HA pair) over the **NITRO REST API** — LB/CS/GSLB vservers + state, services and servers, SSL cert expiry, **GSLB** services/sites, **DNS** records/zones/nameservers, **WAF (AppFw)** and **Bot** profiles/policies + hit stats, HA status, and box CPU/memory/throughput, plus a raw `nitro_get` escape hatch. |
| [fortigate-mcp](fortigate-mcp/) | Query a **FortiGate** firewall over the **FortiOS REST API** — firewall policies (with live hit counters), address/service objects, VIPs, interfaces, routing, IPsec VPN tunnel status, HA, and system/license health, plus a raw `fortios_get` escape hatch. |
| [azure-devops-mcp](azure-devops-mcp/) | Query an on-prem **Azure DevOps Server** (formerly TFS) over its REST API — projects, teams, Git repos/branches/commits/pull requests, work items (WIQL), build/pipeline definitions and runs, releases and the wiki, plus a raw `azdo_get` escape hatch. Optional **write** tools (create/update work items, create/update wiki pages) behind `AZDO_ALLOW_WRITE`. |
| [bookstack-mcp](bookstack-mcp/) | Query a **BookStack** wiki over its REST API — browse the shelves/books/chapters/pages hierarchy, read and search page content, list attachments, and export pages/books to markdown, plus a raw `bookstack_get` escape hatch. |
| [prtg-mcp](prtg-mcp/) | Query a **PRTG Network Monitor** (Paessler) server over its HTTP API — sensors/devices/groups/probes and their up/down state, sensor channels and details, the event log, core/system health, and historic data, plus a raw `prtg_get` escape hatch. |
| [zammad-mcp](zammad-mcp/) | Query a **Zammad** helpdesk over its REST API — browse/search tickets, read the conversation (articles), look up users/organizations and reference data, plus a raw `zammad_get` escape hatch. Optional **write** tools (add note/comment, update ticket, create ticket) behind `ZAMMAD_ALLOW_WRITE`. |
| [snipeit-mcp](snipeit-mcp/) | Query a **Snipe-IT** asset-management instance over its REST API — assets (by tag/serial), who has what, and the model/category/location/license/accessory catalogs, plus a raw `snipeit_get` escape hatch. Optional **write** tools (check out/in, update, create, audit assets) behind `SNIPEIT_ALLOW_WRITE`. |
| [netbox-mcp](netbox-mcp/) | Query a **NetBox** DCIM/IPAM source of truth over its REST API — devices and interfaces, IP addresses and prefixes, virtual machines, and the site/rack/VLAN/VRF/cluster/tenant catalogs, plus a raw `netbox_get` escape hatch. |
| [vcenter-mcp](vcenter-mcp/) | Query a **VMware vCenter** server over the vSphere Automation REST API — VMs and power state, hosts, clusters, datastores, networks, resource pools, and appliance version/health, plus a raw `vcenter_get` escape hatch. |

## Using a server

Each folder is independent: open its README and follow the install steps. The common shape:

```bash
cd <server>-mcp
cp .env.example <server>.env          # fill in URLs / credentials
docker build -t <server>-mcp .
claude mcp add <server> -- docker run -i --rm --env-file ./<server>.env <server>-mcp
```

Then run `/mcp` in Claude Code to confirm the server connected, and ask away. Every server also
supports an always-on `streamable-http` mode via `docker compose up -d` (see each README).

## Using with other clients & gateways

Each server speaks plain MCP over two transports, so it works with any MCP client:

- **stdio** (default) — the client launches `docker run -i …` per session. Best for local clients
  (Claude Code, VS Code/Copilot, Cursor, …).
- **streamable-http** — run it as an always-on service and point clients at a URL:

  ```bash
  cd <server>-mcp && docker compose up -d     # serves http://<host>:8000/mcp
  ```

  Put each server on its own port/host (or behind a gateway, below). Remote clients (e.g. OpenAI)
  **only** support HTTP servers, so use this mode (or a gateway) for them.

### Behind an MCP gateway (e.g. mcpjungle)

A gateway proxies many MCP servers behind **one** endpoint (tool discovery, namespacing, auth) so a
client connects once and sees every server. [mcpjungle](https://github.com/mcpjungle/MCPJungle) is a
self-hosted example:

```bash
# 1. Run the gateway (exposes its own MCP endpoint, default http://localhost:8080/mcp)
curl -O https://raw.githubusercontent.com/mcpjungle/MCPJungle/main/docker-compose.yaml
docker compose up -d

# 2a. Register an atlas server running in streamable-http mode (compose up -d → :8000/mcp):
mcpjungle register --name netbox --url http://netbox-host:8000/mcp

# 2b. …or register a stdio (docker) server via a config file:
cat > netbox.json <<'JSON'
{
  "name": "netbox",
  "transport": "stdio",
  "command": "docker",
  "args": ["run", "-i", "--rm", "--env-file", "/opt/atlas/netbox.env", "netbox-mcp"]
}
JSON
mcpjungle register -c ./netbox.json
```

Clients then point at the **gateway URL** (`http://<gateway-host>:8080/mcp`) instead of each server.
For example, register the gateway with Claude Code:

```bash
claude mcp add --transport http atlas-gateway http://<gateway-host>:8080/mcp
```

### GitHub Copilot (VS Code, agent mode)

Add a workspace `.vscode/mcp.json` (the root key is `servers`). stdio or a gateway/HTTP URL:

```json
{
  "servers": {
    "netbox": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--env-file", "${workspaceFolder}/netbox.env", "netbox-mcp"]
    },
    "atlas-gateway": {
      "type": "http",
      "url": "http://gateway.example.com:8080/mcp"
    }
  }
}
```

Then open Copilot Chat → **Agent** mode → **Tools** and enable the server. (Requires VS Code 1.102+.)

### OpenAI (Responses API / Agents SDK)

OpenAI consumes **remote (HTTP) MCP servers only** — use streamable-http mode or a gateway URL:

```python
from openai import OpenAI
client = OpenAI()
resp = client.responses.create(
    model="gpt-4o",
    tools=[{
        "type": "mcp",
        "server_label": "atlas",
        "server_url": "http://gateway.example.com:8080/mcp",   # or a single server's /mcp URL
        "require_approval": "always",                          # writes should require approval
        # "headers": {"Authorization": "Bearer <gateway-token>"},
    }],
    input="List the NetBox devices at site 3.",
)
print(resp.output_text)
```

> Expose these only on trusted networks (or put auth on the gateway): they carry credentials to your
> infrastructure. Keep `*_ALLOW_WRITE` off — and `require_approval` on — unless you intend writes.

## House style

The servers share a deliberate, lightweight design so they read and operate the same way:

- **Read-only by default** — no write/remediation tools; add them only behind an explicit env flag.
- **Curated tools + a raw escape hatch** — high-value tools for the common questions, plus a raw
  `*_get` tool so anything the API exposes stays reachable.
- **Trimmed results** — responses are projected to the useful fields and row-capped; pass
  `full=true` for the raw payload.
- **Clean errors, not tracebacks**, and **secrets only from env vars**.
- Built on the official **MCP SDK (FastMCP)**, **Poetry** and **httpx**; **stdio** transport by
  default with an optional **streamable-http** mode; shipped as a slim, non-root **Docker** image.

## Adding a server

Copy [`_template/`](_template/) to a new `<name>-mcp/` folder and rename it. Pick a name (e.g.
`acme`), then:

1. `cp -r _template acme-mcp`, and rename the package dir `src/template_mcp/` → `src/acme_mcp/`.
2. Find/replace **case-sensitively** across the folder:
   - `template_mcp` → `acme_mcp` — Python package / imports
   - `template-mcp` → `acme-mcp` — script name, Docker image, FastMCP server name
   - `TEMPLATE_` → `ACME_` — env-var prefix
   - `template.env` → `acme.env` — local env file
3. Wire up `config.py` (required env vars), `client.py` (auth + error mapping) and `server.py`
   (replace the example tools; keep `api_get` as the raw escape hatch) for your API.
4. Update `tests/test_smoke.py` (`EXPECTED_TOOLS`) and the server's own `README.md`.
5. Add a row for the new server to the table above.

The [`_template/README.md`](_template/README.md) doubles as the per-server README skeleton — edit it
in place.

## License

MIT — see [LICENSE](LICENSE).
