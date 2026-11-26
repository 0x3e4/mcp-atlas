# mcp-atlas

A collection of complete, drop-in [MCP](https://modelcontextprotocol.io) servers that connect AI
agents to security and ops systems — any MCP client: [Claude Code](https://docs.claude.com/en/docs/claude-code),
VS Code / Copilot, an MCP gateway such as [mcpjungle](https://github.com/mcpjungle/MCPJungle), OpenAI, or
your own model on Ollama, vLLM or LM Studio (see [Using with other clients & gateways](#using-with-other-clients--gateways)). Each server is **self-contained** — its own source, tests, Dockerfile and README — and is
**read-only** by default: ask about your data in natural language, nothing writes back unless you
switch on its write tools (see [Write tools & confirmation](#write-tools--confirmation)).

## Servers

| Server | Version | What it does |
|--------|---------|--------------|
| [defender-mcp](defender-mcp/) | [1.3.0](defender-mcp/CHANGELOG.md) | Query **Microsoft Defender XDR** via the Microsoft Graph security API — advanced hunting (KQL), incidents, alerts, devices and vulnerabilities, plus raw `graph_get` / `graph_hunt` escape hatches. Case management (Graph beta). Optional **write** tools (update incidents/alerts/cases, comments, case tasks) behind `DEFENDER_ALLOW_WRITE`; can act as the signed-in analyst (`DEFENDER_AUTH=delegated`). |
| [wazuh-mcp](wazuh-mcp/) | [1.3.0](wazuh-mcp/CHANGELOG.md) | Query a **Wazuh** deployment — alerts, the full event **archive** (every collected event, not just rule hits), vulnerabilities, agents, inventory, rules, SCA and manager status, across the Indexer and Manager APIs. Optional **write** tools (restart agents, assign/unassign agent groups, run active response) behind `WAZUH_ALLOW_WRITE`. |
| [netscaler-mcp](netscaler-mcp/) | [1.4.0](netscaler-mcp/CHANGELOG.md) | Query one or more **NetScaler ADC** appliances (or HA pairs) over the **NITRO REST API** — LB/CS/GSLB vservers + state, services and servers, SSL cert expiry, **GSLB** services/sites, **DNS** records/zones/nameservers, **WAF (AppFw)** and **Bot** profiles/policies + hit stats, HA status, and box CPU/memory/throughput, a per-object view with everything bound to it (e.g. a CS vserver's policies in priority order with their targets), a CS → LB → backend diagnosis, plus a raw `nitro_get` escape hatch. Several appliances that don't sync (standalone boxes, GSLB peers) can sit behind one server (`NETSCALER_INSTANCES`): every tool takes `instance`, reads also take `'all'`, and `compare_instances` diffs their GSLB (or any) configuration. **WAF and Bot rollout** tools cover learned rules, a URL inventory, per-check violation counters, bot detections and entries, signature currency, the enforcement path (which policy applies a profile) and the recent violation log lines, plus JSON export/import of profiles. Optional **write** tools (create/change/enable/disable/delete LB and CS vservers, services, service groups, servers, CS policies/actions, monitors, SSL certificates (upload to `/nsconfig/ssl`), profiles and SNI bindings, rewrite/responder policies, pattern sets, GSLB and DNS records and bind them together; clone an app for a new hostname; one batch on several appliances with one confirmation; easy global WAF rules, deploy learned rules, learn→block, bot allow/deny lists and rate limits, signature re-fetch, import/rehost profiles across environments) sit behind `NETSCALER_ALLOW_WRITE`. |
| [netscaler-console-mcp](netscaler-console-mcp/) | [1.5.0](netscaler-console-mcp/CHANGELOG.md) | Analyse and troubleshoot every NetScaler through **NetScaler Console** (formerly ADM, on-prem or service) — instances and their health, applications with health score / response time / errors, performance reports, events, collected syslog, SSL expiry, config audit (unsaved changes, drift), config jobs, licensing; **WAF**: Security Insight violations, single blocked requests parsed from the APPFW syslog, learned relaxation rules, per-profile check counters; per-ADC live diagnosis through the Console's API proxy (`vserver_diagnose`: what is DOWN behind a vserver, running config by app). Optional **write** tools (clear events, re-poll inventories) behind `NETSCALER_CONSOLE_ALLOW_WRITE`; enabling / disabling services, members and vservers behind `NETSCALER_CONSOLE_ALLOW_INSTANCE_WRITE`. |
| [fortigate-mcp](fortigate-mcp/) | [1.4.0](fortigate-mcp/CHANGELOG.md) | Query a **FortiGate** firewall over the **FortiOS REST API** — firewall policies (with live hit counters and policy lookup), objects across 30 config tables, VIPs, interfaces, routing, IPsec / SSL-VPN, SD-WAN health, sessions, logs, the config as CLI text, HA and system/license health, plus a raw `fortios_get` escape hatch. Optional **write** tools (objects and policies: create, change, place) behind `FORTIGATE_ALLOW_WRITE`; deletes behind `FORTIGATE_ALLOW_DELETE`, IP bans behind `FORTIGATE_ALLOW_USER_ACTIONS`. |
| [audiocodes-sbc-mcp](audiocodes-sbc-mcp/) | [1.3.0](audiocodes-sbc-mcp/CHANGELOG.md) | Query an **AudioCodes Mediant SBC** over its device REST API — status and HA, active / historic alarms, call statistics and other KPIs, the configuration as CLI script or INI (secrets masked, filterable), live CLI `show` output, TLS certificates with expiry, the license, SIP test calls, plus a raw `sbc_get` escape hatch. Optional **write** tools (incremental CLI / INI configuration changes, save, test calls, SIP recording, CSRs) behind `AUDIOCODES_ALLOW_WRITE`; reset / configuration replace / firmware, TLS identity changes and license installs each need a switch of their own. |
| [azure-devops-mcp](azure-devops-mcp/) | [1.5.0](azure-devops-mcp/CHANGELOG.md) | Query an on-prem **Azure DevOps Server** (formerly TFS) over its REST API — projects, teams, Git repos (files, commits, diffs, branches, tags), pull requests (threads, files, votes), work items (WIQL, links, history, sprints), builds with failed-task logs, releases, the wiki and search, plus a raw `azdo_get` escape hatch. Optional **write** tools behind `AZDO_ALLOW_WRITE` (work items of any type with links and attachments, wiki pages, pull requests, branches); pushes, merges, votes, pipelines, releases and deletes each need a switch of their own. |
| [bookstack-mcp](bookstack-mcp/) | [1.3.0](bookstack-mcp/CHANGELOG.md) | Query a **BookStack** wiki over its REST API — browse the shelves/books/chapters/pages hierarchy, read and search page content, read attachments (PDF, mails, text, images) and gallery images, and export pages/books to markdown, plus a raw `bookstack_get` escape hatch. Optional **write** tools (create/update pages, chapters, books and shelves, comment on pages, attach files and links, upload images onto pages, draw.io drawings rendered and placed on pages) behind `BOOKSTACK_ALLOW_WRITE`. |
| [prtg-mcp](prtg-mcp/) | [1.3.0](prtg-mcp/CHANGELOG.md) | Query a **PRTG Network Monitor** (Paessler) server over its HTTP API — sensors/devices/groups/probes and their up/down state, sensor channels and details, the event log, core/system health, and historic data, plus a raw `prtg_get` escape hatch. Optional **write** tools (pause/resume, acknowledge alarms, scan now, rename/edit objects, channel limits, clone/move/add devices and groups, auto-discovery) behind `PRTG_ALLOW_WRITE`. |
| [zammad-mcp](zammad-mcp/) | [1.3.0](zammad-mcp/CHANGELOG.md) | Query a **Zammad** helpdesk over its REST API — browse/search tickets, read the conversation (articles) incl. screenshots, PDFs, .eml/.msg mails and text attachments, look up users/organizations and reference data, plus a raw `zammad_get` escape hatch. Optional **write** tools (add note/comment, reply by email to the customer or to all, update/create/tag tickets) behind `ZAMMAD_ALLOW_WRITE`. |
| [snipeit-mcp](snipeit-mcp/) | [1.3.0](snipeit-mcp/CHANGELOG.md) | Query a **Snipe-IT** asset-management instance over its REST API — assets (by tag/serial), who has what, and the model/category/location/license/accessory catalogs, plus a raw `snipeit_get` escape hatch. Optional **write** tools (check out/in, update, create, audit assets) behind `SNIPEIT_ALLOW_WRITE`. |
| [netbox-mcp](netbox-mcp/) | [1.3.0](netbox-mcp/CHANGELOG.md) | Query a **NetBox** DCIM/IPAM source of truth over its REST API — devices and interfaces, IP addresses and prefixes, virtual machines, and the site/rack/VLAN/VRF/cluster/tenant catalogs, plus a raw `netbox_get` escape hatch. Optional **write** tools (create/update IP addresses, assign the next free IP, update devices, add journal entries) behind `NETBOX_ALLOW_WRITE`. |
| [atlas-hub-mcp](atlas-hub-mcp/) | [1.0.0](atlas-hub-mcp/CHANGELOG.md) | **For local models only:** one small server in front of the others (or a gateway) that gives the model five tools instead of hundreds — `search_tools` across all servers, `describe_tool`, `call_read_tool`, `call_write_tool` — so tool definitions no longer eat the context. Keyword search, optional semantic search via an embeddings endpoint; reads and writes stay apart and every write keeps its confirmation. Claude Code and the Claude API search tools on their own and don't need it. |
| [vcenter-mcp](vcenter-mcp/) | [1.3.0](vcenter-mcp/CHANGELOG.md) | Query a **VMware vCenter** server over the vSphere Automation REST API — VMs and power state, hosts, clusters, datastores, networks, resource pools, and appliance version/health, plus a raw `vcenter_get` escape hatch. Optional **write** tools (VM guest shutdown/reboot, hard power actions) behind `VCENTER_ALLOW_WRITE`. |

## Using a server

Each folder is independent: open its README and follow the install steps. The common shape:

```bash
cd <server>-mcp
cp .env.example <server>.env          # fill in URLs / credentials
docker build -t <server>-mcp .
claude mcp add <server> -- docker run -i --rm --env-file ./<server>.env <server>-mcp
```

Then run `/mcp` in Claude Code to confirm the server connected, and ask away. Every server also
supports an always-on `streamable-http` mode via `docker compose up -d` (see each README), which is
what gateways, chat UIs and your own LLM connect to — see
[Using with other clients & gateways](#using-with-other-clients--gateways).

## Write tools & confirmation

Every server has a small set of **opt-in write tools**, configured per server in its env file:

| Variable | Default | Effect |
|---|---|---|
| `<PREFIX>_ALLOW_WRITE` | `false` | Write tools refuse with a clear message until this is `true`. They are always listed, so the agent knows they exist. |
| `<PREFIX>_CONFIRM_WRITE` | `true` | Every write asks first: the tool's first call changes nothing and returns a preview with a `confirm_code`. The agent shows you a short overview of what will happen and asks *"Confirm it?"*; only after you say yes does it repeat the call with `confirm=<code>`. Set `false` to let writes run directly. |

The confirm code is enforced by the server, not just requested from the agent: it is bound to the
exact tool and arguments it was issued for, so the change that runs is the one you confirmed, and a
changed request needs a fresh confirmation (codes also expire when the server restarts). The
credential still needs write rights upstream — each README lists them. Only three servers can delete,
each behind its own switch on top of the write switch: netscaler-mcp (traffic-management objects: LB,
CS, SSL, rewrite / responder, GSLB, DNS; `NETSCALER_ALLOW_DELETE`), fortigate-mcp (config objects
and policies; `FORTIGATE_ALLOW_DELETE`) and azure-devops-mcp (work items, wiki pages, branches;
`AZDO_ALLOW_DELETE`). A delete always asks for confirmation, even with
`<PREFIX>_CONFIRM_WRITE=false`, and the switch is per instance, so it can be on for one user only.
azure-devops-mcp gates its other sensitive writes the same way — pushes, PR merges and policy
bypasses, PR votes, pipelines and releases each have a switch of their own (see its README) — and so
do fortigate-mcp (IP bans, `FORTIGATE_ALLOW_USER_ACTIONS`) and audiocodes-sbc-mcp (resets /
configuration replace / firmware, TLS, licenses).
Run a read-only and a write-enabled instance side by side if you want both (see below).

## Using with other clients & gateways

The servers are not tied to Claude: each speaks plain MCP over two transports, so it works with any
MCP client — desktop agents, gateways, chat UIs, OpenAI, or your own model:

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

Good to know behind a gateway:

- **Tool names are namespaced** by the gateway (mcpjungle: `<server>__<tool>`, e.g.
  `netbox__list_devices`), so several servers with similar tools don't clash.
- **Expose subsets.** Give each audience (or each local model) only the servers / tools it needs, e.g.
  with the gateway's tool groups or by registering a read-only instance only.
- **Confirm codes pass through unchanged**: a write still returns its preview and only runs when the
  client repeats it with `confirm=<code>`.
- **Protect the gateway** (its auth / an internal network): it holds the way into every system.

### Several instances of one server

One image can run as several containers, each with its own env file: for example a shared
read-only BookStack next to a write-enabled one with another token, or one FortiGate server per
firewall. Give each container its own `container_name` and register each one with the gateway under
its own name. Every server README has a ready-to-copy compose example (*Multiple instances*, under
*Always-on HTTP*).

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

### Your own LLM (Ollama, vLLM, LM Studio, llama.cpp …)

A model server only generates text; it needs an **MCP client** in between that lists the tools, hands
them to the model as function definitions, runs the calls and feeds the results back. Three ways:

**1. The bridge script in this repo** — [`examples/llm_bridge.py`](examples/llm_bridge.py) connects any
OpenAI-compatible endpoint to one server or the gateway, as an interactive chat. It only lets a write
through with its confirm code after *you* said yes in the chat, so a model can't confirm its own writes.

```bash
pip install "mcp>=2.3,<3" httpx

# Ollama: a tool-capable model (qwen2.5, llama3.1, mistral-nemo …) and enough context for tool lists
OLLAMA_CONTEXT_LENGTH=32768 ollama serve &
ollama pull qwen2.5:14b
python examples/llm_bridge.py --mcp http://gateway.example.com:8080/mcp \
    --llm http://localhost:11434/v1 --model qwen2.5:14b

# vLLM: tool calling must be switched on, with the parser that fits the model
vllm serve Qwen/Qwen2.5-32B-Instruct --enable-auto-tool-choice --tool-call-parser hermes
#   (Llama 3.1/3.3: --tool-call-parser llama3_json; Mistral: --tool-call-parser mistral)
python examples/llm_bridge.py --mcp http://netbox-mcp:8000/mcp \
    --llm http://vllm-host:8000/v1 --model Qwen/Qwen2.5-32B-Instruct

# one server over stdio, only a few tools, see what the model gets
python examples/llm_bridge.py --stdio "docker run -i --rm --env-file ./netbox.env netbox-mcp" \
    --only list_devices,get_device --list-tools
```

`--mcp-token` sends a bearer token to a protected gateway; `--api-key` one to the model server.

**2. A chat UI with MCP support.** Point it at a server's or the gateway's `/mcp` URL (streamable
HTTP). Examples:

- **Open WebUI**: add the URL under *Settings → Tools* (newer releases speak MCP directly), or put
  [mcpo](https://github.com/open-webui/mcpo) in front, which turns MCP tools into an OpenAPI tool
  server: `uvx mcpo --port 8001 --server-type streamable-http -- http://gateway.example.com:8080/mcp`.
- **LibreChat** (`librechat.yaml`):

  ```yaml
  mcpServers:
    atlas:
      type: streamable-http
      url: http://gateway.example.com:8080/mcp
  ```

**3. Your own code.** The official MCP SDKs (Python, TypeScript, …) give you `list_tools` / `call_tool`.
The bridge script (about 150 lines) shows the whole loop.

Tips for local models:

- **Fewer tools work better.** A gateway with every server exposes hundreds of tools (all servers
  together: ~354 tools, ~116k tokens), too many for most local models. In this order:
  1. Offer only what you need (`--only`, `MCP_TOOLS`, one server per chat, or a gateway tool group).
  2. `MCP_COMPACT_TOOLS=true` on the servers: the first paragraph of each description and compact schemas,
     about 35 % fewer tokens (116k → 76k for all servers, netscaler-mcp 32k → 20k).
  3. [atlas-hub-mcp](atlas-hub-mcp/) in front: the model sees five tools (~1k tokens), searches for the
     one it needs and calls it through the hub. This is only for local models and clients that attach
     every tool to every request; Claude Code and the Claude API already load tools on demand.
- **Use tool-trained models** and enough context: tool definitions alone can take 10–30k tokens. Raise
  Ollama's default context (`OLLAMA_CONTEXT_LENGTH`, or `num_ctx` in a Modelfile).
- **Keep writes behind confirmation.** Leave `<PREFIX>_CONFIRM_WRITE` on and the sensitive switches
  off for instances a local model uses.

> Expose these only on trusted networks (or put auth on the gateway): they carry credentials to your
> infrastructure. Keep `*_ALLOW_WRITE` off — and `require_approval` on — unless you intend writes.

## Security

A server cannot stop a model from being talked into something by text it reads (prompt injection:
a ticket, wiki page, log line or PR comment that says "ignore your instructions and …"). So every server
is built to **contain** it: as little power as needed, a human confirmation the model can't fake, foreign
text marked as such, and a record of every write. All of this lives in one shared module,
[`_shared/atlas_guard.py`](_shared/atlas_guard.py). Every server carries an identical copy
(`src/<package>/_atlas_guard.py`, kept in sync by `scripts/sync_shared.py`, checked in CI). It wraps every
tool and is configured with the same `MCP_*` variables everywhere:

| Variable | Default | Effect |
|---|---|---|
| `MCP_CONFIRM_MODE` | `auto` | How writes are confirmed. The user confirms in the **client's own dialog** (MCP elicitation), and the server then runs exactly the previewed change; the model never sees or relays a confirm code. `auto`: the dialog when the client offers it, else the confirm-code fallback. `elicit`: only through the dialog (clients without it can't write). `elicit-destructive`: deletes, resets, merges, deploys only through the dialog. `code`: always the code flow. |
| `MCP_AUTH_TOKEN` / `MCP_AUTH_TOKEN_FILE` | – | HTTP mode: clients / the gateway must send `Authorization: Bearer <token>` (401 otherwise). Use a different token per instance. |
| `<VAR>_FILE` | – | Read a credential from a file instead of the environment (Docker / Kubernetes secrets): `NETSCALER_PASSWORD_FILE=/run/secrets/ns_password` fills `NETSCALER_PASSWORD`. Works for every password, secret, token, API key, user and client-id variable of every server (per instance too, e.g. `NETSCALER_PROD_PASSWORD_FILE`). The password is then neither in the env file nor in `docker inspect`. A trailing newline is dropped; a missing or empty file, or both variables set differently, stops the server. |
| `MCP_ALLOWED_HOSTS` | – | HTTP mode: allowed `Host` headers (DNS-rebinding protection, 421 otherwise), e.g. `netbox-mcp:8000,localhost:*`. The compose examples set it to the container name. `MCP_ALLOWED_ORIGINS` overrides the derived origins. |
| `MCP_TOOLS` / `MCP_DISABLED_TOOLS` | – | Offer only matching tools / hide matching tools (glob patterns), e.g. `MCP_TOOLS=list_*,get_*`. |
| `MCP_WRITE_LIMIT` | `30` | Max executed writes per minute (`0` = no limit). Brakes loops and mass changes. |
| `MCP_SECRET_SCAN` | `true` | Refuse writes whose arguments carry private keys, cloud / API tokens, JWTs or the server's own credentials. Comments, tickets, wiki pages and mails are ideal exfiltration channels. |
| `MCP_MARK_UNTRUSTED` | `true` | Text other people can write is wrapped in `<untrusted>…</untrusted>`; invisible, bidi and Unicode-tag characters are removed from every result; HTML comments are dropped from marked text. |
| `MCP_COMPACT_TOOLS` | `false` | Smaller tool list: the first paragraph of each description, no schema titles, plain optional types, short `confirm` / `dry_run` help (about −35 % tokens). Meant for local models and gateways that pass every tool on; parameter descriptions with their valid values stay whole. |
| `MCP_DESCRIBE_UNTRUSTED` | `true` | The same warning in every read tool's description, not only in the server instructions — gateways such as mcpjungle pass descriptions on but drop instructions. |
| `MCP_AUDIT_STDERR` | `true` | Audit log of every write (preview, confirmed, executed, declined, refused, failed) as JSON lines on stderr, i.e. `docker logs`. |
| `MCP_AUDIT_GELF` | – | The same events as GELF to Graylog: `udp://graylog:12201` or `tcp://graylog:12201`. |
| `MCP_AUDIT_SYSLOG` | – | The same events as RFC 5424 syslog (JSON message, facility *log audit*), readable by any SIEM (Wazuh, Splunk, Elastic, rsyslog …): `udp://host:514`, `tcp://host:514` (RFC 6587 octet counting) or `tls://host:6514` (RFC 5425). |
| `MCP_AUDIT_INSTANCE` / `MCP_AUDIT_READS` | host name / `false` | Label of this instance (e.g. the user) in every event; also log every read. |

Credentials as Docker secrets instead of env values (compose):

```yaml
services:
  netscaler-mcp:
    env_file: ./netscaler.env            # no NETSCALER_PASSWORD in here
    environment:
      NETSCALER_PASSWORD_FILE: /run/secrets/ns_password
    secrets: [ns_password]
secrets:
  ns_password:
    file: ./secrets/ns_password          # chmod 600, not in git
```

Use a dedicated API account per server with only the rights it needs (read-only for read instances), ideally from LDAP / RADIUS / TACACS so it is rotated and disabled centrally.

Also built in:

- **Tool annotations** on every tool (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`),
  so clients and gateways can auto-allow reads and always ask before destructive tools.
- **Readable errors, no leaks**: the reason of an anticipated failure (bad argument, the upstream API's
  own error) reaches the model; a crash shows only the SDK's generic message, with the traceback in the
  server log. The server's own credentials are masked in every message and every result.
- **Containers**: the compose examples run with a read-only root file system, no Linux capabilities, no
  privilege escalation, `/tmp` as tmpfs and memory / CPU limits; the base image is pinned by digest.
  Limit each container's outbound traffic to its one target system (firewall / Docker network) where
  you can.
- **Supply chain**: CI checks the guard copies, the locks against OSV, and runs every server's tests from
  its `poetry.lock` before it builds; images get an SBOM and build provenance and are signed with cosign
  (keyless). Verify a signature:

  ```bash
  cosign verify ghcr.io/0x3e4/netbox-mcp:<version> \
    --certificate-identity-regexp 'https://github.com/0x3e4/mcp-atlas/.github/workflows/build.yml@.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

### On the client side

- **Claude Code**: keep reads quiet and writes visible. Register a read-only instance and a write instance
  separately; allow the read-only one entirely and leave the write one on "ask"
  (`.claude/settings.json`):

  ```json
  {
    "permissions": {
      "allow": ["mcp__netbox"],
      "ask": ["mcp__netbox-write"]
    }
  }
  ```

- **Gateways** (mcpjungle …): put auth on the gateway, give the gateway each instance's
  `MCP_AUTH_TOKEN`, and expose write instances only to the people who need them. The gateway does not
  pass the end user's identity on, so per-user rights are per instance (env file).
- **Your own LLM**: `examples/llm_bridge.py` refuses confirm codes the user did not approve; with a
  client that supports elicitation, the dialog makes that unnecessary.
- **Local models** follow injected text more readily: give them read-only instances or a small tool set
  (`MCP_TOOLS`), and keep `MCP_CONFIRM_MODE` at `elicit` for any instance that can write.

## House style

The servers share a deliberate, lightweight design so they read and operate the same way:

- **Read-only by default** — write tools only behind `<PREFIX>_ALLOW_WRITE`, each confirmed by the
  user first (`<PREFIX>_CONFIRM_WRITE`); no delete tools, except the opt-in deletes of
  netscaler-mcp (`NETSCALER_ALLOW_DELETE`), fortigate-mcp (`FORTIGATE_ALLOW_DELETE`) and
  azure-devops-mcp (`AZDO_ALLOW_DELETE`), always confirmed.
- **Curated tools + a raw escape hatch** — high-value tools for the common questions, plus a raw
  `*_get` tool so anything the API exposes stays reachable.
- **Trimmed results** — responses are projected to the useful fields and row-capped; pass
  `full=true` for the raw payload.
- **Clean errors, not tracebacks**, and **secrets only from env vars**.
- **One shared guard** ([`_shared/atlas_guard.py`](_shared/atlas_guard.py), see [Security](#security)) wraps every tool:
  confirmation in the client's dialog, annotations, untrusted-text marking, secret masking and scanning,
  write budget, audit log.
- Built on the official **MCP SDK** (2.x, `MCPServer`), **Poetry** and **httpx**; **stdio** transport by
  default with an optional **streamable-http** mode; shipped as a slim, non-root **Docker** image.

## Versioning

Each server has its own version, following [Semantic Versioning](https://semver.org). All servers
started at **1.0.0** on 2026-11-05.

- **MAJOR**: a tool is removed or renamed, a parameter is removed or changes meaning, or an env var
  changes incompatibly. Existing prompts, gateway configs or env files may break.
- **MINOR**: new tools, new optional parameters or new env vars. Existing setups keep working.
- **PATCH**: fixes, dependency and security updates, doc changes.

The [server table](#servers) shows each server's current version, linked to its changelog. `python scripts/sync_readme_versions.py` fills it in from the `pyproject.toml` files, and CI fails when it is out of date.

The version lives in two places that must match: `version` in the server's `pyproject.toml` and
`__version__` in `src/<package>/__init__.py`. A smoke test checks that they agree. Clients see the
version as `serverInfo.version` in the MCP handshake.

CI tags every image `:latest`, `:<git sha>` and `:<version>`. Until the version is bumped,
`:<version>` follows the newest build of that version. Bump it in the same commit as the change, then
pin `image: ghcr.io/<owner>/<server>:<version>` in `compose.yml` where you don't want `:latest`.

Every server has a `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)). Every
change gets an entry under the new version in the same commit, and the server's README and
`.env.example` are updated along with the code.

### Dependency updates

Updates are manual (`poetry update` per server, then rebuild) and checked as a whole each time: every
locked package (direct and transitive), the Poetry version in the Dockerfiles, and the GitHub Actions
in CI, the base image digest in the Dockerfiles, plus an OSV check for known vulnerabilities (`python scripts/osv_check.py`, also run in CI). **A new release is adopted only once it is at least
7 days old**, so a compromised or broken release has time to be spotted and yanked first; this holds for
security fixes too. The CI actions are pinned to exact releases for the same reason.

## Adding a server

Copy [`_template/`](_template/) to a new `<name>-mcp/` folder and rename it. Pick a name (e.g.
`acme`), then:

1. `cp -r _template acme-mcp`, and rename the package dir `src/template_mcp/` → `src/acme_mcp/`.
2. Find/replace **case-sensitively** across the folder:
   - `template_mcp` → `acme_mcp` — Python package / imports
   - `template-mcp` → `acme-mcp` — script name, Docker image, MCP server name
   - `TEMPLATE_` → `ACME_` — env-var prefix
   - `template.env` → `acme.env` — local env file
3. Wire up `config.py` (required env vars), `client.py` (auth + error mapping) and `server.py`
   (replace the example tools; keep `api_get` as the raw escape hatch) for your API.
4. Keep the `harden(...)` call at the end of `server.py` (set `untrusted_keys` to the fields other people can write, `errors` to your client's error class) and run `python scripts/sync_shared.py`, which adds the guard and its test.
5. Update `tests/test_smoke.py` (`EXPECTED_TOOLS`) and the server's own `README.md`. Set the
   version (`pyproject.toml` + `__init__.py`) to `0.1.0` until the first release, then `1.0.0`, and
   keep the `CHANGELOG.md` the template brings along.
6. Add a row for the new server to the table above and run `python scripts/sync_readme_versions.py`.

The [`_template/README.md`](_template/README.md) doubles as the per-server README skeleton — edit it
in place.

## License

MIT — see [LICENSE](LICENSE).
