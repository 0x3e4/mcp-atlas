# netscaler-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **NetScaler ADC** appliance (or HA pair) through the **NITRO REST API**. Ask about
your load balancers in natural language — vservers and their up/down state, backend services/servers,
SSL certificate expiry, HA status, and box CPU/memory/throughput — and roll out the **Web App
Firewall**: learned rules, the URL inventory, easy global rules, export/import between environments and
hostname switching.

- One shared `httpx.AsyncClient`; NITRO **session** login with a cached `NITRO_AUTH_TOKEN` cookie
  (transparently re-logs-in on expiry), or **stateless** `X-NITRO-USER`/`X-NITRO-PASS` per request.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default** — pair the server with a `readonlypolicy` account. The WAF write tools are
  **opt-in** behind `NETSCALER_ALLOW_WRITE`, and every one previews first (`dry_run=true`).
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
| `nitro_get(tree, resourcetype, name?, attrs?, filter?, args?, count?, pagesize?, pageno?)` | Escape hatch: raw read-only GET against any NITRO resource; `args` reaches resources with required lookup arguments (e.g. `appfwlearningdata`, `systemfile`). |

Results are trimmed to the useful columns by default; pass `full=true` for the raw NITRO objects, and
list results are capped (`NETSCALER_MAX_ROWS`, default 200) unless `full`.

### WAF rollout tools

Reads (always available):

| Tool | What it does |
|---|---|
| `list_waf_rules(profile, rule_type?, contains?, limit?)` | A profile's configured rules — relaxations and deny URLs — grouped by rule type. |
| `list_waf_learned_rules(profile, rule_type="all", contains?, min_hits?, limit?)` | What the learning engine recorded: hits, the raw entry, the rule it would deploy as; start URLs also get prefix-rule suggestions. |
| `list_waf_urls(profile, host?, include_learned?, limit?)` | URL inventory: hosts, allowed / denied / referenced URLs, learned URLs marked **covered** or not, and suggested global rules for the uncovered ones. |
| `export_waf_profile(profile, host_map?, save_as?)` | Settings, learning thresholds and every rule as a portable JSON document (optionally with hostnames switched, or saved to a file). |

Writes (opt-in — refuse unless `NETSCALER_ALLOW_WRITE=true`; all preview with `dry_run=true` by default):

| Tool | What it does |
|---|---|
| `add_waf_rule(profile, rule, host?, path?, match?, scheme?, extensions?, field?, …, dry_run)` | Easy rules without hand-written regex: `allow_url`, `allow_static`, `deny_url`, `allow_sql_field`, `allow_xss_field`, `allow_cmd_field`, `allow_field_consistency`, `allow_cookie`, `allow_csrf`, `allow_content_type`, `trusted_learning_client`, or `raw`. `host='*'` makes a rule global across environments; comma-separate profiles to add it to several. |
| `remove_waf_rule(profile, rule_type, rule, all_matches?, dry_run)` | Unbind a rule (pass a row from `list_waf_rules`). |
| `deploy_waf_learned_rules(profile, rule_type, contains?, min_hits?, remove_learned?, limit?, dry_run)` | Turn learned entries into rules — skipping ones that exist or that a start URL rule already covers — and clear them from learning. |
| `discard_waf_learned_rules(profile, rule_type, contains?, max_hits?, all_entries?, limit?, dry_run)` | Drop learned noise (scanners, attack attempts) so it never becomes a rule. |
| `set_waf_check_actions(profile, checks, set_actions?, add_actions?, remove_actions?, dry_run)` | The learn → block switch, per check or `['all']`, with before/after. |
| `import_waf_profile(document \| file, target_profile?, host_map?, mode?, include_settings?, dry_run)` | Apply an export to a profile (created if missing): `merge` adds missing rules, `replace` mirrors the document. |
| `rehost_waf_profile(profile, from_host, to_host, target_profile?, dry_run)` | Switch every rule to another hostname, in place or into a copy for another environment. |
| `save_config()` | `save ns config` — persist applied changes. |

## 1. Create a read-only account

On the appliance, create a system user and bind the built-in **`readonlypolicy`** command policy —
that grants `show`/`stat`/GET-only access, which is all the read tools need.

```
add system user nsmcp <password>
bind system user nsmcp readonlypolicy 100
```

(Or in the GUI: **System → User Administration → Users → Add**, then bind the `readonlypolicy`
command policy.) Use this account's credentials below. For the WAF write tools, use the account from
[WAF rollout → Enable writes](#enable-writes) instead.

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
- **WAF writes / files** — `NETSCALER_ALLOW_WRITE=true` enables the WAF write tools;
  `NETSCALER_EXPORT_DIR` lets export/import use files. See [WAF rollout](#waf-rollout-optional-write-tools).

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
- "Which learned start URLs on WAF profile pr_app aren't covered by a rule yet?"

## WAF rollout (optional write tools)

### Enable writes

1. Set `NETSCALER_ALLOW_WRITE=true` in `netscaler.env`. With it unset the write tools still
   **preview** (`dry_run=true`) but refuse to apply.
2. Use a system user that may change AppFw profiles. A least-privilege command policy covering exactly
   what the tools send (adjust to your change control):

   ```
   add system cmdPolicy nsmcp-waf ALLOW "^((add|set|bind|unbind)\s+appfw\s+profile|set\s+appfw\s+learningsettings|rm\s+appfw\s+learningdata)(\s+.*)?$|^save\s+ns\s+config$"
   add system user nsmcp-waf <password>
   bind system user nsmcp-waf nsmcp-waf 100
   bind system user nsmcp-waf readonlypolicy 110
   ```

   Consider a separate `netscaler-waf` MCP registration (its own env file) so day-to-day
   questions keep using the read-only account.

### Export files (optional)

Documents are always passed inline. To also save/load files, set `NETSCALER_EXPORT_DIR` and mount a
directory writable by the container user (uid 10001):

```bash
mkdir waf-exports && sudo chown 10001 waf-exports
docker run -i --rm --env-file ./netscaler.env \
  -e NETSCALER_EXPORT_DIR=/exports -v "$PWD/waf-exports:/exports" netscaler-mcp
```

For compose, uncomment the `volumes:` block in [`compose.yml.example`](compose.yml.example). File names
are bare (`pr_app-test.json`) — no paths.

### A typical rollout

1. **Learn.** The profile's checks run `learn,log,stats` while real traffic flows. To learn only from
   testers: "add a trusted learning client 10.1.2.0/24 to pr_app".
2. **See the URLs.** "Show the URL inventory for pr_app" → `list_waf_urls` lists every allowed and
   learned URL and groups the uncovered ones into suggested prefix rules.
3. **Add global easy rules.** "Allow everything under /portal/ on any host, and static assets, for
   pr_app — preview first" → `add_waf_rule(rule='allow_url', host='*', path='/portal/')`,
   `add_waf_rule(rule='allow_static', host='*', scheme='any')`. Global (`host='*'`) rules need no
   hostname switching later.
4. **Deal with what's left.** `discard_waf_learned_rules` for noise (e.g. `contains='wp-login'`), then
   `deploy_waf_learned_rules` for the real entries (URLs a prefix rule already covers are just cleared).
5. **Go live.** "Switch pr_app to block: add block, remove learn on all checks" →
   `set_waf_check_actions(checks=['all'], add_actions=['block'], remove_actions=['learn'])`, watch the
   logs, then `save_config`.
6. **Other environments.** `export_waf_profile(profile='pr_app', save_as='pr_app-test.json')` (keep it in
   git as the app's baseline), then
   `import_waf_profile(file='pr_app-test.json', target_profile='pr_app_prod', host_map={'app.test.corp': 'app.corp'})`.
   Or directly on one appliance: `rehost_waf_profile(profile='pr_app', from_host='app.test.corp',
   to_host='app.corp', target_profile='pr_app_prod')`.

Every write call answers first with a plan; say "apply it" to re-run with `dry_run=false`.

### Behaviour & caveats

- **Live immediately, persistent only after `save_config`.** Point `NETSCALER_BASE_URL` at the HA
  primary / management VIP.
- **Traffic-safe order.** Import and rehost bind new rules first, then re-bind changed ones, and remove
  old ones last. In place, a rehost never leaves a legitimate URL without its rule mid-change.
- **`merge` vs `replace`.** `merge` only adds; `replace` also re-binds changed rules and removes rules
  missing from the document. `include_settings` defaults to "only when the profile is created", so an
  existing prod profile keeps its own block/learn actions unless you ask.
- **Hostname switching** rewrites whole-host matches in literal (`app.test.corp`) and regex-escaped
  (`app\.test\.corp`) form. Ports are kept unless part of the mapping. It covers every rule URL,
  URL-bearing settings (e.g. the error URL) and comments. `host='*'` rules are untouched.
- **Learned-data mapping — check the preview.** NITRO documents learned entries only as generic
  `url` / `name` / `value_type` / `value` fields. The mapping onto bindings follows the 14.1 NITRO
  reference, including CSRF's inverted `csrftag` naming, but it hasn't been verified against every
  build. Look at each `rule` in the dry run before deploying. Learned SQL/XSS entries carry no scan
  location, so they deploy as `FORMFIELD` (the appliance default).
- **`covered`** uses Python's regex engine as an approximation of the appliance's PCRE.
- **Not everything is modelled.** Binding types such as log expressions, deny/bypass lists and
  gRPC/REST validation are exported under `other_bindings` for reference but not imported. Use
  `nitro_get` / the GUI for those. The profile must still be bound to an AppFw policy to take effect.
- NetScaler's native `restore appfw profile … -matchURLString/-replaceURLString` needs a tar archive
  created on the appliance. These tools do the same job purely over NITRO, with a reviewable JSON
  document.

## Development

```bash
poetry install
poetry run pytest -q                            # smoke + WAF flow tests (no network, no credentials)
poetry run mcp dev src/netscaler_mcp/server.py  # MCP Inspector to exercise tools
```

## Notes & scope

- **Compatibility.** Built and field-tuned against **NetScaler ADC 14.1**. The NITRO API and the
  attributes used here are stable across 13.0 / 13.1 / 14.1, so older builds work too — if a build
  lacks a projected attribute it simply comes back `null`; use `full=true` or `nitro_get` for the raw
  payload. (NITRO is served under a fixed `/nitro/v1` path — there is no api-version parameter.)
- **Writes are opt-in and WAF-only.** Reads are always available. The WAF write tools refuse unless
  `NETSCALER_ALLOW_WRITE=true` and the account's command policy allows the change. No tool deletes
  profiles, and no other configuration is touched.
- **Feature-gated resources** (GSLB, AppFW) return a clean "feature not enabled" error when the
  feature is off on the appliance.
- The whole-config resources `nsrunningconfig` / `nssavedconfig` are reachable via `nitro_get` but
  return very large payloads — prefer a targeted resource.
- The stat `Interface` resource is **capitalized** — query it via `nitro_get("stat", "Interface")`.
- **Resources with required lookup arguments** (`appfwlearningdata` needs `profilename` +
  `securitycheck`, `systemfile` needs `filelocation`) only answer to `?args=`, not `name` or
  `filter`: `nitro_get("config", "appfwlearningdata", args="profilename:pr_app,securitycheck:startURL")`
  sends `…/config/appfwlearningdata?args=profilename:pr_app,securitycheck:startURL`.
