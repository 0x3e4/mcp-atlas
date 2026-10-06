# netscaler-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **NetScaler ADC** appliance (or HA pair) through the **NITRO REST API**. Ask about
your load balancers in natural language — vservers and their up/down state, backend services/servers,
SSL certificate expiry, HA status, and box CPU/memory/throughput — and roll out the **Web App
Firewall**: learned rules, the URL inventory, easy global rules, export/import between environments and
hostname switching. **Bot management** gets the same treatment — allow/deny lists, rate limiting, TPS,
CAPTCHA and IP reputation — and for both features: are the signatures current, which policy actually
applies a profile, and what do the log lines behind a block say.

- One shared `httpx.AsyncClient`; NITRO **session** login with a cached `NITRO_AUTH_TOKEN` cookie
  (transparently re-logs-in on expiry), or **stateless** `X-NITRO-USER`/`X-NITRO-PASS` per request.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default** — pair the server with a `readonlypolicy` account. The WAF and Bot write
  tools are **opt-in** behind `NETSCALER_ALLOW_WRITE`, and every one previews first (`dry_run=true`).
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

### Bot management tools

Reads (always available):

| Tool | What it does |
|---|---|
| `list_bot_rules(profile, rule_type?, contains?, limit?)` | A profile's entries per detection: allow/deny lists, rate limiting, TPS, CAPTCHA URLs, IP-reputation categories, log/KM expressions, trap URLs. |
| `list_bot_detections(profile?, full?)` | Per detection: is it on, what does it do, how many entries — plus the live counters split by outcome (log / drop / redirect / reset / captcha). |
| `export_bot_profile(profile, host_map?, save_as?)` | The profile's detection settings and every entry as a portable JSON document. |

Writes (opt-in — refuse unless `NETSCALER_ALLOW_WRITE=true`; all preview with `dry_run=true` by default):

| Tool | What it does |
|---|---|
| `add_bot_rule(profile, rule, value?, url?, actions?, …, dry_run)` | Presets: `allow_ip`, `allow_expression`, `block_ip`, `block_expression`, `rate_limit_url` / `_source_ip` / `_session` / `_geo`, `tps_source_ip` / `_url` / `_geo` / `_host`, `captcha`, `ip_reputation`, `trap_url`, `log_expression`, `km_expression`, or `raw`. IPs and CIDRs are classified for you (IPv4 / IPv6 / SUBNET / IPv6_SUBNET). |
| `remove_bot_rule(profile, rule_type, rule, all_matches?, dry_run)` | Unbind an entry (pass a row from `list_bot_rules`). |
| `set_bot_detections(profile, detections, enable?, actions?, signature?, dry_run)` | Switch detections on/off, set the profile-level actions (device fingerprint, trap, signature header checks, spoofed requests) and bind a signature object. |
| `import_bot_profile(document \| file, target_profile?, host_map?, mode?, include_settings?, dry_run)` | Apply an export to a profile (created if missing): `merge` adds, `replace` mirrors the document. |
| `rehost_bot_profile(profile, from_host, to_host, target_profile?, dry_run)` | Switch host-bearing entries to another hostname. |

### Signatures, enforcement and violations (both features)

| Tool | What it does |
|---|---|
| `waf_violations(profile?, include_zero?, full?)` | Per WAF check: violation and log counts (stat `appfwprofile` / `appfw`) — the readiness check before switching a check to block. |
| `list_enforcement(kind?, profile?, limit?)` | Which policies select a profile and where each is bound; flags policies bound nowhere and profiles no policy selects. |
| `list_signatures(kind?, full?)` | Signature objects (source URL, `encryptedversion`) plus the auto-update switch and the related appliance settings. |
| `update_signatures(kind, name, merge_default?, dry_run)` | **Write:** re-fetch a signature object from its configured source URL. |
| `recent_security_violations(feature?, contains?, loglevel?, limit?)` | Recent `APPFW_*` / `BOT_*` lines from `auditmessages`, with the check, profile, client IP and URL pulled out. |

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
  `NETSCALER_EXPORT_DIR` lets export/import use files. See
  [WAF & Bot rollout](#waf--bot-rollout-optional-write-tools).

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

#### Multiple instances (one image, several env files)

The same image runs as several containers side by side, each with its own env file —
for example the shared read-only instance next to a write-enabled one that uses another
account, or one container per appliance or HA pair.
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys):

```yaml
x-netscaler: &netscaler
  image: ghcr.io/0x3e4/netscaler-mcp:latest
  environment:
    MCP_TRANSPORT: streamable-http
    MCP_HOST: 0.0.0.0
    MCP_PORT: "8000"
  restart: unless-stopped
  networks: [atlas-net]

services:
  netscaler-mcp:                    # existing shared read-only instance
    <<: *netscaler
    container_name: netscaler-mcp
    env_file: ./netscaler.env

  netscaler-mcp-instance-a:         # write access with instance a's account
    <<: *netscaler
    container_name: netscaler-mcp-instance-a
    env_file: ./env/instance_a.env

networks:
  atlas-net:
    external: true
```

- `env/instance_a.env` is a complete env file of its own (`mkdir -p env && cp .env.example
  env/instance_a.env`) with instance a's account and `NETSCALER_ALLOW_WRITE=true`. The shared instance keeps
  the flag off. `*.env` is gitignored, so it stays local.
- Every container listens on port 8000 inside its own network namespace, so nothing clashes; the
  gateway reaches each one by its `container_name`. Register them under separate names:

  ```bash
  mcpjungle register --name netscaler --url http://netscaler-mcp:8000/mcp
  mcpjungle register --name netscaler-instance-a --url http://netscaler-mcp-instance-a:8000/mcp
  ```

- `<<:` merges shallowly: an instance that sets its own `environment:` replaces the anchor's whole
  block, so keep per-instance settings in its env file.
- Over stdio no compose is needed — register a second server with the other env file:
  `claude mcp add netscaler-instance-a -- docker run -i --rm --env-file ./env/instance_a.env netscaler-mcp`

## 4. Verify

In Claude Code, run `/mcp` to confirm the `netscaler` server connected, then ask things like:

- "Which LB vservers are DOWN?"
- "List SSL certificates expiring within 30 days."
- "What's the HA status?"
- "Show CPU and memory usage."
- "Show the live request rate for lb vserver vs_web."
- "Which learned start URLs on WAF profile pr_app aren't covered by a rule yet?"
- "Which WAF checks are firing on pr_app, and is anything already blocking?"
- "Is the WAF profile pr_app actually enforced anywhere, and are the signatures current?"
- "What is bot profile bot_app catching at the moment?"

## WAF & Bot rollout (optional write tools)

### Enable writes

1. Set `NETSCALER_ALLOW_WRITE=true` in `netscaler.env`. With it unset the write tools still
   **preview** (`dry_run=true`) but refuse to apply.
2. Use a system user that may change AppFw and Bot profiles. A least-privilege command policy covering
   exactly what the tools send (adjust to your change control):

   ```
   add system cmdPolicy nsmcp-waf ALLOW "^((add|set|bind|unbind)\s+(appfw|bot)\s+profile|set\s+appfw\s+learningsettings|rm\s+appfw\s+learningdata|update\s+(appfw|bot)\s+signatures?)(\s+.*)?$|^save\s+ns\s+config$"
   add system user nsmcp-waf <password>
   bind system user nsmcp-waf nsmcp-waf 100
   bind system user nsmcp-waf readonlypolicy 110
   ```

   (Already created it for WAF only? `set system cmdPolicy nsmcp-waf ALLOW "<spec>"` updates it.)
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

### A typical bot rollout

1. **See what it does today.** "What is bot_app catching?" → `list_bot_detections` shows each detection's
   switch, its action, how many entries it has and what its counters are doing.
2. **Keep the good traffic out of it.** "Allow 10.0.0.0/24 on bot_app" →
   `add_bot_rule(rule='allow_ip', value='10.0.0.0/24')` for monitoring and scanners you run yourself.
3. **Start in log mode.** `set_bot_detections(detections=['device_fingerprint', 'trap'], enable=true,
   actions=['LOG'])`, then watch `list_bot_detections` and `recent_security_violations(feature='bot')`.
4. **Then enforce.** Move the action lists to `['LOG', 'DROP']` per detection, and give the list-style
   detections their own per-entry actions (`add_bot_rule(..., actions=['DROP'])`) — rate limiting, TPS,
   IP reputation and the deny list each carry the action on the entry, not on the profile.
5. **Other environments.** `export_bot_profile(save_as='bot_app-test.json')` →
   `import_bot_profile(file='bot_app-test.json', target_profile='bot_app_prod')`.

### Check it is actually enforced

A profile does nothing until a policy selects it and that policy is bound. `list_enforcement()` shows
both features' policies with their bind points and flags the two silent failure modes: a policy bound
nowhere, and a profile no policy selects. `list_signatures()` answers whether the signature sets are
current (and `update_signatures` re-fetches one), and `recent_security_violations()` gives the log lines
behind a block — the fastest way to tell a false positive from a real one.

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
- **Bot actions live in two places.** Allow/deny lists, rate limiting, TPS and IP reputation only have an
  on/off switch on the profile; each entry carries its own action. Device fingerprint, trap, the
  signature header checks and spoofed-request detection have a profile-level action list.
  `set_bot_detections(detections=['all'], actions=[...])` therefore levels only the latter group.
- **Bot URLs are usually paths** (rate limit, CAPTCHA, trap), so `rehost_bot_profile` often has nothing
  to switch — copy such a profile with `import_bot_profile` instead.
- **Statistics are bucketed by counter name.** NITRO's per-check / per-detection counters are flat and
  irregularly spelled, so `waf_violations` and `list_bot_detections` classify them by token and leave
  anything unrecognised under its raw name. Pass `full=true` for the untouched stat object.
- **`recent_security_violations` needs log lines and permission.** A check only logs while its action
  list includes log, the appliance keeps at most 256 recent audit messages, and the account needs
  `show audit messages`. The message format varies by build and CEF setting, so the raw line is always
  included and the parsed fields are best effort.
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
- **Writes are opt-in and limited to AppFw / Bot profiles** (plus signature re-fetch and
  `save ns config`). Reads are always available. The write tools refuse unless
  `NETSCALER_ALLOW_WRITE=true` and the account's command policy allows the change. No tool deletes a
  profile or a policy, no tool binds a policy to a vserver, and no other configuration is touched.
- **Feature-gated resources** (GSLB, AppFW) return a clean "feature not enabled" error when the
  feature is off on the appliance.
- The whole-config resources `nsrunningconfig` / `nssavedconfig` are reachable via `nitro_get` but
  return very large payloads — prefer a targeted resource.
- The stat `Interface` resource is **capitalized** — query it via `nitro_get("stat", "Interface")`.
- **Resources with required lookup arguments** (`appfwlearningdata` needs `profilename` +
  `securitycheck`, `systemfile` needs `filelocation`) only answer to `?args=`, not `name` or
  `filter`: `nitro_get("config", "appfwlearningdata", args="profilename:pr_app,securitycheck:startURL")`
  sends `…/config/appfwlearningdata?args=profilename:pr_app,securitycheck:startURL`.
