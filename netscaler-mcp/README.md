# netscaler-mcp

A **lightweight** [MCP](https://modelcontextprotocol.io) server that connects a local agent (e.g.
Claude Code) to a **NetScaler ADC** appliance (or HA pair) through the **NITRO REST API**. Ask about
your load balancers in natural language — vservers and their up/down state, backend services/servers,
SSL certificate expiry, HA status, and box CPU/memory/throughput — and, opt-in, **build and change load
balancing, content switching and SSL**: vservers, services, service groups, servers, CS policies and
actions, monitors, certificates (incl. upload to `/nsconfig/ssl`), SSL profiles and SNI, rewrite /
responder policies, pattern sets, GSLB and DNS records, and how they are bound together; clone an existing
app for a new hostname, run one change set on several appliances with one confirmation, and diagnose a
CS → LB → backend path. Roll out the **Web App
Firewall**: learned rules, the URL inventory, easy global rules, export/import between environments and
hostname switching. **Bot management** gets the same treatment — allow/deny lists, rate limiting, TPS,
CAPTCHA and IP reputation — and for both features: are the signatures current, which policy actually
applies a profile, and what do the log lines behind a block say.

- One shared `httpx.AsyncClient`; NITRO **session** login with a cached `NITRO_AUTH_TOKEN` cookie
  (transparently re-logs-in on expiry), or **stateless** `X-NITRO-USER`/`X-NITRO-PASS` per request.
- **stdio** transport by default (for Claude Code); optional **streamable-http** mode.
- **Read-only by default** — pair the server with a `readonlypolicy` account. The write tools (load
  balancing / content switching, WAF, Bot) are **opt-in** behind `NETSCALER_ALLOW_WRITE`, every one previews first (`dry_run=true`), and
  none applies without your confirmation (`NETSCALER_CONFIRM_WRITE`, default on).
- A raw escape-hatch tool (`nitro_get`) so any NITRO `config`/`stat` resource stays reachable.
- **Several appliances** from one server: standalone boxes, GSLB peers or separate HA pairs
  (`NETSCALER_INSTANCES`). Every tool takes `instance=<name>`, reads also take `instance='all'`, and
  `compare_instances` diffs their configuration, e.g. whether GSLB peers carry the same GSLB setup.

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
| `list_instances(probe?)` | The configured appliances and the default one; `probe=true` adds firmware + HA role per box. |
| `compare_instances(resourcetype="gslb", key?, attrs?, instances?, limit?)` | Diff config between appliances that don't sync (GSLB peers, standalone boxes): missing / different objects per instance. |
| `nitro_get(tree, resourcetype, name?, attrs?, filter?, args?, count?, pagesize?, pageno?)` | Escape hatch: raw read-only GET against any NITRO resource; `args` reaches resources with required lookup arguments (e.g. `appfwlearningdata`, `systemfile`). |

Every tool except the two instance tools also takes `instance` (which appliance; reads also accept `'all'`). See
[Several appliances](#several-appliances-gslb-peers-standalone-boxes).

Results are trimmed to the useful columns by default; pass `full=true` for the raw NITRO objects, and
list results are capped (`NETSCALER_MAX_ROWS`, default 200) unless `full`.

### Traffic management: LB, CS, SSL, rewrite / responder, GSLB, DNS

The generic tools below cover every object type in one table (`kind`), so the same five tools create,
change, enable/disable, bind and delete all of them.

| Area | `kind` | Notes |
|---|---|---|
| Load balancing / CS | `lb_vserver`, `cs_vserver`, `service`, `service_group`, `server`, `cs_policy`, `cs_action`, `monitor` | |
| SSL | `ssl_certkey`, `ssl_profile`, `ssl_policy`, `ssl_action`; `ssl_vserver`, `ssl_service`, `ssl_service_group` | The last three are the SSL side of a vserver / service / group (e.g. its `sslprofile`, `snienable`): update only. `ssl_certkey` cert / key / password changes go through `update ssl certKey`. |
| Rewrite / responder | `rewrite_policy`, `rewrite_action`, `rewrite_policylabel`, `responder_policy`, `responder_action`, `responder_policylabel`, `responder_htmlpage` | An HTML page is added by import from a URL (`src`). |
| Policy data | `policy_patset`, `policy_dataset`, `policy_stringmap`, `policy_expression` | |
| GSLB | `gslb_vserver`, `gslb_service`, `gslb_site` | Reading GSLB also works through the list tools above. |
| DNS records | `dns_a`, `dns_aaaa`, `dns_cname`, `dns_txt`, `dns_ns`, `dns_soa` | Several records may share a name; they are told apart by their value. |

Reads (always available):

| Tool | What it does |
|---|---|
| `get_object(kind, name, limit?, full?)` | One object with everything bound to it. `cs_vserver` → **routes**: its CS policies in priority order with rule, action and target LB vserver, plus the default LB vserver; `lb_vserver` → services / groups, policies per feature, analytics profiles; `ssl_vserver` → certificates (SNI or not), SSL policies, ciphers; `ssl_certkey` → expiry and linked CA; DNS kinds → every record under the name. |
| `list_objects(kind, name_contains?, limit?, full?)` | Any kind as a list, e.g. all SSL profiles or rewrite actions. |
| `list_cs_policies` / `list_cs_actions` / `list_lb_monitors` | Shortcuts for the common lists. |
| `search_policy_objects(text, include_values?, limit?)` | Find pattern sets, data sets, string maps and named expressions together, by name, by a pattern / value they hold, or by expression text (e.g. what `CONTAINS_ANY("x")` refers to). |
| `vserver_diagnose(name)` | One traffic path CS → LB → service groups / services → members with live state and counters. Warns about anything not UP, about members that are UP but handle no requests while the vserver gets traffic (typically broken backend TLS the monitor doesn't notice), and about SSL backends monitored only by TCP / `tcp-default`. |

Writes (opt-in, see [Write tools](#write-tools-optional)):

| Tool | What it does |
|---|---|
| `add_object(kind, name, settings, dry_run)` | Create an object; `settings` are the NITRO attributes (lower-case CLI option names), e.g. `lb_vserver` `{"servicetype": "HTTP", "ipv46": "10.0.0.20", "port": 80}`, `ssl_certkey` `{"cert": "app.pem", "key": "app.key", "expirymonitor": "ENABLED", "notificationperiod": 30}`, `ssl_profile` `{"sslprofiletype": "BackEnd", "tls12": "DISABLED", "tls13": "ENABLED"}`. Existing objects (for DNS: the same record) are left alone. Passwords (`passplain`) are masked in every preview and result. |
| `update_object(kind, name, settings?, unset?, dry_run)` | Change attributes (before/after per attribute, only differing ones are sent) or reset them (`unset`). E.g. `ssl_service_group` `{"sslprofile": "prof_backend_tls13"}`, or a certificate renewal `ssl_certkey` `{"cert": "app-2027.pem", "key": "app-2027.key"}`. |
| `set_object_state(kind, names, enabled, members?, graceful?, delay_seconds?, dry_run)` | Enable / disable vservers (also GSLB), services, service groups, servers, or single group members (`members=['srv_web1:80']`), gracefully or after a delay. |
| `change_bindings(binding, name?, add?, remove?, dry_run)` | Bind / unbind. LB/CS: `lb_vserver_service`, `lb_vserver_service_group`, `service_group_member` (`'srv:port'` or `'10.0.0.5:80'`), `service_monitor`, `service_group_monitor`, `cs_vserver_policy`, `cs_vserver_default`. Policies per feature: `lb_vserver_<f>_policy` / `cs_vserver_<f>_policy` with f = `responder`, `rewrite`, `appfw`, `bot`, `cache`, `cmp`, `transform` (priority, bindpoint, gotopriorityexpression, invoke, label), and `lb_vserver_analytics_profile` / `cs_vserver_analytics_profile`. SSL: `ssl_vserver_certkey` (`snicert`, `ca`, `crlcheck`, `ocspcheck`), `ssl_service_certkey`, `ssl_service_group_certkey`, `ssl_vserver_policy`, `ssl_profile_cipher`, `ssl_certkey_link` (CA). Global, without `name`: `rewrite_global_policy`, `responder_global_policy`. Labels: `rewrite_policylabel_policy`, `responder_policylabel_policy`. Data: `policy_patset_pattern`, `policy_dataset_value`, `policy_stringmap_pattern`. GSLB: `gslb_vserver_service`, `gslb_vserver_domain`. Already-bound entries are skipped; a changed weight / priority / flag is re-bound with the live binding's bindpoint and priority; a new single entry (CS default, CA link) replaces the old one. |
| `delete_object(kind, names, dry_run)` | **Delete** objects, in the given order (DNS: a name deletes all its records, `{"hostname": …, "ipaddress": …}` only one). The preview lists what is still bound to each one. The appliance refuses deletes that would leave dangling references (unbind first). Needs `NETSCALER_ALLOW_DELETE=true` on top of `NETSCALER_ALLOW_WRITE`, and **always** asks for confirmation, even with `NETSCALER_CONFIRM_WRITE=false`. |
| `upload_ssl_file(filename, text? \| content_base64? \| file?, overwrite?, dry_run)` | Upload a certificate / key / chain to **`/nsconfig/ssl` only** (no other path is possible). The preview shows size, SHA-256 and what the file contains, never the content. An identical file is skipped; a different one needs `overwrite=true`. `file=` reads from the mounted files directory (`NETSCALER_EXPORT_DIR`) so private keys never pass through the conversation. |
| `sync_gslb_config(force_site?, save_on_sites?, dry_run)` | `sync gslb config` to the other sites; the preview lists local and target sites. |
| `clone_app_setup(template_lb_vserver, template_hostname, new_hostname, backends, …, instances?, save?, dry_run)` | A new app from an existing one: servers, service group with its settings, monitors and SSL profile, LB vserver with its settings and every policy / analytics binding, CS action + policy for the new hostname at the next free priority, the SNI certificate. Names and the CS rule are the template's with the hostname swapped (`name_part` / `new_name_part` when the names use another part). One preview, one confirmation, optionally on several instances. |

A whole setup — certificate files → certkey → server → service group + members → LB vserver + policies →
CS action + policy → SNI certificate — goes into one `apply_batch` with one confirmation. With
`instances=["dc1", "dc2"]` the same batch runs on both standalone boxes: one preview per instance, one
confirmation, applied instance by instance and stopped on the first failure (the second box is then not
touched); afterwards the objects and bindings it touched are compared across the instances. Tearing a
setup down works the same way: unbind, then `delete_object`. A batch that contains a delete always asks
for confirmation.

### WAF rollout tools

Reads (always available):

| Tool | What it does |
|---|---|
| `list_waf_rules(profile, rule_type?, contains?, limit?)` | A profile's configured rules — relaxations and deny URLs — grouped by rule type. |
| `list_waf_learned_rules(profile, rule_type="all", contains?, min_hits?, limit?)` | What the learning engine recorded: hits, the raw entry, the rule it would deploy as; start URLs also get prefix-rule suggestions. |
| `list_waf_urls(profile, host?, include_learned?, limit?)` | URL inventory: hosts, allowed / denied / referenced URLs, learned URLs marked **covered** or not, and suggested global rules for the uncovered ones. |
| `export_waf_profile(profile, host_map?, save_as?)` | Settings, learning thresholds and every rule as a portable JSON document (optionally with hostnames switched, or saved to a file). |

Writes (opt-in — refuse unless `NETSCALER_ALLOW_WRITE=true`; all preview with `dry_run=true` by default
and apply only with the preview's `confirm` code, see [Confirmation before every write](#confirmation-before-every-write)):

| Tool | What it does |
|---|---|
| `add_waf_rule(profile, rule, host?, path?, match?, scheme?, extensions?, field?, …, dry_run)` | Easy rules without hand-written regex: `allow_url`, `allow_static`, `deny_url`, `allow_sql_field`, `allow_xss_field`, `allow_cmd_field`, `allow_field_consistency`, `allow_cookie`, `allow_csrf`, `allow_content_type`, `trusted_learning_client`, or `raw`. `host='*'` makes a rule global across environments; comma-separate profiles to add it to several. |
| `remove_waf_rule(profile, rule_type, rule, all_matches?, dry_run)` | Unbind a rule (pass a row from `list_waf_rules`). |
| `deploy_waf_learned_rules(profile, rule_type, contains?, min_hits?, remove_learned?, limit?, dry_run)` | Turn learned entries into rules — skipping ones that exist or that a start URL rule already covers — and clear them from learning. |
| `discard_waf_learned_rules(profile, rule_type, contains?, max_hits?, all_entries?, limit?, dry_run)` | Drop learned noise (scanners, attack attempts) so it never becomes a rule. |
| `set_waf_check_actions(profile, checks, set_actions?, add_actions?, remove_actions?, dry_run)` | The learn → block switch, per check or `['all']`, with before/after. |
| `import_waf_profile(document \| file, target_profile?, host_map?, mode?, include_settings?, dry_run)` | Apply an export to a profile (created if missing): `merge` adds missing rules, `replace` mirrors the document. |
| `rehost_waf_profile(profile, from_host, to_host, target_profile?, dry_run)` | Switch every rule to another hostname, in place or into a copy for another environment. |
| `save_config(confirm?)` | `save ns config` — persist applied changes (first call returns the confirm code). |
| `apply_batch(changes, save?, dry_run, confirm?)` | **Several changes, one confirmation:** a list of write-tool steps (`{"tool": …, "args": {…}}`: LB/CS, WAF and Bot), previewed together and applied in order with one confirm code, optionally followed by `save ns config`. |

### Bot management tools

Reads (always available):

| Tool | What it does |
|---|---|
| `list_bot_rules(profile, rule_type?, contains?, limit?)` | A profile's entries per detection: allow/deny lists, rate limiting, TPS, CAPTCHA URLs, IP-reputation categories, log/KM expressions, trap URLs. |
| `list_bot_detections(profile?, full?)` | Per detection: is it on, what does it do, how many entries — plus the live counters split by outcome (log / drop / redirect / reset / captcha). |
| `export_bot_profile(profile, host_map?, save_as?)` | The profile's detection settings and every entry as a portable JSON document. |

Writes (opt-in — refuse unless `NETSCALER_ALLOW_WRITE=true`; all preview with `dry_run=true` by default
and apply only with the preview's `confirm` code, see [Confirmation before every write](#confirmation-before-every-write)):

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
| `update_signatures(kind, name, merge_default?, dry_run, confirm?)` | **Write:** re-fetch a signature object from its configured source URL (previews by default, applies with the confirm code). |
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
[Write tools → Enable writes](#enable-writes) instead.

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
- **Writes / deletes / files** — `NETSCALER_ALLOW_WRITE=true` enables the write tools (each still
  asks for confirmation unless `NETSCALER_CONFIRM_WRITE=false`); `NETSCALER_ALLOW_DELETE=true` also
  enables `delete_object`, which always asks for confirmation;
  `NETSCALER_EXPORT_DIR` lets export/import use files. See
  [Write tools](#write-tools-optional).

### Several appliances (GSLB peers, standalone boxes)

An HA pair needs nothing extra: it is one appliance to NITRO (point at the management VIP or primary).
For appliances that do **not** sync with each other — two standalone boxes, GSLB sites in separate
data centres, separate HA pairs — one server can reach all of them:

```bash
NETSCALER_INSTANCES=dc1,dc2
NETSCALER_DC1_BASE_URL=https://10.0.0.10
NETSCALER_DC2_BASE_URL=https://10.0.1.10
NETSCALER_USER=nsmcp                 # shared by both …
NETSCALER_PASSWORD=...
NETSCALER_DC2_PASSWORD=...           # … unless an instance sets its own
# NETSCALER_DEFAULT_INSTANCE=dc1     # default: the first listed
```

- Each listed instance needs its own `NETSCALER_<NAME>_BASE_URL` (`-` in a name becomes `_` in the
  variable). Every other appliance setting — `USER`, `PASSWORD`, `AUTH_MODE`, `SESSION_TIMEOUT`,
  `TIMEOUT`, `VERIFY_SSL`, `CA_BUNDLE`, `ALLOW_WRITE`, `ALLOW_DELETE`, `CONFIRM_WRITE`, `EXPORT_DIR` — can be set per
  instance as `NETSCALER_<NAME>_<KEY>`, with the plain `NETSCALER_<KEY>` as shared fallback. So writes can
  be on for one box and off for another (`NETSCALER_DC2_ALLOW_WRITE=true`).
- Every tool takes **`instance`**; omitted, it uses the default instance. Read tools also take
  **`instance='all'`**: they run on every appliance at once and return `{"instances": {name: result}}`.
  An unreachable box reports its `error` without failing the others.
- **Writes go to one named instance at a time.** With several instances configured, a write tool
  refuses to run without `instance=<name>`, never takes `'all'`, and its preview names the instance.
  The confirm code is bound to that instance: a code from a preview on `dc1` does not apply on `dc2`.
- **`list_instances(probe?)`** shows what is configured (URL, default, write flags); `probe=true` also
  asks each box for its firmware and HA role (`ha_peers` is empty on a standalone appliance).
- **`compare_instances(resourcetype="gslb", key?, attrs?, instances?, limit?)`** diffs configuration
  between instances. `gslb` compares GSLB sites, vservers, services and each GSLB vserver's service and
  domain bindings. All of these must match on every participating site, and nothing syncs them
  outside an HA pair unless you run `sync gslb config`. It also checks that each site is LOCAL on exactly
  one box. Any other config resource type (`appfwprofile`, `sslcertkey`, …) is compared object by object.
  Runtime attributes (states, counters, timestamps) are skipped unless you pass `attrs`. Results list
  what is `missing_on` which instance, what is `different` (per attribute, per instance), and
  `in_sync`.

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
account, or one container per appliance or HA pair. (To reach several appliances from **one**
container, and compare them, use `NETSCALER_INSTANCES` instead — see
[Several appliances](#several-appliances-gslb-peers-standalone-boxes).)
A YAML anchor keeps the shared settings in one place (Compose ignores top-level `x-` keys).
Ready to copy: [`compose.yml.multiuser.example`](compose.yml.multiuser.example).

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
  the flag off. Every write still asks for confirmation first unless
  `NETSCALER_CONFIRM_WRITE=false`. `*.env` is gitignored, so it stays local.
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
- "Where does cs_app send /api traffic, and which backends are behind it?"
- "Take srv_web1 out of sg_web gracefully, then put it back." (write tools)
- "Why does app.example.com answer with 503? Diagnose cs_app." (`vserver_diagnose`)
- "Upload the renewed certificate from the files directory and update cert_app with it." (write tools)
- "Set up new.example.com like old.example.com, backend 10.0.0.71:443, on dc1 and dc2." (`clone_app_setup`)
- "Create vs_app on 10.0.0.21:80 with servers 10.0.0.51 and 10.0.0.52 on port 8080, and route app.example.com to it from cs_app." (write tools, one confirmation)
- "Which learned start URLs on WAF profile pr_app aren't covered by a rule yet?"
- "Which WAF checks are firing on pr_app, and is anything already blocking?"
- "Is the WAF profile pr_app actually enforced anywhere, and are the signatures current?"
- "What is bot profile bot_app catching at the moment?"
- "Do dc1 and dc2 have the same GSLB configuration?" (with `NETSCALER_INSTANCES`)
- "Which certificates expire within 30 days on any of the appliances?"

## Write tools (optional)

The load balancing / content switching tools, the WAF and Bot rollout tools, `update_signatures`,
`save_config` and `apply_batch` change the appliance. They all work the same way.

### Enable writes

1. Set `NETSCALER_ALLOW_WRITE=true` in `netscaler.env`. With it unset the write tools still
   **preview** (`dry_run=true`) but refuse to apply. Leave `NETSCALER_CONFIRM_WRITE` at its default
   (`true`) so nothing is applied without your yes (see below).
2. Use a system user that may change AppFw and Bot profiles. A least-privilege command policy covering
   exactly what the tools send (adjust to your change control):

   ```
   add system cmdPolicy nsmcp-waf ALLOW "^((add|set|bind|unbind)\s+(appfw|bot)\s+profile|set\s+appfw\s+learningsettings|rm\s+appfw\s+learningdata|update\s+(appfw|bot)\s+signatures?)(\s+.*)?$|^save\s+ns\s+config$"
   add system user nsmcp-waf <password>
   bind system user nsmcp-waf nsmcp-waf 100
   bind system user nsmcp-waf readonlypolicy 110
   ```

   For the traffic-management tools (LB, CS, SSL, rewrite / responder, policy data, GSLB, DNS), a
   second policy covers what they send:

   ```
   add system cmdPolicy nsmcp-lb ALLOW "(?i)^((add|set|unset|enable|disable)\s+(lb\s+(vserver|monitor)|cs\s+(vserver|policy|action)|service|serviceGroup|server|ssl\s+(certKey|vserver|service|serviceGroup|profile|policy|action)|(rewrite|responder)\s+(policy|action|policylabel)|policy\s+(patset|dataset|stringmap|expression)|gslb\s+(vserver|service|site)|dns\s+(addRec|aaaaRec|cnameRec|txtRec|nsRec|soaRec))|(bind|unbind)\s+(lb\s+vserver|cs\s+vserver|service|serviceGroup|ssl\s+(vserver|service|serviceGroup|profile)|(rewrite|responder)\s+(global|policylabel)|policy\s+(patset|dataset|stringmap)|gslb\s+vserver)|(update|link|unlink)\s+ssl\s+certKey|import\s+responder\s+htmlpage|sync\s+gslb\s+config)(\s+.*)?$|^save\s+ns\s+config$"
   bind system user nsmcp-waf nsmcp-lb 105
   ```

   `upload_ssl_file` needs to add (and, with `overwrite`, remove) files in `/nsconfig/ssl` only. Keep it
   in its own policy so no other path is writable:

   ```
   add system cmdPolicy nsmcp-sslfiles ALLOW "(?i)^(add|rm)\s+system\s+file\s+\S+\s+-fileLocation\s+\"?/nsconfig/ssl/?\"?(\s+.*)?$"
   bind system user nsmcp-waf nsmcp-sslfiles 107
   ```

   `delete_object` additionally needs the `rm` commands, e.g. as a further policy that you only bind
   where deletes are wanted:

   ```
   add system cmdPolicy nsmcp-lb-rm ALLOW "(?i)^rm\s+(lb\s+(vserver|monitor)|cs\s+(vserver|policy|action)|service|serviceGroup|server|ssl\s+(certKey|profile|policy|action)|(rewrite|responder)\s+(policy|action|policylabel|htmlpage)|policy\s+(patset|dataset|stringmap|expression)|gslb\s+(vserver|service|site)|dns\s+(addRec|aaaaRec|cnameRec|txtRec|nsRec|soaRec))(\s+.*)?$"
   bind system user nsmcp-waf nsmcp-lb-rm 106
   ```

   Look at how the appliance logs a call before relying on a regex (System → Auditing, or
   `show audit messages`): NITRO calls are checked as the CLI command they map to, and the exact
   spelling (e.g. of the `systemfile` upload) is what the policy must match.

   (Not yet checked against a live box: if a call answers "not authorized", look at the command the
   appliance logged for it and widen the regex.)

   (Already created it for WAF only? `set system cmdPolicy nsmcp-waf ALLOW "<spec>"` updates it.)
   Consider a separate `netscaler-waf` MCP registration (its own env file) so day-to-day
   questions keep using the read-only account.
3. Deletes are off even with writes on. Set `NETSCALER_ALLOW_DELETE=true` as well to enable
   `delete_object`. Every delete asks for your confirmation, whatever `NETSCALER_CONFIRM_WRITE` says.

### Confirmation before every write

`NETSCALER_CONFIRM_WRITE` (default `true`) sits on top of the `dry_run` previews. A preview
(`dry_run=true`, the default) changes nothing and, besides the plan computed against the live appliance,
returns a `confirm_code`. The agent shows you a short overview and asks *"Confirm it?"*; only after you
say yes does it repeat the call with `dry_run=false` and `confirm=<code>`. A `dry_run=false` call
without the matching code is answered with the same preview and code and applies nothing.

The code is tied to the tool, its exact arguments **and the computed plan**, so a changed request — or
a profile that changed on the appliance in between — needs a fresh confirmation (codes also expire when
the server restarts). For learned-rule deploy/discard the code binds the entries, not their hit counts,
which keep moving while learning runs. A call with nothing to change needs no confirmation.
`save_config` has no `dry_run`: its first call returns the code, the second (`confirm=<code>`) saves. Set
`NETSCALER_CONFIRM_WRITE=false` to let `dry_run=false` apply directly, as before.

**Several changes → `apply_batch`.** Each write tool asks once per call, so ten single settings would
mean ten previews and ten "Confirm it?" (plus one more for `save_config`). Put them into one
`apply_batch` call instead:

```json
{"changes": [
  {"tool": "add_waf_rule",          "args": {"profile": "pr_app", "rule": "allow_url", "host": "app.example.com", "path": "/api/"}},
  {"tool": "set_waf_check_actions", "args": {"profile": "pr_app", "checks": ["sql_injection", "cross_site_scripting"], "add_actions": ["block"]}},
  {"tool": "set_waf_check_actions", "args": {"profile": "pr_app", "checks": ["start_url"], "remove_actions": ["learn"]}},
  {"tool": "add_bot_rule",          "args": {"profile": "bot_app", "rule": "allow_ip", "value": "10.0.0.0/24"}}
 ],
 "save": true}
```

Every step is previewed exactly like its own tool would preview it. The one code binds all step plans
(and `save`) on that one instance. On apply the steps run in order and stop at the first error: the
rest is reported `not run` and nothing is saved. A step whose live plan no longer matches what you
confirmed is not applied either; that happens, for example, when an earlier step in the same batch
added the rule a later step removes. Steps take the same arguments as the tools, minus `dry_run`,
`confirm` and `instance`.

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

Every write call answers first with a plan and asks *"Confirm it?"*; say yes and the agent re-runs it
with `dry_run=false` and the plan's `confirm` code — only then is anything applied.

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

As with WAF, every bot write shows its plan first and only applies after you confirm it.

### Check it is actually enforced

A profile does nothing until a policy selects it and that policy is bound. `list_enforcement()` shows
both features' policies with their bind points and flags the two silent failure modes: a policy bound
nowhere, and a profile no policy selects. `list_signatures()` answers whether the signature sets are
current (and `update_signatures` re-fetches one), and `recent_security_violations()` gives the log lines
behind a block — the fastest way to tell a false positive from a real one.

### Behaviour & caveats

- **Unverified against a live box (traffic management).** Checked against the NITRO reference and
  the fake appliance only: `update` / `link` / `unlink` on `sslcertkey`, the `systemfile` upload and
  how an existing file is detected, `Import` of a responder HTML page, `sync gslb config` via
  `gslbconfig?action=sync`, the per-member stats `vserver_diagnose` reads
  (`stat servicegroup?statbindings=yes`), and the unbind arguments of policy bindings (bindpoint,
  priority, type). Try them on a test object first.
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
- **Writes are opt-in**: traffic-management objects (LB, CS, SSL, rewrite / responder, policy data, GSLB,
  DNS) and their bindings, certificate files in `/nsconfig/ssl`, AppFw / Bot profiles, signature re-fetch
  and `save ns config`. Reads are always available. The write tools refuse unless
  `NETSCALER_ALLOW_WRITE=true` and the account's command policy allows the change, and (unless
  `NETSCALER_CONFIRM_WRITE=false`) only apply with the confirm code from a preview you approved.
  **Deletes** (`delete_object`, traffic-management objects only) additionally need `NETSCALER_ALLOW_DELETE=true`
  and always need a confirmation. No tool deletes a WAF / Bot profile or policy or binds a policy to a
  vserver.
- **Feature-gated resources** (GSLB, AppFW) return a clean "feature not enabled" error when the
  feature is off on the appliance.
- The whole-config resources `nsrunningconfig` / `nssavedconfig` are reachable via `nitro_get` but
  return very large payloads — prefer a targeted resource.
- The stat `Interface` resource is **capitalized** — query it via `nitro_get("stat", "Interface")`.
- **Resources with required lookup arguments** (`appfwlearningdata` needs `profilename` +
  `securitycheck`, `systemfile` needs `filelocation`) only answer to `?args=`, not `name` or
  `filter`: `nitro_get("config", "appfwlearningdata", args="profilename:pr_app,securitycheck:startURL")`
  sends `…/config/appfwlearningdata?args=profilename:pr_app,securitycheck:startURL`.
