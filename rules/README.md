# IONSEC node2shell detection rules — CVE-2026-111497 (Node2Shell)

Detection and mitigation content for **Node2Shell**, CVE-2026-111497: an out-of-bounds
write in Google's Brotli C decoder (`c/dec/decode.c`, block-switch handling).

- **Severity.** CNA CVSS v4.0 9.2; Red Hat CVSS 3.1 8.1; Node.js rates it High.
- **How Node reaches it.** Through `node:zlib`: Express 5 / body-parser 2 request bodies,
  Koa co-body, `@fastify/compress`, Nest 11+, Apollo standalone, and `fetch`/axios/got
  responses.
- **Other stacks.** Bun < 1.4.4, Python aiohttp/requests/Scrapy with Brotli ≤ 1.2.0, the
  Envoy brotli decompressor, and more.
- **Fixed in.** Node.js 22.23.4 / 24.22.1 / 26.12.1; Bun 1.4.4; brotli 1.0.10 / 1.1.1 /
  1.2.1; PyPI Brotli 1.2.1 / brotlicffi 1.2.1.0.

Compiled 2026-10-24 by IONSEC. Every fingerprint comes from the IONSEC research brief
(catalogue N2S-01 … N2S-25). Each rule names its N2S id and says whether it is
**VERBATIM** (exact documented string or shape) or **DERIVED** (logic grounded in a
documented observation, derivation stated). `references/node2shell-sources.md` maps every
rule to its sources.

## Inventory

| Path | Format | Rules / content |
|---|---|---|
| `sigma/` | Sigma (14 rules) | see the table below |
| `suricata/ionsec-node2shell.rules` | Suricata 6/7/8 | 14 active rules, SIDs 1006600–1006606, 1006610–1006614, 1006620, 1006630; 1 optional commented rule (1006631) |
| `modsecurity/ionsec-node2shell-dropin.conf` | ModSecurity v2 / libmodsecurity v3 / Coraza | 7 active rules: 1026111401 setup, 1026111410–1026111413 detection, 1026111420–1026111421 enforcement. Commented allowlist hooks 1026111402–1026111403; 1026111400 reserved. |
| `edge/` | nginx, Apache, HAProxy, Envoy, Cloudflare, AWS WAF, Azure | 8 inbound files (7 platforms; Azure Front Door and Application Gateway are separate), 3 egress files, `README.md` |
| `app/` | Express, Koa, Fastify, Nest 11+, aiohttp | 5 snippets + `README.md` |
| `yara/ionsec_node2shell.yar` | YARA 4.x | 7 rules + 1 private format rule |
| `references/node2shell-sources.md` | Markdown | provenance table (every rule ↔ N2S id ↔ sources ↔ VERBATIM/DERIVED), fingerprints not turned into rules, source list |

### Sigma rules

| File | N2S | Level | Log source |
|---|---|---|---|
| `web_node2shell_request_content_encoding_br.yml` | N2S-11 (DERIVED) | low (hunting) | webserver |
| `web_node2shell_br_chunked_request.yml` | N2S-12 | medium | webserver |
| `web_node2shell_duplicate_content_encoding.yml` | N2S-13 | medium | webserver |
| `web_node2shell_checker_useragents.yml` | N2S-08/09/10 | medium | webserver |
| `web_node2shell_ostorlab_differential_probe.yml` | N2S-07 | medium | webserver |
| `web_node2shell_lab_route_combo.yml` | N2S-22 | low | webserver |
| `proxy_node2shell_identity_output_in_response.yml` | N2S-19 | high | proxy (response body) |
| `proxy_node2shell_verifier_download_useragent.yml` | N2S-10 (egress) | informational | proxy (egress) |
| `app_nodejs_node2shell_block_switch_error.yml` | N2S-16 (+ DERIVED brotli 1.0.x `ERR_BLOCK_SWITCH`) | medium | application / nodejs |
| `app_nodejs_node2shell_block_length_1_error.yml` | N2S-17 (+ DERIVED `ERR_BLOCK_LENGTH_1`) | low | application / nodejs |
| `lnx_node2shell_runtime_crash.yml` | N2S-18 (Imperva caveat) | low | linux (kernel / journald) |
| `proc_creation_lnx_node2shell_runtime_shell_recon.yml` | N2S-21 (DERIVED) | high | process_creation / linux |
| `proc_creation_win_node2shell_runtime_shell_recon.yml` | N2S-21 (DERIVED) | high | process_creation / windows |
| `file_event_lnx_node2shell_lab_marker.yml` | N2S-20 | low | file_event / linux |

### YARA rules

| Rule | N2S | Use |
|---|---|---|
| `IONSEC_Node2Shell_Trigger_Seed_Payload` | N2S-01…06 | hunting in PCAP carves, captured bodies, `.br` fixtures |
| `IONSEC_Node2Shell_Trigger_Seed_HexText` | N2S-01…04, 06 (DERIVED) | hunting for PoC tooling / self-tests in source and scripts |
| `IONSEC_Node2Shell_Unfixed_Brotli_Decoder_Embedded` | N2S-23 | inventory: decoder compiled in, without the fix |
| `IONSEC_Node2Shell_Unfixed_Brotli_Decoder_Library` | N2S-23 | inventory: libbrotlidec 1.1.0–1.2.0 without the fix |
| `IONSEC_Node2Shell_Brotli_Linked_Consumer_PreFix_Constants` | N2S-23 | informational: links libbrotlidec; check the library |
| `IONSEC_Node2Shell_Unfixed_Brotli_1_0_x_Decoder` | N2S-23 (DERIVED, 1.0.x bare names) | inventory: brotli 1.0.x decoder without the fix |
| `IONSEC_Node2Shell_Unfixed_Brotli_DecodeC_Source` | N2S-24 | inventory: vendored `decode.c` without the fix |

## Coverage map: which rule sees which direction

Node2Shell has two delivery paths:

- **Inbound.** An attacker sends a `Content-Encoding: br` request body to your server.
- **Outbound (fetch-trap).** Your service fetches from an attacker-controlled server that
  answers `Content-Encoding: br`. This needs no inbound request. Webhooks, link previews,
  image proxies, crawlers, SSR of user-supplied URLs and npm are typical. **A WAF in front
  of the app never sees this direction.** Vercel states it for its own Node2Shell WAF
  rules.

| Content | Inbound request | Outbound response (fetch-trap) | Host / post-exploitation |
|---|---|---|---|
| Sigma web_* (br header, chunked, duplicate CE, UAs, Ostorlab, lab routes) | yes | — | — |
| Sigma proxy identity output (N2S-19) | yes (response to the attacker) | — | — |
| Sigma proxy verifier UA (N2S-10) | — | yes (egress proxy, TLS-terminating) | — |
| Sigma app log errors (N2S-16/17) | yes | yes (same error when fetch decodes) | yes |
| Sigma crash / process / file (N2S-18/20/21) | — | — | yes (either path) |
| Suricata 1006600–1006606, 1006610–1006614 | yes | — | — |
| Suricata 1006620 | — | yes (seed in a br response; place the sensor on egress) | — |
| Suricata 1006630 | yes (id output back to the attacker) | — | — |
| ModSecurity / Coraza drop-in | yes (blocks before the body reaches the app) | **no** (cannot see it) | — |
| Edge inbound (nginx/Apache/HAProxy/Envoy/Cloudflare/AWS/Azure) | yes | **no** | — |
| Edge egress (HAProxy/Envoy/nginx) | — | yes (only where the proxy sees HTTP; CONNECT+TLS is opaque) | — |
| App guards (Express/Koa/Fastify/Nest/aiohttp) | yes | **no** (see client switches in `app/README.md`) | — |
| YARA seed rules | yes (captures) | yes (captures) | yes (staged tooling) |
| YARA inventory (N2S-23/24) | — | — | yes (patch status of binaries and sources) |

## Deployment notes

- **Sigma.** Field names follow the php2shell package. Standard: `cs-method`,
  `cs-uri-stem`, `cs-user-agent`, `c-useragent`, `ParentImage`/`Image`/`CommandLine`,
  `TargetFilename`. IONSEC conventions that you must map: `cs-headers-<name>` for logged
  request headers, `request_headers` (raw header block), `request_body` and
  `response_body` (body-aware WAF/proxy logs).
  - Log the request `Content-Encoding`, `Transfer-Encoding` and `Content-Length` headers,
    e.g. nginx `$http_content_encoding $http_transfer_encoding $http_content_length`.
  - Tags use the hyphenated ATT&CK form of the Sigma specification v2 and the php2shell
    template (`attack.initial-access`, not `attack.initial_access`).
  - The app-log rules use `keywords` (full-text). On token-based SIEMs, the exact Node codes
    (`ERR__ERROR_FORMAT_BLOCK_SWITCH`, `ERR_BLOCK_SWITCH` …) match as whole tokens.
- **Suricata.**
  - Load with `-S` or add the file to `rule-files`. Make sure `HOME_NET` covers your Node
    servers (1006630) and egress clients.
  - Put sensors behind TLS termination.
  - Raise `stream.reassembly.depth` on sensors that guard Node APIs.
  - Read the file header before tuning. It explains why payload bytes are matched in the
    raw stream and not in the body buffers, which buffers are normalised, and how to check
    what your Suricata version keeps for br bodies.
- **ModSecurity / Coraza.**
  - Include the file after `crs-setup.conf`. It is detection-only by default; to block,
    set `tx.node2shell_mode=block` (ID 1026111400) before the include. `SecRuleEngine On`
    is required for blocking.
  - It is header-only, phase 1, and decides before the body reaches the backend.
  - Duplicate counting works on libmodsecurity v3 + nginx and on Coraza. On Apache
    httpd + ModSecurity v2, repeated headers arrive merged, so rule 1026111412 (comma list)
    does that job.
- **Edge.** See `edge/README.md`. 415 for inbound rejects; 502 or strip for egress.
  Azure's block status is policy-wide (no 415). The Cloudflare `contains` and AWS/Azure
  `Contains` operators are substring matches (caveat documented).
- **App.** See `app/README.md`. The guard must run before the first body parser. aiohttp
  needs `auto_decompress=False`, because its parser decodes before middleware runs.
- **YARA.** Scan these targets:
  - `node` (and `libnode.*` for `--shared` builds such as Homebrew), `bun`;
  - `libbrotlidec.so*` / `.dylib` / `brotlidec.dll`;
  - Python `_brotli*.so` / `_brotlicffi*.so`, RubyGems `brotli` extensions;
  - Electron frameworks.

  Results:
  - No match means "unknown", never "patched".
  - The linked-consumer rule means "check the linked library".
  - Electron binaries that embed two decoders, and non-C ports (Go andybalholm/brotli,
    Rust brotli-decompressor, Deno), need the runtime self-test (N2S-25).
  - `process.versions.brotli` does not change when the fix lands. Do not use it.

## False-positive guidance

- **Apify.** The Apify JavaScript API client brotli-compresses request bodies of 1,024
  bytes or more by default (docs.apify.com). Expect hits on N2S-11 / the br header rules
  only on Apify-API-shaped endpoints you operate or proxy. A br request whose body is under
  1,024 bytes is not Apify's default behaviour. To silence it:
  - set `compression: 'gzip'` on the client; or
  - allowlist by path **and** source address, only in front of a patched decoder (hooks in
    the ModSecurity, nginx, HAProxy and Cloudflare snippets).
- **Legitimate patch self-tests and scanners send the seed.** The N2S-01 regression vector
  appears in Node's own test, in Ostorlab's differential probe, and in defensive
  known-answer tests in more than 12 public repos. On the wire (Suricata 1006610), in logs
  (N2S-16 on patched hosts) and in files (YARA seed rules), first rule out your own
  scanners, CI and validation jobs.
- **Outbound `Accept-Encoding: br` from Node clients is normal.** undici `fetch`, axios,
  got, node-fetch 3 and needle all advertise br. **No rule here alerts on it; never add
  one.** The egress snippets rewrite it only to keep honest servers from answering br.
- **Other common sources.**
  - Checker UAs: self-identifying exposure checkers (completetech) and authorized scans.
  - id output: pages that document the `id` command. N2S-19 rules are scoped to your own
    servers.
  - Shells from node: build tools, npm scripts and test runners. The process rules filter
    the common ones; tune them to your server entry points.
  - Crashes: many causes. Imperva calls process exits a triage clue, "not a reliable
    stand-alone sign of exploitation".
  - Lab markers and routes (N2S-20/22): internal training runs of the public labs.

## External coverage (brief §6, as of 2026-10-24)

| Vendor / project | Coverage |
|---|---|
| Imperva | Dedicated WAF rules, validated against the attempts it reproduced; no rule IDs published |
| Vercel | WAF rules deployed 21 Oct for every project; block the inbound vector, **do not cover responses the app fetches**; no rule IDs |
| Indusface AppTrana | Emergency update 22 Oct: blocks Brotli request bodies (incl. `gzip, br` lists) and duplicate Content-Encoding headers |
| Cloudflare | No managed rule naming CVE-2026-111497 / Node2Shell / Brotli in the WAF changelog through 22 Oct |
| Tenable | Nessus plugin **370490** (version-based: Node.js 22.x < 22.23.4 / 24.x < 24.22.1 / 26.x < 26.12.1) |
| Qualys | VMDR detections announced 23 Oct (QIDs not retrieved) |
| AWS | No WAF managed rule found |
| Emerging Threats, Snort/Talos, SigmaHQ, Elastic detection-rules, Nuclei templates, OWASP CRS, signature-base, Yara-Rules, Corelight | **No rule found** (repo-scoped code search, 24 Oct). This package fills that gap. |

## Validation status

Rule engines are not installed in the IONSEC build environment: no Suricata,
ModSecurity/Coraza, YARA/yara-python/YARA-X, pySigma/sigma-cli, nginx, HAProxy or Envoy.
`httpd`, `otool` and inline `ruby -e` / `python -c` are blocked by the local shell policy.
What was and was not checked (2026-10-24):

**Machine-validated**

- **YAML well-formedness.** All 14 Sigma files and both Envoy fragments parse with PyYAML
  6.0.3 (Python 3.14).
- **Sigma structure** (IONSEC checker script):
  - required keys; canonical, unique UUIDs; date; level values;
  - tag namespaces, with `cve.2026-111497` on every rule;
  - every condition identifier exists and every selection is used;
  - every `|re` value compiles (Python `re`).
- **JSON.** The 3 edge JSON files parse (jq and Python `json`).
- **Suricata structure** (checker script):
  - header grammar; balanced quotes; every option terminated by `;`;
  - `|..|` hex pairs; no raw `;` or `"` inside content;
  - required `msg`/`sid`/`rev`/`classtype`/`reference`/`metadata`;
  - `metadata` in `key value` form; SIDs unique and inside 1006600–1006699;
  - every `pcre` compiles (Python `re` as a PCRE stand-in).
- **ModSecurity structure** (checker script): continuation lines; balanced quotes; unique
  IDs in 1026111400–1026111499, none equal to 1026111497, none colliding with the
  php2shell IDs 1026109601–1026109610; chain starters carry `id`/`phase`, chained rules do
  not; no dangling chain.
- **YARA structure** (checker script): balanced braces; unique rule names; every declared
  string referenced; hex tokens well-formed; seed strings exactly 22/23/22/22/40/22 bytes.
- **Behavioural regex tests.** 70+ cases, all passing:
  - the br-token regex in Python and in the JavaScript engine (Node 26);
  - the Suricata header pcres on synthetic header buffers (br, lists, `brotli`,
    `X-Content-Encoding`, `Accept-Encoding`);
  - the duplicate-header pcre;
  - the seed contents and the to_client family pcre on N2S-01…04 plus a mutated negative;
  - the N2S-05 probe length (1,032 bytes);
  - the id-output regex; the Linux process regex;
  - the Envoy Lua token logic, emulated.
- **YARA N2S-24, emulated** with the same regex on google/brotli `decode.c` at 8 tags.
  It matches v1.0.3, v1.0.9, v1.1.0 and v1.2.0, and does not match v1.0.2 (pre-bug) or
  the fixed v1.0.10, v1.1.1 and v1.2.1.
- **YARA N2S-23 / seed rules, emulated** on real binaries on the build machine (read-only
  byte checks; nothing executed):

  | Binary | Rule matched |
  |---|---|
  | Homebrew `libbrotlidec.1.2.0.dylib` (unfixed) | Library |
  | Homebrew Node 26.7.0 `libnode.147.dylib` (pre-fix, `--shared-brotli`) | Linked consumer |
  | 50 KB `node` launcher | none |
  | `libbrotlicommon` | none |
  | `/usr/bin/ruby` | none (no seed false positive) |

  The brotli 1.0.x rule is checked for logic only: no 1.0.x binary was available.
- **App snippets.** `node --check` passes for the three JS files and for `nest-main.ts`
  (Node 26 type stripping). The Python snippet compiles. This checks syntax only.

**Not validated**

- Suricata: not loaded (`suricata -T` not run). Mixed raw-stream + HTTP-buffer rules
  (1006606, 1006620), `http.header.raw` behaviour and libhtp body decoding were not
  observed on a real engine. Verify with the steps in the rules file header.
- ModSecurity: not loaded into v2, v3 or Coraza. Connector-specific duplicate-header
  behaviour is documented, not tested.
- YARA: not compiled. Run `yara -w ionsec_node2shell.yar /dev/null` first.
- Sigma: no backend conversion or field mapping tested.
- nginx, Apache, HAProxy, Envoy: not syntax-checked (`nginx -t`, `apachectl configtest`,
  `haproxy -c`, `envoy --mode validate` were not available). Version-dependent features are
  flagged inline: HAProxy `http-request return` (2.2+), Envoy `string_match`, nginx 1.23
  header joining.
- Cloudflare, AWS WAF, Azure: not deployed. Plan- and API-dependent details are flagged:
  Cloudflare `matches` plan availability, AWS CLI blob encoding, `SingleHeader` duplicates,
  Azure block status codes.
- App guards: not run against real frameworks; the packages are not installed.

**Never done:** no trigger seed was sent to, or decoded by, any decoder during this work.
