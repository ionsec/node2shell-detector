# Node2Shell — Rule Provenance & Curated Sources
**Package:** `node2shell-detector/rules` (IONSEC) · **Compiled:** 2026-10-24 · **CVE:** CVE-2026-111497 · **Fingerprint ids:** N2S-01 … N2S-25

Every fingerprint used in this package is copied from the IONSEC Node2Shell research brief
(`BRIEF.md`, compiled 2026-10-24). The brief took each one from the fetched source named
beside it; nothing comes from model memory. Each rule below maps to:

- its N2S id;
- its source URL(s), as listed in the brief;
- its provenance:
  - **VERBATIM**: an exact documented string, byte sequence or request shape;
  - **DERIVED**: a threshold or logic grounded in a documented observation. The derivation
    is stated in the rule.

Brief confidence codes: **V** vendor/upstream, **P** public PoC or scanner source,
**D** derived by IONSEC.

Notes on how some rows were checked:

- *Research cache* means the raw source files that the research agents fetched (PoC repo
  copies, page text). IONSEC used them only to check transcription and placement, never as
  a new fingerprint source.
- *Local clone* means a library source tree fetched during the research and read here to
  confirm option names and decoder behaviour.
- The brotli 1.0.x rendering rows were added at the IONSEC coordinator's request, after
  verification against the google/brotli tags.

---

## A. Rule provenance

### A1. Sigma (`rules/sigma/`, 14 rules)

| File | Sigma id | N2S | Provenance | Sources |
|---|---|---|---|---|
| `web_node2shell_request_content_encoding_br.yml` | 73562698-212c-4098-8fcc-25ef3580815d | N2S-11 | DERIVED: br token, any case, inside lists; body-presence test is IONSEC noise reduction | expressjs.com/en/guide/migrating-5.html · imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/ · nodejs.org/en/blog/vulnerability/october-2026-security-releases · indusface.com/blog/cve-2026-111497-node2shell-nodejs-brotli-rce/ · aikido.dev (workaround) · docs.apify.com/api/client/js/docs/next/concepts/http-compression (FP) |
| `web_node2shell_br_chunked_request.yml` | 783dbd17-c30f-4a5a-9b4b-eb6c1c4ad0fa | N2S-12 | VERBATIM header combination (P) | github.com/tc4dy/CVE-2026-111497-Toolkit |
| `web_node2shell_duplicate_content_encoding.yml` | 51c264c4-6861-4af1-bbf6-f121daf70c70 | N2S-13 | VERBATIM vendor logic (V); how duplicates show in logs is DERIVED | indusface.com/blog/cve-2026-111497-node2shell-nodejs-brotli-rce/ |
| `web_node2shell_checker_useragents.yml` | 7d96412b-e098-4b6d-bd16-56b95ecc2bf3 | N2S-08, N2S-09, N2S-10 | VERBATIM strings (P); N2S-10 repo UNCONFIRMED in the brief | github.com/completetech-security/node2shell-check · github.com/Ghost-Bx1/Node2Shell-CVE-2026-111497 (poc.py:272) · github.com/CaterMaoZi/CVE-2026-111497-POC (research cache: tools/verify_brotli.py) |
| `web_node2shell_ostorlab_differential_probe.yml` | d34c384d-3e65-465a-a663-71396c7afa61 | N2S-07 (+ N2S-01 as third body) | VERBATIM constants (P); Content-Length 10/14/22 restates the payload sizes | github.com/Ostorlab/agent_asteroid (agent/exploits/cve_2026_111497.py) |
| `web_node2shell_lab_route_combo.yml` | 6279dd78-42f5-434f-bdf5-51c065c22ab2 | N2S-22 | VERBATIM route names (P); br requirement per the brief's FP note | github.com/dimasma0305/CVE-2026-111497-POC · github.com/TheFool-TAROT/CVE-2026-111497-brotli-pwn |
| `proxy_node2shell_identity_output_in_response.yml` | 42e4e392-8fbb-4ce2-97ee-b9b84e62e3c7 | N2S-19 | VERBATIM regex (P) | github.com/dimasma0305/CVE-2026-111497-POC · github.com/Arkango/CVE-2026-111497 |
| `proxy_node2shell_verifier_download_useragent.yml` | e0911bcb-9e31-4b44-a85c-fadcba220e8d | N2S-10 | VERBATIM string; egress placement DERIVED from the research cache (the string is sent to nodejs.org / raw.githubusercontent.com) | github.com/CaterMaoZi/CVE-2026-111497-POC |
| `app_nodejs_node2shell_block_switch_error.yml` | 692cd3a6-f017-40dc-9b0b-3f0e327afc9f | N2S-16 | VERBATIM `ERR__ERROR_FORMAT_BLOCK_SWITCH` / `_ERROR_FORMAT_BLOCK_SWITCH` (V+D); DERIVED `ERR_BLOCK_SWITCH` (brotli 1.0.x `return #NAME;`, e.g. Debian bookworm libbrotli1 1.0.9-2+deb12u1) | nodejs.org/en/blog/vulnerability/october-2026-security-releases · github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b · google/brotli tags v1.0.3/v1.0.9/v1.0.10/v1.1.0 (local clone) · github.com/dimasma0305/CVE-2026-111497-POC · lists.debian.org/debian-lts-announce/2026/10/msg00049.html |
| `app_nodejs_node2shell_block_length_1_error.yml` | 4e52fc1d-b1a0-4bc2-8d85-812bca2a44ca | N2S-17 | VERBATIM `ERR__ERROR_FORMAT_BLOCK_LENGTH_1` (P+D); DERIVED `ERR_BLOCK_LENGTH_1` (brotli 1.0.x) | github.com/oven-sh/bun/issues/46352 · google/brotli tags (local clone) |
| `lnx_node2shell_runtime_crash.yml` | a9853605-870f-4f1c-9394-d7833a899f87 | N2S-18 | V (Imperva caveat); the kernel/systemd line shapes are DERIVED | imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/ |
| `proc_creation_lnx_node2shell_runtime_shell_recon.yml` | 9c84faf3-e975-4c5e-9df8-ae8500c01ceb | N2S-21 | DERIVED (D): command list id/whoami/uname/curl/wget from the brief; build-tool filter is IONSEC tuning | github.com/Arkango/CVE-2026-111497 · github.com/dimasma0305/CVE-2026-111497-POC |
| `proc_creation_win_node2shell_runtime_shell_recon.yml` | 5cb7e168-cbdd-4fd6-8a4e-72f86194a620 | N2S-21 | DERIVED: Windows translation of the same command list | as above |
| `file_event_lnx_node2shell_lab_marker.yml` | 41d44453-96e2-4336-aa6a-8dc088d6ada2 | N2S-20 | VERBATIM path (P), lab marker | github.com/TheFool-TAROT/CVE-2026-111497-brotli-pwn |

### A2. Suricata (`rules/suricata/ionsec-node2shell.rules`, private block 1006600–1006699)

| SID | Direction / buffer | N2S | Provenance | Sources |
|---|---|---|---|---|
| 1006600 | to_server · http.method + http.header | N2S-11 | DERIVED (hunting) | expressjs.com migrating-5 · indusface |
| 1006601 | to_server · http.header | N2S-12 | VERBATIM | tc4dy/CVE-2026-111497-Toolkit |
| 1006602 | to_server · http.header.raw | N2S-13 | VERBATIM vendor logic | indusface |
| 1006603 | to_server · http.user_agent | N2S-08 | VERBATIM | completetech-security/node2shell-check |
| 1006604 | to_server · http.user_agent | N2S-09 | VERBATIM | Ghost-Bx1/Node2Shell-CVE-2026-111497 |
| 1006605 | any · http.user_agent | N2S-10 | VERBATIM (repo UNCONFIRMED in the brief) | CaterMaoZi/CVE-2026-111497-POC |
| 1006606 | to_server · raw stream + http.method/header/content_type (mixed) | N2S-07 | VERBATIM | Ostorlab/agent_asteroid |
| 1006610 | to_server · raw stream | N2S-01, N2S-02 | VERBATIM | Node regression test (b5f41529df) via nodejs.org release post · Ostorlab · hypnguyen1209 |
| 1006611 | to_server · raw stream | N2S-03 | VERBATIM | hypnguyen1209/CVE-2026-111497 (via gh0st-nemesis compare_public_pocs.py) |
| 1006612 | to_server · raw stream | N2S-04 | VERBATIM | hypnguyen1209/CVE-2026-111497 |
| 1006613 | to_server · raw stream | N2S-05 | VERBATIM (8-byte header + first 64 of 1,024 `A`) | ZeroHackOrg/node2shell-poc |
| 1006614 | to_server · raw stream | N2S-06 | VERBATIM | Ghost-Bx1/Node2Shell-CVE-2026-111497 (exploit.py) |
| 1006620 | to_client · raw stream + http.header (mixed) | N2S-01…04 | VERBATIM bytes; pcre pins the two variable bytes | imperva (fetch() RCE path) · vercel.com/kb/bulletin/node-js-security-advisory · Ghost-Bx1 `--fetch-trap` |
| 1006630 | to_client from $HOME_NET · http.response_body | N2S-19 | VERBATIM regex; ADAPTED from dimasma0305 lab sid 9001497 rev 2 (licence not stated in the fetched files; logic re-implemented, not copied) | dimasma0305/CVE-2026-111497-POC · Arkango/CVE-2026-111497 |
| 1006631 (commented) | to_client raw socket | N2S-19 | dimasma0305's raw-socket form, ports scoped | dimasma0305/CVE-2026-111497-POC |

### A3. ModSecurity / Coraza (`rules/modsecurity/ionsec-node2shell-dropin.conf`, IDs 1026111400–1026111499)

| ID | Purpose | N2S | Provenance | Sources |
|---|---|---|---|---|
| 1026111400 | reserved for the operator's mode override (`tx.node2shell_mode=block`) | — | — | — |
| 1026111401 | default mode `detect` | — | — | — |
| 1026111402 / 1026111403 | allowlist hook, commented examples (path + IP / shared-secret header) | — | FP handling per brief §5.5 | docs.apify.com (Apify client compression) |
| 1026111410 | Content-Encoding contains the br token | N2S-11 | DERIVED | expressjs.com · indusface · aikido.dev |
| 1026111411 | more than one Content-Encoding header | N2S-13 | VERBATIM vendor logic | indusface |
| 1026111412 | Content-Encoding comma list (httpd merges duplicates) | N2S-13 | DERIVED | indusface |
| 1026111413 | PoC / checker user-agents | N2S-08, N2S-09, N2S-10 | VERBATIM | completetech · Ghost-Bx1 · CaterMaoZi |
| 1026111420 | enforce 415 (block mode) | — | — | 415 rationale: body-parser read.js (research cache), inflation 2.1.0 and @fastify/compress 9.2.2 (local clones) |
| 1026111421 | enforce 403 (block mode) | — | — | — |

The php2shell drop-in uses 1026109601–1026109610, so the ranges do not collide.
1026111497 is deliberately unused.

### A4. YARA (`rules/yara/ionsec_node2shell.yar`)

| Rule | N2S | Provenance | Sources |
|---|---|---|---|
| `IONSEC_N2S_Executable` (private) | — | file-format gate (ELF / Mach-O / fat / PE) | — |
| `IONSEC_Node2Shell_Trigger_Seed_Payload` | N2S-01…06 | VERBATIM bytes | as Suricata 1006610–1006614 |
| `IONSEC_Node2Shell_Trigger_Seed_HexText` | N2S-01…04, N2S-06 | DERIVED (hex-text rendering of the VERBATIM bytes, as the PoC sources carry them) | hypnguyen1209 exploit/poc.py · Ostorlab · Ghost-Bx1 |
| `IONSEC_Node2Shell_Unfixed_Brotli_Decoder_Embedded` | N2S-23 | DERIVED (BLOCK_SWITCH name exists only in fixed brotli; Node v26.12.0 has 0, v26.12.1 has 1) | github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b · b418fa8 / da98063 / 50a9b70 |
| `IONSEC_Node2Shell_Unfixed_Brotli_Decoder_Library` | N2S-23 | DERIVED (NUL-bounded table entry = the decoder's own table) | as above |
| `IONSEC_Node2Shell_Brotli_Linked_Consumer_PreFix_Constants` | N2S-23 | DERIVED; brief §3 / §5.3 (Debian nodejs links the system libbrotli; `--shared-brotli`) | security-tracker.debian.org/tracker/CVE-2026-111497 |
| `IONSEC_Node2Shell_Unfixed_Brotli_1_0_x_Decoder` | N2S-23 | DERIVED (brotli 1.0.x bare names; coordinator-verified) | google/brotli tags v1.0.3 / v1.0.9 / v1.0.10 (50a9b70) |
| `IONSEC_Node2Shell_Unfixed_Brotli_DecodeC_Source` | N2S-24 | DERIVED from the fix diff | github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b |

### A5. Edge and app snippets

| Files | N2S | Provenance | Sources |
|---|---|---|---|
| `rules/edge/*-inbound-*`, `cloudflare-waf-custom-rules.txt`, `aws-waf-reject-br-rule.json`, `azure-*-reject-br-rule.json` | N2S-11 (+ N2S-13 where the platform can count headers) | DERIVED from the vendor workarounds (reject br request bodies at proxy / LB / middleware; Aikido, Indusface) | aikido.dev · indusface · vercel.com/kb/bulletin/node-js-security-advisory · developers.cloudflare.com/changelog/product/waf/ |
| `rules/edge/*-egress-*` | outbound path (brief §5.2, §5.6 #3) | DERIVED from Aikido's outbound advice (drop br from Accept-Encoding **and** never decode br responses) and Vercel's caveat | aikido.dev (Python / "HTTP2Shell" post) · vercel.com/kb/bulletin/node-js-security-advisory · Envoy GHSA-3wvj-j6qm-62mr via openwall.com/lists/oss-security/2026/10/23/25 |
| `rules/app/*` | N2S-11 | DERIVED; option names read in local clones (@fastify/compress 9.2.2, aiohttp 3.14.5, @koa/bodyparser 6.1.0, koa-body 8.0.1, inflation 2.1.0) and in body-parser read.js (research cache) | brief §5.1 / §5.2 · expressjs.com · docs.apify.com |

---

## B. Fingerprints and intel not turned into rules (and why)

| Item | Why not a rule |
|---|---|
| **N2S-14** (POST `/` with `Content-Type: application/octet-stream` + `Content-Encoding: br`, tc4dy) | Fully covered by the N2S-11 rules. The extra constraints (root path, octet-stream) would only add a near-duplicate alert. |
| **N2S-15** (~23 MB br body built from `1 << 24` literals, 6mile / OpenSourceMalware) | The only fingerprint is "very large + br". The brief gives an approximate size, so any byte threshold would be invented. Covered by the N2S-11 rules (any size). |
| **N2S-25** (runtime self-test: feed N2S-01 to the runtime's own decoder) | Not a detection rule. It executes the trigger in a throwaway child process and belongs to the opt-in host tool. |
| **N2S-01…06 in Sigma / ModSecurity** | Binary request bodies do not survive text access logs. The ModSecurity drop-in decides in phase 1 on headers, before any body byte reaches the backend. Covered by Suricata (raw stream) and YARA. |
| dimasma0305 evidence hashes (`trigger_sha256=b7a6…4df4`, two-part `a6b8…bebd` + `64cd…c724`, brief §6) | Whole-file hashes of one lab harness's trigger artefacts. They need exact carving boundaries, and the byte-level seed rules already cover the trigger family. |
| hafizhrf artefact sizes, TheFool-TAROT `poc/dos.br` 86 B | Sizes only; contents were not fetched, so there is no fingerprint. |
| Ostorlab reading the Node version from `X-Powered-By` / `Server` | Response-side reconnaissance, not an attack fingerprint. |
| trailofbits/brotli-checker `fingerprints.json` (20 `decode.c` SHA-256s) | The brief says the licence was not checked, so the list must not be copied. The N2S-24 YARA rule checks the logic instead. |
| `GET /file?p=` and `GET /warm` (TheFool-TAROT), `GET /health` (dimasma0305) | Common route names with no body. Kept as triage context in the N2S-22 rule, not as selections. |
| errno `-17` / `-9` alone | They collide with EEXIST / EBADF in Node file-system errors. Only the code strings are used. |
| Outbound `Accept-Encoding: br` from Node clients | NORMAL behaviour (undici, axios, got, node-fetch 3, needle). Never alert on it (brief §5.5). |

---

## C. Sources (from the brief)

### C1. Record, advisories, upstream

| Publisher | Item | URL |
|---|---|---|
| CVE Program (CNA Google) | CVE-2026-111497 record | https://cveawg.mitre.org/api/cve/CVE-2026-111497 |
| Node.js | "Wednesday, October 21, 2026 Security Releases" | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| google/brotli | fix commit 0ed4268a "Detect and report invalid stream earlier." (release twins b418fa8 / da98063 / 50a9b70) | https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b |
| GitHub | GHSA-9v8h-qqgm-4m35 (PyPI Brotli / brotlicffi) | https://github.com/advisories/GHSA-9v8h-qqgm-4m35 |
| oss-security | Envoy downstream GHSA-3wvj-j6qm-62mr | https://www.openwall.com/lists/oss-security/2026/10/23/25 |
| Red Hat | CVE page (Important, CVSS 3.1 8.1) | https://access.redhat.com/security/cve/CVE-2026-111497 |
| Ubuntu | CVE page | https://ubuntu.com/security/CVE-2026-111497 |
| Debian | security tracker; DLA-4855-1 | https://security-tracker.debian.org/tracker/CVE-2026-111497 · https://lists.debian.org/debian-lts-announce/2026/10/msg00049.html |
| AWS | ALAS entry | https://explore.alas.aws.amazon.com/CVE-2026-111497.html |
| CISA | vulnrichment (ADP SSVC) | https://github.com/cisagov/vulnrichment |
| NCSC-NL | NCSC-2026-0453 | https://advisories.ncsc.nl/2026/ncsc-2026-0453.html |
| GovCERT.HK | A26-10-37 | https://www.govcert.gov.hk/en/alerts_detail.php?id=2126 |

### C2. Research, vendor protections, scanners

| Publisher | Item | URL |
|---|---|---|
| Imperva Red Team | "Node2Shell: From Brotli Data to Remote Code Execution" (22 Oct) | https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/ |
| Vercel | Node.js security advisory bulletin (WAF rules, response-side caveat) | https://vercel.com/kb/bulletin/node-js-security-advisory |
| Indusface | AppTrana emergency rules (br bodies, list variants, duplicate Content-Encoding) | https://www.indusface.com/blog/cve-2026-111497-node2shell-nodejs-brotli-rce/ |
| Cloudflare | WAF changelog (no Node2Shell rule through 22 Oct) | https://developers.cloudflare.com/changelog/product/waf/ |
| Tenable | Nessus plugin 370490 | https://www.tenable.com/plugins/nessus/370490 |
| Qualys | blog, 23 Oct | https://blog.qualys.com/product-tech/2026/10/23/node-js-patches-brotli-remote-code-execution-flaw-find-vulnerable-runtimes-before-attackers-do |
| Aikido | Node2Shell timeline and "HTTP2Shell" Python follow-up | aikido.dev |
| OpenSourceMalware | "Node2Shell affects Python" | https://opensourcemalware.com/blog/node2shell-affects-python |
| Hadrian | "Node2Shell: what we know …" | https://hadrian.io/vulnerability-alerts/node2shell-what-we-know-about-the-node-js-brotli-rce-cve-2026-111497 |
| Cycode | Node2Shell blog | https://cycode.com/blog/node2shell-cve-2026-111497/ |
| Apify | JS client HTTP compression (legitimate br sender) | https://docs.apify.com/api/client/js/docs/next/concepts/http-compression |
| Express | Migrating to Express 5 | https://expressjs.com/en/guide/migrating-5.html |
| Bun | issue oven-sh/bun#46352 | https://github.com/oven-sh/bun/issues/46352 |

### C3. Public PoC and scanner repositories (read via the GitHub API by the research agents; nothing executed)

dimasma0305/CVE-2026-111497-POC · hypnguyen1209/CVE-2026-111497 · gh0st-nemesis/node2shell-poc ·
TheFool-TAROT/CVE-2026-111497-brotli-pwn · Arkango/CVE-2026-111497 · ZeroHackOrg/node2shell-poc ·
Ghost-Bx1/Node2Shell-CVE-2026-111497 · tc4dy/CVE-2026-111497-Toolkit · CaterMaoZi/CVE-2026-111497-POC ·
completetech-security/node2shell-check · Ostorlab/agent_asteroid · 6mile/node-python2shell ·
lesterlam/node2shell · s1ko/poc-cve-2026-111497 · trailofbits/brotli-checker ·
AdapptOnAzure/cve-2026-111497-mitigation (third-party Azure rule, not Microsoft's).

---

## D. Provenance discipline

- **Fingerprints.** Every string, byte sequence and request shape is copied from the
  brief. The brief copied it from the source in its tables.
- **No invented fingerprints.** The following are labelled DERIVED in the rules, with the
  derivation stated:
  - tuning (the body-presence test, the build-tool filters);
  - log-line renderings (kernel and systemd crash lines, the brotli 1.0.x error names);
  - translations (Windows commands, the hex-text form of the seeds).
- **Adaptation.** SID 1006630 adapts dimasma0305's lab rule 9001497. The attribution and
  the delta are in the Suricata file header. No rule text was copied, because no licence
  was recorded.
- **Attribution hygiene.** No vendor endorses these rules or contributed to them. The
  vendor protections named in the README (Imperva, Vercel, Indusface, Tenable 370490) are
  situational awareness, not reproduced logic.
