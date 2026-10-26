<div align="center">

<!-- ══════════════════════════════════════════════════════════════════ -->
<!--  node2shell-detector — hero banner (brand: crimson / dark)          -->
<!-- ══════════════════════════════════════════════════════════════════ -->

# node2shell-detector

**Host-side detections for Node2Shell (CVE-2026-111497)**

> *One pass, four checks: runtime posture, decoder fingerprints, dependency exposure, log fingerprints — plus an opt-in behavioural self-test.*

An out-of-bounds write in Google's Brotli C decoder, which **Node.js bundles** (so do Bun and
the PyPI `Brotli` / `brotlicffi` wheels). It is reachable whenever an application
decompresses attacker-influenced Brotli data through `node:zlib` — a `Content-Encoding: br`
request body behind Express 5 / body-parser 2.x, or the response of a server the app fetches
from. Node.js shipped the fix on 2026-10-21: **22.23.4 / 24.22.1 / 26.12.1**. Every other Node
line is end-of-life with **no fix**. Bun: **1.4.4**. Upstream brotli: **1.0.10 / 1.1.1 / 1.2.1**.
This package answers the on-shift question four ways, and ships the network coverage beside it
(see [Rules package](#rules-package)).

```bash
# 1) posture + decoder fingerprints with defaults (discovers node/nodejs/bun/deno on PATH, nvm, fnm,
#    volta, asdf, n, Homebrew, /usr/bin, /usr/local/bin; libbrotlidec in the standard lib dirs;
#    Python Brotli modules in the running interpreter's site-packages)
python3 -m node2shell_detector

# 2) point at the runtime that actually serves traffic, and at the project it serves
python3 -m node2shell_detector --node-bin /opt/app/node/bin/node --project /srv/app

# 3) scan logs: access log + application / journald text (repeatable --log; .gz supported)
python3 -m node2shell_detector --log /var/log/nginx/access.log --log /var/log/app/stderr.log

# 4) fingerprint an Electron app or any folder of binaries / vendored decode.c
python3 -m node2shell_detector --check binaries --scan-dir /Applications/SomeApp.app

# 5) machine-readable report
python3 -m node2shell_detector --project /srv/app --log /var/log/nginx/access.log --json | jq .
```

<!-- Hero buttons -->
[![Quick Start](https://img.shields.io/badge/Quick_Start-Get_Started-e63946?style=for-the-badge&logo=terminal&logoColor=white&labelColor=0a0a0f)](https://github.com/ionsec/node2shell-detector#host-tool)
[![Node.js advisory](https://img.shields.io/badge/Node.js-Security_Release_2026--10--21-0a0a0f?style=for-the-badge&labelColor=1a1a2e)](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
[![CVE](https://img.shields.io/badge/CVE-2026--111497-e63946?style=for-the-badge&labelColor=0a0a0f)](https://www.cve.org/CVERecord?id=CVE-2026-111497)
[![License](https://img.shields.io/badge/License-AGPL--3.0-e63946?style=for-the-badge&labelColor=0a0a0f)](LICENSE)

---

**Developed by [IONSEC](https://github.com/ionsec)** · repo: <https://github.com/ionsec/node2shell-detector>

</div>

---

Every fingerprint, CVE fact, fixed version and threshold in this package comes from the IONSEC
research brief (compiled 2026-10-24 from fetched primary sources — the Node.js release post, the
google/brotli tags and commits, GHSA-9v8h-qqgm-4m35, vendor and distro advisories, and the public
write-ups). **No fingerprint is invented.** Findings carry their provenance: `VERBATIM` = exact
documented string / shape / version; `DERIVED` = a threshold or inference grounded in a documented
observation, with the derivation stated inline. Findings cite the brief's fingerprint ids
(`N2S-01` … `N2S-25`). Where the brief says **UNCONFIRMED**, the tool says *unknown / verify* and
never issues a guessed verdict.

**Status as of the brief (2026-10-24):** CNA CVSS v4.0 **9.2**; Red Hat *Important*, CVSS 3.1
**8.1**; Node.js rates it *High*. No confirmed exploitation anywhere the research looked; CISA ADP
SSVC: Exploitation *none*, Automatable *no*, Technical Impact *total*; not in KEV. Imperva reproduced
code execution on stock Node 24.22.0 (Linux arm64) in a lab — "did not succeed on every attempt".
A public PoC landscape exists (40+ repos), so treat the *attempt* shapes below as live.

# Host tool

## What it checks — and what a finding can actually tell you

| Check | What it does | What a finding means |
|---|---|---|
| **HOST POSTURE** | Runtime inventory and verdicts: `node` / `nodejs` (PATH, nvm, fnm, volta, asdf, n, Homebrew, `/usr/bin`, `/usr/local/bin`, `--node-bin`), `bun`, `deno`; `node --version` and a `node -p` probe of `process.versions` + `node_shared_brotli`; shared-brotli builds resolved against the distro / Homebrew package; Python `Brotli` / `brotlicffi` read from `site-packages` metadata (no imports); the N2S-20 marker file | **Exposure.** Not an incident. A version-table verdict is only as good as the build is official — see the evidence hierarchy below. |
| **BINARY FINGERPRINTS** | Stream-scans binaries for the Brotli error-table strings (**N2S-23**, derivation below): node / bun, `libbrotlidec*`, Python `_brotli*.so` / `_brotlicffi*.so` / `.pyd`, project `*.node` addons, and any ELF / Mach-O (incl. universal) / PE under `--scan-dir` (e.g. Electron frameworks); checks vendored `decode.c` sources (**N2S-24**) | **Derived evidence** of which decoder a file carries — stronger than a version string, weaker than behaviour. No table in the file = *inconclusive*, never *patched*. |
| **DEPENDENCY EXPOSURE** | Lockfiles (`package-lock.json` v1/v2/v3, `npm-shrinkwrap.json`, `yarn.lock` classic + berry, `pnpm-lock.yaml`, text `bun.lock`), `node_modules` (bounded walk), Python requirements / `poetry.lock` / `uv.lock` / `pdm.lock` / `Pipfile.lock`, `go.mod` / `go.sum`, `Cargo.lock`, `Gemfile.lock`, `pom.xml` / `build.gradle`, Dockerfile and compose `node` / `oven/bun` tags — against the brief's exposure table | **Reachability.** An npm / PyPI package only decides whether attacker bytes reach a decoder; **the runtime decides exploitability** (brief §5). Server-side decoders: warn, critical when the same run found a vulnerable runtime. |
| **LOG SCAN** | Access logs (combined, common, LTSV, JSON lines) and application / stderr / journald text against the documented fingerprints: scanner UAs, `Content-Encoding: br` request shapes, seed bytes in escaped bodies, the Ostorlab sweep, lab routes, decoder error codes, crash lines, `id` output in a response | **Attempt evidence, not execution.** A hit timestamps an attempt and gives hunting context. |
| **SELF-TEST** *(opt-in, `--self-test`)* | Feeds the public 22-byte Node regression vector to each node / bun binary's **own** decoder inside a throwaway child process, with a timeout (**N2S-25**) | **Ground truth for that binary:** `ERR__ERROR_FORMAT_BLOCK_SWITCH` / `-17` = fixed; `BLOCK_LENGTH_1` / `-9`, any other decoder error, or a crash = vulnerable behaviour. |

### Honest limits

- **A log hit never proves execution.** Imperva calls unexpected process exits a triage clue,
  "not a reliable stand-alone sign of exploitation". Correlate `Content-Encoding: br` requests with
  crash records, response anomalies (`uid=… gid=…` in a response body — N2S-19) and the host
  checks. The **fetch-trap** direction (your service fetching from an attacker-controlled server
  that answers `br`) needs no inbound request: a WAF or an access log of *inbound* traffic never
  sees it.
- **`process.versions.brotli` does not change when the fix lands.** It is computed from
  `BrotliEncoderVersion()` and the fix commit does not touch `version.h`, so a fixed 24.22.1 still
  reports `1.2.0`. The tool prints it for context and **never uses it for a verdict**. Use the Node
  version for official builds, the distro package for shared-brotli builds, the decoder
  fingerprint, or the self-test.
- **Evidence hierarchy.** When checks disagree, trust, in this order: behavioural self-test
  (N2S-25) › decoder fingerprint of the binary (N2S-23) › shared-library / package verdict ›
  version table. With `--self-test` the behavioural result **overrides** the version / package
  verdict for that binary (a vendor backport without a version bump stops false-flagging). Without
  it, a version-vs-fingerprint disagreement is reported as `EVIDENCE_CONFLICT` (warn) instead of
  being resolved silently.
- **Posture is point-in-time** and covers the runtimes it can see. It does not enter containers,
  and managed platforms (AWS Lambda, Vercel, Netlify, Google Cloud Functions / Run, Azure Functions)
  have no public patch level in the brief — verify `process.version` from inside the function.
  AWS Elastic Beanstalk / App Runner and Amazon Linux runtimes were still on unfixed builds when the
  brief was compiled.
- **EOL honesty.** Node 25 / 23 / 21 / 20 / ≤ 19 have **no fixed release**; the only remedies are
  moving to 22.23.4+ / 24.22.1+ / 26.12.1+ or a vendor build that backports the fix (verify it with
  N2S-23 / N2S-25). The brief verified lines back to v12.22.12; for anything older the tool says so.
- **After patching, restart every process** — a patched binary on disk is not loaded into running
  processes. **Container images must be rebuilt, not restarted** (docker-node moved the 22 / 24 / 26
  images on 2026-10-21; floating tags are reported as *info — rebuild*).
- **Shared-brotli builds** (`--shared-brotli`, including Homebrew's Node) link the system
  `libbrotlidec`: the Node version says nothing and the verdict moves to the library (table below).
  Nothing is guessed when the library cannot be attributed: *unknown / verify*, warn.
- **Strings are derived evidence.** A stripped error table reads *inconclusive*. A file that links
  **two** Brotli copies (an Electron Framework carries Chromium's network decoder and Node's) is
  fixed only if every table found is; the Electron case is downgraded to *info* because the brief
  lists Electron as **UNCONFIRMED**.
- **Deno** uses Rust decoders (brotli 6.0.0 + brotli-decompressor 4.0.1 in 2.9.8's `Cargo.lock`),
  not the C library. Whether the Rust port carries the same flaw is **unresolved, not cleared** —
  reported as *info*. The same holds for the Rust crate in `Cargo.lock`.
- **The edge is covered by the separate rules package** — host tooling complements, not replaces,
  network / WAF coverage (see [Rules package](#rules-package)).

### Networked / not networked

Nothing in this tool opens a socket (a test asserts the package imports no network module).
Posture shells out to **local** commands with timeouts — `node --version`, `node -p`, `bun --version`,
`deno --version`, `ldd` / `otool -L`, `dpkg-query`, `rpm`, `apk`, `brew list` (with Homebrew's
auto-update and analytics switched off) — after stripping `NODE_OPTIONS` / `BUN_OPTIONS` from the
child environment; everything else reads local files. There is no update or IOC-feed fetching
feature — IOC freshness is your intel process's job. The opt-in self-test spawns a child **runtime**
on a local script; the child has no reason to, and the script does not, load any network module.

---

## Run

From this directory (`python3` = 3.10+, standard library only):

```
python3 -m node2shell_detector
```

## CLI

| Flag | Meaning |
|---|---|
| `--project PATH` | project directory for the dependency scan (repeatable); its `.venv` / `venv` site-packages are read too |
| `--log PATH` | log file(s) to scan; repeatable; plain or `.gz` |
| `--node-bin PATH` | extra node binary to interrogate (repeatable); default discovery covers PATH, nvm, fnm, volta, asdf, n, Homebrew, `/usr/bin`, `/usr/local/bin` |
| `--bun-bin PATH` | extra bun binary (repeatable); default probes PATH and `~/.bun/bin/bun` |
| `--deno-bin PATH` | extra deno binary to report on (repeatable); default probes PATH and `~/.deno/bin/deno` |
| `--python-site PATH` | extra `site-packages` / `dist-packages` directory to read (repeatable) |
| `--scan-dir PATH` | directory tree to fingerprint for ELF / Mach-O (incl. fat) / PE binaries and vendored `decode.c` (repeatable), e.g. an Electron app |
| `--check NAME` | run only this check: `posture` / `binaries` / `deps` / `logs` (repeatable; default: all four) |
| `--self-test` | **opt-in** behavioural test (N2S-25) of each node / bun binary — read [Self-test](#self-test-opt-in) first |
| `--self-test-timeout SEC` | timeout per self-test child (default 10) |
| `--no-discover` | inspect **only** what you name (`--node-bin` / `--bun-bin` / `--deno-bin` / `--scan-dir` / `--python-site` / `--project`): skip PATH, version-manager, Homebrew, system-library and running-interpreter discovery — useful inside containers and for reproducible runs |
| `--log-format FMT` | `auto` (default) / `combined` / `common` / `ltsv` / `json` |
| `--max-lines N` | lines scanned per log file (default 200,000) |
| `--max-binary-mb MB` | skip binaries larger than this when fingerprinting (default 512) |
| `--probe-timeout SEC` | timeout per local probe command (default 10) |
| `--json` | JSON report (same content as text mode) |
| `--quiet` | text mode: only warn / critical finding lines |
| `--version`, `-h`, `--help` | metadata / help |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | checks ran; no warn / critical finding |
| `1` | at least one warn / critical finding — inspect the report |
| `2` | invocation / resource problem (bad flag values, missing explicit paths) |

### Reading the output

- Severities: `critical` (act now: a vulnerable or EOL runtime, a decoder without the fix, `id`
  output in a response), `warn` (real exposure surface or attempt evidence), `info` (context —
  including every *unknown / verify*), `ok` (verified fixed / mitigated).
- Every finding carries `basis` (`VERBATIM` / `DERIVED` provenance), `ids` (the brief's `N2S-xx`
  fingerprints it rests on) and, for log findings, the file, line and a **defanged** evidence
  excerpt (IPv4 addresses are `[.]`-mangled; control bytes are escaped).
- Per log rule, up to the first 8 line hits are shown with `repeat_count` showing the real volume;
  the per-file list is capped at 60 entries severity-first. `finding_count` per file is the
  untruncated total. Full detail: `--json`.
- Set `NODE2SHELL_DEBUG=1` to include tracebacks of a failed check in the error list.

## Posture verdicts

| Runtime / line | Verdict | Source |
|---|---|---|
| Node 22 < 22.23.4, 24 < 24.22.1, 26 < 26.12.1 | **critical** — a fixed release exists | brief §1, §3 |
| Node ≥ the fixed release on those lines | ok (restart everything) | §3 |
| Node 25 / 23 / 21 / 20 / ≤ 19 | **critical** — EOL, **no fix**, move lines | §3 |
| Node on a line newer than the brief's table | info — *unknown / verify* | — |
| pre-release / nightly / custom version string | warn — *unknown / verify* (use N2S-23 / N2S-25) | — |
| Shared-brotli Node (`node_shared_brotli`, or `ldd` / `otool -L` shows `libbrotlidec`) | the **system library** decides (next table) | §3 |
| Bun < 1.4.4 | **critical** — every earlier release affected | §3, §5.3 |
| Bun ≥ 1.4.4 | ok | §3 |
| Deno | info — Rust decoder, status unresolved | §5.3 |
| Python `Brotli` < 1.2.1 / `brotlicffi` 1.0.9.0 – 1.2.0.2 | **critical** if `aiohttp` is installed beside it (its server decodes `br` request bodies by default), else warn; Scrapy, requests, httpx, urllib3 and pip are named as consumers | §5.4 |
| `/tmp/pwn_marker.txt` exists (N2S-20) | warn — a lab-PoC marker; trivially renamed, may be your own test | §7 |

Shared-brotli resolution (the library file itself is also fingerprinted with N2S-23; a package /
file disagreement is reported as a conflict, warn):

| Platform | Evidence | Fixed when |
|---|---|---|
| Debian / Ubuntu | `zgrep CVE-2026-111497 /usr/share/doc/libbrotli1/changelog.Debian.gz`, then a `dpkg` version compare (a small, correct comparator: epochs, `~`, letters vs non-letters) | the changelog names the CVE, or the version is ≥ bookworm `1.0.9-2+deb12u1` / trixie `1.1.0-2+deb13u1` (or an upstream-fixed 1.0.10 / 1.1.1 / 1.2.1+). forky / sid `1.2.0-4` was unfixed at fetch time; Ubuntu listed brotli *Needs evaluation* with no fixed package on 2026-10-23 |
| RPM (RHEL / Fedora …) | `rpm -q --changelog brotli \| grep CVE-2026-111497` | the changelog names the CVE (Red Hat: Important, no fixed package listed at fetch time) |
| Alpine | `brotli-libs` | ≥ `1.2.1-r0` (`1.1.1-r0` on 3.21) |
| Homebrew | Cellar path of the linked library, else `brew list --versions brotli` | brotli ≥ 1.2.1 |
| anything else | — | warn — *unknown / verify* |

## Binary fingerprints (N2S-23 / N2S-24)

**Derivation (DERIVED).** `BrotliDecoderErrorString()` returns the stringified error name, so a
compiled decoder carries `_ERROR_FORMAT_BLOCK_LENGTH_1` (present before the fix) and — only after the
fix — `_ERROR_FORMAT_BLOCK_SWITCH`. The BLOCK_SWITCH code (-17) and its name were introduced only by
the fix commits (`git log -S`: `0ed4268` / `b418fa8` / `da98063` / `50a9b70`); Node v26.12.0 has 0
occurrences of the string, v26.12.1 has 1.

| The file has … | Verdict |
|---|---|
| `_ERROR_FORMAT_BLOCK_SWITCH` | **ok** — fixed decoder |
| `_ERROR_FORMAT_BLOCK_LENGTH_1` but not `…_BLOCK_SWITCH` | **critical** — decoder without the CVE-2026-111497 fix |
| neither | **info** — no Brotli error table, inconclusive (dynamic link, other language, stripped) |

**Brotli 1.0.x builds name their errors without the prefix (DERIVED — not in the brief; verified against
the google/brotli tags).** In v1.0.9 and v1.0.10 `BrotliDecoderErrorString` uses `return #NAME;`; from
v1.1.0 it is `return #PREFIX #NAME;`. A decoder built from 1.0.x — Node 12–16's bundled 1.0.9, Debian
bookworm's system `libbrotlidec.so.1` (1.0.9, fixed as `1.0.9-2+deb12u1` through the 1.0.x-branch fix) —
therefore carries the **bare** strings `BLOCK_LENGTH_1` / `BLOCK_SWITCH`, each as its own NUL-terminated
string (the NUL delimiters matter: `BLOCK_LENGTH_1` is also the tail of the 1.1+ name). The tool
recognises such a table by bare `BLOCK_LENGTH_1` **plus** a corroborating bare name (`EXUBERANT_META_NIBBLE`
or `CONTEXT_MAP_REPEAT`) and no `_ERROR_FORMAT_` prefix: bare `BLOCK_SWITCH` in it → fixed, absent →
vulnerable. A bare `BLOCK_*` string **without** the corroboration is ambiguous → *unknown*, never
"patched". Node's error codes on these builds read `ERR_BLOCK_SWITCH` / `ERR_BLOCK_LENGTH_1` (the log scan
matches both forms). During development the verdicts were checked against real builds of the upstream tags
(compile-only, nothing executed): **v1.0.9 → vulnerable, v1.0.10 → fixed, v1.1.0 → vulnerable, v1.1.1 → fixed.**

Details:

- **Targets.** Discovered node / bun binaries; `libbrotlidec*.so*` / `*.dylib` in the standard library
  directories (Linux multiarch, `/usr/local/lib`, Homebrew prefixes); the library a shared-brotli Node
  links; Python `_brotli*.so` / `_brotlicffi*.so` / `.pyd` in the scanned site-packages; `*.node`
  addons in `--project` `node_modules`; every ELF / Mach-O (incl. fat) / PE file under `--scan-dir`
  (files without a Brotli table are counted, not listed).
- **Streaming.** Files are read in 4 MiB chunks with marker-length overlap (a marker straddling a
  chunk boundary is found); a per-file size cap (`--max-binary-mb`, default 512) skips larger files
  with an *info* finding. Mach-O universal binaries are scanned **per slice** and the worst slice
  decides.
- **Source check (N2S-24).** Any `decode.c` containing `DecodeBlockTypeAndLength`:
  `max_block_type <= 1` followed by `return BROTLI_FALSE;` with no
  `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` → *vulnerable vendored source* (warn: a source file only says
  what would be compiled); with the constant → fixed; anything else → *unrecognised* (info). The same
  shapes hold in v1.0.9 / v1.0.10.
- **Electron.** Discovery is by `--scan-dir` only. The marker cannot say which of two linked copies
  carries it, and the brief lists Electron as **UNCONFIRMED** (every stable line checked still carried
  pre-fix Node 24.x; Chromium's decoder pin likely contains the fix) — *fixed* is reported as *info*.

## Dependency exposure (brief §5.1, §5.2)

All Node-side npm decoders end in Node's own `zlib.createBrotliDecompress`: **no npm upgrade fixes
anything, and no downgrade is needed.** Ranges below are the brief's; a package outside its range is
not flagged.

| Server side — decodes `br` request bodies | Affected | Switch |
|---|---|---|
| `body-parser` / `express` | body-parser 2.x (2.0.0–2.4.0 read) · express ≥ 5.0.0 | `inflate: false` (rejects every compressed body) |
| `inflation` / `co-body` | inflation ≥ 2.1.0 · co-body ≥ 5.0.0 | — / don't parse `br` requests |
| `@koa/bodyparser`, `koa-bodyparser`, `koa-body` | ≥ 5.0.0 · 2.4.0, 2.5.x, 4.1.0, 4.2.x–4.4.x · ≥ 2.4.0 | `enableTypes` / `json`, `urlencoded`, `text: false` |
| `@fastify/compress` / `fastify-compress` | ≥ 5.0.0 · ≥ 3.1.0 | `globalDecompression: false`, per-route `decompress: false`, or `requestEncodings` without `br` |
| `@nestjs/platform-express` | ≥ 11.0.0 (Nest 8–10 = Express 4: no) | `bodyParser: false` + your own parser |
| `@apollo/server` · `@strapi/strapi` · `parse-server` | 5.x · 5.x · 9.x | none / none / none |
| *Verified not decoders:* Express 4 / body-parser 1.x (415 unsupported encoding) | reported once as **ok** | — |

| Client side — decodes `br` responses | Affected | Switch |
|---|---|---|
| `axios` | ≥ 1.0.0 | `decompress: false` |
| `got` | 11–16 | `decompress: false` |
| `node-fetch` | 3.x (2.x: **UNCONFIRMED** → *unknown / verify*, info) | `compress: false` |
| `needle`, `superagent`, `ky`, `decompress-response` | as read in the brief | — |
| *Usage not visible → always info:* `http-proxy-middleware` (`responseInterceptor`), `next` images (`remotePatterns` / `domains`), `@whatwg-node/server` / `graphql-yoga` (`useContentEncoding()`), `n8n` (partly), `@remix-run/web-fetch` | | |

Severity: a **server-side** decoder is **warn**, escalated to **critical** when posture found a
vulnerable runtime in the same run (the finding's `related` lists it); a **client-side** decoder is
**info**, or **warn** with a vulnerable runtime; the *usage-not-visible* rows stay info. Run
`--check posture --check deps` together on the host that serves the project. Other ecosystems:
PyPI `Brotli` / `brotlicffi` (critical with `aiohttp`, else warn; version floors that still admit
1.2.0 are info), Go `github.com/andybalholm/brotli` < v1.2.7 (a pseudo-version → *verify*), Cargo
`brotli-decompressor` (info, unresolved), RubyGems `brotli` < 0.9.1, Maven `brotli4j` < 1.24.0, and
`FROM node:<tag>` / `oven/bun:<tag>`: pinned vulnerable tags and EOL lines are critical, floating
tags are *info — rebuild*. `package.json` ranges are **not** resolved (only locked / installed
versions), and how your code uses a library is not analysed.

## Log formats & what each rule needs

Per line auto-detect: **combined** and **common** (Apache / nginx), **LTSV**, **JSON lines** (nginx-style
flat objects, Caddy-style nested `request.headers`, and Docker `json-file` wrappers `{"log": "…"}`, which
are unwrapped). Keys used: `req|request`, `method`, `uri|path|url`, `host` (LTSV) / `remote_addr|remote_ip`,
`status`, `ua|user_agent|http_user_agent`, `body|request_body`, `resp_body|response_body`,
`content_length`, `request_length`, `body_bytes_received`.

The `Content-Encoding: br` rules read **request headers**, which standard combined / common logs do
not contain. Log them as LTSV or JSON. Request-header fields are recognised by a key **ending in**
`content_encoding` / `transfer_encoding` / `content_type` (`http_content_encoding`, `req_content_encoding`,
or Caddy's `request.headers.Content-Encoding`); a key containing `resp`, `response`, `sent`, `upstream`,
`downstream`, `origin`, `backend` or the token `out` is **response-side and ignored** — so a normal
brotli-compressed *response* (`sent_http_content_encoding: br`) and a normal `Accept-Encoding: gzip,
deflate, br` request never alert.

```nginx
log_format n2s "host:$remote_addr\ttime:$time_iso8601\treq:$request\tstatus:$status\tsize:$body_bytes_sent"
               "\tua:$http_user_agent\tcontent_encoding:$http_content_encoding"
               "\ttransfer_encoding:$http_transfer_encoding\tcontent_type:$http_content_type"
               "\tcontent_length:$http_content_length\trequest_length:$request_length";
access_log /var/log/nginx/n2s.log n2s;
```
```apache
LogFormat "host:%h\ttime:%{%Y-%m-%dT%H:%M:%S%z}t\treq:%r\tstatus:%>s\tsize:%B\tua:%{User-Agent}i\tcontent_encoding:%{Content-Encoding}i\ttransfer_encoding:%{Transfer-Encoding}i\tcontent_type:%{Content-Type}i\tcontent_length:%{Content-Length}i\trequest_length:%I" n2s
```

| Needs | Rules |
|---|---|
| any log (UA, text, crash) | N2S-08/09/10 UAs · N2S-16/17 decoder error codes · N2S-18 crash lines · N2S-19 `id` output · seed bytes in URLs |
| request headers (LTSV / JSON) | N2S-11 `br` token (also inside lists) · N2S-12 `br` + `chunked` without Content-Length · N2S-13 duplicate `Content-Encoding` · N2S-14 `br` + `application/octet-stream` `POST /` · N2S-15 very large `br` body · N2S-22 lab routes **together with `br`** from the same client |
| a body field (`$request_body`, escaped) | N2S-01…06 seed bytes — `\xNN`, JSON `\u00NN`, `%NN` and plain-hex forms are decoded before matching; N2S-05 also as a truncated prefix |
| request-length fields | N2S-07 Ostorlab sweep (same client POSTs ≥ 3 of `/`, `/api`, `/api/v1`, `/graphql` with tiny bodies) · N2S-15 |

Caveats the tool applies for you: `errno: -17` is **EEXIST** and `errno: -9` is **EBADF** in libuv, so the
errno forms only count beside brotli / zlib / decompression context without `EEXIST` / `EBADF` (the
`ERR__ERROR_FORMAT_*` codes need no context); bare `uid=0 gid=0` fields on auditd-style lines are not `id`
output; the real Apify JavaScript client brotli-compresses request bodies ≥ 1,024 B by default, so
N2S-11 can hit a legitimate sender — rule it out first.

## Derived thresholds (documented shapes, conservative cut-offs)

Tune in `node2shell_detector/fingerprints.py` (`THRESHOLDS`) — tuning parameters, not fingerprints:

| Rule | Threshold | Documented basis |
|---|---|---|
| OSTORLAB_PROBE_SWEEP (N2S-07) | ≥ 3 of the 4 candidate paths; tiny = ≤ 64 B (`content_length`) or ≤ 1,024 B (`request_length`, which includes headers); warn with `br` or the documented 10 / 14 / 22 B bodies, else info | Ostorlab's probe bodies and paths |
| BR_LARGE_BODY (N2S-15) | `br` request body ≥ 16 MiB (`1 << 24`) | "1<<24 literals", ~23 MB |
| LAB_ROUTES_WITH_BR (N2S-22) | `br` from the same client; ≥ 3 × `GET /warm` adds "cadence" | lab routes |
| NODE_PROCESS_CRASH (N2S-18) | info for 1–2 records, warn from 3 | Imperva: a single exit is only a clue |
| N2S-05 truncated prefix | header + ≥ 64 × `0x41` | log pipelines truncate bodies |

## Self-test (opt-in)

`--self-test` runs, for each node / bun binary, a **throwaway child process** with a timeout:

```js
zlib.brotliDecompressSync(Buffer.from('<the public 22-byte Node regression vector>', 'hex'))
```

and records the error code / errno (`ERR__ERROR_FORMAT_BLOCK_SWITCH` / -17 → **ok, fixed decoder**; any
other decoder error such as `BLOCK_LENGTH_1` / -9, or a crash / signal → **critical, vulnerable decoder
behaviour**; no error, a timeout or a non-decoder error → warn, *unknown / verify*).

**Why it is opt-in.** On an **unpatched** runtime this *executes the public regression vector*, which
exercises the bug inside the throwaway child (a crash of the child is the expected result there). The
vector is the one in Node's own test suite — there is no payload, no shellcode and no network, and it never
touches a long-running process of yours — but it does drive an out-of-bounds write on a vulnerable decoder,
so it never runs unless you ask, and only on runtimes you are allowed to test. The script lives in a
temporary directory that is removed afterwards; the child gets `NODE_OPTIONS` / `BUN_OPTIONS` stripped, its
own session (a timeout kills the whole process group) and a relative `--node-bin` is made absolute first.
Deno is not tested (status unresolved). The package's own tests exercise this **only against stub scripts**.

## A manual remote exposure check (benign; your own systems only)

Derived by IONSEC from Ostorlab's negative control: POST the **uncompressed** JSON `{"ping":1}` with
`Content-Encoding: br` to your own endpoint. It is a deliberately invalid Brotli stream — it is **not** the
trigger — and it asks one question: does this endpoint try to decode Brotli request bodies?

```bash
curl -sS -i -X POST 'https://your-service.example/api' \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H 'Content-Encoding: br' \
  --data-binary '{"ping":1}'
```

| Response | Meaning |
|---|---|
| **400** | the endpoint **decodes Brotli** (decompression of the non-Brotli body failed) — the decoder is reachable from outside; check the runtime / library behind it |
| **2xx** | the endpoint **ignores** `Content-Encoding` — no decoder reached on this path |
| **415** | the endpoint **rejects** the encoding (e.g. Express 4 / body-parser 1.x, or an edge rule) |

Try the candidate paths Ostorlab uses: `/`, `/api`, `/api/v1`, `/graphql`. A 400 is *reachability*, not
exploitability: whether the decoder behind it is fixed is what the posture / fingerprint / self-test checks
answer. **Only run this against systems you own or are authorized to test.**

## Fingerprint catalogue (brief §7) and what this tool does with each

Provenance: `V` vendor / upstream-published · `P` copied from public PoC / scanner source · `D` derived by
IONSEC (derivation stated). `V` / `P` → **VERBATIM**, `D` → **DERIVED**.

| id | type | value (as documented) | provenance | covered by |
|---|---|---|---|---|
| `N2S-01` | payload-bytes | 200010414141fcffff07002228f00b60f7f41f000000 | `V+P` VERBATIM | logs: SEED_BYTES_N2S_01..06 (escaped bodies); `--self-test` feeds it to your own runtime |
| `N2S-02` | payload-bytes | 200010414141fcffff07002228f00b60f7f41f00000000 | `P` VERBATIM | logs: SEED_BYTES |
| `N2S-03` | payload-bytes | 200018414141fcffff07002228f00b60f7f41f000000 | `P` VERBATIM | logs: SEED_BYTES |
| `N2S-04` | payload-bytes | 200010414141fcffff0f002228f00b60f7f41f000000 | `P` VERBATIM | logs: SEED_BYTES |
| `N2S-05` | payload-bytes | 1b00000000000000 + 1024 × 41 (1,032 B) | `P` VERBATIM | logs: SEED_BYTES (full 1,032 B or truncated prefix) |
| `N2S-06` | payload-bytes | 1b0100002479b16f50c0030500c00000000000000003 | `P` VERBATIM | logs: SEED_BYTES |
| `N2S-07` | http-request | POST `Content-Encoding: br` + JSON bodies `{"ping":1}` / `8b04807b2270696e67223a317d03` / N2S-01 to `/`, `/api`, `/api/v1`, `/graphql` | `P` VERBATIM | logs: OSTORLAB_PROBE_SWEEP (needs request-length fields) |
| `N2S-08` | user-agent | starts with `Node2ShellChecker/` | `P` VERBATIM | logs: UA_NODE2SHELL_CHECKER |
| `N2S-09` | user-agent | `Mozilla/5.0 (compatible; security-scanner)` | `P` VERBATIM | logs: UA_SECURITY_SCANNER_GENERIC |
| `N2S-10` | user-agent | `cve-2026-111497-verify` (source repo UNCONFIRMED) | `P` VERBATIM | logs: UA_CVE_VERIFY |
| `N2S-11` | http-request | `Content-Encoding` containing token `br` (case-insensitive, also inside lists) on a request with a body | `D` DERIVED | logs: REQUEST_CONTENT_ENCODING_BR (needs request headers in the log) |
| `N2S-12` | http-request | `Content-Encoding: br` + `Transfer-Encoding: chunked`, no Content-Length | `P` VERBATIM | logs: BR_CHUNKED_NO_LENGTH |
| `N2S-13` | http-request | duplicate `Content-Encoding` request headers | `V` VERBATIM | logs: DUPLICATE_CONTENT_ENCODING |
| `N2S-14` | http-request | `Content-Encoding: br` + `Content-Type: application/octet-stream` `POST /` | `P` VERBATIM | logs: BR_OCTET_STREAM_ROOT_POST |
| `N2S-15` | http-request | very large `br` request body (~23 MB, `1<<24` literals) | `P` VERBATIM | logs: BR_LARGE_BODY |
| `N2S-16` | log-line | `ERR__ERROR_FORMAT_BLOCK_SWITCH` / errno `-17` — only a **patched** decoder emits it | `V+D` VERBATIM+DERIVED | logs: BROTLI_BLOCK_SWITCH_ERROR (an attempt reached a patched decoder) |
| `N2S-17` | log-line | `ERR__ERROR_FORMAT_BLOCK_LENGTH_1` / errno `-9` (weak) | `P+D` VERBATIM+DERIVED | logs: BROTLI_BLOCK_LENGTH_1_ERROR (info) |
| `N2S-18` | process/log | Node / Bun crash right after a `br` request or outbound fetch | `V` VERBATIM | logs: NODE_PROCESS_CRASH (kernel / systemd-coredump / exit 139) |
| `N2S-19` | http-response | `uid=<n>(…) gid=<n>(…)` in a response body | `P` VERBATIM | logs: RESPONSE_ID_MARKER (critical) |
| `N2S-20` | file | `/tmp/pwn_marker.txt` | `P` VERBATIM | posture: HOST_MARKER_FILE |
| `N2S-21` | process | node / bun server spawning `sh` / `bash -c` with `id`, `whoami`, `uname`, curl / wget | `D` DERIVED | **not covered by the host tool** (process telemetry) — see the Sigma process rules in `rules/` |
| `N2S-22` | http-request | lab routes `POST /upload`, `GET /health`, `POST /stage` `/tail` `/close`, repeated `GET /warm` **together with `br`** | `P` VERBATIM | logs: LAB_ROUTES_WITH_BR |
| `N2S-23` | binary | contains `_ERROR_FORMAT_BLOCK_LENGTH_1` but not `_ERROR_FORMAT_BLOCK_SWITCH` → unpatched; contains `_ERROR_FORMAT_BLOCK_SWITCH` → fixed | `D` DERIVED | binaries: BIN_DECODER_FIXED / BIN_DECODER_VULNERABLE / BIN_DECODER_INCONCLUSIVE |
| `N2S-24` | source | vendored `decode.c`: `max_block_type <= 1` → `return BROTLI_FALSE;` without `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` → vulnerable | `D` DERIVED | binaries: SRC_DECODER_VULNERABLE / SRC_DECODER_FIXED |
| `N2S-25` | runtime | feed N2S-01 to the runtime's own decoder: `-17` = fixed; `-9` or a crash = vulnerable | `V+P` VERBATIM | `--self-test`: SELFTEST_FIXED / SELFTEST_VULNERABLE / SELFTEST_CRASH |
| `N2S-23` / `N2S-16` **1.0.x form** | binary / log-line | bare NUL-delimited `BLOCK_LENGTH_1` + `EXUBERANT_META_NIBBLE` or `CONTEXT_MAP_REPEAT` (no `_ERROR_FORMAT_` prefix); `ERR_BLOCK_SWITCH` / `ERR_BLOCK_LENGTH_1` | `D` DERIVED — **not in the brief**; verified against the google/brotli tags (v1.0.9 / v1.0.10 use `return #NAME;`, v1.1.0+ `return #PREFIX #NAME;`) | binaries: the same findings, bare table; logs: the same rules |

## Tests

```
python3 -m pytest -q        # from this directory (pytest is the only third-party tool; the package itself is stdlib-only)
```

- Synthetic benign + attack corpora live in `node2shell_detector/corpora.py` (attack lines built **only** from
  catalogue values, each with its fingerprint id; client IPs are RFC 5737 documentation addresses).
- **Back-audit.** Every catalogue UA, seed byte string and header shape must be matched by the detector (as
  escaped, percent-encoded and plain-hex bodies); benign traffic — curl, browsers, python-requests, undici,
  normal `Accept-Encoding: br` on requests and `Content-Encoding: br` on **responses**, EEXIST / EBADF `errno`
  lines, auditd `uid=0 gid=0` fields — must produce **nothing**. Further tests keep the constants identical to
  the brief, assert the package imports no network module and that the trigger bytes live only in
  `fingerprints.py`, and check this README against the code.
- The dpkg version comparator, the version tables, each lockfile parser (small fixtures), the binary scanner
  (synthetic ELF / Mach-O / fat / PE files with and without the marker strings, chunk-boundary and size-cap
  cases) and the CLI have their own tests. The self-test is only ever run against **stub scripts**
  (`examples/fixture_node*.sh`-style); the suite never executes a real runtime's decoder.
- Static example corpora and fixtures for manual smoke runs live in `examples/` (regenerate:
  `python3 examples/make_examples.py`):

```bash
python3 -m node2shell_detector --no-discover --check posture --node-bin examples/fixture_node.sh
python3 -m node2shell_detector --no-discover --check binaries --scan-dir examples/fixture_bins --scan-dir examples/fixture_vendor
python3 -m node2shell_detector --no-discover --check posture --check deps --node-bin examples/fixture_node.sh --project examples/fixture_project
python3 -m node2shell_detector --check logs --log examples/logs/access_exploit.log --log examples/logs/app_exploit.log
python3 -m node2shell_detector --no-discover --self-test --check posture --node-bin examples/fixture_node.sh   # stub only
```

## Known gaps

- **Containers.** No container / volume traversal and no image inspection — run the tool inside, or point
  `--node-bin` / `--scan-dir` at an extracted root file system (`--no-discover` keeps it from also probing the
  host). Dockerfile and compose tags are read, but a built image's contents are not.
- **Managed hosts.** AWS Lambda / Elastic Beanstalk / App Runner, Vercel, Netlify, Google Cloud Functions /
  Run, Azure Functions and Amazon Linux have no public patch level in the brief — verify `process.version`
  from inside the function. Vercel's WAF rules cover the inbound vector only, not responses the app fetches.
- **Windows.** The posture probes, library discovery and the self-test's process-group handling are POSIX /
  macOS oriented; PE files are recognised for `--scan-dir`, nothing else is Windows-aware.
- **Electron.** Apps are only found through `--scan-dir` (`/Applications/Foo.app`, an install directory); the
  marker cannot say which Brotli copy carries it (see above), and the brief lists the fix status as
  UNCONFIRMED — use the Node version inside the Electron release or a self-test of the app's runtime.
- **Deno and the Rust / Go ports.** Deno and `brotli-decompressor` are *info — unresolved*; `andybalholm/brotli`
  is judged by its version only.
- **Not covered:** .NET (`System.IO.Compression.Native` vendors brotli 1.1.0; no fix found in the brief), PECL
  `brotli`, curl / libcurl built against an unpatched libbrotli (covered through the library check), nginx
  `ngx_brotli` / Apache `mod_brotli` (encoder only — not affected), Envoy / Istio decompressor filters,
  workerd. Those are in the brief's §5 tables, not in this tool.
- **Dependency scan.** `package.json` ranges are not resolved; `bun.lockb` (binary) is skipped with a note;
  usage of a library inside your code is not analysed. Walks are bounded (depth, file and package counts).
- The tool is attempt-oriented on logs: it does not (and cannot) verify that a runtime was actually exploited.

## Provenance & attribution

- **No invented fingerprints.** Every fingerprint string is copied exactly from a fetched vendor or upstream
  publication or public scanner source named in the brief; the catalogue (`node2shell_detector/fingerprints.py`)
  keeps each id with its source and confidence. Two details go **beyond** the brief and are labelled DERIVED
  wherever they appear: the Brotli 1.0.x bare-name error table / `ERR_BLOCK_SWITCH` form, and the (conservative)
  derived thresholds above.
- **No attribution claims.** Vendor and project names appear only as sources, never as claims of endorsement
  or contribution.
- **Defanged output.** IPv4 addresses in evidence are `[.]`-mangled so copied output is inert.

## Reporting

See [SECURITY.md](SECURITY.md) for vulnerability reports against this tool and [CONTRIBUTING.md](CONTRIBUTING.md)
for factual patches (fingerprints that cite a fetched, dated source; version-table corrections). The code is
licensed AGPL-3.0 — see [LICENSE](LICENSE).

# Rules package

IONSEC's network / WAF / host rules for the same CVE live in **[`rules/`](rules/README.md)** — read
**[`rules/README.md`](rules/README.md)** for the inventory, the coverage map and the false-positive
guidance. In short:

| Content | Counts / ranges |
|---|---|
| `rules/sigma/` | 14 Sigma rules (web, proxy, application log, Linux / Windows process, file event, crash) |
| `rules/suricata/ionsec-node2shell.rules` | 14 active rules in the private SID block **1006600–1006699** (1006600–1006606, 1006610–1006614, 1006620, 1006630) plus one optional commented rule |
| `rules/modsecurity/ionsec-node2shell-dropin.conf` | 7 active rules in the ID range **1026111400–1026111499**; detection-only by default |
| `rules/edge/` | 8 inbound reject files (nginx, Apache, HAProxy, Envoy, Cloudflare, AWS WAF, Azure Front Door and Application Gateway) and 3 egress files |
| `rules/app/` | 5 app-level guards (Express, Koa, Fastify, Nest 11+, aiohttp) |
| `rules/yara/ionsec_node2shell.yar` | 7 rules + 1 private format rule |
| `rules/references/node2shell-sources.md` | provenance: every rule ↔ N2S id ↔ sources ↔ VERBATIM / DERIVED |

The two directions matter: **inbound** (an attacker sends a `Content-Encoding: br` body to your server) is
what WAF, edge and Suricata rules see; **outbound** (your service fetches from an attacker-controlled server —
webhooks, link previews, image proxies, crawlers, npm) is not visible to a WAF in front of the app, which is why
this host tool, the egress snippets and the self-test exist. The rules README states what was and was **not**
validated (the rule engines were not installed in the build environment), and notes that no equivalent rule
was found in Emerging Threats, Snort / Talos, SigmaHQ, Elastic detection-rules, Nuclei, OWASP CRS,
signature-base, Yara-Rules or Corelight when it was written.
