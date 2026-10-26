"""Static, documented fingerprints and thresholds for Node2Shell (CVE-2026-111497).

Everything in this module is copied from the IONSEC research brief (BRIEF.md,
compiled 2026-10-24 from fetched primary sources). The catalogue below is BRIEF s7,
ids N2S-01 .. N2S-25; version facts live in versions.py (BRIEF s3, s5).

Confidence letters (BRIEF s7): V = vendor/upstream-published, P = copied from public
PoC/scanner source, D = derived by IONSEC from the fix diff or a documented
behaviour (derivation stated). They map onto the finding `basis` labels:
  V / P  -> VERBATIM   (exact documented string / shape / version)
  D      -> DERIVED    (threshold or inference; the derivation is stated inline)
  V+D    -> VERBATIM+DERIVED

Anything marked "UNCONFIRMED" in the brief stays unknown here: the tool prints
"unknown / verify" rather than a guessed verdict.

Trigger bytes: the only trigger bytes in this package are the public Node.js
regression vector (N2S-01) and the published PoC constants N2S-02..06 listed in the
brief. They are used as DATA (matching, or fed to the operator's own runtime by the
opt-in self-test). Nothing here builds, mutates or sends an exploit.
"""

import re

# ---------------------------------------------------------------------------
# Fingerprint catalogue (BRIEF s7) - one entry per id, copied verbatim
# ---------------------------------------------------------------------------

CATALOGUE = {
    "N2S-01": {
        "type": "payload-bytes",
        "value": "200010414141fcffff07002228f00b60f7f41f000000",
        "note": "22 B; Node regression vector / 'oob-base' seed",
        "where": "raw request body, PCAP, WAF body log; response body for fetch-trap",
        "source": "nodejs/node test (b5f41529df); >=12 repos; Ostorlab",
        "conf": "V+P",
        "fp": "legit patch self-tests and scanners send it",
    },
    "N2S-02": {
        "type": "payload-bytes",
        "value": "200010414141fcffff07002228f00b60f7f41f00000000",
        "note": "23 B; oob-extended",
        "where": "raw request body, PCAP, WAF body log; response body for fetch-trap",
        "source": "hypnguyen1209 via gh0st-nemesis",
        "conf": "P",
        "fp": "",
    },
    "N2S-03": {
        "type": "payload-bytes",
        "value": "200018414141fcffff07002228f00b60f7f41f000000",
        "note": "oob-huffman",
        "where": "raw request body, PCAP, WAF body log; response body for fetch-trap",
        "source": "hypnguyen1209 via gh0st-nemesis",
        "conf": "P",
        "fp": "",
    },
    "N2S-04": {
        "type": "payload-bytes",
        "value": "200010414141fcffff0f002228f00b60f7f41f000000",
        "note": "oob-padding",
        "where": "raw request body, PCAP, WAF body log; response body for fetch-trap",
        "source": "hypnguyen1209 via gh0st-nemesis",
        "conf": "P",
        "fp": "",
    },
    "N2S-05": {
        "type": "payload-bytes",
        "value": "1b00000000000000 + 1024 x 41",
        "note": "1,032 B naive probe",
        "where": "request body",
        "source": "ZeroHackOrg node2shell.py",
        "conf": "P",
        "fp": "naive probe",
    },
    "N2S-06": {
        "type": "payload-bytes",
        "value": "1b0100002479b16f50c0030500c00000000000000003",
        "note": "22 B fallback stream",
        "where": "request body",
        "source": "Ghost-Bx1 exploit.py",
        "conf": "P",
        "fp": "low value",
    },
    "N2S-07": {
        "type": "http-request",
        "value": "POST Content-Encoding: br + Content-Type: application/json + Accept: application/json, "
                 "bodies {\"ping\":1} (10 B, uncompressed), 8b04807b2270696e67223a317d03 (14 B), "
                 "N2S-01 (22 B), to /, /api, /api/v1, /graphql",
        "note": "Ostorlab exposure-scanner sweep",
        "where": "access/WAF logs",
        "source": "Ostorlab",
        "conf": "P",
        "fp": "exposure scanner - still worth knowing who scans",
    },
    "N2S-08": {
        "type": "user-agent",
        "value": "starts with Node2ShellChecker/",
        "note": "optional ' (+contact)' suffix",
        "where": "access log",
        "source": "completetech-security/node2shell-check",
        "conf": "P",
        "fp": "self-identifying",
    },
    "N2S-09": {
        "type": "user-agent",
        "value": "Mozilla/5.0 (compatible; security-scanner)",
        "note": "",
        "where": "access log",
        "source": "Ghost-Bx1 poc.py:272",
        "conf": "P",
        "fp": "generic",
    },
    "N2S-10": {
        "type": "user-agent",
        "value": "cve-2026-111497-verify",
        "note": "source repo not pinned (UNCONFIRMED)",
        "where": "access log",
        "source": "a fetched PoC/checker; repo not pinned",
        "conf": "P",
        "fp": "UNCONFIRMED repo",
    },
    "N2S-11": {
        "type": "http-request",
        "value": "Content-Encoding containing token br (case-insensitive, also inside lists) on a request with a body",
        "note": "",
        "where": "proxy/WAF logs that record request headers",
        "source": "Express 5 / body-parser 2.x decode it (expressjs.com migrating-5 guide; inflate default true)",
        "conf": "D",
        "fp": "real but rare legit sender: Apify JS client brotli-compresses request bodies >=1,024 B by default",
    },
    "N2S-12": {
        "type": "http-request",
        "value": "Content-Encoding: br + Transfer-Encoding: chunked, no Content-Length",
        "note": "",
        "where": "proxy logs",
        "source": "tc4dy crash_express",
        "conf": "P",
        "fp": "",
    },
    "N2S-13": {
        "type": "http-request",
        "value": "duplicate Content-Encoding request headers",
        "note": "",
        "where": "WAF",
        "source": "Indusface AppTrana",
        "conf": "V",
        "fp": "",
    },
    "N2S-14": {
        "type": "http-request",
        "value": "Content-Encoding: br + Content-Type: application/octet-stream POST /",
        "note": "",
        "where": "access log",
        "source": "tc4dy exploit.py / verifier.py",
        "conf": "P",
        "fp": "",
    },
    "N2S-15": {
        "type": "http-request",
        "value": "very large br request body (~23 MB, 1<<24 literals)",
        "note": "",
        "where": "access log byte counts",
        "source": "6mile brotli_trigger.py; OpenSourceMalware",
        "conf": "P",
        "fp": "big uploads exist; needs br too",
    },
    "N2S-16": {
        "type": "log-line",
        "value": "ERR__ERROR_FORMAT_BLOCK_SWITCH / errno -17",
        "note": "only a patched decoder emits it",
        "where": "Node app logs / stack traces",
        "source": "fixed node_zlib.cc builds \"ERR_\" + BrotliDecoderErrorString(); upstream string "
                  "_ERROR_FORMAT_BLOCK_SWITCH; dimasma oracle",
        "conf": "V+D",
        "fp": "only a patched decoder emits it -> attempt against a patched host; other malformed streams "
              "can reach it",
    },
    "N2S-17": {
        "type": "log-line",
        "value": "ERR__ERROR_FORMAT_BLOCK_LENGTH_1 / errno -9",
        "note": "weak",
        "where": "app logs",
        "source": "Bun issue #46352: unpatched decoders return it on the seed",
        "conf": "P+D",
        "fp": "weak; ordinary corrupt input can produce it",
    },
    "N2S-18": {
        "type": "process/log",
        "value": "Node/Bun process crash (SIGSEGV/SIGBUS/abort, restart, CrashLoopBackOff) right after a br "
                 "request or outbound fetch",
        "note": "",
        "where": "kernel log, journald, orchestrator",
        "source": "Imperva: exits are a triage clue, not a stand-alone sign",
        "conf": "V",
        "fp": "many causes",
    },
    "N2S-19": {
        "type": "http-response",
        "value": "uid=<n>(...) gid=<n>(...) in an HTTP response body",
        "note": "",
        "where": "NIDS / WAF response inspection",
        "source": "dimasma0305 regex + lab sid 9001497; Arkango /bin/bash -c id",
        "conf": "P",
        "fp": "near-zero in legit traffic",
    },
    "N2S-20": {
        "type": "file",
        "value": "/tmp/pwn_marker.txt",
        "note": "lab marker",
        "where": "host FS",
        "source": "TheFool-TAROT",
        "conf": "P",
        "fp": "lab marker, trivially renamed",
    },
    "N2S-21": {
        "type": "process",
        "value": "node/bun server process spawning sh/bash -c with id, whoami, uname, curl/wget",
        "note": "",
        "where": "EDR / auditd",
        "source": "Arkango; dimasma id output; generic post-exploitation",
        "conf": "D",
        "fp": "npm scripts/build tools spawn shells - scope to long-running servers",
    },
    "N2S-22": {
        "type": "http-request",
        "value": "lab routes POST /upload, GET /health, POST /stage /tail /close, repeated GET /warm "
                 "together with br",
        "note": "",
        "where": "access log",
        "source": "dimasma0305, TheFool-TAROT labs",
        "conf": "P",
        "fp": "common route names - only with br",
    },
    "N2S-23": {
        "type": "binary",
        "value": "contains _ERROR_FORMAT_BLOCK_LENGTH_1 but not _ERROR_FORMAT_BLOCK_SWITCH -> unpatched "
                 "decoder; contains _ERROR_FORMAT_BLOCK_SWITCH -> fixed",
        "note": "derivation: the BLOCK_SWITCH code (-17) and its name were introduced only by the fix commits "
                "(git log -S: 0ed4268/b418fa8/da98063/50a9b70); Node v26.12.0 has 0 occurrences, v26.12.1 has 1",
        "where": "node, bun, libbrotlidec.so*, Python _brotli*.so, _brotlicffi*.so, Electron frameworks",
        "source": "derived from the fix commits",
        "conf": "D",
        "fp": "if the error-string table was stripped away -> unknown, never patched",
    },
    "N2S-24": {
        "type": "source",
        "value": "vendored decode.c: max_block_type <= 1 -> return BROTLI_FALSE; and no "
                 "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH -> vulnerable; with the constant -> fixed",
        "note": "",
        "where": "source trees, node_modules native addons, vendored C deps",
        "source": "fix diff 0ed4268a",
        "conf": "D",
        "fp": "",
    },
    "N2S-25": {
        "type": "runtime",
        "value": "feed N2S-01 to the runtime's own decoder: -17 BLOCK_SWITCH = fixed; -9 BLOCK_LENGTH_1 or crash "
                 "= vulnerable",
        "note": "executes the trigger in a throwaway child - opt-in only",
        "where": "throwaway child process",
        "source": "Node test; Bun issue; s1ko ASan",
        "conf": "V+P",
        "fp": "",
    },
}

# Detection details that go BEYOND the brief. They are DERIVED by IONSEC (coordinator-verified
# against the google/brotli tags v1.0.9, v1.0.10, v1.1.0, v1.1.1 and re-checked by building those
# tags and scanning the results) and are listed here so nothing is silently invented.
LEGACY_NAMES_NOTE = (
    "Brotli 1.0.x builds error names WITHOUT the prefix (DERIVED, not in the brief; verified against the "
    "google/brotli tags): in v1.0.9 and v1.0.10 `BrotliDecoderErrorString` uses `return #NAME;`, from v1.1.0 it is "
    "`return #PREFIX #NAME;`. A decoder built from 1.0.x (Node 12-16's bundled 1.0.9, Debian bookworm's system "
    "libbrotlidec 1.0.9 - fixed there as 1.0.9-2+deb12u1 via the 1.0.x-branch fix) therefore carries the bare "
    "strings BLOCK_LENGTH_1 / BLOCK_SWITCH instead of _ERROR_FORMAT_BLOCK_LENGTH_1 / _ERROR_FORMAT_BLOCK_SWITCH, and "
    "Node's \"ERR_\" + BrotliDecoderErrorString() codes read ERR_BLOCK_LENGTH_1 / ERR_BLOCK_SWITCH")

DERIVED_EXTENSIONS = {
    "N2S-23/1.0.x-table": {
        "extends": "N2S-23",
        "value": "bare NUL-delimited BLOCK_LENGTH_1 plus a corroborating bare table name (EXUBERANT_META_NIBBLE or "
                 "CONTEXT_MAP_REPEAT) and no _ERROR_FORMAT_ prefix = a Brotli 1.0.x error table; bare BLOCK_SWITCH in "
                 "it -> fixed, absent -> vulnerable; BLOCK_LENGTH_1 without corroboration -> ambiguous, unknown "
                 "(never 'patched')",
        "note": LEGACY_NAMES_NOTE,
        "conf": "D",
    },
    "N2S-16/1.0.x-code": {
        "extends": "N2S-16 / N2S-17",
        "value": "ERR_BLOCK_SWITCH (and ERR_BLOCK_LENGTH_1 for N2S-17) in a log line, errno -17 / -9 unchanged",
        "note": LEGACY_NAMES_NOTE,
        "conf": "D",
    },
}

# What the host tool does with each id (README table; checked by a test).
COVERAGE = {
    "N2S-01": "logs: SEED_BYTES_N2S_01..06 (escaped bodies); selftest feeds it to your own runtime",
    "N2S-02": "logs: SEED_BYTES",
    "N2S-03": "logs: SEED_BYTES",
    "N2S-04": "logs: SEED_BYTES",
    "N2S-05": "logs: SEED_BYTES (full 1,032 B or truncated prefix)",
    "N2S-06": "logs: SEED_BYTES",
    "N2S-07": "logs: OSTORLAB_PROBE_SWEEP (needs request-length fields)",
    "N2S-08": "logs: UA_NODE2SHELL_CHECKER",
    "N2S-09": "logs: UA_SECURITY_SCANNER_GENERIC",
    "N2S-10": "logs: UA_CVE_VERIFY (source repo UNCONFIRMED)",
    "N2S-11": "logs: REQUEST_CONTENT_ENCODING_BR (needs request headers in the log)",
    "N2S-12": "logs: BR_CHUNKED_NO_LENGTH (needs request headers in the log)",
    "N2S-13": "logs: DUPLICATE_CONTENT_ENCODING (needs request headers in the log)",
    "N2S-14": "logs: BR_OCTET_STREAM_ROOT_POST (needs request headers in the log)",
    "N2S-15": "logs: BR_LARGE_BODY (needs request headers + body size in the log)",
    "N2S-16": "logs: BROTLI_BLOCK_SWITCH_ERROR (attempt reached a patched decoder; also the bare ERR_BLOCK_SWITCH of "
              "1.0.x builds, DERIVED)",
    "N2S-17": "logs: BROTLI_BLOCK_LENGTH_1_ERROR (info; also the bare ERR_BLOCK_LENGTH_1 of 1.0.x builds, DERIVED)",
    "N2S-18": "logs: NODE_PROCESS_CRASH (kernel / systemd-coredump / exit 139)",
    "N2S-19": "logs: RESPONSE_ID_MARKER (critical)",
    "N2S-20": "posture: HOST_MARKER_FILE",
    "N2S-21": "not covered by the host tool (process telemetry) - see rules/README.md",
    "N2S-22": "logs: LAB_ROUTES_WITH_BR (needs request headers in the log)",
    "N2S-23": "binaries: BIN_DECODER_FIXED / BIN_DECODER_VULNERABLE / BIN_DECODER_INCONCLUSIVE (1.1+ _ERROR_FORMAT_ "
              "names; plus the bare-name 1.0.x table, DERIVED)",
    "N2S-24": "binaries: SRC_DECODER_VULNERABLE / SRC_DECODER_FIXED",
    "N2S-25": "--self-test: SELFTEST_FIXED / SELFTEST_VULNERABLE / SELFTEST_CRASH",
}


def provenance(conf: str) -> str:
    """Map a brief confidence code (V / P / D / V+D ...) to a basis label."""
    parts = [p.strip() for p in conf.split("+")]
    verbatim = any(p in ("V", "P") for p in parts)
    derived = "D" in parts
    if verbatim and derived:
        return "VERBATIM+DERIVED"
    return "DERIVED" if derived else "VERBATIM"


def basis(*ids: str, note: str = "") -> str:
    """Compose a finding `basis` string from catalogue entries."""
    labels = {provenance(CATALOGUE[i]["conf"]) for i in ids}
    if len(labels) == 1:
        label = labels.pop()
    else:
        label = "VERBATIM+DERIVED"
    cites = "; ".join(f"{i} ({CATALOGUE[i]['type']}, conf {CATALOGUE[i]['conf']}, "
                      f"{CATALOGUE[i]['source']})" for i in ids)
    return f"{label}: {cites}" + (f" - {note}" if note else "")


def brief_basis(section: str, note: str, derived: bool = False) -> str:
    """Basis for findings that rest on a BRIEF section rather than a catalogue id."""
    return f"{'DERIVED' if derived else 'VERBATIM'}: BRIEF {section} - {note}"


# ---------------------------------------------------------------------------
# Seed bytes N2S-01 .. N2S-06 (data only; used for log matching and the self-test)
# ---------------------------------------------------------------------------

SEED_HEX = {
    "N2S-01": "200010414141fcffff07002228f00b60f7f41f000000",
    "N2S-02": "200010414141fcffff07002228f00b60f7f41f00000000",
    "N2S-03": "200018414141fcffff07002228f00b60f7f41f000000",
    "N2S-04": "200010414141fcffff0f002228f00b60f7f41f000000",
    "N2S-06": "1b0100002479b16f50c0030500c00000000000000003",
}
SEED_BYTES = {k: bytes.fromhex(v) for k, v in SEED_HEX.items()}

# N2S-05: 1b00000000000000 + 1024 x 0x41 (1,032 B)
N2S_05_HEAD = bytes.fromhex("1b00000000000000")
N2S_05_PAD_BYTE = b"A"
N2S_05_PAD_COUNT = 1024
N2S_05_BYTES = N2S_05_HEAD + N2S_05_PAD_BYTE * N2S_05_PAD_COUNT

# The public Node.js regression vector (N2S-01) - what the opt-in self-test feeds to
# the operator's own runtime inside a throwaway child process.
REGRESSION_VECTOR_HEX = SEED_HEX["N2S-01"]
assert len(REGRESSION_VECTOR_HEX) == 44  # 22 bytes (BRIEF s2)

# Ostorlab remote-probe constants (BRIEF s6, verbatim)
OSTORLAB_BENIGN_BROTLI_HEX = "8b04807b2270696e67223a317d03"   # 14 B, valid Brotli of {"ping":1}
OSTORLAB_JSON_BODY = '{"ping":1}'                              # 10 B, sent uncompressed with Content-Encoding: br
OSTORLAB_CANDIDATE_PATHS = ("/", "/api", "/api/v1", "/graphql")
OSTORLAB_BODY_SIZES = (10, 14, 22)                              # bytes of the three probe bodies (N2S-07)

# ---------------------------------------------------------------------------
# User agents (N2S-08..10)
# ---------------------------------------------------------------------------

UA_NODE2SHELL_CHECKER_PREFIX = "Node2ShellChecker/"             # N2S-08 ('starts with')
UA_SECURITY_SCANNER_GENERIC = "Mozilla/5.0 (compatible; security-scanner)"  # N2S-09
UA_CVE_VERIFY_TOKEN = "cve-2026-111497-verify"                  # N2S-10 (repo UNCONFIRMED)

# One concrete, labelled-synthetic example per UA family for the back-audit test.
# N2S-08 is published only as 'Node2ShellChecker/<version>' (+ optional contact): the
# version below is a placeholder, not a published value.
UA_EXAMPLES = (
    ("N2S-08", UA_NODE2SHELL_CHECKER_PREFIX + "0.0.0 (+https://example.org/contact)"),
    ("N2S-09", UA_SECURITY_SCANNER_GENERIC),
    ("N2S-10", UA_CVE_VERIFY_TOKEN),
)

# ---------------------------------------------------------------------------
# Lab routes (N2S-22) and host marker (N2S-20)
# ---------------------------------------------------------------------------

LAB_ROUTES = (
    ("POST", "/upload"), ("GET", "/health"),
    ("POST", "/stage"), ("POST", "/tail"), ("POST", "/close"),
    ("GET", "/warm"),
)
LAB_WARM_ROUTE = ("GET", "/warm")

HOST_MARKER_PATHS = ("/tmp/pwn_marker.txt",)                    # N2S-20

# ---------------------------------------------------------------------------
# Text / log markers (N2S-16..19)
# ---------------------------------------------------------------------------

ERR_BLOCK_SWITCH = "ERR__ERROR_FORMAT_BLOCK_SWITCH"             # N2S-16 (errno -17)
ERR_BLOCK_LENGTH_1 = "ERR__ERROR_FORMAT_BLOCK_LENGTH_1"         # N2S-17 (errno -9)
ERRNO_BLOCK_SWITCH = -17
ERRNO_BLOCK_LENGTH_1 = -9
# DERIVED (not in the brief; see LEGACY_NAMES_NOTE): on decoders built from Brotli 1.0.x the name has no
# `_ERROR_FORMAT_` prefix, so Node's "ERR_" + BrotliDecoderErrorString() reads ERR_BLOCK_SWITCH / ERR_BLOCK_LENGTH_1.
# errno is unchanged (-17 / -9: v1.0.10's decode.h has BLOCK_SWITCH, -17).
ERR_BLOCK_SWITCH_LEGACY = "ERR_BLOCK_SWITCH"
ERR_BLOCK_LENGTH_1_LEGACY = "ERR_BLOCK_LENGTH_1"
RE_ERR_BLOCK_SWITCH_LEGACY = re.compile(r"(?<![A-Za-z0-9_])ERR_BLOCK_SWITCH(?![A-Za-z0-9_])")
RE_ERR_BLOCK_LENGTH_1_LEGACY = re.compile(r"(?<![A-Za-z0-9_])ERR_BLOCK_LENGTH_1(?![A-Za-z0-9_])")

# N2S-19 response marker - the dimasma0305 regex, verbatim (BRIEF s6).
RE_UID_GID = re.compile(r"uid=\d+(?:\([^)\r\n]+\))?\s+gid=\d+(?:\([^)\r\n]+\))?")

# ---------------------------------------------------------------------------
# Binary / source markers (N2S-23 / N2S-24) - BRIEF s7; derivation in the catalogue
# ---------------------------------------------------------------------------

BIN_MARKER_SWITCH = b"_ERROR_FORMAT_BLOCK_SWITCH"
BIN_MARKER_LENGTH1 = b"_ERROR_FORMAT_BLOCK_LENGTH_1"

# Brotli 1.0.x-style error tables (DERIVED, not in the brief; see LEGACY_NAMES_NOTE): the names are bare, stored as
# their own NUL-terminated strings. The NUL delimiters matter: BLOCK_LENGTH_1 is also a SUFFIX of the 1.1+ string
# _ERROR_FORMAT_BLOCK_LENGTH_1, so a bare name must be a whole C string. Verified on real builds of v1.0.9 / v1.0.10
# (bare names present, no prefixed ones) and v1.1.0 / v1.1.1 (prefixed names only).
BIN_LEGACY_LENGTH1 = b"\x00BLOCK_LENGTH_1\x00"
BIN_LEGACY_SWITCH = b"\x00BLOCK_SWITCH\x00"
BIN_LEGACY_CORROBORATION = (b"\x00EXUBERANT_META_NIBBLE\x00", b"\x00CONTEXT_MAP_REPEAT\x00")

SRC_FUNCTION = "DecodeBlockTypeAndLength"
SRC_CONSTANT = "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH"
SRC_VULNERABLE_RE = re.compile(r"max_block_type\s*<=\s*1\s*\)\s*\{\s*return\s+BROTLI_FALSE\s*;")

# ---------------------------------------------------------------------------
# Derived thresholds (documented shapes, conservative cut-offs). Tuning parameters,
# not fingerprints - tune here.
# ---------------------------------------------------------------------------

THRESHOLDS = {
    # N2S-07: same client POSTs >= 3 of the 4 Ostorlab candidate paths with tiny bodies
    "sweep_min_paths": 3,
    # exact body-size fields (content_length / body_bytes_received): documented bodies are 10/14/22 B
    "sweep_tiny_exact_max": 64,
    # request_length includes the request line and headers: accept the whole request up to this size
    "sweep_tiny_total_max": 1024,
    # N2S-15: '1<<24 literals' / ~23 MB -> br request bodies of at least 16 MiB
    "br_large_body_min": 1 << 24,
    # N2S-22: 'repeated GET /warm' (heap grooming) -> at least 3, from a client that also sent br
    "warm_repeat_min": 3,
    # N2S-18: a single crash is only a triage clue (Imperva); three or more -> warn
    "crash_warn_min": 3,
    # request bodies / lines are not decoded above this size
    "scan_text_cap": 2 * 1024 * 1024,
    # N2S-05 truncated-prefix tolerance: header + at least this many 'A' bytes
    "seed05_trunc_min_pad": 64,
}
