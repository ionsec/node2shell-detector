"""LOG SCAN: access logs (nginx/Apache common + combined, LTSV, JSON lines) and
application / stderr / journald text, matched against the Node2Shell fingerprints in the
research brief (BRIEF s7, N2S-01 .. N2S-25). No fingerprint is invented; every finding
states its basis (VERBATIM = exact documented string/shape, DERIVED = threshold or
inference with the derivation stated) and the N2S ids it rests on.

Honest limits (also in README):
- A log hit is ATTEMPT evidence, never proof of execution. Imperva: unexpected process
  exits are "not a reliable stand-alone sign of exploitation"; no public source reported
  in-the-wild exploitation as of 2026-10-24.
- Standard combined / common access logs carry neither request headers nor bodies, so the
  `Content-Encoding: br` rules (N2S-11..15, N2S-22) and the body-seed rules only fire
  where you log them: LTSV / JSON-lines fields (see README, "Log formats"). The UA, text
  and crash rules run on any log.
- Response-side bytes (N2S-19) are only visible if a response body is logged.
- Escaped bodies: nginx `$request_body` / Apache `\\xNN` escapes and percent-encoding are
  decoded before the seed bytes (N2S-01..06) are searched. The seed hex is also searched
  as a plain hex string.
- `errno: -17` is EEXIST and `errno: -9` is EBADF in libuv: the errno forms are only read
  as Brotli errors when the same line mentions brotli / zlib / decompression and not
  EEXIST - the `ERR__ERROR_FORMAT_*` code strings need no context.
- Benign traffic is deliberately NOT flagged: browsers, curl, python-requests, and normal
  `Accept-Encoding: br` on requests / `Content-Encoding: br` on RESPONSES.
"""

import gzip
import json
import os
import re
from collections import Counter, defaultdict
from typing import Optional

from . import fingerprints as fp
from .report import clean_evidence, defang, finding

TH = fp.THRESHOLDS
BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

RE_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')
RE_COMMON = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s*$')

_RESP_FRAGMENTS = ("resp", "sent", "upstream", "downstream", "origin", "backend")
_RESP_TOKENS = {"out", "o"}


def _norm(key) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _flatten(obj, prefix: str = "", out: Optional[dict] = None, depth: int = 0) -> dict:
    out = {} if out is None else out
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):
            out[prefix] = [("" if x is None else str(x)) for x in obj]
        else:
            for i, v in enumerate(obj):
                _flatten(v, f"{prefix}[{i}]", out, depth + 1)
    else:
        out[prefix] = obj
    return out


def _flat_text(flat: dict) -> str:
    lines = []
    for k, v in flat.items():
        if isinstance(v, list):
            v = ", ".join(v)
        lines.append(f"{k}={v}")
    return "\n".join(lines)


class _Index:
    """Normalised-key index over a flat dict (full key first, then the last path segment)."""

    def __init__(self, flat: dict):
        self.flat = flat
        self.idx = {}
        for k, v in flat.items():
            self.idx.setdefault(_norm(k), v)
        for k, v in flat.items():
            self.idx.setdefault(_norm(re.split(r"[.\[]", str(k))[-1].rstrip("]")), v)

    def first(self, *names):
        for n in names:
            v = self.idx.get(_norm(n))
            if v not in (None, "", []):
                return ", ".join(v) if isinstance(v, list) else v
        return None

    def present(self, *names) -> bool:
        return any(_norm(n) in self.idx for n in names)

    def request_header(self, header_norm: str):
        """Values of a REQUEST header from keys ending in `header_norm` (e.g. 'contentencoding'),
        skipping response-side keys. None = no such field logged at all."""
        vals, seen = [], False
        for key, val in self.flat.items():
            nk = _norm(key)
            if not nk.endswith(header_norm):
                continue
            tokens = set(re.split(r"[^a-z0-9]+", str(key).lower()))
            if any(f in nk for f in _RESP_FRAGMENTS) or tokens & _RESP_TOKENS:
                continue
            seen = True
            if isinstance(val, list):
                vals.extend(str(x) for x in val)
            elif val is not None:
                vals.append(str(val))
        if not seen:
            return None
        return [v.strip() for v in vals if v.strip() and v.strip() != "-"]


def _split_request(req: str):
    parts = (req or "").split()
    if len(parts) >= 3:
        return parts[0], " ".join(parts[1:-1]), parts[-1]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return (req or ""), "", ""


def _to_int(v) -> Optional[int]:
    s = str(v if v is not None else "").strip().replace(",", "")
    return int(s) if s.isdigit() else None


def _unescape_body(text: str) -> str:
    """Bodies must be escaped to stay on one log line. Unescape the simple sequences for
    display / structure; the seed search decodes more (decode_logged_bytes)."""
    if "\\" not in text:
        return text
    return text.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")


def _record_from_flat(flat: dict, fmt: str, ltsv: bool = False) -> Optional[dict]:
    ix = _Index(flat)
    req = ix.first("request", "req", "request_line")
    method, uri, proto = "", "", ""
    if isinstance(req, str) and " " in req.strip():
        method, uri, proto = _split_request(req)
    method = str(ix.first("request_method", "method", "verb", "requestmethod", "http_method") or method or "")
    uri = str(ix.first("request_uri", "uri", "url", "path", "requestpath", "request_path", "uri_path",
                       "target", "http_url", "full_uri") or uri or "")
    if not method and not uri:
        return None
    proto = str(ix.first("server_protocol", "protocol", "proto", "http_version") or proto or "")
    ip_names = ["remote_addr", "remote_ip", "client_ip", "clientip", "clienthost", "src_ip", "remote_host", "ip"]
    if ltsv:
        ip_names += ["host", "fwd", "forwardedfor"]
    ip_names += ["http_x_forwarded_for", "x_forwarded_for"]
    status = ix.first("status", "status_code", "response_status", "downstreamstatus", "originstatus", "statuscode")
    size = ix.first("body_bytes_sent", "size", "bytes", "bytes_sent", "response_size", "resp_size")
    ce = ix.request_header("contentencoding")
    ctype = ix.request_header("contenttype")
    te = ix.request_header("transferencoding")
    ua = ix.first("http_user_agent", "user_agent", "ua", "agent", "useragent")
    if ua is None:
        h = ix.request_header("useragent")
        ua = ", ".join(h) if h else ""
    cl_present = ix.present("content_length", "http_content_length", "req_content_length",
                            "request_content_length", "requestcontentsize")
    path = uri.split("?", 1)[0].split("#", 1)[0]
    return {
        "ip": (str(ix.first(*ip_names)) if ix.first(*ip_names) is not None else None),
        "ts": ix.first("time", "time_local", "timestamp", "ts", "@timestamp", "time_iso8601", "datetime", "date"),
        "method": method, "uri": uri, "path": path, "proto": proto,
        "status": _to_int(status), "size": size,
        "ref": str(ix.first("http_referer", "referer", "referrer") or ""),
        "ua": str(ua or ""),
        "cookie": str(ix.first("http_cookie", "cookie") or ""),
        "body": _unescape_body(str(ix.first("request_body", "req_body", "body", "http_body", "post_body") or "")),
        "resp_body": str(ix.first("response_body", "resp_body") or ""),
        "content_length": (str(ix.first("content_length", "http_content_length", "req_content_length",
                                        "request_content_length", "requestcontentsize") or "")
                           if cl_present else None),
        "request_length": str(ix.first("request_length", "requestlength") or "").strip(),
        "body_bytes_received": str(ix.first("body_bytes_received", "request_body_size") or "").strip(),
        "ce": ce, "ctype": ", ".join(ctype) if ctype else (None if ctype is None else ""),
        "te": ", ".join(te) if te else (None if te is None else ""),
        "format": fmt,
    }


def parse_ltsv(line: str) -> Optional[dict]:
    fields = {}
    for token in line.rstrip("\r\n").split("\t"):
        if ":" not in token:
            return None
        key, _, val = token.partition(":")
        fields[key.strip()] = val
    if not fields:
        return None
    return fields


def parse_json_line(line: str):
    """-> (record | None, flat | None). Docker json-file wrappers ({"log": "..."}) are unwrapped."""
    s = line.strip()
    if not s.startswith("{"):
        return None, None
    try:
        obj = json.loads(s)
    except ValueError:
        return None, None
    if not isinstance(obj, dict):
        return None, None
    flat = _flatten(obj)
    rec = _record_from_flat(flat, "json")
    if rec is not None:
        return rec, flat
    inner = flat.get("log") if isinstance(flat.get("log"), str) else None
    if inner:
        rec2 = parse_access_line(inner.rstrip("\n"), "auto")
        if rec2 is not None:
            rec2["format"] = "json+" + rec2.get("format", "?")
            return rec2, flat
    return None, flat


def parse_access_line(line: str, fmt: str = "auto") -> Optional[dict]:
    """Parse one access-log line: combined / common / LTSV / JSON lines."""
    text = line.rstrip("\r\n")
    if fmt in ("auto", "json") and text.lstrip().startswith("{"):
        rec, _flat = parse_json_line(text)
        if rec is not None or fmt == "json":
            return rec
    if fmt == "json":
        return None
    if fmt in ("auto", "combined", "common"):
        m = RE_COMBINED.match(text) if fmt in ("auto", "combined") else None
        mfmt = "combined"
        if m is not None and m.group("ua") is None:
            mfmt = "common"                    # the optional referer/UA group did not match: a common-format line
        if not m and fmt in ("auto", "common"):
            m = RE_COMMON.match(text)
            mfmt = "common"
        if m:
            d = m.groupdict()
            method, uri, proto = _split_request(d.get("req") or "")
            return {
                "ip": d.get("ip"), "ts": d.get("ts"), "method": method, "uri": uri,
                "path": uri.split("?", 1)[0], "proto": proto,
                "status": int(d["status"]) if d.get("status", "").isdigit() else None,
                "size": d.get("size"), "ref": d.get("ref") or "", "ua": d.get("ua") or "",
                "cookie": "", "body": "", "resp_body": "", "content_length": None,
                "request_length": "", "body_bytes_received": "", "ce": None, "ctype": None, "te": None,
                "format": mfmt,
            }
    if fmt in ("auto", "ltsv"):
        fields = parse_ltsv(text)
        if fields is not None:
            return _record_from_flat(fields, "ltsv", ltsv=True)
    return None


def iter_lines(path: str):
    """Yield (line_no, line) from a plain or .gz log file."""
    op = gzip.open if (path.endswith(".gz") or _is_gzip(path)) else open
    with op(path, "rt", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            yield i, line


def _is_gzip(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"\x1f\x8b"
    except OSError:
        return False


# ---------------------------------------------------------------------------
# seed bytes N2S-01..06 in escaped / percent-encoded / hex bodies
# ---------------------------------------------------------------------------

_ESC_PREFILTER = re.compile(r"\\x00|\\X00|%00|\\u0000|\\0(?![0-9])|\x00")
_UNESC = re.compile(r"\\x([0-9A-Fa-f]{2})|\\u00([0-9A-Fa-f]{2})|%([0-9A-Fa-f]{2})|\\(0)(?![0-9])|\\([nrt\\\"'/])")
_ESC_MAP = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'", "/": "/"}


def decode_logged_bytes(text: str) -> bytes:
    """Decode nginx/Apache `\\xNN`, JSON `\\u00NN`, `\\0`, simple escapes and `%NN` into the raw
    bytes the log line stands for (chars above U+00FF cannot be seed bytes and become '?')."""
    def repl(m):
        h = m.group(1) or m.group(2) or m.group(3)
        if h:
            return chr(int(h, 16))
        if m.group(4):
            return "\x00"
        return _ESC_MAP[m.group(5)]
    return _UNESC.sub(repl, text).encode("latin-1", "replace")


_RE_SEED05_RUN = re.compile(re.escape(fp.N2S_05_HEAD) + b"(A{%d,})" % TH["seed05_trunc_min_pad"])
_SEED05_HEX_PREFIX = fp.N2S_05_HEAD.hex() + "41" * TH["seed05_trunc_min_pad"]


def _prune_prefix(counts: dict) -> dict:
    """The 22-byte N2S-01 is the prefix of the 23-byte N2S-02: drop N2S-01 when every one of
    its occurrences sits inside an N2S-02 occurrence."""
    if "N2S-01" in counts and "N2S-02" in counts and counts["N2S-01"] - counts["N2S-02"] <= 0:
        counts = {k: v for k, v in counts.items() if k != "N2S-01"}
    return counts


def find_seeds(text: str) -> list:
    """Seed byte strings N2S-01..06 in a log line / body: [(id, form, detail)]."""
    hits = []
    if not text:
        return hits
    text = text[:TH["scan_text_cap"]]
    # (a) plain contiguous hex
    low = text.lower()
    hex_counts = _prune_prefix({sid: low.count(hx) for sid, hx in fp.SEED_HEX.items() if hx in low})
    for sid in hex_counts:
        hits.append((sid, "hex", ""))
    if _SEED05_HEX_PREFIX in low:
        n = 0
        i = low.index(_SEED05_HEX_PREFIX) + len(fp.N2S_05_HEAD.hex())
        while low.startswith("41", i):
            n += 1
            i += 2
        hits.append(("N2S-05", "hex", f"{n} x 0x41"))
    # (b) escaped / percent-encoded bytes
    if _ESC_PREFILTER.search(text):
        raw = decode_logged_bytes(text)
        byte_counts = _prune_prefix({sid: raw.count(bs) for sid, bs in fp.SEED_BYTES.items() if bs in raw})
        for sid in byte_counts:
            if not any(h[0] == sid for h in hits):
                hits.append((sid, "escaped bytes", ""))
        m = _RE_SEED05_RUN.search(raw)
        if m and not any(h[0] == "N2S-05" for h in hits):
            n = len(m.group(1))
            hits.append(("N2S-05", "escaped bytes", f"{n} x 0x41" + ("" if n >= fp.N2S_05_PAD_COUNT
                                                                      else " (log truncated the run)")))
    return hits


_SEED_RULE = {
    "N2S-01": ("the public Node.js regression vector / 'oob-base' seed (22 B) - sent by patch self-tests, scanners "
               "and PoCs alike"),
    "N2S-02": "the 'oob-extended' PoC seed (23 B)",
    "N2S-03": "the 'oob-huffman' PoC seed",
    "N2S-04": "the 'oob-padding' PoC seed",
    "N2S-05": "the naive 1,032 B probe (an 8-byte header + 1024 x 0x41) from a public PoC",
    "N2S-06": "the 22 B fallback stream from a public PoC",
}


# ---------------------------------------------------------------------------
# text rules (any line): N2S-16 / 17 / 18 / 19 + seeds
# ---------------------------------------------------------------------------

_RE_ERRNO_17 = re.compile(r"errno\W{0,4}-17\b", re.IGNORECASE)
_RE_ERRNO_9 = re.compile(r"errno\W{0,4}-9\b", re.IGNORECASE)
_RE_BROTLI_CONTEXT = re.compile(r"brotli|zlib|decompress|inflate", re.IGNORECASE)

RE_CRASH = (
    re.compile(r"\b(?:node|nodejs|bun)\[\d+\]:\s+segfault at\b", re.IGNORECASE),
    re.compile(r"\bsegfault at [0-9a-f]+\b.*\bin (?:node|nodejs|bun)\b", re.IGNORECASE),
    re.compile(r"\bSegmentation fault\b"),
    re.compile(r"\bProcess \d+ \((?:node|nodejs|bun)\)"),
    re.compile(r"code=(?:dumped|killed), status=(?:11/SEGV|6/ABRT|7/BUS|4/ILL)"),
    re.compile(r"(?:exit(?:ed)?(?: with)?(?: status)?(?: code)?|Exit ?Code|exitCode)\W{0,3}139\b", re.IGNORECASE),
    re.compile(r"\bExited \(139\)"),
)
_AUDITD_TOKENS = re.compile(r"\b(?:auid|euid|suid|fsuid|egid|sgid|fsgid)=|\btype=[A-Z_]+\b")
# cheap substring gate before the crash regexes (keeps a 200k-line scan fast)
_CRASH_PREFILTER = ("egfault", "Segmentation", "139", "(node)", "(nodejs)", "(bun)", "status=")


def _eval_text(text: str, raw: str, line_no: int, path: str, out: list, state: dict) -> None:
    where = {"file": path, "line": line_no}

    # N2S-19 - `id` output in a logged response / text. Critical.
    for m in (fp.RE_UID_GID.finditer(text) if "uid=" in text else ()):
        named = "(" in m.group(0)
        if not named and _AUDITD_TOKENS.search(text):
            continue      # auditd-style `uid=0 gid=0` fields: not `id` output
        out.append(finding(
            "RESPONSE_ID_MARKER", "critical",
            "`uid=<n>(...) gid=<n>(...)` - the output of `id` - appears in this logged line. This is the documented "
            "marker the lab RCE PoC returns on the HTTP socket and it is near-zero in legitimate traffic: treat as "
            "possible code execution until ruled out (process tree, new files, auditd execve). It can also be an "
            "innocent log of an `id` command - verify.",
            check="logs", evidence=clean_evidence(raw),
            basis=fp.basis("N2S-19", note="regex copied verbatim; bare numeric `uid=0 gid=0` is skipped on auditd-style lines"),
            fingerprints=["N2S-19"], **where))
        break

    # N2S-16 - the patched decoder's permanent error
    has_errno = "errno" in text.lower()
    sw_code = fp.ERR_BLOCK_SWITCH in text
    # DERIVED bare form of decoders built from Brotli 1.0.x (no `_ERROR_FORMAT_` prefix): ERR_BLOCK_SWITCH
    sw_legacy = "ERR_BLOCK_SWITCH" in text and bool(fp.RE_ERR_BLOCK_SWITCH_LEGACY.search(text))
    sw_errno = (has_errno and bool(_RE_ERRNO_17.search(text)) and bool(_RE_BROTLI_CONTEXT.search(text))
                and "EEXIST" not in text)
    if sw_code or sw_legacy or sw_errno:
        note = ("the code string needs no context; errno -17 alone is EEXIST in libuv, so it counts only beside "
                "brotli/zlib context without EEXIST")
        if sw_legacy:
            note += ". The bare form ERR_BLOCK_SWITCH is DERIVED: " + fp.LEGACY_NAMES_NOTE
        out.append(finding(
            "BROTLI_BLOCK_SWITCH_ERROR", "warn",
            "log line carries the patched Brotli decoder's permanent error for an invalid block switch "
            "(ERR__ERROR_FORMAT_BLOCK_SWITCH / errno -17): an attempt reached a PATCHED decoder and was rejected - "
            "attempt evidence against this host, not proof of anything else. Only a patched decoder emits it; other "
            "malformed streams can reach it too, and patch self-tests / scanners trigger it on purpose."
            + (" This line has the bare `ERR_BLOCK_SWITCH` form: the decoder was built from Brotli 1.0.x, whose "
               "error names carry no _ERROR_FORMAT_ prefix (DERIVED)." if sw_legacy else ""),
            check="logs", evidence=clean_evidence(raw),
            basis=fp.basis("N2S-16", note=note), fingerprints=["N2S-16"], **where))

    # N2S-17 - weak
    l1_code = fp.ERR_BLOCK_LENGTH_1 in text
    l1_legacy = "ERR_BLOCK_LENGTH_1" in text and bool(fp.RE_ERR_BLOCK_LENGTH_1_LEGACY.search(text))
    l1_errno = (has_errno and bool(_RE_ERRNO_9.search(text)) and bool(_RE_BROTLI_CONTEXT.search(text))
                and "EBADF" not in text)
    if l1_code or l1_legacy or l1_errno:
        note = ("errno -9 alone is EBADF in libuv, so it counts only beside brotli/zlib context without EBADF")
        if l1_legacy:
            note += ". The bare form ERR_BLOCK_LENGTH_1 is DERIVED: " + fp.LEGACY_NAMES_NOTE
        out.append(finding(
            "BROTLI_BLOCK_LENGTH_1_ERROR", "info",
            "log line carries ERR__ERROR_FORMAT_BLOCK_LENGTH_1 / errno -9: unpatched decoders return it for the public "
            "regression vector (Bun issue #46352), but ordinary corrupt Brotli input produces it too - weak signal; "
            "check the runtime posture and whether this host is patched."
            + (" This line has the bare `ERR_BLOCK_LENGTH_1` form of a decoder built from Brotli 1.0.x (DERIVED)."
               if l1_legacy else ""),
            check="logs", evidence=clean_evidence(raw),
            basis=fp.basis("N2S-17", note=note), fingerprints=["N2S-17"], **where))

    # N2S-18 - crash lines (counted; one finding per file in _finalize)
    if any(tok in text for tok in _CRASH_PREFILTER):
        for rx in RE_CRASH:
            if rx.search(text):
                state["crash"].append((line_no, raw))
                break

    # N2S-01..06 - seed bytes in a logged body / URL / response
    for sid, form, detail in find_seeds(text):
        out.append(finding(
            f"SEED_BYTES_{sid.replace('-', '_')}", "warn",
            f"{sid}: {_SEED_RULE[sid]} found as {form} in this log line" + (f" ({detail})" if detail else "")
            + ". Attempt / test evidence, not proof of execution; legitimate patch self-tests and exposure scanners "
              "send the same bytes.",
            check="logs", evidence=clean_evidence(raw),
            basis=fp.basis(sid, note="bytes copied verbatim; matched after decoding \\xNN / %NN escapes and as plain hex"),
            fingerprints=[sid], **where))


# ---------------------------------------------------------------------------
# access-record rules
# ---------------------------------------------------------------------------

def _tokens(values) -> list:
    toks = []
    for v in values or []:
        toks.extend(t for t in re.split(r"[,\s;]+", v.lower()) if t)
    return toks


def _size_info(rec: dict):
    """(kind, bytes): 'exact' from content_length / body_bytes_received, 'total' from request_length."""
    for key in ("content_length", "body_bytes_received"):
        n = _to_int(rec.get(key))
        if n is not None:
            return "exact", n
    n = _to_int(rec.get("request_length"))
    if n is not None:
        return "total", n
    return None


def _eval_record(rec: dict, raw: str, line_no: int, path: str, out: list, state: dict) -> None:
    where = {"file": path, "line": line_no}
    ua = (rec.get("ua") or "").strip()
    ua_low = ua.lower()
    ip = rec.get("ip")
    method = (rec.get("method") or "").upper()
    rpath = rec.get("path") or ""

    # N2S-08 / 09 / 10 - scanner user agents
    if ua_low.startswith(fp.UA_NODE2SHELL_CHECKER_PREFIX.lower()):
        out.append(finding(
            "UA_NODE2SHELL_CHECKER", "warn",
            "User-Agent starts with `Node2ShellChecker/` - the self-identifying UA of the completetech-security "
            "node2shell-check exposure checker (an authorised scan of your own estate, or someone else probing it) - "
            "attempt/exposure telemetry, not proof of execution",
            check="logs", evidence=ua, basis=fp.basis("N2S-08"), fingerprints=["N2S-08"], **where))
    if ua_low == fp.UA_SECURITY_SCANNER_GENERIC.lower():
        out.append(finding(
            "UA_SECURITY_SCANNER_GENERIC", "warn",
            "User-Agent is exactly `Mozilla/5.0 (compatible; security-scanner)` - the UA of the Ghost-Bx1 PoC "
            "(poc.py). It is generic: other scanners may use it too - attempt telemetry, not proof of execution",
            check="logs", evidence=ua, basis=fp.basis("N2S-09"), fingerprints=["N2S-09"], **where))
    if fp.UA_CVE_VERIFY_TOKEN in ua_low:
        out.append(finding(
            "UA_CVE_VERIFY", "warn",
            "User-Agent contains `cve-2026-111497-verify` - a self-identifying verifier UA copied from a fetched "
            "PoC/checker whose source repository the brief could not pin (UNCONFIRMED) - attempt telemetry, not "
            "proof of execution",
            check="logs", evidence=ua, basis=fp.basis("N2S-10"), fingerprints=["N2S-10"], **where))

    # Content-Encoding: br request rules (need request headers in the log)
    ce = rec.get("ce")
    size = _size_info(rec)
    has_body = method in BODY_METHODS or bool(rec.get("body")) or bool(size and size[0] == "exact" and size[1] > 0)
    toks = _tokens(ce)
    br = "br" in toks
    if br and has_body:
        out.append(finding(
            "REQUEST_CONTENT_ENCODING_BR", "warn",
            f"request with a body carries `Content-Encoding: {', '.join(ce)}` (token br) - Express 5 / body-parser 2.x "
            "and the other server-side decoders decode it by default, so this is the request shape that reaches the "
            "Brotli decoder. Rare but real legitimate senders exist (the Apify JS client brotli-compresses request "
            "bodies >= 1,024 B by default). Attempt evidence, not proof of execution.",
            check="logs", evidence=f"{method} {rec.get('uri')} Content-Encoding: {', '.join(ce)}",
            basis=fp.basis("N2S-11", note="header token match is case-insensitive and also inside lists"),
            fingerprints=["N2S-11"], **where))
        te = (rec.get("te") or "").lower()
        cl = rec.get("content_length")
        cl_n = _to_int(cl)
        if "chunked" in te and not (cl_n and cl_n > 0):
            out.append(finding(
                "BR_CHUNKED_NO_LENGTH", "warn",
                "`Content-Encoding: br` + `Transfer-Encoding: chunked` and no usable Content-Length - the shape the "
                "tc4dy crash_express request uses. Attempt evidence, not proof of execution.",
                check="logs", evidence=f"{method} {rec.get('uri')} CE={', '.join(ce)} TE={rec.get('te')}",
                basis=fp.basis("N2S-12"), fingerprints=["N2S-12"], **where))
        if method == "POST" and rpath == "/" and "application/octet-stream" in (rec.get("ctype") or "").lower():
            out.append(finding(
                "BR_OCTET_STREAM_ROOT_POST", "warn",
                "POST / with `Content-Type: application/octet-stream` and `Content-Encoding: br` - the shape of the "
                "tc4dy exploit.py / verifier.py. Attempt evidence, not proof of execution.",
                check="logs", evidence=f"POST / CT={rec.get('ctype')} CE={', '.join(ce)}",
                basis=fp.basis("N2S-14"), fingerprints=["N2S-14"], **where))
        if size and size[1] >= TH["br_large_body_min"]:
            out.append(finding(
                "BR_LARGE_BODY", "warn",
                f"very large `Content-Encoding: br` request body ({size[1]} bytes, {size[0]} size field) - the ~23 MB "
                "`1<<24 literals` stream of the public Python trigger is this size class; big legitimate uploads "
                "exist, but not usually Brotli-encoded. Attempt evidence, not proof of execution.",
                check="logs", evidence=f"{method} {rec.get('uri')} {size[0]}={size[1]} CE={', '.join(ce)}",
                basis=fp.basis("N2S-15", note=f"threshold {TH['br_large_body_min']} B is a tuning parameter derived "
                                               "from '1<<24 literals' / ~23 MB"),
                fingerprints=["N2S-15"], **where))
    if ce and (len(ce) >= 2 or (len(toks) >= 2 and len(set(toks)) < len(toks))) and has_body:
        out.append(finding(
            "DUPLICATE_CONTENT_ENCODING", "warn" if br else "info",
            "duplicate `Content-Encoding` request headers (or a repeated token) on a request with a body - the "
            "evasion shape Indusface AppTrana blocks"
            + (" (and one of them is br: it reaches the decoder)" if br else " (no br token: it cannot reach the Brotli decoder)")
            + ". A comma-joined `$http_content_encoding` cannot distinguish duplicates from a legal list.",
            check="logs", evidence=f"{method} {rec.get('uri')} Content-Encoding: {', '.join(ce)}",
            basis=fp.basis("N2S-13"), fingerprints=["N2S-13"], **where))

    # aggregates ------------------------------------------------------------
    if ip:
        if br and has_body:
            state["br_clients"][ip] += 1
            state["br_line"].setdefault(ip, line_no)
        route = (method, rpath)
        if route in fp.LAB_ROUTES:
            state["lab"][ip][f"{method} {rpath}"] += 1
        # N2S-07 sweep shape
        if method == "POST" and rpath in fp.OSTORLAB_CANDIDATE_PATHS and size:
            kind, n = size
            tiny = (n <= TH["sweep_tiny_exact_max"]) if kind == "exact" else (n <= TH["sweep_tiny_total_max"])
            if tiny:
                ent = state["sweep"][ip]
                ent["paths"].setdefault(rpath, line_no)
                ent["br"] = ent["br"] or br
                ent["doc"] = ent["doc"] or (kind == "exact" and n in fp.OSTORLAB_BODY_SIZES)
                ent["sizes"].add(f"{n}{'' if kind == 'exact' else ' (request_length)'}")
                ent["first_raw"] = ent["first_raw"] or raw


def new_state() -> dict:
    return {
        "crash": [],
        "br_clients": Counter(),
        "br_line": {},
        "lab": defaultdict(Counter),
        "sweep": defaultdict(lambda: {"paths": {}, "br": False, "doc": False, "sizes": set(), "first_raw": ""}),
    }


def eval_line(rec: Optional[dict], text: str, raw: str, line_no: int, path: str, out: list, state: dict) -> None:
    """Evaluate one log line: text rules always, access rules when the line parsed as a request."""
    _eval_text(text, raw, line_no, path, out, state)
    if rec is not None:
        _eval_record(rec, raw, line_no, path, out, state)


def _finalize(state: dict, path: str, out: list) -> None:
    # N2S-18 - crash lines: a single crash is a triage clue only (Imperva)
    crashes = state["crash"]
    if crashes:
        sev = "warn" if len(crashes) >= TH["crash_warn_min"] else "info"
        first = crashes[0]
        out.append(finding(
            "NODE_PROCESS_CRASH", sev,
            f"{len(crashes)} Node/Bun crash record(s) in this log (kernel segfault in node/bun, `Segmentation fault`, "
            "systemd-coredump, exit code 139). Imperva: unexpected exits are a triage clue, 'not a reliable "
            "stand-alone sign of exploitation' - correlate with `Content-Encoding: br` requests and outbound fetches "
            "at the same timestamps. Warn from "
            f"{TH['crash_warn_min']} records.",
            check="logs", file=path, line=first[0], evidence=clean_evidence(first[1]),
            basis=fp.basis("N2S-18", note=f"warn threshold {TH['crash_warn_min']} is a tuning parameter"),
            fingerprints=["N2S-18"]))
    # N2S-07 - Ostorlab sweep shape
    for ip, ent in state["sweep"].items():
        if len(ent["paths"]) >= TH["sweep_min_paths"]:
            strong = ent["br"] or ent["doc"]
            out.append(finding(
                "OSTORLAB_PROBE_SWEEP", "warn" if strong else "info",
                f"client {defang(ip)} POSTed tiny bodies to {len(ent['paths'])} of the 4 Ostorlab candidate paths "
                f"({', '.join(sorted(ent['paths']))}) - the exposure-scanner sweep shape (negative control "
                '`{"ping":1}` + Content-Encoding: br, then the 22 B vector).'
                + (" Documented body sizes (10 / 14 / 22 B) or a br header were seen." if strong
                   else " No br header / documented body size visible: shape only.")
                + " A scan, not an exploit - but it is how exposure gets mapped.",
                check="logs", file=path, line=min(ent["paths"].values()),
                evidence=clean_evidence(f"{ip} POST {' '.join(sorted(ent['paths']))} sizes={','.join(sorted(ent['sizes']))}"),
                basis=fp.basis("N2S-07", note=f"needs request-length fields; tiny = <= {TH['sweep_tiny_exact_max']} B "
                                              f"(content-length) or <= {TH['sweep_tiny_total_max']} B (request_length) - tuning parameters"),
                fingerprints=["N2S-07"]))
    # N2S-22 - lab routes together with br
    for ip, routes in state["lab"].items():
        if state["br_clients"].get(ip):
            warm = routes.get(f"{fp.LAB_WARM_ROUTE[0]} {fp.LAB_WARM_ROUTE[1]}", 0)
            out.append(finding(
                "LAB_ROUTES_WITH_BR", "warn",
                f"client {defang(ip)} sent {state['br_clients'][ip]} `Content-Encoding: br` request(s) AND hit PoC-lab "
                f"routes ({', '.join(f'{r} x{n}' for r, n in sorted(routes.items()))})"
                + (f"; GET /warm x{warm} is the repeated heap-grooming cadence" if warm >= TH["warm_repeat_min"] else "")
                + ". The route names are common - the br header from the same client is what makes this a signal. "
                  "Attempt evidence, not proof of execution.",
                check="logs", file=path, line=state["br_line"].get(ip),
                evidence=clean_evidence(f"{ip} routes: {dict(routes)} br_requests={state['br_clients'][ip]}"),
                basis=fp.basis("N2S-22", note="only together with br from the same client"),
                fingerprints=["N2S-22", "N2S-11"]))


# ---------------------------------------------------------------------------
# file scanning entry
# ---------------------------------------------------------------------------

def _compact_findings(out: list, per_rule_display: int = 8, cap: int = 60) -> list:
    """Per rule show the first N line hits with a repeat_count, then cap the whole list
    severity-first (critical first)."""
    per_rule = defaultdict(list)
    for f in out:
        per_rule[f["rule"]].append(f)
    final = []
    for rule, fs in per_rule.items():
        fs.sort(key=lambda f: (f.get("line") or 0))
        kept = list(fs[:per_rule_display])
        if len(fs) > per_rule_display and kept:
            kept[0]["repeat_count"] = len(fs)
        final.extend(kept)
    sev_rank = {"critical": 0, "warn": 1, "info": 2, "ok": 3}
    final.sort(key=lambda f: (sev_rank.get(f.get("severity"), 9), f.get("line") or 0))
    return final[:cap]


def scan_log_file(path: str, fmt: str = "auto", max_lines: int = 200000) -> dict:
    out = []
    state = new_state()
    stats = {"lines_scanned": 0, "parsed": 0, "unparsed": 0}
    fmt_seen = set()
    cap = TH["scan_text_cap"]
    for i, line in iter_lines(path):
        if i > max_lines:
            break
        stats["lines_scanned"] += 1
        if not line.strip():
            continue
        raw = line.rstrip("\r\n")
        text = raw[:cap]
        rec, is_json = None, False
        if fmt in ("auto", "json") and raw.lstrip().startswith("{"):
            rec, flat = parse_json_line(raw)
            if flat is not None:                  # valid JSON: rules run on the decoded field text
                is_json = True
                text = _flat_text(flat)[:cap]
        if rec is None and not is_json:
            rec = parse_access_line(raw, fmt)
        if rec is None:
            stats["unparsed"] += 1
        else:
            stats["parsed"] += 1
            fmt_seen.add(rec.get("format", "?"))
        eval_line(rec, text, raw, i, path, out, state)
    _finalize(state, path, out)
    compact = _compact_findings(out)
    kind = "access" if stats["parsed"] and stats["parsed"] >= stats["unparsed"] else (
        "mixed" if stats["parsed"] else "text")
    return {
        "path": path, "kind": kind,
        "format": ",".join(sorted(fmt_seen)) if fmt_seen else ("text" if fmt == "auto" else fmt),
        "lines_scanned": stats["lines_scanned"], "parsed": stats["parsed"], "unparsed": stats["unparsed"],
        "findings": compact, "finding_count": len(out), "finding_cap": 60,
    }
