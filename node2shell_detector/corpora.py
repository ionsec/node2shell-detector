"""Synthetic log corpora for node2shell-detector tests and examples.

The EXPLOIT corpora contain ONLY values documented in the research brief (BRIEF s7,
fingerprint ids N2S-01 .. N2S-25): UA strings, seed bytes, header shapes, error
strings, crash-line shapes. Each builder cites its fingerprint id inline. Nothing here
is a working exploit: the seed bytes are the public regression vector / published PoC
constants used as DATA inside log text.

Synthetic, clearly not published values: client IPs come from the RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); the
`Node2ShellChecker/` version suffix is a placeholder (the brief gives only
`Node2ShellChecker/<version>`); timestamps and routes are invented.

The BENIGN corpora contain ordinary traffic chosen to trip nothing: browsers, curl,
python-requests, normal `Accept-Encoding: br` on REQUESTS and `Content-Encoding: br` on
RESPONSES, EEXIST / EBADF errno lines, auditd `uid=0 gid=0` fields.

Bodies and headers live in LTSV fields / JSON lines (escaped like nginx `$request_body`)
so the corpus stays line-based; the tool decodes the escapes before matching.
"""

import json

from . import fingerprints as fp

CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
BENIGN_UAS = {
    "curl": "curl/8.5.0",
    "plain": "Mozilla/5.0",
    "chrome": CHROME_UA,
    "firefox": FIREFOX_UA,
    "requests": "python-requests/2.31.0",
    "node": "node",
    "undici": "undici",
    "axios": "axios/1.7.2",
}

# documentation-range client addresses (synthetic)
IP_A, IP_B, IP_C, IP_D = "192.0.2.10", "192.0.2.11", "198.51.100.7", "203.0.113.9"


def esc(body: str) -> str:
    """Escape a body so it can live on one LTSV log line."""
    return (body.replace("\\", "\\\\").replace("\x00", "\\x00")
            .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"))


def nginx_escape(data: bytes) -> str:
    """nginx `$request_body` default escaping: bytes < 0x20, `"`, `\\` and > 0x7e become \\xNN."""
    return "".join("\\x%02X" % b if (b < 0x20 or b > 0x7E or b in (0x22, 0x5C)) else chr(b) for b in data)


def percent_encode(data: bytes) -> str:
    return "".join(chr(b) if (0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A) else "%%%02X" % b
                   for b in data)


def ltsv(fields: dict) -> str:
    return "\t".join(f"{k}:{v}" for k, v in fields.items())


def combined(ip: str, ts: str, method: str, uri: str, status: int, size: int, ua: str, ref: str = "-") -> str:
    return f'{ip} - - [{ts} +0000] "{method} {uri} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


# ---------------------------------------------------------------- benign ----

def benign_access_combined() -> list:
    return [
        combined("10.0.0.14", "24/Oct/2026:09:00:11", "GET", "/", 200, 10413, CHROME_UA),
        combined("10.0.0.15", "24/Oct/2026:09:00:41", "POST", "/login", 302, 210, FIREFOX_UA,
                 "https://www.example.org/login"),
        combined("10.0.0.16", "24/Oct/2026:09:01:02", "GET", "/robots.txt", 404, 153, BENIGN_UAS["curl"]),
        combined("10.0.0.17", "24/Oct/2026:09:01:44", "GET", "/api/status", 200, 77, BENIGN_UAS["requests"]),
        # lab-route NAMES are common routes: no br from this client -> not a signal
        combined("10.0.0.16", "24/Oct/2026:09:03:14", "GET", "/health", 200, 4, BENIGN_UAS["curl"]),
        combined("10.0.0.18", "24/Oct/2026:09:03:20", "POST", "/upload", 200, 33, BENIGN_UAS["axios"]),
        combined("10.0.0.18", "24/Oct/2026:09:03:55", "GET", "/graphql?query=%7Bme%7Bid%7D%7D", 200, 120, BENIGN_UAS["undici"]),
        combined("10.0.0.19", "24/Oct/2026:09:04:10", "POST", "/api/v1/orders", 201, 512, BENIGN_UAS["node"]),
    ]


def benign_access_ltsv() -> list:
    out = []
    # normal Accept-Encoding: br on the REQUEST, Content-Encoding: br on the RESPONSE (resp_ / sent_ keys)
    out.append(ltsv({"host": "10.0.0.14", "time": "24/Oct/2026:09:10:00", "req": "GET /static/app.js HTTP/1.1",
                     "status": "200", "size": "88211", "ua": CHROME_UA, "accept_encoding": "gzip, deflate, br",
                     "resp_content_encoding": "br", "sent_http_content_encoding": "br"}))
    # a gzip-compressed JSON request body: Content-Encoding present, but not br
    out.append(ltsv({"host": "10.0.0.20", "time": "24/Oct/2026:09:10:30", "req": "POST /api/v1/events HTTP/1.1",
                     "status": "202", "size": "0", "ua": BENIGN_UAS["node"], "content_encoding": "gzip",
                     "content_type": "application/json", "content_length": "812", "request_length": "1310"}))
    # ordinary JSON POSTs to ONE candidate path (a sweep needs >= 3 distinct paths)
    for i in range(3):
        out.append(ltsv({"host": "10.0.0.21", "time": f"24/Oct/2026:09:11:0{i}", "req": "POST /api/v1 HTTP/1.1",
                         "status": "200", "size": "17", "ua": BENIGN_UAS["axios"],
                         "content_type": "application/json", "content_length": "10", "request_length": "205"}))
    # a large upload without any Content-Encoding
    out.append(ltsv({"host": "10.0.0.22", "time": "24/Oct/2026:09:12:00", "req": "POST /upload HTTP/1.1",
                     "status": "200", "size": "0", "ua": FIREFOX_UA, "content_type": "multipart/form-data",
                     "content_length": "25281929", "request_length": "25282400"}))
    # POST / with octet-stream but no br
    out.append(ltsv({"host": "10.0.0.23", "time": "24/Oct/2026:09:12:30", "req": "POST / HTTP/1.1",
                     "status": "200", "size": "2", "ua": BENIGN_UAS["curl"],
                     "content_type": "application/octet-stream", "content_length": "64"}))
    # a benign body that is plain text
    out.append(ltsv({"host": "10.0.0.24", "time": "24/Oct/2026:09:13:00", "req": "POST /api/notes HTTP/1.1",
                     "status": "200", "size": "5", "ua": CHROME_UA, "content_length": "27",
                     "body": esc('{"title":"hello","text":"world"}')}))
    return out


def benign_access_json() -> list:
    nginx_style = {"remote_addr": "10.0.0.30", "time_iso8601": "2026-10-24T09:20:00+00:00",
                   "request": "GET /app.css HTTP/1.1", "status": 200, "body_bytes_sent": 5120,
                   "http_user_agent": CHROME_UA, "http_accept_encoding": "gzip, deflate, br",
                   "sent_http_content_encoding": "br"}
    caddy_style = {"level": "info", "ts": 1761297600.1, "logger": "http.log.access",
                   "request": {"remote_ip": "10.0.0.31", "method": "GET", "uri": "/index.html",
                               "headers": {"User-Agent": [CHROME_UA], "Accept-Encoding": ["gzip, deflate, br"]}},
                   "status": 200, "size": 2048,
                   "resp_headers": {"Content-Encoding": ["br"], "Content-Type": ["text/html"]}}
    return [json.dumps(nginx_style), json.dumps(caddy_style)]


def benign_app_log() -> list:
    return [
        "[2026-10-24T09:30:00.123Z] INFO server listening on :3000",
        "[2026-10-24T09:30:05.401Z] ERROR Error: EEXIST: file already exists, mkdir '/tmp/cache' "
        "{ errno: -17, code: 'EEXIST', syscall: 'mkdir', path: '/tmp/cache' }",
        "[2026-10-24T09:30:06.002Z] ERROR Error: EBADF: bad file descriptor, close "
        "{ errno: -9, code: 'EBADF', syscall: 'close' }",
        "[2026-10-24T09:30:07.870Z] WARN Error: incorrect header check at Zlib.zlibOnError "
        "{ errno: -3, code: 'Z_DATA_ERROR' }",
        # auditd-style uid/gid fields are not `id` output
        "type=SYSCALL msg=audit(1761298200.123:4242): arch=c000003e syscall=59 success=yes exit=0 "
        "auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 comm=\"ls\" exe=\"/usr/bin/ls\"",
        json.dumps({"level": 30, "time": 1761298300000, "msg": "request completed", "res": {"statusCode": 200}}),
    ]


def all_benign_lines() -> list:
    return benign_access_combined() + benign_access_ltsv() + benign_access_json() + benign_app_log()


# --------------------------------------------------------------- exploit ----

def _seed_line(ip: str, sid: str, body: bytes, form: str = "nginx") -> str:
    """One LTSV line whose logged body carries seed bytes `body` (N2S-01..06)."""
    logged = nginx_escape(body) if form == "nginx" else body.hex()
    return ltsv({"host": ip, "time": "24/Oct/2026:10:00:00", "req": "POST /api HTTP/1.1", "status": "400",
                 "size": "52", "ua": CHROME_UA, "content_length": str(len(body)), "body": logged})


def exploit_lines_by_id() -> dict:
    """{fingerprint id: [log lines]} - one scenario per log-visible fingerprint, built from catalogue values."""
    br_hdr = {"content_encoding": "br", "content_type": "application/json"}
    L = {}
    # N2S-08 / 09 / 10 - user agents (access log, combined format)
    L["N2S-08"] = [combined(IP_A, "24/Oct/2026:10:01:00", "GET", "/", 200, 512, fp.UA_EXAMPLES[0][1])]
    L["N2S-09"] = [combined(IP_B, "24/Oct/2026:10:01:10", "POST", "/", 400, 40, fp.UA_SECURITY_SCANNER_GENERIC)]
    L["N2S-10"] = [combined(IP_C, "24/Oct/2026:10:01:20", "POST", "/api", 400, 40, fp.UA_CVE_VERIFY_TOKEN)]
    # N2S-01..06 - seed bytes in a logged request body (nginx-escaped) ...
    L["N2S-01"] = [_seed_line(IP_A, "N2S-01", fp.SEED_BYTES["N2S-01"]),
                   _seed_line(IP_B, "N2S-01", fp.SEED_BYTES["N2S-01"], form="hex")]   # ... and as a hex dump
    L["N2S-02"] = [_seed_line(IP_A, "N2S-02", fp.SEED_BYTES["N2S-02"])]
    L["N2S-03"] = [_seed_line(IP_A, "N2S-03", fp.SEED_BYTES["N2S-03"])]
    L["N2S-04"] = [_seed_line(IP_A, "N2S-04", fp.SEED_BYTES["N2S-04"])]
    L["N2S-05"] = [_seed_line(IP_A, "N2S-05", fp.N2S_05_BYTES)]
    L["N2S-06"] = [_seed_line(IP_A, "N2S-06", fp.SEED_BYTES["N2S-06"])]
    # N2S-07 - Ostorlab sweep: same client, four candidate paths, tiny br bodies of 10 / 14 / 22 B
    sweep = []
    for n, (path, size) in enumerate((("/", 10), ("/api", 14), ("/api/v1", 22), ("/graphql", 22))):
        sweep.append(ltsv({"host": IP_D, "time": f"24/Oct/2026:10:02:0{n}", "req": f"POST {path} HTTP/1.1",
                           "status": "400", "size": "31", "ua": "python-httpx/0.27.0",
                           "content_length": str(size), "request_length": str(size + 230),
                           **br_hdr, "accept": "application/json"}))
    L["N2S-07"] = sweep
    # N2S-11 - br request body
    L["N2S-11"] = [ltsv({"host": IP_A, "time": "24/Oct/2026:10:03:00", "req": "POST /api/upload HTTP/1.1",
                         "status": "400", "size": "40", "ua": CHROME_UA, "content_length": "180", **br_hdr})]
    # N2S-12 - br + chunked, no Content-Length
    L["N2S-12"] = [ltsv({"host": IP_B, "time": "24/Oct/2026:10:03:10", "req": "POST /api/upload HTTP/1.1",
                         "status": "500", "size": "0", "ua": CHROME_UA, "content_encoding": "br",
                         "transfer_encoding": "chunked", "content_length": "-"})]
    # N2S-13 - duplicate Content-Encoding request headers (JSON array of header lines)
    L["N2S-13"] = [json.dumps({"request": {"remote_ip": IP_C, "method": "POST", "uri": "/api/v1",
                                           "headers": {"Content-Encoding": ["br", "br"],
                                                       "Content-Type": ["application/json"],
                                                       "Content-Length": ["22"]}},
                               "status": 400, "size": 31})]
    # N2S-14 - br + application/octet-stream POST /
    L["N2S-14"] = [ltsv({"host": IP_D, "time": "24/Oct/2026:10:03:30", "req": "POST / HTTP/1.1", "status": "400",
                         "size": "21", "ua": CHROME_UA, "content_encoding": "br",
                         "content_type": "application/octet-stream", "content_length": "22"})]
    # N2S-15 - ~23 MB br request body (1<<24 literals) -> synthetic size 23,068,672 B
    L["N2S-15"] = [ltsv({"host": IP_A, "time": "24/Oct/2026:10:03:40", "req": "POST /api/import HTTP/1.1",
                         "status": "413", "size": "0", "ua": CHROME_UA, "content_length": "23068672",
                         "request_length": "23069000", **br_hdr})]
    # N2S-16 / 17 - application log lines (Node app stderr)
    L["N2S-16"] = [
        "[2026-10-24T10:04:00.100Z] ERROR Error: Decompression failed\n".rstrip("\n")
        + " at BrotliDecoder.zlibOnError [as onerror] (node:zlib:190:17) "
          "{ errno: -17, code: 'ERR__ERROR_FORMAT_BLOCK_SWITCH' }",
        json.dumps({"level": 50, "time": 1761299040000, "msg": "body decode failed",
                    "err": {"code": "ERR__ERROR_FORMAT_BLOCK_SWITCH", "errno": -17, "type": "Error"}}),
        # bare form of a decoder built from Brotli 1.0.x (no _ERROR_FORMAT_ prefix) - DERIVED, see LEGACY_NAMES_NOTE
        "[2026-10-24T10:04:05.300Z] ERROR Error: Decompression failed "
        "{ errno: -17, code: 'ERR_BLOCK_SWITCH' }",
    ]
    L["N2S-17"] = ["[2026-10-24T10:04:10.200Z] ERROR Error: Decompression failed "
                   "{ errno: -9, code: 'ERR__ERROR_FORMAT_BLOCK_LENGTH_1' }",
                   "[2026-10-24T10:04:11.200Z] ERROR Error: Decompression failed "
                   "{ errno: -9, code: 'ERR_BLOCK_LENGTH_1' }"]
    # N2S-18 - crash records: kernel segfault, systemd-coredump, shell, exit code 139 (3 -> warn)
    L["N2S-18"] = [
        "Oct 24 10:05:00 host kernel: node[4242]: segfault at 7f3a00000000 ip 0000563c1a2b3c4d sp 00007ffd1c2e3f40 "
        "error 4 in node[563c19800000+2a00000]",
        "Oct 24 10:05:01 host systemd-coredump[4300]: Process 4242 (node) of user 1000 dumped core.",
        "Oct 24 10:05:02 host app.sh[1]: Segmentation fault (core dumped) node server.js",
        "Oct 24 10:05:05 host dockerd[9]: container 3f2a exited with code 139",
    ]
    # N2S-19 - `id` output in a logged response body
    L["N2S-19"] = [
        ltsv({"host": IP_B, "time": "24/Oct/2026:10:06:00", "req": "POST /api HTTP/1.1", "status": "200",
              "size": "55", "ua": CHROME_UA, "resp_body": "uid=1000(node) gid=1000(node) groups=1000(node)"}),
        "[2026-10-24T10:06:01.000Z] INFO uid=0(root) gid=0(root) groups=0(root)",
    ]
    # N2S-22 - lab routes together with br from the same client
    lab = [ltsv({"host": IP_C, "time": "24/Oct/2026:10:07:00", "req": "POST /upload HTTP/1.1", "status": "400",
                 "size": "30", "ua": CHROME_UA, "content_length": "22", **br_hdr})]
    for n in range(3):
        lab.append(ltsv({"host": IP_C, "time": f"24/Oct/2026:10:07:1{n}", "req": "GET /warm HTTP/1.1",
                         "status": "200", "size": "2", "ua": CHROME_UA}))
    lab.append(ltsv({"host": IP_C, "time": "24/Oct/2026:10:07:30", "req": "GET /health HTTP/1.1", "status": "200",
                     "size": "4", "ua": CHROME_UA}))
    L["N2S-22"] = lab
    return L


#: fingerprint id -> the rule the host tool must raise for it (back-audit target)
EXPECTED_RULE = {
    "N2S-01": "SEED_BYTES_N2S_01", "N2S-02": "SEED_BYTES_N2S_02", "N2S-03": "SEED_BYTES_N2S_03",
    "N2S-04": "SEED_BYTES_N2S_04", "N2S-05": "SEED_BYTES_N2S_05", "N2S-06": "SEED_BYTES_N2S_06",
    "N2S-07": "OSTORLAB_PROBE_SWEEP", "N2S-08": "UA_NODE2SHELL_CHECKER", "N2S-09": "UA_SECURITY_SCANNER_GENERIC",
    "N2S-10": "UA_CVE_VERIFY", "N2S-11": "REQUEST_CONTENT_ENCODING_BR", "N2S-12": "BR_CHUNKED_NO_LENGTH",
    "N2S-13": "DUPLICATE_CONTENT_ENCODING", "N2S-14": "BR_OCTET_STREAM_ROOT_POST", "N2S-15": "BR_LARGE_BODY",
    "N2S-16": "BROTLI_BLOCK_SWITCH_ERROR", "N2S-17": "BROTLI_BLOCK_LENGTH_1_ERROR", "N2S-18": "NODE_PROCESS_CRASH",
    "N2S-19": "RESPONSE_ID_MARKER", "N2S-22": "LAB_ROUTES_WITH_BR",
}


def exploit_access_lines() -> list:
    """Every exploit scenario that is an access-log line (for the example log)."""
    out = []
    for sid, lines in exploit_lines_by_id().items():
        if sid in ("N2S-16", "N2S-17", "N2S-18"):
            continue
        out.extend(lines)
    return out


def exploit_app_lines() -> list:
    L = exploit_lines_by_id()
    return L["N2S-16"] + L["N2S-17"] + L["N2S-18"] + [L["N2S-19"][1]]


def all_exploit_lines() -> list:
    out = []
    for lines in exploit_lines_by_id().values():
        out.extend(lines)
    return out
