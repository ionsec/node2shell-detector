"""LOG SCAN: formats, every log-side N2S rule, benign traffic, decoding, compaction, defanging."""

import gzip
import json

import pytest

from conftest import write_lines
from node2shell_detector import corpora, fingerprints as fp, logs

IP = "192.0.2.50"


def scan(tmp_path, lines, name="access.log", fmt="auto", max_lines=200000):
    p = write_lines(tmp_path, name, lines)
    return logs.scan_log_file(str(p), fmt=fmt, max_lines=max_lines)


def rules(res):
    return [f["rule"] for f in res["findings"]]


def one(res, rule):
    hits = [f for f in res["findings"] if f["rule"] == rule]
    assert hits, f"{rule} not in {sorted(set(rules(res)))}"
    return hits[0]


def req(method="POST", path="/api", **fields):
    base = {"host": IP, "time": "24/Oct/2026:11:00:00", "req": f"{method} {path} HTTP/1.1",
            "status": "400", "size": "0", "ua": "curl/8.5.0"}
    base.update(fields)
    return corpora.ltsv(base)


# ------------------------------------------------------------------ benign ----

def test_benign_corpora_produce_nothing(tmp_path):
    for name, lines in (("combined", corpora.benign_access_combined()), ("ltsv", corpora.benign_access_ltsv()),
                        ("json", corpora.benign_access_json()), ("app", corpora.benign_app_log()),
                        ("all", corpora.all_benign_lines())):
        res = scan(tmp_path, lines, name=f"{name}.log")
        assert res["finding_count"] == 0, (name, [f["rule"] for f in res["findings"]])


@pytest.mark.parametrize("label,ua", sorted(corpora.BENIGN_UAS.items()))
def test_benign_user_agents_are_not_flagged(tmp_path, label, ua):
    line = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "POST", "/api", 200, 10, ua)
    assert scan(tmp_path, [line])["finding_count"] == 0


def test_normal_br_on_requests_and_responses_is_not_flagged(tmp_path):
    lines = [
        req("GET", "/app.js", accept_encoding="gzip, deflate, br", resp_content_encoding="br"),
        req("GET", "/app.css", http_accept_encoding="gzip, deflate, br", sent_http_content_encoding="br"),
        req("GET", "/x", out_content_encoding="br"),
        req("GET", "/y", upstream_http_content_encoding="br"),
        json.dumps({"request": {"method": "GET", "uri": "/z", "remote_ip": "192.0.2.51",
                                "headers": {"Accept-Encoding": ["gzip, deflate, br"]}},
                    "resp_headers": {"Content-Encoding": ["br"]}, "status": 200}),
        json.dumps({"request": {"method": "GET", "uri": "/z", "remote_ip": "192.0.2.51"},
                    "response": {"headers": {"Content-Encoding": "br"}}, "status": 200}),
    ]
    assert scan(tmp_path, lines)["finding_count"] == 0


# ------------------------------------------------------------------ the back-audit ----

EXPECTED_SEVERITY = {"N2S-19": "critical", "N2S-17": "info"}


@pytest.mark.parametrize("sid", sorted(corpora.EXPECTED_RULE))
def test_each_fingerprint_scenario_fires_its_rule(tmp_path, sid):
    res = scan(tmp_path, corpora.exploit_lines_by_id()[sid])
    hits = [f for f in res["findings"] if f["rule"] == corpora.EXPECTED_RULE[sid]]
    assert hits, f"{sid}: {corpora.EXPECTED_RULE[sid]} not raised; got {sorted(set(rules(res)))}"
    assert all(sid in f["fingerprints"] for f in hits)
    assert hits[0]["severity"] == EXPECTED_SEVERITY.get(sid, "warn")
    for f in hits:
        assert f["basis"].startswith(("VERBATIM", "DERIVED")) and sid in f["basis"]
        assert f["check"] == "logs" and f["file"] and f["line"]
        assert f["evidence"]


def test_full_exploit_corpus_in_one_file(tmp_path):
    res = scan(tmp_path, corpora.all_exploit_lines())
    assert set(corpora.EXPECTED_RULE.values()) <= set(rules(res))
    assert res["findings"][0]["severity"] == "critical"                     # severity-first ordering
    assert res["finding_count"] >= len(set(corpora.EXPECTED_RULE.values()))


def test_attempt_evidence_wording_is_present(tmp_path):
    res = scan(tmp_path, corpora.exploit_lines_by_id()["N2S-11"] + corpora.exploit_lines_by_id()["N2S-16"])
    for rule in ("REQUEST_CONTENT_ENCODING_BR", "BROTLI_BLOCK_SWITCH_ERROR"):
        msg = one(res, rule)["message"]
        assert "attempt" in msg.lower()
    assert "not proof of execution" in one(res, "REQUEST_CONTENT_ENCODING_BR")["message"]
    assert "PATCHED decoder" in one(res, "BROTLI_BLOCK_SWITCH_ERROR")["message"]


# ------------------------------------------------------------------ formats ----

def test_parse_formats():
    c = logs.parse_access_line('192.0.2.10 - - [24/Oct/2026:10:00:00 +0000] "POST /api?x=1 HTTP/1.1" 200 12 "-" "curl/8.5.0"')
    assert (c["format"], c["method"], c["uri"], c["path"], c["status"], c["ua"]) == (
        "combined", "POST", "/api?x=1", "/api", 200, "curl/8.5.0")
    common = logs.parse_access_line('192.0.2.10 - - [24/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 404 153')
    assert common["format"] == "common" and common["ua"] == "" and common["ce"] is None
    lt = logs.parse_access_line(req("POST", "/graphql", content_encoding="br", content_length="22",
                                    content_type="application/json", transfer_encoding="chunked"))
    assert lt["format"] == "ltsv" and lt["ip"] == IP and lt["path"] == "/graphql"
    assert lt["ce"] == ["br"] and lt["ctype"] == "application/json" and lt["te"] == "chunked"
    assert lt["content_length"] == "22"
    nginx = logs.parse_access_line(json.dumps({"remote_addr": "192.0.2.11", "request": "POST /x HTTP/1.1", "status": 200,
                                               "http_user_agent": "ua/1", "http_content_encoding": "br",
                                               "request_length": 300}))
    assert nginx["format"] == "json" and nginx["ip"] == "192.0.2.11" and nginx["ce"] == ["br"]
    assert nginx["request_length"] == "300"
    caddy = logs.parse_access_line(json.dumps({"request": {"remote_ip": "192.0.2.12", "method": "POST", "uri": "/y",
                                                           "headers": {"Content-Encoding": ["br", "gzip"],
                                                                       "User-Agent": ["ua/2"],
                                                                       "Content-Length": ["22"]}}, "status": 400}))
    assert caddy["ip"] == "192.0.2.12" and caddy["ce"] == ["br", "gzip"] and caddy["ua"] == "ua/2"
    assert caddy["content_length"] == "22"
    assert logs.parse_access_line("this is not a log line") is None
    assert logs.parse_access_line("{not json") is None


def test_docker_json_wrapper_is_unwrapped(tmp_path):
    inner_ltsv = req("POST", "/api", content_encoding="br", content_length="22")
    wrapped = json.dumps({"log": inner_ltsv + "\n", "stream": "stdout", "time": "2026-10-24T10:00:00Z"})
    app = json.dumps({"log": "[ts] ERROR { errno: -17, code: 'ERR__ERROR_FORMAT_BLOCK_SWITCH' }\n", "stream": "stderr"})
    res = scan(tmp_path, [wrapped, app])
    assert "REQUEST_CONTENT_ENCODING_BR" in rules(res) and "BROTLI_BLOCK_SWITCH_ERROR" in rules(res)
    rec = logs.parse_access_line(wrapped)
    assert rec["format"] == "json+ltsv"


def test_forced_formats(tmp_path):
    comb = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, fp.UA_SECURITY_SCANNER_GENERIC)
    assert "UA_SECURITY_SCANNER_GENERIC" in rules(scan(tmp_path, [comb], fmt="combined"))
    assert "UA_SECURITY_SCANNER_GENERIC" not in rules(scan(tmp_path, [comb], fmt="ltsv"))
    assert "UA_SECURITY_SCANNER_GENERIC" not in rules(scan(tmp_path, [comb], fmt="json"))
    ltsv_line = req(ua=fp.UA_SECURITY_SCANNER_GENERIC)
    assert "UA_SECURITY_SCANNER_GENERIC" in rules(scan(tmp_path, [ltsv_line], fmt="ltsv"))
    assert "UA_SECURITY_SCANNER_GENERIC" not in rules(scan(tmp_path, [ltsv_line], fmt="combined"))
    # text rules run on every line whatever the forced format
    app = "[ts] { errno: -17, code: 'ERR__ERROR_FORMAT_BLOCK_SWITCH' }"
    assert "BROTLI_BLOCK_SWITCH_ERROR" in rules(scan(tmp_path, [app], fmt="json"))


def test_kind_and_format_reporting(tmp_path):
    res = scan(tmp_path, corpora.benign_access_combined())
    assert res["kind"] == "access" and res["format"] == "combined" and res["unparsed"] == 0
    res = scan(tmp_path, corpora.benign_app_log()[:3], name="app.log")
    assert res["kind"] == "text" and res["parsed"] == 0
    mixed = scan(tmp_path, corpora.benign_access_combined()[:3] + corpora.benign_app_log()[:4], name="mixed.log")
    assert mixed["kind"] == "mixed"


# ------------------------------------------------------------------ user agents ----

@pytest.mark.parametrize("ua,expected", [
    ("Node2ShellChecker/1.2.3", True),
    ("Node2ShellChecker/0.0.0 (+https://example.org/contact)", True),
    ("node2shellchecker/0.1", True),                                   # prefix match is case-insensitive
    ("MyNode2ShellChecker/1", False),                                  # 'starts with', not 'contains'
    ("Node2Shell", False),
])
def test_ua_n2s_08(tmp_path, ua, expected):
    line = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, ua)
    assert ("UA_NODE2SHELL_CHECKER" in rules(scan(tmp_path, [line]))) is expected


@pytest.mark.parametrize("ua,expected", [
    ("Mozilla/5.0 (compatible; security-scanner)", True),
    ("mozilla/5.0 (compatible; Security-Scanner)", True),
    ("Mozilla/5.0 (compatible; security-scanner) Extra", False),       # exact match only
    ("Mozilla/5.0 (compatible; Googlebot/2.1)", False),
])
def test_ua_n2s_09(tmp_path, ua, expected):
    line = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, ua)
    assert ("UA_SECURITY_SCANNER_GENERIC" in rules(scan(tmp_path, [line]))) is expected


@pytest.mark.parametrize("ua,expected", [
    ("cve-2026-111497-verify", True), ("cve-2026-111497-verify/1.0", True), ("CVE-2026-111497-Verify", True),
    ("cve-2026-111497", False),
])
def test_ua_n2s_10(tmp_path, ua, expected):
    line = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, ua)
    res = scan(tmp_path, [line])
    assert ("UA_CVE_VERIFY" in rules(res)) is expected
    if expected:
        assert "UNCONFIRMED" in one(res, "UA_CVE_VERIFY")["message"]


# ------------------------------------------------------------------ Content-Encoding: br ----

@pytest.mark.parametrize("ce,flag", [
    ("br", True), ("BR", True), ("gzip, br", True), ("br, gzip", True), ("Br ", True),
    ("gzip", False), ("identity", False), ("bar", False), ("", False), ("-", False),
])
def test_n2s_11_token_match(tmp_path, ce, flag):
    res = scan(tmp_path, [req("POST", "/api", content_encoding=ce, content_length="30")])
    assert ("REQUEST_CONTENT_ENCODING_BR" in rules(res)) is flag


def test_n2s_11_needs_a_body_and_a_logged_header(tmp_path):
    assert "REQUEST_CONTENT_ENCODING_BR" not in rules(scan(tmp_path, [req("GET", "/", content_encoding="br")]))
    assert "REQUEST_CONTENT_ENCODING_BR" in rules(scan(tmp_path, [req("PUT", "/x", content_encoding="br")]))
    assert "REQUEST_CONTENT_ENCODING_BR" in rules(scan(tmp_path, [req("GET", "/x", content_encoding="br",
                                                                      content_length="22")]))      # a GET with a body
    assert scan(tmp_path, [req("POST", "/api")])["finding_count"] == 0                             # header not logged
    f = one(scan(tmp_path, [req("POST", "/api", content_encoding="br")]), "REQUEST_CONTENT_ENCODING_BR")
    assert "Apify" in f["message"] and f["fingerprints"] == ["N2S-11"]


def test_n2s_11_json_header_shapes(tmp_path):
    lines = [
        json.dumps({"remote_addr": "192.0.2.60", "request": "POST /a HTTP/1.1", "status": 400,
                    "http_content_encoding": "br"}),
        json.dumps({"request": {"remote_ip": "192.0.2.61", "method": "POST", "uri": "/b",
                                "headers": {"Content-Encoding": ["br"]}}, "status": 400}),
        json.dumps({"requestHeaders": {"contentEncoding": "br"}, "method": "POST", "uri": "/c",
                    "remote_addr": "192.0.2.62"}),
    ]
    res = scan(tmp_path, lines)
    assert len([f for f in res["findings"] if f["rule"] == "REQUEST_CONTENT_ENCODING_BR"]) == 3


@pytest.mark.parametrize("fields,flag", [
    ({"transfer_encoding": "chunked", "content_length": "-"}, True),
    ({"transfer_encoding": "chunked"}, True),                          # Content-Length not logged
    ({"transfer_encoding": "chunked", "content_length": "22"}, False),   # both present: a different shape
    ({"content_length": "-"}, False),                                  # no chunked
])
def test_n2s_12(tmp_path, fields, flag):
    res = scan(tmp_path, [req("POST", "/api", content_encoding="br", **fields)])
    assert ("BR_CHUNKED_NO_LENGTH" in rules(res)) is flag


@pytest.mark.parametrize("ce,rule,severity", [
    ("br, br", "DUPLICATE_CONTENT_ENCODING", "warn"),
    ("gzip, gzip", "DUPLICATE_CONTENT_ENCODING", "info"),             # duplicates, but no br: cannot reach Brotli
])
def test_n2s_13_comma_joined(tmp_path, ce, rule, severity):
    f = one(scan(tmp_path, [req("POST", "/api", content_encoding=ce, content_length="22")]), rule)
    assert f["severity"] == severity and f["fingerprints"] == ["N2S-13"]


def test_n2s_13_array_and_lists(tmp_path):
    arr = json.dumps({"request": {"remote_ip": "192.0.2.70", "method": "POST", "uri": "/a",
                                  "headers": {"Content-Encoding": ["gzip", "gzip"]}}, "status": 400})
    assert one(scan(tmp_path, [arr]), "DUPLICATE_CONTENT_ENCODING")["severity"] == "info"
    res = scan(tmp_path, [req("POST", "/api", content_encoding="gzip, br", content_length="22")])
    assert "REQUEST_CONTENT_ENCODING_BR" in rules(res)                 # a legal list is N2S-11, not a duplicate
    assert "DUPLICATE_CONTENT_ENCODING" not in rules(res)


@pytest.mark.parametrize("method,path,ctype,ce,flag", [
    ("POST", "/", "application/octet-stream", "br", True),
    ("POST", "/", "Application/Octet-Stream; charset=x", "br", True),
    ("POST", "/api", "application/octet-stream", "br", False),
    ("GET", "/", "application/octet-stream", "br", False),
    ("POST", "/", "application/octet-stream", "gzip", False),
    ("POST", "/", "application/json", "br", False),
])
def test_n2s_14(tmp_path, method, path, ctype, ce, flag):
    res = scan(tmp_path, [req(method, path, content_type=ctype, content_encoding=ce, content_length="22")])
    assert ("BR_OCTET_STREAM_ROOT_POST" in rules(res)) is flag


@pytest.mark.parametrize("fields,flag", [
    ({"content_length": str((1 << 24) - 1)}, False),
    ({"content_length": str(1 << 24)}, True),
    ({"content_length": "23068672"}, True),
    ({"request_length": "20000000"}, True),                            # total-size field also counts
    ({"request_length": "5000"}, False),
])
def test_n2s_15_threshold(tmp_path, fields, flag):
    res = scan(tmp_path, [req("POST", "/api", content_encoding="br", **fields)])
    assert ("BR_LARGE_BODY" in rules(res)) is flag
    # a big upload without br is never flagged
    assert "BR_LARGE_BODY" not in rules(scan(tmp_path, [req("POST", "/api", **fields)]))


# ------------------------------------------------------------------ N2S-07 sweep ----

def sweep_lines(paths, size_field, size, **extra):
    return [req("POST", p, **{size_field: str(size)}, **extra) for p in paths]


FOUR = ("/", "/api", "/api/v1", "/graphql")


def test_n2s_07_documented_sizes_and_br_are_warn(tmp_path):
    lines = [req("POST", p, content_length=str(s)) for p, s in zip(FOUR[:3], (10, 14, 22))]
    f = one(scan(tmp_path, lines), "OSTORLAB_PROBE_SWEEP")
    assert f["severity"] == "warn" and f["fingerprints"] == ["N2S-07"]
    assert "192[.]0[.]2[.]50" in f["message"] and IP not in f["message"] and IP not in f["evidence"]     # defanged
    f2 = one(scan(tmp_path, sweep_lines(FOUR[:3], "content_length", 40, content_encoding="br")), "OSTORLAB_PROBE_SWEEP")
    assert f2["severity"] == "warn"


def test_n2s_07_shape_only_is_info(tmp_path):
    assert one(scan(tmp_path, sweep_lines(FOUR[:3], "content_length", 40)), "OSTORLAB_PROBE_SWEEP")["severity"] == "info"
    f = one(scan(tmp_path, sweep_lines(FOUR[:3], "request_length", 300)), "OSTORLAB_PROBE_SWEEP")
    assert f["severity"] == "info" and "request_length" in f["evidence"]


@pytest.mark.parametrize("lines_factory", [
    lambda: sweep_lines(FOUR[:2], "content_length", 10, content_encoding="br"),                # only 2 paths
    lambda: [req("GET", p, content_length="10") for p in FOUR[:3]],                             # not POST
    lambda: sweep_lines(FOUR[:3], "content_length", 4096, content_encoding="br"),               # bodies not tiny
    lambda: sweep_lines(FOUR[:3], "request_length", 5000),                                      # request too big
    lambda: [req("POST", p) for p in FOUR],                                                     # no size logged
    lambda: [req("POST", "/api", content_length="10", host=f"192.0.2.{i}") for i in range(20)],  # one path, many ips
    lambda: [req("POST", p, content_length="10", host=f"192.0.2.{i}") for i, p in enumerate(FOUR)],  # one path per ip
    lambda: sweep_lines(("/a", "/b", "/c"), "content_length", 10),                              # not candidate paths
])
def test_n2s_07_negative_shapes(tmp_path, lines_factory):
    assert "OSTORLAB_PROBE_SWEEP" not in rules(scan(tmp_path, lines_factory()))


# ------------------------------------------------------------------ N2S-22 lab routes ----

def lab(ip=IP, br=True, warm=3, health=True):
    out = []
    if br:
        out.append(req("POST", "/upload", host=ip, content_encoding="br", content_length="22"))
    out += [req("GET", "/warm", host=ip, status="200") for _ in range(warm)]
    if health:
        out.append(req("GET", "/health", host=ip, status="200"))
    return out


def test_n2s_22_needs_br_from_the_same_client(tmp_path):
    f = one(scan(tmp_path, lab()), "LAB_ROUTES_WITH_BR")
    assert f["severity"] == "warn" and "GET /warm x3" in f["message"] and "cadence" in f["message"]
    assert set(f["fingerprints"]) == {"N2S-22", "N2S-11"} and IP not in f["message"]
    assert "LAB_ROUTES_WITH_BR" not in rules(scan(tmp_path, lab(br=False)))                       # routes alone: no
    other = lab(br=False) + [req("POST", "/api", host="192.0.2.99", content_encoding="br", content_length="22")]
    assert "LAB_ROUTES_WITH_BR" not in rules(scan(tmp_path, other))                                # br from someone else
    few = scan(tmp_path, lab(warm=2))
    assert "cadence" not in one(few, "LAB_ROUTES_WITH_BR")["message"]
    hb = [req("POST", "/api", content_encoding="br", content_length="22"), req("GET", "/health", status="200")]
    assert "LAB_ROUTES_WITH_BR" in rules(scan(tmp_path, hb))                                       # /health only WITH br
    assert "LAB_ROUTES_WITH_BR" not in rules(scan(tmp_path, [req("GET", "/health", status="200")]))


# ------------------------------------------------------------------ N2S-16 / 17 text rules ----

@pytest.mark.parametrize("line,flag", [
    ("[ts] ERROR { errno: -17, code: 'ERR__ERROR_FORMAT_BLOCK_SWITCH' }", True),
    ("[ts] ERROR brotli decompress failed { errno: -17 }", True),
    ("[ts] ERROR zlib: unexpected { errno: -17 }", True),
    ('{"level":50,"err":{"code":"ERR__ERROR_FORMAT_BLOCK_SWITCH","errno":-17}}', True),
    ("[ts] ERROR EEXIST: file already exists, mkdir '/tmp/x' { errno: -17, code: 'EEXIST' }", False),
    ("[ts] ERROR brotli cache dir { errno: -17, code: 'EEXIST', syscall: 'mkdir' }", False),
    ("[ts] ERROR something { errno: -17 }", False),                       # errno -17 alone is EEXIST in libuv
    ("[ts] ERROR { errno: -170 }", False),
])
def test_n2s_16_text(tmp_path, line, flag):
    assert ("BROTLI_BLOCK_SWITCH_ERROR" in rules(scan(tmp_path, [line], name="app.log"))) is flag


@pytest.mark.parametrize("line,flag", [
    ("[ts] ERROR { errno: -9, code: 'ERR__ERROR_FORMAT_BLOCK_LENGTH_1' }", True),
    ("[ts] ERROR brotli decompress { errno: -9 }", True),
    ("[ts] ERROR EBADF: bad file descriptor, close { errno: -9, code: 'EBADF' }", False),
    ("[ts] ERROR zlib thing { errno: -9, code: 'EBADF' }", False),
    ("[ts] ERROR other { errno: -9 }", False),
    ("[ts] ERROR brotli { errno: -90 }", False),
])
def test_n2s_17_text(tmp_path, line, flag):
    res = scan(tmp_path, [line], name="app.log")
    assert ("BROTLI_BLOCK_LENGTH_1_ERROR" in rules(res)) is flag
    if flag:
        assert one(res, "BROTLI_BLOCK_LENGTH_1_ERROR")["severity"] == "info"


# --- the bare names of decoders built from Brotli 1.0.x (DERIVED, see fingerprints.LEGACY_NAMES_NOTE) ---

def test_legacy_bare_error_codes(tmp_path):
    sw = scan(tmp_path, ["[ts] ERROR Error: Decompression failed { errno: -17, code: 'ERR_BLOCK_SWITCH' }"], name="a.log")
    f = one(sw, "BROTLI_BLOCK_SWITCH_ERROR")
    assert f["severity"] == "warn" and "bare `ERR_BLOCK_SWITCH` form" in f["message"] and "1.0.x" in f["message"]
    assert f["basis"].startswith("VERBATIM+DERIVED") and "return #NAME;" in f["basis"]
    l1 = scan(tmp_path, ["[ts] ERROR Error: Decompression failed { errno: -9, code: 'ERR_BLOCK_LENGTH_1' }"], name="b.log")
    g = one(l1, "BROTLI_BLOCK_LENGTH_1_ERROR")
    assert g["severity"] == "info" and "bare `ERR_BLOCK_LENGTH_1` form" in g["message"]
    assert "return #NAME;" in g["basis"]
    # the prefixed form keeps its own wording and does not claim the bare form
    pre = scan(tmp_path, ["[ts] { errno: -17, code: 'ERR__ERROR_FORMAT_BLOCK_SWITCH' }"], name="c.log")
    assert "bare" not in one(pre, "BROTLI_BLOCK_SWITCH_ERROR")["message"]
    assert "return #NAME;" not in one(pre, "BROTLI_BLOCK_SWITCH_ERROR")["basis"]


@pytest.mark.parametrize("text", ["XERR_BLOCK_SWITCH", "ERR_BLOCK_SWITCH_EXTRA", "myERR_BLOCK_SWITCH_", "ERR-BLOCK-SWITCH"])
def test_legacy_code_is_a_whole_token(tmp_path, text):
    assert "BROTLI_BLOCK_SWITCH_ERROR" not in rules(scan(tmp_path, [f"[ts] {text}"], name="a.log"))


def test_legacy_code_in_json_and_wrapped_lines(tmp_path):
    lines = [json.dumps({"level": 50, "err": {"code": "ERR_BLOCK_SWITCH", "errno": -17}}),
             json.dumps({"log": "[ts] ERROR { errno: -17, code: 'ERR_BLOCK_SWITCH' }\n", "stream": "stderr"})]
    res = scan(tmp_path, lines)
    assert len([f for f in res["findings"] if f["rule"] == "BROTLI_BLOCK_SWITCH_ERROR"]) == 2


# ------------------------------------------------------------------ N2S-19 ----

@pytest.mark.parametrize("line,flag", [
    ("[ts] INFO uid=1000(node) gid=1000(node) groups=1000(node)", True),
    ("[ts] INFO uid=0(root) gid=0(root)", True),
    ("[ts] INFO uid=1000 gid=1000 groups=1000", True),                  # bare numeric, not auditd-style
    ("type=SYSCALL msg=audit(1.2:3): auid=1000 uid=0 gid=0 euid=0 suid=0", False),
    ("[ts] INFO uid=abc gid=def", False),
    ("[ts] INFO uid=1000", False),
])
def test_n2s_19(tmp_path, line, flag):
    res = scan(tmp_path, [line], name="app.log")
    assert ("RESPONSE_ID_MARKER" in rules(res)) is flag
    if flag:
        assert one(res, "RESPONSE_ID_MARKER")["severity"] == "critical"


def test_n2s_19_in_a_logged_response_body_field(tmp_path):
    res = scan(tmp_path, [req("POST", "/api", resp_body="uid=1000(node) gid=1000(node) groups=1000(node)")])
    f = one(res, "RESPONSE_ID_MARKER")
    assert f["severity"] == "critical" and "possible code execution" in f["message"]
    assert "verbatim" in f["basis"]


# ------------------------------------------------------------------ N2S-18 crash lines ----

CRASHES = [
    "Oct 24 10:05:00 host kernel: node[4242]: segfault at 7f3a ip 0000563c sp 00007ffd error 4 in node[563c+2a00000]",
    "Oct 24 10:05:00 host kernel: bun[99]: segfault at 0 ip 0000563c sp 00007ffd error 4 in bun[563c+2a00000]",
    "Oct 24 10:05:01 host systemd-coredump[4300]: Process 4242 (node) of user 1000 dumped core.",
    "Oct 24 10:05:02 host app.sh[1]: Segmentation fault (core dumped) node server.js",
    "Oct 24 10:05:03 host systemd[1]: app.service: Main process exited, code=dumped, status=11/SEGV",
    "Oct 24 10:05:03 host systemd[1]: app.service: Main process exited, code=killed, status=6/ABRT",
    "Oct 24 10:05:04 host dockerd[9]: container 3f2a exited with code 139",
    "NAME  READY  STATUS\nweb  0/1  Error  Exited (139)",
    '{"msg":"child process","exitCode":139}',
    "State: Terminated  Reason: Error  Exit Code: 139",
]


@pytest.mark.parametrize("line", CRASHES)
def test_each_crash_shape_is_counted(tmp_path, line):
    res = scan(tmp_path, [line], name="syslog.log")
    f = one(res, "NODE_PROCESS_CRASH")
    assert f["severity"] == "info" and f["fingerprints"] == ["N2S-18"] and "triage clue" in f["message"]


def test_crash_threshold_info_then_warn(tmp_path):
    assert one(scan(tmp_path, CRASHES[:2], name="s1.log"), "NODE_PROCESS_CRASH")["severity"] == "info"
    f = one(scan(tmp_path, CRASHES[:3], name="s2.log"), "NODE_PROCESS_CRASH")
    assert f["severity"] == "warn" and "3 Node/Bun crash record(s)" in f["message"]


@pytest.mark.parametrize("line", [
    "container exited with code 1390",
    "container exited with code 13",
    "GET /status=200 HTTP/1.1",
    "node[1]: started",
    "[ts] Process 12 (python) of user 1 dumped core.",
])
def test_not_a_crash(tmp_path, line):
    assert "NODE_PROCESS_CRASH" not in rules(scan(tmp_path, [line], name="s.log"))


# ------------------------------------------------------------------ seed bytes N2S-01..06 ----

SEED_IDS = ["N2S-01", "N2S-02", "N2S-03", "N2S-04", "N2S-06"]


@pytest.mark.parametrize("sid", SEED_IDS)
def test_seed_forms(tmp_path, sid):
    seed = fp.SEED_BYTES[sid]
    rule = f"SEED_BYTES_{sid.replace('-', '_')}"
    forms = {
        "nginx": req("POST", "/api", body=corpora.nginx_escape(seed)),
        "percent": req("GET", "/?b=" + corpora.percent_encode(seed)),
        "hex": req("POST", "/api", body=seed.hex()),
        "hex-upper": req("POST", "/api", body=seed.hex().upper()),
        "json-u00": json.dumps({"remote_addr": "192.0.2.80", "request": "POST /api HTTP/1.1", "status": 400,
                                "request_body": seed.decode("latin-1")}),
        "json-escaped-text": json.dumps({"remote_addr": "192.0.2.81", "request": "POST /api HTTP/1.1",
                                         "request_body": corpora.nginx_escape(seed)}),
    }
    for form, line in forms.items():
        res = scan(tmp_path, [line], name=f"{sid}_{form}.log")
        assert rule in rules(res), f"{form}: {sorted(set(rules(res)))}"
        f = one(res, rule)
        assert f["severity"] == "warn" and f["fingerprints"] == [sid]
        assert "not proof of execution" in f["message"]


def test_seed_n2s_05_full_and_truncated(tmp_path):
    full = req("POST", "/", body=corpora.nginx_escape(fp.N2S_05_BYTES))
    f = one(scan(tmp_path, [full]), "SEED_BYTES_N2S_05")
    assert "1024 x 0x41" in f["message"] and "truncated" not in f["message"]
    cut = req("POST", "/", body=corpora.nginx_escape(fp.N2S_05_HEAD + b"A" * 100))
    g = one(scan(tmp_path, [cut]), "SEED_BYTES_N2S_05")
    assert "log truncated the run" in g["message"]
    short = req("POST", "/", body=corpora.nginx_escape(fp.N2S_05_HEAD + b"A" * 40))
    assert "SEED_BYTES_N2S_05" not in rules(scan(tmp_path, [short]))
    hexform = req("POST", "/", body=(fp.N2S_05_HEAD + b"A" * 1024).hex())
    assert "SEED_BYTES_N2S_05" in rules(scan(tmp_path, [hexform]))


def test_seed_n2s_02_is_not_double_reported_as_n2s_01(tmp_path):
    res = scan(tmp_path, [req("POST", "/", body=corpora.nginx_escape(fp.SEED_BYTES["N2S-02"]))])
    assert "SEED_BYTES_N2S_02" in rules(res) and "SEED_BYTES_N2S_01" not in rules(res)
    hexres = scan(tmp_path, [req("POST", "/", body=fp.SEED_BYTES["N2S-02"].hex())], name="h.log")
    assert "SEED_BYTES_N2S_02" in rules(hexres) and "SEED_BYTES_N2S_01" not in rules(hexres)
    both = req("POST", "/", body=corpora.nginx_escape(fp.SEED_BYTES["N2S-02"] + b"zz" + fp.SEED_BYTES["N2S-01"]))
    assert {"SEED_BYTES_N2S_01", "SEED_BYTES_N2S_02"} <= set(rules(scan(tmp_path, [both], name="b.log")))
    only01 = scan(tmp_path, [req("POST", "/", body=corpora.nginx_escape(fp.SEED_BYTES["N2S-01"]))], name="o.log")
    assert rules(only01).count("SEED_BYTES_N2S_01") == 1 and "SEED_BYTES_N2S_02" not in rules(only01)


def test_seed_search_ignores_benign_escapes(tmp_path):
    lines = [
        req("POST", "/", body=corpora.nginx_escape(b"\x00\x01\x02 plain bytes \xfc\xff")),
        req("POST", "/", body="200010414141"),                          # only the first 6 bytes of the hex
        req("POST", "/", body=corpora.nginx_escape(fp.SEED_BYTES["N2S-01"][:-3])),   # truncated seed
        req("GET", "/?q=%00%10AAA"),
    ]
    assert scan(tmp_path, lines)["finding_count"] == 0


def test_decode_logged_bytes():
    assert logs.decode_logged_bytes(r"\x41\x42") == b"AB"
    assert logs.decode_logged_bytes("%41%7a") == b"Az"
    assert logs.decode_logged_bytes(r"Aü") == b"A\xfc"
    assert logs.decode_logged_bytes(r"a\nb\tc\\d") == b"a\nb\tc\\d"
    assert logs.decode_logged_bytes(r"\0x") == b"\x00x"
    assert logs.decode_logged_bytes(r"\012") == b"\\012"                 # octal-looking escapes are left alone
    assert logs.decode_logged_bytes("€") == b"?"                    # above U+00FF cannot be a seed byte
    assert logs.find_seeds("") == []


# ------------------------------------------------------------------ files, caps, compaction ----

def test_gzip_logs_with_and_without_extension(tmp_path):
    line = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, fp.UA_SECURITY_SCANNER_GENERIC)
    for name in ("access.log.gz", "rotated.log"):
        p = tmp_path / name
        with gzip.open(p, "wt") as fh:
            fh.write(line + "\n")
        assert "UA_SECURITY_SCANNER_GENERIC" in rules(logs.scan_log_file(str(p)))


def test_max_lines_cap(tmp_path):
    bad = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, fp.UA_SECURITY_SCANNER_GENERIC)
    ok_line = corpora.benign_access_combined()[0]
    lines = [ok_line] * 7 + [bad]
    capped = scan(tmp_path, lines, max_lines=5)
    assert capped["lines_scanned"] == 5 and capped["finding_count"] == 0
    full = scan(tmp_path, lines, name="full.log")
    assert full["lines_scanned"] == 8 and full["finding_count"] == 1


def test_blank_lines_are_skipped(tmp_path):
    res = scan(tmp_path, ["", "   ", corpora.benign_access_combined()[0], ""])
    assert res["parsed"] == 1 and res["unparsed"] == 0


def test_compaction_per_rule_display_and_repeat_count(tmp_path):
    bad = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, fp.UA_SECURITY_SCANNER_GENERIC)
    res = scan(tmp_path, [bad] * 20)
    assert res["finding_count"] == 20 and len(res["findings"]) == 8
    assert res["findings"][0]["repeat_count"] == 20
    assert [f["line"] for f in res["findings"]] == list(range(1, 9))


def test_compaction_cap_and_severity_order():
    fs = [{"rule": f"R{i}", "severity": "info", "line": i} for i in range(100)]
    fs.append({"rule": "CRIT", "severity": "critical", "line": 500})
    out = logs._compact_findings(fs)
    assert len(out) == 60 and out[0]["rule"] == "CRIT"


def test_no_raw_ips_in_the_report(tmp_path):
    res = scan(tmp_path, corpora.all_exploit_lines())
    blob = json.dumps(res["findings"])
    for ip in (corpora.IP_A, corpora.IP_B, corpora.IP_C, corpora.IP_D):
        assert ip not in blob, ip
    assert "[.]" in blob                                                 # defanged forms are present


def test_evidence_is_clean_and_bounded(tmp_path):
    line = req("POST", "/api", body=corpora.nginx_escape(fp.SEED_BYTES["N2S-01"]) + "A" * 5000)
    f = one(scan(tmp_path, [line]), "SEED_BYTES_N2S_01")
    assert len(f["evidence"]) <= 240 and all(c.isprintable() for c in f["evidence"])
