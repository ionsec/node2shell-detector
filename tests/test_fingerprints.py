"""Catalogue + fingerprint consistency tests - the zero-invented-fingerprints audit."""

import ast
import re
import sys
from pathlib import Path

import pytest

import node2shell_detector
from conftest import TOOL_ROOT, write_lines
from node2shell_detector import corpora, fingerprints as fp, logs

PKG = TOOL_ROOT / "node2shell_detector"

# Typed here straight from BRIEF s7 / s6 - an independent copy to compare the constants against.
BRIEF_SEEDS = {
    "N2S-01": "200010414141fcffff07002228f00b60f7f41f000000",
    "N2S-02": "200010414141fcffff07002228f00b60f7f41f00000000",
    "N2S-03": "200018414141fcffff07002228f00b60f7f41f000000",
    "N2S-04": "200010414141fcffff0f002228f00b60f7f41f000000",
    "N2S-06": "1b0100002479b16f50c0030500c00000000000000003",
}
BRIEF_SIZES = {"N2S-01": 22, "N2S-02": 23, "N2S-03": 22, "N2S-04": 22, "N2S-06": 22}


def rules_of(tmp_path, lines, name="a.log"):
    p = write_lines(tmp_path, name, lines)
    res = logs.scan_log_file(str(p))
    return res, [f["rule"] for f in res["findings"]]


# ------------------------------------------------------------------ catalogue ----

def test_catalogue_is_complete_and_well_formed():
    ids = {f"N2S-{i:02d}" for i in range(1, 26)}
    assert set(fp.CATALOGUE) == ids and set(fp.COVERAGE) == ids
    for sid, entry in fp.CATALOGUE.items():
        for key in ("type", "value", "where", "source", "conf", "fp", "note"):
            assert key in entry, (sid, key)
        assert entry["type"] and entry["value"] and entry["source"], sid
        assert set(entry["conf"].replace("+", "")) <= set("VPD"), sid


def test_confidence_codes_match_the_brief():
    expected = {"N2S-01": "V+P", "N2S-02": "P", "N2S-03": "P", "N2S-04": "P", "N2S-05": "P", "N2S-06": "P",
                "N2S-07": "P", "N2S-08": "P", "N2S-09": "P", "N2S-10": "P", "N2S-11": "D", "N2S-12": "P",
                "N2S-13": "V", "N2S-14": "P", "N2S-15": "P", "N2S-16": "V+D", "N2S-17": "P+D", "N2S-18": "V",
                "N2S-19": "P", "N2S-20": "P", "N2S-21": "D", "N2S-22": "P", "N2S-23": "D", "N2S-24": "D",
                "N2S-25": "V+P"}
    assert {k: v["conf"] for k, v in fp.CATALOGUE.items()} == expected


def test_seed_constants_match_the_brief():
    assert fp.SEED_HEX == BRIEF_SEEDS
    for sid, hx in BRIEF_SEEDS.items():
        assert fp.SEED_BYTES[sid] == bytes.fromhex(hx) and len(fp.SEED_BYTES[sid]) == BRIEF_SIZES[sid]
        assert fp.CATALOGUE[sid]["value"] == hx
    assert fp.SEED_BYTES["N2S-02"].startswith(fp.SEED_BYTES["N2S-01"])         # oob-extended = oob-base + 1 byte
    assert fp.N2S_05_BYTES == bytes.fromhex("1b00000000000000") + b"\x41" * 1024 and len(fp.N2S_05_BYTES) == 1032
    assert fp.REGRESSION_VECTOR_HEX == BRIEF_SEEDS["N2S-01"]


def test_ostorlab_constants_match_the_brief():
    assert fp.OSTORLAB_BENIGN_BROTLI_HEX == "8b04807b2270696e67223a317d03"
    assert len(bytes.fromhex(fp.OSTORLAB_BENIGN_BROTLI_HEX)) == 14
    assert fp.OSTORLAB_JSON_BODY == '{"ping":1}' and len(fp.OSTORLAB_JSON_BODY) == 10
    assert fp.OSTORLAB_CANDIDATE_PATHS == ("/", "/api", "/api/v1", "/graphql")
    assert fp.OSTORLAB_BODY_SIZES == (10, 14, 22)


def test_other_constants_match_the_brief():
    assert fp.UA_NODE2SHELL_CHECKER_PREFIX == "Node2ShellChecker/"
    assert fp.UA_SECURITY_SCANNER_GENERIC == "Mozilla/5.0 (compatible; security-scanner)"
    assert fp.UA_CVE_VERIFY_TOKEN == "cve-2026-111497-verify"
    assert fp.HOST_MARKER_PATHS == ("/tmp/pwn_marker.txt",)
    assert fp.ERR_BLOCK_SWITCH == "ERR__ERROR_FORMAT_BLOCK_SWITCH" and fp.ERRNO_BLOCK_SWITCH == -17
    assert fp.ERR_BLOCK_LENGTH_1 == "ERR__ERROR_FORMAT_BLOCK_LENGTH_1" and fp.ERRNO_BLOCK_LENGTH_1 == -9
    assert fp.RE_UID_GID.pattern == r"uid=\d+(?:\([^)\r\n]+\))?\s+gid=\d+(?:\([^)\r\n]+\))?"
    assert set(fp.LAB_ROUTES) == {("POST", "/upload"), ("GET", "/health"), ("POST", "/stage"), ("POST", "/tail"),
                                  ("POST", "/close"), ("GET", "/warm")}
    assert node2shell_detector.CVE_ID == "CVE-2026-111497" and node2shell_detector.__version__ == "1.0.0"


def test_provenance_labels_and_basis_builder():
    assert fp.provenance("V") == fp.provenance("P") == fp.provenance("V+P") == "VERBATIM"
    assert fp.provenance("D") == "DERIVED"
    assert fp.provenance("V+D") == fp.provenance("P+D") == "VERBATIM+DERIVED"
    b = fp.basis("N2S-23", note="because")
    assert b.startswith("DERIVED: N2S-23 (binary, conf D, derived from the fix commits)") and b.endswith("- because")
    assert fp.basis("N2S-08").startswith("VERBATIM: N2S-08 (user-agent, conf P, completetech-security/node2shell-check)")
    assert fp.basis("N2S-16").startswith("VERBATIM+DERIVED: N2S-16")
    assert fp.basis("N2S-08", "N2S-23").startswith("VERBATIM+DERIVED: N2S-08 ")      # mixed provenance
    assert fp.brief_basis("s3", "x") == "VERBATIM: BRIEF s3 - x"
    assert fp.brief_basis("s3", "x", derived=True) == "DERIVED: BRIEF s3 - x"


# ------------------------------------------------------------------ the back-audit ----

def test_every_catalogue_user_agent_is_caught(tmp_path):
    """Forward audit: each UA family in the catalogue fires its rule."""
    for sid, ua in fp.UA_EXAMPLES:
        line = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "GET", "/", 200, 1, ua)
        res, rules = rules_of(tmp_path, [line], name=f"{sid}.log")
        assert corpora.EXPECTED_RULE[sid] in rules, (sid, ua, rules)
        assert all(sid in f["fingerprints"] for f in res["findings"] if f["rule"] == corpora.EXPECTED_RULE[sid])


def test_every_catalogue_byte_string_is_caught(tmp_path):
    """Forward audit: each seed (N2S-01..06) is found as escaped bytes, percent-encoded bytes and plain hex."""
    seeds = dict(fp.SEED_BYTES)
    seeds["N2S-05"] = fp.N2S_05_BYTES
    for sid, data in seeds.items():
        rule = corpora.EXPECTED_RULE[sid]
        for form, body in (("nginx", corpora.nginx_escape(data)), ("percent", corpora.percent_encode(data)),
                           ("hex", data.hex())):
            line = corpora.ltsv({"host": "192.0.2.9", "time": "t", "req": "POST /x HTTP/1.1", "status": "400",
                                 "size": "0", "ua": "ua", "body": body})
            res, rules = rules_of(tmp_path, [line], name=f"{sid}_{form}.log")
            assert rule in rules, (sid, form, sorted(set(rules)))


def test_log_visible_ids_equal_the_scenarios():
    logged = {sid for sid, text in fp.COVERAGE.items() if text.startswith("logs:")}
    assert logged == set(corpora.EXPECTED_RULE)
    assert set(corpora.exploit_lines_by_id()) == set(corpora.EXPECTED_RULE)
    # the rest are covered elsewhere, or deliberately not covered
    assert {sid for sid in fp.CATALOGUE if sid not in logged} == {"N2S-20", "N2S-21", "N2S-23", "N2S-24", "N2S-25"}
    assert fp.COVERAGE["N2S-21"].startswith("not covered by the host tool")
    assert fp.COVERAGE["N2S-20"].startswith("posture:") and fp.COVERAGE["N2S-25"].startswith("--self-test:")


def test_benign_user_agents_and_corpora_are_clean(tmp_path):
    for label, ua in corpora.BENIGN_UAS.items():
        line = corpora.combined("192.0.2.9", "24/Oct/2026:11:00:00", "POST", "/upload.php", 200, 10, ua)
        res, _ = rules_of(tmp_path, [line], name=f"{label}.log")
        assert res["finding_count"] == 0, label
    res, rules = rules_of(tmp_path, corpora.all_benign_lines(), name="benign.log")
    assert res["finding_count"] == 0, rules


def test_exploit_corpus_lines_are_all_scanned(tmp_path):
    lines = corpora.all_exploit_lines()
    assert len(lines) > 30
    res, rules = rules_of(tmp_path, lines, name="exploit.log")
    assert res["parsed"] >= 20 and set(corpora.EXPECTED_RULE.values()) <= set(rules)


def test_findings_cite_only_catalogue_ids_with_provenance(tmp_path):
    res, _ = rules_of(tmp_path, corpora.all_exploit_lines(), name="exploit.log")
    for f in res["findings"]:
        assert f["fingerprints"], f["rule"]
        assert set(f["fingerprints"]) <= set(fp.CATALOGUE)
        assert f["basis"].split(":")[0] in ("VERBATIM", "DERIVED", "VERBATIM+DERIVED")
        assert f["fingerprints"][0] in f["basis"]


def test_coverage_texts_name_real_rules():
    """Every UPPER_SNAKE rule name in COVERAGE is emitted somewhere in the package (not just documented)."""
    sources = "\n".join(p.read_text() for p in PKG.glob("*.py") if p.name not in ("fingerprints.py",))
    tokens = set()
    for text in fp.COVERAGE.values():
        tokens |= set(re.findall(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b", text))
    assert tokens
    for token in sorted(tokens):
        if token.startswith("SEED_BYTES"):
            assert "SEED_BYTES_" in sources
        else:
            assert f'"{token}"' in sources, token


# ------------------------------------------------------------------ code-level guarantees ----

NETWORK_MODULES = {"socket", "ssl", "http", "urllib", "urllib2", "urllib3", "ftplib", "smtplib", "telnetlib", "xmlrpc",
                   "requests", "aiohttp", "httpx", "websocket", "websockets", "asyncio", "socketserver", "poplib",
                   "imaplib", "nntplib", "selectors"}


def test_package_imports_no_network_module():
    for path in sorted(PKG.glob("*.py")):
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module.split(".")[0]]
            assert not (set(names) & NETWORK_MODULES), (path.name, names)


def test_trigger_bytes_live_only_in_fingerprints_py():
    """The only trigger bytes in the code base are the catalogue constants - everything else derives from them."""
    needles = list(BRIEF_SEEDS.values()) + ["8b04807b2270696e67223a317d03", "1b00000000000000"]
    for path in sorted(PKG.glob("*.py")):
        if path.name == "fingerprints.py":
            continue
        text = path.read_text().lower()
        for hx in needles:
            assert hx not in text, (path.name, hx)


def test_package_is_stdlib_only():
    stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
    for path in sorted(PKG.glob("*.py")):
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            top = None
            if isinstance(node, ast.Import):
                tops = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                tops = [node.module.split(".")[0]]
            else:
                continue
            for top in tops:
                if stdlib is not None:
                    assert top in stdlib or top == "node2shell_detector", (path.name, top)
