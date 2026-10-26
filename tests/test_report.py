"""Reporting helpers: severity model, defanging, exit codes, text + JSON renderers."""

import json

from node2shell_detector import __version__, report as rp


def test_defang_and_clean_evidence():
    assert rp.defang("from 192.0.2.10 and 10.0.0.1") == "from 192[.]0[.]2[.]10 and 10[.]0[.]0[.]1"
    assert rp.defang("version 1.2.3") == "version 1.2.3"                      # not a dotted quad
    # 4-part versions look like IPs: defanged by default, kept when asked (version-bearing evidence)
    assert rp.clean_evidence("brotlicffi 1.0.9.0") == "brotlicffi 1[.]0[.]9[.]0"
    assert rp.clean_evidence("brotlicffi 1.0.9.0", defang_ips=False) == "brotlicffi 1.0.9.0"
    assert rp.clean_evidence("a\r\nb\x00c\x7f") == "a\\r b\\x00c\\x7f"
    assert len(rp.clean_evidence("x" * 1000)) == 240
    assert len(rp.clean_evidence("x" * 1000, limit=10)) == 10


def test_finding_shape_and_defaults():
    f = rp.finding("R", "warn", "msg", check="logs", file="f.log", line=3, evidence="e 1.2.3.4", basis="VERBATIM: x")
    assert set(f) == {"rule", "severity", "check", "message", "file", "line", "evidence", "basis",
                      "fingerprints", "related"}
    assert f["evidence"] == "e 1[.]2[.]3[.]4" and f["fingerprints"] == [] and f["related"] == []
    g = rp.finding("R", "ok", "m", fingerprints=["N2S-23"], related=["x"], evidence="")
    assert g["evidence"] is None and g["fingerprints"] == ["N2S-23"] and g["related"] == ["x"]


def test_severity_max():
    assert rp.severity_max("ok", "info") == "info"
    assert rp.severity_max("warn", "critical", "info") == "critical"
    assert rp.severity_max() == "ok"
    assert rp.SEV_ORDER["crit"] == rp.SEV_ORDER["critical"]


def mk(findings_by_section, errors=()):
    rep = rp.new_report(["x"])
    for sec, fs in findings_by_section.items():
        rep[sec] = {"findings": fs}
    rep["errors"] = list(errors)
    return rp.finalize(rep)


def test_exit_codes_and_counts():
    ok = rp.finding("A", "ok", "m")
    info = rp.finding("B", "info", "m")
    warn = rp.finding("C", "warn", "m")
    crit = rp.finding("D", "critical", "m")
    clean = mk({"posture": [ok, info], "logs": []})
    assert clean["summary"]["exit_code"] == rp.TOOL_EXIT_CLEAN == 0
    assert clean["summary"]["counts"] == {"critical": 0, "warn": 0, "info": 1, "ok": 1}
    assert mk({"deps": [warn]})["summary"]["exit_code"] == rp.TOOL_EXIT_FINDINGS == 1
    assert mk({"binaries": [crit], "selftest": [ok]})["summary"]["exit_code"] == 1
    assert mk({"posture": [ok]}, errors=["bad flag"])["summary"]["exit_code"] == rp.TOOL_EXIT_ERROR == 2
    assert mk({"posture": [crit]}, errors=["bad"])["summary"]["exit_code"] == 2     # errors win
    assert [f["rule"] for f in rp.all_findings(mk({"posture": [ok], "logs": [warn]}))] == ["A", "C"]


def test_new_report_has_every_section():
    rep = rp.new_report(["--json"])
    assert rep["tool"] == "node2shell-detector" and rep["version"] == __version__ == "1.0.0"
    assert rep["cve"] == "CVE-2026-111497" and rep["argv"] == ["--json"] and rep["errors"] == []
    for sec in ("posture", "binaries", "deps", "logs", "selftest"):
        assert rep[sec] is None


def test_render_text_sections_and_finding_lines():
    f1 = rp.finding("NODE_RUNTIME_VERSION", "critical", "boom", check="posture", file="/usr/bin/node",
                    evidence="v24.22.0", basis="VERBATIM: BRIEF s3", fingerprints=["N2S-23"], related=["a", "b"])
    f1["repeat_count"] = 5
    f2 = rp.finding("LOG_RULE", "warn", "attempt", check="logs", file="x.log", line=7)
    rep = rp.new_report(["x"])
    rep["posture"] = {"runtimes": [{"kind": "node", "bin": "/usr/bin/node", "version": "v24.22.0", "shared": "no",
                                    "verdict": {"severity": "critical", "status": "vulnerable_unpatched",
                                                "source": "version-table"}}],
                      "python": {"sites": [{"path": "/sp", "packages": {"brotli": "1.1.0"}}]},
                      "markers": [{"path": "/tmp/pwn_marker.txt", "present": False}], "notes": ["n"],
                      "findings": [f1]}
    rep["binaries"] = {"targets": [{"kind": "lib", "path": "/l.so", "status": "fixed", "severity": "ok"}],
                       "stats": {"scanned": 1, "fixed": 1, "vulnerable": 0, "inconclusive": 0, "skipped_large": 0,
                                 "unreadable": 0, "sources": 0}, "notes": [], "findings": []}
    rep["deps"] = {"projects": [{"path": "/p", "files": ["a"], "packages_scanned": 3, "truncated": False}],
                   "runtime_escalation": True, "notes": [], "findings": []}
    rep["logs"] = {"files": [{"path": "x.log", "format": "ltsv", "lines_scanned": 9, "parsed": 9, "finding_count": 1}],
                   "body_visibility_note": "note", "findings": [f2]}
    rep["selftest"] = {"binaries": [{"kind": "node", "bin": "/usr/bin/node", "status": "fixed", "severity": "ok",
                                     "code": "ERR__ERROR_FORMAT_BLOCK_SWITCH", "errno": -17, "returncode": 0}],
                       "notes": [], "findings": []}
    text = rp.render_text(rp.finalize(rep))
    for needle in ("== HOST POSTURE ==", "== BINARY FINGERPRINTS", "== DEPENDENCY EXPOSURE", "== LOG SCAN ==",
                   "== SELF-TEST (opt-in, N2S-25", "== SUMMARY ==", "exit_code=1",
                   "process.versions.brotli is never used for a verdict",
                   "[critical] NODE_RUNTIME_VERSION", "ids: N2S-23", "basis: VERBATIM: BRIEF s3",
                   "related: a; b", "[x5 in file]", "(x.log:7)", "evidence: v24.22.0",
                   "vulnerable runtime found by posture"):
        assert needle in text, needle
    # findings are listed once, severity-first, after the summary
    assert text.index("[critical] NODE_RUNTIME_VERSION") > text.index("== SUMMARY ==")
    assert text.index("[critical]") < text.index("[warning]")
    assert text.count("NODE_RUNTIME_VERSION") == 1


def test_render_text_without_findings_and_with_errors():
    rep = rp.new_report(["x"])
    rep["errors"] = ["--log nope: file not found"]
    text = rp.render_text(rp.finalize(rep))
    assert "== ERRORS (1) ==" in text and "[error]   --log nope: file not found" in text
    assert "exit_code=2" in text and "errors present" in text


def test_render_json_roundtrip():
    rep = mk({"posture": [rp.finding("A", "warn", "m")]})
    doc = json.loads(rp.render_json(rep))
    assert doc["summary"]["counts"]["warn"] == 1 and doc["posture"]["findings"][0]["rule"] == "A"
