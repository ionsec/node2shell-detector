"""The shipped examples/ directory works as documented and cannot drift from the code."""

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import TOOL_ROOT, posture_of
from node2shell_detector import binscan, corpora, deps, logs, runtimes, selftest

EX = TOOL_ROOT / "examples"


def rules_of(res):
    return [f["rule"] for f in res["findings"]]


# ------------------------------------------------------------------ logs ----

def test_example_logs_match_the_corpora_builders():
    expected = {
        "access_benign.log": corpora.benign_access_combined() + corpora.benign_access_ltsv()
        + corpora.benign_access_json(),
        "access_exploit.log": corpora.exploit_access_lines(),
        "app_benign.log": corpora.benign_app_log(),
        "app_exploit.log": corpora.exploit_app_lines(),
    }
    for name, lines in expected.items():
        assert (EX / "logs" / name).read_text() == "\n".join(lines) + "\n", name


def test_example_logs_behave_as_advertised():
    for name in ("access_benign.log", "app_benign.log"):
        assert logs.scan_log_file(str(EX / "logs" / name))["finding_count"] == 0, name
    acc = logs.scan_log_file(str(EX / "logs" / "access_exploit.log"))
    app = logs.scan_log_file(str(EX / "logs" / "app_exploit.log"))
    got = set(rules_of(acc)) | set(rules_of(app))
    assert set(corpora.EXPECTED_RULE.values()) <= got


# ------------------------------------------------------------------ stub runtimes ----

def test_stub_runtimes_are_labelled_executable_and_harmless():
    for name in ("fixture_node.sh", "fixture_node_fixed.sh", "fixture_bun.sh"):
        p = EX / name
        text = p.read_text()
        assert text.startswith("#!/bin/sh") and "TEST FIXTURE" in text and "Do not deploy" in text
        assert p.stat().st_mode & stat.S_IXUSR
        assert not any(w in text for w in ("curl", "wget", "nc ", "http://", "https://"))
    out = subprocess.run([str(EX / "fixture_node.sh"), "--version"], capture_output=True, text=True).stdout
    assert out.strip() == "v24.22.0"


def test_stub_posture_verdicts():
    vuln = posture_of(node=[str(EX / "fixture_node.sh")])
    assert vuln["runtimes"][0]["verdict"]["severity"] == "critical"
    fixed = posture_of(node=[str(EX / "fixture_node_fixed.sh")])
    assert fixed["runtimes"][0]["verdict"]["severity"] == "ok"
    bun = posture_of(bun=[str(EX / "fixture_bun.sh")])
    assert bun["runtimes"][0]["verdict"]["severity"] == "critical" and bun["runtimes"][0]["version"] == "1.4.3"


def test_self_test_runs_only_against_the_stubs():
    assert selftest.run_one(str(EX / "fixture_node.sh"), "node")["status"] == "vulnerable"
    assert selftest.run_one(str(EX / "fixture_node_fixed.sh"), "node")["status"] == "fixed"
    assert selftest.run_one(str(EX / "fixture_bun.sh"), "bun")["status"] == "vulnerable"


# ------------------------------------------------------------------ binaries / sources ----

def test_fixture_binaries():
    want = {"decoder_fixed.bin": ("fixed", ["1.1+"]), "decoder_vulnerable.bin": ("vulnerable", ["1.1+"]),
            "decoder_legacy_vulnerable.bin": ("vulnerable", ["1.0.x"]), "decoder_legacy_fixed.bin": ("fixed", ["1.0.x"]),
            "no_table.bin": ("inconclusive", [])}
    for name, (status, tables) in want.items():
        rec = binscan.scan_binary(str(EX / "fixture_bins" / name))
        assert (rec["status"], rec["tables"]) == (status, tables), name
        assert rec["exec_kind"] == "elf"


def test_fixture_decode_c_stand_ins():
    vuln = EX / "fixture_vendor" / "c" / "dec" / "decode.c"
    fixed = EX / "fixture_vendor_fixed" / "c" / "dec" / "decode.c"
    assert "SYNTHETIC" in vuln.read_text() and "NOT the upstream file" in fixed.read_text()
    assert binscan.check_decode_c(str(vuln))["status"] == "vulnerable"
    assert binscan.check_decode_c(str(fixed))["status"] == "fixed"


def test_fixture_binaries_via_the_cli():
    r = subprocess.run([sys.executable, "-m", "node2shell_detector", "--no-discover", "--check", "binaries",
                        "--scan-dir", str(EX / "fixture_bins"), "--scan-dir", str(EX / "fixture_vendor"),
                        "--scan-dir", str(EX / "fixture_vendor_fixed"), "--json"],
                       capture_output=True, text=True, cwd=TOOL_ROOT, timeout=120)
    assert r.returncode == 1
    doc = json.loads(r.stdout)
    st = doc["binaries"]["stats"]
    assert (st["fixed"], st["vulnerable"], st["inconclusive"], st["sources"]) == (2, 2, 1, 2)


# ------------------------------------------------------------------ project / site-packages ----

def test_fixture_project_findings():
    res = deps.scan_project(str(EX / "fixture_project"), ["/usr/bin/node"])
    by = {}
    for f in res["findings"]:
        by.setdefault(f["rule"], []).append(f)
    assert {f["evidence"].split(" ")[0] for f in by["DEP_SERVER_BODY_DECODER"]} == {"express@5.1.0", "body-parser@2.2.0"}
    assert all(f["severity"] == "critical" for f in by["DEP_SERVER_BODY_DECODER"])        # escalated
    assert by["DEP_CLIENT_DECODER"][0]["severity"] == "warn" and by["DEP_CONDITIONAL_DECODER"][0]["severity"] == "info"
    assert by["DEP_PY_BROTLI"][0]["severity"] == "critical"                                # aiohttp is pinned beside it
    assert by["DEP_GO_BROTLI"][0]["severity"] == "warn"
    assert sorted(f["severity"] for f in by["DOCKER_BASE_IMAGE"]) == ["critical", "critical", "info"]


def test_fixture_site_packages():
    res = runtimes.run_posture(discovered=[], python_sites=[str(EX / "fixture_site-packages")],
                               include_running_python=False, host_marker_paths=[])
    f = [x for x in res["findings"] if x["rule"] == "PY_BROTLI_MODULE"][0]
    assert f["severity"] == "critical" and "aiohttp 3.9.5" in f["message"] and "requests 2.32.0" in f["message"]


# ------------------------------------------------------------------ generator drift ----

def test_regenerating_the_examples_reproduces_the_committed_files(tmp_path):
    work = tmp_path / "copy"
    (work / "examples").mkdir(parents=True)
    shutil.copy(EX / "make_examples.py", work / "examples" / "make_examples.py")
    env = dict(os.environ, PYTHONPATH=str(TOOL_ROOT))
    r = subprocess.run([sys.executable, str(work / "examples" / "make_examples.py")], capture_output=True, text=True,
                       env=env, cwd=work, timeout=120)
    assert r.returncode == 0, r.stderr

    def tree(root: Path):
        out = {}
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.name != "make_examples.py" and "__pycache__" not in p.parts:
                out[str(p.relative_to(root))] = p.read_bytes()
        return out

    committed, regenerated = tree(EX), tree(work / "examples")
    assert set(committed) == set(regenerated)
    for rel in committed:
        assert committed[rel] == regenerated[rel], rel
