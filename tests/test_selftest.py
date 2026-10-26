"""SELF-TEST (N2S-25): classification, throwaway-child mechanics. Only ever run against STUB scripts."""

import os
import re
import time
from pathlib import Path

import pytest

from conftest import make_stub_bun, make_stub_deno, make_stub_node, write_exec
from node2shell_detector import fingerprints as fp, selftest

SWITCH_OUT = '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_SWITCH","errno":-17,"name":"Error"}\n'


@pytest.mark.parametrize("rc,out,timed_out,status,severity", [
    (0, SWITCH_OUT, False, "fixed", "ok"),
    (0, '{"ok":false,"errno":-17}\n', False, "fixed", "ok"),
    (0, '{"ok":false,"code":"ERR_BLOCK_SWITCH","errno":-17}\n', False, "fixed", "ok"),         # 1.0.x bare code, -17
    (0, '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_LENGTH_1","errno":-9}\n', False, "vulnerable", "critical"),
    (0, '{"ok":false,"errno":-9}\n', False, "vulnerable", "critical"),
    (0, '{"ok":false,"code":"ERR_BLOCK_LENGTH_1","errno":-9}\n', False, "vulnerable", "critical"),
    (0, '{"ok":false,"code":"ERR__ERROR_FORMAT_PADDING_1","errno":-14}\n', False, "vulnerable", "critical"),
    (-11, "", False, "crash", "critical"),
    (-6, "", False, "crash", "critical"),
    (139, "", False, "crash", "critical"),
    (134, "", False, "crash", "critical"),
    (0, '{"ok":true}\n', False, "inconclusive", "warn"),
    (0, '{"ok":false,"name":"TypeError"}\n', False, "inconclusive", "warn"),
    (0, "hello\n", False, "inconclusive", "warn"),
    (0, "", False, "inconclusive", "warn"),
    (0, "", True, "inconclusive", "warn"),
    (1, "", False, "inconclusive", "warn"),
])
def test_classify(rc, out, timed_out, status, severity):
    res = selftest.classify(rc, out, timed_out)
    assert (res["status"], res["severity"]) == (status, severity), res
    assert res["detail"]


def test_classify_details():
    assert selftest.classify(-11, "", False)["signal"] == "SIGSEGV"
    assert "CRASHED" in selftest.classify(-11, "", False)["detail"]
    assert "timed out" in selftest.classify(None, "", True)["detail"]
    f = selftest.classify(0, SWITCH_OUT, False)
    assert f["code"] == "ERR__ERROR_FORMAT_BLOCK_SWITCH" and f["errno"] == -17
    v = selftest.classify(0, '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_LENGTH_1","errno":-9}', False)
    assert "BLOCK_LENGTH_1" in v["detail"] and v["errno"] == -9
    assert "stderr: boom" in selftest.classify(1, "", False, "boom")["detail"]
    # last JSON line wins when the runtime prints warnings first
    assert selftest.classify(0, "(node:1) Warning: x\n" + SWITCH_OUT, False)["status"] == "fixed"


@pytest.mark.parametrize("behaviour,status,severity", [
    ("fixed", "fixed", "ok"),
    ("vulnerable", "vulnerable", "critical"),
    ("crash", "crash", "critical"),
    ("exit139", "crash", "critical"),
    ("noerror", "inconclusive", "warn"),
    ("typeerror", "inconclusive", "warn"),
    ("garbage", "inconclusive", "warn"),
])
def test_run_one_against_stub_runtimes(tmp_path, behaviour, status, severity):
    node = make_stub_node(tmp_path, "24.22.0", behaviour=behaviour)
    res = selftest.run_one(node, "node")
    assert (res["status"], res["severity"]) == (status, severity), res
    assert res["bin"] == node and res["kind"] == "node"
    bun = make_stub_bun(tmp_path, "1.4.3", behaviour=behaviour)
    assert selftest.run_one(bun, "bun")["status"] == status


def test_timeout_kills_the_child_and_reports_unknown(tmp_path):
    node = make_stub_node(tmp_path, "24.22.0", behaviour="timeout")      # the stub sleeps 30 s
    t0 = time.time()
    res = selftest.run_one(node, "node", timeout=1)
    assert time.time() - t0 < 15
    assert res["status"] == "inconclusive" and res["severity"] == "warn" and "timed out" in res["detail"]


def test_unrunnable_binary_is_inconclusive(tmp_path):
    notexec = tmp_path / "node"
    notexec.write_text("not executable")
    notexec.chmod(0o644)
    res = selftest.run_one(str(notexec), "node")
    assert res["status"] == "inconclusive" and "could not execute" in res["detail"]


def test_relative_binary_path_still_runs(tmp_path, monkeypatch):
    """The child runs in its own temp dir: a relative --node-bin must be resolved before the spawn."""
    stub = Path(make_stub_node(tmp_path, "24.22.1", behaviour="fixed", name="relnode"))
    monkeypatch.chdir(stub.parent)
    assert selftest.run_one("./relnode", "node")["status"] == "fixed"
    monkeypatch.chdir(tmp_path)
    assert selftest.run_one(f"{stub.parent.name}/relnode", "node")["status"] == "fixed"


def test_run_selftest_findings_and_notes(tmp_path):
    fixed = make_stub_node(tmp_path, "24.22.1", behaviour="fixed")
    vuln = make_stub_bun(tmp_path, "1.4.3", behaviour="vulnerable")
    deno = make_stub_deno(tmp_path)
    res = selftest.run_selftest([{"kind": "node", "path": fixed}, {"kind": "bun", "bin": vuln},
                                 {"kind": "deno", "path": deno}])
    by_rule = {f["rule"]: f for f in res["findings"]}
    assert set(by_rule) == {"SELFTEST_FIXED", "SELFTEST_VULNERABLE"}
    assert by_rule["SELFTEST_FIXED"]["severity"] == "ok" and by_rule["SELFTEST_VULNERABLE"]["severity"] == "critical"
    for f in res["findings"]:
        assert f["check"] == "selftest" and f["fingerprints"] == ["N2S-25", "N2S-01"]
        assert f["basis"].startswith("VERBATIM") and "N2S-25" in f["basis"]
        assert "authoritative" in f["message"] and "N2S-25" in f["message"]
    assert [r["status"] for r in res["binaries"]] == ["fixed", "vulnerable"]
    assert any("Deno" in n and "not tested" in n for n in res["notes"])
    assert any("throwaway child" in n for n in res["notes"])


def test_run_selftest_with_nothing_to_test():
    res = selftest.run_selftest([])
    assert res["binaries"] == [] and res["findings"] == [] and any("no node / bun binary" in n for n in res["notes"])
    assert selftest.run_selftest([{"kind": "deno", "path": "/x"}])["binaries"] == []


def test_selftest_script_is_data_only_and_network_free():
    js = selftest.SELFTEST_JS
    assert fp.REGRESSION_VECTOR_HEX == fp.SEED_HEX["N2S-01"] and fp.REGRESSION_VECTOR_HEX in js
    assert "require('zlib')" in js and "brotliDecompressSync" in js
    assert set(re.findall(r"require\('([^']+)'\)", js)) == {"zlib"}             # nothing else is loaded
    for banned in ("net", "http", "https", "dgram", "dns", "tls", "child_process", "fs", "eval", "fetch", "WebSocket"):
        assert not re.search(rf"\b{banned}\b", js), banned
    assert len(bytes.fromhex(fp.REGRESSION_VECTOR_HEX)) == 22


def test_child_environment_script_and_workdir(tmp_path, monkeypatch):
    cap = tmp_path / "capture"
    cap.mkdir()
    monkeypatch.setenv("N2S_CAPTURE_DIR", str(cap))
    monkeypatch.setenv("NODE_OPTIONS", "--require /tmp/evil.js")
    monkeypatch.setenv("BUN_OPTIONS", "--preload /tmp/evil.js")
    stub = write_exec(tmp_path / "capnode", (
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  *.js) cp "$1" "$N2S_CAPTURE_DIR/script.js"; env > "$N2S_CAPTURE_DIR/env.txt"; '
        'pwd > "$N2S_CAPTURE_DIR/cwd.txt"; echo \'' + SWITCH_OUT.strip() + "';;\n"
        "esac\n"))
    res = selftest.run_one(stub, "node")
    assert res["status"] == "fixed"
    assert fp.REGRESSION_VECTOR_HEX in (cap / "script.js").read_text()
    env = (cap / "env.txt").read_text()
    assert "NODE_OPTIONS" not in env and "BUN_OPTIONS" not in env              # option preloaders are stripped
    assert "n2s-selftest-" in (cap / "cwd.txt").read_text()                    # runs in its own temp dir


def test_temp_dir_is_removed_afterwards(tmp_path, monkeypatch):
    seen = []
    real = selftest.tempfile.TemporaryDirectory

    class Spy(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            seen.append(self.name)

    monkeypatch.setattr(selftest.tempfile, "TemporaryDirectory", Spy)
    selftest.run_one(make_stub_node(tmp_path, "24.22.1", behaviour="fixed"), "node")
    assert seen and not any(Path(p).exists() for p in seen)
