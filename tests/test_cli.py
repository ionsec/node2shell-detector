"""CLI: exit codes, sections, hermetic stub runs (--no-discover), opt-in self-test, end-to-end escalation."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import (M_LENGTH1, M_SWITCH, TOOL_ROOT, make_elf, make_stub_bun, make_stub_node, write_exec,
                      write_lines)
from node2shell_detector import cli, corpora, selftest

SWITCH_OUT = '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_SWITCH","errno":-17,"name":"Error"}'


def run_cli(args, env=None, timeout=240):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "node2shell_detector", *args], capture_output=True, text=True,
                          cwd=TOOL_ROOT, timeout=timeout, env=e)


def run_main(capsys, args):
    code = cli.main(list(args))
    return code, capsys.readouterr().out


def run_json(capsys, args):
    code, out = run_main(capsys, list(args) + ["--json"])
    return code, json.loads(out)


def rule_list(doc, section):
    return [f["rule"] for f in (doc.get(section) or {}).get("findings", [])]


def npm_project(root, pkgs):
    packages = {"": {"name": "app"}}
    for n, v in pkgs.items():
        packages[f"node_modules/{n}"] = {"version": v}
    Path(root).mkdir(parents=True, exist_ok=True)
    (Path(root) / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    return str(root)


def make_site(root, pkgs):
    site = Path(root)
    site.mkdir(parents=True, exist_ok=True)
    for name, ver in pkgs.items():
        d = site / f"{name}-{ver}.dist-info"
        d.mkdir()
        (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\n\n")
    return str(site)


# ------------------------------------------------------------------ subprocess: entry point + exit codes ----

def test_version_and_help():
    r = run_cli(["--version"])
    assert r.returncode == 0 and r.stdout.strip() == "node2shell-detector 1.0.0"
    h = run_cli(["--help"])
    assert h.returncode == 0
    for flag in ("--project", "--log", "--node-bin", "--bun-bin", "--python-site", "--scan-dir", "--check",
                 "--self-test", "--no-discover", "--json", "--quiet", "--max-lines"):
        assert flag in h.stdout, flag
    assert "exit codes: 0 = clean, 1 = findings, 2 = invocation/resource error" in " ".join(h.stdout.split())


def test_clean_logs_exit0(tmp_path):
    log = write_lines(tmp_path, "access_benign.log", corpora.all_benign_lines())
    r = run_cli(["--check", "logs", "--log", str(log), "--json"])
    assert r.returncode == 0, r.stdout[:2000]
    doc = json.loads(r.stdout)
    assert doc["summary"]["exit_code"] == 0 and doc["summary"]["counts"]["warn"] == 0
    assert doc["summary"]["counts"]["critical"] == 0 and doc["tool"] == "node2shell-detector"
    assert doc["cve"] == "CVE-2026-111497" and doc["errors"] == []
    assert doc["selftest"] is None and doc["posture"] is None and doc["binaries"] is None


def test_exploit_logs_exit1_and_defanged(tmp_path):
    log = write_lines(tmp_path, "access_exploit.log", corpora.all_exploit_lines())
    r = run_cli(["--check", "logs", "--log", str(log), "--json"])
    assert r.returncode == 1
    doc = json.loads(r.stdout)
    assert doc["summary"]["counts"]["critical"] >= 1 and doc["summary"]["counts"]["warn"] >= 5
    for ip in (corpora.IP_A, corpora.IP_B, corpora.IP_C, corpora.IP_D):
        assert ip not in r.stdout                                    # IPs are defanged in the report
    assert {"UA_NODE2SHELL_CHECKER", "REQUEST_CONTENT_ENCODING_BR", "RESPONSE_ID_MARKER"} <= set(
        rule_list(doc, "logs"))


def test_text_mode_sections_and_ids(tmp_path):
    node = make_stub_node(tmp_path, "24.22.0")
    log = write_lines(tmp_path, "a.log", corpora.exploit_lines_by_id()["N2S-11"])
    r = run_cli(["--no-discover", "--node-bin", node, "--log", str(log), "--check", "posture", "--check", "binaries",
                 "--check", "logs"])
    assert r.returncode == 1
    for needle in ("== HOST POSTURE ==", "== BINARY FINGERPRINTS", "== LOG SCAN ==", "== SUMMARY ==",
                   "[critical] NODE_RUNTIME_VERSION", "ids: N2S-11", "basis: VERBATIM", "evidence:"):
        assert needle in r.stdout, needle
    assert "== SELF-TEST" not in r.stdout and "== DEPENDENCY" not in r.stdout


def test_quiet_mode(tmp_path):
    log = write_lines(tmp_path, "a.log", corpora.all_exploit_lines())
    r = run_cli(["--check", "logs", "--log", str(log), "--quiet"])
    assert r.returncode == 1
    for line in r.stdout.splitlines():
        assert line.startswith("[warn") or line.startswith("[critical]") or line.strip() == ""
    assert "[critical]" in r.stdout and "== SUMMARY" not in r.stdout


@pytest.mark.parametrize("argv", [
    ["--log", "{missing}"],
    ["--project", "{missing}"],
    ["--scan-dir", "{missing}"],
    ["--python-site", "{missing}"],
    ["--node-bin", "{missing}"],
    ["--bun-bin", "{missing}"],
    ["--deno-bin", "{missing}"],
    ["--max-lines", "0"],
    ["--max-binary-mb", "0"],
    ["--probe-timeout", "0"],
    ["--self-test-timeout", "-1"],
])
def test_invocation_problems_exit_2(tmp_path, argv):
    argv = [a.replace("{missing}", str(tmp_path / "does_not_exist")) for a in argv]
    r = run_cli(argv + ["--json"])
    assert r.returncode == 2, r.stdout[:1500]
    doc = json.loads(r.stdout)
    assert doc["errors"] and doc["summary"]["exit_code"] == 2


def test_log_that_is_a_directory_exit_2(tmp_path):
    r = run_cli(["--log", str(tmp_path)])
    assert r.returncode == 2 and "not a regular file" in r.stdout


def test_bad_check_name_exit_2():
    r = run_cli(["--check", "bogus"])
    assert r.returncode == 2 and "invalid choice" in r.stderr


def test_default_run_on_this_host_does_not_crash():
    """Real discovery on whatever machine this is: structure only, never the verdicts."""
    r = run_cli(["--json"])
    assert r.returncode in (0, 1), r.stdout[:2000]
    doc = json.loads(r.stdout)
    assert doc["tool"] == "node2shell-detector"
    for sec in ("posture", "binaries", "deps", "logs"):
        assert doc[sec] is not None
    assert doc["selftest"] is None                                   # opt-in only
    assert doc["errors"] == []


# ------------------------------------------------------------------ in-process: hermetic stub runs ----

def test_vulnerable_stub_exit1_and_fixed_stub_exit0(tmp_path, capsys):
    code, doc = run_json(capsys, ["--no-discover", "--node-bin", make_stub_node(tmp_path, "24.22.0"),
                                  "--check", "posture"])
    assert code == 1 and doc["summary"]["counts"]["critical"] == 1
    code, doc = run_json(capsys, ["--no-discover", "--node-bin", make_stub_node(tmp_path, "24.22.1"),
                                  "--check", "posture"])
    assert code == 0 and doc["summary"]["counts"] == {"critical": 0, "warn": 0, "info": 0, "ok": 1}
    code, doc = run_json(capsys, ["--no-discover", "--bun-bin", make_stub_bun(tmp_path, "1.4.3"),
                                  "--check", "posture"])
    assert code == 1 and "BUN_RUNTIME_VERSION" in rule_list(doc, "posture")


def test_no_discover_with_nothing_named(capsys):
    code, doc = run_json(capsys, ["--no-discover"])
    assert code == 0
    assert "NO_NODE_RUNTIME_FOUND" in rule_list(doc, "posture")
    assert doc["deps"]["notes"] and "no --project given" in doc["deps"]["notes"][0]
    assert doc["logs"]["files"] == [] and "no --log given" in doc["logs"]["body_visibility_note"]
    assert any("nothing to fingerprint" in n for n in doc["binaries"]["notes"])


def test_self_test_is_opt_in(tmp_path, capsys, monkeypatch):
    marker = tmp_path / "ran-selftest"
    stub = write_exec(tmp_path / "markernode", (
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  --version) echo "v24.22.0";;\n'
        "  -p) echo '{\"versions\":{\"node\":\"24.22.0\",\"brotli\":\"1.2.0\"},\"shared\":false}';;\n"
        f'  *.js) touch "{marker}"; echo \'{SWITCH_OUT}\';;\n'
        "esac\n"))

    def boom(*a, **k):
        raise AssertionError("the self-test ran without --self-test")

    monkeypatch.setattr(selftest, "run_selftest", boom)
    code, doc = run_json(capsys, ["--no-discover", "--node-bin", stub])
    assert doc["selftest"] is None and not marker.exists() and doc["errors"] == []
    monkeypatch.undo()
    code, doc = run_json(capsys, ["--no-discover", "--node-bin", stub, "--self-test"])
    assert marker.exists() and doc["selftest"] is not None


def test_self_test_overrides_the_version_table(tmp_path, capsys):
    # version table says vulnerable (24.22.0), the behavioural test says FIXED -> posture reconciled, exit 0
    stub = make_stub_node(tmp_path, "24.22.0", behaviour="fixed")
    code, doc = run_json(capsys, ["--no-discover", "--node-bin", stub, "--check", "posture", "--self-test"])
    assert code == 0, doc["summary"]
    rt = doc["posture"]["runtimes"][0]
    assert rt["verdict"]["source"] == "behavioural" and rt["verdict"]["severity"] == "ok"
    assert rt["verdict_before_selftest"]["status"] == "vulnerable_unpatched"
    assert [f["rule"] for f in doc["selftest"]["findings"]] == ["SELFTEST_FIXED"]
    assert doc["summary"]["counts"]["critical"] == 0
    # ... and the other way round: version says fixed (24.22.1), behaviour says vulnerable -> critical
    stub2 = make_stub_node(tmp_path, "24.22.1", behaviour="vulnerable")
    code, doc = run_json(capsys, ["--no-discover", "--node-bin", stub2, "--check", "posture", "--self-test"])
    assert code == 1 and doc["posture"]["runtimes"][0]["verdict"]["severity"] == "critical"
    assert "SELFTEST_VULNERABLE" in rule_list(doc, "selftest")
    # a crashing child is vulnerable behaviour too (a bun stub this time)
    stub3 = make_stub_bun(tmp_path, "1.4.4", behaviour="crash")
    code, doc = run_json(capsys, ["--no-discover", "--bun-bin", stub3, "--check", "posture", "--self-test"])
    assert code == 1 and "SELFTEST_CRASH" in rule_list(doc, "selftest")


def test_self_test_without_posture_and_text_section(tmp_path, capsys):
    log = write_lines(tmp_path, "a.log", corpora.benign_access_combined())
    stub = make_stub_node(tmp_path, "24.22.1", behaviour="fixed")
    code, out = run_main(capsys, ["--no-discover", "--node-bin", stub, "--check", "logs", "--log", str(log),
                                  "--self-test"])
    assert code == 0 and "== SELF-TEST (opt-in, N2S-25" in out and "== HOST POSTURE ==" not in out


def test_deps_escalation_end_to_end(tmp_path, capsys):
    proj = npm_project(tmp_path / "proj", {"express": "5.1.0", "axios": "1.7.2"})
    args = ["--no-discover", "--check", "posture", "--check", "deps", "--project", proj]
    vuln = make_stub_node(tmp_path, "24.22.0")
    code, doc = run_json(capsys, args[:1] + ["--node-bin", vuln] + args[1:])
    srv = [f for f in doc["deps"]["findings"] if f["rule"] == "DEP_SERVER_BODY_DECODER"][0]
    assert code == 1 and srv["severity"] == "critical" and srv["related"] == [vuln]
    assert doc["deps"]["runtime_escalation"] is True
    assert [f for f in doc["deps"]["findings"] if f["rule"] == "DEP_CLIENT_DECODER"][0]["severity"] == "warn"
    fixed = make_stub_node(tmp_path, "24.22.1")
    code, doc = run_json(capsys, args[:1] + ["--node-bin", fixed] + args[1:])
    srv = [f for f in doc["deps"]["findings"] if f["rule"] == "DEP_SERVER_BODY_DECODER"][0]
    assert srv["severity"] == "warn" and doc["deps"]["runtime_escalation"] is False
    code, doc = run_json(capsys, ["--no-discover", "--check", "deps", "--project", proj])
    assert doc["deps"]["runtime_escalation"] is None
    assert [f for f in doc["deps"]["findings"] if f["rule"] == "DEP_SERVER_BODY_DECODER"][0]["severity"] == "warn"


def test_self_test_result_feeds_the_escalation(tmp_path, capsys):
    proj = npm_project(tmp_path / "proj", {"express": "5.1.0"})
    # version table says vulnerable, behaviour says fixed: the deps check must NOT escalate
    stub = make_stub_node(tmp_path, "24.22.0", behaviour="fixed")
    code, doc = run_json(capsys, ["--no-discover", "--node-bin", stub, "--check", "posture", "--check", "deps",
                                  "--project", proj, "--self-test"])
    srv = [f for f in doc["deps"]["findings"] if f["rule"] == "DEP_SERVER_BODY_DECODER"][0]
    assert srv["severity"] == "warn" and doc["deps"]["runtime_escalation"] is False


def test_binaries_check_via_cli(tmp_path, capsys):
    apps = tmp_path / "apps"
    apps.mkdir()
    make_elf(apps / "vuln.bin", (M_LENGTH1,))
    code, doc = run_json(capsys, ["--no-discover", "--check", "binaries", "--scan-dir", str(apps)])
    assert code == 1
    assert any(t["path"].endswith("vuln.bin") and t["status"] == "vulnerable" for t in doc["binaries"]["targets"])
    assert "BIN_DECODER_VULNERABLE" in rule_list(doc, "binaries")
    ok_dir = tmp_path / "ok"
    ok_dir.mkdir()
    make_elf(ok_dir / "fixed.bin", (M_SWITCH, M_LENGTH1))
    code, doc = run_json(capsys, ["--no-discover", "--check", "binaries", "--scan-dir", str(ok_dir)])
    assert code == 0 and "BIN_DECODER_FIXED" in rule_list(doc, "binaries")
    code, doc = run_json(capsys, ["--no-discover", "--check", "binaries", "--scan-dir", str(apps),
                                  "--max-binary-mb", "1"])
    assert code == 1                                                    # 16 KiB is well under the 1 MiB cap


def test_python_sites_via_cli(tmp_path, capsys):
    site = make_site(tmp_path / "site-packages", {"Brotli": "1.1.0", "aiohttp": "3.9.5"})
    code, doc = run_json(capsys, ["--no-discover", "--check", "posture", "--python-site", site])
    f = [f for f in doc["posture"]["findings"] if f["rule"] == "PY_BROTLI_MODULE"][0]
    assert code == 1 and f["severity"] == "critical"
    proj = tmp_path / "proj"
    venv_site = proj / ".venv" / "lib" / "python3.12" / "site-packages"
    make_site(venv_site, {"brotlicffi": "1.2.1.0"})
    code, doc = run_json(capsys, ["--no-discover", "--check", "posture", "--project", str(proj)])
    cffi = [f for f in doc["posture"]["findings"] if f["rule"] == "PY_BROTLICFFI_MODULE"]
    assert code == 0 and [f["severity"] for f in cffi] == ["ok"]          # found through <project>/.venv


# ------------------------------------------------------------------ cross-check ----

def test_crosscheck_reports_conflicts_between_version_table_and_fingerprint():
    def rep(ver_sev, bin_status, source="version-table"):
        return {"posture": {"runtimes": [{"kind": "node", "bin": "/x/node", "realpath": "/x/node",
                                          "verdict": {"severity": ver_sev, "status": "s", "source": source}}]},
                "binaries": {"targets": [{"kind": "node", "path": "/x/node", "status": bin_status}], "findings": []}}
    a = rep("critical", "fixed")                                         # version says vulnerable, marker says fixed
    cli._crosscheck(a)
    f = a["binaries"]["findings"][0]
    assert f["rule"] == "EVIDENCE_CONFLICT" and f["severity"] == "warn" and f["fingerprints"] == ["N2S-23", "N2S-25"]
    assert "VULNERABLE" in f["message"] and "FIXED" in f["message"] and "--self-test" in f["message"]
    b = rep("ok", "vulnerable")                                          # the other way round
    cli._crosscheck(b)
    assert b["binaries"]["findings"][0]["rule"] == "EVIDENCE_CONFLICT"
    for agree in (rep("ok", "fixed"), rep("critical", "vulnerable"), rep("critical", "inconclusive"),
                  rep("warn", "fixed"), rep("critical", "fixed", source="behavioural"),
                  rep("critical", "fixed", source="shared-library")):
        cli._crosscheck(agree)
        assert agree["binaries"]["findings"] == []


def test_main_accepts_argv_none_via_sys_argv(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["node2shell-detector", "--no-discover", "--check", "deps", "--json"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["argv"][0] == "node2shell-detector"
