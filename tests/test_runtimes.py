"""HOST POSTURE: runtime verdicts (stub runtimes only), shared-brotli distro verdicts,
Python site-packages, discovery, host marker, self-test reconciliation."""

import gzip
import os
import sys
from pathlib import Path

import pytest

import conftest
from conftest import (M_LENGTH1, M_SWITCH, make_elf, make_stub_bun, make_stub_deno, make_stub_node,
                      posture_of, write_exec)
from node2shell_detector import fingerprints as fp
from node2shell_detector import runtimes, versions

_REAL_LINKED = runtimes.linked_brotli_libs          # captured before the isolation fixture patches it
_ORIG_GLOBS = (runtimes.NODE_GLOBS, runtimes.BUN_GLOBS, runtimes.DENO_GLOBS)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Never touch the machine's real runtimes / linkage while testing."""
    monkeypatch.setattr(runtimes, "NODE_GLOBS", ())
    monkeypatch.setattr(runtimes, "BUN_GLOBS", ())
    monkeypatch.setattr(runtimes, "DENO_GLOBS", ())
    monkeypatch.setattr(runtimes, "linked_brotli_libs", lambda path: [])


def ok(out):
    return {"rc": 0, "out": out, "err": "", "timeout": False}


def fake_cmds(monkeypatch, **handlers):
    """Stub the package-manager commands; everything else (the runtime stubs) runs for real."""
    real = runtimes.run_cmd

    def fake(cmd, timeout=runtimes.PROBE_TIMEOUT, extra_env=None):
        h = handlers.get(cmd[0])
        if h is not None:
            return h(cmd)
        if cmd[0] in ("dpkg-query", "rpm", "apk", "brew"):
            return None                             # command not available on this "host"
        return real(cmd, timeout=timeout, extra_env=extra_env)

    monkeypatch.setattr(runtimes, "run_cmd", fake)


def finding(res, rule):
    hits = [f for f in res["findings"] if f["rule"] == rule]
    assert hits, f"{rule} not in {[f['rule'] for f in res['findings']]}"
    return hits[0]


# ------------------------------------------------------------------ node verdicts ----

def test_vulnerable_node_is_critical(tmp_path):
    node = make_stub_node(tmp_path, "24.22.0")
    res = posture_of(node=[node])
    rt = res["runtimes"][0]
    assert rt["version"] == "v24.22.0"
    assert rt["verdict"]["severity"] == "critical" and rt["verdict"]["source"] == "version-table"
    f = finding(res, "NODE_RUNTIME_VERSION")
    assert f["severity"] == "critical" and f["check"] == "posture"
    # the finding text states that process.versions.brotli is never used for a verdict
    assert "process.versions.brotli" in f["message"]
    assert "does not change when the fix lands" in f["message"]
    assert "never used for a verdict" in f["message"]
    assert "24.22.0" in f["evidence"]
    assert f["basis"].startswith("VERBATIM")
    assert "fixed release exists" in f["message"]


@pytest.mark.parametrize("ver", ["22.23.4", "24.22.1", "26.12.1", "24.23.0"])
def test_fixed_node_is_ok(tmp_path, ver):
    res = posture_of(node=[make_stub_node(tmp_path, ver)])
    assert res["runtimes"][0]["verdict"]["severity"] == "ok"
    assert finding(res, "NODE_RUNTIME_VERSION")["severity"] == "ok"
    assert "Restart" in finding(res, "NODE_RUNTIME_VERSION")["message"]


def test_brotli_version_never_decides(tmp_path):
    # a FIXED node still reports brotli 1.2.0; an UNFIXED one reports 1.2.1 - the value must not matter
    fixed = posture_of(node=[make_stub_node(tmp_path, "24.22.1", brotli="1.2.0")])
    unfixed = posture_of(node=[make_stub_node(tmp_path, "24.22.0", brotli="1.2.1")])
    assert fixed["runtimes"][0]["verdict"]["severity"] == "ok"
    assert unfixed["runtimes"][0]["verdict"]["severity"] == "critical"
    assert fixed["runtimes"][0]["brotli_version"] == "1.2.0"
    # and the same node version gives the same verdict for any brotli value
    a = posture_of(node=[make_stub_node(tmp_path, "22.23.3", brotli="1.1.0")])["runtimes"][0]["verdict"]
    b = posture_of(node=[make_stub_node(tmp_path, "22.23.3", brotli="9.9.9")])["runtimes"][0]["verdict"]
    c = posture_of(node=[make_stub_node(tmp_path, "22.23.3", brotli=None)])["runtimes"][0]["verdict"]
    assert a["status"] == b["status"] == c["status"] == "vulnerable_unpatched"


@pytest.mark.parametrize("ver", ["20.20.2", "25.9.0", "18.20.8", "23.11.1", "21.7.3", "19.9.0"])
def test_eol_nodes_are_critical_no_fix(tmp_path, ver):
    res = posture_of(node=[make_stub_node(tmp_path, ver)])
    v = res["runtimes"][0]["verdict"]
    assert (v["status"], v["severity"]) == ("eol_no_fix", "critical")
    assert "NO fixed release" in finding(res, "NODE_RUNTIME_VERSION")["message"]


def test_future_and_prerelease_node(tmp_path):
    fut = posture_of(node=[make_stub_node(tmp_path, "27.1.0")])["runtimes"][0]["verdict"]
    assert (fut["status"], fut["severity"]) == ("unknown_future_branch", "info")
    pre = posture_of(node=[make_stub_node(tmp_path, "24.22.1-nightly2026102100abc")])["runtimes"][0]["verdict"]
    assert (pre["status"], pre["severity"]) == ("unknown_prerelease", "warn")


def test_missing_probe_keys_are_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(runtimes, "linked_brotli_libs", lambda path: None)      # ldd / otool unavailable
    node = make_stub_node(tmp_path, "24.22.0", probe="empty")
    res = posture_of(node=[node])
    rt = res["runtimes"][0]
    assert rt["brotli_version"] is None and rt["shared_flag"] is None and rt["shared"] == "unknown"
    assert "could not be determined" in rt["verdict"]["detail"]
    f = finding(res, "NODE_RUNTIME_VERSION")
    assert "process.versions.brotli=unknown" in f["evidence"] and "node_shared_brotli=unknown" in f["evidence"]


def test_failed_probe_falls_back_to_version_table(tmp_path):
    node = make_stub_node(tmp_path, "24.22.0", probe="fail")
    res = posture_of(node=[node])
    f = finding(res, "NODE_RUNTIME_VERSION")
    assert f["severity"] == "critical" and "Probe notes" in f["message"]
    assert any("no JSON" in e for e in res["runtimes"][0]["errors"])


def test_explicit_binary_that_cannot_run_is_warn(tmp_path):
    bad = write_exec(tmp_path / "badnode", "#!/bin/sh\nexit 3\n")
    res = posture_of(node=[bad])
    f = finding(res, "NODE_BIN_UNREADABLE")
    assert f["severity"] == "warn" and "unknown / verify" in f["message"]
    notexec = tmp_path / "notexec"
    notexec.write_text("not executable")
    notexec.chmod(0o644)
    res2 = posture_of(node=[str(notexec)])
    assert finding(res2, "NODE_BIN_UNREADABLE")["severity"] == "warn"


def test_unparseable_version_output(tmp_path):
    node = make_stub_node(tmp_path, "1.0.0", version_out="not-a-version")
    res = posture_of(node=[node])
    f = finding(res, "NODE_RUNTIME_VERSION")
    assert f["severity"] == "warn" and "unparseable" in f["message"]


def test_version_probe_timeout(tmp_path):
    slow = write_exec(tmp_path / "slownode", "#!/bin/sh\nsleep 5\n")
    res = posture_of(node=[slow], timeout=1)
    assert any("timed out" in e for e in res["runtimes"][0]["errors"])
    assert finding(res, "NODE_BIN_UNREADABLE")["severity"] == "warn"


def test_no_runtime_found_is_info():
    res = runtimes.run_posture(discovered=[], include_running_python=False, host_marker_paths=[])
    f = finding(res, "NO_NODE_RUNTIME_FOUND")
    assert f["severity"] == "info" and "containers" in f["message"]


# ------------------------------------------------------------------ bun / deno ----

def test_bun_verdicts(tmp_path):
    vuln = posture_of(bun=[make_stub_bun(tmp_path, "1.4.3")])
    f = finding(vuln, "BUN_RUNTIME_VERSION")
    assert f["severity"] == "critical" and "1.4.4" in f["message"] and "every Bun release before 1.4.4" in f["message"]
    fixed = posture_of(bun=[make_stub_bun(tmp_path, "1.4.4")])
    assert finding(fixed, "BUN_RUNTIME_VERSION")["severity"] == "ok"


def test_deno_is_info_unresolved(tmp_path):
    res = posture_of(deno=[make_stub_deno(tmp_path, "2.9.8")])
    rt = res["runtimes"][0]
    assert rt["version"] == "2.9.8"
    f = finding(res, "DENO_RUNTIME_STATUS")
    assert f["severity"] == "info" and "unresolved" in f["message"] and "NOT cleared" in f["message"]
    assert "BRIEF s5.3" in f["basis"]


# ------------------------------------------------------------------ shared brotli ----

def shared_node(tmp_path, monkeypatch, lib_path, probe_shared=True, version="22.23.2"):
    node = make_stub_node(tmp_path, version, shared=probe_shared)
    monkeypatch.setattr(runtimes, "linked_brotli_libs",
                        lambda p: [{"name": "libbrotlidec.so.1", "path": lib_path}])
    return node


def test_shared_build_moves_verdict_debian_changelog(tmp_path, monkeypatch):
    lib = make_elf(tmp_path / "libbrotlidec.so.1")                 # marker scan inconclusive
    chg = tmp_path / "changelog.Debian.gz"
    with gzip.open(chg, "wt") as fh:
        fh.write("brotli (1.0.9-2+deb12u1) bookworm-security; urgency=high\n\n  * CVE-2026-111497: fix\n")
    monkeypatch.setattr(runtimes, "DEBIAN_CHANGELOG_PATHS", (str(chg),))
    fake_cmds(monkeypatch, **{"dpkg-query": lambda cmd: ok("1.0.9-2+b2\n")})
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    rt = res["runtimes"][0]
    assert rt["shared"] == "yes"
    assert rt["eval"]["status"] == "vulnerable_unpatched"            # the version table alone would say vulnerable ...
    assert (rt["verdict"]["status"], rt["verdict"]["severity"]) == ("patched", "ok")   # ... the library decides
    assert rt["verdict"]["source"] == "shared-library"
    f = finding(res, "NODE_SHARED_BROTLI")
    assert f["severity"] == "ok" and "changelog.Debian.gz" in f["message"] and "says nothing" in f["message"]
    assert "never used for a verdict" in f["message"]


@pytest.mark.parametrize("pkg_version,expected", [
    ("1.0.9-2+deb12u1", "ok"), ("1.0.9-2+b2", "critical"),
    ("1.1.0-2+deb13u1", "ok"), ("1.1.0-2", "critical"),
    ("1.2.0-4", "critical"), ("1.2.0-5", "warn"),
])
def test_shared_debian_version_fallback(tmp_path, monkeypatch, pkg_version, expected):
    lib = make_elf(tmp_path / "libbrotlidec.so.1")
    monkeypatch.setattr(runtimes, "DEBIAN_CHANGELOG_PATHS", (str(tmp_path / "missing.gz"),))
    fake_cmds(monkeypatch, **{"dpkg-query": lambda cmd: ok(pkg_version + "\n")})
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    assert res["runtimes"][0]["verdict"]["severity"] == expected
    assert finding(res, "NODE_SHARED_BROTLI")["severity"] == expected


def rpm_handler(version, changelog):
    def h(cmd):
        if "--changelog" in cmd:
            return ok(changelog)
        if cmd[-1] == "brotli":
            return ok(version + "\n")
        return {"rc": 1, "out": "", "err": "package not installed", "timeout": False}
    return h


def test_shared_rpm_changelog(tmp_path, monkeypatch):
    lib = make_elf(tmp_path / "libbrotlidec.so.1")
    fake_cmds(monkeypatch, rpm=rpm_handler("1.0.9-4.el9", "* Fri Oct 23 2026 Maint <m@example.org> - 1.0.9-4\n- CVE-2026-111497\n"))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    assert res["runtimes"][0]["verdict"]["severity"] == "ok"
    fake_cmds(monkeypatch, rpm=rpm_handler("1.0.9-4.el9", "* Mon Jan 01 2026 Maint - 1.0.9-3\n- rebuild\n"))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    v = res["runtimes"][0]["verdict"]
    assert v["severity"] == "critical" and "no CVE-2026-111497 entry" in v["detail"]
    assert "Red Hat" in v["detail"]
    # an upstream-fixed version needs no changelog entry
    fake_cmds(monkeypatch, rpm=rpm_handler("1.2.1-1.fc43", "- unrelated\n"))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    assert res["runtimes"][0]["verdict"]["severity"] == "ok"


@pytest.mark.parametrize("apk_ver,expected", [
    ("1.1.0-r2", "critical"), ("1.2.0-r0", "critical"),
    ("1.2.1-r0", "ok"), ("1.1.1-r0", "ok"), ("1.2.2-r1", "ok"),
])
def test_shared_alpine(tmp_path, monkeypatch, apk_ver, expected):
    lib = make_elf(tmp_path / "libbrotlidec.so.1")
    fake_cmds(monkeypatch, apk=lambda cmd: ok(f"brotli-libs-{apk_ver}\n"))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    assert res["runtimes"][0]["verdict"]["severity"] == expected


@pytest.mark.parametrize("ver,expected", [("1.2.0", "critical"), ("1.1.0", "critical"), ("1.2.1", "ok")])
def test_shared_homebrew_cellar_path(tmp_path, monkeypatch, ver, expected):
    lib = f"/opt/homebrew/Cellar/brotli/{ver}/lib/libbrotlidec.1.dylib"       # need not exist
    fake_cmds(monkeypatch)
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib, version="26.7.0")])
    v = res["runtimes"][0]["verdict"]
    assert v["severity"] == expected and v["source"] == "shared-library"
    if expected == "critical":
        assert "brew upgrade brotli" in v["detail"]


def test_shared_homebrew_brew_list_fallback(tmp_path, monkeypatch):
    lib = make_elf(tmp_path / "libbrotlidec.dylib")
    fake_cmds(monkeypatch, brew=lambda cmd: ok("brotli 1.1.0 1.2.1\n"))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    assert res["runtimes"][0]["verdict"]["severity"] == "ok"       # highest installed keg
    fake_cmds(monkeypatch, brew=lambda cmd: ok("brotli 1.2.0\n"))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    assert res["runtimes"][0]["verdict"]["severity"] == "critical"


def test_shared_unknown_is_warn_verify(tmp_path, monkeypatch):
    lib = make_elf(tmp_path / "libbrotlidec.so.1")                  # no markers, no package manager
    fake_cmds(monkeypatch)
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, lib)])
    v = res["runtimes"][0]["verdict"]
    assert (v["status"], v["severity"]) == ("unknown_verify", "warn")
    assert "unknown / verify" in v["detail"] and "zgrep CVE-2026-111497" in v["detail"]


def test_shared_marker_only_evidence(tmp_path, monkeypatch):
    fake_cmds(monkeypatch)
    fixed = make_elf(tmp_path / "fixed.so", markers=(M_SWITCH, M_LENGTH1))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, fixed)])
    assert res["runtimes"][0]["verdict"]["severity"] == "ok"
    vuln = make_elf(tmp_path / "vuln.so", markers=(M_LENGTH1,))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, vuln)])
    assert res["runtimes"][0]["verdict"]["severity"] == "critical"


def test_shared_evidence_conflict_is_warn(tmp_path, monkeypatch):
    chg = tmp_path / "changelog.Debian.gz"
    with gzip.open(chg, "wt") as fh:
        fh.write("  * CVE-2026-111497\n")
    monkeypatch.setattr(runtimes, "DEBIAN_CHANGELOG_PATHS", (str(chg),))
    fake_cmds(monkeypatch, **{"dpkg-query": lambda cmd: ok("1.0.9-2+deb12u1\n")})
    vuln_lib = make_elf(tmp_path / "vuln.so", markers=(M_LENGTH1,))
    res = posture_of(node=[shared_node(tmp_path, monkeypatch, vuln_lib)])
    v = res["runtimes"][0]["verdict"]
    assert (v["status"], v["severity"]) == ("conflict_verify", "warn")
    assert "evidence conflict" in v["detail"]


def test_shared_flag_true_without_linked_libs(tmp_path, monkeypatch):
    fake_cmds(monkeypatch)
    node = make_stub_node(tmp_path, "24.22.1", shared=True)         # linkage inspected: nothing found
    res = posture_of(node=[node])
    rt = res["runtimes"][0]
    assert rt["shared"] == "yes"
    assert rt["verdict"]["severity"] == "warn"                      # version says fixed, but the library decides


def test_linkage_alone_makes_a_build_shared(tmp_path, monkeypatch):
    lib = make_elf(tmp_path / "libbrotlidec.so.1", markers=(M_SWITCH,))
    fake_cmds(monkeypatch)
    node = make_stub_node(tmp_path, "22.23.2", shared=False)        # config flag says static
    monkeypatch.setattr(runtimes, "linked_brotli_libs",
                        lambda p: [{"name": "libbrotlidec.so.1", "path": lib}])
    rt = posture_of(node=[node])["runtimes"][0]
    assert rt["shared"] == "yes" and rt["verdict"]["severity"] == "ok"


# ------------------------------------------------------------------ ldd / otool parsing ----

def test_linked_libs_ldd(monkeypatch):
    monkeypatch.setattr(runtimes.platform, "system", lambda: "Linux")
    out = ("\tlinux-vdso.so.1 (0x00007ffc)\n"
           "\tlibbrotlidec.so.1 => /lib/x86_64-linux-gnu/libbrotlidec.so.1 (0x00007f1)\n"
           "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2)\n")
    monkeypatch.setattr(runtimes, "run_cmd", lambda cmd, timeout=10, extra_env=None: ok(out))
    assert _REAL_LINKED("/usr/bin/node") == [
        {"name": "libbrotlidec.so.1", "path": "/lib/x86_64-linux-gnu/libbrotlidec.so.1"}]


def test_linked_libs_ldd_not_found_and_static(monkeypatch):
    monkeypatch.setattr(runtimes.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runtimes, "run_cmd", lambda cmd, timeout=10, extra_env=None:
                        ok("\tlibbrotlidec.so.1 => not found\n"))
    assert _REAL_LINKED("/x") == [{"name": "libbrotlidec.so.1", "path": None}]
    monkeypatch.setattr(runtimes, "run_cmd", lambda cmd, timeout=10, extra_env=None:
                        {"rc": 1, "out": "\tnot a dynamic executable\n", "err": "", "timeout": False})
    assert _REAL_LINKED("/x") == []
    monkeypatch.setattr(runtimes, "run_cmd", lambda cmd, timeout=10, extra_env=None: None)
    assert _REAL_LINKED("/x") is None                               # no ldd: unknown, not "no"
    monkeypatch.setattr(runtimes, "run_cmd", lambda cmd, timeout=10, extra_env=None:
                        {"rc": 1, "out": "", "err": "weird failure", "timeout": False})
    assert _REAL_LINKED("/x") is None


def test_linked_libs_otool(monkeypatch):
    monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
    out = ("/opt/homebrew/bin/node:\n"
           "\t/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib (compatibility version 1.0.0, current version 1.2.0)\n"
           "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1356.0.0)\n")
    monkeypatch.setattr(runtimes, "run_cmd", lambda cmd, timeout=10, extra_env=None: ok(out))
    assert _REAL_LINKED("/opt/homebrew/bin/node") == [
        {"name": "libbrotlidec.1.dylib", "path": "/opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib"}]


# ------------------------------------------------------------------ python sites ----

def make_site(root, pkgs, eggs=None):
    site = Path(root)
    site.mkdir(parents=True, exist_ok=True)
    for name, ver in pkgs.items():
        d = site / f"{name.replace('-', '_')}-{ver}.dist-info"
        d.mkdir()
        (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\nSummary: x\n\nBody\n")
    for name, ver in (eggs or {}).items():
        d = site / f"{name}-{ver}.egg-info"
        d.mkdir()
        (d / "PKG-INFO").write_text(f"Metadata-Version: 1.1\nName: {name}\nVersion: {ver}\n")
    return str(site)


def py_posture(sites, **kw):
    return runtimes.run_posture(discovered=[], python_sites=sites, include_running_python=False,
                                host_marker_paths=[], **kw)


def test_read_site_packages_dist_and_egg_info(tmp_path):
    site = make_site(tmp_path / "sp", {"Brotli": "1.1.0", "My_Pkg": "2.0"}, eggs={"oldpkg": "0.1"})
    pk = runtimes.read_site_packages(site)
    assert pk == {"brotli": "1.1.0", "my-pkg": "2.0", "oldpkg": "0.1"}


def test_python_brotli_with_aiohttp_is_critical(tmp_path):
    site = make_site(tmp_path / "sp", {"Brotli": "1.1.0", "aiohttp": "3.9.5", "requests": "2.32.0",
                                       "httpx": "0.27.0", "urllib3": "2.2.0", "pip": "24.0", "Scrapy": "2.11.0"})
    res = py_posture([site])
    f = finding(res, "PY_BROTLI_MODULE")
    assert f["severity"] == "critical"
    assert "aiohttp 3.9.5" in f["message"] and "auto_decompress" in f["message"]
    for consumer in ("requests", "httpx", "urllib3", "pip", "scrapy"):
        assert consumer in f["message"], consumer
    assert "defang" not in f["message"]


def test_python_brotli_without_aiohttp_is_warn_and_fixed_is_ok(tmp_path):
    warn = py_posture([make_site(tmp_path / "a", {"Brotli": "1.2.0", "requests": "2.32.0"})])
    f = finding(warn, "PY_BROTLI_MODULE")
    assert f["severity"] == "warn" and "requests" in f["message"]
    fixed = py_posture([make_site(tmp_path / "b", {"Brotli": "1.2.1", "aiohttp": "3.14.5"})])
    assert finding(fixed, "PY_BROTLI_MODULE")["severity"] == "ok"
    outside = py_posture([make_site(tmp_path / "c", {"Brotli": "1.0.1"})])
    assert finding(outside, "PY_BROTLI_MODULE")["severity"] == "info"


@pytest.mark.parametrize("ver,aio,expected", [
    ("1.0.9.0", False, "warn"), ("1.2.0.2", False, "warn"), ("1.2.0.2", True, "critical"),
    ("1.2.1.0", True, "ok"), ("0.8.0", True, "ok"),
])
def test_python_brotlicffi(tmp_path, ver, aio, expected):
    pk = {"brotlicffi": ver}
    if aio:
        pk["aiohttp"] = "3.9.5"
    res = py_posture([make_site(tmp_path / "s", pk)])
    f = finding(res, "PY_BROTLICFFI_MODULE")
    assert f["severity"] == expected
    assert "[.]" not in f["evidence"] and ver in f["evidence"]       # 4-part versions are not defanged like IPs


def test_python_site_dirs_discovery(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    venv_site = proj / ".venv" / "lib" / "python3.12" / "site-packages"
    venv_site.mkdir(parents=True)
    plain_venv = proj / "venv" / "lib64" / "python3.11" / "site-packages"
    plain_venv.mkdir(parents=True)
    extra = tmp_path / "extra-site"
    extra.mkdir()
    running = tmp_path / "running" / "site-packages"
    running.mkdir(parents=True)
    monkeypatch.setattr(sys, "path", [str(running), "/nonexistent/other"])
    got = runtimes.python_site_dirs([str(extra)], [str(proj)])
    assert str(venv_site) in got and str(plain_venv) in got and str(extra) in got and str(running) in got
    assert len(got) == len(set(os.path.realpath(g) for g in got))
    only = runtimes.python_site_dirs([str(extra)], [str(proj)], include_running=False)
    assert str(running) not in only and str(extra) in only


# ------------------------------------------------------------------ discovery ----

def test_discovery_version_manager_layouts(tmp_path, monkeypatch):
    monkeypatch.setattr(runtimes, "NODE_GLOBS", _ORIG_GLOBS[0])
    monkeypatch.setattr(runtimes, "BUN_GLOBS", _ORIG_GLOBS[1])
    monkeypatch.setattr(runtimes, "DENO_GLOBS", _ORIG_GLOBS[2])
    home = tmp_path / "home"
    want = {
        "nvm": home / ".nvm/versions/node/v22.23.4/bin/node",
        "fnm": home / ".local/share/fnm/node-versions/v24.22.1/installation/bin/node",
        "volta": home / ".volta/tools/image/node/26.12.1/bin/node",
        "asdf": home / ".asdf/installs/nodejs/20.20.2/bin/node",
        "n": tmp_path / "nprefix/n/versions/node/20.0.0/bin/node",
    }
    for p in want.values():
        p.parent.mkdir(parents=True)
        write_exec(p, "#!/bin/sh\n")
    bun = home / ".bun/bin/bun"
    bun.parent.mkdir(parents=True)
    write_exec(bun, "#!/bin/sh\n")
    deno = home / ".deno/bin/deno"
    deno.parent.mkdir(parents=True)
    write_exec(deno, "#!/bin/sh\n")
    shim = home / ".asdf/shims/node"
    shim.parent.mkdir(parents=True)
    write_exec(shim, "#!/bin/sh\n")                                  # version-manager shim: skipped
    volta_shim_target = home / ".volta/bin/volta-shim"
    volta_shim_target.parent.mkdir(parents=True)
    write_exec(volta_shim_target, "#!/bin/sh\n")
    os.symlink(volta_shim_target, home / ".volta/bin/node")          # volta's node is a symlink to its shim
    found = runtimes.discover(home=str(home), environ={"N_PREFIX": str(tmp_path / "nprefix")}, path_env="")
    by_path = {e["path"]: e for e in found}
    for source, p in want.items():
        assert str(p) in by_path, source
        assert by_path[str(p)]["source"] == source and by_path[str(p)]["kind"] == "node"
    assert by_path[str(bun)]["kind"] == "bun" and by_path[str(deno)]["kind"] == "deno"
    assert str(shim) not in by_path
    assert str(home / ".volta/bin/node") not in by_path


def test_discovery_path_dedupes_by_realpath(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    write_exec(a / "node", "#!/bin/sh\n")
    os.symlink(a / "node", b / "node")                               # same binary via two PATH dirs
    write_exec(b / "nodejs", "#!/bin/sh\n")                          # Debian-style name
    write_exec(b / "bun", "#!/bin/sh\n")
    found = runtimes.discover(home=str(tmp_path / "nohome"), environ={}, path_env=f"{a}{os.pathsep}{b}")
    nodes = [e for e in found if e["kind"] == "node"]
    assert len(nodes) == 2                                           # node (deduped) + nodejs
    assert {e["source"] for e in nodes} == {"PATH"}
    assert [e["kind"] for e in found if e["path"].endswith("bun")] == ["bun"]


def test_discovery_explicit_flag_and_explicit_only(tmp_path):
    n = write_exec(tmp_path / "mynode", "#!/bin/sh\n")
    found = runtimes.discover(node_bins=[n], home=str(tmp_path), environ={}, path_env=str(tmp_path))
    assert found[0]["path"] == n and found[0]["explicit"] is True and found[0]["source"] == "--node-bin"
    only = runtimes.discover(node_bins=[n], bun_bins=[], home=str(tmp_path), environ={}, path_env=str(tmp_path),
                             explicit_only=True)
    assert [e["path"] for e in only] == [n]
    write_exec(tmp_path / "node", "#!/bin/sh\n")                      # PATH candidate: ignored when explicit_only
    assert [e["path"] for e in runtimes.discover(explicit_only=True, environ={}, path_env=str(tmp_path))] == []


def test_clean_env_drops_option_preloaders(monkeypatch):
    monkeypatch.setenv("NODE_OPTIONS", "--require /tmp/evil.js")
    monkeypatch.setenv("BUN_OPTIONS", "--preload /tmp/evil.js")
    env = runtimes.clean_env({"X": "1"})
    assert "NODE_OPTIONS" not in env and "BUN_OPTIONS" not in env and env["X"] == "1"
    assert env["LC_ALL"] == "C"


# ------------------------------------------------------------------ host marker ----

def test_host_marker_file_n2s_20(tmp_path):
    marker = tmp_path / "pwn_marker.txt"
    absent = runtimes.run_posture(discovered=[], include_running_python=False, host_marker_paths=[str(marker)])
    assert [f for f in absent["findings"] if f["rule"] == "HOST_MARKER_FILE"] == []
    marker.write_text("lab marker")
    present = runtimes.run_posture(discovered=[], include_running_python=False, host_marker_paths=[str(marker)])
    f = finding(present, "HOST_MARKER_FILE")
    assert f["severity"] == "warn" and f["fingerprints"] == ["N2S-20"]
    assert "trivially renamed" in f["message"] and f["basis"].startswith("VERBATIM")
    assert runtimes.scan_host_markers() == [{"path": "/tmp/pwn_marker.txt",
                                             "present": os.path.exists("/tmp/pwn_marker.txt"), "id": "N2S-20"}]


# ------------------------------------------------------------------ self-test reconciliation ----

def test_apply_selftest_fixed_overrides_version_table(tmp_path):
    node = make_stub_node(tmp_path, "24.22.0")
    res = posture_of(node=[node])
    assert res["runtimes"][0]["verdict"]["severity"] == "critical"
    runtimes.apply_selftest(res, [{"bin": node, "status": "fixed"}])
    rt = res["runtimes"][0]
    assert rt["verdict"]["severity"] == "ok" and rt["verdict"]["source"] == "behavioural"
    assert rt["verdict_before_selftest"]["status"] == "vulnerable_unpatched"
    assert finding(res, "NODE_RUNTIME_VERSION")["severity"] == "ok"
    assert "authoritative" in rt["verdict"]["detail"]
    assert runtimes.vulnerable_runtimes(res) == []


def test_apply_selftest_vulnerable_overrides_a_version_pass(tmp_path):
    node = make_stub_node(tmp_path, "24.22.1")
    res = posture_of(node=[node])
    assert res["runtimes"][0]["verdict"]["severity"] == "ok"
    runtimes.apply_selftest(res, [{"bin": node, "status": "vulnerable", "detail": "BLOCK_LENGTH_1"}])
    assert res["runtimes"][0]["verdict"]["severity"] == "critical"
    assert runtimes.vulnerable_runtimes(res) == [node]
    crash = posture_of(node=[make_stub_node(tmp_path, "24.22.1")])
    runtimes.apply_selftest(crash, [{"bin": crash["runtimes"][0]["bin"], "status": "crash"}])
    assert crash["runtimes"][0]["verdict"]["severity"] == "critical"


def test_apply_selftest_inconclusive_changes_nothing(tmp_path):
    node = make_stub_node(tmp_path, "24.22.0")
    res = posture_of(node=[node])
    runtimes.apply_selftest(res, [{"bin": node, "status": "inconclusive"}])
    assert res["runtimes"][0]["verdict"]["source"] == "version-table"
    assert runtimes.vulnerable_runtimes(res) == [node]
