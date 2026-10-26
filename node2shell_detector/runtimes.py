"""HOST POSTURE check: Node.js / Bun / Deno runtime inventory and verdicts, shared-brotli
(distro / Homebrew) verdicts, Python Brotli modules, and the one documented host marker.

Facts enforced here (sources = BRIEF.md; nothing beyond it):

- Node fixed releases 22.23.4 / 24.22.1 / 26.12.1 (security release 2026-10-21): a
  version below that on those lines is critical (a fixed release exists). 25 / 23 / 21 /
  20 / <=19 are end-of-life with NO fix -> critical, move lines. (BRIEF s1, s3;
  versions.py holds the tables.)
- Bun < 1.4.4 -> critical (every earlier release affected); Deno -> info, the Rust
  decoder's status is unresolved (BRIEF s5.3).
- `process.versions.brotli` does NOT change when the fix lands (it is computed from
  BrotliEncoderVersion(); the fix does not touch version.h). It is printed for context
  only and never used for a verdict (BRIEF s3).
- Shared-brotli builds (`--shared-brotli`: process.config flag, or ldd / otool -L shows
  libbrotlidec) link the system library: the Node version says nothing and the verdict
  moves to the distro / Homebrew package (BRIEF s3):
    Debian/Ubuntu  zgrep CVE-2026-111497 in /usr/share/doc/libbrotli1/changelog.Debian.gz,
                   falling back to a dpkg version compare (bookworm 1.0.9-2+deb12u1,
                   trixie 1.1.0-2+deb13u1)
    RPM            rpm -q --changelog grep (Red Hat listed no fixed package at fetch time)
    Alpine         brotli-libs >= 1.2.1-r0 (1.1.1-r0 on 3.21)
    Homebrew       brotli >= 1.2.1
    unknown        warn "verify"
- Python (BRIEF s5.4): Brotli < 1.2.1 and brotlicffi 1.0.9.0 - 1.2.0.2 are critical when
  aiohttp (a server that decodes br request bodies by default) is installed beside them,
  else warn; Scrapy, requests, httpx, urllib3 and pip are named as consumers.

Local commands only (node --version / -p, bun --version, deno --version, ldd / otool -L,
dpkg-query, rpm, apk, brew list); every call has a timeout. Nothing opens a socket.
"""

import glob
import gzip
import json
import os
import platform
import re
import shutil
import site
import subprocess
import sys
from typing import Optional

from . import binscan, fingerprints as fp, versions
from .report import finding

PROBE_TIMEOUT = 10  # seconds per local command

# The one-liner of the spec: versions + the shared-brotli build flag. A missing key = unknown.
NODE_PROBE_JS = ("JSON.stringify({versions: process.versions, "
                 "shared: process.config.variables.node_shared_brotli})")

NODE_NAMES = ("node", "nodejs")

# (source label, glob). "~" = home; "$VAR" expands from the environment (skipped when unset).
NODE_GLOBS = (
    ("nvm", "~/.nvm/versions/node/*/bin/node"),
    ("nvm", "$NVM_DIR/versions/node/*/bin/node"),
    ("fnm", "~/.local/share/fnm/node-versions/*/installation/bin/node"),
    ("fnm", "~/Library/Application Support/fnm/node-versions/*/installation/bin/node"),
    ("fnm", "~/.fnm/node-versions/*/installation/bin/node"),
    ("fnm", "$FNM_DIR/node-versions/*/installation/bin/node"),
    ("volta", "~/.volta/tools/image/node/*/bin/node"),
    ("asdf", "~/.asdf/installs/nodejs/*/bin/node"),
    ("asdf", "$ASDF_DATA_DIR/installs/nodejs/*/bin/node"),
    ("n", "/usr/local/n/versions/node/*/bin/node"),
    ("n", "$N_PREFIX/n/versions/node/*/bin/node"),
    ("n", "$N_PREFIX/bin/node"),
    ("homebrew", "/opt/homebrew/bin/node"),
    ("homebrew", "/opt/homebrew/opt/node*/bin/node"),
    ("homebrew", "/opt/homebrew/Cellar/node*/*/bin/node"),
    ("homebrew", "/usr/local/opt/node*/bin/node"),
    ("homebrew", "/usr/local/Cellar/node*/*/bin/node"),
    ("homebrew", "/home/linuxbrew/.linuxbrew/bin/node"),
    ("homebrew", "/home/linuxbrew/.linuxbrew/Cellar/node*/*/bin/node"),
    ("system", "/usr/bin/node"),
    ("system", "/usr/bin/nodejs"),
    ("system", "/usr/local/bin/node"),
    ("system", "/usr/local/bin/nodejs"),
    ("system", "/opt/node*/bin/node"),
    ("system", "/usr/local/lib/nodejs/*/bin/node"),
    ("snap", "/snap/bin/node"),
)
BUN_GLOBS = (
    ("bun", "~/.bun/bin/bun"),
    ("bun", "$BUN_INSTALL/bin/bun"),
    ("asdf", "~/.asdf/installs/bun/*/bin/bun"),
    ("homebrew", "/opt/homebrew/bin/bun"),
    ("homebrew", "/usr/local/bin/bun"),
    ("system", "/usr/bin/bun"),
)
DENO_GLOBS = (
    ("deno", "~/.deno/bin/deno"),
    ("deno", "$DENO_INSTALL/bin/deno"),
    ("homebrew", "/opt/homebrew/bin/deno"),
    ("homebrew", "/usr/local/bin/deno"),
    ("system", "/usr/bin/deno"),
)

DEBIAN_CHANGELOG_PATHS = (versions.DEBIAN_CHANGELOG,)
BREW_ENV = {"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1", "HOMEBREW_NO_INSTALL_FROM_API": "1"}

PYTHON_CONSUMERS = ("scrapy", "requests", "httpx", "urllib3", "pip")


# ---------------------------------------------------------------------------
# local command helper (everything shells out through here so tests can stub it)
# ---------------------------------------------------------------------------

def clean_env(extra: Optional[dict] = None) -> dict:
    """Environment for local probes: no NODE_OPTIONS / BUN_OPTIONS (they can preload code),
    stable locale, Homebrew told not to touch the network."""
    env = dict(os.environ)
    for k in ("NODE_OPTIONS", "BUN_OPTIONS"):
        env.pop(k, None)
    env["NODE_NO_WARNINGS"] = "1"
    env["LC_ALL"] = "C"
    if extra:
        env.update(extra)
    return env


def run_cmd(cmd, timeout: int = PROBE_TIMEOUT, extra_env: Optional[dict] = None):
    """Run a local command. None = not runnable here; rc -1 + timeout=True = timed out."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL, env=clean_env(extra_env))
        return {"rc": proc.returncode, "out": proc.stdout or "", "err": proc.stderr or "", "timeout": False}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out": "", "err": "timeout", "timeout": True}
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# discovery (no execution)
# ---------------------------------------------------------------------------

def _expand(pattern: str, home: str, environ) -> Optional[str]:
    if pattern.startswith("~"):
        pattern = home + pattern[1:]
    m = re.search(r"\$([A-Z_]+)", pattern)
    if m:
        val = environ.get(m.group(1))
        if not val:
            return None
        pattern = pattern.replace("$" + m.group(1), val)
    return pattern


def _is_shim(path: str, real: str) -> bool:
    """Version-manager shims (asdf, nodenv, mise, volta) re-dispatch and may fetch toolchains: skip."""
    if os.path.basename(os.path.dirname(path)) == "shims":
        return True
    return os.path.basename(real) in ("volta-shim", "volta", "asdf", "mise", "rtx")


def _usable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def discover(node_bins=(), bun_bins=(), deno_bins=(), home: Optional[str] = None,
             environ=None, path_env: Optional[str] = None, explicit_only: bool = False) -> list:
    """Find runtime binaries without executing them.

    Returns [{kind, path, realpath, source, explicit}] deduplicated by realpath. Order:
    explicit (--node-bin / --bun-bin / --deno-bin), PATH entries, then nvm / fnm / volta /
    asdf / n / Homebrew / system locations. `explicit_only` (--no-discover) stops after the
    explicit ones.
    """
    environ = os.environ if environ is None else environ
    home = home or os.path.expanduser("~")
    path_env = environ.get("PATH", "") if path_env is None else path_env
    entries, by_real = [], {}

    def add(kind, path, source, explicit=False):
        try:
            real = os.path.realpath(path)
        except OSError:
            real = path
        if not explicit:
            if not _usable(path) or _is_shim(path, real):
                return
        key = (kind, real)
        if key in by_real:
            if explicit:
                by_real[key]["explicit"] = True
            return
        rec = {"kind": kind, "path": path, "realpath": real, "source": source, "explicit": explicit}
        by_real[key] = rec
        entries.append(rec)

    for kind, paths in (("node", node_bins), ("bun", bun_bins), ("deno", deno_bins)):
        for p in paths:
            add(kind, p, f"--{kind}-bin", explicit=True)

    if explicit_only:
        return entries
    names = {"node": NODE_NAMES, "bun": ("bun",), "deno": ("deno",)}
    for kind in ("node", "bun", "deno"):
        for d in path_env.split(os.pathsep):
            if not d:
                continue
            for name in names[kind]:
                add(kind, os.path.join(d, name), "PATH")
    for kind, table in (("node", NODE_GLOBS), ("bun", BUN_GLOBS), ("deno", DENO_GLOBS)):
        for source, pattern in table:
            pat = _expand(pattern, home, environ)
            if not pat:
                continue
            for p in sorted(glob.glob(pat)):
                add(kind, p, source)
    return entries


# ---------------------------------------------------------------------------
# shared-brotli detection (ldd / otool -L)
# ---------------------------------------------------------------------------

def linked_brotli_libs(path: str) -> Optional[list]:
    """libbrotlidec libraries a binary links: None = could not inspect, [] = inspected, none."""
    system = platform.system()
    if system == "Darwin":
        cmds = [["otool", "-L", path]]
    elif system == "Linux":
        cmds = [["ldd", path]]
    else:
        cmds = [["ldd", path], ["otool", "-L", path]]
    for cmd in cmds:
        res = run_cmd(cmd)
        if res is None or res["timeout"]:
            continue
        text = res["out"] + res["err"]
        if res["rc"] != 0 and "not a dynamic executable" not in text and "statically linked" not in text \
                and "libbrotlidec" not in text:
            continue
        libs = []
        for line in res["out"].splitlines():
            if "libbrotlidec" not in line:
                continue
            if "=>" in line:
                name = line.split("=>")[0].strip()
                target = line.split("=>", 1)[1].split("(")[0].strip()
                lib_path = None if (not target or target == "not found") else target
            else:
                token = line.strip().split(" (")[0].strip()
                name, lib_path = os.path.basename(token), token
            libs.append({"name": name, "path": lib_path})
        return libs
    return None


# ---------------------------------------------------------------------------
# runtime inspection (executes only --version / -p one-liners / deno --version)
# ---------------------------------------------------------------------------

def _last_json(text: str):
    for line in reversed([l for l in text.splitlines() if l.strip()]):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def inspect_node(path: str, timeout: int = PROBE_TIMEOUT) -> dict:
    rt = {"kind": "node", "bin": path, "realpath": _real(path), "version": None, "versions": None,
          "brotli_version": None, "shared_flag": None, "linked": None, "shared": "unknown",
          "errors": [], "eval": None, "shared_eval": None, "verdict": None}
    res = run_cmd([path, "--version"], timeout=timeout)
    if res is None:
        rt["errors"].append("could not execute")
        return rt
    if res["timeout"]:
        rt["errors"].append(f"`--version` timed out after {timeout}s")
        return rt
    out = (res["out"] or "").strip()
    if res["rc"] != 0 or not out:
        rt["errors"].append(f"`--version` failed (rc={res['rc']})")
        return rt
    rt["version"] = out.splitlines()[0].strip()
    if versions.parse_node_version(rt["version"]) is None:
        rt["errors"].append(f"unparseable version output {rt['version']!r}")
        return rt
    probe = run_cmd([path, "-p", NODE_PROBE_JS], timeout=timeout)
    data = _last_json(probe["out"]) if probe and not probe["timeout"] and probe["rc"] == 0 else None
    if isinstance(data, dict):
        vm = data.get("versions")
        if isinstance(vm, dict):
            rt["versions"] = vm
            rt["brotli_version"] = vm.get("brotli")
        if "shared" in data and isinstance(data["shared"], bool):
            rt["shared_flag"] = data["shared"]
    else:
        rt["errors"].append("`-p` probe produced no JSON (process.versions / node_shared_brotli unknown)")
    rt["linked"] = linked_brotli_libs(path)
    rt["shared"] = _shared_state(rt["shared_flag"], rt["linked"])
    return rt


def _shared_state(flag: Optional[bool], linked: Optional[list]) -> str:
    if flag is True or (linked or []):
        return "yes"
    if flag is False:
        return "no"
    if linked is not None:          # inspected, none linked, flag key missing
        return "no"
    return "unknown"


def inspect_bun(path: str, timeout: int = PROBE_TIMEOUT) -> dict:
    rt = {"kind": "bun", "bin": path, "realpath": _real(path), "version": None, "errors": [],
          "eval": None, "verdict": None}
    res = run_cmd([path, "--version"], timeout=timeout)
    if res is None:
        rt["errors"].append("could not execute")
    elif res["timeout"]:
        rt["errors"].append(f"`--version` timed out after {timeout}s")
    elif res["rc"] != 0 or not res["out"].strip():
        rt["errors"].append(f"`--version` failed (rc={res['rc']})")
    else:
        rt["version"] = res["out"].strip().splitlines()[0].strip()
    return rt


def inspect_deno(path: str, timeout: int = PROBE_TIMEOUT) -> dict:
    rt = {"kind": "deno", "bin": path, "realpath": _real(path), "version": None, "errors": [],
          "eval": None, "verdict": None}
    res = run_cmd([path, "--version"], timeout=timeout)
    if res is None:
        rt["errors"].append("could not execute")
    elif res["timeout"]:
        rt["errors"].append(f"`--version` timed out after {timeout}s")
    elif res["rc"] != 0 or not res["out"].strip():
        rt["errors"].append(f"`--version` failed (rc={res['rc']})")
    else:
        m = re.search(r"deno\s+(\S+)", res["out"].strip().splitlines()[0])
        rt["version"] = m.group(1) if m else res["out"].strip().splitlines()[0].strip()
    return rt


def _real(path: str) -> str:
    try:
        return os.path.realpath(path)
    except OSError:
        return path


# ---------------------------------------------------------------------------
# system brotli (shared builds): package manager + binary marker
# ---------------------------------------------------------------------------

def _read_text_maybe_gz(path: str) -> Optional[str]:
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, EOFError, gzip.BadGzipFile):
        return None


def debian_status() -> Optional[dict]:
    """Debian/Ubuntu libbrotli1: changelog grep first, dpkg version compare second (BRIEF s3)."""
    res = run_cmd(["dpkg-query", "-W", "-f=${Version}\n", "libbrotli1"])
    version = res["out"].strip() if (res and res["rc"] == 0 and res["out"].strip()) else None
    text, cl_path = None, None
    for p in DEBIAN_CHANGELOG_PATHS:
        text = _read_text_maybe_gz(p)
        if text is not None:
            cl_path = p
            break
    if version is None and text is None:
        return None
    evidence = [f"dpkg-query libbrotli1 -> {version or 'not installed / unreadable'}",
                f"changelog: {cl_path or 'not readable'}"]
    if text is not None and "CVE-2026-111497" in text:
        return {"manager": "dpkg", "package": "libbrotli1", "version": version, "status": "patched",
                "severity": "ok", "evidence": evidence,
                "detail": f"libbrotli1 {version or ''}: {cl_path} mentions CVE-2026-111497 (the fix is in this "
                          "package build)."}
    if version is None:
        return {"manager": "dpkg", "package": "libbrotli1", "version": None, "status": "unknown",
                "severity": "warn", "evidence": evidence,
                "detail": "libbrotli1 changelog does not mention CVE-2026-111497 and the package version could "
                          "not be read - unknown / verify."}
    st = versions.debian_version_status(version)
    st.update({"manager": "dpkg", "package": "libbrotli1", "version": version, "evidence": evidence})
    return st


def rpm_status() -> Optional[dict]:
    """RPM brotli: `rpm -q --changelog` grep (BRIEF s3: Red Hat listed no fixed package at fetch time)."""
    for name in ("brotli", "libbrotlidec1", "libbrotli"):
        res = run_cmd(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", name])
        if not res or res["rc"] != 0 or not res["out"].strip():
            continue
        version = res["out"].strip().splitlines()[0]
        evidence = [f"rpm -q {name} -> {version}"]
        chg = run_cmd(["rpm", "-q", "--changelog", name], timeout=30)
        if chg and chg["rc"] == 0 and "CVE-2026-111497" in chg["out"]:
            return {"manager": "rpm", "package": name, "version": version, "status": "patched", "severity": "ok",
                    "evidence": evidence + ["rpm -q --changelog mentions CVE-2026-111497"],
                    "detail": f"{name} {version}: the package changelog mentions CVE-2026-111497."}
        ut = versions.parse_dotted(version.split("-")[0])
        st = versions.brotli_upstream_status(ut) if ut else None
        if st == "not_affected_old":
            return {"manager": "rpm", "package": name, "version": version, "status": "not_affected",
                    "severity": "ok", "evidence": evidence,
                    "detail": f"{name} {version}: upstream {versions.fmt(ut)} predates the vulnerable check (1.0.3)."}
        if st == "fixed":
            return {"manager": "rpm", "package": name, "version": version, "status": "patched", "severity": "ok",
                    "evidence": evidence,
                    "detail": f"{name} {version}: upstream {versions.fmt(ut)} is a fixed google/brotli release."}
        return {"manager": "rpm", "package": name, "version": version, "status": "vulnerable_unpatched",
                "severity": "critical", "evidence": evidence + ["rpm -q --changelog: no CVE-2026-111497 entry"],
                "detail": f"{name} {version}: no CVE-2026-111497 entry in the package changelog (distro builds keep "
                          "the old version string, so the changelog is the evidence); Red Hat rated it Important "
                          "with no fixed package listed at fetch time (BRIEF s3) - check your vendor's advisories."}
    return None


def alpine_status() -> Optional[dict]:
    """Alpine brotli-libs >= 1.2.1-r0 (1.1.1-r0 on 3.21) (BRIEF s3)."""
    res = run_cmd(["apk", "info", "-v", "brotli-libs"])
    if not res or res["rc"] != 0:
        return None
    m = re.search(r"brotli-libs-(\d+(?:\.\d+)*)-r(\d+)", res["out"])
    if not m:
        return None
    version = f"{m.group(1)}-r{m.group(2)}"
    ut = versions.parse_dotted(m.group(1))
    st = versions.brotli_upstream_status(ut)
    base = {"manager": "apk", "package": "brotli-libs", "version": version,
            "evidence": [f"apk info -v brotli-libs -> {version}"]}
    if st in ("fixed", "not_affected_old"):
        return dict(base, status="patched", severity="ok",
                    detail=f"brotli-libs {version}: >= the fixed Alpine builds (1.2.1-r0; 1.1.1-r0 on 3.21).")
    return dict(base, status="vulnerable_unpatched", severity="critical",
                detail=f"brotli-libs {version} < 1.2.1-r0 (1.1.1-r0 on Alpine 3.21): upgrade the brotli-libs package "
                       "(BRIEF s3).")


def homebrew_status(lib_paths) -> Optional[dict]:
    """Homebrew brotli >= 1.2.1 (BRIEF s3)."""
    version = None
    for p in lib_paths or []:
        m = re.search(r"/Cellar/brotli/([^/]+)/", _real(p))
        if m:
            version = m.group(1)
            break
    evidence = []
    if version:
        evidence.append(f"Cellar path of the linked library -> brotli {version}")
    else:
        res = run_cmd(["brew", "list", "--versions", "brotli"], timeout=30, extra_env=BREW_ENV)
        if res and res["rc"] == 0 and res["out"].strip():
            toks = res["out"].strip().splitlines()[0].split()[1:]
            parsed = [(versions.parse_dotted(t), t) for t in toks if versions.parse_dotted(t)]
            if parsed:
                version = max(parsed)[1]
                evidence.append(f"brew list --versions brotli -> {' '.join(toks)}")
    if not version:
        return None
    vt = versions.parse_dotted(version)
    st = versions.brotli_upstream_status(vt)
    base = {"manager": "brew", "package": "brotli", "version": version, "evidence": evidence}
    if st in ("fixed", "not_affected_old"):
        return dict(base, status="patched", severity="ok",
                    detail=f"Homebrew brotli {version} >= 1.2.1 (fixed upstream release).")
    return dict(base, status="vulnerable_unpatched", severity="critical",
                detail=f"Homebrew brotli {version} < 1.2.1 - `brew upgrade brotli` (BRIEF s3: Homebrew needs >= 1.2.1).")


def package_status(lib_paths) -> Optional[dict]:
    brewish = any(re.search(r"/(Cellar|homebrew|linuxbrew)/|/opt/homebrew/|/usr/local/opt/", _real(p) or "")
                  or re.search(r"/(Cellar|homebrew|linuxbrew)/|/opt/homebrew/|/usr/local/opt/", p or "")
                  for p in (lib_paths or []))
    order = ("homebrew", "debian", "rpm", "alpine") if brewish else ("debian", "rpm", "alpine", "homebrew")
    for name in order:
        if name == "homebrew":
            res = homebrew_status(lib_paths)
        elif name == "debian":
            res = debian_status()
        elif name == "rpm":
            res = rpm_status()
        else:
            res = alpine_status()
        if res:
            return res
    return None


def eval_system_brotli(libs: list, max_bytes: int = binscan.DEFAULT_MAX_BYTES) -> dict:
    """Verdict for a shared-brotli Node build: the system library decides (BRIEF s3).

    Evidence: (1) the owning package (changelog / version / Homebrew), (2) the N2S-23
    marker scan of the actual library file. Disagreement is reported as a conflict."""
    paths = [l["path"] for l in libs or [] if l.get("path")]
    markers = []
    for p in paths:
        rec = binscan.scan_binary(_real(p), max_bytes=max_bytes)
        markers.append({"path": p, "status": rec["status"]})
    if any(m["status"] == "vulnerable" for m in markers):
        mk = "vulnerable"
    elif markers and all(m["status"] == "fixed" for m in markers):
        mk = "fixed"
    else:
        mk = "inconclusive"
    pkg = package_status(paths)
    evidence = list(pkg["evidence"]) if pkg else []
    evidence += [f"N2S-23 marker {m['path']}: {m['status']}" for m in markers]
    pkg_note = f"{pkg['manager']} {pkg['package']} {pkg['version']}" if pkg else "no package manager attributed the library"
    lead = ("shared-brotli build: the decoder is the system libbrotli, so the Node version says nothing "
            "(BRIEF s3). ")
    if pkg:
        ps = pkg["status"]
        if ps in ("patched", "not_affected"):
            if mk == "vulnerable":
                return _shared("conflict_verify", "warn", evidence, lead + f"{pkg['detail']} BUT the N2S-23 marker scan "
                               "of the linked library shows no BLOCK_SWITCH (the unpatched table) - evidence conflict: "
                               "verify which libbrotli this process really loads.")
            return _shared("patched", "ok", evidence, lead + pkg["detail"]
                           + (" The N2S-23 marker scan of the library file agrees." if mk == "fixed" else ""))
        if ps == "vulnerable_unpatched":
            if mk == "fixed":
                return _shared("conflict_verify", "warn", evidence, lead + f"{pkg['detail']} BUT the N2S-23 marker scan "
                               "of the linked library shows the fixed error table - evidence conflict (backport or "
                               "different library?): verify.")
            return _shared("vulnerable_unpatched", "critical", evidence, lead + pkg["detail"])
        # package status unknown
        if mk == "fixed":
            return _shared("patched", "ok", evidence, lead + f"{pkg['detail']} The N2S-23 marker scan of the library "
                           "file shows the fixed error table (derived evidence).")
        if mk == "vulnerable":
            return _shared("vulnerable_unpatched", "critical", evidence, lead + f"{pkg['detail']} The N2S-23 marker "
                           "scan of the library file shows the unpatched error table.")
        return _shared("unknown_verify", "warn", evidence, lead + f"{pkg['detail']} unknown / verify.")
    if mk == "fixed":
        return _shared("patched", "ok", evidence, lead + "No package manager could attribute the library, but the "
                       "N2S-23 marker scan of the library file shows the fixed error table (derived evidence).")
    if mk == "vulnerable":
        return _shared("vulnerable_unpatched", "critical", evidence, lead + "No package manager could attribute the "
                       "library; the N2S-23 marker scan shows the unpatched error table.")
    return _shared("unknown_verify", "warn", evidence, lead + "The library could not be attributed to a package "
                   "(dpkg / rpm / apk / Homebrew) and the marker scan was inconclusive - unknown / verify: "
                   "`zgrep CVE-2026-111497 /usr/share/doc/libbrotli1/changelog.Debian.gz` (Debian/Ubuntu), "
                   "`rpm -q --changelog brotli | grep CVE-2026-111497` (RPM), apk / brew version checks.")


def _shared(status, severity, evidence, detail) -> dict:
    return {"status": status, "severity": severity, "detail": detail, "evidence": evidence}


# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------

def evaluate_runtime(rt: dict) -> dict:
    """Fill rt['eval'] / rt['verdict'] from the version table (or the system library)."""
    if rt["kind"] == "node":
        ev = versions.eval_node_version(rt["version"])
        rt["eval"] = ev
        if rt.get("shared") == "yes":
            sev = eval_system_brotli(rt.get("linked") or [])
            rt["shared_eval"] = sev
            rt["verdict"] = {"status": sev["status"], "severity": sev["severity"], "detail": sev["detail"],
                             "source": "shared-library"}
        else:
            detail = ev["detail"]
            if rt.get("shared") == "unknown" and ev["severity"] in ("critical", "warn", "ok"):
                detail += (" Whether this build links the system libbrotli (--shared-brotli) could not be "
                           "determined (process.config / ldd / otool unavailable): if it does, the system package "
                           "decides instead.")
            rt["verdict"] = {"status": ev["status"], "severity": ev["severity"], "detail": detail,
                             "source": "version-table"}
    elif rt["kind"] == "bun":
        ev = versions.eval_bun_version(rt["version"])
        rt["eval"] = ev
        rt["verdict"] = {"status": ev["status"], "severity": ev["severity"], "detail": ev["detail"],
                         "source": "version-table"}
    else:
        ev = versions.eval_deno_version(rt.get("version") or "")
        rt["eval"] = ev
        rt["verdict"] = {"status": ev["status"], "severity": ev["severity"], "detail": ev["detail"],
                         "source": "brief s5.3"}
    return rt


def apply_selftest(posture: dict, results: list) -> None:
    """Let the behavioural self-test (N2S-25) override the version-table / package verdict
    for the same binary (it is the ground truth, BRIEF s3/s7) and rebuild the findings."""
    by_real = {_real(r["bin"]): r for r in results}
    for rt in posture.get("runtimes", []):
        if rt.get("kind") not in ("node", "bun") or not rt.get("verdict"):
            continue
        r = by_real.get(rt["realpath"])
        if not r:
            continue
        old = rt["verdict"]
        if r["status"] == "fixed" and old["severity"] in ("critical", "warn"):
            rt["verdict_before_selftest"] = old
            rt["verdict"] = {"status": "patched_behavioural", "severity": "ok", "source": "behavioural",
                             "detail": f"the behavioural self-test (N2S-25) shows a FIXED decoder (BLOCK_SWITCH / -17), "
                                       f"overriding the {old['source']} verdict '{old['status']}' - likely a vendor "
                                       "backport or a patched shared library. The behavioural result is authoritative "
                                       "for this binary. Restart long-running processes."}
        elif r["status"] in ("vulnerable", "crash") and old["severity"] != "critical":
            rt["verdict_before_selftest"] = old
            rt["verdict"] = {"status": "vulnerable_behavioural", "severity": "critical", "source": "behavioural",
                             "detail": f"the behavioural self-test (N2S-25) shows VULNERABLE decoder behaviour "
                                       f"({r.get('detail', '')}), overriding the {old['source']} verdict "
                                       f"'{old['status']}'."}
    posture["findings"] = build_findings(posture)


def vulnerable_runtimes(posture: Optional[dict]) -> list:
    """Paths of node/bun runtimes whose verdict is critical (used for the deps escalation)."""
    out = []
    for rt in (posture or {}).get("runtimes", []):
        if rt.get("kind") in ("node", "bun") and (rt.get("verdict") or {}).get("severity") == "critical":
            out.append(rt["bin"])
    return out


# ---------------------------------------------------------------------------
# Python site-packages (BRIEF s5.4) - metadata only, nothing imported
# ---------------------------------------------------------------------------

def python_site_dirs(extra_sites=(), project_dirs=(), include_running: bool = True) -> list:
    """site-packages / dist-packages of the running interpreter, --python-site dirs, and
    .venv / venv under each --project."""
    cands = list(extra_sites)
    if include_running:
        for p in sys.path:
            if p and os.path.basename(p.rstrip(os.sep)) in ("site-packages", "dist-packages"):
                cands.append(p)
        try:
            cands.extend(site.getsitepackages())
        except Exception:  # noqa: BLE001 - virtualenv's site lacks getsitepackages on some versions
            pass
        try:
            cands.append(site.getusersitepackages())
        except Exception:  # noqa: BLE001
            pass
    for proj in project_dirs:
        for venv in (".venv", "venv"):
            base = os.path.join(proj, venv)
            for pat in ("lib/python*/site-packages", "lib64/python*/site-packages", "Lib/site-packages"):
                cands.extend(sorted(glob.glob(os.path.join(base, pat))))
    out, seen = [], set()
    for c in cands:
        if not c or not os.path.isdir(c):
            continue
        real = _real(c)
        if real in seen:
            continue
        seen.add(real)
        out.append(c)
    return out


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _read_metadata_headers(path: str) -> dict:
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for _ in range(80):
                line = fh.readline()
                if not line or not line.strip():
                    break
                k, _, v = line.partition(":")
                if k in ("Name", "Version") and k not in out:
                    out[k] = v.strip()
    except OSError:
        pass
    return out


def read_site_packages(site_dir: str) -> dict:
    """{normalized name: version} from *.dist-info/METADATA and *.egg-info/PKG-INFO."""
    pkgs = {}
    try:
        entries = list(os.scandir(site_dir))
    except OSError:
        return pkgs
    for e in entries:
        name = e.name
        meta = None
        if name.endswith(".dist-info") and e.is_dir():
            meta = os.path.join(e.path, "METADATA")
        elif name.endswith(".egg-info"):
            meta = os.path.join(e.path, "PKG-INFO") if e.is_dir() else e.path
        if not meta:
            continue
        h = _read_metadata_headers(meta)
        if h.get("Name") and h.get("Version"):
            pkgs[_norm_name(h["Name"])] = h["Version"]
    return pkgs


def scan_python_sites(site_dirs) -> dict:
    sites = []
    for sd in site_dirs:
        sites.append({"path": sd, "packages": read_site_packages(sd)})
    return {"sites": sites}


def python_findings(py: dict) -> list:
    out = []
    for site_rec in py.get("sites", []):
        pk, path = site_rec["packages"], site_rec["path"]
        aio = pk.get("aiohttp")
        consumers = [n for n in PYTHON_CONSUMERS if n in pk]
        for name, rule, fn in (("brotli", "PY_BROTLI_MODULE", versions.eval_pypi_brotli),
                               ("brotlicffi", "PY_BROTLICFFI_MODULE", versions.eval_pypi_brotlicffi),
                               ("brotlipy", "PY_BROTLIPY_MODULE", versions.eval_pypi_brotlipy)):
            ver = pk.get(name)
            if not ver:
                continue
            ev = fn(ver)
            sev = ev["severity"]
            extra = ""
            if ev["status"] == "vulnerable_unpatched":
                if aio:
                    sev = "critical"
                    extra = (f" aiohttp {aio} is installed in the same environment: the aiohttp SERVER decodes "
                             "`Content-Encoding: br` request bodies by default (auto_decompress=True) when Brotli is "
                             "installed - the only Python server the brief found doing so (BRIEF s5.4); critical if "
                             "this environment serves requests (aiohttp used only as a client still decodes br "
                             "responses).")
                if consumers:
                    extra += (" Consumers here that decode br responses automatically when the module is "
                              f"importable: {', '.join(f'{c} {pk[c]}' for c in consumers)}"
                              " (Scrapy always advertises + decodes br; requests / httpx advertise it by default).")
            out.append(finding(
                rule, sev, f"{path}: {name} {ver} - {ev['detail']}{extra}",
                check="posture", file=path, evidence=f"{name} {ver}" + (f"; aiohttp {aio}" if aio else ""),
                basis=fp.brief_basis("s5.4 / GHSA-9v8h-qqgm-4m35",
                                     "PyPI Brotli < 1.2.1 and brotlicffi 1.0.9.0-1.2.0.2 bundle the vulnerable C "
                                     "decoder; critical when aiohttp is present, else warn"),
                related=[f"{c} {pk[c]}" for c in consumers], defang_ips=False))
    return out


# ---------------------------------------------------------------------------
# host marker (N2S-20)
# ---------------------------------------------------------------------------

def scan_host_markers(paths=None) -> list:
    return [{"path": p, "present": os.path.exists(p), "id": "N2S-20"}
            for p in (paths if paths is not None else fp.HOST_MARKER_PATHS)]


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

def _runtime_evidence(rt: dict) -> str:
    bits = [f"{rt['bin']} --version -> {rt.get('version')}"]
    if rt["kind"] == "node":
        bits.append(f"process.versions.brotli={rt.get('brotli_version') or 'unknown'}")
        bits.append(f"node_shared_brotli={rt['shared_flag'] if rt.get('shared_flag') is not None else 'unknown'}")
        if rt.get("linked"):
            bits.append("links " + ", ".join(l["name"] for l in rt["linked"]))
    return "; ".join(bits)


def build_findings(posture: dict) -> list:
    findings = []
    for rt in posture.get("runtimes", []):
        kind = rt["kind"]
        if rt.get("errors") and not rt.get("version"):
            sev = "warn" if rt.get("explicit") else "info"
            rule = {"node": "NODE_BIN_UNREADABLE", "bun": "BUN_BIN_UNREADABLE", "deno": "DENO_BIN_UNREADABLE"}[kind] \
                if rt.get("explicit") else "RUNTIME_PROBE_FAILED"
            findings.append(finding(
                rule, sev, f"{rt['bin']}: could not be interrogated ({'; '.join(rt['errors'])}) - version posture "
                           "unknown / verify", check="posture", file=rt["bin"],
                basis=fp.brief_basis("s3", "the runtime version decides the verdict; none could be read"),
                defang_ips=False))
            continue
        v = rt.get("verdict") or {}
        if kind == "node":
            rule = "NODE_SHARED_BROTLI" if v.get("source") == "shared-library" else "NODE_RUNTIME_VERSION"
            brotli_note = (f" (process.versions.brotli={rt.get('brotli_version')} is shown for context only: it does "
                           "not change when the fix lands, so it is never used for a verdict.)"
                           if rt.get("brotli_version") else
                           " (process.versions.brotli does not change when the fix lands and is never used for a "
                           "verdict.)")
            msg = f"{rt['bin']} reports Node {rt['version']} -> {v.get('status')}. {v.get('detail', '')}{brotli_note}"
            if rt.get("errors"):
                msg += f" Probe notes: {'; '.join(rt['errors'])}."
            findings.append(finding(
                rule, v.get("severity", "info"), msg, check="posture", file=rt["bin"],
                evidence=_runtime_evidence(rt),
                basis=fp.brief_basis(
                    "s3 version matrix" + (" + distro table" if rule == "NODE_SHARED_BROTLI" else ""),
                    "fixed releases 22.23.4 / 24.22.1 / 26.12.1; EOL lines 25/23/21/20/<=19 have no fix"
                    + ("; shared-brotli builds: the system library decides (changelog / dpkg / rpm / apk / brew)"
                       if rule == "NODE_SHARED_BROTLI" else "")),
                related=(rt.get("shared_eval") or {}).get("evidence", []), defang_ips=False))
        elif kind == "bun":
            findings.append(finding(
                "BUN_RUNTIME_VERSION", v.get("severity", "info"),
                f"{rt['bin']} reports Bun {rt['version']} -> {v.get('status')}. {v.get('detail', '')}",
                check="posture", file=rt["bin"], evidence=f"{rt['bin']} --version -> {rt['version']}",
                basis=fp.brief_basis("s3 / s5.3", "Bun < 1.4.4 affected (every release); 1.4.4 pins brotli v1.2.1"),
                defang_ips=False))
        else:
            findings.append(finding(
                "DENO_RUNTIME_STATUS", "info",
                f"{rt['bin']} reports Deno {rt.get('version')} -> {v.get('status')}. {v.get('detail', '')}",
                check="posture", file=rt["bin"], evidence=f"{rt['bin']} --version -> {rt.get('version')}",
                basis=fp.brief_basis("s5.3", "Deno uses Rust decoders; the status is unresolved, not cleared"),
                defang_ips=False))
    findings.extend(python_findings(posture.get("python") or {}))
    for m in posture.get("markers", []):
        if m.get("present"):
            findings.append(finding(
                "HOST_MARKER_FILE", "warn",
                f"{m['path']} exists - the lab marker file the TheFool-TAROT PoC lab writes (N2S-20). Presence means "
                "that lab PoC (or a copy of its marker) ran on this host; it is trivially renamed, so absence proves "
                "nothing, and it can be your own test - verify before escalating",
                check="posture", file=m["path"], evidence=f"presence of {m['path']}",
                basis=fp.basis("N2S-20"), fingerprints=["N2S-20"], defang_ips=False))
    if not any(r["kind"] in ("node", "bun") for r in posture.get("runtimes", [])) and not posture.get("had_explicit"):
        findings.append(finding(
            "NO_NODE_RUNTIME_FOUND", "info",
            "no node / bun binary discovered (PATH, nvm, fnm, volta, asdf, n, Homebrew, /usr/bin, /usr/local/bin) - "
            "posture must be taken on the host or container that actually runs the service (this tool does not "
            "enter containers)", check="posture",
            basis=fp.brief_basis("s3", "version posture needs a runtime to interrogate")))
    return findings


# ---------------------------------------------------------------------------
# entry
# ---------------------------------------------------------------------------

def run_posture(node_bins=(), bun_bins=(), deno_bins=(), python_sites=(), project_dirs=(),
                timeout: int = PROBE_TIMEOUT, discovered: Optional[list] = None,
                include_running_python: bool = True, host_marker_paths=None) -> dict:
    posture = {"runtimes": [], "python": {}, "markers": [], "findings": [], "notes": [],
               "had_explicit": bool(list(node_bins) or list(bun_bins) or list(deno_bins))}
    entries = discovered if discovered is not None else discover(node_bins, bun_bins, deno_bins)
    for ent in entries:
        if ent["kind"] == "node":
            rt = inspect_node(ent["path"], timeout=timeout)
        elif ent["kind"] == "bun":
            rt = inspect_bun(ent["path"], timeout=timeout)
        else:
            rt = inspect_deno(ent["path"], timeout=timeout)
        rt["source"] = ent.get("source")
        rt["explicit"] = ent.get("explicit", False)
        if rt.get("version") and not (rt["kind"] == "node" and versions.parse_node_version(rt["version"]) is None):
            evaluate_runtime(rt)
        elif rt.get("version") is None or rt["kind"] == "node":
            rt["verdict"] = {"status": "unknown_probe_failed", "severity": "warn" if rt["explicit"] else "info",
                             "detail": "; ".join(rt.get("errors") or ["could not be interrogated"]),
                             "source": "probe"}
        posture["runtimes"].append(rt)
    posture["python"] = scan_python_sites(
        python_site_dirs(python_sites, project_dirs, include_running=include_running_python))
    posture["markers"] = scan_host_markers(host_marker_paths)
    if not posture["runtimes"]:
        posture["notes"].append("no node / bun / deno runtime found")
    posture["findings"] = build_findings(posture)
    return posture
