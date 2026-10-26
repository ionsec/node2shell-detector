"""node2shell-detector CLI - orchestrates the checks:

  posture  : Node / Bun / Deno inventory + verdicts, shared-brotli distro verdicts, Python
             Brotli modules, host marker (local commands with timeouts)
  binaries : decoder error-string fingerprint (N2S-23) and vendored decode.c check (N2S-24)
             (local file reads only)
  deps     : exposure scan of --project directories (lockfiles, node_modules, Dockerfiles ...)
  logs     : access / application log scan against the N2S fingerprints (local reads only)
  --self-test (opt-in, N2S-25): feeds the public regression vector to each runtime's own
             decoder in a throwaway child - see README before enabling

Exit codes:
  0 - checks ran, no warn/critical finding
  1 - at least one warn/critical finding (inspect the report)
  2 - invocation/resource problem (bad flag values, missing explicit paths)

Nothing here opens a network socket.
"""

import argparse
import os
import sys
import traceback

from . import (CVE_ID, TOOL_NAME, __version__, binscan, deps, logs, runtimes, selftest,
               report as rp)
from .report import finding

CHECKS = ("posture", "binaries", "deps", "logs")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(f"{TOOL_NAME} v{__version__} - host-side checks for Node2Shell ({CVE_ID}), the "
                     "out-of-bounds write in Google's Brotli C decoder that Node.js and Bun bundle. Runtime posture, "
                     "decoder binary fingerprints, dependency exposure and log scan. Local operations only; every "
                     "fingerprint and version comes from the IONSEC research brief (2026-10-24)."),
        epilog=("exit codes: 0 = clean, 1 = findings, 2 = invocation/resource error. A log hit is an ATTEMPT "
                "indicator, never proof of execution; posture is point-in-time; process.versions.brotli is never "
                "used for a verdict - see README limits."),
    )
    p.add_argument("--project", metavar="PATH", action="append", default=[],
                   help="project directory to scan for decoder exposure (repeatable): lockfiles, node_modules, "
                        "requirements, go.mod, Cargo.lock, Gemfile.lock, pom.xml, Dockerfiles; also .venv/venv "
                        "site-packages")
    p.add_argument("--log", metavar="PATH", action="append", default=[],
                   help="log file to scan (repeatable; access log, application / stderr / journald text; .gz ok)")
    p.add_argument("--node-bin", metavar="PATH", action="append", default=[],
                   help="extra node binary to interrogate (repeatable; PATH, nvm, fnm, volta, asdf, n, Homebrew and "
                        "/usr/bin are discovered automatically)")
    p.add_argument("--bun-bin", metavar="PATH", action="append", default=[],
                   help="extra bun binary to interrogate (repeatable; PATH and ~/.bun/bin/bun are discovered)")
    p.add_argument("--deno-bin", metavar="PATH", action="append", default=[],
                   help="extra deno binary to report on (repeatable; PATH and ~/.deno/bin/deno are discovered)")
    p.add_argument("--python-site", metavar="PATH", action="append", default=[],
                   help="extra site-packages / dist-packages directory to read (repeatable; the running "
                        "interpreter's and each --project's .venv/venv are scanned automatically)")
    p.add_argument("--scan-dir", metavar="PATH", action="append", default=[],
                   help="directory tree to scan for ELF / Mach-O / PE binaries carrying a Brotli decoder and for "
                        "vendored decode.c (repeatable), e.g. an Electron app folder")
    p.add_argument("--no-discover", action="store_true",
                   help="inspect ONLY what you name (--node-bin / --bun-bin / --deno-bin / --scan-dir / "
                        "--python-site / --project): skip PATH, version-manager, Homebrew, system-library and "
                        "running-interpreter discovery (useful inside containers, and for reproducible runs)")
    p.add_argument("--check", metavar="NAME", action="append", default=[], choices=CHECKS,
                   help="run only this check (repeatable; default: posture, binaries, deps and logs)")
    p.add_argument("--self-test", action="store_true",
                   help="OPT-IN behavioural test (N2S-25): run the public 22-byte regression vector against each "
                        "node/bun binary's own decoder in a throwaway child. On an unpatched runtime this exercises "
                        "the bug inside that child. Never use against a runtime you are not allowed to test")
    p.add_argument("--self-test-timeout", metavar="SEC", type=int, default=selftest.TIMEOUT,
                   help=f"timeout per self-test child (default {selftest.TIMEOUT})")
    p.add_argument("--log-format", metavar="FMT", default="auto",
                   choices=("auto", "combined", "common", "ltsv", "json"),
                   help="force an access-log format (default: auto-detect per line)")
    p.add_argument("--max-lines", metavar="N", type=int, default=200000,
                   help="cap log lines scanned per file (default 200000)")
    p.add_argument("--max-binary-mb", metavar="MB", type=int, default=binscan.DEFAULT_MAX_BYTES // (1024 * 1024),
                   help="skip binaries larger than this when fingerprinting (default 512)")
    p.add_argument("--probe-timeout", metavar="SEC", type=int, default=runtimes.PROBE_TIMEOUT,
                   help=f"timeout per local probe command (default {runtimes.PROBE_TIMEOUT})")
    p.add_argument("--json", action="store_true", help="JSON report instead of text")
    p.add_argument("--quiet", action="store_true", help="only warn/critical finding lines in text mode")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return p


def _validate(args, rep: dict) -> None:
    for path in args.log:
        if not os.path.exists(path):
            rep["errors"].append(f"--log {path}: file not found")
        elif not os.path.isfile(path):
            rep["errors"].append(f"--log {path}: not a regular file")
    for flag, paths in (("--node-bin", args.node_bin), ("--bun-bin", args.bun_bin), ("--deno-bin", args.deno_bin)):
        for p in paths:
            if not os.path.isfile(p):
                rep["errors"].append(f"{flag} {p}: not found (or not a file)")
    for flag, paths in (("--project", args.project), ("--scan-dir", args.scan_dir), ("--python-site", args.python_site)):
        for p in paths:
            if not os.path.isdir(p):
                rep["errors"].append(f"{flag} {p}: not a directory")
    for flag, val in (("--max-lines", args.max_lines), ("--max-binary-mb", args.max_binary_mb),
                      ("--probe-timeout", args.probe_timeout), ("--self-test-timeout", args.self_test_timeout)):
        if val < 1:
            rep["errors"].append(f"{flag} {val}: must be >= 1")


def _crosscheck(rep: dict) -> None:
    """Report posture-vs-binary evidence conflicts (e.g. a vendor backport without a version bump)."""
    post, bins = rep.get("posture"), rep.get("binaries")
    if not post or not bins:
        return
    by_real = {binscan._real(t["path"]): t for t in bins.get("targets", []) if t.get("kind") in ("node", "bun")}
    for rt in post.get("runtimes", []):
        if rt.get("kind") not in ("node", "bun"):
            continue
        t = by_real.get(rt.get("realpath"))
        v = rt.get("verdict") or {}
        if not t or v.get("source") in ("behavioural", "shared-library"):
            continue
        ver_state = {"ok": "fixed", "critical": "vulnerable"}.get(v.get("severity"))
        bin_state = t.get("status") if t.get("status") in ("fixed", "vulnerable") else None
        if ver_state and bin_state and ver_state != bin_state:
            bins["findings"].append(finding(
                "EVIDENCE_CONFLICT", "warn",
                f"{rt['bin']}: the {v.get('source')} verdict says {ver_state.upper()} ({v.get('status')}) but the decoder "
                f"fingerprint (N2S-23) says {bin_state.upper()} - conflicting evidence. A vendor backport without a "
                "version bump, a build with two Brotli copies, or a modified binary can do this. Run --self-test "
                "(N2S-25) for the behavioural answer; until then treat this runtime as unverified.",
                check="binaries", file=rt["bin"], evidence=f"version-table={ver_state}; N2S-23={bin_state}",
                basis=("DERIVED: version-table verdict (BRIEF s3) vs error-string fingerprint (N2S-23) disagree; "
                       "behaviour (N2S-25) is the tie-breaker"),
                fingerprints=["N2S-23", "N2S-25"], defang_ips=False))


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    rep = rp.new_report(sys.argv if argv is None else argv)
    want = set(args.check or CHECKS)

    _validate(args, rep)
    if rep["errors"]:
        rep = rp.finalize(rep)
        _emit(rep, args)
        return rp.TOOL_EXIT_ERROR

    debug = bool(os.environ.get("NODE2SHELL_DEBUG"))

    def fail(name: str, e: Exception) -> None:
        rep["errors"].append(f"{name} check failed: {e.__class__.__name__}: {e}")
        if debug:
            rep["errors"].append(traceback.format_exc())

    # --- discovery (no execution) -------------------------------------------------
    discovered = []
    if "posture" in want or "binaries" in want or args.self_test:
        try:
            discovered = runtimes.discover(args.node_bin, args.bun_bin, args.deno_bin,
                                           explicit_only=args.no_discover)
        except Exception as e:  # never die on a partial result
            fail("discovery", e)

    # --- posture ------------------------------------------------------------------
    posture = None
    if "posture" in want:
        try:
            posture = runtimes.run_posture(
                node_bins=args.node_bin, bun_bins=args.bun_bin, deno_bins=args.deno_bin,
                python_sites=args.python_site, project_dirs=args.project, timeout=args.probe_timeout,
                discovered=discovered, include_running_python=not args.no_discover)
            rep["posture"] = posture
        except Exception as e:
            fail("posture", e)

    # --- self-test (opt-in) - before deps so the escalation sees the reconciled verdicts -----
    if args.self_test:
        try:
            targets = [e for e in discovered if e["kind"] in ("node", "bun", "deno")]
            st = selftest.run_selftest(targets, timeout=args.self_test_timeout)
            rep["selftest"] = st
            if posture is not None:
                runtimes.apply_selftest(posture, st["binaries"])
        except Exception as e:
            fail("self-test", e)

    # --- binaries -----------------------------------------------------------------
    if "binaries" in want:
        try:
            lib_extra = []
            for rt in (posture or {}).get("runtimes", []):
                lib_extra.extend(l["path"] for l in (rt.get("linked") or []) if l.get("path"))
            rep["binaries"] = binscan.run_binaries(
                node_bins=[e["path"] for e in discovered if e["kind"] == "node"],
                bun_bins=[e["path"] for e in discovered if e["kind"] == "bun"],
                lib_extra=lib_extra,
                python_sites=runtimes.python_site_dirs(args.python_site, args.project,
                                                       include_running=not args.no_discover),
                scan_dirs=args.scan_dir, project_dirs=args.project,
                max_bytes=args.max_binary_mb * 1024 * 1024, discover_libs=not args.no_discover)
            _crosscheck(rep)
        except Exception as e:
            fail("binaries", e)

    # --- deps ---------------------------------------------------------------------
    if "deps" in want:
        if args.project:
            try:
                rep["deps"] = deps.run_deps(args.project, runtimes.vulnerable_runtimes(posture),
                                            posture_ran=posture is not None)
            except Exception as e:
                fail("deps", e)
        else:
            rep["deps"] = {"projects": [], "findings": [], "runtime_escalation": None,
                           "notes": ["no --project given: dependency scan skipped (pass the directory of each "
                                     "Node / Python / Go / ... project you want assessed)"]}

    # --- logs ---------------------------------------------------------------------
    if "logs" in want and args.log:
        file_reports = []
        for path in args.log:
            try:
                file_reports.append(logs.scan_log_file(path, fmt=args.log_format, max_lines=args.max_lines))
            except OSError as e:
                rep["errors"].append(f"log scan failed for {path}: {e}")
        rep["logs"] = {
            "files": file_reports,
            "findings": [f for fr in file_reports for f in fr.get("findings", [])],
            "body_visibility_note": (
                "request headers (Content-Encoding / Transfer-Encoding / Content-Type) and bodies are only visible "
                "in LTSV / JSON-lines logs that record them; UA, text, crash and seed-in-URL rules run on any log"),
        }
    elif "logs" in want and not args.log:
        rep["logs"] = {"files": [], "findings": [], "body_visibility_note":
                       "no --log given: log scan skipped (pass an access log and/or application / journald text)"}

    rep = rp.finalize(rep)

    if args.quiet and not args.json:
        sys.stdout.write(_quiet_text(rep))
    else:
        _emit(rep, args)
    return rep["summary"]["exit_code"]


def _emit(rep: dict, args) -> None:
    if args.json:
        sys.stdout.write(rp.render_json(rep) + "\n")
    else:
        sys.stdout.write(rp.render_text(rep))


def _quiet_text(rep: dict) -> str:
    lines = []
    for f in rp.all_findings(rep):
        sev = f.get("severity", "info")
        if sev in ("warn", "critical"):
            lines.append(f"[{sev}] {f.get('rule')}: {f.get('message')}"
                         + (f" :: {f.get('evidence')}" if f.get("evidence") else ""))
    for err in rep.get("errors", []):
        lines.append(f"[error] {err}")
    return "\n".join(lines) + ("\n" if lines else "")


if __name__ == "__main__":
    sys.exit(main())
