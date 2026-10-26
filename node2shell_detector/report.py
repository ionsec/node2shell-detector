"""Reporting helpers: severity model, IP defanging, text + JSON renderers.

Finding model (same as php2shell-detector, plus `fingerprints`):
  rule         stable rule id, e.g. NODE_RUNTIME_VERSION
  severity     critical / warn / info / ok
  check        posture / binaries / deps / logs / selftest
  message      human text; states what the evidence can and cannot tell
  file, line   where it was seen (log findings: file + line)
  evidence     short excerpt - control bytes escaped, IPv4 dotted quads defanged
  basis        provenance: "VERBATIM: ..." (exact documented string/shape/version) or
               "DERIVED: ..." (threshold/inference, derivation stated)
  fingerprints brief fingerprint ids (N2S-01 .. N2S-25) the finding rests on
  related      free-form cross references (e.g. the runtimes behind an escalation)
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional

from . import __version__, CVE_ID, TOOL_NAME, BRIEF_DATE

SEV_ORDER = {"ok": 0, "info": 1, "warn": 2, "critical": 3}
SEV_ORDER["crit"] = 3

TOOL_EXIT_CLEAN = 0      # ran fine, no warn/critical finding
TOOL_EXIT_FINDINGS = 1   # at least one warn/critical finding
TOOL_EXIT_ERROR = 2      # invocation/resource problem (bad args, missing files)

SECTIONS = ("posture", "binaries", "deps", "logs", "selftest")
SECTION_ORDER = ("critical", "warn", "info", "ok")


def severity_max(*severities: str) -> str:
    best = "ok"
    for s in severities:
        if s in SEV_ORDER and SEV_ORDER[s] > SEV_ORDER.get(best, 0):
            best = s
    return best


def defang(value: str) -> str:
    """Defang dotted-quad IPs in evidence strings so copied output is inert."""
    return re.sub(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", lambda m: m.group(1).replace(".", "[.]"), value)


def clean_evidence(text: str, limit: int = 240, defang_ips: bool = True) -> str:
    """Sanitize a raw excerpt for the report: strip control bytes, defang IPs.

    `defang_ips=False` is for version-bearing evidence (a 4-part brotlicffi version
    such as 1.0.9.0 looks like a dotted quad and must not be mangled).
    """
    txt = text.replace("\r", "\\r").replace("\n", " ")
    txt = "".join(c if (c.isprintable() and c != "\x7f") else "\\x%02x" % (ord(c) & 0xFF) for c in txt)
    txt = txt[:limit]
    return (defang(txt) if defang_ips else txt).rstrip()


def finding(rule: str, severity: str, message: str, *, check: str = "",
            file: Optional[str] = None, line: Optional[int] = None,
            evidence: Optional[str] = None, basis: str = "",
            related: Optional[list] = None, fingerprints: Optional[list] = None,
            defang_ips: bool = True) -> dict:
    return {
        "rule": rule,
        "severity": severity,
        "check": check,
        "message": message,
        "file": file,
        "line": line,
        "evidence": clean_evidence(evidence, defang_ips=defang_ips) if evidence else None,
        "basis": basis,
        "fingerprints": list(fingerprints or []),
        "related": related or [],
    }


def new_report(argv) -> dict:
    rep = {
        "tool": TOOL_NAME,
        "version": __version__,
        "cve": CVE_ID,
        "brief_date": BRIEF_DATE,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "argv": list(argv),
    }
    for sec in SECTIONS:
        rep[sec] = None
    rep["errors"] = []
    rep["summary"] = {}
    return rep


def all_findings(report: dict) -> list:
    out = []
    for section in SECTIONS:
        body = report.get(section) or {}
        out.extend(body.get("findings", []))
    return out


def finalize(report: dict) -> dict:
    counts = {"critical": 0, "warn": 0, "info": 0, "ok": 0}
    for f in all_findings(report):
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    report["summary"] = {
        "counts": counts,
        "exit_code": _exit_code(report, counts),
    }
    return report


def _exit_code(report: dict, counts: dict) -> int:
    if report.get("errors"):
        return TOOL_EXIT_ERROR
    if counts["critical"] or counts["warn"]:
        return TOOL_EXIT_FINDINGS
    return TOOL_EXIT_CLEAN


def render_text(report: dict) -> str:
    out = []
    gen = report.get("generated_utc", "?")
    out.append(f"{TOOL_NAME} v{__version__} - local checks for Node2Shell ({CVE_ID})")
    out.append(f"generated {gen} | basis: IONSEC research brief (BRIEF.md, {BRIEF_DATE})")
    out.append("log hits are attempt evidence, never proof of execution; posture is point-in-time; "
               "process.versions.brotli is never used for a verdict")
    out.append("")

    if report.get("errors"):
        out.append(f"== ERRORS ({len(report['errors'])}) ==")
        for err in report["errors"]:
            out.append(f"[error]   {err}")
        out.append("")

    titles = (
        ("posture", "== HOST POSTURE =="),
        ("binaries", "== BINARY FINGERPRINTS (N2S-23 / N2S-24; local file reads only) =="),
        ("deps", "== DEPENDENCY EXPOSURE (reachability only; the runtime decides exploitability) =="),
        ("logs", "== LOG SCAN =="),
        ("selftest", "== SELF-TEST (opt-in, N2S-25; runs the public regression vector in throwaway children) =="),
    )
    renderers = {
        "posture": _render_posture, "binaries": _render_binaries, "deps": _render_deps,
        "logs": _render_logs, "selftest": _render_selftest,
    }
    for key, title in titles:
        body = report.get(key)
        if body is None:
            continue
        out.append(title)
        out.extend(renderers[key](body))
        out.append("")

    summary = report.get("summary") or {}
    counts = summary.get("counts") or report.get("counts") or {}
    ec = summary.get("exit_code")
    if ec is None:
        ec = summary.get("exit", 0)
    out.append("== SUMMARY ==")
    out.append(f"findings: critical={counts.get('critical', 0)} warn={counts.get('warn', 0)} "
               f"info={counts.get('info', 0)} ok={counts.get('ok', 0)} | exit_code={ec}")
    if report.get("errors"):
        out.append("(errors present: check invocation / file paths)")

    findings = all_findings(report)
    if findings:
        order = {"critical": 0, "warn": 1, "info": 2, "ok": 3}
        findings.sort(key=lambda f: (order.get(f.get("severity"), 9), f.get("check", ""), f.get("rule", "")))
        shown = 0
        for f in findings:
            if shown >= 200:
                rest = len(findings) - shown
                out.append(f"  ... {rest} more finding(s) truncated - see --json")
                break
            shown += 1
            out.append(_format_finding(f))
    return "\n".join(out) + "\n"


def _sev_tag(sev: str) -> str:
    return {"critical": "critical", "warn": "warning", "info": "   info", "ok": "     ok"}.get(sev, "  " + sev)


def _format_finding(f: dict) -> str:
    loc = ""
    if f.get("file"):
        loc = f"{f['file']}" + (f":{f['line']}" if f.get("line") else "")
    line = f"[{_sev_tag(f.get('severity', 'info'))}] {f.get('rule', '?'):<28} {f.get('message', '')}"
    if loc:
        line += f"  ({loc})"
    if f.get("repeat_count"):
        line += f"  [x{f['repeat_count']} in file]"
    if f.get("evidence"):
        line += f"\n            evidence: {f['evidence']}"
    if f.get("fingerprints"):
        line += f"\n            ids: {', '.join(f['fingerprints'])}"
    if f.get("basis"):
        line += f"\n            basis: {f['basis']}"
    if f.get("related"):
        line += f"\n            related: {'; '.join(str(r) for r in f['related'])}"
    return line


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str, sort_keys=False)


# ---------------------------------------------------------------------------
# section renderers (inventory rows; findings are listed once, after the summary)
# ---------------------------------------------------------------------------

def _render_posture(post: dict) -> list:
    out = []
    runtimes = post.get("runtimes", [])
    if not runtimes:
        out.append("  no node / bun / deno runtime discovered or probed")
    for rt in runtimes:
        v = rt.get("verdict") or {}
        shared = rt.get("shared")
        shared_txt = f" shared-brotli={shared}" if rt.get("kind") == "node" else ""
        ver = rt.get("version") or "?"
        out.append(f"[{_sev_tag(v.get('severity', 'info'))}] {rt.get('kind', '?')}: {rt.get('bin', '?')}"
                   f" -> {ver}{shared_txt} : {v.get('status', '?')}"
                   + (f" ({v['source']})" if v.get("source") else ""))
    py = post.get("python") or {}
    for site in py.get("sites", []):
        pk = site.get("packages") or {}
        bits = [f"{n} {pk[n]}" for n in ("brotli", "brotlicffi", "brotlipy", "aiohttp", "scrapy",
                                         "requests", "httpx", "urllib3", "pip") if n in pk]
        out.append(f"  python site: {site.get('path')} ({', '.join(bits) if bits else 'no brotli-related packages'})")
    for m in post.get("markers", []):
        out.append(f"  host marker {m.get('path')}: {'PRESENT' if m.get('present') else 'absent'}")
    for note in post.get("notes", []):
        out.append(f"  note: {note}")
    return out


def _render_binaries(body: dict) -> list:
    out = []
    st = body.get("stats") or {}
    out.append(f"  targets scanned: {st.get('scanned', 0)} | fixed={st.get('fixed', 0)} "
               f"vulnerable={st.get('vulnerable', 0)} inconclusive={st.get('inconclusive', 0)} "
               f"skipped_large={st.get('skipped_large', 0)} unreadable={st.get('unreadable', 0)}"
               f" | decode.c sources: {st.get('sources', 0)}")
    for t in body.get("targets", []):
        out.append(f"[{_sev_tag(t.get('severity', 'info'))}] {t.get('kind', '?')}: {t.get('path')} -> {t.get('status')}")
    for note in body.get("notes", []):
        out.append(f"  note: {note}")
    return out


def _render_deps(body: dict) -> list:
    out = []
    for pr in body.get("projects", []):
        out.append(f"  {pr.get('path')}: files parsed={len(pr.get('files', []))} "
                   f"packages={pr.get('packages_scanned', 0)}"
                   + (" (walk truncated)" if pr.get("truncated") else ""))
    if body.get("runtime_escalation") is not None:
        out.append("  runtime context: "
                   + ("vulnerable runtime found by posture in this run - server-side decoders escalate to critical"
                      if body.get("runtime_escalation")
                      else "no vulnerable runtime recorded in this run (posture not run, or runtimes fixed)"))
    for note in body.get("notes", []):
        out.append(f"  note: {note}")
    return out


def _render_logs(logs: dict) -> list:
    out = []
    for fs in logs.get("files", []):
        out.append(f"  {fs.get('path')}: format={fs.get('format')} lines_scanned={fs.get('lines_scanned')} "
                   f"parsed={fs.get('parsed')} findings={fs.get('finding_count')}")
    if logs.get("body_visibility_note"):
        out.append(f"  note: {logs['body_visibility_note']}")
    return out


def _render_selftest(body: dict) -> list:
    out = []
    for r in body.get("binaries", []):
        out.append(f"[{_sev_tag(r.get('severity', 'info'))}] {r.get('kind', '?')}: {r.get('bin')} -> {r.get('status')}"
                   f" (code={r.get('code')} errno={r.get('errno')} rc={r.get('returncode')})")
    for note in body.get("notes", []):
        out.append(f"  note: {note}")
    return out
