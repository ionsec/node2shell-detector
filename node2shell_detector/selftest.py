"""SELF-TEST (N2S-25) - opt-in only (`--self-test`).

For each node / bun binary this spawns a THROWAWAY CHILD with a timeout that feeds the
public Node.js regression vector (N2S-01, 22 bytes) to the runtime's own decoder:

    zlib.brotliDecompressSync(Buffer.from('<22-byte vector>', 'hex'))

and records the error the decoder raises (BRIEF s2, s7):

  ERR__ERROR_FORMAT_BLOCK_SWITCH / errno -17  -> ok       fixed decoder
  ERR__ERROR_FORMAT_BLOCK_LENGTH_1 / errno -9
  (or any other ERR__ERROR_* decoder error)   -> critical vulnerable decoder behaviour
  crash / signal (SIGSEGV, SIGBUS, abort ...) -> critical vulnerable decoder behaviour
  no error / timeout / a non-decoder error    -> warn     inconclusive: unknown / verify

WHY IT IS OPT-IN: on an UNPATCHED runtime this executes the public regression vector,
which exercises the bug inside the throwaway child process. The vector is the one in
Node's own test suite (`test/parallel/test-zlib-invalid-input.js`, commit b5f41529df) and
is not an exploit - there is no payload, no shellcode, no network - but it does drive an
out-of-bounds write on a vulnerable decoder, and a crash of the child is the expected
result there. Nothing here ever touches a long-running process of yours, opens a socket,
or leaves a file behind (the script lives in a temp dir that is removed afterwards).

Behaviour beats strings and versions: this is the ground truth for a runtime that is
vendor-patched without a version bump, or that links a patched shared library. Deno is
not tested (Rust decoder, status unresolved: BRIEF s5.3).
"""

import json
import os
import signal
import subprocess
import tempfile
from typing import Optional

from . import fingerprints as fp
from . import runtimes
from .report import finding

TIMEOUT = 10  # seconds per child

# The child script: a vector, a try/catch, one JSON line. The vector is data (N2S-01).
SELFTEST_JS = (
    "const zlib = require('zlib');\n"
    "const vector = Buffer.from('@@VECTOR@@', 'hex');\n"
    "let out;\n"
    "try { zlib.brotliDecompressSync(vector); out = { ok: true }; }\n"
    "catch (e) { out = { ok: false, code: e && e.code, errno: e && e.errno, name: e && e.name }; }\n"
    "process.stdout.write(JSON.stringify(out) + '\\n');\n"
).replace("@@VECTOR@@", fp.REGRESSION_VECTOR_HEX)

CRASH_EXIT_CODES = {132: "SIGILL", 134: "SIGABRT", 135: "SIGBUS", 138: "SIGBUS", 139: "SIGSEGV"}  # 128 + signal (shell-wrapped)


def _last_json(text: str):
    for line in reversed([l for l in (text or "").splitlines() if l.strip()]):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def classify(returncode: Optional[int], stdout: str, timed_out: bool, stderr: str = "") -> dict:
    """Map a child's outcome to a self-test verdict (pure; unit-tested)."""
    base = {"code": None, "errno": None, "returncode": returncode, "signal": None}
    if timed_out:
        return dict(base, status="inconclusive", severity="warn",
                    detail="the child timed out and was killed - unknown / verify (a hang is not evidence either way)")
    if returncode is not None and returncode < 0:
        sig = -returncode
        try:
            name = signal.Signals(sig).name
        except ValueError:
            name = f"signal {sig}"
        return dict(base, status="crash", severity="critical", signal=name,
                    detail=f"the child CRASHED with {name} while decoding the regression vector - vulnerable decoder "
                           "behaviour (a patched decoder returns BLOCK_SWITCH / -17 instead)")
    if returncode in CRASH_EXIT_CODES:
        return dict(base, status="crash", severity="critical", signal=CRASH_EXIT_CODES[returncode],
                    detail=f"the child exited with {returncode} ({CRASH_EXIT_CODES[returncode]}) while decoding the "
                           "regression vector - vulnerable decoder behaviour")
    data = _last_json(stdout)
    if not isinstance(data, dict):
        return dict(base, status="inconclusive", severity="warn",
                    detail=f"the child produced no parseable result (exit {returncode}) - unknown / verify"
                           + (f"; stderr: {stderr.strip()[:120]}" if stderr and stderr.strip() else ""))
    code, errno = data.get("code"), data.get("errno")
    base.update(code=code, errno=errno)
    if data.get("ok") is True:
        return dict(base, status="inconclusive", severity="warn",
                    detail="the decoder raised NO error for the invalid 22-byte vector - unexpected, the brief does "
                           "not cover it: unknown / verify")
    if code == fp.ERR_BLOCK_SWITCH or errno == fp.ERRNO_BLOCK_SWITCH:
        return dict(base, status="fixed", severity="ok",
                    detail="the invalid block switch was rejected with BLOCK_SWITCH (-17): the decoder this runtime "
                           "actually uses is patched")
    if (isinstance(code, str) and code.startswith("ERR__ERROR_")) or errno == fp.ERRNO_BLOCK_LENGTH_1:
        return dict(base, status="vulnerable", severity="critical",
                    detail=f"the decoder raised {code or 'a decoder error'} (errno {errno}) instead of BLOCK_SWITCH "
                           "(-17): unpatched decoders return BLOCK_LENGTH_1 (-9) for this vector - vulnerable decoder "
                           "behaviour")
    return dict(base, status="inconclusive", severity="warn",
                detail=f"the runtime raised a non-decoder error (code={code!r}, name={data.get('name')!r}) - Brotli "
                       "may be unsupported or the probe failed: unknown / verify")


def run_one(path: str, kind: str, timeout: int = TIMEOUT) -> dict:
    """Run the self-test script under one runtime in a throwaway child."""
    rec = {"bin": path, "kind": kind}
    with tempfile.TemporaryDirectory(prefix="n2s-selftest-") as tmp:
        script = os.path.join(tmp, "selftest.js")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(SELFTEST_JS)
        timed_out = False
        # the child runs in its own temp dir, so a relative binary path must be made absolute first
        exe = os.path.abspath(path) if os.sep in path else path
        try:
            proc = subprocess.Popen([exe, script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    stdin=subprocess.DEVNULL, cwd=tmp, env=runtimes.clean_env(),
                                    text=True, errors="replace", start_new_session=True)
        except OSError as e:
            return dict(rec, status="inconclusive", severity="warn", code=None, errno=None, returncode=None,
                        signal=None, detail=f"could not execute the runtime ({e.__class__.__name__}: {e}) - "
                                            "unknown / verify")
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
            out, err = proc.communicate()
    res = classify(proc.returncode, out, timed_out, err)
    res.update(rec)
    return res


def run_selftest(binaries: list, timeout: int = TIMEOUT) -> dict:
    """binaries = [{'kind': 'node'|'bun'|'deno', 'path'|'bin': ...}]; deno is skipped (Rust decoder)."""
    results, findings, notes = [], [], []
    for b in binaries:
        kind = b.get("kind")
        path = b.get("path") or b.get("bin")
        if kind not in ("node", "bun"):
            if kind == "deno":
                notes.append(f"{path}: not tested - Deno uses Rust decoders and its status is unresolved (BRIEF s5.3)")
            continue
        res = run_one(path, kind, timeout=timeout)
        results.append(res)
        st = res["status"]
        rule = {"fixed": "SELFTEST_FIXED", "vulnerable": "SELFTEST_VULNERABLE", "crash": "SELFTEST_CRASH"}.get(
            st, "SELFTEST_INCONCLUSIVE")
        findings.append(finding(
            rule, res["severity"], f"{path} [{kind}]: {res['detail']} (N2S-25; behavioural result, authoritative for "
                                   "this binary)",
            check="selftest", file=path,
            evidence=f"code={res.get('code')} errno={res.get('errno')} returncode={res.get('returncode')} "
                     f"signal={res.get('signal')}",
            basis=fp.basis("N2S-25", note="the public regression vector (N2S-01) fed to the runtime's own decoder in "
                                          "a throwaway child; -17 BLOCK_SWITCH = fixed, -9 BLOCK_LENGTH_1 or a crash "
                                          "= vulnerable"),
            fingerprints=["N2S-25", "N2S-01"], defang_ips=False))
    if not results:
        notes.append("no node / bun binary to test")
    notes.append("each runtime ran the public regression vector once, in a throwaway child with a "
                 f"{timeout}s timeout; on an unpatched runtime that exercises the bug inside the child only")
    return {"binaries": results, "findings": findings, "notes": notes}
