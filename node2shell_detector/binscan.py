"""BINARY FINGERPRINTS: N2S-23 (decoder error-string marker) and N2S-24 (vendored
decode.c source). Local file reads only - nothing is executed, nothing is networked.

Derivation (BRIEF s7, N2S-23, DERIVED): `BrotliDecoderErrorString()` returns the
stringified error name, so a compiled decoder carries the byte string
`_ERROR_FORMAT_BLOCK_LENGTH_1` (present before the fix) and, only after the fix,
`_ERROR_FORMAT_BLOCK_SWITCH`. The BLOCK_SWITCH error code (-17) and its name were
introduced only by the fix commits (`git log -S`: 0ed4268 / b418fa8 / da98063 /
50a9b70); Node v26.12.0 has 0 occurrences, v26.12.1 has 1. Verdicts:

  has _ERROR_FORMAT_BLOCK_SWITCH                              -> fixed decoder  (ok)
  has _ERROR_FORMAT_BLOCK_LENGTH_1, lacks ..._BLOCK_SWITCH    -> decoder without the
                                                                 CVE-2026-111497 fix (critical)
  has neither                                                 -> no Brotli error table,
                                                                 inconclusive (info)

Brotli 1.0.x builds (DERIVED, NOT in the brief; verified against the google/brotli tags
and by building v1.0.9 / v1.0.10 / v1.1.0 / v1.1.1): before v1.1.0 `BrotliDecoderErrorString`
uses `return #NAME;`, from v1.1.0 `return #PREFIX #NAME;`. A decoder built from 1.0.x
(Node 12-16's bundled 1.0.9, Debian bookworm's system libbrotlidec 1.0.9, fixed there as
1.0.9-2+deb12u1 via the 1.0.x-branch fix) carries BARE names, each its own NUL-terminated
string: a bare table is recognised by BLOCK_LENGTH_1 plus a corroborating bare name
(EXUBERANT_META_NIBBLE or CONTEXT_MAP_REPEAT) and no `_ERROR_FORMAT_` prefix; bare
BLOCK_SWITCH in it -> fixed, absent -> vulnerable. A bare BLOCK_* string without the
corroboration is ambiguous -> unknown, never "patched". A file with both table styles
(two Brotli copies) is fixed only if every table is.

Limits (also in README): this is derived evidence, not proof. A stripped error table
reads as "inconclusive", never "patched". A file that links TWO Brotli copies (an
Electron Framework carries Chromium's network decoder and Node's) can show the
marker from one copy while the other is unpatched - the tool says so for Electron
frameworks and downgrades "fixed" to info there (the brief lists Electron as
UNCONFIRMED). Behaviour beats strings: `--self-test` (N2S-25) is the stronger check.

N2S-24 (source): a vendored `decode.c` that defines DecodeBlockTypeAndLength is
vulnerable when it has `max_block_type <= 1` followed by `return BROTLI_FALSE;` and
no BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH, and fixed when it has the constant.
"""

import fnmatch
import glob
import os
import struct
from typing import Iterable, Optional

from . import fingerprints as fp
from .report import finding

CHUNK = 4 * 1024 * 1024                    # read size; markers straddling a boundary are caught by the overlap
DEFAULT_MAX_BYTES = 512 * 1024 * 1024      # per-file size cap (override: --max-binary-mb)
MIN_BINARY_BYTES = 8 * 1024                # smaller files cannot carry a decoder with an error table
MAX_SOURCE_BYTES = 4 * 1024 * 1024         # decode.c is ~120 KiB; refuse absurd files
MAX_WALK_FILES = 400_000                   # per walked root
MAX_BINARIES_SCANNED = 20_000              # per run
SKIP_DIR_NAMES = {".git", ".hg", ".svn", "__pycache__"}

LIB_GLOB_DIRS = (
    "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/local/lib",
    "/usr/lib/*-linux-gnu", "/lib/*-linux-gnu",
    "/opt/homebrew/lib", "/opt/homebrew/opt/brotli/lib", "/opt/homebrew/Cellar/brotli/*/lib",
    "/usr/local/opt/brotli/lib", "/usr/local/Cellar/brotli/*/lib",
    "/home/linuxbrew/.linuxbrew/lib",
)
LIB_PATTERNS = ("libbrotlidec*.so*", "libbrotlidec*.dylib")
PY_MODULE_PATTERNS = ("_brotli*.so", "_brotli*.so.*", "_brotli*.pyd",
                      "_brotlicffi*.so", "_brotlicffi*.so.*", "_brotlicffi*.pyd")

CPU_NAMES = {0x01000007: "x86_64", 0x0100000C: "arm64", 7: "i386", 12: "arm", 0x0200000C: "arm64_32"}

_EXPLICIT_KINDS = ("node", "bun", "lib", "python-module")


# ---------------------------------------------------------------------------
# magic detection
# ---------------------------------------------------------------------------

def exec_kind(path: str) -> Optional[str]:
    """'elf' / 'macho' / 'macho-fat' / 'pe' by magic bytes, else None."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
            if len(head) < 4:
                return None
            if head[:4] == b"\x7fELF":
                return "elf"
            if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                return "macho"
            if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
                # Mach-O universal ("fat") headers share the CAFEBABE magic with Java class
                # files; a fat header's next u32 is the (small) architecture count.
                if len(head) >= 8 and 1 <= struct.unpack(">I", head[4:8])[0] <= 30:
                    return "macho-fat"
                return None
            if head[:2] == b"MZ" and len(head) >= 0x40:
                pe_off = struct.unpack("<I", head[0x3C:0x40])[0]
                if pe_off + 4 <= len(head):
                    return "pe" if head[pe_off:pe_off + 4] == b"PE\x00\x00" else None
                fh.seek(pe_off)
                return "pe" if fh.read(4) == b"PE\x00\x00" else None
    except OSError:
        return None
    return None


def fat_slices(path: str) -> list:
    """[(label, offset, size)] for a Mach-O universal binary; [] if it cannot be parsed."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            if len(head) < 8:
                return []
            magic, n = struct.unpack(">II", head)
            is64 = magic == 0xCAFEBABF
            entry = 32 if is64 else 20
            raw = fh.read(entry * n)
    except OSError:
        return []
    out = []
    for i in range(n):
        rec = raw[i * entry:(i + 1) * entry]
        if len(rec) < entry:
            break
        if is64:
            cpu, _sub, off, size, _al, _res = struct.unpack(">IIQQII", rec)
        else:
            cpu, _sub, off, size, _al = struct.unpack(">IIIII", rec)
        out.append((CPU_NAMES.get(cpu, f"cpu{cpu:#x}"), off, size))
    return out


# ---------------------------------------------------------------------------
# marker scan (N2S-23)
# ---------------------------------------------------------------------------

# (flag, bytes). The first two are the 1.1+ prefixed names (BRIEF s7, N2S-23). The rest are the DERIVED
# Brotli 1.0.x-style bare names - whole NUL-delimited C strings (see fingerprints.LEGACY_NAMES_NOTE).
_MARKERS = (
    ("has_switch", fp.BIN_MARKER_SWITCH),
    ("has_length1", fp.BIN_MARKER_LENGTH1),
    ("legacy_switch", fp.BIN_LEGACY_SWITCH),
    ("legacy_length1", fp.BIN_LEGACY_LENGTH1),
    ("legacy_nibble", fp.BIN_LEGACY_CORROBORATION[0]),
    ("legacy_ctxmap", fp.BIN_LEGACY_CORROBORATION[1]),
)
_OVERLAP = max(len(b) for _name, b in _MARKERS) - 1
_FLAG_KEYS = ("has_switch", "has_length1", "legacy_switch", "legacy_length1", "legacy_corroborated")


def scan_markers(path: str, max_bytes: int = DEFAULT_MAX_BYTES, start: int = 0,
                 length: Optional[int] = None) -> dict:
    """Stream-scan `path` (or one slice) for the error-table markers (1.1+ prefixed names and the
    1.0.x-style bare names).

    Chunks overlap by len(longest marker) - 1 bytes so a marker straddling a chunk
    boundary is still found. Files (or slices) above `max_bytes` are skipped.
    """
    res = {"path": path, "size": None, "has_switch": False, "has_length1": False,
           "legacy_switch": False, "legacy_length1": False, "legacy_corroborated": False,
           "skipped_large": False, "error": None}
    try:
        size = os.path.getsize(path)
    except OSError as e:
        res["error"] = str(e)
        return res
    res["size"] = size
    span = max(0, size - start) if length is None else max(0, min(length, size - start))
    if span > max_bytes:
        res["skipped_large"] = True
        return res
    found = {name: False for name, _pat in _MARKERS}
    carry = b""
    remaining = span
    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            while remaining > 0:
                chunk = fh.read(min(CHUNK, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                buf = carry + chunk
                for name, pat in _MARKERS:
                    if not found[name] and pat in buf:
                        found[name] = True
                if all(found.values()):
                    break
                carry = buf[-_OVERLAP:] if _OVERLAP else b""
    except OSError as e:
        res["error"] = str(e)
    res["has_switch"], res["has_length1"] = found["has_switch"], found["has_length1"]
    res["legacy_switch"], res["legacy_length1"] = found["legacy_switch"], found["legacy_length1"]
    res["legacy_corroborated"] = found["legacy_nibble"] or found["legacy_ctxmap"]
    return res


def classify_markers(has_switch: bool, has_length1: bool, legacy_switch: bool = False,
                     legacy_length1: bool = False, legacy_corroborated: bool = False) -> dict:
    """N2S-23 verdict from the marker flags.

    A file can carry a 1.1+ table (prefixed names), a 1.0.x-style table (bare names, DERIVED), or - when it links
    two Brotli copies - both. Fixed only if every table found has its BLOCK_SWITCH; any table without it makes the
    file vulnerable. A bare BLOCK_LENGTH_1 / BLOCK_SWITCH without the corroborating 1.0.x table names is ambiguous:
    it is never read as a table, so it can never read as 'patched'."""
    tables = []                    # (label, fixed)
    if has_switch or has_length1:
        tables.append(("1.1+", bool(has_switch)))
    legacy_table = bool(legacy_length1 and legacy_corroborated)
    if legacy_table:
        tables.append(("1.0.x", bool(legacy_switch)))
    ambiguous = bool((legacy_length1 or legacy_switch) and not legacy_table)
    names = [t[0] for t in tables]
    legacy_blurb = ("the Brotli 1.0.x-style error table (bare names - DERIVED: 1.0.x builds omit the _ERROR_FORMAT_ "
                    "prefix)")
    if not tables:
        detail = ("no Brotli error table in this file (neither marker present) - inconclusive: the decoder "
                  "may be linked dynamically, written in another language, or stripped; this is never read "
                  "as 'patched'")
        if ambiguous:
            detail += ("; a bare BLOCK_LENGTH_1 / BLOCK_SWITCH string was found without the corroborating 1.0.x "
                       "table names (EXUBERANT_META_NIBBLE / CONTEXT_MAP_REPEAT), so it is ambiguous and not read "
                       "as an error table - unknown / verify")
        return {"status": "inconclusive", "severity": "info", "tables": names, "detail": detail}
    if len(tables) == 1:
        label, fixed = tables[0]
        if label == "1.1+":
            if fixed:
                detail = ("fixed decoder: the Brotli error table has _ERROR_FORMAT_BLOCK_SWITCH"
                          + (" (and _ERROR_FORMAT_BLOCK_LENGTH_1)" if has_length1 else "")
                          + " - that code was introduced only by the CVE-2026-111497 fix commits")
            else:
                detail = ("decoder without the CVE-2026-111497 fix: the Brotli error table has "
                          "_ERROR_FORMAT_BLOCK_LENGTH_1 but not _ERROR_FORMAT_BLOCK_SWITCH")
        elif fixed:
            detail = (f"fixed decoder: {legacy_blurb} has BLOCK_SWITCH (and BLOCK_LENGTH_1) - that code was "
                      "introduced only by the CVE-2026-111497 fix (v1.0.10 on the 1.0.x branch)")
        else:
            detail = (f"decoder without the CVE-2026-111497 fix: {legacy_blurb} has BLOCK_LENGTH_1 but not "
                      "BLOCK_SWITCH")
    else:
        parts = ", ".join(f"{label} table {'fixed' if fixed else 'WITHOUT the fix'}" for label, fixed in tables)
        if all(fixed for _l, fixed in tables):
            detail = f"fixed decoder: this file links two Brotli copies and both are fixed ({parts})"
        else:
            detail = ("decoder without the CVE-2026-111497 fix: this file links two Brotli copies and at least one "
                      f"is unfixed ({parts})")
    if all(fixed for _l, fixed in tables):
        return {"status": "fixed", "severity": "ok", "tables": names, "detail": detail}
    return {"status": "vulnerable", "severity": "critical", "tables": names, "detail": detail}


def scan_binary(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    """Scan one binary; Mach-O universal files are scanned slice by slice and the worst
    slice decides (so a fixed arm64 slice cannot hide a vulnerable x86_64 one)."""
    kind = exec_kind(path)
    rec = {"path": path, "realpath": _real(path), "exec_kind": kind, "size": None, "has_switch": False,
           "has_length1": False, "legacy_switch": False, "legacy_length1": False, "legacy_corroborated": False,
           "tables": [], "slices": [], "status": "unreadable", "severity": "info", "detail": ""}
    if kind == "macho-fat":
        slices = fat_slices(path)
        if slices:
            worst = None
            skipped = 0
            for label, off, size in slices:
                r = scan_markers(path, max_bytes=max_bytes, start=off, length=size)
                rec["size"] = r["size"]
                if r["error"]:
                    continue
                if r["skipped_large"]:
                    skipped += 1
                    continue
                flags = {k: r[k] for k in _FLAG_KEYS}
                cls = classify_markers(**flags)
                rec["slices"].append(dict({"arch": label, "status": cls["status"]}, **flags))
                if worst is None or _rank(cls["status"]) > _rank(worst["status"]):
                    worst = dict(cls, **flags)
            if worst is None:
                rec.update(status="skipped_large" if skipped else "unreadable", severity="info",
                           detail="every Mach-O slice was skipped (size cap) or unreadable")
                return rec
            rec.update(status=worst["status"], severity=worst["severity"], detail=worst["detail"],
                       tables=worst["tables"], **{k: worst[k] for k in _FLAG_KEYS})
            if len(rec["slices"]) > 1:
                rec["detail"] += " [universal binary, slices: " + ", ".join(
                    f"{s['arch']}={s['status']}" for s in rec["slices"]) + "]"
            return rec
    r = scan_markers(path, max_bytes=max_bytes)
    rec["size"] = r["size"]
    if r["error"]:
        rec.update(status="unreadable", severity="info", detail=r["error"])
        return rec
    if r["skipped_large"]:
        rec.update(status="skipped_large", severity="info",
                   detail=f"{r['size']} bytes exceeds the {max_bytes}-byte scan cap (--max-binary-mb) - not scanned")
        return rec
    flags = {k: r[k] for k in _FLAG_KEYS}
    cls = classify_markers(**flags)
    rec.update(status=cls["status"], severity=cls["severity"], detail=cls["detail"], tables=cls["tables"], **flags)
    return rec


def _rank(status: str) -> int:
    return {"vulnerable": 3, "inconclusive": 2, "fixed": 1}.get(status, 0)


def _real(path: str) -> str:
    try:
        return os.path.realpath(path)
    except OSError:
        return path


# ---------------------------------------------------------------------------
# source check (N2S-24)
# ---------------------------------------------------------------------------

def check_decode_c(path: str) -> Optional[dict]:
    """N2S-24 verdict for a `decode.c`; None when it does not define DecodeBlockTypeAndLength."""
    try:
        if os.path.getsize(path) > MAX_SOURCE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    if fp.SRC_FUNCTION not in text:
        return None
    if fp.SRC_CONSTANT in text:
        return {"status": "fixed", "severity": "ok",
                "detail": f"vendored decode.c defines {fp.SRC_FUNCTION} and contains {fp.SRC_CONSTANT}: fixed source"}
    if fp.SRC_VULNERABLE_RE.search(text):
        return {"status": "vulnerable", "severity": "warn",
                "detail": f"vulnerable vendored source: {fp.SRC_FUNCTION} has `max_block_type <= 1` followed by "
                          f"`return BROTLI_FALSE;` and the file has no {fp.SRC_CONSTANT}. A source file only says "
                          "what WOULD be compiled - the compiled artefact decides (run the binary check on what you "
                          "ship / --self-test)"}
    return {"status": "unrecognised", "severity": "info",
            "detail": f"decode.c defines {fp.SRC_FUNCTION} but matches neither the vulnerable shape nor the fix - "
                      "modified source: unknown / verify"}


# ---------------------------------------------------------------------------
# target discovery
# ---------------------------------------------------------------------------

def find_library_targets(extra_dirs: Iterable[str] = ()) -> list:
    """libbrotlidec*.so* / *.dylib in the standard library directories (deduped by realpath)."""
    seen, out = set(), []
    for d in list(LIB_GLOB_DIRS) + list(extra_dirs):
        for dirpath in sorted(glob.glob(d)):
            if not os.path.isdir(dirpath):
                continue
            for pat in LIB_PATTERNS:
                for p in sorted(glob.glob(os.path.join(dirpath, pat))):
                    real = _real(p)
                    if real in seen or not os.path.isfile(real):
                        continue
                    seen.add(real)
                    out.append(p)
    return out


def find_python_module_targets(site_dirs: Iterable[str], max_depth: int = 3) -> list:
    """_brotli*.so / _brotlicffi*.so / .pyd under the scanned site-packages directories."""
    seen, out = set(), []
    for site in site_dirs:
        if not os.path.isdir(site):
            continue
        base_depth = site.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(site):
            if dirpath.rstrip(os.sep).count(os.sep) - base_depth >= max_depth:
                dirnames[:] = []
            for fn in filenames:
                if any(fnmatch.fnmatch(fn, pat) for pat in PY_MODULE_PATTERNS):
                    p = os.path.join(dirpath, fn)
                    real = _real(p)
                    if real not in seen and os.path.isfile(real):
                        seen.add(real)
                        out.append(p)
    return out


def walk_roots(roots: Iterable[str], want_binaries: bool, want_addons: bool, want_sources: bool,
               max_files: int = MAX_WALK_FILES):
    """Bounded walk. Returns (binary_candidates, addon_candidates, decode_c_files, truncated)."""
    binaries, addons, sources, truncated = [], [], [], False
    for root in roots:
        count = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for fn in filenames:
                count += 1
                if count > max_files:
                    truncated = True
                    break
                p = os.path.join(dirpath, fn)
                if want_sources and fn == "decode.c":
                    sources.append(p)
                if os.path.islink(p):
                    continue
                if want_addons and fn.endswith(".node"):
                    addons.append(p)
                elif want_binaries:
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if st.st_size >= MIN_BINARY_BYTES and exec_kind(p) is not None:
                        binaries.append(p)
            if truncated:
                break
    return binaries, addons, sources, truncated


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def run_binaries(node_bins: Iterable[str] = (), bun_bins: Iterable[str] = (),
                 lib_extra: Iterable[str] = (), python_sites: Iterable[str] = (),
                 scan_dirs: Iterable[str] = (), project_dirs: Iterable[str] = (),
                 max_bytes: int = DEFAULT_MAX_BYTES, lib_dirs_extra: Iterable[str] = (),
                 discover_libs: bool = True) -> dict:
    """The BINARY FINGERPRINTS check (N2S-23 for binaries, N2S-24 for decode.c sources).

    `discover_libs=False` (--no-discover) skips the standard library directories."""
    targets = []     # (path, kind)
    seen = set()

    def add(path, kind):
        real = _real(path)
        if real in seen or not os.path.isfile(real):
            return
        seen.add(real)
        targets.append((path, kind))

    for p in node_bins:
        add(p, "node")
    for p in bun_bins:
        add(p, "bun")
    if discover_libs:
        for p in find_library_targets(lib_dirs_extra):
            add(p, "lib")
    for p in lib_extra:
        add(p, "lib")
    for p in find_python_module_targets(python_sites):
        add(p, "python-module")

    scan_dirs = [d for d in scan_dirs if os.path.isdir(d)]
    project_dirs = [d for d in project_dirs if os.path.isdir(d)]
    bins, _a, srcs_a, trunc_a = walk_roots(scan_dirs, True, False, True)
    _b, addons, srcs_b, trunc_b = walk_roots(project_dirs, False, True, True)
    for p in bins:
        add(p, "electron" if "Electron Framework" in p else "scan-dir")
    for p in addons:
        if exec_kind(p) is not None:
            add(p, "addon")

    stats = {"scanned": 0, "fixed": 0, "vulnerable": 0, "inconclusive": 0, "skipped_large": 0,
             "unreadable": 0, "sources": 0, "walk_truncated": bool(trunc_a or trunc_b), "capped": False}
    rows, findings, notes = [], [], []
    quiet_inconclusive = 0

    for path, kind in targets:
        if stats["scanned"] >= MAX_BINARIES_SCANNED:
            stats["capped"] = True
            break
        rec = scan_binary(path, max_bytes=max_bytes)
        rec["kind"] = kind
        if "Electron Framework" in path:
            rec["kind"] = kind = "electron"
        stats["scanned"] += 1
        st = rec["status"]
        if st in ("fixed", "vulnerable", "inconclusive", "skipped_large", "unreadable"):
            stats[st] += 1
        rows.append({k: rec[k] for k in ("path", "kind", "status", "severity", "exec_kind", "size")}
                    | {"slices": rec.get("slices", []), "tables": rec.get("tables", [])})
        f = _finding_for(rec, kind, max_bytes)
        if f is None:
            if st == "inconclusive":
                quiet_inconclusive += 1
            continue
        findings.append(f)

    srcs = []
    for p in srcs_a + srcs_b:
        real = _real(p)
        if real not in {_real(s) for s in srcs}:
            srcs.append(p)
    for p in srcs:
        res = check_decode_c(p)
        if res is None:
            continue
        stats["sources"] += 1
        rule = {"vulnerable": "SRC_DECODER_VULNERABLE", "fixed": "SRC_DECODER_FIXED"}.get(
            res["status"], "SRC_DECODER_UNRECOGNISED")
        findings.append(finding(
            rule, res["severity"], f"{p}: {res['detail']}", check="binaries", file=p,
            evidence=f"{fp.SRC_FUNCTION} found; constant {fp.SRC_CONSTANT}: "
                     f"{'present' if res['status'] == 'fixed' else 'absent'}",
            basis=fp.basis("N2S-24", note="vulnerable = `max_block_type <= 1` then `return BROTLI_FALSE;` without "
                                          "the constant; the constant was introduced by the fix commits"),
            fingerprints=["N2S-24"], defang_ips=False))
        rows.append({"path": p, "kind": "source", "status": res["status"], "severity": res["severity"],
                     "exec_kind": None, "size": None, "slices": []})

    if quiet_inconclusive:
        notes.append(f"{quiet_inconclusive} walked file(s) (--scan-dir / project native addons) contained no Brotli "
                     "error table: inconclusive, not listed individually (a stripped table is never read as patched)")
    if stats["walk_truncated"]:
        notes.append(f"walk truncated at {MAX_WALK_FILES} files per root - narrow --scan-dir")
    if stats["capped"]:
        notes.append(f"stopped after {MAX_BINARIES_SCANNED} scanned binaries - narrow --scan-dir")
    if not targets and not srcs:
        notes.append("no scan targets found (no node/bun binary, libbrotlidec, Python extension, --scan-dir file "
                     "or decode.c) - nothing to fingerprint on this host")
    return {"targets": rows, "stats": stats, "findings": findings, "notes": notes}


def _finding_for(rec: dict, kind: str, max_bytes: int) -> Optional[dict]:
    path, st = rec["path"], rec["status"]
    yn = lambda b: "yes" if b else "no"          # noqa: E731
    evidence = (f"{os.path.basename(path)}: _ERROR_FORMAT_BLOCK_LENGTH_1={yn(rec['has_length1'])} "
                f"_ERROR_FORMAT_BLOCK_SWITCH={yn(rec['has_switch'])}; 1.0.x bare names: "
                f"BLOCK_LENGTH_1={yn(rec['legacy_length1'])} BLOCK_SWITCH={yn(rec['legacy_switch'])} "
                f"corroborated={yn(rec['legacy_corroborated'])}; size={rec['size']}")
    what = {"node": "Node.js binary", "bun": "Bun binary", "lib": "system libbrotlidec library",
            "python-module": "Python Brotli extension module", "electron": "Electron Framework binary",
            "addon": "native addon", "scan-dir": "binary"}.get(kind, "binary")
    basis_note = ("derived: BLOCK_SWITCH (-17) and its name were introduced only by the fix commits "
                  "(0ed4268 / b418fa8 / da98063 / 50a9b70); Node v26.12.0 has 0 occurrences, v26.12.1 has 1")
    if "1.0.x" in rec.get("tables", []) or rec.get("legacy_length1") or rec.get("legacy_switch"):
        basis_note += ". " + fp.LEGACY_NAMES_NOTE
    common = dict(check="binaries", file=path, evidence=evidence, fingerprints=["N2S-23"],
                  basis=fp.basis("N2S-23", note=basis_note), defang_ips=False)
    if st == "vulnerable":
        extra = ""
        if kind == "lib":
            extra = " Update the distro/Homebrew brotli package: every shared-brotli consumer (curl, Node built with --shared-brotli, ...) uses this file."
        elif kind == "python-module":
            extra = " Upgrade Brotli to 1.2.1 / brotlicffi to 1.2.1.0 (BRIEF s5.4)."
        elif kind in ("node", "bun"):
            extra = " Upgrade the runtime to a fixed release (Node 22.23.4 / 24.22.1 / 26.12.1, Bun 1.4.4)."
        return finding("BIN_DECODER_VULNERABLE", "critical",
                       f"{path} [{what}]: {rec['detail']}.{extra}", **common)
    if st == "fixed":
        sev, msg = "ok", f"{path} [{what}]: {rec['detail']}"
        if kind == "electron":
            sev = "info"
            msg += (". Electron frameworks can link two Brotli copies (Chromium's network decoder and Node's); the "
                    "marker cannot say which copy carries it, and the brief lists Electron as UNCONFIRMED - "
                    "unknown / verify per app (Node version inside the Electron release, or --self-test of the app's "
                    "runtime)")
        return finding("BIN_DECODER_FIXED", sev, msg, **common)
    if st == "inconclusive":
        if kind in _EXPLICIT_KINDS or kind == "electron":
            return finding("BIN_DECODER_INCONCLUSIVE", "info", f"{path} [{what}]: {rec['detail']}", **common)
        return None
    if st == "skipped_large":
        return finding("BIN_SKIPPED_LARGE", "info", f"{path} [{what}]: {rec['detail']}",
                       check="binaries", file=path, basis=fp.basis("N2S-23"), fingerprints=["N2S-23"],
                       defang_ips=False)
    if st == "unreadable" and kind in _EXPLICIT_KINDS:
        return finding("BIN_UNREADABLE", "info", f"{path} [{what}]: could not be read ({rec['detail']}) - unknown / verify",
                       check="binaries", file=path, basis=fp.basis("N2S-23"), fingerprints=["N2S-23"],
                       defang_ips=False)
    return None
