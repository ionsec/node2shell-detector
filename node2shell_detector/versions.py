"""Fixed-version tables (with source notes) and version comparators.

Every constant is copied from the IONSEC research brief (BRIEF.md, 2026-10-24). The
source section is stated beside each table. Nothing here is guessed: where the brief
leaves a case open the evaluators return a status starting with "unknown" and the
reporting layer says "unknown / verify".

IMPORTANT (BRIEF s3): `process.versions.brotli` is computed from BrotliEncoderVersion()
and the fix commit does not touch version.h - the value does NOT change when the fix
lands. It cannot tell patched from unpatched and is never used for a verdict here.
Use the Node version for official builds, the distro package for shared-brotli builds,
the binary fingerprint (N2S-23) or the behavioural self-test (N2S-25).
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Node.js (BRIEF s1 release post + s3 version matrix)
# ---------------------------------------------------------------------------

# First fixed release per line (Node.js "Wednesday, October 21, 2026 Security Releases").
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
# Last vulnerable release per line, as listed in BRIEF s3 (context only).
NODE_LAST_VULNERABLE = {
    26: "26.12.0", 24: "24.22.0", 22: "22.23.3",
    25: "25.9.0", 23: "23.11.1", 20: "20.20.2", 18: "18.20.8",
}
# End-of-life lines with NO fixed release (BRIEF s3). "Node 25/23/21/20/<=19": every EOL
# line has the vulnerable early return (checked v12.22.12 -> v25.9.0).
NODE_EOL_NO_FIX_LINES = (25, 23, 21, 20)
NODE_EOL_MAX_MAJOR = 19            # everything <= 19 is end-of-life (22 is the oldest line with a fix)
NODE_NEWEST_LINE_IN_BRIEF = 26
NODE_OLDEST_CHECKED = (12, 22, 12)  # oldest release the brief verified as vulnerable
NODE_LINE_NAMES = {22: "Jod", 24: "Krypton", 20: "Iron"}   # BRIEF s3 table labels (docker aliases)

# ---------------------------------------------------------------------------
# Bun (BRIEF s3, s5.3)
# ---------------------------------------------------------------------------

BUN_FIXED = (1, 4, 4)               # 1.4.4 (2026-10-22) pins brotli v1.2.1; every earlier release affected

# ---------------------------------------------------------------------------
# Upstream google/brotli (BRIEF s1)
# ---------------------------------------------------------------------------

BROTLI_FIRST_AFFECTED = (1, 0, 3)   # vulnerable check introduced by 35e69fc, first shipped in v1.0.3
BROTLI_FIXED_RELEASES = ((1, 0, 10), (1, 1, 1), (1, 2, 1))   # v1.0.10, v1.1.1, v1.2.1 (2026-10-21)

# ---------------------------------------------------------------------------
# Distros (BRIEF s3)
# ---------------------------------------------------------------------------

DEBIAN_FIXED = {                    # DLA-4855-1 (bookworm), DSA-6582-1 (trixie)
    "bookworm": "1.0.9-2+deb12u1",
    "trixie": "1.1.0-2+deb13u1",
}
DEBIAN_UNFIXED_AT_BRIEF = "1.2.0-4"  # forky/sid: unfixed at fetch time
DEBIAN_CHANGELOG = "/usr/share/doc/libbrotli1/changelog.Debian.gz"
ALPINE_FIXED = {"default (edge, 3.23, 3.24)": "1.2.1-r0", "3.21": "1.1.1-r0"}
HOMEBREW_FIXED = (1, 2, 1)

# ---------------------------------------------------------------------------
# Other ecosystems (BRIEF s5.4)
# ---------------------------------------------------------------------------

PYPI_BROTLI_FIXED = (1, 2, 1)             # fixed 1.2.1 only (no PyPI backport line); GHSA range >=1.0.3,<1.2.1
PYPI_BROTLI_FIRST = (1, 0, 3)
PYPI_BROTLICFFI_FIRST = (1, 0, 9, 0)      # affected 1.0.9.0-1.0.9.2, 1.1.0.0, 1.2.0.0-1.2.0.2
PYPI_BROTLICFFI_FIXED = (1, 2, 1, 0)
GO_BROTLI_FIXED = (1, 2, 7)               # andybalholm/brotli: pre-fix logic v1.0.0-v1.2.6, fixed v1.2.7
GEM_BROTLI_FIXED = (0, 9, 1)              # affected 0.4.0-0.9.0, fixed 0.9.1 / 0.9.2
GEM_BROTLI_FIRST_LISTED = (0, 4, 0)
BROTLI4J_FIXED = (1, 24, 0)               # affected 1.21.0-1.23.0 (vendored 1.2.0), fixed 1.24.0
BROTLI4J_FIRST_LISTED = (1, 21, 0)


# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------

def parse_dotted(text: str) -> Optional[tuple]:
    """First dotted-numeric version in `text` as an int tuple, or None."""
    m = re.search(r"(\d+(?:\.\d+)*)", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def cmp_tuple(a: tuple, b: tuple) -> int:
    """Compare version tuples of different lengths (missing parts count as 0)."""
    n = max(len(a), len(b))
    pa = tuple(a) + (0,) * (n - len(a))
    pb = tuple(b) + (0,) * (n - len(b))
    return (pa > pb) - (pa < pb)


def fmt(t: tuple) -> str:
    return ".".join(str(x) for x in t)


def brotli_upstream_status(vt: tuple) -> str:
    """Status of an upstream google/brotli version (BRIEF s1): 'not_affected_old',
    'vulnerable' or 'fixed'."""
    if cmp_tuple(vt, BROTLI_FIRST_AFFECTED) < 0:
        return "not_affected_old"
    f101, f111, f121 = BROTLI_FIXED_RELEASES
    if cmp_tuple(vt, f121) >= 0:
        return "fixed"
    if cmp_tuple(vt, f111) >= 0 and cmp_tuple(vt, (1, 2, 0)) < 0:
        return "fixed"
    if cmp_tuple(vt, f101) >= 0 and cmp_tuple(vt, (1, 1, 0)) < 0:
        return "fixed"
    return "vulnerable"


# ---------------------------------------------------------------------------
# Node.js
# ---------------------------------------------------------------------------

_RE_NODE_VER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(.*)$")


def parse_node_version(text: str) -> Optional[tuple]:
    """'v24.22.0' -> (24, 22, 0, '') ; 'v24.22.1-nightly2026...' -> (24, 22, 1, '-nightly...')."""
    first = (text or "").strip().splitlines()[0].strip() if (text or "").strip() else ""
    m = _RE_NODE_VER.match(first)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4).strip()


def _fixed_list() -> str:
    return "22.23.4+, 24.22.1+ or 26.12.1+"


def eval_node_version(text: str) -> dict:
    """Version-table verdict for an official-build Node.js (BRIEF s3).

    Not valid for shared-brotli builds (the caller moves the verdict to the system
    library) and never consults process.versions.brotli.
    """
    pv = parse_node_version(text)
    if pv is None:
        return {"status": "unparseable", "severity": "warn", "line": None, "fixed_in": None,
                "detail": f"could not parse a Node.js version from {text!r} - unknown / verify "
                          "(run --check binaries or --self-test)."}
    major, minor, patch, suffix = pv
    ver = f"{major}.{minor}.{patch}{suffix}"
    base = (major, minor, patch)

    if major in NODE_FIXED:
        fixed = NODE_FIXED[major]
        fixed_s = fmt(fixed)
        if suffix:
            return {"status": "unknown_prerelease", "severity": "warn", "line": major, "fixed_in": fixed_s,
                    "detail": f"{ver} is a pre-release / nightly / custom build on the {major}.x line (fixed in "
                              f"{fixed_s}); a version comparison cannot say whether the fix commits are in - "
                              "unknown / verify with --check binaries (N2S-23) or --self-test (N2S-25)."}
        if base >= fixed:
            return {"status": "patched", "severity": "ok", "line": major, "fixed_in": fixed_s,
                    "detail": f"{ver} >= {fixed_s} - the {major}.x line fix (CVE-2026-111497, security release "
                              "2026-10-21). Restart every Node process: a patched binary on disk is not loaded "
                              "into running processes."}
        return {"status": "vulnerable_unpatched", "severity": "critical", "line": major, "fixed_in": fixed_s,
                "detail": f"{ver} < {fixed_s} on the {major}.x line - a fixed release exists: upgrade to "
                          f"{fixed_s} or later, then restart every process (BRIEF s3). Any app that passes "
                          "attacker-influenced Brotli data to node:zlib (request bodies, fetch responses) is "
                          "reachable."}

    if major in NODE_EOL_NO_FIX_LINES or major <= NODE_EOL_MAX_MAJOR:
        last = NODE_LAST_VULNERABLE.get(major)
        extra = ""
        if last:
            extra = f" (last release the brief lists as vulnerable: {last})"
        if base < NODE_OLDEST_CHECKED:
            extra += (" The brief verified lines back to v12.22.12 only; it does not say whether a build this "
                      "old bundles a Brotli in the affected range - treated as affected by the EOL rule, verify.")
        return {"status": "eol_no_fix", "severity": "critical", "line": major, "fixed_in": None,
                "detail": f"{ver}: the {major}.x line is end-of-life and NO fixed release exists for it "
                          f"(BRIEF s3: every EOL line has the vulnerable early return){extra}. The only remedy is "
                          f"to move to a supported line ({_fixed_list()}), or to a vendor build that backports "
                          "the fix (verify it with --check binaries / --self-test)."}

    return {"status": "unknown_future_branch", "severity": "info", "line": major, "fixed_in": None,
            "detail": f"{ver}: the {major}.x line is newer than the lines in the brief's fixed-version table "
                      f"(newest listed: {NODE_NEWEST_LINE_IN_BRIEF}.x). A release cut after 2026-10-21 should "
                      "contain the fix, but the brief cannot confirm it - unknown / verify."}


# ---------------------------------------------------------------------------
# Bun
# ---------------------------------------------------------------------------

def eval_bun_version(text: str) -> dict:
    """Bun < 1.4.4 -> critical (every earlier release affected); >= 1.4.4 -> ok (BRIEF s3/s5.3)."""
    first = (text or "").strip().splitlines()[0].strip() if (text or "").strip() else ""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(.*)$", first)
    if not m:
        return {"status": "unparseable", "severity": "warn", "fixed_in": fmt(BUN_FIXED),
                "detail": f"could not parse a Bun version from {text!r} - unknown / verify."}
    base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    suffix = m.group(4).strip()
    ver = ".".join(str(x) for x in base) + suffix
    fixed_s = fmt(BUN_FIXED)
    if suffix.startswith("-"):
        return {"status": "unknown_prerelease", "severity": "warn", "fixed_in": fixed_s,
                "detail": f"{ver} is a canary / pre-release build (fixed in {fixed_s}); a version comparison "
                          "cannot say whether the fix is in - unknown / verify with --self-test (N2S-25)."}
    if base >= BUN_FIXED:
        return {"status": "patched", "severity": "ok", "fixed_in": fixed_s,
                "detail": f"{ver} >= {fixed_s} - pins brotli v1.2.1 (BRIEF s3). Restart every Bun process."}
    return {"status": "vulnerable_unpatched", "severity": "critical", "fixed_in": fixed_s,
            "detail": f"{ver} < {fixed_s}: every Bun release before 1.4.4 is affected (BRIEF s3). Bun reaches the "
                      "decoder by default - fetch() br responses, node:zlib, DecompressionStream - with no opt-out "
                      "found (BRIEF s5.3). Upgrade to 1.4.4 or later."}


# ---------------------------------------------------------------------------
# Deno (BRIEF s5.3) - Rust decoders, status unresolved
# ---------------------------------------------------------------------------

DENO_NOTE = ("Deno uses Rust decoders (brotli 6.0.0 + brotli-decompressor 4.0.1 in the 2.9.8 Cargo.lock), not the C "
             "library. Whether the Rust port carries the same logic flaw is unresolved, NOT cleared: the pre-fix "
             "early-return logic is still present in brotli-decompressor 6.1.1 (src/decode.rs); Rust's default "
             "bounds-checked accessors should turn it into a panic / DoS rather than memory corruption (inference; "
             "the 'unsafe' feature uses unchecked accessors). No Deno release notes mention it - unknown / verify "
             "with your Deno vendor.")


def eval_deno_version(text: str) -> dict:
    return {"status": "unresolved", "severity": "info", "detail": DENO_NOTE}


# ---------------------------------------------------------------------------
# PyPI Brotli / brotlicffi (BRIEF s1 GHSA, s5.4)
# ---------------------------------------------------------------------------

def eval_pypi_brotli(version: str) -> dict:
    vt = parse_dotted(version)
    if vt is None:
        return {"status": "unparseable", "severity": "warn",
                "detail": f"cannot parse Brotli version {version!r} - unknown / verify."}
    fixed = fmt(PYPI_BROTLI_FIXED)
    if cmp_tuple(vt, PYPI_BROTLI_FIXED) >= 0:
        return {"status": "patched", "severity": "ok", "detail": f"Brotli {version} >= {fixed} (fixed 2026-10-22)."}
    if cmp_tuple(vt, PYPI_BROTLI_FIRST) < 0:
        return {"status": "unknown_outside_range", "severity": "info",
                "detail": f"Brotli {version} is below the CNA/GHSA affected range (>=1.0.3,<1.2.1) but PYSEC-2026-4322 "
                          f"lists 0.5.2/0.6.0/1.0.1 - the advisories conflict; unknown / verify. Upgrade to {fixed}+."}
    return {"status": "vulnerable_unpatched", "severity": "warn",
            "detail": f"Brotli {version} < {fixed} bundles the vulnerable C decoder (GHSA-9v8h-qqgm-4m35; PyPI has "
                      f"no backport line - {fixed} is the only fixed release) unless it was built with "
                      "USE_SYSTEM_BROTLI=1, in which case the system library decides (run --check binaries)."}


def eval_pypi_brotlicffi(version: str) -> dict:
    vt = parse_dotted(version)
    if vt is None:
        return {"status": "unparseable", "severity": "warn",
                "detail": f"cannot parse brotlicffi version {version!r} - unknown / verify."}
    fixed = fmt(PYPI_BROTLICFFI_FIXED)
    if cmp_tuple(vt, PYPI_BROTLICFFI_FIXED) >= 0:
        return {"status": "patched", "severity": "ok", "detail": f"brotlicffi {version} >= {fixed}."}
    if cmp_tuple(vt, PYPI_BROTLICFFI_FIRST) < 0:
        return {"status": "not_affected", "severity": "ok",
                "detail": f"brotlicffi {version} predates 1.0.9.0: not affected per BRIEF s5.4 "
                          "(0.8.0 pins a pre-1.0.3 brotli commit)."}
    return {"status": "vulnerable_unpatched", "severity": "warn",
            "detail": f"brotlicffi {version} is in 1.0.9.0-1.2.0.2 (fixed {fixed}): it bundles the vulnerable C "
                      "decoder statically unless built with USE_SHARED_BROTLI (then the system library decides)."}


def eval_pypi_brotlipy(version: str) -> dict:
    vt = parse_dotted(version) or ()
    if vt and cmp_tuple(vt, (0, 7, 0)) <= 0:
        return {"status": "not_affected", "severity": "ok",
                "detail": f"brotlipy {version}: not affected per BRIEF s5.4 (0.7.0 pins a pre-1.0.3 commit)."}
    return {"status": "unknown_outside_range", "severity": "info",
            "detail": f"brotlipy {version}: not covered by the brief - unknown / verify."}


# ---------------------------------------------------------------------------
# Go / RubyGems / Maven (BRIEF s5.4)
# ---------------------------------------------------------------------------

_RE_GO_PSEUDO = re.compile(r"\d{14}-[0-9a-f]{12}")


def eval_go_brotli(version: str) -> dict:
    """github.com/andybalholm/brotli: pre-fix logic v1.0.0-v1.2.6, fixed v1.2.7."""
    if _RE_GO_PSEUDO.search(version or ""):
        return {"status": "unknown_pseudo_version", "severity": "warn",
                "detail": f"{version} is a Go pseudo-version (an untagged commit); whether it includes the v1.2.7 "
                          "fix cannot be told from the version - unknown / verify the commit."}
    vt = parse_dotted(version)
    if vt is None:
        return {"status": "unparseable", "severity": "warn", "detail": f"cannot parse {version!r} - unknown / verify."}
    if cmp_tuple(vt, GO_BROTLI_FIXED) >= 0:
        return {"status": "patched", "severity": "ok", "detail": f"{version} >= v1.2.7 (fixed 2026-10-23)."}
    return {"status": "vulnerable_unpatched", "severity": "warn",
            "detail": f"{version} < v1.2.7: pure-Go translation with the pre-fix logic (v1.0.0-v1.2.6); fixed in "
                      "v1.2.7 (BRIEF s5.4). Library - reachable where the app decodes untrusted Brotli."}


def eval_gem_brotli(version: str) -> dict:
    vt = parse_dotted(version)
    if vt is None:
        return {"status": "unparseable", "severity": "warn", "detail": f"cannot parse {version!r} - unknown / verify."}
    if cmp_tuple(vt, GEM_BROTLI_FIXED) >= 0:
        return {"status": "patched", "severity": "ok", "detail": f"brotli gem {version} >= 0.9.1 (fixed 2026-10-24)."}
    if cmp_tuple(vt, GEM_BROTLI_FIRST_LISTED) < 0:
        return {"status": "unknown_outside_range", "severity": "info",
                "detail": f"brotli gem {version} predates the 0.4.0-0.9.0 range the brief lists (vendored 1.0.9 / "
                          "1.1.0 / 1.2.0) - unknown / verify. Upgrade to 0.9.1+."}
    return {"status": "vulnerable_unpatched", "severity": "warn",
            "detail": f"brotli gem {version} is in 0.4.0-0.9.0 (vendored brotli 1.0.9 / 1.1.0 / 1.2.0); fixed in "
                      "0.9.1 / 0.9.2 (BRIEF s5.4). Net::HTTP does not decode br, so exposure needs explicit "
                      "Brotli.inflate calls."}


def eval_brotli4j(version: str) -> dict:
    vt = parse_dotted(version)
    if vt is None:
        return {"status": "unparseable", "severity": "warn", "detail": f"cannot parse {version!r} - unknown / verify."}
    if cmp_tuple(vt, BROTLI4J_FIXED) >= 0:
        return {"status": "patched", "severity": "ok", "detail": f"brotli4j {version} >= 1.24.0."}
    note = ""
    if cmp_tuple(vt, BROTLI4J_FIRST_LISTED) < 0:
        note = (" The brief lists 1.21.0-1.23.0 (vendored 1.2.0); earlier releases bundle older brotli (any "
                "release >= 1.0.3 is in range) but were not individually verified.")
    return {"status": "vulnerable_unpatched", "severity": "warn",
            "detail": f"brotli4j {version} < 1.24.0 (fixed in 1.24.0, BRIEF s5.4).{note}"}


# ---------------------------------------------------------------------------
# Docker image tags (BRIEF s3: official images moved on 2026-10-21; rebuild, don't restart)
# ---------------------------------------------------------------------------

_REBUILD_NOTE = ("a floating tag resolves when the image is BUILT: images must be rebuilt (not just restarted) to "
                 "pick up the fixed runtime - docker-node moved the 22 / 24 / 26 images to 22.23.4 / 24.22.1 / "
                 "26.12.1 on 2026-10-21 (BRIEF s3).")


def _tag_head(tag: str) -> str:
    return (tag or "").strip().lower().split("-")[0]


def _numeric_parts(head: str) -> Optional[tuple]:
    if re.fullmatch(r"\d+(\.\d+){0,2}", head):
        return tuple(int(x) for x in head.split("."))
    return None


def eval_node_tag(tag: str) -> dict:
    """Classify the tag of a `node` base image (FROM node:<tag>)."""
    head = _tag_head(tag)
    if not head:
        return {"status": "floating", "severity": "info", "detail": f"untagged `node` image (latest): {_REBUILD_NOTE}"}
    if "$" in tag:
        return {"status": "unresolved_variable", "severity": "info",
                "detail": f"tag {tag!r} contains an unresolved build variable - unknown / verify the resolved version."}
    alias_major = {"jod": 22, "krypton": 24, "iron": 20}.get(head)
    parts = _numeric_parts(head)
    if parts is None and alias_major is None:
        return {"status": "floating", "severity": "info",
                "detail": f"tag {tag!r} floats (no pinned version): {_REBUILD_NOTE}"}
    if parts is None:
        parts = (alias_major,)
    if len(parts) == 3:
        res = eval_node_version("v%d.%d.%d" % parts)
        res["detail"] = f"pinned image node:{tag}: " + res["detail"]
        return res
    major = parts[0]
    if major in NODE_FIXED:
        fixed = NODE_FIXED[major]
        if len(parts) == 2:
            c = cmp_tuple(parts, fixed[:2])
            if c < 0:
                return {"status": "vulnerable_unpatched", "severity": "critical", "line": major,
                        "fixed_in": fmt(fixed),
                        "detail": f"node:{tag} pins the {parts[0]}.{parts[1]} minor line, whose last patch is below "
                                  f"{fmt(fixed)} - every build of that tag is vulnerable (fixed in {fmt(fixed)})."}
            if c > 0:
                return {"status": "unknown_future_branch", "severity": "info",
                        "detail": f"node:{tag}: newer than the brief's fixed-version table - unknown / verify."}
        return {"status": "floating_rebuild", "severity": "info", "line": major, "fixed_in": fmt(fixed),
                "detail": f"node:{tag} floats within the {major}.x line (fixed in {fmt(fixed)}): {_REBUILD_NOTE}"}
    if major in NODE_EOL_NO_FIX_LINES or major <= NODE_EOL_MAX_MAJOR:
        return {"status": "eol_no_fix", "severity": "critical", "line": major, "fixed_in": None,
                "detail": f"node:{tag}: the {major}.x line is end-of-life with NO fixed release (BRIEF s3) - move "
                          f"to a supported line ({_fixed_list()})."}
    return {"status": "unknown_future_branch", "severity": "info",
            "detail": f"node:{tag}: newer than the brief's fixed-version table - unknown / verify."}


def eval_bun_tag(tag: str) -> dict:
    """Classify the tag of an `oven/bun` base image."""
    head = _tag_head(tag)
    if not head or "$" in (tag or ""):
        return {"status": "floating", "severity": "info",
                "detail": f"oven/bun tag {tag!r} floats or is an unresolved variable: {_REBUILD_NOTE}"}
    parts = _numeric_parts(head)
    if parts is None:
        return {"status": "floating", "severity": "info",
                "detail": f"oven/bun:{tag} floats (no pinned version): {_REBUILD_NOTE}"}
    if len(parts) == 3:
        res = eval_bun_version("%d.%d.%d" % parts)
        res["detail"] = f"pinned image oven/bun:{tag}: " + res["detail"]
        return res
    if len(parts) == 2 and cmp_tuple(parts, BUN_FIXED[:2]) < 0:
        return {"status": "vulnerable_unpatched", "severity": "critical", "fixed_in": fmt(BUN_FIXED),
                "detail": f"oven/bun:{tag} pins the {parts[0]}.{parts[1]} minor line, entirely below {fmt(BUN_FIXED)} "
                          "- every build of that tag is vulnerable (every earlier Bun release is affected)."}
    return {"status": "floating_rebuild", "severity": "info", "fixed_in": fmt(BUN_FIXED),
            "detail": f"oven/bun:{tag} floats (fixed in {fmt(BUN_FIXED)}): {_REBUILD_NOTE}"}


# ---------------------------------------------------------------------------
# dpkg version comparator (Debian Policy 5.6.12): epochs, '~', digits vs non-digits
# ---------------------------------------------------------------------------

def _dpkg_order(c: Optional[str]) -> int:
    if c is None or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < la else None)
            bc = _dpkg_order(b[j] if j < lb else None)
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def dpkg_parse(version: str) -> tuple:
    """'1:2.0-3+b1' -> (1, '2.0', '3+b1')."""
    v = version.strip()
    epoch = 0
    if ":" in v:
        e, _, rest = v.partition(":")
        if e.isdigit():
            epoch, v = int(e), rest
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """Compare two Debian version strings: -1 (a<b), 0 (a==b), 1 (a>b)."""
    ea, ua, ra = dpkg_parse(a)
    eb, ub, rb = dpkg_parse(b)
    if ea != eb:
        return -1 if ea < eb else 1
    for x, y in ((ua, ub), (ra, rb)):
        r = _dpkg_verrevcmp(x, y)
        if r:
            return -1 if r < 0 else 1
    return 0


def debian_version_status(version: str) -> dict:
    """Status of a Debian/Ubuntu libbrotli1 package version when the changelog check
    did not find CVE-2026-111497 (BRIEF s3: bookworm 1.0.9-2+deb12u1, trixie 1.1.0-2+deb13u1;
    forky/sid 1.2.0-4 unfixed at fetch time)."""
    _epoch, upstream, _rev = dpkg_parse(version)
    ut = parse_dotted(upstream)
    if ut is None:
        return {"status": "unknown", "severity": "warn",
                "detail": f"cannot parse libbrotli1 version {version!r} - unknown / verify."}
    st = brotli_upstream_status(ut)
    if st == "not_affected_old":
        return {"status": "not_affected", "severity": "ok",
                "detail": f"libbrotli1 {version}: upstream {fmt(ut)} predates the vulnerable check (1.0.3)."}
    if st == "fixed":
        return {"status": "patched", "severity": "ok",
                "detail": f"libbrotli1 {version}: upstream {fmt(ut)} is a fixed google/brotli release "
                          "(1.0.10 / 1.1.1 / 1.2.1+)."}
    series = ut[:3]
    for series_t, suite in (((1, 0, 9), "bookworm"), ((1, 1, 0), "trixie")):
        if series == series_t:
            threshold = DEBIAN_FIXED[suite]
            if dpkg_compare(version, threshold) >= 0:
                return {"status": "patched", "severity": "ok",
                        "detail": f"libbrotli1 {version} >= {threshold} (Debian {suite} fix)."}
            return {"status": "vulnerable_unpatched", "severity": "critical",
                    "detail": f"libbrotli1 {version} < {threshold} (Debian {suite} fixed version; DLA-4855-1 / "
                              "DSA-6582-1) and its changelog does not mention CVE-2026-111497. On Ubuntu the "
                              "Debian thresholds do not apply: Ubuntu listed brotli as 'Needs evaluation' with no "
                              "fixed package as of 2026-10-23 (BRIEF s3) - check USNs."}
    if series == (1, 2, 0):
        if dpkg_compare(version, DEBIAN_UNFIXED_AT_BRIEF) <= 0:
            return {"status": "vulnerable_unpatched", "severity": "critical",
                    "detail": f"libbrotli1 {version}: forky/sid 1.2.0-4 was unfixed at fetch time (BRIEF s3) and the "
                              "changelog does not mention CVE-2026-111497."}
        return {"status": "unknown", "severity": "warn",
                "detail": f"libbrotli1 {version} is newer than the unfixed 1.2.0-4 but the changelog does not "
                          "mention CVE-2026-111497 - unknown / verify (zgrep the changelog, check the tracker)."}
    return {"status": "vulnerable_unpatched", "severity": "critical",
            "detail": f"libbrotli1 {version}: upstream {fmt(ut)} is in the affected range (1.0.3 - 1.2.0, outside the "
                      "fixed Debian series) and the changelog does not mention CVE-2026-111497."}
