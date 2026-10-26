#!/usr/bin/env python3
"""Regenerate the static example corpora and fixtures under examples/ (used for smoke runs).

Everything is produced by node2shell_detector.corpora / fingerprints - the SAME builders the
pytest suite uses - so the shipped examples and the tests cannot drift:

  logs/                 benign + exploit-shaped log corpora, built ONLY from catalogue values
                        (BRIEF s7, N2S-01 .. N2S-25); client IPs are RFC 5737 documentation
                        addresses
  fixture_node*.sh      clearly-labelled STUB runtimes (never a real node / bun) - safe targets
  fixture_bun.sh        for --self-test: they only print canned JSON
  fixture_bins/         synthetic ELF-magic files carrying (or lacking) the Brotli error-table
                        marker strings - NOT real decoders
  fixture_vendor*/      synthetic stand-ins for a vendored decode.c (NOT the upstream file)
  fixture_project/      a tiny project: lockfile, Dockerfile, requirements, go.mod
  fixture_site-packages/  dist-info metadata for Brotli 1.1.0 + aiohttp 3.9.5 (no code)

Usage: python3 examples/make_examples.py
"""

import json
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL_ROOT = HERE.parent
sys.path.insert(0, str(TOOL_ROOT))

from node2shell_detector import corpora, fingerprints as fp  # noqa: E402

LOGS = HERE / "logs"
STUB_HEADER = ("#!/bin/sh\n"
               "# TEST FIXTURE - synthetic runtime STUB for the node2shell-detector smoke runs; it is not a "
               "real node/bun and only prints canned output. Do not deploy.\n")
SWITCH_OUT = '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_SWITCH","errno":-17,"name":"Error"}'
LENGTH1_OUT = '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_LENGTH_1","errno":-9,"name":"Error"}'


def write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def stub_node(version: str, behaviour_out: str) -> str:
    probe = '{"versions":{"node":"%s","brotli":"1.2.0"},"shared":false}' % version
    return (STUB_HEADER + 'case "$1" in\n'
            f'  --version|-v) echo "v{version}";;\n'
            f"  -p) echo '{probe}';;\n"
            f"  *.js) echo '{behaviour_out}';;\n"
            "  *) : ;;\n"
            "esac\n")


def stub_bun(version: str, behaviour_out: str) -> str:
    return (STUB_HEADER + 'case "$1" in\n'
            f'  --version|-v) echo "{version}";;\n'
            f"  *.js) echo '{behaviour_out}';;\n"
            "  *) : ;;\n"
            "esac\n")


def elf(path: Path, markers=(), size: int = 16 * 1024) -> None:
    """Synthetic ELF-magic file: NUL-filled, marker strings NUL-delimited inside (an error-table stand-in)."""
    body = bytearray(size)
    body[:8] = b"\x7fELF\x02\x01\x01\x00"
    off = 256
    for m in markers:
        body[off:off + len(m)] = m
        off += len(m) + 16
    path.write_bytes(bytes(body))


VULNERABLE_C = """\
/* SYNTHETIC stand-in for c/dec/decode.c (examples only) - NOT the upstream file.
   Shape of the pre-fix block-switch check (N2S-24). */
static BROTLI_INLINE BROTLI_BOOL DecodeBlockTypeAndLength(
    int safe, BrotliDecoderState* s, int tree_type) {
  brotli_reg_t max_block_type = s->num_block_types[tree_type];
  if (max_block_type <= 1) {
    return BROTLI_FALSE;
  }
  return BROTLI_TRUE;
}
"""
FIXED_C = """\
/* SYNTHETIC stand-in for c/dec/decode.c (examples only) - NOT the upstream file.
   Shape of the fixed block-switch check (N2S-24). */
static BROTLI_INLINE BrotliDecoderErrorCode DecodeBlockTypeAndLength(
    int safe, BrotliDecoderState* s, int tree_type) {
  brotli_reg_t max_block_type = s->num_block_types[tree_type];
  if (max_block_type <= 1) {
    return BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
  }
  return BROTLI_DECODER_SUCCESS;
}
"""


def logs() -> None:
    LOGS.mkdir(exist_ok=True)
    files = {
        "access_benign.log": corpora.benign_access_combined() + corpora.benign_access_ltsv()
        + corpora.benign_access_json(),
        "access_exploit.log": corpora.exploit_access_lines(),
        "app_benign.log": corpora.benign_app_log(),
        "app_exploit.log": corpora.exploit_app_lines(),
    }
    for name, lines in files.items():
        (LOGS / name).write_text("\n".join(lines) + "\n")
        print(f"wrote {LOGS / name} ({len(lines)} lines)")


def runtimes() -> None:
    write_exec(HERE / "fixture_node.sh", stub_node("24.22.0", LENGTH1_OUT))        # vulnerable by version + behaviour
    write_exec(HERE / "fixture_node_fixed.sh", stub_node("24.22.1", SWITCH_OUT))    # fixed by version + behaviour
    write_exec(HERE / "fixture_bun.sh", stub_bun("1.4.3", LENGTH1_OUT))
    print("wrote fixture_node.sh (v24.22.0, vulnerable), fixture_node_fixed.sh (v24.22.1, fixed), "
          "fixture_bun.sh (1.4.3, vulnerable)")


def binaries() -> None:
    d = HERE / "fixture_bins"
    d.mkdir(exist_ok=True)
    elf(d / "decoder_fixed.bin", (fp.BIN_MARKER_SWITCH, fp.BIN_MARKER_LENGTH1))
    elf(d / "decoder_vulnerable.bin", (fp.BIN_MARKER_LENGTH1,))
    # Brotli 1.0.x-style tables (bare names, DERIVED - see README): bare BLOCK_SWITCH present = fixed
    legacy = (b"BLOCK_LENGTH_1", b"EXUBERANT_META_NIBBLE", b"CONTEXT_MAP_REPEAT")
    elf(d / "decoder_legacy_vulnerable.bin", legacy)
    elf(d / "decoder_legacy_fixed.bin", legacy + (b"BLOCK_SWITCH",))
    elf(d / "no_table.bin", ())
    (HERE / "fixture_vendor" / "c" / "dec").mkdir(parents=True, exist_ok=True)
    (HERE / "fixture_vendor_fixed" / "c" / "dec").mkdir(parents=True, exist_ok=True)
    (HERE / "fixture_vendor" / "c" / "dec" / "decode.c").write_text(VULNERABLE_C)
    (HERE / "fixture_vendor_fixed" / "c" / "dec" / "decode.c").write_text(FIXED_C)
    print("wrote fixture_bins/ (5 synthetic marker files), fixture_vendor*/ (synthetic decode.c stand-ins)")


def project() -> None:
    d = HERE / "fixture_project"
    d.mkdir(exist_ok=True)
    (d / "package.json").write_text(json.dumps({
        "name": "fixture-app", "version": "1.0.0", "private": True,
        "dependencies": {"express": "^5.1.0", "axios": "^1.7.2"}}, indent=2) + "\n")
    packages = {"": {"name": "fixture-app", "version": "1.0.0"}}
    for name, ver in (("express", "5.1.0"), ("body-parser", "2.2.0"), ("axios", "1.7.2"), ("next", "16.4.3")):
        packages[f"node_modules/{name}"] = {"version": ver}
    (d / "package-lock.json").write_text(json.dumps(
        {"name": "fixture-app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": packages},
        indent=2) + "\n")
    (d / "Dockerfile").write_text("# fixture: a pinned vulnerable tag, a floating tag and a Bun image\n"
                                  "FROM node:24.22.0-alpine AS build\n"
                                  "FROM node:24 AS runtime\n"
                                  "FROM oven/bun:1.4.3\n")
    (d / "requirements.txt").write_text("Brotli==1.1.0\naiohttp==3.9.5\n")
    (d / "go.mod").write_text("module example.org/fixture\n\ngo 1.22\n\n"
                              "require github.com/andybalholm/brotli v1.1.1\n")
    site = HERE / "fixture_site-packages"
    site.mkdir(exist_ok=True)
    for name, ver in (("Brotli", "1.1.0"), ("aiohttp", "3.9.5"), ("requests", "2.32.0")):
        di = site / f"{name}-{ver}.dist-info"
        di.mkdir(exist_ok=True)
        (di / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\n\n")
    print("wrote fixture_project/ and fixture_site-packages/")


def main() -> None:
    logs()
    runtimes()
    binaries()
    project()


if __name__ == "__main__":
    main()
