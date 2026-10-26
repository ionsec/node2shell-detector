"""Shared test helpers: stub runtimes (shell scripts), synthetic binaries, isolation.

Every runtime used by the tests is a clearly-labelled STUB script - never a real Node or
Bun. The self-test is only ever run against these stubs.
"""

import os
import stat
import struct
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parents[1]

# make the package importable no matter where pytest is invoked from
sys.path.insert(0, str(TOOL_ROOT))

M_SWITCH = b"_ERROR_FORMAT_BLOCK_SWITCH"
M_LENGTH1 = b"_ERROR_FORMAT_BLOCK_LENGTH_1"

STUB_HEADER = ("#!/bin/sh\n"
               "# TEST FIXTURE (node2shell-detector tests): emulates a runtime binary; do not deploy.\n")

# what the stub prints when the self-test script (*.js) is run under it
SELFTEST_BEHAVIOURS = {
    "fixed": "echo '{\"ok\":false,\"code\":\"ERR__ERROR_FORMAT_BLOCK_SWITCH\",\"errno\":-17,\"name\":\"Error\"}'",
    "vulnerable": "echo '{\"ok\":false,\"code\":\"ERR__ERROR_FORMAT_BLOCK_LENGTH_1\",\"errno\":-9,\"name\":\"Error\"}'",
    "crash": "kill -SEGV $$",
    "exit139": "exit 139",
    "timeout": "sleep 30",
    "noerror": "echo '{\"ok\":true}'",
    "typeerror": "echo '{\"ok\":false,\"name\":\"TypeError\"}'",
    "garbage": "echo hello",
}

_counter = {"n": 0}


def _unique_dir(tmp_path, stem):
    _counter["n"] += 1
    d = Path(tmp_path) / f"{stem}_{_counter['n']}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_exec(path, text):
    path = Path(path)
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def make_stub_node(tmp_path, version="24.22.0", brotli="1.2.0", shared=False, behaviour="vulnerable",
                   probe="json", version_out=None, name="node"):
    """A stub `node`: --version, -p <one-liner> (canned JSON), and a self-test behaviour for *.js."""
    d = _unique_dir(tmp_path, "node")
    ver_line = version_out if version_out is not None else f"v{version}"
    vers = '{"node":"%s"' % version + (',"brotli":"%s"' % brotli if brotli else "") + "}"
    if probe == "json":
        shared_part = "" if shared is None else (',"shared":%s' % ("true" if shared else "false"))
        probe_cmd = "echo '%s'" % ('{"versions":%s%s}' % (vers, shared_part))
    elif probe == "empty":
        probe_cmd = "echo '{}'"
    elif probe == "fail":
        probe_cmd = "exit 1"
    else:
        probe_cmd = "echo not-json"
    script = (STUB_HEADER + 'case "$1" in\n'
              f'  --version|-v) echo "{ver_line}";;\n'
              f"  -p) {probe_cmd};;\n"
              f"  *.js) {SELFTEST_BEHAVIOURS[behaviour]};;\n"
              "  *) : ;;\n"
              "esac\n")
    return write_exec(d / name, script)


def make_stub_bun(tmp_path, version="1.4.3", behaviour="vulnerable", name="bun"):
    d = _unique_dir(tmp_path, "bun")
    script = (STUB_HEADER + 'case "$1" in\n'
              f'  --version|-v) echo "{version}";;\n'
              f"  *.js) {SELFTEST_BEHAVIOURS[behaviour]};;\n"
              "  *) : ;;\n"
              "esac\n")
    return write_exec(d / name, script)


def make_stub_deno(tmp_path, version="2.9.8", name="deno"):
    d = _unique_dir(tmp_path, "deno")
    script = (STUB_HEADER + 'case "$1" in\n'
              f'  --version) echo "deno {version} (stable, release, x86_64-unknown-linux-gnu)"\n'
              '             echo "v8 13.0.245.12-rusty"\n'
              '             echo "typescript 5.8.3";;\n'
              "  *) : ;;\n"
              "esac\n")
    return write_exec(d / name, script)


# ---------------------------------------------------------------- synthetic binaries ----

def _place(body: bytearray, markers, start=256):
    off = start
    for m in markers:
        body[off:off + len(m)] = m
        off += len(m) + 16


def make_elf(path, markers=(), size=16 * 1024, magic=b"\x7fELF\x02\x01\x01\x00"):
    """A synthetic ELF-magic file with NUL-delimited marker strings (an error-table stand-in)."""
    body = bytearray(size)
    body[:len(magic)] = magic
    _place(body, markers)
    Path(path).write_bytes(bytes(body))
    return str(path)


def make_fat(path, slices):
    """A synthetic Mach-O universal binary. slices = [(cputype, markers), ...]."""
    n = len(slices)
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", n)
    entries, blobs, offset = b"", [], 4096
    for cpu, markers in slices:
        blob = bytearray(8192)
        blob[:4] = b"\xcf\xfa\xed\xfe"
        _place(blob, markers)
        entries += struct.pack(">IIIII", cpu, 0, offset, len(blob), 12)
        blobs.append((offset, bytes(blob)))
        offset += (len(blob) // 4096 + 1) * 4096
    data = bytearray(offset)
    data[:len(header) + len(entries)] = header + entries
    for off, blob in blobs:
        data[off:off + len(blob)] = blob
    Path(path).write_bytes(bytes(data))
    return str(path)


def write_lines(tmp_path, name, lines):
    p = Path(tmp_path) / name
    p.write_text("\n".join(lines) + "\n")
    return p


def posture_of(node=(), bun=(), deno=(), **kw):
    """run_posture over explicit stubs only (no discovery, no running-interpreter sites, no host markers)."""
    from node2shell_detector import runtimes
    entries = runtimes.discover(node_bins=list(node), bun_bins=list(bun), deno_bins=list(deno), explicit_only=True)
    kw.setdefault("include_running_python", False)
    kw.setdefault("host_marker_paths", [])
    return runtimes.run_posture(node_bins=list(node), bun_bins=list(bun), deno_bins=list(deno),
                                discovered=entries, **kw)
