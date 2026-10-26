"""BINARY FINGERPRINTS (N2S-23) and vendored decode.c source check (N2S-24) on synthetic files."""

import os
import struct
from pathlib import Path

import pytest

from conftest import M_LENGTH1, M_SWITCH, make_elf, make_fat, write_exec, write_lines
from node2shell_detector import binscan, fingerprints as fp

FINGERPRINT_NOTE = "BLOCK_SWITCH"


def by_rule(res, rule):
    return [f for f in res["findings"] if f["rule"] == rule]


# ---------------------------------------------------------------- verdict table ----

def test_classify_markers_table():
    assert binscan.classify_markers(True, True)["status"] == "fixed"
    assert binscan.classify_markers(True, False)["status"] == "fixed"       # BLOCK_SWITCH alone = fixed
    assert binscan.classify_markers(False, True)["status"] == "vulnerable"
    inc = binscan.classify_markers(False, False)
    assert inc["status"] == "inconclusive" and inc["severity"] == "info"
    assert "never read as 'patched'" in inc["detail"]
    assert binscan.classify_markers(False, True)["severity"] == "critical"
    assert binscan.classify_markers(True, True)["severity"] == "ok"


def test_marker_constants_match_the_brief():
    assert fp.BIN_MARKER_SWITCH == b"_ERROR_FORMAT_BLOCK_SWITCH"
    assert fp.BIN_MARKER_LENGTH1 == b"_ERROR_FORMAT_BLOCK_LENGTH_1"
    assert fp.ERR_BLOCK_SWITCH == "ERR_" + fp.BIN_MARKER_SWITCH.decode()     # Node builds "ERR_" + BrotliDecoderErrorString()


@pytest.mark.parametrize("markers,status", [
    ((M_SWITCH, M_LENGTH1), "fixed"),
    ((M_SWITCH,), "fixed"),
    ((M_LENGTH1,), "vulnerable"),
    ((), "inconclusive"),
])
def test_scan_binary_verdicts(tmp_path, markers, status):
    p = make_elf(tmp_path / "decoder.bin", markers)
    rec = binscan.scan_binary(p)
    assert rec["status"] == status and rec["exec_kind"] == "elf"
    assert rec["has_switch"] == (M_SWITCH in markers) and rec["has_length1"] == (M_LENGTH1 in markers)


@pytest.mark.parametrize("offset", list(range(0, 40)))
def test_marker_straddling_a_chunk_boundary_is_found(tmp_path, monkeypatch, offset):
    monkeypatch.setattr(binscan, "CHUNK", 16)
    data = bytearray(200)
    data[offset:offset + len(M_LENGTH1)] = M_LENGTH1
    p = tmp_path / "f.bin"
    p.write_bytes(bytes(data))
    res = binscan.scan_markers(str(p))
    assert res["has_length1"] is True and res["has_switch"] is False


def test_both_markers_found_across_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(binscan, "CHUNK", 7)
    data = bytearray(300)
    data[13:13 + len(M_SWITCH)] = M_SWITCH
    data[101:101 + len(M_LENGTH1)] = M_LENGTH1
    p = tmp_path / "f.bin"
    p.write_bytes(bytes(data))
    res = binscan.scan_markers(str(p))
    assert res["has_switch"] and res["has_length1"]


def test_size_cap_skips_large_files(tmp_path):
    p = make_elf(tmp_path / "big.bin", (M_LENGTH1,), size=16 * 1024)
    assert binscan.scan_markers(p, max_bytes=1000)["skipped_large"] is True
    rec = binscan.scan_binary(p, max_bytes=1000)
    assert rec["status"] == "skipped_large"
    res = binscan.run_binaries(node_bins=[p], max_bytes=1000, discover_libs=False)
    f = by_rule(res, "BIN_SKIPPED_LARGE")[0]
    assert f["severity"] == "info" and "--max-binary-mb" in f["message"]
    assert res["stats"]["skipped_large"] == 1


def test_unreadable_target_is_reported_not_crashed(tmp_path):
    res = binscan.scan_markers(str(tmp_path / "missing"))
    assert res["error"]


# ---------------------------------------------------------------- magic ----

def test_exec_kind_magic(tmp_path):
    def w(name, data):
        p = tmp_path / name
        p.write_bytes(data + b"\x00" * 64)
        return str(p)
    assert binscan.exec_kind(w("elf", b"\x7fELF\x02\x01")) == "elf"
    for magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        assert binscan.exec_kind(w("macho", magic)) == "macho"
    assert binscan.exec_kind(w("fat", b"\xca\xfe\xba\xbe" + struct.pack(">I", 2))) == "macho-fat"
    assert binscan.exec_kind(w("java", b"\xca\xfe\xba\xbe" + struct.pack(">I", 52))) is None   # Java class, not a fat binary
    pe = bytearray(0x100)
    pe[:2] = b"MZ"
    pe[0x3C:0x40] = struct.pack("<I", 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    assert binscan.exec_kind(w("pe", bytes(pe))) == "pe"
    mz_only = bytearray(0x100)
    mz_only[:2] = b"MZ"
    assert binscan.exec_kind(w("mz", bytes(mz_only))) is None
    assert binscan.exec_kind(w("text", b"#!/bin/sh\n")) is None
    assert binscan.exec_kind(str(tmp_path / "missing")) is None


def test_fat_binary_scanned_per_slice(tmp_path):
    # arm64 slice fixed, x86_64 slice vulnerable: the worst slice decides
    p = make_fat(tmp_path / "fat", [(0x0100000C, (M_SWITCH, M_LENGTH1)), (0x01000007, (M_LENGTH1,))])
    assert binscan.exec_kind(p) == "macho-fat"
    assert [s[0] for s in binscan.fat_slices(p)] == ["arm64", "x86_64"]
    rec = binscan.scan_binary(p)
    assert rec["status"] == "vulnerable"
    assert "arm64=fixed" in rec["detail"] and "x86_64=vulnerable" in rec["detail"]
    ok = make_fat(tmp_path / "fat_ok", [(0x0100000C, (M_SWITCH,)), (0x01000007, (M_SWITCH, M_LENGTH1))])
    assert binscan.scan_binary(ok)["status"] == "fixed"
    none = make_fat(tmp_path / "fat_none", [(0x0100000C, ()), (0x01000007, ())])
    assert binscan.scan_binary(none)["status"] == "inconclusive"


# ---------------------------------------------------------------- run_binaries ----

def test_explicit_targets_are_reported_with_severities(tmp_path):
    fixed = make_elf(tmp_path / "node_fixed", (M_SWITCH, M_LENGTH1))
    vuln = make_elf(tmp_path / "node_vuln", (M_LENGTH1,))
    inc = make_elf(tmp_path / "bun_inc", ())
    res = binscan.run_binaries(node_bins=[fixed, vuln], bun_bins=[inc], discover_libs=False)
    f_fixed, f_vuln, f_inc = (by_rule(res, r)[0] for r in
                              ("BIN_DECODER_FIXED", "BIN_DECODER_VULNERABLE", "BIN_DECODER_INCONCLUSIVE"))
    assert (f_fixed["severity"], f_vuln["severity"], f_inc["severity"]) == ("ok", "critical", "info")
    assert "decoder without the CVE-2026-111497 fix" in f_vuln["message"]
    assert "fixed decoder" in f_fixed["message"]
    assert "no Brotli error table" in f_inc["message"] and "inconclusive" in f_inc["message"]
    for f in (f_fixed, f_vuln, f_inc):
        assert f["fingerprints"] == ["N2S-23"] and f["basis"].startswith("DERIVED")
        assert "0ed4268" in f["basis"] and "v26.12.1 has 1" in f["basis"]      # the derivation is in the basis
    assert res["stats"]["fixed"] == 1 and res["stats"]["vulnerable"] == 1 and res["stats"]["inconclusive"] == 1


def test_scan_dir_walk_finds_decoders_and_ignores_non_binaries(tmp_path):
    root = tmp_path / "apps"
    root.mkdir()
    make_elf(root / "fixed.bin", (M_SWITCH,))
    make_elf(root / "vuln.bin", (M_LENGTH1,))
    make_elf(root / "none.bin", ())
    (root / "notes.txt").write_bytes(M_LENGTH1 + b" appears in a text file")      # no exec magic: ignored
    small = root / "tiny.bin"
    small.write_bytes(b"\x7fELF" + M_LENGTH1)                                       # below the minimum size: ignored
    res = binscan.run_binaries(scan_dirs=[str(root)], discover_libs=False)
    paths = {f["file"] for f in res["findings"]}
    assert str(root / "fixed.bin") in paths and str(root / "vuln.bin") in paths
    assert str(root / "none.bin") not in paths and str(root / "notes.txt") not in paths
    assert str(small) not in paths
    assert any("no Brotli error table" in n for n in res["notes"])                   # aggregated, never 'patched'
    assert res["stats"]["scanned"] == 3


def test_electron_framework_fixed_marker_is_not_a_clean_bill(tmp_path):
    fw = tmp_path / "App.app" / "Contents" / "Frameworks" / "Electron Framework.framework" / "Versions" / "A"
    fw.mkdir(parents=True)
    make_elf(fw / "Electron Framework", (M_SWITCH, M_LENGTH1), magic=b"\xcf\xfa\xed\xfe")
    res = binscan.run_binaries(scan_dirs=[str(tmp_path)], discover_libs=False)
    f = by_rule(res, "BIN_DECODER_FIXED")[0]
    assert f["severity"] == "info"                                  # downgraded from ok
    assert "UNCONFIRMED" in f["message"] and "two Brotli copies" in f["message"]
    vuln = tmp_path / "Other.app" / "Electron Framework"
    vuln.parent.mkdir(parents=True)
    make_elf(vuln, (M_LENGTH1,), magic=b"\xcf\xfa\xed\xfe")
    res2 = binscan.run_binaries(scan_dirs=[str(vuln.parent)], discover_libs=False)
    assert by_rule(res2, "BIN_DECODER_VULNERABLE")[0]["severity"] == "critical"


def test_library_and_python_module_targets(tmp_path):
    libdir = tmp_path / "lib"
    libdir.mkdir()
    real = make_elf(libdir / "libbrotlidec.so.1.0.9", (M_LENGTH1,))
    os.symlink(real, libdir / "libbrotlidec.so.1")                  # symlink + real file: one target
    found = binscan.find_library_targets(extra_dirs=[str(libdir)])
    assert len([p for p in found if str(libdir) in p]) == 1
    site = tmp_path / "site-packages"
    (site / "brotlicffi").mkdir(parents=True)
    mod1 = make_elf(site / "_brotli.cpython-312-x86_64-linux-gnu.so", (M_LENGTH1,))
    mod2 = make_elf(site / "brotlicffi" / "_brotlicffi.abi3.so", (M_SWITCH,))
    make_elf(site / "_other.so", (M_LENGTH1,))
    mods = binscan.find_python_module_targets([str(site)])
    assert sorted(mods) == sorted([mod1, mod2])
    res = binscan.run_binaries(python_sites=[str(site)], lib_dirs_extra=[str(libdir)], discover_libs=True)
    f = by_rule(res, "BIN_DECODER_VULNERABLE")
    assert any("Python Brotli extension module" in x["message"] and "1.2.1.0" in x["message"] for x in f)
    assert any("system libbrotlidec library" in x["message"] for x in f)
    assert by_rule(res, "BIN_DECODER_FIXED")                        # the brotlicffi module with the fixed table


def test_native_addon_in_project_node_modules(tmp_path):
    addon = tmp_path / "proj" / "node_modules" / "somebrotli" / "build" / "Release" / "addon.node"
    addon.parent.mkdir(parents=True)
    make_elf(addon, (M_LENGTH1,))
    res = binscan.run_binaries(project_dirs=[str(tmp_path / "proj")], discover_libs=False)
    f = by_rule(res, "BIN_DECODER_VULNERABLE")[0]
    assert "native addon" in f["message"] and f["file"] == str(addon)


def test_no_targets_note(tmp_path):
    res = binscan.run_binaries(discover_libs=False)
    assert res["targets"] == [] and any("nothing to fingerprint" in n for n in res["notes"])


# ---------------------------------------------------------------- decode.c (N2S-24) ----

# Synthetic stand-ins for the vendored function - NOT the upstream file.
VULNERABLE_C = """\
/* synthetic stand-in for c/dec/decode.c (tests only) */
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
/* synthetic stand-in for c/dec/decode.c (tests only) */
static BROTLI_INLINE BrotliDecoderErrorCode DecodeBlockTypeAndLength(
    int safe, BrotliDecoderState* s, int tree_type) {
  brotli_reg_t max_block_type = s->num_block_types[tree_type];
  if (max_block_type <= 1) {
    return BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
  }
  return BROTLI_DECODER_SUCCESS;
}
"""
ODD_C = """\
static int DecodeBlockTypeAndLength(int safe) {
  if (safe > 7) { return 0; }
  return 1;
}
"""


def put(tmp_path, rel, text):
    p = Path(tmp_path) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_decode_c_verdicts(tmp_path):
    v = binscan.check_decode_c(str(put(tmp_path, "a/decode.c", VULNERABLE_C)))
    assert v["status"] == "vulnerable" and v["severity"] == "warn"
    assert "compiled artefact decides" in v["detail"]
    f = binscan.check_decode_c(str(put(tmp_path, "b/decode.c", FIXED_C)))
    assert f["status"] == "fixed" and f["severity"] == "ok"
    o = binscan.check_decode_c(str(put(tmp_path, "c/decode.c", ODD_C)))
    assert o["status"] == "unrecognised" and o["severity"] == "info"
    assert binscan.check_decode_c(str(put(tmp_path, "d/decode.c", "int main() { return 0; }"))) is None
    # whitespace / comment variations of the vulnerable shape still match
    spaced = VULNERABLE_C.replace("max_block_type <= 1", "max_block_type<=1").replace("{\n    return", "{ return")
    assert binscan.check_decode_c(str(put(tmp_path, "e/decode.c", spaced)))["status"] == "vulnerable"
    # the constant wins even if the old shape is still present elsewhere in the file
    both = VULNERABLE_C + FIXED_C
    assert binscan.check_decode_c(str(put(tmp_path, "f/decode.c", both)))["status"] == "fixed"


def test_decode_c_found_in_scan_dirs_and_project_node_modules(tmp_path):
    put(tmp_path, "vendor/deps/brotli/c/dec/decode.c", VULNERABLE_C)
    put(tmp_path, "proj/node_modules/native-pkg/deps/brotli/c/dec/decode.c", FIXED_C)
    put(tmp_path, "vendor/other/decode.c", "int unrelated;")
    res = binscan.run_binaries(scan_dirs=[str(tmp_path / "vendor")], project_dirs=[str(tmp_path / "proj")],
                               discover_libs=False)
    vuln = by_rule(res, "SRC_DECODER_VULNERABLE")[0]
    assert vuln["severity"] == "warn" and vuln["fingerprints"] == ["N2S-24"] and vuln["basis"].startswith("DERIVED")
    assert "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" in vuln["evidence"] or "absent" in vuln["evidence"]
    assert by_rule(res, "SRC_DECODER_FIXED")[0]["severity"] == "ok"
    assert res["stats"]["sources"] == 2                              # the unrelated decode.c is not counted


def test_oversized_decode_c_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(binscan, "MAX_SOURCE_BYTES", 50)
    assert binscan.check_decode_c(str(put(tmp_path, "decode.c", VULNERABLE_C))) is None
