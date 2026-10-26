"""Brotli 1.0.x-style (bare-name) error tables - DERIVED, not in the brief.

Before v1.1.0 `BrotliDecoderErrorString` returns `#NAME`, from v1.1.0 `#PREFIX #NAME`; a decoder built from
1.0.x (Node 12-16's bundled 1.0.9, Debian bookworm's libbrotlidec 1.0.9) carries bare, NUL-delimited names.
These tests use synthetic files; the same verdicts were also checked against real builds of the upstream
tags v1.0.9 / v1.0.10 / v1.1.0 / v1.1.1 during development (see the README).
"""

import pytest

from conftest import M_LENGTH1, M_SWITCH, make_elf, make_fat
from node2shell_detector import binscan, fingerprints as fp

L1, SW = b"BLOCK_LENGTH_1", b"BLOCK_SWITCH"
NIB, CTX = b"EXUBERANT_META_NIBBLE", b"CONTEXT_MAP_REPEAT"


def by_rule(res, rule):
    return [f for f in res["findings"] if f["rule"] == rule]


def test_bare_marker_constants_are_nul_delimited_whole_strings():
    assert fp.BIN_LEGACY_LENGTH1 == b"\x00BLOCK_LENGTH_1\x00"
    assert fp.BIN_LEGACY_SWITCH == b"\x00BLOCK_SWITCH\x00"
    assert fp.BIN_LEGACY_CORROBORATION == (b"\x00EXUBERANT_META_NIBBLE\x00", b"\x00CONTEXT_MAP_REPEAT\x00")
    # the bare name is a SUFFIX of the 1.1+ name: the NUL delimiters are what keep them apart
    assert fp.BIN_MARKER_LENGTH1.endswith(b"BLOCK_LENGTH_1")


@pytest.mark.parametrize("markers,status,tables", [
    ((L1, SW, NIB), "fixed", ["1.0.x"]),                # 1.0.10-style: bare BLOCK_SWITCH present
    ((L1, SW, CTX), "fixed", ["1.0.x"]),
    ((L1, SW, NIB, CTX), "fixed", ["1.0.x"]),
    ((L1, NIB), "vulnerable", ["1.0.x"]),               # 1.0.9-style: no BLOCK_SWITCH
    ((L1, CTX), "vulnerable", ["1.0.x"]),
    ((L1, NIB, CTX), "vulnerable", ["1.0.x"]),
])
def test_legacy_table_verdicts(tmp_path, markers, status, tables):
    rec = binscan.scan_binary(make_elf(tmp_path / "libbrotlidec.so.1", markers))
    assert rec["status"] == status and rec["tables"] == tables
    assert "1.0.x-style error table" in rec["detail"] and "DERIVED" in rec["detail"]


@pytest.mark.parametrize("markers", [
    (L1,),                      # bare BLOCK_LENGTH_1 alone: ambiguous
    (SW,),                      # bare BLOCK_SWITCH alone: must NEVER read as 'patched'
    (L1, SW),                   # both, but no corroborating table name
    (NIB,),                     # corroboration alone is not a table
])
def test_ambiguous_bare_names_are_unknown_never_patched(tmp_path, markers):
    rec = binscan.scan_binary(make_elf(tmp_path / "x.bin", markers))
    assert rec["status"] == "inconclusive" and rec["severity"] == "info"
    assert rec["tables"] == []
    if L1 in markers or SW in markers:
        assert "ambiguous" in rec["detail"]
    assert "never read as 'patched'" in rec["detail"]


def test_bare_name_inside_a_longer_string_does_not_count(tmp_path):
    # BLOCK_LENGTH_1 / BLOCK_SWITCH only as the tail of other strings (no leading NUL) - e.g. the 1.1+ names
    p = make_elf(tmp_path / "f.bin", (M_LENGTH1, b"X" + SW + b"Y", NIB, CTX))
    res = binscan.scan_markers(p)
    assert res["has_length1"] is True                   # the 1.1+ prefixed name
    assert res["legacy_length1"] is False               # ... which is NOT a bare BLOCK_LENGTH_1
    assert res["legacy_switch"] is False
    assert res["legacy_corroborated"] is True
    rec = binscan.scan_binary(p)
    assert rec["tables"] == ["1.1+"] and rec["status"] == "vulnerable"


def test_a_prefixed_fixed_table_is_not_confused_by_bare_look_alikes(tmp_path):
    rec = binscan.scan_binary(make_elf(tmp_path / "f.bin", (M_SWITCH, M_LENGTH1)))
    assert rec["status"] == "fixed" and rec["tables"] == ["1.1+"]
    assert rec["legacy_length1"] is False and rec["legacy_switch"] is False


def test_two_brotli_copies_one_of_each_style(tmp_path):
    both_fixed = binscan.scan_binary(make_elf(tmp_path / "a", (M_SWITCH, L1, SW, NIB)))
    assert both_fixed["status"] == "fixed" and both_fixed["tables"] == ["1.1+", "1.0.x"]
    assert "two Brotli copies and both are fixed" in both_fixed["detail"]
    legacy_unfixed = binscan.scan_binary(make_elf(tmp_path / "b", (M_SWITCH, L1, NIB)))
    assert legacy_unfixed["status"] == "vulnerable"
    assert "at least one is unfixed" in legacy_unfixed["detail"] and "1.0.x table WITHOUT the fix" in legacy_unfixed["detail"]
    prefixed_unfixed = binscan.scan_binary(make_elf(tmp_path / "c", (M_LENGTH1, L1, SW, NIB)))
    assert prefixed_unfixed["status"] == "vulnerable"
    assert "1.1+ table WITHOUT the fix" in prefixed_unfixed["detail"]


def test_classify_markers_signature_stays_backward_compatible():
    assert binscan.classify_markers(True, True)["status"] == "fixed"
    assert binscan.classify_markers(False, True)["status"] == "vulnerable"
    assert binscan.classify_markers(False, False)["status"] == "inconclusive"
    assert binscan.classify_markers(False, False, True, True, True)["status"] == "fixed"
    assert binscan.classify_markers(False, False, False, True, True)["status"] == "vulnerable"
    assert binscan.classify_markers(False, False, True, False, True)["status"] == "inconclusive"   # switch, no length_1


@pytest.mark.parametrize("offset", list(range(0, 40)))
def test_legacy_marker_straddling_a_chunk_boundary_is_found(tmp_path, monkeypatch, offset):
    monkeypatch.setattr(binscan, "CHUNK", 16)
    data = bytearray(200)
    data[offset:offset + len(fp.BIN_LEGACY_SWITCH)] = fp.BIN_LEGACY_SWITCH
    p = tmp_path / "f.bin"
    p.write_bytes(bytes(data))
    assert binscan.scan_markers(str(p))["legacy_switch"] is True


def test_fat_binary_with_legacy_slices(tmp_path):
    p = make_fat(tmp_path / "fat", [(0x0100000C, (L1, SW, NIB)), (0x01000007, (L1, NIB))])
    rec = binscan.scan_binary(p)
    assert rec["status"] == "vulnerable"
    assert "arm64=fixed" in rec["detail"] and "x86_64=vulnerable" in rec["detail"]
    assert all(s["legacy_length1"] for s in rec["slices"])


def test_findings_carry_the_derivation_and_stay_derived(tmp_path):
    vuln = make_elf(tmp_path / "libbrotlidec.so.1", (L1, NIB))
    fixed = make_elf(tmp_path / "libbrotlidec.so.1.0.10", (L1, SW, NIB))
    res = binscan.run_binaries(lib_extra=[vuln, fixed], discover_libs=False)
    v = by_rule(res, "BIN_DECODER_VULNERABLE")[0]
    f = by_rule(res, "BIN_DECODER_FIXED")[0]
    assert v["severity"] == "critical" and f["severity"] == "ok"
    for x in (v, f):
        assert x["fingerprints"] == ["N2S-23"] and x["basis"].startswith("DERIVED")
        assert "return #NAME;" in x["basis"] and "#PREFIX #NAME" in x["basis"]    # the derivation is stated
        assert "bookworm" in x["basis"] and "1.0.9-2+deb12u1" in x["basis"]
        assert "1.0.x bare names" in x["evidence"]
    assert "system libbrotlidec library" in v["message"]


def test_legacy_names_note_and_extensions_are_registered():
    assert "return #NAME;" in fp.LEGACY_NAMES_NOTE and "return #PREFIX #NAME;" in fp.LEGACY_NAMES_NOTE
    assert set(fp.DERIVED_EXTENSIONS) == {"N2S-23/1.0.x-table", "N2S-16/1.0.x-code"}
    assert all(e["conf"] == "D" for e in fp.DERIVED_EXTENSIONS.values())
