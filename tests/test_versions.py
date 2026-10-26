"""Fixed-version tables, comparators and the dpkg version comparator."""

import pytest

from node2shell_detector import versions as v


def test_fixed_tables_match_brief():
    # BRIEF s1 / s3: fixed releases of the 2026-10-21 Node.js security release
    assert v.NODE_FIXED == {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
    assert v.NODE_LAST_VULNERABLE[26] == "26.12.0"
    assert v.NODE_LAST_VULNERABLE[24] == "24.22.0"
    assert v.NODE_LAST_VULNERABLE[22] == "22.23.3"
    assert v.NODE_EOL_NO_FIX_LINES == (25, 23, 21, 20)
    assert v.NODE_EOL_MAX_MAJOR == 19
    assert v.BUN_FIXED == (1, 4, 4)
    # upstream google/brotli fixed releases
    assert v.BROTLI_FIXED_RELEASES == ((1, 0, 10), (1, 1, 1), (1, 2, 1))
    assert v.BROTLI_FIRST_AFFECTED == (1, 0, 3)
    # distros
    assert v.DEBIAN_FIXED == {"bookworm": "1.0.9-2+deb12u1", "trixie": "1.1.0-2+deb13u1"}
    assert v.DEBIAN_CHANGELOG == "/usr/share/doc/libbrotli1/changelog.Debian.gz"
    assert v.HOMEBREW_FIXED == (1, 2, 1)
    # other ecosystems
    assert v.PYPI_BROTLI_FIXED == (1, 2, 1)
    assert v.PYPI_BROTLICFFI_FIXED == (1, 2, 1, 0)
    assert v.PYPI_BROTLICFFI_FIRST == (1, 0, 9, 0)
    assert v.GO_BROTLI_FIXED == (1, 2, 7)
    assert v.GEM_BROTLI_FIXED == (0, 9, 1)
    assert v.BROTLI4J_FIXED == (1, 24, 0)


@pytest.mark.parametrize("ver,status,sev", [
    ("v22.23.3", "vulnerable_unpatched", "critical"),
    ("v22.23.4", "patched", "ok"),
    ("v22.24.0", "patched", "ok"),
    ("v22.0.0", "vulnerable_unpatched", "critical"),
    ("v24.22.0", "vulnerable_unpatched", "critical"),
    ("v24.22.1", "patched", "ok"),
    ("v24.23.0", "patched", "ok"),
    ("v24.16.0", "vulnerable_unpatched", "critical"),
    ("v26.12.0", "vulnerable_unpatched", "critical"),
    ("v26.12.1", "patched", "ok"),
    ("v26.7.0", "vulnerable_unpatched", "critical"),
    ("26.12.1", "patched", "ok"),                       # no leading v
    ("v25.9.0", "eol_no_fix", "critical"),
    ("v25.0.0", "eol_no_fix", "critical"),
    ("v23.11.1", "eol_no_fix", "critical"),
    ("v21.7.3", "eol_no_fix", "critical"),
    ("v20.20.2", "eol_no_fix", "critical"),
    ("v20.99.0", "eol_no_fix", "critical"),            # EOL lines never become fixed
    ("v19.9.0", "eol_no_fix", "critical"),
    ("v18.20.8", "eol_no_fix", "critical"),
    ("v16.20.2", "eol_no_fix", "critical"),
    ("v12.22.12", "eol_no_fix", "critical"),
    ("v10.24.1", "eol_no_fix", "critical"),
    ("v27.0.0", "unknown_future_branch", "info"),
    ("v24.22.1-nightly2026102100abcdef", "unknown_prerelease", "warn"),
    ("v24.22.1-rc.1", "unknown_prerelease", "warn"),
    ("v26.0.0-pre", "unknown_prerelease", "warn"),
    ("not-a-version", "unparseable", "warn"),
    ("", "unparseable", "warn"),
])
def test_node_version_table(ver, status, sev):
    ev = v.eval_node_version(ver)
    assert ev["status"] == status, ev
    assert ev["severity"] == sev, ev
    assert ev["detail"]


def test_node_eol_wording_says_no_fix_and_move_lines():
    ev = v.eval_node_version("v20.20.2")
    assert "NO fixed release" in ev["detail"]
    assert "22.23.4+, 24.22.1+ or 26.12.1+" in ev["detail"]
    assert "20.20.2" in ev["detail"]                    # the brief's last-vulnerable release for the line
    old = v.eval_node_version("v10.24.1")
    assert "v12.22.12" in old["detail"] and "verify" in old["detail"]   # older than the brief checked


def test_node_vulnerable_wording_says_fixed_release_exists():
    ev = v.eval_node_version("v24.22.0")
    assert ev["fixed_in"] == "24.22.1"
    assert "fixed release exists" in ev["detail"]


@pytest.mark.parametrize("ver,status,sev", [
    ("1.4.3", "vulnerable_unpatched", "critical"),
    ("1.3.14", "vulnerable_unpatched", "critical"),
    ("1.4.2", "vulnerable_unpatched", "critical"),
    ("1.0.0", "vulnerable_unpatched", "critical"),
    ("1.4.4", "patched", "ok"),
    ("1.5.0", "patched", "ok"),
    ("2.0.0", "patched", "ok"),
    ("1.4.4-canary.20261022+abc", "unknown_prerelease", "warn"),
    ("garbage", "unparseable", "warn"),
])
def test_bun_version_table(ver, status, sev):
    ev = v.eval_bun_version(ver)
    assert (ev["status"], ev["severity"]) == (status, sev)


def test_deno_is_info_unresolved():
    ev = v.eval_deno_version("2.9.8")
    assert ev["severity"] == "info" and ev["status"] == "unresolved"
    assert "unresolved" in ev["detail"] and "NOT cleared" in ev["detail"]
    assert "unknown / verify" in ev["detail"]


@pytest.mark.parametrize("tag,status,sev", [
    ("22.23.3", "vulnerable_unpatched", "critical"),
    ("22.23.3-bookworm-slim", "vulnerable_unpatched", "critical"),
    ("22.23.4-alpine3.23", "patched", "ok"),
    ("24.22.0", "vulnerable_unpatched", "critical"),
    ("24.22.1", "patched", "ok"),
    ("26.12.0-trixie", "vulnerable_unpatched", "critical"),
    ("22.22", "vulnerable_unpatched", "critical"),     # older minor line: every patch is below the fix
    ("22.23", "floating_rebuild", "info"),
    ("24", "floating_rebuild", "info"),
    ("22", "floating_rebuild", "info"),
    ("26-slim", "floating_rebuild", "info"),
    ("jod", "floating_rebuild", "info"),
    ("krypton-alpine", "floating_rebuild", "info"),
    ("iron", "eol_no_fix", "critical"),
    ("20", "eol_no_fix", "critical"),
    ("20.11.1-alpine3.19", "eol_no_fix", "critical"),
    ("25-slim", "eol_no_fix", "critical"),
    ("18", "eol_no_fix", "critical"),
    ("lts", "floating", "info"),
    ("latest", "floating", "info"),
    ("current-slim", "floating", "info"),
    ("alpine3.20", "floating", "info"),
    ("bookworm", "floating", "info"),
    ("${NODE_VERSION}-alpine", "unresolved_variable", "info"),
])
def test_node_image_tags(tag, status, sev):
    ev = v.eval_node_tag(tag)
    assert (ev["status"], ev["severity"]) == (status, sev), ev


def test_floating_tag_says_rebuild():
    assert "rebuilt" in v.eval_node_tag("24")["detail"]
    assert "rebuilt" in v.eval_bun_tag("1")["detail"]


@pytest.mark.parametrize("tag,status,sev", [
    ("1.4.3", "vulnerable_unpatched", "critical"),
    ("1.4.3-alpine", "vulnerable_unpatched", "critical"),
    ("1.4.4", "patched", "ok"),
    ("1.3", "vulnerable_unpatched", "critical"),
    ("1.4", "floating_rebuild", "info"),
    ("1", "floating_rebuild", "info"),
    ("latest", "floating", "info"),
    ("canary", "floating", "info"),
    ("slim", "floating", "info"),
])
def test_bun_image_tags(tag, status, sev):
    ev = v.eval_bun_tag(tag)
    assert (ev["status"], ev["severity"]) == (status, sev), ev


@pytest.mark.parametrize("vt,expected", [
    ((1, 0, 2), "not_affected_old"),
    ((1, 0, 3), "vulnerable"), ((1, 0, 9), "vulnerable"),
    ((1, 0, 10), "fixed"),
    ((1, 1, 0), "vulnerable"),
    ((1, 1, 1), "fixed"),
    ((1, 2, 0), "vulnerable"),
    ((1, 2, 1), "fixed"), ((1, 3, 0), "fixed"),
])
def test_upstream_brotli_status(vt, expected):
    assert v.brotli_upstream_status(vt) == expected


# ---------------------------------------------------------------- dpkg comparator ----

@pytest.mark.parametrize("a,b,expected", [
    ("1.0-1", "1.0-2", -1),
    ("1.0-2", "1.0-1", 1),
    ("1.0-1", "1.0-1", 0),
    ("1.0~rc1", "1.0", -1),                  # tilde sorts before everything, even the empty string
    ("1.0~~", "1.0~", -1),
    ("1.0~", "1.0", -1),
    ("1:0.9", "2.0", 1),                     # epoch wins
    ("2.0", "1:0.9", -1),
    ("0:1.0", "1.0", 0),
    ("1.0.9-2+deb12u1", "1.0.9-2+b2", 1),    # a binNMU of the unfixed build is older than the fix
    ("1.0.9-2+deb12u2", "1.0.9-2+deb12u1", 1),
    ("1.0.9-2build6", "1.0.9-2+deb12u1", -1),   # letters sort before '+'
    ("1.1.0-2+deb13u1", "1.1.0-2", 1),
    ("2.0", "1.99", 1),
    ("1.10", "1.9", 1),                      # numeric, not lexical
    ("1.0", "1.00", 0),                      # leading zeros ignored
    ("1.0a", "1.0", 1),
    ("1.0a", "1.0+", -1),                    # letters sort before non-letters
    ("1.0+b1", "1.0", 1),
    ("1.2.3-1", "1.2.3~rc1-1", 1),
    ("1.0-0", "1.0", 0),                     # missing revision == "0"
    ("1.0.9-2", "1.0.9-2", 0),
])
def test_dpkg_compare(a, b, expected):
    assert v.dpkg_compare(a, b) == expected
    assert v.dpkg_compare(b, a) == -expected     # antisymmetric


def test_dpkg_parse_epoch_upstream_revision():
    assert v.dpkg_parse("1:2.0-3+b1") == (1, "2.0", "3+b1")
    assert v.dpkg_parse("2.0") == (0, "2.0", "")
    assert v.dpkg_parse("1.0-rc-2") == (0, "1.0-rc", "2")    # revision = after the LAST hyphen
    assert v.dpkg_parse("x:1.0-1") == (0, "x:1.0", "1")      # a non-numeric 'epoch' is not an epoch


@pytest.mark.parametrize("ver,status,sev", [
    ("1.0.9-2+deb12u1", "patched", "ok"),         # bookworm fix
    ("1.0.9-2+deb12u2", "patched", "ok"),
    ("1.0.9-2+b2", "vulnerable_unpatched", "critical"),
    ("1.0.9-2", "vulnerable_unpatched", "critical"),
    ("1.1.0-2+deb13u1", "patched", "ok"),         # trixie fix
    ("1.1.0-2", "vulnerable_unpatched", "critical"),
    ("1.1.0-2build2", "vulnerable_unpatched", "critical"),   # Ubuntu: no fix at brief time
    ("1.2.0-4", "vulnerable_unpatched", "critical"),         # forky/sid: unfixed at fetch time
    ("1.2.0-5", "unknown", "warn"),               # newer than the unfixed build: verify
    ("1.2.1-1", "patched", "ok"),                 # upstream fixed release
    ("1.0.10-1", "patched", "ok"),
    ("1.1.1-1", "patched", "ok"),
    ("1.0.2-1", "not_affected", "ok"),            # predates the vulnerable check
    ("1.0.7-1", "vulnerable_unpatched", "critical"),
    ("garbage", "unknown", "warn"),
])
def test_debian_version_status(ver, status, sev):
    ev = v.debian_version_status(ver)
    assert (ev["status"], ev["severity"]) == (status, sev), ev


# ---------------------------------------------------------------- other ecosystems ----

@pytest.mark.parametrize("ver,status,sev", [
    ("1.0.4", "vulnerable_unpatched", "warn"),
    ("1.1.0", "vulnerable_unpatched", "warn"),
    ("1.2.0", "vulnerable_unpatched", "warn"),
    ("1.2.1", "patched", "ok"),
    ("1.2.2", "patched", "ok"),
    ("1.0.1", "unknown_outside_range", "info"),   # GHSA says not affected, PYSEC lists it: unknown / verify
    ("0.5.2", "unknown_outside_range", "info"),
    ("junk", "unparseable", "warn"),
])
def test_pypi_brotli(ver, status, sev):
    ev = v.eval_pypi_brotli(ver)
    assert (ev["status"], ev["severity"]) == (status, sev)


@pytest.mark.parametrize("ver,status,sev", [
    ("1.0.9.0", "vulnerable_unpatched", "warn"),
    ("1.0.9.2", "vulnerable_unpatched", "warn"),
    ("1.1.0.0", "vulnerable_unpatched", "warn"),
    ("1.2.0.2", "vulnerable_unpatched", "warn"),
    ("1.2.1.0", "patched", "ok"),
    ("0.8.0", "not_affected", "ok"),
])
def test_pypi_brotlicffi(ver, status, sev):
    ev = v.eval_pypi_brotlicffi(ver)
    assert (ev["status"], ev["severity"]) == (status, sev)


def test_pypi_brotlipy():
    assert v.eval_pypi_brotlipy("0.7.0")["status"] == "not_affected"
    assert v.eval_pypi_brotlipy("0.9.0")["severity"] == "info"


@pytest.mark.parametrize("ver,status", [
    ("v1.0.0", "vulnerable_unpatched"), ("v1.2.6", "vulnerable_unpatched"),
    ("v1.2.7", "patched"), ("v1.3.0", "patched"),
    ("v1.2.7-0.20261023120000-abcdef123456", "unknown_pseudo_version"),
])
def test_go_brotli(ver, status):
    assert v.eval_go_brotli(ver)["status"] == status


@pytest.mark.parametrize("ver,status", [
    ("0.4.0", "vulnerable_unpatched"), ("0.9.0", "vulnerable_unpatched"),
    ("0.9.1", "patched"), ("0.9.2", "patched"),
    ("0.3.0", "unknown_outside_range"),
])
def test_gem_brotli(ver, status):
    assert v.eval_gem_brotli(ver)["status"] == status


@pytest.mark.parametrize("ver,status", [
    ("1.21.0", "vulnerable_unpatched"), ("1.23.0", "vulnerable_unpatched"),
    ("1.18.0", "vulnerable_unpatched"), ("1.24.0", "patched"), ("2.0.0", "patched"),
])
def test_brotli4j(ver, status):
    assert v.eval_brotli4j(ver)["status"] == status


def test_cmp_tuple_pads_with_zero():
    assert v.cmp_tuple((1, 2, 1), (1, 2, 1, 0)) == 0
    assert v.cmp_tuple((1, 2, 0, 2), (1, 2, 1, 0)) == -1
    assert v.parse_dotted("brotlicffi 1.0.9.0") == (1, 0, 9, 0)
    assert v.parse_dotted("none") is None
