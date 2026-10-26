"""README + repo metadata consistency: the docs describe what the code actually does."""

import re

import pytest

from conftest import TOOL_ROOT
from node2shell_detector import cli, corpora, fingerprints as fp

README = (TOOL_ROOT / "README.md").read_text()
PLAIN = " ".join(README.replace("*", "").replace("`", "").split())   # marks stripped, whitespace collapsed
RULES = TOOL_ROOT / "rules"


def test_every_catalogue_id_is_in_the_readme():
    for sid in fp.CATALOGUE:
        assert f"`{sid}`" in README, sid


def test_every_log_rule_name_is_documented():
    for rule in set(corpora.EXPECTED_RULE.values()):
        needle = "SEED_BYTES" if rule.startswith("SEED_BYTES_") else rule
        assert needle in README, rule
    for rule in ("BIN_DECODER_FIXED", "BIN_DECODER_VULNERABLE", "BIN_DECODER_INCONCLUSIVE", "SRC_DECODER_VULNERABLE",
                 "SRC_DECODER_FIXED", "SELFTEST_FIXED", "SELFTEST_VULNERABLE", "SELFTEST_CRASH",
                 "HOST_MARKER_FILE", "EVIDENCE_CONFLICT"):
        assert rule in README, rule


def test_every_cli_flag_is_documented():
    flags = {opt for action in cli.build_parser()._actions for opt in action.option_strings}
    assert {"--project", "--log", "--node-bin", "--bun-bin", "--deno-bin", "--python-site", "--scan-dir", "--check",
            "--self-test", "--no-discover", "--json", "--quiet", "--max-lines", "--log-format"} <= flags
    for flag in sorted(flags):
        assert flag in README, flag


def test_required_links_and_urls():
    for needle in ("https://github.com/ionsec/node2shell-detector",
                   "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
                   "https://www.cve.org/CVERecord?id=CVE-2026-111497",
                   "rules/README.md", "AGPL-3.0", "(LICENSE)", "SECURITY.md", "CONTRIBUTING.md"):
        assert needle in README, needle


def test_the_honest_limits_are_stated():
    for phrase in (
        "A log hit never proves execution",
        "process.versions.brotli does not change when the fix lands",
        "never uses it for a verdict",
        "Nothing in this tool opens a socket",
        "Posture is point-in-time",
        "EOL honesty",
        "no fixed release",
        "restart every process",
        "rebuilt, not restarted",
        "fetch-trap",
        "unknown / verify",
        "Evidence hierarchy",
        "fixed 24.22.1 still reports 1.2.0",
        "UNCONFIRMED",
        "unresolved, not cleared",
        "Known gaps",
    ):
        assert phrase in PLAIN, phrase
    # the exit-code contract of the template
    assert "| 0 | checks ran; no warn / critical finding |" in PLAIN
    assert "| 1 | at least one warn / critical finding" in PLAIN
    assert "| 2 | invocation / resource problem" in PLAIN


def test_known_gaps_cover_the_requested_topics():
    gaps = PLAIN.split("Known gaps", 1)[1].split("# Rules package", 1)[0]
    for topic in ("Containers", "Managed hosts", "Windows", "Electron", "Deno"):
        assert topic in gaps, topic


def test_self_test_is_documented_as_opt_in_and_dangerous_on_unpatched_runtimes():
    for phrase in ("--self-test", "opt-in", "throwaway child process",
                   "On an unpatched runtime this executes the public regression vector",
                   "exercises the bug inside the throwaway child", "Why it is opt-in",
                   "only against stub scripts"):
        assert phrase in PLAIN, phrase


def test_the_manual_remote_exposure_check_is_documented():
    for phrase in ("Content-Encoding: br", '{"ping":1}', "--data-binary", "400", "decodes Brotli", "2xx", "ignores",
                   "415", "rejects", "Ostorlab", "/graphql",
                   "Only run this against systems you own or are authorized to test"):
        assert phrase in PLAIN, phrase


def test_brotli_1_0_x_bare_name_note_is_in_the_readme():
    for phrase in ("BLOCK_LENGTH_1", "BLOCK_SWITCH", "ERR_BLOCK_SWITCH", "ERR_BLOCK_LENGTH_1",
                   "EXUBERANT_META_NIBBLE", "CONTEXT_MAP_REPEAT", "return #NAME;", "return #PREFIX #NAME;",
                   "bookworm", "1.0.9-2+deb12u1", "NUL-delimited", "not in the brief",
                   "v1.0.9 → vulnerable, v1.0.10 → fixed, v1.1.0 → vulnerable, v1.1.1 → fixed"):
        assert phrase in PLAIN, phrase
    assert "1.0.x form" in PLAIN                               # its own line in the fingerprint table


def test_the_readme_does_not_repeat_an_unsourced_cvss():
    assert re.search(r"CVSS[^\n]{0,40}9\.8", README) is None
    assert "9.2" in README and "8.1" in README                 # the two scores the sources support


def test_rules_package_section_matches_the_rules_directory():
    if not (RULES / "README.md").exists():
        pytest.skip("rules/ not present")
    section = PLAIN.split("# Rules package", 1)[1]
    assert "rules/README.md" in README
    assert "1006600–1006699" in section and "1026111400–1026111499" in section
    sigma = list((RULES / "sigma").glob("*.yml"))
    assert f"{len(sigma)} Sigma rules" in section
    rules_file = (RULES / "suricata" / "ionsec-node2shell.rules").read_text().splitlines()
    active = [l for l in rules_file if l.startswith("alert ")]
    assert f"{len(active)} active rules" in section
    sids = [int(m) for l in active for m in re.findall(r"sid:(\d+)", l)]
    assert sids and all(1006600 <= s <= 1006699 for s in sids)
    modsec_ids = [int(i) for i in re.findall(r"id:(\d{10})", (RULES / "modsecurity" /
                                                              "ionsec-node2shell-dropin.conf").read_text())]
    assert modsec_ids and all(1026111400 <= i <= 1026111499 for i in modsec_ids)
    assert "7 rules + 1 private format rule" in section


def test_repo_metadata_files():
    lic = (TOOL_ROOT / "LICENSE").read_text()
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in lic and "Version 3, 19 November 2007" in lic
    sec = (TOOL_ROOT / "SECURITY.md").read_text()
    assert "https://github.com/ionsec/node2shell-detector/security/advisories/new" in sec
    assert "info@ionsec.io" in sec and "opens no sockets" in sec and "--self-test" in sec
    contrib = (TOOL_ROOT / "CONTRIBUTING.md").read_text()
    assert "N2S-xx" in contrib and "process.versions.brotli" in contrib and "No exploit or PoC code" in contrib
    ignore = (TOOL_ROOT / ".gitignore").read_text().split()
    assert {"__pycache__/", ".pytest_cache/", ".venv/", "venv/", ".DS_Store", "*.pyc"} <= set(ignore)
    ini = (TOOL_ROOT / "pytest.ini").read_text()
    assert "testpaths = tests" in ini and "[pytest]" in ini


def test_package_layout():
    for name in ("__init__", "__main__", "cli", "versions", "runtimes", "binscan", "deps", "logs", "selftest",
                 "fingerprints", "corpora", "report"):
        assert (TOOL_ROOT / "node2shell_detector" / f"{name}.py").is_file(), name
    for d in ("tests", "examples"):
        assert (TOOL_ROOT / d).is_dir()
