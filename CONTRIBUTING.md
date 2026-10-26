# Contributing

Small, factual patches: fingerprint additions that cite a fetched, dated source;
version-table corrections with the advisory or release note that supports them;
threshold tuning with its documented observation; backend field mappings for the
log formats.

- Fingerprints: copied exactly as published — zero invented strings. Every entry keeps
  its brief id (`N2S-xx`), source and confidence (V / P / D) in `fingerprints.py`; where a
  fact is unconfirmed the tool says "unknown / verify", it never guesses a verdict.
- Versions: fixed-version tables live in `versions.py` with their source note. Never use
  `process.versions.brotli` for a verdict (it does not change when the fix lands).
- Tests: every new fingerprint or threshold gets a corpus line (in `corpora.py`, built only
  from catalogue values) and a test; `python3 -m pytest -q` must stay green. Benign
  traffic must keep producing nothing.
- No exploit or PoC code, and no network access in the tool. The only trigger bytes in the
  codebase are the public Node.js regression vector and the published PoC constants listed
  in the brief, used as data. `--self-test` stays opt-in and is tested against stub
  scripts only.
- Commits: factual, technical subjects. No marketing.

IONSEC internal contributions: branch from `main`, keep the subject line plain, and
explain the provenance in the body when adding fingerprints.
