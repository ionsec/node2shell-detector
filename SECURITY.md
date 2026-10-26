# Security policy

## Supported versions

Only the latest build on `main` is supported. Pin a tag for production use.

## Reporting a vulnerability

Report privately — do not open a public issue.

- Email: info@ionsec.io
- or https://github.com/ionsec/node2shell-detector/security/advisories/new

Include: affected check (posture / binaries / deps / logs / self-test / rules), how to
reproduce, and where the fingerprint logic or threshold fails. Reports about the Brotli,
Node.js or Bun vulnerability itself belong with the respective project (google/brotli,
the Node.js security team, Bun), not here.

## Scope notes

This package intentionally opens no sockets. Posture runs **local** commands with
timeouts (`node --version`, `node -p`, `ldd` / `otool -L`, `dpkg-query`, `rpm`, `apk`,
`brew list`); the binaries and log checks read local files only. Findings of the log
scan are attempt evidence, not proof of execution. The opt-in `--self-test` feeds the
public Node.js regression vector to a runtime's own decoder inside a throwaway child
process — on an unpatched runtime that exercises the bug in that child — so it never
runs unless asked. See "Honest limits" in the README before relying on a verdict.

Exploit or PoC code is out of scope for this repository and will not be accepted: the
only trigger bytes in the codebase are the public Node.js regression vector and the
published PoC constants listed in the research brief, used as data.
