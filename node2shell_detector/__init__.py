"""node2shell-detector - host-side posture, binary-fingerprint, dependency and log
checks for Node2Shell (CVE-2026-111497): an out-of-bounds write in Google's Brotli C
decoder that Node.js and Bun bundle.

Every fingerprint, CVE fact, fixed version and threshold in this package is copied
from the IONSEC research brief (compiled 2026-10-24 from fetched primary sources):

  BRIEF.md   sections are cited as "BRIEF s<n>"; the fingerprint catalogue (s7) is
             cited by its ids, N2S-01 .. N2S-25.

No fingerprint, IOC, version or config flag is invented by this tool. Where the brief
says UNCONFIRMED, the tool says "unknown / verify" and never issues a guessed verdict.
"""

__version__ = "1.0.0"
TOOL_NAME = "node2shell-detector"
CVE_ID = "CVE-2026-111497"
BRIEF_DATE = "2026-10-24"
