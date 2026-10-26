/*
   =============================================================================
   IONSEC node2shell detector — YARA rules
   CVE-2026-111497 (Node2Shell) — out-of-bounds write in the Google Brotli C decoder
   Compiled: 2026-10-24 · Author: IONSEC · File: ionsec_node2shell.yar
   =============================================================================
   Rule families
     A. Trigger payloads (hunting): N2S-01..06 byte streams in PCAP carves, captured
        request/response bodies, WAF body exports, .br fixtures; plus the hex-text form
        the public PoCs and self-tests embed.
     B. Decoder inventory (N2S-23): executables and libraries whose Brotli decoder was
        built WITHOUT the fix (google/brotli 0ed4268a and its release-branch twins
        b418fa8 / da98063 / 50a9b70).
     C. Vendored source (N2S-24): decode.c without the fix.

   Derivation for family B (N2S-23, DERIVED; brief section 7):
     - The fix adds the error code BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH (-17) to the
       BROTLI_DECODER_ERROR_CODES_LIST in decode.h; before it, "-17 code is reserved".
       BrotliDecoderErrorString() turns that list into a string table, so the name
       BLOCK_SWITCH appears in a binary only when the decoder carries the fix
       ("git log -S": only 0ed4268 / b418fa8 / da98063 / 50a9b70 introduce it; brief:
       Node v26.12.0 has 0 occurrences, v26.12.1 has 1). BLOCK_LENGTH_1 (-9) is in every
       version, so it proves a decoder error table is present.
     - brotli 1.1.0+ build the names as #PREFIX #NAME ("_ERROR_FORMAT_BLOCK_LENGTH_1");
       brotli 1.0.x, including the 1.0.10 fix, build bare #NAME ("BLOCK_LENGTH_1")
       (verified in the google/brotli tags v1.0.3/v1.0.9/v1.0.10 versus v1.1.0+;
       confirmed by the IONSEC coordinator). Hence a separate 1.0.x rule.
     - Node.js also exports the codes as zlib constants named
       "BROTLI_DECODER_ERROR_FORMAT_*" (node_zlib.cc NODE_DEFINE_CONSTANT); a fixed Node
       adds "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" (commit b5f41529df). These names
       contain the prefixed substrings, which is why Node 12-16 (brotli 1.0.9) still
       match the prefixed rules.
     - Builds that link a shared libbrotlidec (Debian/Ubuntu nodejs, Homebrew node,
       --shared-brotli, USE_SYSTEM_BROTLI=1) carry no decoder table of their own: the
       verdict belongs to the library file, and a pre-fix Node source tree still shows
       pre-fix constants. Family B therefore separates "embedded" from "library" from
       "linked consumer".
     - No decoder string table at all (stripped error strings, other implementations)
       => no match = "unknown", never "patched".
     - Node built with --shared (e.g. Homebrew) keeps its code in libnode.<abi>.dylib /
       libnode.so.<abi>; the "node" launcher holds neither constants nor a decoder. Scan
       the libnode file. IONSEC emulated family B on this build machine (2026-10-24):
       Homebrew libbrotlidec.1.2.0.dylib -> Unfixed_Brotli_Decoder_Library;
       Homebrew Node 26.7.0 libnode.147.dylib -> Linked_Consumer_PreFix_Constants;
       the 50 KB node launcher -> no match. Static archives (libbrotlidec.a) are not
       executables and are not scanned by family B.
   Coverage gaps (by design): binaries that embed two decoders (Electron: Chromium's
   copy may carry the fix while Node's does not) can contain both names and stay silent;
   ports that are not the C library (Go andybalholm/brotli, Rust brotli-decompressor,
   Deno) are not covered. Use the runtime self-test (N2S-25) for those.
   Validation: no YARA binary or yara-python exists in the IONSEC build environment
   (2026-10-24); syntax was linted by hand and with a structural checker. Run
   "yara -w ionsec_node2shell.yar /dev/null" (or yarac) before deployment.
   =============================================================================
*/

private rule IONSEC_N2S_Executable
{
    meta:
        description = "ELF, Mach-O (thin or fat) or PE file"
    condition:
        uint32(0) == 0x464C457F                                  // ELF
        or uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF    // Mach-O 32/64 little-endian
        or uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE    // Mach-O 32/64 big-endian
        or ((uint32be(0) == 0xCAFEBABE or uint32be(0) == 0xCAFEBABF) and uint32be(4) < 0x20)  // fat Mach-O, not a Java class
        or (uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550)  // PE
}

/* ---------------------------------------------------------------------------
   A. Trigger payloads
   --------------------------------------------------------------------------- */

rule IONSEC_Node2Shell_Trigger_Seed_Payload
{
    meta:
        author = "IONSEC"
        date = "2026-10-24"
        description = "Node2Shell (CVE-2026-111497) Brotli trigger byte streams N2S-01..06 inside a file: PCAP carve, captured request or response body, WAF body export, .br fixture"
        cve = "CVE-2026-111497"
        n2s_ids = "N2S-01 N2S-02 N2S-03 N2S-04 N2S-05 N2S-06"
        provenance = "VERBATIM: bytes copied from the IONSEC brief section 7 (Node regression vector test-zlib-invalid-input.js b5f41529df; hypnguyen1209 poc.py variants; ZeroHackOrg node2shell.py; Ghost-Bx1 exploit.py)"
        confidence = "hunting"
        false_positives = "Legitimate patch self-tests and scanners embed the N2S-01 seed: Node's own regression test, Ostorlab's differential probe and defensive known-answer tests in more than 12 public repos (vmware/photon patch test, ks-labs, bdamokos/EP-open-data-portal, Sureshot-Labs, mikey1384/translator). A hit in a test fixture, scanner package or your own validation capture is expected."
        reference = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
    strings:
        $n2s_01 = { 20 00 10 41 41 41 FC FF FF 07 00 22 28 F0 0B 60 F7 F4 1F 00 00 00 }
        $n2s_02 = { 20 00 10 41 41 41 FC FF FF 07 00 22 28 F0 0B 60 F7 F4 1F 00 00 00 00 }
        $n2s_03 = { 20 00 18 41 41 41 FC FF FF 07 00 22 28 F0 0B 60 F7 F4 1F 00 00 00 }
        $n2s_04 = { 20 00 10 41 41 41 FC FF FF 0F 00 22 28 F0 0B 60 F7 F4 1F 00 00 00 }
        // N2S-05: 8-byte header + first 32 of the 1,024 'A' bytes; the condition checks the last 4
        $n2s_05 = { 1B 00 00 00 00 00 00 00  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41 }
        $n2s_06 = { 1B 01 00 00 24 79 B1 6F 50 C0 03 05 00 C0 00 00 00 00 00 00 00 03 }
    condition:
        any of ($n2s_01, $n2s_02, $n2s_03, $n2s_04, $n2s_06)
        or for any i in (1..#n2s_05) : ( uint32(@n2s_05[i] + 1028) == 0x41414141 )
}

rule IONSEC_Node2Shell_Trigger_Seed_HexText
{
    meta:
        author = "IONSEC"
        date = "2026-10-24"
        description = "Node2Shell (CVE-2026-111497) trigger seeds written as hex text, as embedded by public PoCs, scanners and patch self-tests (source files, scripts, notebooks)"
        cve = "CVE-2026-111497"
        n2s_ids = "N2S-01 N2S-02 N2S-03 N2S-04 N2S-06"
        provenance = "DERIVED: hex-text rendering of the VERBATIM byte strings of N2S-01..04 and N2S-06, the form in which the brief's sources carry them (hypnguyen1209 exploit/poc.py literal hex streams, Ostorlab DIFFERENTIAL_BLOCK_SWITCH_PAYLOAD, Ghost-Bx1 fallback stream); the N2S-01 text is a prefix of the N2S-02 text"
        confidence = "hunting, low"
        false_positives = "Mostly defensive code: Node's regression test, Ostorlab's scanner, patch known-answer tests in more than 12 public repos. Useful to find PoC tooling staged on hosts where no such code belongs."
        reference = "https://github.com/hypnguyen1209/CVE-2026-111497"
    strings:
        $hex_01 = "200010414141fcffff07002228f00b60f7f41f000000" ascii wide nocase
        $hex_03 = "200018414141fcffff07002228f00b60f7f41f000000" ascii wide nocase
        $hex_04 = "200010414141fcffff0f002228f00b60f7f41f000000" ascii wide nocase
        $hex_06 = "1b0100002479b16f50c0030500c00000000000000003" ascii wide nocase
    condition:
        filesize < 20MB and any of them
}

/* ---------------------------------------------------------------------------
   B. Decoder inventory (N2S-23)
   --------------------------------------------------------------------------- */

rule IONSEC_Node2Shell_Unfixed_Brotli_Decoder_Embedded
{
    meta:
        author = "IONSEC"
        date = "2026-10-24"
        description = "Executable embeds a Google Brotli decoder (1.1.0+ naming, or Node's zlib constants) built WITHOUT the CVE-2026-111497 fix: _ERROR_FORMAT_BLOCK_LENGTH_1 present, _ERROR_FORMAT_BLOCK_SWITCH absent, no reference to a shared libbrotlidec. Typical hits: official node binaries before 22.23.4/24.22.1/26.12.1 (and every EOL line), bun before 1.4.4, Python _brotli/_brotlicffi extensions before 1.2.1/1.2.1.0, Electron frameworks with a pre-fix Node."
        cve = "CVE-2026-111497"
        n2s_ids = "N2S-23"
        provenance = "DERIVED: the BLOCK_SWITCH code (-17) and its name exist only in fixed brotli (git log -S: 0ed4268/b418fa8/da98063/50a9b70); Node v26.12.0 has 0 occurrences, v26.12.1 has 1 (brief section 7). See file header for the full derivation."
        confidence = "inventory"
        verdict = "decoder without the fix (embedded)"
        false_positives = "A binary that embeds the error table but whose decoder is never fed untrusted data is still unfixed, only less exposed. Binaries that contain the string libbrotlidec for an unrelated reason fall into the linked-consumer rule instead."
        reference = "https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b"
    strings:
        $len1   = "_ERROR_FORMAT_BLOCK_LENGTH_1" ascii
        $switch = "_ERROR_FORMAT_BLOCK_SWITCH" ascii
        $so     = "libbrotlidec" ascii
        $dll    = "brotlidec.dll" ascii nocase
    condition:
        IONSEC_N2S_Executable and $len1 and not $switch and not $so and not $dll
}

rule IONSEC_Node2Shell_Unfixed_Brotli_Decoder_Library
{
    meta:
        author = "IONSEC"
        date = "2026-10-24"
        description = "libbrotlidec (or a binary that names it and also carries its own 1.1.0+ decoder table) built WITHOUT the CVE-2026-111497 fix: stand-alone, NUL-bounded _ERROR_FORMAT_BLOCK_LENGTH_1 table entry present, _ERROR_FORMAT_BLOCK_SWITCH absent. Typical hits: libbrotlidec.so.1 / libbrotlidec.1.dylib / brotlidec.dll from brotli 1.1.0 to 1.2.0 without the distro fix."
        cve = "CVE-2026-111497"
        n2s_ids = "N2S-23"
        provenance = "DERIVED: same derivation as the embedded rule; the NUL-bounded form proves the decoder's own string table (a consumer only holds the longer BROTLI_DECODER_ERROR_FORMAT_* constant names)"
        confidence = "inventory"
        verdict = "decoder without the fix (library)"
        false_positives = "Distro builds that backport the fix keep their old version number but gain the BLOCK_SWITCH name and therefore do not match; a match means the fix is absent from this file."
        reference = "https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b"
    strings:
        $len1_table = "\x00_ERROR_FORMAT_BLOCK_LENGTH_1\x00" ascii
        $switch     = "_ERROR_FORMAT_BLOCK_SWITCH" ascii
        $so         = "libbrotlidec" ascii
        $dll        = "brotlidec.dll" ascii nocase
    condition:
        IONSEC_N2S_Executable and $len1_table and not $switch and ($so or $dll)
}

rule IONSEC_Node2Shell_Brotli_Linked_Consumer_PreFix_Constants
{
    meta:
        author = "IONSEC"
        date = "2026-10-24"
        description = "INFORMATIONAL: binary links a shared libbrotlidec and carries pre-fix Brotli error constants (e.g. a Node.js built with --shared-brotli from a pre-fix source tree: Debian/Ubuntu nodejs, Homebrew node). Its decoder is the linked library - check that file (library rule, 1.0.x rule) or the distro brotli package version; the Node version alone says nothing."
        cve = "CVE-2026-111497"
        n2s_ids = "N2S-23"
        provenance = "DERIVED: brief section 3/5.3 (Debian nodejs links the system libbrotli; --shared-brotli moves the fix to the distro brotli package)"
        confidence = "inventory, informational"
        verdict = "unknown: depends on the linked libbrotlidec"
        false_positives = "Unstripped libraries whose DWARF debug strings hold the enum names can land here; classify them by package version."
        reference = "https://security-tracker.debian.org/tracker/CVE-2026-111497"
    strings:
        $len1       = "_ERROR_FORMAT_BLOCK_LENGTH_1" ascii
        $len1_table = "\x00_ERROR_FORMAT_BLOCK_LENGTH_1\x00" ascii
        $switch     = "_ERROR_FORMAT_BLOCK_SWITCH" ascii
        $so         = "libbrotlidec" ascii
        $dll        = "brotlidec.dll" ascii nocase
    condition:
        IONSEC_N2S_Executable and $len1 and not $len1_table and not $switch and ($so or $dll)
}

rule IONSEC_Node2Shell_Unfixed_Brotli_1_0_x_Decoder
{
    meta:
        author = "IONSEC"
        date = "2026-10-24"
        description = "Executable or library carrying a brotli 1.0.x decoder error table (bare names, no _ERROR_FORMAT_ prefix) WITHOUT the CVE-2026-111497 fix: BLOCK_LENGTH_1 and EXUBERANT_META_NIBBLE present, BLOCK_SWITCH absent. Typical hits: libbrotlidec 1.0.x without the distro update (e.g. Debian bookworm libbrotli1 before 1.0.9-2+deb12u1), PyPI Brotli 1.0.x extensions, RubyGems brotli 0.4.0."
        cve = "CVE-2026-111497"
        n2s_ids = "N2S-23"
        provenance = "DERIVED: brotli 1.0.x BrotliDecoderErrorString() returns #NAME (google/brotli v1.0.3/v1.0.9/v1.0.10 versus #PREFIX #NAME from v1.1.0); the 1.0.x-branch fix (v1.0.10, 50a9b70) adds BLOCK_SWITCH to that bare table. Added at the IONSEC coordinator's request after verification against the tags."
        confidence = "inventory"
        verdict = "decoder without the fix (brotli 1.0.x)"
        false_positives = "Stands down when any _ERROR_FORMAT_ string is present (1.1.0+ tables, Node's zlib constants, DWARF enum names): the prefixed rules decide those files. Another library that happens to contain both bare names and no BLOCK_SWITCH would match; none is known."
        reference = "https://github.com/google/brotli/commit/50a9b70"
    strings:
        $bare_len1   = "BLOCK_LENGTH_1\x00" ascii
        $bare_meta   = "EXUBERANT_META_NIBBLE\x00" ascii
        $bare_switch = "BLOCK_SWITCH\x00" ascii
        $prefix      = "_ERROR_FORMAT_" ascii
    condition:
        IONSEC_N2S_Executable and $bare_len1 and $bare_meta and not $bare_switch and not $prefix
}

/* ---------------------------------------------------------------------------
   C. Vendored source (N2S-24)
   --------------------------------------------------------------------------- */

rule IONSEC_Node2Shell_Unfixed_Brotli_DecodeC_Source
{
    meta:
        author = "IONSEC"
        date = "2026-10-24"
        description = "Vendored Google Brotli decode.c (or an amalgamation containing it) WITHOUT the CVE-2026-111497 fix: DecodeBlockTypeAndLength() returns BROTLI_FALSE for max_block_type <= 1 and BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH is absent. Look in source trees, node_modules native addons, vendored C dependencies, Python sdists."
        cve = "CVE-2026-111497"
        n2s_ids = "N2S-24"
        provenance = "DERIVED from the fix diff 0ed4268a: pre-fix 'if (max_block_type <= 1) { return BROTLI_FALSE; }' becomes 'return BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;' (present from v1.0.3, commit 35e69fc, to v1.2.0; v1.0.2 has no such check and does not match)"
        confidence = "inventory"
        verdict = "source without the fix"
        false_positives = "Forks that fixed the bug differently (without the BLOCK_SWITCH code) would match; check the code."
        reference = "https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b"
    strings:
        $fn    = "DecodeBlockTypeAndLength" ascii
        $vuln  = /max_block_type\s*<=\s*1\s*\)\s*\{?\s*return\s+BROTLI_FALSE\s*;/ ascii
        $fixed = "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" ascii
    condition:
        filesize < 5MB and $fn and $vuln and not $fixed
}
