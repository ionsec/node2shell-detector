# Edge mitigations — Node2Shell (CVE-2026-111497)

Ready-to-paste snippets that stop Brotli data from reaching a vulnerable decoder at the
edge. They mitigate. The fix is patching the runtime or library decoder: Node.js 22.23.4,
24.22.1 and 26.12.1; Bun 1.4.4; brotli 1.0.10, 1.1.1 and 1.2.1; or the distro `brotli`
package when Node is built with `--shared-brotli`. No npm or PyPI package upgrade fixes
the decoder by itself.

Compiled 2026-10-24 by IONSEC. Fingerprint provenance: N2S-11 (DERIVED) and N2S-13
(VERBATIM, Indusface vendor logic). See `../references/node2shell-sources.md`.

## Inbound: reject request bodies declared `Content-Encoding: br`

| File | Platform | Status | Duplicate headers |
|---|---|---|---|
| `nginx-inbound-reject-br.conf` | nginx (map + server-level `if`) | 415 | nginx 1.23+ joins repeats in `$http_*`, so br in a second header is seen. Older nginx sees only the first. |
| `apache-inbound-reject-br.conf` | Apache httpd: mod_rewrite (415) or `<If>` (403) | 415 / 403 | httpd merges repeats into one list before the check |
| `haproxy-inbound-reject-br.cfg` | HAProxy 2.2+ `http-request return` (older: `deny` 403) | 415 | `req.hdr` tries every comma value of every instance; `req.fhdr_cnt > 1` rejects duplicates |
| `envoy-inbound-reject-br.yaml` | Envoy route match → `direct_response`, or a first-position Lua filter | 415 | header matchers and Lua `get()` see the comma-joined value |
| `cloudflare-waf-custom-rules.txt` | Cloudflare WAF custom rule (`contains` on all plans, `matches` regex where available) | plan default, or 415 as a custom response | one array element per header instance |
| `aws-waf-reject-br-rule.json` | AWS WAF v2 rule (ByteMatch, `content-encoding`, LOWERCASE, CONTAINS) | 415 custom response | not verified for SingleHeader; see notes |
| `azure-frontdoor-reject-br-rule.json` | Azure Front Door WAF custom rule (`RequestHeader`) | policy-wide block code | not verified |
| `azure-appgw-reject-br-rule.json` | Azure Application Gateway WAF v2 custom rule (`RequestHeaders`) | policy-wide block code | not verified |

All inbound snippets match the token `br` in any case, alone or inside a list (`gzip, br`,
`BR`, ` br ; x`), and not `brotli` or `x-br`. The exception is the Cloudflare `contains`
option and the AWS/Azure `Contains` operators, which are substring matches; see the
caveat below. Vendors give the same advice: Aikido matches br case-insensitively inside
lists, and Indusface AppTrana blocks list variants and duplicate Content-Encoding headers.

### Why 415

415 Unsupported Media Type is what the Node ecosystem already answers for request
codings it does not handle:

- body-parser 1.x / Express 4 answers 415 for `br`;
- body-parser 2.x answers 415 for every coding when `inflate: false`;
- `inflation` (co-body) and `@fastify/compress` answer 415 for unsupported codings.

Clients and monitoring then see a familiar "coding not supported" answer that will not be
retried, not a generic WAF 403. RFC 9110 §15.5.16 says the server ought to list the
codings it accepts in `Accept-Encoding`. The HAProxy, Envoy-Lua and app snippets send
`Accept-Encoding: gzip, deflate`; the others cannot add it portably.

### Platform notes

- **Cloudflare.** The WAF changelog through 22 Oct shows no managed rule for
  CVE-2026-111497. Option 1 (`contains`) works on every plan. It is a substring match, so a
  made-up coding such as `x-brotli` would also match. No registered request coding other
  than br contains the letters "br", so the over-match is theoretical, and it can never
  miss a br token. Option 2 (`matches`) is token-exact but needs a plan that includes the
  regex operator. A custom 415 response depends on your plan's Block options.
- **AWS WAF.** Paste the JSON into the rule JSON editor of a web ACL. With the API or
  CLI, `SearchString` is a blob: the console and SDKs accept plain text, but AWS CLI v2
  needs `--cli-binary-format raw-in-base64-out` (or the base64 value `YnI=`). `CONTAINS` is
  a substring match (same caveat as Cloudflare). The behaviour of `SingleHeader` with a
  repeated header was not verified. If you need duplicates covered, add a second statement
  on `Headers` with `MatchPattern.IncludedHeaders: ["content-encoding"]`. AWS has no managed
  rule for this CVE (brief §6).
- **Azure.** These files are single entries for the `customRules` array of a Front Door
  WAF policy (`Microsoft.Network/FrontDoorWebApplicationFirewallPolicies`) or an
  Application Gateway WAF policy (`Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies`).
  The two schemas differ: Front Door uses `matchVariable: RequestHeader` and
  `negateCondition`; Application Gateway uses `matchVariables[].variableName:
  RequestHeaders` and the API's own spelling `negationConditon`. The block status is set
  once per policy (`customBlockResponseStatusCode`), and 415 is not among the documented
  choices, so these rules answer 403 (or whatever your policy sets). The third-party rule
  `cve-2026-111497-resp-strip-br` published by AdapptOnAzure is not Microsoft's.
- **nginx.** Keep the `if` at server level (only `return` inside). For path-scoped
  allowlisting, move it into the locations that need it.
- **Envoy.** Upgrade first if you run the brotli decompressor filter (GHSA-3wvj-j6qm-62mr:
  affected through 1.36.11, 1.37.7, 1.38.5 and 1.39.2). The route option runs in the
  router, after earlier HTTP filters. The Lua option runs first.

### Allowlisting known Brotli senders

The Apify JavaScript API client brotli-compresses request bodies of 1,024 bytes or more by
default (docs.apify.com). Every snippet has a commented allowlist hook. Allow by path
**and** source address, only in front of a patched decoder, and prefer changing the sender:
`new ApifyClient({ compression: 'gzip' })` is a documented client option. Never allowlist
by User-Agent.

## Outbound: responses your application fetches

A WAF in front of your app only sees requests coming in. It never sees the responses your
app pulls from other servers. Vercel says so about its own Node2Shell WAF rules: they
"do not cover responses the app fetches". Built-in `fetch()` (undici), axios ≥ 1.0, got,
node-fetch 3, needle, superagent, npm (minipass-fetch), Bun `fetch` and Python
requests/httpx/aiohttp with Brotli installed all decode a `Content-Encoding: br` response
automatically. A malicious server can send br whatever the client asked for. Webhooks,
link previews and unfurlers, oEmbed, image and avatar proxies, crawlers and SSR of
user-supplied URLs are SSRF-shaped: no inbound request is needed.

| File | Platform | Action |
|---|---|---|
| `haproxy-egress-deny-br.cfg` | HAProxy egress backend | rewrites `br` in Accept-Encoding to `identity`; `http-response deny deny_status 502` when the response Content-Encoding has the br token |
| `envoy-egress-br-guard.yaml` | Envoy egress / sidecar (Lua) | rewrites Accept-Encoding; on a br response, removes Content-Encoding, sets status 502 and tags the response |
| `nginx-egress-strip-br.conf` | nginx relay or plain-HTTP forward proxy | asks for gzip/deflate only; on a br response, strips Content-Encoding (body passes undecoded) and tags the response |

Things to know before deploying:

- **The proxy must see HTTP.** A CONNECT tunnel carrying TLS end to end is opaque to every
  proxy. Originate TLS at the egress proxy (the app speaks plain HTTP to it), or use a
  TLS-terminating egress. Otherwise fall back on the app-level client switches in
  `../app/README.md`, and patch.
- **Strip versus reject.** Removing `Content-Encoding` is safe: client libraries only run
  the Brotli decoder when the header says br, so they hand the raw bytes to the app as
  identity. Rejecting with 502 is cleaner where the proxy can do it (HAProxy).
- **Never "fix" egress by decoding at the proxy.** Envoy's brotli decompressor is itself
  affected on unpatched versions. nginx `ngx_brotli` and Apache `mod_brotli` are encoders
  only and are not affected.
- **Normal traffic.** Outbound `Accept-Encoding: br` from Node clients is normal (undici,
  axios, got, node-fetch 3, needle). Do not alert on it. Rewriting it is only a way to keep
  honest servers from answering br.

## Test checklist (lab, after deploying)

```
curl -si -X POST -H 'Content-Encoding: br'        --data-binary 'x' https://lab.example/api   # expect 415 (or 403 on Azure, <If>, old HAProxy)
curl -si -X POST -H 'Content-Encoding: GZIP, br'  --data-binary 'x' https://lab.example/api   # expect 415
curl -si -X POST -H 'Content-Encoding: gzip'      --data-binary 'x' https://lab.example/api   # expect NOT 415
curl -si -X POST -H 'Content-Encoding: brotli'    --data-binary 'x' https://lab.example/api   # token-exact snippets: NOT 415; substring rules (Cloudflare option 1, AWS, Azure): 415
```

The body `x` is not Brotli data. These checks exercise only the header logic and never
send the trigger.
