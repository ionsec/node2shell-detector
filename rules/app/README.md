# App-level mitigations — Node2Shell (CVE-2026-111497)

Small, runnable guards that refuse `Content-Encoding: br` request bodies **before** any
body parser hands them to the Brotli decoder. They are stopgaps for hosts you cannot
patch today. The fix is the runtime or library decoder: Node.js 22.23.4 / 24.22.1 /
26.12.1, Bun 1.4.4, PyPI Brotli 1.2.1 / brotlicffi 1.2.1.0, or the distro `brotli` package
for `--shared-brotli` builds. Upgrading npm packages does not fix the decoder. Every
Node-side decoder below ends in Node's own `zlib.createBrotliDecompress`.

Compiled 2026-10-24 by IONSEC from the research brief (§5.1, §5.2). Option names were
checked against local clones: `@fastify/compress` 9.2.2, `@koa/bodyparser` 6.1.0,
`koa-body` 8.0.1, aiohttp 3.14.5.

| File | Framework | Decodes br by default? (brief §5.1) | Guard |
|---|---|---|---|
| `express-reject-br.js` | Express 5 / body-parser 2.x (also Parse Server, Strapi-style stacks on Express) | YES: `inflate` defaults to true | middleware registered before `express.json()`; alternative `inflate: false` |
| `koa-reject-br.js` | Koa + co-body ≥ 5 (inflation 2.1.0), `@koa/bodyparser`, `koa-bodyparser`, `koa-body` | YES | middleware registered before the body parser |
| `fastify-reject-br.js` | Fastify + `@fastify/compress` | YES on every route once the plugin is registered (Fastify core: no) | `onRequest` hook, plus `globalDecompression: false` or `requestEncodings` without br |
| `nest-main.ts` | NestJS 11+ on `@nestjs/platform-express` (Express 5) | YES (Nest 8–10 on Express 4: no, 415) | `bodyParser: false`, guard, then `useBodyParser(...)` |
| `aiohttp_no_br.py` | Python aiohttp server with Brotli installed | YES (`auto_decompress=True`) | `handler_args={"auto_decompress": False}`, plus a 415 middleware |

All guards answer **415** with `Accept-Encoding: gzip, deflate`, the same status
body-parser 1.x, `inflation` and `@fastify/compress` use for unsupported codings
(RFC 9110 §15.5.16). They match `br` case-insensitively, also inside lists
(`gzip, br`), with token boundaries (not `brotli`), and check every instance of a
repeated header. Node joins repeats with `", "`; aiohttp uses `getall()`.

## Placement rules (where these guards fail)

- **Express / Koa / Nest.** The guard must run before the first parser. A parser
  registered earlier, or mounted on a router that runs first, decodes before the guard
  sees the request. Route-level parsers (`router.post('/x', express.json(), h)`) are fine
  as long as the guard is app-level.
- **Fastify.** Hooks added on the root instance apply to every route. A hook added
  inside an encapsulated plugin only covers that plugin. `@fastify/compress` decodes in
  `preParsing`, which runs after `onRequest`.
  - Gotcha read in the plugin source: a per-route `decompress: { ... }` object recomputes
    `requestEncodings` from its own options (the default list includes br) and turns
    decompression back on for that route, even with `globalDecompression: false`.
  - Repeat `requestEncodings` in every per-route `decompress` object, or use
    `decompress: false`.
- **aiohttp.** A middleware alone is **not** enough. aiohttp's parser decompresses body
  bytes as they arrive, inside `feed_data()`, before middleware runs (aiohttp 3.14.5
  `http_parser.py`, `DeflateBuffer`). Only `auto_decompress=False` stops the decoder. Cost:
  gzip, deflate and zstd request bodies are no longer decompressed either.
- **Apollo Server standalone** decodes with no switch (body-parser JSON). Put it behind a
  br-rejecting proxy (`../edge/`), or run it through Express with the guard.
- **`inflate: false` (Express).** Rejects every compressed body, gzip and deflate too, with
  415 "content encoding unsupported". It is simple and complete, but clients that gzip
  uploads break.

## Known legitimate senders

The Apify JavaScript API client brotli-compresses request bodies of 1,024 bytes or more by
default (docs.apify.com). If you operate an Apify-API-compatible endpoint, either keep that
service on a patched runtime and exempt only its route from the guard, or have the client
send gzip: `new ApifyClient({ compression: 'gzip' })`.

## Outbound: client-side exposure (not covered by these guards)

Your app is also exposed when it **fetches** from a server the attacker controls
(webhooks, link previews, image proxies, crawlers, SSR of user-supplied URLs, npm through
an untrusted registry). Switches from the brief (§5.2):

| Client | Decodes br responses | Switch |
|---|---|---|
| built-in `fetch()` (undici) | YES, whenever the response says br, even if not requested | none; `Accept-Encoding: identity` only changes what is asked for. Patch, or use an egress guard (`../edge/`). |
| axios ≥ 1.0 | YES | `decompress: false` |
| got 11–16 | YES (decompress-response) | `decompress: false` |
| node-fetch 3 | YES | `compress: false` |
| needle, superagent, ky (via fetch) | YES | — (patch / egress guard) |
| Bun < 1.4.4 `fetch` | YES, default-on | none: upgrade to Bun 1.4.4 |
| Python requests / httpx / urllib3 with Brotli installed | YES | upgrade Brotli / brotlicffi |

With decompression off, the client returns compressed bytes your code must handle. Never
alert on outbound `Accept-Encoding: br` from Node clients. It is their normal default.

## Quick check (header logic only)

```
node express-reject-br.js &
curl -si -X POST -H 'Content-Type: application/json' -H 'Content-Encoding: br'   --data-binary 'x' http://127.0.0.1:3000/echo   # 415
curl -si -X POST -H 'Content-Type: application/json' -H 'Content-Encoding: gzip, BR' --data-binary 'x' http://127.0.0.1:3000/echo # 415
curl -si -X POST -H 'Content-Type: application/json' --data '{"a":1}' http://127.0.0.1:3000/echo                              # 200
```

The body `x` is not Brotli data, so the check never exercises the decoder. Do not send the
public trigger seed to an unpatched runtime outside an isolated lab.
