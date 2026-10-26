'use strict';
// IONSEC node2shell detector — Fastify guard for CVE-2026-111497 (Node2Shell)
// Fastify core does not decode request bodies; @fastify/compress does, on every route,
// once registered (request decompression is on by default and br is a default
// requestEncodings entry). Two layers below: an onRequest hook (runs before preParsing,
// where @fastify/compress decodes) and safe @fastify/compress options.
// Option names checked against @fastify/compress 9.2.2 (index.js processDecompressParams).
// Run: node fastify-reject-br.js   (needs: npm i fastify @fastify/compress)

const fastify = require('fastify')({ logger: true });

// "br" as a coding token: any case, alone or in a list ("gzip, br"); not "brotli"/"x-br".
const BR_TOKEN = /(?:^|[\s,])br(?:[\s,;]|$)/i;

// Layer 1: reject before any body handling. Added on the root instance, so it applies to
// every route, including routes registered by plugins later.
fastify.addHook('onRequest', async (request, reply) => {
  const ce = request.headers['content-encoding'];
  if (typeof ce === 'string' && BR_TOKEN.test(ce)) {
    reply
      .code(415)
      .header('Accept-Encoding', 'gzip, deflate')
      .header('Connection', 'close')
      .send({ error: 'Unsupported Content-Encoding' });
    return reply; // mandatory in async hooks: stops the lifecycle here
  }
});

// Layer 2: keep response compression, configure request decompression safely.
fastify.register(require('@fastify/compress'), {
  // A) no request decompression at all (default is true):
  globalDecompression: false,
  // B) or keep gzip/deflate request decompression and drop br. Unsupported codings then
  //    get 415 FST_CP_ERR_INVALID_CONTENT_ENCODING:
  // requestEncodings: ['gzip', 'deflate', 'identity'],
});
// GOTCHA (from the plugin source): a per-route `decompress: { ... }` object recomputes
// requestEncodings from its own options, where the default list includes br, and it turns
// decompression back on for that route even with globalDecompression: false. Repeat
// requestEncodings in every per-route decompress object, or use `decompress: false`.

fastify.post('/echo', async (request) => ({ received: request.body ?? null }));

if (require.main === module) {
  fastify.listen({ port: Number(process.env.PORT) || 3000 }).catch((err) => {
    fastify.log.error(err);
    process.exit(1);
  });
}

module.exports = { fastify, BR_TOKEN };
