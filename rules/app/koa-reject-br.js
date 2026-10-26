'use strict';
// IONSEC node2shell detector — Koa guard for CVE-2026-111497 (Node2Shell)
// co-body >= 5 (through inflation 2.1.0), @koa/bodyparser, koa-bodyparser and koa-body
// decode br request bodies by default. Register the guard BEFORE the body parser.
// Run: node koa-reject-br.js   (needs: npm i koa @koa/bodyparser)

const Koa = require('koa');
const { bodyParser } = require('@koa/bodyparser'); // koa-body: const { koaBody } = require('koa-body')

// "br" as a coding token: any case, alone or in a list ("gzip, br"); not "brotli"/"x-br".
const BR_TOKEN = /(?:^|[\s,])br(?:[\s,;]|$)/i;

async function rejectBrotliRequestBodies(ctx, next) {
  const ce = ctx.get('Content-Encoding'); // '' when absent; repeats joined with ", "
  if (ce && BR_TOKEN.test(ce)) {
    // Set the response directly: ctx.throw() would go through Koa's error handler, which
    // drops headers set beforehand.
    ctx.status = 415;
    ctx.set('Accept-Encoding', 'gzip, deflate');
    ctx.set('Connection', 'close');
    ctx.body = 'Unsupported Content-Encoding';
    return; // next() is never called: no parser reads the body
  }
  await next();
}

const app = new Koa();
app.use(rejectBrotliRequestBodies);   // 1) guard
app.use(bodyParser());                // 2) parser after it

app.use((ctx) => {
  ctx.body = { received: ctx.request.body ?? null };
});

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => console.log(`listening on :${port}`));
}

module.exports = { rejectBrotliRequestBodies, BR_TOKEN };
