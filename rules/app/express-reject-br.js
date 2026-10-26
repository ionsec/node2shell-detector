'use strict';
// IONSEC node2shell detector — Express guard for CVE-2026-111497 (Node2Shell)
// Rejects request bodies declared Content-Encoding br BEFORE any body parser reads them.
// Express 5 / body-parser 2.x decode br by default (inflate: true); Express 4 / body-parser
// 1.x already answer 415. Register the guard FIRST, above express.json() and friends.
// Run: node express-reject-br.js   (needs: npm i express)

const express = require('express');

// "br" as a coding token: any case, alone or in a list ("gzip, br"); not "brotli"/"x-br".
const BR_TOKEN = /(?:^|[\s,])br(?:[\s,;]|$)/i;

function rejectBrotliRequestBodies(req, res, next) {
  const ce = req.headers['content-encoding']; // Node joins repeated headers with ", "
  if (typeof ce === 'string' && BR_TOKEN.test(ce)) {
    // 415 like body-parser itself; Accept-Encoding per RFC 9110 15.5.16. Connection: close
    // lets Node discard the unread body without ever handing it to zlib.
    res.set({ 'Accept-Encoding': 'gzip, deflate', Connection: 'close' });
    res.status(415).type('text/plain').send('Unsupported Content-Encoding');
    return;
  }
  next();
}

const app = express();
app.use(rejectBrotliRequestBodies);          // 1) guard
app.use(express.json());                     // 2) parsers after it
app.use(express.urlencoded({ extended: false }));

// Alternative without custom code: switch decompression off in every body parser.
// COST: gzip and deflate request bodies are rejected too (415 "content encoding unsupported").
// app.use(express.json({ inflate: false }));
// app.use(express.urlencoded({ extended: false, inflate: false }));
// app.use(express.raw({ inflate: false }));
// app.use(express.text({ inflate: false }));

app.post('/echo', (req, res) => res.json({ received: req.body }));

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => console.log(`listening on :${port}`));
}

module.exports = { rejectBrotliRequestBodies, BR_TOKEN };
