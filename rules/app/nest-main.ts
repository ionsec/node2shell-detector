// IONSEC node2shell detector — NestJS 11+ (platform-express, Express 5) guard for
// CVE-2026-111497 (Node2Shell)
// Nest 11/12 run on Express 5, whose built-in parsers (body-parser 2.x) decode br request
// bodies by default; Nest 8-10 (Express 4) answer 415. Nest+Fastify does not decode bodies
// unless you add @fastify/compress (see fastify-reject-br.js).
// Recipe: turn Nest's automatic parsers off, install the guard, then re-add the parsers
// you need so they run AFTER the guard.
// Drop-in replacement for src/main.ts (needs @nestjs/core, @nestjs/platform-express).

import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import type { NextFunction, Request, Response } from 'express';
import { AppModule } from './app.module';

// "br" as a coding token: any case, alone or in a list ("gzip, br"); not "brotli"/"x-br".
const BR_TOKEN = /(?:^|[\s,])br(?:[\s,;]|$)/i;

export function rejectBrotliRequestBodies(req: Request, res: Response, next: NextFunction): void {
  const ce = req.headers['content-encoding']; // Node joins repeated headers with ", "
  if (typeof ce === 'string' && BR_TOKEN.test(ce)) {
    res.set({ 'Accept-Encoding': 'gzip, deflate', Connection: 'close' });
    res.status(415).type('text/plain').send('Unsupported Content-Encoding');
    return;
  }
  next();
}

async function bootstrap(): Promise<void> {
  // bodyParser: false -> Nest does not register express.json()/urlencoded() on its own.
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false });

  app.use(rejectBrotliRequestBodies);                   // 1) guard first
  app.useBodyParser('json');                            // 2) then the parsers you need
  app.useBodyParser('urlencoded', { extended: true });
  // If your Nest version lacks useBodyParser: app.use(express.json()) after the guard.

  await app.listen(Number(process.env.PORT) || 3000);
}

void bootstrap();
