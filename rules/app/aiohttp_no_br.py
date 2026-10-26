"""IONSEC node2shell detector — aiohttp server guard for CVE-2026-111497 (Node2Shell).

aiohttp is the one Python server found that decodes "Content-Encoding: br" request bodies
by default (auto_decompress=True) when the Brotli/brotlicffi package is installed. That
package bundles the vulnerable Google Brotli C decoder up to Brotli 1.2.0 /
brotlicffi 1.2.0.2 (fixed: Brotli 1.2.1, brotlicffi 1.2.1.0).

Why a middleware alone is NOT enough here (aiohttp 3.14.5 source, http_parser.py):
the request parser wraps the payload in DeflateBuffer as soon as the headers are parsed,
and body bytes that arrive in the same read are decompressed inside feed_data(), before
any middleware or handler runs. The server-level switch below stops that: with
auto_decompress=False the parser never builds a decoder. The middleware then answers
415 so compressed bodies are not mistaken for plain ones.

COST: auto_decompress=False turns off gzip/deflate/zstd request decompression too.
Clients that send gzip bodies need explicit handling.

auto_decompress is a RequestHandler option (aiohttp >= 3.8). Three equivalent ways to set
it, checked against aiohttp 3.14.5:
  web.Application(handler_args={"auto_decompress": False})   # used below
  web.run_app(app, auto_decompress=False)                     # kwargs -> AppRunner -> Server
  web.AppRunner(app, auto_decompress=False)

Run: python3 aiohttp_no_br.py   (needs: pip install aiohttp)
"""

import re

from aiohttp import web

# "br" as a coding token: any case, alone or in a list ("gzip, br"); not "brotli"/"x-br".
BR_TOKEN = re.compile(r"(?:^|[\s,])br(?:[\s,;]|$)", re.IGNORECASE)


@web.middleware
async def reject_brotli_request_bodies(request, handler):
    # getall(): repeated Content-Encoding headers are separate entries in aiohttp
    content_encoding = ", ".join(request.headers.getall("Content-Encoding", []))
    if BR_TOKEN.search(content_encoding):
        raise web.HTTPUnsupportedMediaType(
            text="Unsupported Content-Encoding",
            headers={"Accept-Encoding": "gzip, deflate"},
        )
    return await handler(request)


async def echo(request):
    body = await request.read()  # raw bytes: nothing was decompressed by the server
    return web.json_response({"received_bytes": len(body)})


def make_app():
    app = web.Application(
        middlewares=[reject_brotli_request_bodies],
        handler_args={"auto_decompress": False},
    )
    app.router.add_post("/echo", echo)
    return app


if __name__ == "__main__":
    web.run_app(make_app(), port=8080)
