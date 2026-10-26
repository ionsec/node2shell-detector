"""DEPENDENCY EXPOSURE: which projects hand attacker bytes to a Brotli decoder.

RULE OF THUMB (BRIEF s5): an npm / PyPI package only decides *reachability*; the
runtime or library decoder decides *exploitability*. All Node-side npm decoders below
end in Node's own `zlib.createBrotliDecompress` - no npm upgrade fixes anything and no
npm downgrade is needed. So:

  server-side request-body decoder present (BRIEF s5.1)   -> warn; escalated to critical
                                                              when posture found a vulnerable
                                                              runtime in the same run
  client-side response decoder present   (BRIEF s5.2)     -> info; warn with a vulnerable runtime
  usage the tool cannot see (http-proxy-middleware responseInterceptor, next images,
  graphql-yoga / @whatwg-node plugin, n8n partly)         -> info, always
  Express 4 / body-parser 1.x (rejects br with 415)       -> ok

Parsed: package-lock.json (v1/v2/v3) / npm-shrinkwrap.json, yarn.lock (classic + berry),
pnpm-lock.yaml (v5/v6/v9, line parsing), bun.lock (text), node_modules (bounded walk of
package.json / .pnpm directory names); Python requirements*.txt / poetry.lock / uv.lock /
pdm.lock / Pipfile.lock; go.mod / go.sum; Cargo.lock; Gemfile.lock; pom.xml / build.gradle;
Dockerfiles (and compose `image:` lines) for node / oven/bun tags.

Deliberately NOT done: package.json ranges are not resolved (only lockfile / installed
versions are evaluated); usage of a library inside your code is not analysed.
"""

import json
import os
import re
from collections import OrderedDict, defaultdict
from typing import Callable, NamedTuple, Optional

from . import fingerprints as fp, versions
from .report import finding

MAX_DEPTH = 8
MAX_DIRS = 60_000
MAX_NM_PACKAGES = 40_000
MAX_LOCK_BYTES = 128 * 1024 * 1024
MAX_PKG_JSON_BYTES = 1024 * 1024
SKIP_DIR_NAMES = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox",
                  ".mypy_cache", ".pytest_cache", "target", "dist", "build", ".gradle"}

PY_INTEREST = {"brotli", "brotlicffi", "brotlipy", "aiohttp", "scrapy", "requests", "httpx", "urllib3"}
PY_CONSUMERS = ("scrapy", "requests", "httpx", "urllib3")


class Pkg(NamedTuple):
    eco: str        # npm | pypi | go | cargo | gem | maven | docker
    name: str
    version: str
    source: str     # file the version came from
    extra: str = "" # pypi: requirement operator ('' = resolved/locked); docker: kind


# ---------------------------------------------------------------------------
# npm exposure table (BRIEF s5.1 / s5.2) - copied from the brief, ranges verbatim
# ---------------------------------------------------------------------------

def _ge(*t) -> Callable:
    return lambda v: versions.cmp_tuple(v, t) >= 0


def _major(m: int) -> Callable:
    return lambda v: v[0] == m


def _major_range(lo: int, hi: int) -> Callable:
    return lambda v: lo <= v[0] <= hi


def _any(_v) -> bool:
    return True


def _koa_bodyparser(v: tuple) -> bool:
    """koa-bodyparser decodes br in 2.4.0, 2.5.x, 4.1.0, 4.2.x-4.4.x (not 2.0-2.3, 3.x, 4.0.0)."""
    c = versions.cmp_tuple
    return (c(v, (2, 4, 0)) >= 0 and v[0] == 2) or (v[0] == 4 and c(v, (4, 1, 0)) >= 0)


# name -> (kind, predicate, affected range as printed, what it does, the brief's switch)
NPM_RULES = OrderedDict([
    ("body-parser", ("server", _major(2), "2.x (2.0.0-2.4.0 read; Imperva reproduced 2.0.0-2.3.0)",
                     "body-parser 2.x decodes br request bodies by default (`inflate` defaults true; "
                     "read.js -> zlib.createBrotliDecompress); standalone or through Express 5",
                     "`inflate: false` (rejects every compressed body, gzip/deflate too)")),
    ("express", ("server", _ge(5, 0, 0), ">=5.0.0",
                 "Express 5 built-ins (express.json / urlencoded / text / raw) are body-parser 2.x and decode br "
                 "request bodies by default (Imperva: 5.0.0-5.3.0 reproduced)",
                 "`inflate: false` (rejects every compressed body)")),
    ("inflation", ("server", _ge(2, 1, 0), ">=2.1.0 (br added 2023-10-13)",
                   "inflation 2.1.0+ decodes br unconditionally (1.x / 2.0.0 are gzip/deflate only)",
                   "none")),
    ("co-body", ("server", _ge(5, 0, 0), ">=5.0.0 (4.2.0 pins inflation ~2.0.0)",
                 "co-body 5+ (Koa) decodes br when inflation resolves >=2.1.0",
                 "don't parse br requests")),
    ("@koa/bodyparser", ("server", _ge(5, 0, 0), ">=5.0.0 (6.1.0 read)",
                         "@koa/bodyparser 5+ decodes br for json + form by default",
                         "`enableTypes` without json / form")),
    ("koa-bodyparser", ("server", _koa_bodyparser, "2.4.0, 2.5.x, 4.1.0, 4.2.x-4.4.x (not 2.0-2.3, 3.x, 4.0.0)",
                        "legacy koa-bodyparser in the listed versions decodes br for json + form",
                        "`enableTypes`")),
    ("koa-body", ("server", _ge(2, 4, 0), ">=2.4.0 (8.0.1 read)",
                  "koa-body decodes br for json / urlencoded / text",
                  "`json` / `urlencoded` / `text: false`")),
    ("@fastify/compress", ("server", _ge(5, 0, 0), ">=5.0.0 (9.2.2 read)",
                           "@fastify/compress decompresses request bodies on EVERY route once registered; default "
                           "requestEncodings include br",
                           "`globalDecompression: false`, per-route `decompress: false`, or `requestEncodings` "
                           "without br (-> 415)")),
    ("fastify-compress", ("server", _ge(3, 1, 0), ">=3.1.0 (3.7.0 verified)",
                          "legacy fastify-compress 3.1.0+ decompresses request bodies incl. br",
                          "`globalDecompression: false` / `requestEncodings` without br")),
    ("@nestjs/platform-express", ("server", _ge(11, 0, 0), ">=11.0.0 (Nest 11/12 = Express 5; Nest 8-10 = Express 4: no)",
                                  "Nest 11+ on Express 5 decodes br request bodies through body-parser 2.x",
                                  "`bodyParser: false` + your own parser")),
    ("@apollo/server", ("server", _major(5), "5.x (5.5.1 verified)",
                        "Apollo Server 5 standalone decodes br via body-parser json (the 50 MB limit applies to "
                        "decoded bytes)",
                        "none - front it with a proxy that rejects br request bodies")),
    ("@strapi/strapi", ("server", _major(5), "5.x (5.59.0 / koa-body 6.0.1 read)",
                        "Strapi 5 (koa-body) decodes br for json / urlencoded / text", "none listed")),
    ("parse-server", ("server", _major(9), "9.x (9.10.7 / express 5.2.1 read)",
                      "Parse Server 9 (Express 5) decodes br for json / urlencoded", "none listed")),
    # --- partly / conditional (usage not visible -> info)
    ("n8n", ("partial", _major(2), "2.x (2.44.6 read)",
             "n8n: PARTLY - the /api/v1 express.json parser decodes br; the main body reader is gzip/deflate only",
             "none listed")),
    ("@whatwg-node/server", ("conditional", _any, "any (0.13.1 read)",
                             "decodes br request bodies only when the useContentEncoding() plugin is added",
                             "don't add the plugin")),
    ("graphql-yoga", ("conditional", _any, "any (6.0.1 read)",
                      "decodes br request bodies only when the useContentEncoding() plugin is added",
                      "don't add the plugin")),
    # --- client side (BRIEF s5.2): attacker controls a server the app fetches from
    ("axios", ("client", _ge(1, 0, 0), ">=1.0.0 (0.x has no br)",
               "axios advertises gzip, compress, deflate, br and decodes br responses", "`decompress: false`")),
    ("got", ("client", _major_range(11, 16), "11-16",
             "got adds br when process.versions.brotli exists and decodes via decompress-response",
             "`decompress: false`")),
    ("node-fetch", ("client", _major(3), "3.x",
                    "node-fetch 3 advertises gzip, deflate, br and decodes br", "`compress: false`")),
    ("needle", ("client", _any, "any (3.5.0 read)",
                "needle advertises gzip, deflate, br and decodes br", "none listed")),
    ("superagent", ("client", _any, "any (10.4.1 read)",
                    "superagent advertises gzip, deflate but decodes br if the server sends it", "none listed")),
    ("ky", ("client", _any, "any", "ky goes through fetch, which decodes br responses", "none listed")),
    ("decompress-response", ("client", _any, "any (^6 / ^10 read, used by got)",
                             "decompress-response decodes br responses", "none listed")),
    ("http-proxy-middleware", ("conditional", _any, "2.0.6, 3.0.x, 4.0.0-4.2.0",
                               "decodes upstream br responses only with responseInterceptor + selfHandleResponse",
                               "don't use responseInterceptor")),
    ("next", ("conditional", _any, "any (16.4.3 read)",
              "the image optimizer decodes br from remote images only when images.remotePatterns / domains are "
              "non-empty (default [])", "keep images.remotePatterns / domains empty")),
    ("@remix-run/web-fetch", ("conditional", _any, "4.4.2 read",
                              "Remix 2 `installGlobals()` (web-fetch polyfill) decodes br responses; "
                              "`nativeFetch: true` uses undici (same decoder)", "none listed")),
])
# node-fetch 2.x: advertises gzip,deflate - whether it decodes a br response is UNCONFIRMED in the brief
NODE_FETCH_V2_NOTE = ("node-fetch 2.x advertises gzip,deflate; the brief did not confirm whether it decodes a br "
                      "response (UNCONFIRMED) - unknown / verify")


# ---------------------------------------------------------------------------
# bounded project walk
# ---------------------------------------------------------------------------

def _classify(fn: str, dirname: str) -> Optional[str]:
    low = fn.lower()
    if fn in ("package-lock.json", "npm-shrinkwrap.json"):
        return "npm-lock"
    if fn == "yarn.lock":
        return "yarn"
    if fn == "pnpm-lock.yaml":
        return "pnpm"
    if fn == "bun.lock":
        return "bun"
    if fn == "bun.lockb":
        return "bun-lockb"
    if (low.startswith("requirements") and low.endswith(".txt")) or \
            (os.path.basename(dirname) == "requirements" and low.endswith(".txt")):
        return "requirements"
    if fn in ("poetry.lock", "uv.lock", "pdm.lock"):
        return "toml-lock"
    if fn == "Pipfile.lock":
        return "pipfile"
    if fn == "go.mod":
        return "go-mod"
    if fn == "go.sum":
        return "go-sum"
    if fn == "Cargo.lock":
        return "cargo"
    if fn == "Gemfile.lock":
        return "gem"
    if fn == "pom.xml":
        return "pom"
    if fn in ("build.gradle", "build.gradle.kts"):
        return "gradle"
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        return "docker"
    if re.match(r"^(docker-)?compose[\w.\-]*\.ya?ml$", low):
        return "compose"
    if re.match(r"^next\.config\.(js|mjs|cjs|ts)$", low):
        return "next-config"
    return None


def find_project_files(root: str) -> dict:
    """Bounded walk: {kind: [paths]}, plus 'node_modules': [dirs], 'truncated': bool."""
    found = defaultdict(list)
    truncated = False
    dirs_seen = 0
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirs_seen += 1
        depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
        if dirs_seen > MAX_DIRS:
            truncated = True
            break
        if "node_modules" in dirnames and depth <= 6:
            found["node_modules"].append(os.path.join(dirpath, "node_modules"))
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES)
        if depth >= MAX_DEPTH:
            dirnames[:] = []
        for fn in sorted(filenames):
            kind = _classify(fn, dirpath)
            if kind:
                found[kind].append(os.path.join(dirpath, fn))
    found["truncated"] = truncated
    return found


def _read(path: str, limit: int = MAX_LOCK_BYTES) -> Optional[str]:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# npm-family parsers
# ---------------------------------------------------------------------------

def _name_from_nm_path(key: str) -> str:
    idx = key.rfind("node_modules/")
    return key[idx + len("node_modules/"):] if idx != -1 else key


def _alias(name: str, version: str):
    m = re.match(r"^npm:(@?[^@]+)@(.+)$", version or "")
    return (m.group(1), m.group(2)) if m else (name, version)


def parse_package_lock(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    data = json.loads(text)
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):                         # lockfile v2 / v3 (and .package-lock.json)
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue
            name = meta.get("name") or _name_from_nm_path(key)
            ver = meta.get("version")
            if name and isinstance(ver, str) and ver[:1].isdigit():
                out.append(Pkg("npm", name, ver, path))
        return out

    def walk(deps):
        for name, meta in (deps or {}).items():            # lockfile v1
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if isinstance(ver, str):
                n, v = _alias(name, ver)
                if v[:1].isdigit():
                    out.append(Pkg("npm", n, v, path))
            walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return out


_YARN_NAME = re.compile(r'^"?(@?[^@\s",]+)@')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def parse_yarn_lock(path: str) -> list:
    """yarn classic (`version "x"`) and berry (`version: x`)."""
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    out, name = [], None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1].strip()
            name = None
            if header.startswith("__metadata"):
                continue
            first = header.split(", ")[0].strip()
            m = _YARN_NAME.match(first)
            if m:
                name = m.group(1)
            continue
        if name:
            m = _YARN_VERSION.match(line)
            if m:
                ver = m.group(1)
                if ver[:1].isdigit():
                    out.append(Pkg("npm", name, ver, path))
                name = None
    return out


_PNPM_V6 = re.compile(r"^/?(@[^/@\s]+/[^/@\s]+|[^/@\s]+)@(\d[^\s:(')\"]*)")
_PNPM_V5 = re.compile(r"^/(@[^/@\s]+/[^/@\s]+|[^/@\s]+)/(\d[^\s:_(')\"]*)")


def parse_pnpm_lock(path: str) -> list:
    """pnpm-lock.yaml v5 (/name/1.0.0), v6 (/name@1.0.0) and v9 (name@1.0.0), line parsing."""
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    out, seen, section = [], set(), None
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            section = line.split(":")[0].strip() if line.rstrip().endswith(":") else None
            continue
        if section not in ("packages", "snapshots"):
            continue
        if not line.startswith("  ") or line.startswith("   "):
            continue
        key = line.strip().rstrip(":").strip("'\"")
        m = _PNPM_V6.match(key) or _PNPM_V5.match(key)
        if not m:
            continue
        pair = (m.group(1), m.group(2))
        if pair not in seen:
            seen.add(pair)
            out.append(Pkg("npm", pair[0], pair[1], path))
    return out


_BUN_ENTRY = re.compile(r'\[\s*"((?:@[^"/@\s]+/)?[^"/@\s]+)@(\d[^"\s]*)"')


def parse_bun_lock(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    out, seen = [], set()
    for m in _BUN_ENTRY.finditer(text):
        pair = (m.group(1), m.group(2))
        if pair not in seen:
            seen.add(pair)
            out.append(Pkg("npm", pair[0], pair[1], path))
    return out


_PNPM_DIR = re.compile(r"^(@?[^@]+?)@(\d[^_(]*)")


def scan_node_modules(nm_dir: str, budget: list) -> list:
    """Bounded walk of one node_modules tree: package.json name/version (+ .pnpm dir names).
    `budget` is a one-element list holding the remaining package.json reads."""
    out = []
    stack = [(nm_dir, 0)]

    def handle_pkg(pdir: str, depth: int):
        if budget[0] <= 0:
            return
        pj = os.path.join(pdir, "package.json")
        try:
            if os.path.getsize(pj) > MAX_PKG_JSON_BYTES:
                return
            with open(pj, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = None
        budget[0] -= 1
        if isinstance(data, dict) and isinstance(data.get("name"), str) and isinstance(data.get("version"), str):
            out.append(Pkg("npm", data["name"], data["version"], pj))
        nested = os.path.join(pdir, "node_modules")
        if depth < 4 and os.path.isdir(nested) and not os.path.islink(nested):
            stack.append((nested, depth + 1))

    while stack and budget[0] > 0:
        d, depth = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            if e.name == ".pnpm" and e.is_dir(follow_symlinks=False):
                try:
                    for pe in os.scandir(e.path):
                        m = _PNPM_DIR.match(pe.name.replace("+", "/"))
                        if m:
                            out.append(Pkg("npm", m.group(1), m.group(2), pe.path))
                except OSError:
                    pass
                continue
            if e.name.startswith(".") or not e.is_dir(follow_symlinks=False):
                continue
            if e.name.startswith("@"):
                try:
                    for sub in sorted(os.scandir(e.path), key=lambda s: s.name):
                        if sub.is_dir(follow_symlinks=False):
                            handle_pkg(sub.path, depth)
                except OSError:
                    pass
            else:
                handle_pkg(e.path, depth)
    return out


# ---------------------------------------------------------------------------
# Python / Go / Rust / Ruby / Java parsers
# ---------------------------------------------------------------------------

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^\s;,#\\]+)?")


def parse_requirements(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    out = []
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://", ".")):
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
        if name not in PY_INTEREST:
            continue
        op, ver = m.group(2) or "", m.group(3) or ""
        if ver and ver[:1].isdigit():
            out.append(Pkg("pypi", name, ver, path, op))
        else:
            out.append(Pkg("pypi", name, "", path, op or "any"))
    return out


def parse_toml_packages(path: str, eco: str) -> list:
    """poetry.lock / uv.lock / pdm.lock / Cargo.lock: [[package]] blocks with name + version."""
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    out = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        n = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        v = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
        if not (n and v):
            continue
        name = n.group(1)
        if eco == "pypi":
            name = re.sub(r"[-_.]+", "-", name).lower()
            if name not in PY_INTEREST:
                continue
        elif eco == "cargo" and name not in ("brotli", "brotli-decompressor"):
            continue
        out.append(Pkg(eco, name, v.group(1), path, ""))
    return out


def parse_pipfile_lock(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            n = re.sub(r"[-_.]+", "-", name).lower()
            ver = (meta or {}).get("version", "") if isinstance(meta, dict) else ""
            if n in PY_INTEREST and isinstance(ver, str):
                out.append(Pkg("pypi", n, ver.lstrip("="), path, ""))
    return out


_GO_RE = re.compile(r"github\.com/andybalholm/brotli\s+(v[0-9A-Za-z.+\-]+?)(?:/go\.mod)?(?:\s|$)")


def parse_go(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    seen, out = set(), []
    for m in _GO_RE.finditer(text):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(Pkg("go", "github.com/andybalholm/brotli", m.group(1), path))
    return out


def parse_gemfile_lock(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    return [Pkg("gem", "brotli", m.group(1), path)
            for m in re.finditer(r"(?m)^\s{4}brotli \(([^)\s]+)\)", text)]


def parse_pom(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    props = dict(re.findall(r"<([\w.\-]+)>\s*([^<$\s]+)\s*</\1>", text))
    out = []
    for m in re.finditer(r"<artifactId>\s*([\w.\-]*brotli4j[\w.\-]*)\s*</artifactId>\s*<version>\s*([^<\s]+)\s*</version>", text):
        ver = m.group(2)
        pm = re.fullmatch(r"\$\{([\w.\-]+)\}", ver)
        if pm:
            ver = props.get(pm.group(1), ver)
        out.append(Pkg("maven", "brotli4j", ver, path))
    return out


def parse_gradle(path: str) -> list:
    text = _read(path)
    if text is None:
        raise OSError("unreadable or too large")
    return [Pkg("maven", "brotli4j", m.group(2), path)
            for m in re.finditer(r"com\.aayushatharva\.brotli4j:([\w\-]+):([\w.\-]+)", text)]


# ---------------------------------------------------------------------------
# Dockerfile / compose
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(r"^\s*FROM\s+((?:--\S+\s+)*)(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)
_ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?\s*$", re.IGNORECASE)


def split_image(ref: str):
    """'registry/library/node:22.23.3-slim@sha256:..' -> (repo components, tag or None, digest?)."""
    digest = "@" in ref
    ref = ref.split("@")[0]
    name, tag = ref, None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
    parts = name.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    return parts, tag, digest


def image_kind(parts) -> Optional[str]:
    if parts and parts[-1] == "node" and all(p in ("library", "docker") for p in parts[:-1]):
        return "node"
    if parts[-2:] == ["oven", "bun"]:
        return "bun"
    return None


def parse_dockerfile(path: str) -> list:
    text = _read(path, 4 * 1024 * 1024)
    if text is None:
        raise OSError("unreadable or too large")
    args, stages, out = {}, set(), []
    seen_from = False                      # only ARGs before the first FROM are global
    for raw in text.splitlines():
        a = _ARG_RE.match(raw)
        if a and not seen_from:
            args[a.group(1)] = (a.group(2) or "").strip().strip("\"'")
            continue
        m = _FROM_RE.match(raw)
        if not m:
            continue
        seen_from = True
        ref = m.group(2)
        stage = m.group(3)
        if stage:
            stages.add(stage.lower())
        if ref.lower() in stages and ref.lower() != (stage or "").lower():
            continue
        ref = re.sub(r"\$\{(\w+)(?::-([^}]*))?\}|\$(\w+)",
                     lambda mm: args.get(mm.group(1) or mm.group(3)) or (mm.group(2) or mm.group(0)), ref)
        parts, tag, digest = split_image(ref)
        kind = image_kind(parts)
        if kind:
            out.append(Pkg("docker", kind, tag if tag is not None else ("<digest>" if digest else ""), path, kind))
    return out


def parse_compose(path: str) -> list:
    text = _read(path, 4 * 1024 * 1024)
    if text is None:
        raise OSError("unreadable or too large")
    out = []
    for m in re.finditer(r"(?m)^\s*image:\s*['\"]?([^\s'\"#]+)", text):
        parts, tag, digest = split_image(m.group(1))
        kind = image_kind(parts)
        if kind:
            out.append(Pkg("docker", kind, tag if tag is not None else ("<digest>" if digest else ""), path, kind))
    return out


# ---------------------------------------------------------------------------
# evaluation -> findings
# ---------------------------------------------------------------------------

_REACH = ("Reachability only: the npm package decides whether attacker bytes reach a decoder; the runtime decides "
          "whether that is exploitable (BRIEF s5).")


def _basis(note: str, derived: bool = False) -> str:
    return fp.brief_basis("s5.1 / s5.2", note, derived=derived)


def _npm_findings(pkgs: list, runtime_vulnerable: list, project: str) -> list:
    out = []
    by_key = OrderedDict()
    for p in pkgs:
        if p.eco != "npm":
            continue
        by_key.setdefault((p.name, p.version), []).append(p.source)
    escalated = bool(runtime_vulnerable)
    ok_rows = []
    for (name, ver), sources in by_key.items():
        vt = versions.parse_dotted(ver)
        if vt is None:
            continue
        also = f" (also {len(sources) - 1} more file(s))" if len(sources) > 1 else ""
        if name == "node-fetch" and vt[0] == 2:
            out.append(finding(
                "DEP_CLIENT_DECODER", "info", f"node-fetch {ver}: {NODE_FETCH_V2_NOTE}. {_REACH}",
                check="deps", file=sources[0], evidence=f"node-fetch@{ver}{also}",
                basis=fp.brief_basis("s5.2", "node-fetch 2.7.0 advertises gzip,deflate; br decode UNCONFIRMED"),
                defang_ips=False))
            continue
        if name in ("body-parser", "express") and ((name == "body-parser" and vt[0] == 1)
                                                    or (name == "express" and vt[0] == 4)):
            ok_rows.append((name, ver, sources[0]))
            continue
        rule = NPM_RULES.get(name)
        if not rule or not rule[1](vt):
            continue
        kind, _pred, rng, what, switch = rule
        if kind == "server":
            sev = "critical" if escalated else "warn"
            esc = (f" ESCALATED to critical: this run's posture check found a vulnerable runtime "
                   f"({', '.join(runtime_vulnerable[:3])}); any request carrying `Content-Encoding: br` reaches "
                   "the decoder with one unauthenticated request." if escalated else
                   " Severity warn: no vulnerable runtime was recorded in this run (posture not run, or the runtime "
                   "is fixed) - re-run with --check posture on the host that serves this project.")
            rule_id = "DEP_SERVER_BODY_DECODER"
            msg = (f"{name} {ver} [affected: {rng}]: {what}. Switch: {switch}. Attacker-reachable surface = request "
                   f"bodies with `Content-Encoding: br`.{esc} {_REACH}")
            basis = _basis("server-side request-body decoders (br decoded by default) - exact version ranges")
        elif kind == "client":
            sev = "warn" if escalated else "info"
            rule_id = "DEP_CLIENT_DECODER"
            esc = (f" Escalated to warn: a vulnerable runtime was found in this run ({', '.join(runtime_vulnerable[:3])})."
                   if escalated else "")
            msg = (f"{name} {ver} [{rng}]: {what}. Switch: {switch}. Attacker-reachable surface = responses from "
                   f"servers this app fetches from (webhooks, link previews, image proxies, crawlers, SSR fetches of "
                   f"user-supplied URLs; WAFs do not see it).{esc} {_REACH}")
            basis = fp.brief_basis("s5.2", "client-side decoders: a malicious server can send br regardless of "
                                           "Accept-Encoding")
        else:
            sev = "info"
            rule_id = "DEP_CONDITIONAL_DECODER"
            msg = (f"{name} {ver} [{rng}]: {what}. The tool cannot see how this library is used (config / plugin), so "
                   f"this stays info. Switch: {switch}. {_REACH}")
            basis = fp.brief_basis("s5.1 / s5.2", "decodes br only under a condition the tool cannot see")
        out.append(finding(rule_id, sev, msg, check="deps", file=sources[0], evidence=f"{name}@{ver}{also}",
                           basis=basis, related=list(runtime_vulnerable[:3]) if sev == "critical" else [],
                           defang_ips=False))
    if ok_rows:
        names = ", ".join(f"{n} {v}" for n, v, _ in ok_rows[:4])
        out.append(finding(
            "DEP_NOT_A_DECODER", "ok",
            f"{names}: Express 4 / body-parser 1.x reject `Content-Encoding: br` request bodies (415 unsupported "
            f"encoding) - not a server-side decoder (BRIEF s5.1).",
            check="deps", file=ok_rows[0][2], evidence=names,
            basis=fp.brief_basis("s5.1", "body-parser 1.x / Express 4: NO -> 415 unsupported encoding"),
            defang_ips=False))
    return out


def _py_findings(pkgs: list, project: str) -> list:
    out = []
    py = [p for p in pkgs if p.eco == "pypi"]
    if not py:
        return out
    names = {p.name for p in py}
    aio = next((p for p in py if p.name == "aiohttp"), None)
    consumers = sorted(n for n in PY_CONSUMERS if n in names)
    seen = set()
    for p in py:
        if p.name not in ("brotli", "brotlicffi", "brotlipy"):
            continue
        key = (p.name, p.version, p.extra)
        if key in seen:                       # the same pin in requirements.txt and a lockfile
            continue
        seen.add(key)
        fixed = versions.PYPI_BROTLI_FIXED if p.name == "brotli" else versions.PYPI_BROTLICFFI_FIXED
        fn = {"brotli": versions.eval_pypi_brotli, "brotlicffi": versions.eval_pypi_brotlicffi,
              "brotlipy": versions.eval_pypi_brotlipy}[p.name]
        pinned = p.extra in ("", "==", "===")
        floor = versions.parse_dotted(p.version) if p.version else None
        extra = ""
        if pinned and p.version:
            ev = fn(p.version)
            sev, status = ev["severity"], ev["status"]
            detail = ev["detail"]
            if status == "vulnerable_unpatched" and aio is not None:
                sev = "critical"
                extra = (f" aiohttp is in the same project ({aio.name} {aio.version or 'unpinned'}): its SERVER "
                         "decodes `Content-Encoding: br` request bodies by default when Brotli is installed "
                         "(BRIEF s5.4).")
        elif floor is not None and p.extra in (">=", "~=", ">") and p.name != "brotlipy":
            if versions.cmp_tuple(floor, fixed) >= 0:
                sev, status = "ok", "floor_fixed"
                detail = f"requirement floor {p.extra}{p.version} is at or above the fixed version {versions.fmt(fixed)}."
            else:
                sev, status = "info", "floor_admits_vulnerable"
                detail = (f"requirement {p.extra}{p.version} admits vulnerable versions (fixed: {versions.fmt(fixed)}); "
                          "the brief notes urllib3's `brotli` extra and Scrapy pin `brotli>=1.2.0`, which still admits "
                          "vulnerable 1.2.0. The resolved version is unknown here - verify the installed version "
                          "(posture scans site-packages) and require >= " + versions.fmt(fixed) + ".")
        else:
            sev, status = "info", "unresolved"
            detail = (f"{p.name} is required without a resolvable pin ({p.extra or 'any'} {p.version}) - unknown / "
                      "verify the installed version.")
        if consumers:
            extra += f" Consumers named in the project: {', '.join(consumers)}."
        if p.extra == "":
            label = f"{p.name} {p.version}"                      # resolved / locked version
        elif p.extra == "any":
            label = f"{p.name} (any version)"
        else:
            label = f"{p.name}{p.extra}{p.version}"              # e.g. brotli==1.1.0, brotli>=1.0.9
        out.append(finding(
            "DEP_PY_BROTLI", sev, f"{p.name} {p.version or '(unpinned)'} -> {status}. {detail}{extra} {_REACH}",
            check="deps", file=p.source, evidence=label,
            basis=fp.brief_basis("s5.4 / GHSA-9v8h-qqgm-4m35",
                                 "PyPI Brotli < 1.2.1, brotlicffi 1.0.9.0-1.2.0.2 affected; aiohttp server decodes br "
                                 "request bodies by default"),
            defang_ips=False))
    return out


def _other_findings(pkgs: list) -> list:
    out, seen = [], set()
    for p in pkgs:
        key = (p.eco, p.name, p.version)
        if key in seen:                       # e.g. the same version in go.mod and go.sum
            continue
        seen.add(key)
        if p.eco == "go":
            ev = versions.eval_go_brotli(p.version)
            out.append(finding(
                "DEP_GO_BROTLI", ev["severity"], f"github.com/andybalholm/brotli {p.version}: {ev['detail']}",
                check="deps", file=p.source, evidence=f"andybalholm/brotli {p.version}",
                basis=fp.brief_basis("s5.4", "andybalholm/brotli pre-fix logic in v1.0.0-v1.2.6, fixed v1.2.7 (23 Oct)"),
                defang_ips=False))
        elif p.eco == "cargo":
            vt = versions.parse_dotted(p.version) or ()
            if p.name == "brotli" and not (vt and 7 <= vt[0] <= 9):
                continue
            out.append(finding(
                "DEP_RUST_BROTLI_DECOMPRESSOR", "info",
                f"{p.name} {p.version}: Rust port of the decoder - the pre-fix early-return logic is still present in "
                "brotli-decompressor 6.1.1 and no fixed crates.io release exists (BRIEF s5.4); safe-Rust impact is "
                "likely a panic / DoS rather than memory corruption (inference, NOT confirmed). Status unresolved - "
                "unknown / verify.",
                check="deps", file=p.source, evidence=f"{p.name} {p.version}",
                basis=fp.brief_basis("s5.4 / s5.3", "Rust brotli-decompressor: unresolved, not cleared"),
                defang_ips=False))
        elif p.eco == "gem":
            ev = versions.eval_gem_brotli(p.version)
            out.append(finding(
                "DEP_RUBY_BROTLI", ev["severity"], f"brotli gem {p.version}: {ev['detail']}", check="deps",
                file=p.source, evidence=f"brotli {p.version}",
                basis=fp.brief_basis("s5.4", "RubyGems brotli 0.4.0-0.9.0 affected, fixed 0.9.1 / 0.9.2 (24 Oct)"),
                defang_ips=False))
        elif p.eco == "maven":
            ev = versions.eval_brotli4j(p.version)
            out.append(finding(
                "DEP_JAVA_BROTLI4J", ev["severity"], f"brotli4j {p.version}: {ev['detail']}", check="deps",
                file=p.source, evidence=f"brotli4j {p.version}",
                basis=fp.brief_basis("s5.4", "brotli4j 1.21.0-1.23.0 (vendored 1.2.0) affected, fixed 1.24.0"),
                defang_ips=False))
    return out


def _docker_findings(pkgs: list) -> list:
    out = []
    for p in pkgs:
        if p.eco != "docker":
            continue
        if p.version == "<digest>":
            sev, status = "info", "digest_pinned"
            detail = ("the image is pinned by digest only: the runtime version cannot be read from a digest - "
                      "unknown / verify, and remember images must be REBUILT (not just restarted) to pick up the fix "
                      "(BRIEF s3).")
        else:
            ev = versions.eval_node_tag(p.version) if p.name == "node" else versions.eval_bun_tag(p.version)
            sev, status, detail = ev["severity"], ev["status"], ev["detail"]
        label = "node" if p.name == "node" else "oven/bun"
        out.append(finding(
            "DOCKER_BASE_IMAGE", sev, f"{label}:{p.version or 'latest'} -> {status}. {detail}", check="deps",
            file=p.source, evidence=f"FROM {label}:{p.version or 'latest'}",
            basis=fp.brief_basis("s3", "official images: docker-node moved 22/24/26 to the fixed releases on "
                                       "2026-10-21; images must be rebuilt, not just restarted"),
            defang_ips=False))
    return out


def _next_config_note(paths: list) -> Optional[str]:
    for p in paths:
        text = _read(p, 1024 * 1024) or ""
        if re.search(r"remotePatterns\s*:\s*\[\s*[^\]\s]", text) or re.search(r"\bdomains\s*:\s*\[\s*['\"]", text):
            return p
    return None


# ---------------------------------------------------------------------------
# entry
# ---------------------------------------------------------------------------

def scan_project(root: str, runtime_vulnerable: Optional[list] = None) -> dict:
    runtime_vulnerable = runtime_vulnerable or []
    found = find_project_files(root)
    pkgs, parsed, notes, findings = [], [], [], []
    parsers = (
        ("npm-lock", parse_package_lock), ("yarn", parse_yarn_lock), ("pnpm", parse_pnpm_lock),
        ("bun", parse_bun_lock), ("requirements", parse_requirements),
        ("pipfile", parse_pipfile_lock), ("go-mod", parse_go), ("go-sum", parse_go),
        ("gem", parse_gemfile_lock), ("pom", parse_pom), ("gradle", parse_gradle),
        ("docker", parse_dockerfile), ("compose", parse_compose),
    )
    for kind, fn in parsers:
        for path in found.get(kind, []):
            try:
                pkgs.extend(fn(path))
                parsed.append(path)
            except (OSError, ValueError) as e:
                notes.append(f"{path}: not parsed ({e.__class__.__name__}: {e})")
    for path in found.get("toml-lock", []):
        try:
            pkgs.extend(parse_toml_packages(path, "pypi"))
            parsed.append(path)
        except (OSError, ValueError) as e:
            notes.append(f"{path}: not parsed ({e.__class__.__name__}: {e})")
    for path in found.get("cargo", []):
        try:
            pkgs.extend(parse_toml_packages(path, "cargo"))
            parsed.append(path)
        except (OSError, ValueError) as e:
            notes.append(f"{path}: not parsed ({e.__class__.__name__}: {e})")
    for path in found.get("bun-lockb", []):
        notes.append(f"{path}: binary bun.lockb not parsed - use `bun install --save-text-lockfile` / bun.lock, or "
                     "scan node_modules")
    budget = [MAX_NM_PACKAGES]
    for nm in found.get("node_modules", []):
        pkgs.extend(scan_node_modules(nm, budget))
        parsed.append(nm)
    if budget[0] <= 0:
        notes.append(f"node_modules walk capped at {MAX_NM_PACKAGES} packages")

    findings.extend(_npm_findings(pkgs, runtime_vulnerable, root))
    findings.extend(_py_findings(pkgs, root))
    findings.extend(_other_findings(pkgs))
    findings.extend(_docker_findings(pkgs))
    nxt = _next_config_note(found.get("next-config", []))
    if nxt:
        findings.append(finding(
            "DEP_NEXT_IMAGES_CONFIG", "info",
            f"{nxt} sets images.remotePatterns / domains: the Next.js image optimizer fetches and decodes remote "
            "images (br included) for those hosts (BRIEF s5.2) - the decoder is the runtime's. Info only.",
            check="deps", file=nxt, basis=fp.brief_basis("s5.2", "Next.js image optimizer decodes br only if "
                                                              "remotePatterns/domains are non-empty"),
            defang_ips=False))
    return {"path": root, "files": parsed, "packages_scanned": len(pkgs), "truncated": bool(found.get("truncated")),
            "notes": notes, "findings": findings}


def run_deps(project_dirs, vulnerable_runtimes: Optional[list] = None, posture_ran: bool = False) -> dict:
    """The DEPENDENCY EXPOSURE check over every --project directory."""
    vuln = list(vulnerable_runtimes or [])
    projects, findings, notes = [], [], []
    for root in project_dirs:
        if not os.path.isdir(root):
            continue
        res = scan_project(root, vuln)
        findings.extend(res.pop("findings"))
        notes.extend(res.pop("notes"))
        projects.append(res)
    if not posture_ran:
        notes.append("posture was not part of this run: server-side decoders stay at warn (they escalate to critical "
                     "only when this run's posture check finds a vulnerable runtime)")
    return {"projects": projects, "findings": findings, "notes": notes,
            "runtime_escalation": (bool(vuln) if posture_ran else None)}
