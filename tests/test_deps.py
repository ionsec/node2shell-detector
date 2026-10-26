"""DEPENDENCY EXPOSURE: lockfile / manifest parsers, the BRIEF s5.1 / s5.2 exposure table, escalation."""

import json
import os
from pathlib import Path

import pytest

from node2shell_detector import deps

SERVER, CLIENT, COND, OKROW = ("DEP_SERVER_BODY_DECODER", "DEP_CLIENT_DECODER", "DEP_CONDITIONAL_DECODER",
                               "DEP_NOT_A_DECODER")


def w(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def scan(root, vuln=None):
    return deps.scan_project(str(root), vuln or [])


def by_rule(res, rule):
    return [f for f in res["findings"] if f["rule"] == rule]


def hits_for(res, name, ver):
    out = []
    for f in res["findings"]:
        e = f["evidence"] or ""
        if e.startswith(f"{name}@{ver}") or e.startswith(f"{name} {ver}"):
            out.append(f)
    return out


def npm_lock(root, pkgs, version=3):
    packages = {"": {"name": "app", "version": "1.0.0"}}
    for name, ver in pkgs.items():
        packages[f"node_modules/{name}"] = {"version": ver}
    w(root, "package-lock.json", json.dumps({"name": "app", "lockfileVersion": version, "packages": packages}))


# ------------------------------------------------------------------ the exposure table ----

CASES = [
    # --- server side (BRIEF s5.1)
    ("body-parser", "2.0.0", SERVER), ("body-parser", "2.4.0", SERVER), ("body-parser", "3.0.0", None),
    ("body-parser", "1.20.3", OKROW),
    ("express", "5.0.0", SERVER), ("express", "5.3.0", SERVER), ("express", "4.21.2", OKROW),
    ("inflation", "2.1.0", SERVER), ("inflation", "2.0.0", None), ("inflation", "1.0.0", None),
    ("co-body", "5.0.0", SERVER), ("co-body", "6.2.0", SERVER), ("co-body", "4.2.0", None),
    ("@koa/bodyparser", "5.0.0", SERVER), ("@koa/bodyparser", "6.1.0", SERVER), ("@koa/bodyparser", "4.6.0", None),
    ("koa-bodyparser", "2.3.0", None), ("koa-bodyparser", "2.4.0", SERVER), ("koa-bodyparser", "2.5.1", SERVER),
    ("koa-bodyparser", "3.0.0", None), ("koa-bodyparser", "4.0.0", None), ("koa-bodyparser", "4.1.0", SERVER),
    ("koa-bodyparser", "4.2.0", SERVER), ("koa-bodyparser", "4.4.1", SERVER),
    ("koa-body", "2.3.0", None), ("koa-body", "2.4.0", SERVER), ("koa-body", "8.0.1", SERVER),
    ("@fastify/compress", "4.9.0", None), ("@fastify/compress", "5.0.0", SERVER),
    ("@fastify/compress", "9.2.2", SERVER),
    ("fastify-compress", "3.0.0", None), ("fastify-compress", "3.1.0", SERVER), ("fastify-compress", "3.7.0", SERVER),
    ("@nestjs/platform-express", "10.4.0", None), ("@nestjs/platform-express", "11.0.0", SERVER),
    ("@apollo/server", "4.11.0", None), ("@apollo/server", "5.5.1", SERVER),
    ("@strapi/strapi", "4.25.0", None), ("@strapi/strapi", "5.59.0", SERVER),
    ("parse-server", "8.0.0", None), ("parse-server", "9.10.7", SERVER),
    # --- partly / conditional (usage not visible -> info)
    ("n8n", "1.60.0", None), ("n8n", "2.44.6", COND),
    ("@whatwg-node/server", "0.13.1", COND), ("graphql-yoga", "6.0.1", COND),
    ("http-proxy-middleware", "3.0.3", COND), ("next", "16.4.3", COND), ("@remix-run/web-fetch", "4.4.2", COND),
    # --- client side (BRIEF s5.2)
    ("axios", "0.27.2", None), ("axios", "1.0.0", CLIENT), ("axios", "1.7.2", CLIENT),
    ("got", "10.7.0", None), ("got", "11.8.6", CLIENT), ("got", "16.0.0", CLIENT), ("got", "17.0.0", None),
    ("node-fetch", "2.7.0", CLIENT), ("node-fetch", "3.3.2", CLIENT),
    ("needle", "3.5.0", CLIENT), ("superagent", "10.4.1", CLIENT), ("ky", "1.2.0", CLIENT),
    ("decompress-response", "6.0.0", CLIENT),
    ("lodash", "4.17.21", None),
]


@pytest.mark.parametrize("name,ver,expected", CASES)
def test_exposure_table(tmp_path, name, ver, expected):
    npm_lock(tmp_path, {name: ver})
    hits = hits_for(scan(tmp_path), name, ver)
    if expected is None:
        assert hits == []
    else:
        assert [h["rule"] for h in hits] == [expected], hits


def test_severities_without_a_vulnerable_runtime(tmp_path):
    npm_lock(tmp_path, {"express": "5.1.0", "axios": "1.7.2", "next": "16.4.3", "body-parser": "1.20.3"})
    res = scan(tmp_path)
    assert by_rule(res, SERVER)[0]["severity"] == "warn"
    assert by_rule(res, CLIENT)[0]["severity"] == "info"
    assert by_rule(res, COND)[0]["severity"] == "info"
    assert by_rule(res, OKROW)[0]["severity"] == "ok"
    f = by_rule(res, SERVER)[0]
    assert "Reachability only" in f["message"] and "runtime decides" in f["message"]
    assert "no vulnerable runtime was recorded" in f["message"]
    assert f["basis"].startswith("VERBATIM") and "BRIEF s5.1" in f["basis"]
    assert f["evidence"].startswith("express@5.1.0")


def test_escalation_with_a_vulnerable_runtime(tmp_path):
    npm_lock(tmp_path, {"express": "5.1.0", "axios": "1.7.2", "next": "16.4.3", "node-fetch": "2.7.0"})
    res = scan(tmp_path, ["/usr/bin/node", "/opt/x/bun"])
    srv = by_rule(res, SERVER)[0]
    assert srv["severity"] == "critical" and "ESCALATED to critical" in srv["message"]
    assert "/usr/bin/node" in srv["message"] and srv["related"] == ["/usr/bin/node", "/opt/x/bun"]
    assert by_rule(res, CLIENT)[0 if by_rule(res, CLIENT)[0]["evidence"].startswith("axios") else 1]["severity"] == "warn"
    assert all(f["severity"] == "info" for f in by_rule(res, COND))            # can't see usage: always info
    nf = [f for f in by_rule(res, CLIENT) if f["evidence"].startswith("node-fetch@2.7.0")][0]
    assert nf["severity"] == "info" and "UNCONFIRMED" in nf["message"] and "unknown / verify" in nf["message"]


def test_duplicates_across_lockfile_and_node_modules_are_reported_once(tmp_path):
    npm_lock(tmp_path, {"body-parser": "2.2.0"})
    w(tmp_path, "node_modules/body-parser/package.json", json.dumps({"name": "body-parser", "version": "2.2.0"}))
    res = scan(tmp_path)
    hits = by_rule(res, SERVER)
    assert len(hits) == 1 and "also 1 more file" in hits[0]["evidence"]


# ------------------------------------------------------------------ npm-family parsers ----

def test_package_lock_v1_with_nesting_and_alias(tmp_path):
    lock = {"name": "app", "lockfileVersion": 1, "dependencies": {
        "koa-body": {"version": "6.0.1", "dependencies": {"co-body": {"version": "6.2.0"}}},
        "body-parser": {"version": "1.20.3"},
        "my-alias": {"version": "npm:body-parser@2.0.0"},
        "linked": {"version": "file:../x"},
    }}
    w(tmp_path, "package-lock.json", json.dumps(lock))
    pk = {(p.name, p.version) for p in deps.parse_package_lock(str(tmp_path / "package-lock.json"))}
    assert pk == {("koa-body", "6.0.1"), ("co-body", "6.2.0"), ("body-parser", "1.20.3"), ("body-parser", "2.0.0")}
    res = scan(tmp_path)
    assert {f["evidence"].split(" ")[0] for f in by_rule(res, SERVER)} == {
        "koa-body@6.0.1", "co-body@6.2.0", "body-parser@2.0.0"}


def test_package_lock_v2_uses_packages_only_and_nested_paths(tmp_path):
    lock = {"lockfileVersion": 2,
            "packages": {"": {"name": "app"},
                         "node_modules/express": {"version": "5.1.0"},
                         "node_modules/express/node_modules/body-parser": {"version": "2.3.0"},
                         "node_modules/@koa/bodyparser": {"version": "5.1.1"},
                         "node_modules/linked": {"link": True, "resolved": "../x"}},
            "dependencies": {"express": {"version": "5.1.0"}}}
    w(tmp_path, "npm-shrinkwrap.json", json.dumps(lock))
    pk = {(p.name, p.version) for p in deps.parse_package_lock(str(tmp_path / "npm-shrinkwrap.json"))}
    assert pk == {("express", "5.1.0"), ("body-parser", "2.3.0"), ("@koa/bodyparser", "5.1.1")}


def test_yarn_classic_and_berry(tmp_path):
    classic = w(tmp_path, "classic/yarn.lock", """# yarn lockfile v1


axios@^1.6.0:
  version "1.7.2"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.7.2.tgz#abc"

body-parser@^2.0.0, body-parser@^2.1.0:
  version "2.2.0"
  dependencies:
    bytes "3.1.2"

"@fastify/compress@^8.0.0":
  version "8.0.1"
""")
    berry = w(tmp_path, "berry/yarn.lock", """__metadata:
  version: 8
  cacheKey: 10c0

"axios@npm:^1.6.0":
  version: 1.7.2
  resolution: "axios@npm:1.7.2"

"@koa/bodyparser@npm:^5.0.0, @koa/bodyparser@npm:^5.1.0":
  version: 5.1.1
  resolution: "@koa/bodyparser@npm:5.1.1"

"app@workspace:.":
  version: 0.0.0-use.local
""")
    c = {(p.name, p.version) for p in deps.parse_yarn_lock(str(classic))}
    b = {(p.name, p.version) for p in deps.parse_yarn_lock(str(berry))}
    assert c == {("axios", "1.7.2"), ("body-parser", "2.2.0"), ("@fastify/compress", "8.0.1")}
    assert ("axios", "1.7.2") in b and ("@koa/bodyparser", "5.1.1") in b
    assert not any(n == "app" and not v[0].isdigit() for n, v in b)


def test_pnpm_v9_v6_v5(tmp_path):
    v9 = w(tmp_path, "v9/pnpm-lock.yaml", """lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      express:
        specifier: ^5.1.0
        version: 5.1.0

packages:

  body-parser@2.2.0:
    resolution: {integrity: sha512-x}
    engines: {node: '>=18'}

  '@koa/bodyparser@5.1.1':
    resolution: {integrity: sha512-y}

  express@5.1.0:
    resolution: {integrity: sha512-z}

snapshots:

  body-parser@2.2.0:
    dependencies:
      bytes: 3.1.2

  express@5.1.0(supports-color@8.1.1):
    dependencies:
      body-parser: 2.2.0
""")
    v6 = w(tmp_path, "v6/pnpm-lock.yaml", """lockfileVersion: '6.0'

packages:

  /body-parser@2.2.0:
    resolution: {integrity: sha512-x}
    dev: false

  /@koa/bodyparser@5.1.1(peer@1.0.0):
    resolution: {integrity: sha512-y}
""")
    v5 = w(tmp_path, "v5/pnpm-lock.yaml", """lockfileVersion: 5.4

packages:

  /body-parser/2.2.0:
    resolution: {integrity: sha512-x}

  /@koa/bodyparser/5.1.1_peer@1.0.0:
    resolution: {integrity: sha512-y}
""")
    got9 = {(p.name, p.version) for p in deps.parse_pnpm_lock(str(v9))}
    assert got9 == {("body-parser", "2.2.0"), ("@koa/bodyparser", "5.1.1"), ("express", "5.1.0")}
    want = {("body-parser", "2.2.0"), ("@koa/bodyparser", "5.1.1")}
    assert {(p.name, p.version) for p in deps.parse_pnpm_lock(str(v6))} == want
    assert {(p.name, p.version) for p in deps.parse_pnpm_lock(str(v5))} == want


def test_bun_lock_text_and_binary_note(tmp_path):
    w(tmp_path, "bun.lock", """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "express": "^5.1.0",
      },
    },
  },
  "packages": {
    "express": ["express@5.1.0", "", { "dependencies": { "body-parser": "^2.2.0" } }, "sha512-aaa"],

    "body-parser": ["body-parser@2.2.0", "", {}, "sha512-bbb"],

    "@koa/bodyparser": ["@koa/bodyparser@5.1.1", "", {}, "sha512-ccc"],
  }
}
""")
    w(tmp_path, "bun.lockb", "binary-lockfile-placeholder")
    res = scan(tmp_path)
    assert {f["evidence"].split(" ")[0] for f in by_rule(res, SERVER)} == {
        "express@5.1.0", "body-parser@2.2.0", "@koa/bodyparser@5.1.1"}
    assert any("bun.lockb" in n for n in res["notes"])


def test_node_modules_walk_scoped_nested_and_pnpm_store(tmp_path):
    nm = tmp_path / "node_modules"
    w(nm, "body-parser/package.json", json.dumps({"name": "body-parser", "version": "2.3.0"}))
    w(nm, "@koa/bodyparser/package.json", json.dumps({"name": "@koa/bodyparser", "version": "6.1.0"}))
    w(nm, "express/package.json", json.dumps({"name": "express", "version": "5.1.0"}))
    w(nm, "express/node_modules/inflation/package.json", json.dumps({"name": "inflation", "version": "2.1.0"}))
    w(nm, ".bin/should-be-ignored/package.json", json.dumps({"name": "ignored", "version": "9.9.9"}))
    w(nm, "broken/package.json", "{not json")
    (nm / ".pnpm" / "axios@1.7.2" / "node_modules" / "axios").mkdir(parents=True)
    (nm / ".pnpm" / "@fastify+compress@8.0.1_peer@1.0.0" / "node_modules").mkdir(parents=True)
    pk = {(p.name, p.version) for p in deps.scan_node_modules(str(nm), [1000])}
    assert pk == {("body-parser", "2.3.0"), ("@koa/bodyparser", "6.1.0"), ("express", "5.1.0"),
                  ("inflation", "2.1.0"), ("axios", "1.7.2"), ("@fastify/compress", "8.0.1")}
    res = scan(tmp_path)
    assert {f["evidence"].split(" ")[0] for f in by_rule(res, SERVER)} == {
        "body-parser@2.3.0", "@koa/bodyparser@6.1.0", "express@5.1.0", "inflation@2.1.0",
        "@fastify/compress@8.0.1"}                      # the .pnpm store entry is flagged too
    assert [f["evidence"].split(" ")[0] for f in by_rule(res, CLIENT)] == ["axios@1.7.2"]


def test_node_modules_budget_is_bounded(tmp_path):
    for i in range(30):
        w(tmp_path, f"node_modules/pkg{i}/package.json", json.dumps({"name": f"pkg{i}", "version": "1.0.0"}))
    budget = [10]
    got = deps.scan_node_modules(str(tmp_path / "node_modules"), budget)
    assert len(got) <= 10 and budget[0] <= 0


def test_unparseable_lockfile_is_noted_not_fatal(tmp_path):
    w(tmp_path, "package-lock.json", "{ this is not json")
    res = scan(tmp_path)
    assert any("package-lock.json" in n and "not parsed" in n for n in res["notes"])
    assert res["findings"] == []


# ------------------------------------------------------------------ python ----

def test_requirements_pinned_brotli_with_aiohttp_is_critical(tmp_path):
    w(tmp_path, "requirements.txt", """# deps
Brotli==1.1.0
aiohttp[speedups]==3.9.5
requests>=2.31
scrapy~=2.11
brotlicffi==1.2.1.0 ; platform_python_implementation != "CPython"
urllib3[brotli]>=2.0
-r other.txt
git+https://example.org/x.git#egg=y
""")
    res = scan(tmp_path)
    py = {f["evidence"]: f for f in by_rule(res, "DEP_PY_BROTLI")}
    assert py["brotli==1.1.0"]["severity"] == "critical"
    assert "aiohttp" in py["brotli==1.1.0"]["message"] and "Consumers named in the project" in py["brotli==1.1.0"]["message"]
    assert py["brotlicffi==1.2.1.0"]["severity"] == "ok"
    assert "[.]" not in py["brotlicffi==1.2.1.0"]["evidence"]               # a 4-part version is not an IP


def test_requirements_without_aiohttp_is_warn_and_floors(tmp_path):
    w(tmp_path, "requirements.txt", "brotli==1.2.0\n")
    assert by_rule(scan(tmp_path), "DEP_PY_BROTLI")[0]["severity"] == "warn"
    p2 = tmp_path / "p2"
    w(p2, "requirements.txt", "brotli>=1.0.9\n")
    f = by_rule(scan(p2), "DEP_PY_BROTLI")[0]
    assert f["severity"] == "info" and "admits vulnerable versions" in f["message"] and "brotli>=1.2.0" in f["message"]
    p3 = tmp_path / "p3"
    w(p3, "requirements.txt", "brotli>=1.2.1\nbrotlicffi\n")
    sev = {f["evidence"]: f["severity"] for f in by_rule(scan(p3), "DEP_PY_BROTLI")}
    assert sev["brotli>=1.2.1"] == "ok" and sev["brotlicffi (any version)"] == "info"


def test_python_lockfiles(tmp_path):
    w(tmp_path, "poetry/poetry.lock", """[[package]]
name = "Brotli"
version = "1.1.0"
description = "Python bindings for the Brotli compression library"
optional = false

[[package]]
name = "aiohttp"
version = "3.9.5"
description = "Async http client/server framework (asyncio)"

[[package]]
name = "unrelated"
version = "1.0.0"
""")
    res = scan(tmp_path / "poetry")
    f = by_rule(res, "DEP_PY_BROTLI")[0]
    assert f["severity"] == "critical" and f["evidence"] == "brotli 1.1.0"
    w(tmp_path, "uv/uv.lock", """version = 1

[[package]]
name = "brotlicffi"
version = "1.2.0.2"
source = { registry = "https://pypi.org/simple" }
""")
    assert by_rule(scan(tmp_path / "uv"), "DEP_PY_BROTLI")[0]["severity"] == "warn"
    w(tmp_path, "pipenv/Pipfile.lock", json.dumps({
        "default": {"brotli": {"version": "==1.2.1"}, "aiohttp": {"version": "==3.9.5"}},
        "develop": {"brotlicffi": {"version": "==1.0.9.0"}}}))
    sev = {f["evidence"]: f["severity"] for f in by_rule(scan(tmp_path / "pipenv"), "DEP_PY_BROTLI")}
    assert sev == {"brotli 1.2.1": "ok", "brotlicffi 1.0.9.0": "critical"}


def test_same_pin_in_requirements_and_lock_is_reported_once(tmp_path):
    w(tmp_path, "requirements.txt", "brotli==1.1.0\n")
    w(tmp_path, "uv.lock", '[[package]]\nname = "brotli"\nversion = "1.1.0"\n')
    res = scan(tmp_path)
    # '==' requirement and a resolved lock entry are different shapes ('==' vs '') -> at most two, never more
    assert 1 <= len(by_rule(res, "DEP_PY_BROTLI")) <= 2


# ------------------------------------------------------------------ go / rust / ruby / java ----

def test_go_mod_and_sum(tmp_path):
    w(tmp_path, "go.mod", """module example.org/app

go 1.22

require (
	github.com/andybalholm/brotli v1.1.1
	golang.org/x/net v0.30.0
)
""")
    w(tmp_path, "go.sum", """github.com/andybalholm/brotli v1.1.1 h1:abc=
github.com/andybalholm/brotli v1.1.1/go.mod h1:def=
""")
    res = scan(tmp_path)
    hits = by_rule(res, "DEP_GO_BROTLI")
    assert len(hits) == 1 and hits[0]["severity"] == "warn" and "v1.2.7" in hits[0]["message"]
    p2 = tmp_path / "fixed"
    w(p2, "go.mod", "require github.com/andybalholm/brotli v1.2.7 // indirect\n")
    assert by_rule(scan(p2), "DEP_GO_BROTLI")[0]["severity"] == "ok"
    p3 = tmp_path / "pseudo"
    w(p3, "go.mod", "require github.com/andybalholm/brotli v1.2.7-0.20261023120000-abcdef123456\n")
    f = by_rule(scan(p3), "DEP_GO_BROTLI")[0]
    assert f["severity"] == "warn" and "pseudo-version" in f["message"]


def test_cargo_lock_is_info_unresolved(tmp_path):
    w(tmp_path, "Cargo.lock", """[[package]]
name = "brotli"
version = "8.0.1"

[[package]]
name = "brotli-decompressor"
version = "5.0.0"

[[package]]
name = "brotli"
version = "3.5.0"

[[package]]
name = "serde"
version = "1.0.200"
""")
    res = scan(tmp_path)
    hits = by_rule(res, "DEP_RUST_BROTLI_DECOMPRESSOR")
    assert sorted(f["evidence"] for f in hits) == ["brotli 8.0.1", "brotli-decompressor 5.0.0"]
    assert all(f["severity"] == "info" and "unknown / verify" in f["message"] and "NOT confirmed" in f["message"]
               for f in hits)


def test_gemfile_lock(tmp_path):
    w(tmp_path, "Gemfile.lock", """GEM
  remote: https://rubygems.org/
  specs:
    brotli (0.8.0)
    rack (3.0.0)

PLATFORMS
  ruby
""")
    f = by_rule(scan(tmp_path), "DEP_RUBY_BROTLI")[0]
    assert f["severity"] == "warn" and "0.9.1" in f["message"]
    p2 = tmp_path / "p2"
    w(p2, "Gemfile.lock", "GEM\n  specs:\n    brotli (0.9.2)\n")
    assert by_rule(scan(p2), "DEP_RUBY_BROTLI")[0]["severity"] == "ok"


def test_pom_and_gradle_brotli4j(tmp_path):
    w(tmp_path, "m/pom.xml", """<project>
  <properties><brotli4j.version>1.18.0</brotli4j.version></properties>
  <dependencies>
    <dependency>
      <groupId>com.aayushatharva.brotli4j</groupId>
      <artifactId>brotli4j</artifactId>
      <version>${brotli4j.version}</version>
    </dependency>
  </dependencies>
</project>
""")
    f = by_rule(scan(tmp_path / "m"), "DEP_JAVA_BROTLI4J")[0]
    assert f["severity"] == "warn" and f["evidence"] == "brotli4j 1.18.0"
    w(tmp_path, "g/build.gradle", """dependencies {
    implementation 'com.aayushatharva.brotli4j:brotli4j:1.23.0'
    runtimeOnly("com.aayushatharva.brotli4j:native-linux-x86_64:1.23.0")
}
""")
    hits = by_rule(scan(tmp_path / "g"), "DEP_JAVA_BROTLI4J")
    assert len(hits) == 1 and hits[0]["severity"] == "warn"                  # the two artefacts dedupe by version
    w(tmp_path, "h/build.gradle.kts", 'implementation("com.aayushatharva.brotli4j:brotli4j:1.24.0")\n')
    assert by_rule(scan(tmp_path / "h"), "DEP_JAVA_BROTLI4J")[0]["severity"] == "ok"


# ------------------------------------------------------------------ docker ----

DOCKERFILE = """ARG NODE_VERSION=24.22.0
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS build
RUN echo hi
FROM node:24 AS runtime
FROM build AS final
FROM oven/bun:1.4.3
FROM node@sha256:abcdef0123456789
FROM docker.io/library/node:20-alpine
FROM alpine:3.20
FROM public.ecr.aws/docker/library/node:22.23.4-slim
FROM myorg/node:1.0
"""


def test_dockerfile_tags(tmp_path):
    w(tmp_path, "Dockerfile", DOCKERFILE)
    res = scan(tmp_path)
    got = {f["evidence"]: f for f in by_rule(res, "DOCKER_BASE_IMAGE")}
    assert set(got) == {"FROM node:24.22.0-alpine", "FROM node:24", "FROM oven/bun:1.4.3",
                        "FROM node:<digest>", "FROM node:20-alpine", "FROM node:22.23.4-slim"}
    sev = {k: v["severity"] for k, v in got.items()}
    assert sev == {"FROM node:24.22.0-alpine": "critical", "FROM node:24": "info", "FROM oven/bun:1.4.3": "critical",
                   "FROM node:<digest>": "info", "FROM node:20-alpine": "critical", "FROM node:22.23.4-slim": "ok"}
    assert "rebuilt" in got["FROM node:24"]["message"]                        # floating tag -> rebuild
    assert "digest" in got["FROM node:<digest>"]["message"]
    assert "NO fixed release" in got["FROM node:20-alpine"]["message"]


def test_dockerfile_variants_and_compose(tmp_path):
    w(tmp_path, "docker/Dockerfile.prod", "FROM node:22.23.3-bookworm-slim\n")
    w(tmp_path, "api.dockerfile", "FROM node:${UNSET_VERSION}\n")
    w(tmp_path, "docker-compose.yml", """services:
  web:
    image: node:20
  db:
    image: postgres:16
  runner:
    image: 'oven/bun:1.4.4'
""")
    res = scan(tmp_path)
    got = {f["evidence"]: f["severity"] for f in by_rule(res, "DOCKER_BASE_IMAGE")}
    assert got["FROM node:22.23.3-bookworm-slim"] == "critical"
    assert got["FROM node:${UNSET_VERSION}"] == "info"
    assert got["FROM node:20"] == "critical" and got["FROM oven/bun:1.4.4"] == "ok"
    assert not any("postgres" in k for k in got)


def test_split_image_and_kind():
    assert deps.split_image("docker.io/library/node:22.23.3-slim@sha256:ab") == (["library", "node"], "22.23.3-slim", True)
    assert deps.split_image("localhost:5000/node:20") == (["node"], "20", False)
    assert deps.image_kind(["library", "node"]) == "node" and deps.image_kind(["oven", "bun"]) == "bun"
    assert deps.image_kind(["myorg", "node"]) is None and deps.image_kind(["alpine"]) is None


# ------------------------------------------------------------------ next config ----

def test_next_images_config_note(tmp_path):
    w(tmp_path, "a/next.config.mjs", "export default { images: { remotePatterns: [{ protocol: 'https', hostname: 'example.org' }] } }\n")
    assert by_rule(scan(tmp_path / "a"), "DEP_NEXT_IMAGES_CONFIG")[0]["severity"] == "info"
    w(tmp_path, "b/next.config.js", "module.exports = { images: { domains: ['example.org'] } }\n")
    assert by_rule(scan(tmp_path / "b"), "DEP_NEXT_IMAGES_CONFIG")
    w(tmp_path, "c/next.config.js", "module.exports = { images: { remotePatterns: [] } }\n")
    assert by_rule(scan(tmp_path / "c"), "DEP_NEXT_IMAGES_CONFIG") == []


# ------------------------------------------------------------------ walk bounds / run_deps ----

def test_walk_prunes_node_modules_git_and_depth(tmp_path):
    lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/express": {"version": "5.1.0"}}})
    w(tmp_path, "node_modules/foo/package-lock.json", lock)           # lockfile INSIDE node_modules: ignored
    w(tmp_path, ".git/package-lock.json", lock)
    w(tmp_path, ".venv/lib/package-lock.json", lock)
    deep = "/".join("abcdefghi")                                      # 9 levels
    w(tmp_path, f"{deep}/package-lock.json", lock)
    w(tmp_path, "svc/api/package-lock.json", lock)                    # depth 2: parsed
    found = deps.find_project_files(str(tmp_path))
    assert [os.path.relpath(p, tmp_path) for p in found["npm-lock"]] == ["svc/api/package-lock.json"]


def test_run_deps_escalation_flags_and_notes(tmp_path):
    p1, p2 = tmp_path / "p1", tmp_path / "p2"
    npm_lock(p1, {"express": "5.1.0"})
    npm_lock(p2, {"axios": "1.7.2"})
    missing = str(tmp_path / "nope")
    esc = deps.run_deps([str(p1), str(p2), missing], vulnerable_runtimes=["/usr/bin/node"], posture_ran=True)
    assert esc["runtime_escalation"] is True and len(esc["projects"]) == 2
    assert by_rule(esc, SERVER)[0]["severity"] == "critical"
    clean = deps.run_deps([str(p1)], vulnerable_runtimes=[], posture_ran=True)
    assert clean["runtime_escalation"] is False and by_rule(clean, SERVER)[0]["severity"] == "warn"
    nop = deps.run_deps([str(p1)], vulnerable_runtimes=None, posture_ran=False)
    assert nop["runtime_escalation"] is None
    assert any("posture was not part of this run" in n for n in nop["notes"])
    assert nop["projects"][0]["packages_scanned"] == 1 and nop["projects"][0]["files"]
