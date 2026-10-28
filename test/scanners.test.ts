// Source scanners: the benchmark project, plus targeted cases for every
// false-alarm guard. Run with: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { buildFixture } from "./fixture.ts";
import { runRepoScan, shieldFor } from "../src/engine.ts";
import { scanSecrets } from "../src/scanners/secrets.ts";
import { scanCode } from "../src/scanners/code.ts";
import { insideLiteral, isTestPath } from "../src/util/source.ts";
import type { ScanFile } from "../src/util/walk.ts";
import type { Finding } from "../src/types.ts";

const file = (rel: string, text: string): ScanFile => ({ path: rel, rel, text, lines: text.split("\n") });
const rules = (fs: Finding[]) => fs.map((f) => f.rule);
const j = (...p: string[]) => p.join("");

test("benchmark: every planted issue is caught with the right rule, and no decoy is flagged", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ls-bench-"));
  try {
    const { expected, decoys } = buildFixture(dir);
    const findings = await runRepoScan(dir, { offline: true });
    const missed = expected.filter((e) => !findings.some((f) => f.rule === e.rule && f.location === e.file && (f.line === undefined || (f.line >= e.start && f.line <= e.end))));
    assert.deepEqual(missed.map((m) => `${m.rule} ${m.file}:${m.start}`), []);
    const falseAlarms = findings.filter((f) => decoys.includes(f.location ?? ""));
    assert.deepEqual(falseAlarms.map((f) => `${f.rule} ${f.location}`), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secrets: evidence is redacted, never the full value", () => {
  const key = j("sk_", "live_", "51HxQ2bD9kLm8Np4Rt7Vw3Yz");
  const [f] = scanSecrets([file("pay.js", `const k = "${key}";`)]);
  assert.equal(f.rule, "secret.live-payment-key");
  assert.ok(!f.evidence!.includes(key), "the live key must not appear in the report");
});

test("secrets: placeholders, env reads and plain words are not secrets", () => {
  const out = scanSecrets([file("a.js", [
    `const key = process.env.API_KEY;`,
    `const password = "your-password-here";`,
    `autocomplete: mode === "login" ? "current-password" : "new-password"`,
    `const token = "<TOKEN>";`,
    `const secret = "\${SECRET}";`,
  ].join("\n"))]);
  assert.deepEqual(rules(out), []);
});

test("secrets: obviously fake keys are ignored, real-looking ones are not", () => {
  const fake = j("github_pat_", "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ");
  const real = j("ghp_", "R8kLm2Np4Qs6Tu8Vw0Xy2Za4Bc6De8Fg0Hi2");
  assert.deepEqual(rules(scanSecrets([file("t.js", `const t = "${fake}";`)])), []);
  assert.deepEqual(rules(scanSecrets([file("t.js", `const t = "${real}";`)])), ["secret.github-token"]);
});

test("secrets: test files skip guessed secrets but still catch real provider keys", () => {
  const aws = j("AKIA", "Q3R7NV2KZ7KD2M4W");
  const out = scanSecrets([file("test/login.test.ts", `const PASSWORD = "Lagos-Builds-2026!";\nconst k = "${aws}";`)]);
  assert.deepEqual(rules(out), ["secret.aws-access-key"]);
});

test("secrets: a reviewed line can be suppressed with lucent-ignore", () => {
  const aws = j("AKIA", "Q3R7NV2KZ7KD2M4W");
  assert.deepEqual(rules(scanSecrets([file("a.js", `const k = "${aws}"; // lucent-ignore: revoked key kept for a demo`)])), []);
  assert.deepEqual(rules(scanSecrets([file("a.js", `// lucent-ignore-next-line\nconst k = "${aws}";`)])), []);
});

test("secrets: a committed .env is reported once, plus each secret value; templates are not", () => {
  const out = scanSecrets([file(".env", "DB_PASSWORD=Qm8vR2kL9xZ\nPORT=3000\nAPI_KEY=Zk2mQ9vT3bL8\n"), file(".env.example", "DB_PASSWORD=changeme\n")]);
  assert.deepEqual(rules(out), ["secret.env-file", "secret.env-value", "secret.env-value"]);
});

test("code: jwt.verify with algorithms on the following lines is not flagged", () => {
  const src = `const d = jwt.verify(\n  token,\n  SECRET, { algorithms: ["HS256"] }\n);`;
  assert.deepEqual(rules(scanCode([file("auth.ts", src)])), []);
  assert.deepEqual(rules(scanCode([file("auth.ts", `const d = jwt.verify(token, SECRET);`)])), ["code.js.jwt-no-alg"]);
});

test("code: SQL with only fixed text interpolated is safe; dynamic identifiers with bound values are medium", () => {
  const safe = "db.prepare(`SELECT * FROM f ${openOnly ? \"WHERE done = 0\" : \"\"} ORDER BY id`).all();";
  const ident = "db.prepare(`UPDATE t SET ${col} = ? WHERE id = ?`).run(v, id);";
  const bad = "db.prepare(`SELECT * FROM users WHERE id = ${req.params.id}`).get();";
  assert.deepEqual(scanCode([file("a.ts", safe)]), []);
  assert.equal(scanCode([file("a.ts", ident)])[0].severity, "medium");
  assert.equal(scanCode([file("a.ts", bad)])[0].severity, "critical");
});

test("code: words inside strings, regexes and comments are not code", () => {
  const src = [
    `const label = "eval() is dangerous";`,
    `const re = /eval\\s*\\(/;`,
    `doThing(); // never call eval(x) here`,
    `// eval(userInput)`,
  ].join("\n");
  assert.deepEqual(rules(scanCode([file("a.js", src)])), []);
  assert.deepEqual(rules(scanCode([file("a.js", "eval(userInput);")])), ["code.js.eval"]);
});

test("code: XSS severity follows the data source", () => {
  const sev = (line: string) => scanCode([file("a.js", line)])[0]?.severity;
  assert.equal(sev("el.innerHTML = renderView();"), "low");
  assert.equal(sev("el.innerHTML = location.hash;"), "high");
  assert.equal(sev("document.write(msg);"), "medium");
  assert.equal(sev(`el.innerHTML = "";`), undefined); // clearing an element is safe
  assert.equal(sev("el.innerHTML = DOMPurify.sanitize(html);"), undefined);
});

test("code: test files are not reported for code patterns", () => {
  assert.deepEqual(scanCode([file("src/__tests__/db.test.ts", "db.query(`SELECT * FROM t WHERE id = ${id}`);")]), []);
});

test("code: Dockerfile stages are understood", () => {
  const multi = "FROM node:22-slim AS build\nRUN npm ci\nFROM build\nUSER node\nCMD [\"node\",\"a.js\"]";
  assert.deepEqual(rules(scanCode([file("Dockerfile", multi)])), []);
});

test("helpers: literal detection and test-path detection", () => {
  assert.equal(insideLiteral(`x = "a eval( b"`, 8), true);
  assert.equal(insideLiteral(`eval(x)`, 0), false);
  assert.equal(insideLiteral(`r = /a(b)/; eval(x)`, 12), false);
  for (const p of ["test/a.ts", "src/x.test.ts", "pkg/a_test.go", "tests/test_x.py", "spec/a_spec.rb", "src/FooTests.cs"]) assert.equal(isTestPath(p), true, p);
  for (const p of ["src/testimony.ts", "src/contest.js", "latest/app.py"]) assert.equal(isTestPath(p), false, p);
});

test("engine: shield state follows the worst finding", () => {
  const f = (severity: Finding["severity"]): Finding => ({ rule: "x", severity, category: "code", title: "", detail: "", remediation: "" });
  assert.equal(shieldFor([]), "secure");
  assert.equal(shieldFor([f("info")]), "secure");
  assert.equal(shieldFor([f("low"), f("medium")]), "at_risk");
  assert.equal(shieldFor([f("medium"), f("high")]), "exposed");
});

test("engine: scanning never crashes on odd files", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ls-odd-"));
  try {
    const put = (rel: string, body: string | Buffer) => { mkdirSync(dirname(join(dir, rel)), { recursive: true }); writeFileSync(join(dir, rel), body); };
    put("bin.dat", Buffer.from([0, 1, 2, 255, 254, 0]));
    put("long.js", "x".repeat(50_000));
    put("weird/ünïcödé.py", "print('hi')\n");
    put("empty.ts", "");
    put("package-lock.json", "{ not json");
    const out = await runRepoScan(dir, { offline: true });
    assert.ok(Array.isArray(out));
    assert.ok(!out.some((x) => x.rule.endsWith("-failed")), "no check should fail");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
