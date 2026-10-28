// The web app's security gates, exercised against a real running server.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import http from "node:http";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";

const PASSWORD = "Correct-Horse-Battery-9";
const ADMIN_EMAIL = "owner@example.com";
const ADMIN_PASSWORD = "Admin-Staple-Lantern-4";
const ROOT = join(import.meta.dirname, "..");
let proc: ChildProcess;
let base = "";
let dataDir = "";
let cookie = "";
let slow: http.Server;
let slowUrl = "";

async function call(path: string, opts: { method?: string; body?: unknown; auth?: boolean; headers?: Record<string, string> } = {}) {
  const res = await fetch(base + path, {
    method: opts.method ?? "GET",
    headers: { ...(opts.body ? { "content-type": "application/json" } : {}), ...(opts.auth === false ? {} : { cookie }), ...opts.headers },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data: any = null;
  try { data = await res.json(); } catch { /* not JSON */ }
  return { status: res.status, data, headers: res.headers };
}

before(async () => {
  // A slow website, used to hold one scan open while a second one is attempted.
  slow = http.createServer((_q, r) => setTimeout(() => { r.writeHead(200, { "content-type": "text/html" }); r.end("<html></html>"); }, 1500));
  await new Promise<void>((r) => slow.listen(0, "127.0.0.1", () => r()));
  slowUrl = `http://127.0.0.1:${(slow.address() as AddressInfo).port}`;

  dataDir = mkdtempSync(join(tmpdir(), "ls-srv-"));
  const port = 20000 + Math.floor(Math.random() * 30000);
  base = `http://127.0.0.1:${port}`;
  proc = spawn(process.execPath, [...process.execArgv, join(ROOT, "src/server/server.ts")], {
    env: { ...process.env, PORT: String(port), LUCENT_PASSWORD: PASSWORD, LUCENT_ADMIN_EMAIL: ADMIN_EMAIL, LUCENT_ADMIN_PASSWORD: ADMIN_PASSWORD, LUCENT_DATA_DIR: dataDir, LUCENT_TICK_MS: "3600000", LUCENT_ALLOW_INTERNAL: "1" },
    stdio: "ignore",
  });
  for (let i = 0; i < 100; i++) {
    try { await fetch(base + "/api/auth"); break; } catch { await new Promise((r) => setTimeout(r, 100)); }
  }
});

after(() => {
  proc?.kill();
  slow?.close();
  rmSync(dataDir, { recursive: true, force: true });
});

test("everything private needs a login; public pages do not", async () => {
  assert.equal((await call("/api/assets", { auth: false })).status, 401);
  assert.equal((await call("/api/favicon?u=example.com", { auth: false })).status, 401);
  for (const p of ["/about", "/terms", "/privacy"]) assert.equal((await fetch(base + p)).status, 200, p);
});

test("a wrong password is refused, and repeated guessing is locked out", async () => {
  assert.equal((await call("/api/login", { method: "POST", body: { password: "nope" }, auth: false })).status, 401);
  // (8 failures trigger a lock; the lock is per address, so it is checked last in this file)
});

test("the right password opens a secure session cookie", async () => {
  const res = await fetch(base + "/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: PASSWORD }) });
  assert.equal(res.status, 200);
  const set = res.headers.get("set-cookie") ?? "";
  assert.match(set, /HttpOnly/);
  assert.match(set, /SameSite=Lax/);
  cookie = set.split(";")[0];
  assert.equal((await call("/api/assets")).status, 200);
});

test("state changes from another site are blocked (CSRF)", async () => {
  const r = await call("/api/assets", { method: "POST", body: { name: "x", kind: "repo", target: "/tmp" }, headers: { origin: "https://evil.example" } });
  assert.equal(r.status, 403);
});

test("static files cannot escape the UI folder", async () => {
  for (const p of ["/../package.json", "/..%2f..%2fpackage.json", "/%2e%2e/%2e%2e/etc/passwd"]) {
    const r = await fetch(base + p);
    const text = await r.text();
    assert.ok(!text.includes('"name": "lucent-shield"') && !text.includes("root:x:0:0"), p);
  }
});

test("every scan needs explicit authorisation, recorded in the audit log", async () => {
  const { data } = await call("/api/assets", { method: "POST", body: { name: "code", kind: "repo", target: ROOT + "/src/util" } });
  const id = data.asset.id;
  assert.equal((await call(`/api/assets/${id}/scan`, { method: "POST", body: {} })).status, 403);
  const ok = await call(`/api/assets/${id}/scan`, { method: "POST", body: { authorized: true } });
  assert.equal(ok.status, 200);
  const log = JSON.parse(readFileSync(join(dataDir, "authorizations.json"), "utf8"));
  assert.equal(log[0].assetId, id);
  assert.ok(log[0].at);
});

test("a website cannot be scanned until domain ownership is proven", async () => {
  const add = await call("/api/assets", { method: "POST", body: { name: "site", kind: "web", target: slowUrl, authorized: true } });
  assert.equal(add.status, 200);
  assert.equal(add.data.asset.verified, false);
  assert.ok(add.data.asset.verifyToken.length >= 20);
  const r = await call(`/api/assets/${add.data.asset.id}/scan`, { method: "POST", body: { authorized: true } });
  assert.equal(r.status, 403);
  const v = await call(`/api/assets/${add.data.asset.id}/verify`, { method: "POST" });
  assert.equal(v.data.verified, false); // the token is not published on that site
});

test("forensics needs a legal attestation and a reference", async () => {
  const p = join(dataDir, "evidence.txt");
  writeFileSync(p, "hello");
  const { data } = await call("/api/assets", { method: "POST", body: { name: "ev", kind: "artifact", target: p } });
  const id = data.asset.id;
  assert.equal((await call(`/api/assets/${id}/scan`, { method: "POST", body: { authorized: true } })).status, 403);
  assert.equal((await call(`/api/assets/${id}/scan`, { method: "POST", body: { authorized: true, legal: true, reference: "  " } })).status, 403);
  assert.equal((await call(`/api/assets/${id}/scan`, { method: "POST", body: { authorized: true, legal: true, reference: "WARRANT-2026-014" } })).status, 200);
  const log = JSON.parse(readFileSync(join(dataDir, "authorizations.json"), "utf8"));
  assert.equal(log[0].reference, "WARRANT-2026-014");
});

test("the same asset cannot be scanned twice at once", async () => {
  // Mark a website as verified directly in storage, then race two scans.
  const add = await call("/api/assets", { method: "POST", body: { name: "slow", kind: "web", target: slowUrl, authorized: true } });
  const file = join(dataDir, "assets.json");
  const assets = JSON.parse(readFileSync(file, "utf8"));
  assets.find((a: any) => a.id === add.data.asset.id).verified = true;
  writeFileSync(file, JSON.stringify(assets));
  const first = call(`/api/assets/${add.data.asset.id}/scan`, { method: "POST", body: { authorized: true } });
  await new Promise((r) => setTimeout(r, 200));
  const second = await call(`/api/assets/${add.data.asset.id}/scan`, { method: "POST", body: { authorized: true } });
  assert.equal(second.status, 409);
  assert.equal((await first).status, 200);
});

test("a damaged data file is kept aside, never silently wiped", async () => {
  writeFileSync(join(dataDir, "alerts.json"), "{ broken");
  assert.equal((await call("/api/alerts")).status, 200);
  assert.ok(readdirSync(dataDir).some((f) => f.startsWith("alerts.json.corrupt-")));
});

test("the admin view is for the admin only", async () => {
  // A normal dashboard session is refused.
  assert.equal((await call("/api/admin/overview")).status, 403);
  assert.equal((await call("/api/admin/audit.json")).status, 403);
  assert.equal((await call("/api/auth")).data.admin, false);
  // The dashboard password does not open the admin account, nor a wrong admin password.
  assert.equal((await call("/api/login", { method: "POST", body: { email: ADMIN_EMAIL, password: PASSWORD }, auth: false })).status, 401);
  // The admin email (any letter case) with the admin password does.
  const res = await fetch(base + "/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "Owner@Example.com", password: ADMIN_PASSWORD }) });
  assert.equal(res.status, 200);
  const admin = (res.headers.get("set-cookie") ?? "").split(";")[0];
  assert.equal((await call("/api/auth", { headers: { cookie: admin } })).data.admin, true);
  const o = await call("/api/admin/overview", { headers: { cookie: admin } });
  assert.equal(o.status, 200);
  assert.ok(o.data.authorizations.length > 0, "audit trail is shown");
  assert.ok(o.data.logins.some((l: any) => l.role === "admin" && !l.ok), "the refused admin sign-in is recorded");
  assert.ok(o.data.assets.every((a: any) => !("verifyToken" in a) && !("findings" in a)));
  assert.equal(JSON.stringify(o.data).includes(ADMIN_PASSWORD), false, "no secret is ever returned");
  assert.equal(JSON.stringify(o.data).includes(PASSWORD), false);
  const dl = await fetch(base + "/api/admin/audit.json", { headers: { cookie: admin } });
  assert.match(dl.headers.get("content-disposition") ?? "", /attachment/);
});

test("logging out ends the session for real (the old cookie stops working)", async () => {
  const old = cookie;
  assert.equal((await call("/api/logout", { method: "POST" })).status, 200);
  assert.equal((await call("/api/assets", { headers: { cookie: old } })).status, 401);
});

test("repeated wrong passwords lock the address out", async () => {
  let last = 0;
  for (let i = 0; i < 9; i++) last = (await call("/api/login", { method: "POST", body: { password: "guess" + i }, auth: false })).status;
  assert.equal(last, 429);
  // Even the right password is refused while locked.
  assert.equal((await call("/api/login", { method: "POST", body: { password: PASSWORD }, auth: false })).status, 429);
});
