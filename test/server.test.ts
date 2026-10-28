// The web app's security gates, exercised against a real running server.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import http from "node:http";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { codeFor, stepAt } from "../src/server/totp.ts";

const ADMIN_EMAIL = "owner@example.com";
const ADMIN_PASSWORD = "Admin-Staple-Lantern-4";
const ALICE = { name: "Alice", email: "alice@example.com", password: "Alice-Correct-Horse-9" };
const BOB = { name: "Bob", email: "bob@example.com", password: "Bob-Battery-Staple-77" };
const ROOT = join(import.meta.dirname, "..");
let proc: ChildProcess;
let base = "";
let dataDir = "";
let cookie = ""; // the admin's session
let alice = "";
let bob = "";
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

async function signup(body: object): Promise<{ status: number; cookie: string; data: any }> {
  const r = await fetch(base + "/api/signup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: r.status, cookie: (r.headers.get("set-cookie") ?? "").split(";")[0], data: await r.json().catch(() => null) };
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
    env: { ...process.env, PORT: String(port), LUCENT_REQUIRE_2FA: "0", LUCENT_ADMIN_EMAIL: ADMIN_EMAIL, LUCENT_ADMIN_PASSWORD: ADMIN_PASSWORD, LUCENT_DATA_DIR: dataDir, LUCENT_TICK_MS: "3600000", LUCENT_ALLOW_INTERNAL: "1" },
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
  assert.equal((await call("/api/auth", { auth: false })).data.authed, false);
  for (const p of ["/about", "/terms", "/privacy"]) assert.equal((await fetch(base + p)).status, 200, p);
});

test("sign-up checks the name, email and password", async () => {
  assert.equal((await signup({ name: "", email: "a@b.co", password: "long-enough-pass" })).status, 400);
  assert.equal((await signup({ name: "X", email: "not-an-email", password: "long-enough-pass" })).status, 400);
  assert.equal((await signup({ name: "X", email: "x@example.com", password: "short" })).status, 400);
});

test("nobody can claim the admin email without the admin password", async () => {
  const r = await signup({ name: "Mallory", email: ADMIN_EMAIL, password: "Guessing-The-Admin-1" });
  assert.equal(r.status, 403);
  assert.equal(r.cookie, "");
});

test("creating an account signs you in with a secure session cookie", async () => {
  const r = await fetch(base + "/api/signup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(ALICE) });
  assert.equal(r.status, 200);
  const set = r.headers.get("set-cookie") ?? "";
  assert.match(set, /HttpOnly/);
  assert.match(set, /SameSite=Lax/);
  alice = set.split(";")[0];
  const me = await call("/api/auth", { headers: { cookie: alice } });
  assert.equal(me.data.user.email, ALICE.email);
  assert.equal(me.data.user.admin, false);
  assert.ok(!("hash" in me.data.user) && !("salt" in me.data.user), "the password hash never leaves the server");
  assert.equal((await signup({ ...ALICE, name: "Alice again" })).status, 409, "one account per email");
  bob = (await signup(BOB)).cookie;
  // The stored file holds a hash, never the password.
  const users = readFileSync(join(dataDir, "users.json"), "utf8");
  assert.ok(!users.includes(ALICE.password));
});

test("the admin account is created with the admin email and admin password", async () => {
  const r = await signup({ name: "Saleem", email: "Owner@Example.com", password: ADMIN_PASSWORD });
  assert.equal(r.status, 200);
  assert.equal(r.data.user.admin, true);
  cookie = r.cookie;
});

test("logging in: right details work, wrong ones get the same message either way", async () => {
  const ok = await call("/api/login", { method: "POST", body: { email: ALICE.email, password: ALICE.password }, auth: false });
  assert.equal(ok.status, 200);
  const wrongPass = await call("/api/login", { method: "POST", body: { email: ALICE.email, password: "nope-nope-nope" }, auth: false });
  const noUser = await call("/api/login", { method: "POST", body: { email: "ghost@example.com", password: "nope-nope-nope" }, auth: false });
  assert.equal(wrongPass.status, 401);
  assert.equal(noUser.status, 401);
  assert.equal(wrongPass.data.error, noUser.data.error, "no way to tell which emails have accounts");
});

test("state changes from another site are blocked (CSRF), including log in and sign-up", async () => {
  const evil = { origin: "https://evil.example" };
  assert.equal((await call("/api/assets", { method: "POST", body: { name: "x", kind: "web", target: "https://x.example", authorized: true }, headers: evil })).status, 403);
  assert.equal((await call("/api/login", { method: "POST", body: { email: ALICE.email, password: ALICE.password }, auth: false, headers: evil })).status, 403);
  assert.equal((await call("/api/signup", { method: "POST", body: { name: "E", email: "e@example.com", password: "long-enough-pass" }, auth: false, headers: evil })).status, 403);
});

test("static files cannot escape the UI folder", async () => {
  for (const p of ["/../package.json", "/..%2f..%2fpackage.json", "/%2e%2e/%2e%2e/etc/passwd"]) {
    const r = await fetch(base + p);
    const text = await r.text();
    assert.ok(!text.includes('"name": "lucent-shield"') && !text.includes("root:x:0:0"), p);
  }
});

test("normal accounts cannot read the server's own files", async () => {
  const h = { cookie: alice };
  assert.equal((await call("/api/assets", { method: "POST", body: { name: "srv", kind: "repo", target: "/etc" }, headers: h })).status, 400);
  assert.equal((await call("/api/assets", { method: "POST", body: { name: "srv", kind: "repo", target: ROOT }, headers: h })).status, 400);
  assert.equal((await call("/api/assets", { method: "POST", body: { name: "ev", kind: "artifact", target: "/etc/passwd" }, headers: h })).status, 403);
  assert.equal((await call("/api/assets", { method: "POST", body: { name: "gh", kind: "repo", target: "https://github.com/alice/shop" }, headers: h })).status, 200);
});

test("each account sees only its own assets", async () => {
  const mine = await call("/api/assets", { method: "POST", body: { name: "alice-site", kind: "web", target: "https://alice.example", authorized: true }, headers: { cookie: alice } });
  const id = mine.data.asset.id;
  const theirs = await call("/api/assets", { headers: { cookie: bob } });
  assert.equal(theirs.data.assets.length, 0, "Bob sees none of Alice's assets");
  for (const [path, method] of [[`/api/assets/${id}`, "GET"], [`/api/assets/${id}/scan`, "POST"], [`/api/assets/${id}/report`, "GET"], [`/api/assets/${id}`, "DELETE"]] as const) {
    assert.equal((await call(path, { method, body: method === "POST" ? { authorized: true } : undefined, headers: { cookie: bob } })).status, 404, `${method} ${path}`);
  }
  assert.equal((await call(`/api/assets/${id}`, { headers: { cookie: alice } })).status, 200, "still there for Alice");
});

test("every scan needs explicit authorisation, recorded in the audit log with who gave it", async () => {
  const { data } = await call("/api/assets", { method: "POST", body: { name: "code", kind: "repo", target: ROOT + "/src/util" } });
  const id = data.asset.id;
  assert.equal((await call(`/api/assets/${id}/scan`, { method: "POST", body: {} })).status, 403);
  const ok = await call(`/api/assets/${id}/scan`, { method: "POST", body: { authorized: true } });
  assert.equal(ok.status, 200);
  const log = JSON.parse(readFileSync(join(dataDir, "authorizations.json"), "utf8"));
  assert.equal(log[0].assetId, id);
  assert.equal(log[0].email, ADMIN_EMAIL);
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

test("protect needs a scan first, proven ownership, and its own recorded permission", async () => {
  // Code asset: scanned earlier in this file by the admin.
  const code = (await call("/api/assets")).data.assets.find((a: any) => a.kind === "repo" && a.lastScanAt);
  assert.equal(code.monitor, false, "nothing is watched until the owner presses Protect");
  assert.equal((await call(`/api/assets/${code.id}/monitor`, { method: "POST", body: { on: true } })).status, 403, "needs explicit permission");
  const on = await call(`/api/assets/${code.id}/monitor`, { method: "POST", body: { on: true, authorized: true } });
  assert.equal(on.status, 200);
  assert.equal(on.data.asset.monitor, true);
  const log = JSON.parse(readFileSync(join(dataDir, "authorizations.json"), "utf8"));
  assert.equal(log[0].reference, "Continuous protection (Protect)");

  // An unverified website can never be protected (so it is never scanned in the background).
  const site = (await call("/api/assets", { method: "POST", body: { name: "unproven", kind: "web", target: "https://unproven.example", authorized: true } })).data.asset;
  assert.equal((await call(`/api/assets/${site.id}/monitor`, { method: "POST", body: { on: true, authorized: true } })).status, 403);

  // Recent activity holds only real events.
  const ev = (await call("/api/activity")).data.events;
  assert.ok(ev.some((e: any) => e.type === "protect-on" && e.assetId === code.id));
  assert.ok(ev.some((e: any) => e.type === "added" && e.assetId === site.id));
  assert.ok(!ev.some((e: any) => e.type === "scan" && e.assetId === site.id), "no scan is reported for the unproven site");
  assert.equal((await call("/api/activity", { headers: { cookie: bob } })).data.events.length, 0, "each account sees only its own activity");
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

test("the assessment report carries the scan's authorization", async () => {
  const list = (await call("/api/assets")).data.assets.filter((a: any) => a.lastScanAt);
  assert.ok(list.length, "a scanned asset exists");
  const id = list[0].id;
  const view = await fetch(`${base}/api/assets/${id}/report?view=1`, { headers: { cookie } });
  assert.equal(view.status, 200);
  assert.match(view.headers.get("content-disposition") ?? "", /^inline/);
  const html = await view.text();
  assert.ok(html.includes("Security Assessment Report") && html.includes("Explicit authorization was given"));
  const dl = await fetch(`${base}/api/assets/${id}/report?format=md`, { headers: { cookie } });
  assert.match(dl.headers.get("content-disposition") ?? "", /^attachment/);
  assert.equal((await fetch(`${base}/api/assets/${id}/report`)).status, 401, "needs a login");
});

test("owners who cannot change files or DNS can ask a person; only the admin approves", async () => {
  const site = (await call("/api/assets", { method: "POST", body: { name: "nontech", kind: "web", target: "https://nontech.example", authorized: true }, headers: { cookie: alice } })).data.asset;
  assert.equal((await call(`/api/assets/${site.id}/verify-request`, { method: "POST", body: { note: "short", contact: "x" }, headers: { cookie: alice } })).status, 400);
  const r = await call(`/api/assets/${site.id}/verify-request`, { method: "POST", body: { note: "I own the business; my developer built the site.", contact: "+234 800 000 0000" }, headers: { cookie: alice } });
  assert.equal(r.status, 200);
  // Still not scannable until a person approves.
  assert.equal((await call(`/api/assets/${site.id}/scan`, { method: "POST", body: { authorized: true }, headers: { cookie: alice } })).status, 403);
  assert.equal((await call(`/api/admin/verify/${site.id}`, { method: "POST", body: { approve: true }, headers: { cookie: alice } })).status, 403, "a customer cannot approve");
  const o = await call("/api/admin/overview");
  assert.ok(o.data.verifyRequests.some((v: any) => v.id === site.id && v.contact === "+234 800 000 0000"));
  assert.equal((await call(`/api/admin/verify/${site.id}`, { method: "POST", body: { approve: true } })).status, 200);
  assert.equal((await call(`/api/assets/${site.id}`, { headers: { cookie: alice } })).data.asset.verified, true);
  const log = JSON.parse(readFileSync(join(dataDir, "authorizations.json"), "utf8"));
  assert.equal(log[0].reference, "Ownership approved on manual review");
  assert.equal(log[0].email, ADMIN_EMAIL);
});

test("the admin view is for the admin only", async () => {
  assert.equal((await call("/api/admin/overview", { headers: { cookie: alice } })).status, 403);
  assert.equal((await call("/api/admin/audit.json", { headers: { cookie: alice } })).status, 403);
  const o = await call("/api/admin/overview");
  assert.equal(o.status, 200);
  assert.equal(o.data.totals.users, 3);
  assert.ok(o.data.users.some((u: any) => u.email === ADMIN_EMAIL && u.admin));
  assert.ok(o.data.authorizations.length > 0, "audit trail is shown");
  assert.ok(o.data.logins.some((l: any) => l.event === "signup" && !l.ok && l.email === ADMIN_EMAIL), "the attempt to claim the admin email is recorded");
  assert.ok(o.data.assets.every((a: any) => !("verifyToken" in a) && !("findings" in a)));
  const text = JSON.stringify(o.data);
  for (const secret of [ADMIN_PASSWORD, ALICE.password, '"hash"', '"salt"']) assert.equal(text.includes(secret), false, secret);
  const dl = await fetch(base + "/api/admin/audit.json", { headers: { cookie } });
  assert.match(dl.headers.get("content-disposition") ?? "", /attachment/);
});

test("two-step login: set up with an app code, then every login needs a code", async () => {
  const h = { cookie: alice };
  const st = await call("/api/account/2fa/start", { method: "POST", body: { password: ALICE.password }, headers: h });
  assert.equal(st.status, 200);
  assert.match(st.data.uri, /^otpauth:\/\/totp\/Lucent%20Shield:/);
  const secret = st.data.secret;
  assert.equal((await call("/api/account/2fa/enable", { method: "POST", body: { code: "000000" }, headers: h })).status, 400);
  const on = await call("/api/account/2fa/enable", { method: "POST", body: { code: codeFor(secret, stepAt()) }, headers: h });
  assert.equal(on.status, 200);
  assert.equal(on.data.recoveryCodes.length, 10);
  assert.equal(on.data.user.twoStep, true);

  // The password alone is no longer enough: no session cookie, just a ticket.
  const pw = await fetch(base + "/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: ALICE.email, password: ALICE.password }) });
  const step1 = await pw.json();
  assert.equal(step1.needCode, true);
  assert.equal(pw.headers.get("set-cookie"), null);
  const code = codeFor(secret, stepAt() + 1);
  const ok = await call("/api/login/code", { method: "POST", body: { ticket: step1.ticket, code }, auth: false });
  assert.equal(ok.status, 200);
  assert.equal((await call("/api/login/code", { method: "POST", body: { ticket: step1.ticket, code }, auth: false })).status, 401, "a ticket works once");

  // The same code can never be used twice.
  const again = (await call("/api/login", { method: "POST", body: { email: ALICE.email, password: ALICE.password }, auth: false })).data.ticket;
  assert.equal((await call("/api/login/code", { method: "POST", body: { ticket: again, code }, auth: false })).status, 401);

  // A recovery code works once.
  const rc = on.data.recoveryCodes[0];
  const t2 = (await call("/api/login", { method: "POST", body: { email: ALICE.email, password: ALICE.password }, auth: false })).data.ticket;
  assert.equal((await call("/api/login/code", { method: "POST", body: { ticket: t2, code: rc }, auth: false })).status, 200);
  const t3 = (await call("/api/login", { method: "POST", body: { email: ALICE.email, password: ALICE.password }, auth: false })).data.ticket;
  assert.equal((await call("/api/login/code", { method: "POST", body: { ticket: t3, code: rc }, auth: false })).status, 401);

  // Turning it off needs a valid code too; the secret is never shown to the admin.
  assert.equal((await call("/api/account/2fa/disable", { method: "POST", body: { password: ALICE.password, code: "123456" }, headers: h })).status, 400);
  const o = await call("/api/admin/overview");
  assert.ok(!JSON.stringify(o.data).includes(secret));
  assert.ok(o.data.users.some((u: any) => u.email === ALICE.email && u.twoStep));
});

test("too many new accounts from one address are refused", async () => {
  assert.equal((await signup({ name: "Carol", email: "carol@example.com", password: "Carol-Long-Password-1" })).status, 200);
  assert.equal((await signup({ name: "Dave", email: "dave@example.com", password: "Dave-Long-Password-1" })).status, 429);
});

test("logging out ends the session for real (the old cookie stops working)", async () => {
  assert.equal((await call("/api/logout", { method: "POST", headers: { cookie: bob } })).status, 200);
  assert.equal((await call("/api/assets", { headers: { cookie: bob } })).status, 401);
});

test("repeated wrong passwords lock the address out", async () => {
  let last = 0;
  for (let i = 0; i < 9; i++) last = (await call("/api/login", { method: "POST", body: { email: ALICE.email, password: "guess-" + i }, auth: false })).status;
  assert.equal(last, 429);
  // Even the right password is refused while locked.
  assert.equal((await call("/api/login", { method: "POST", body: { email: ALICE.email, password: ALICE.password }, auth: false })).status, 429);
});
