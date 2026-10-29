// By default every account must set up an authenticator app before it can do anything.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { codeFor, stepAt } from "../src/server/totp.ts";

const ROOT = join(import.meta.dirname, "..");
let proc: ChildProcess, base = "", dataDir = "";

async function call(path: string, method = "GET", body?: unknown, cookie = "") {
  const r = await fetch(base + path, { method, headers: { ...(body ? { "content-type": "application/json" } : {}), ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, data: await r.json().catch(() => null), cookie: (r.headers.get("set-cookie") ?? "").split(";")[0] };
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "ls-2fa-"));
  const port = 20000 + Math.floor(Math.random() * 30000);
  base = `http://127.0.0.1:${port}`;
  const env: NodeJS.ProcessEnv = { ...process.env, PORT: String(port), LUCENT_DATA_DIR: dataDir, LUCENT_TICK_MS: "3600000" };
  delete env.LUCENT_REQUIRE_2FA;
  proc = spawn(process.execPath, [...process.execArgv, join(ROOT, "src/server/server.ts")], { env, stdio: "ignore" });
  for (let i = 0; i < 100; i++) { try { await fetch(base + "/api/auth"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
});
after(() => { proc?.kill(); rmSync(dataDir, { recursive: true, force: true }); });

test("a new account must set up its authenticator before using anything", async () => {
  const s = await call("/api/signup", "POST", { name: "Ngozi", email: "ngozi@example.com", password: "Ngozi-Long-Password-1" });
  assert.equal(s.status, 200);
  const cookie = s.cookie;
  assert.equal((await call("/api/auth", "GET", undefined, cookie)).data.twoStepRequired, true);
  const blocked = await call("/api/assets", "GET", undefined, cookie);
  assert.equal(blocked.status, 403);
  assert.equal(blocked.data.code, "2fa_required");
  // Setup works straight after sign-up, without asking for the password again.
  const st = await call("/api/account/2fa/start", "POST", {}, cookie);
  assert.equal(st.status, 200);
  assert.equal((await call("/api/account/2fa/enable", "POST", { code: codeFor(st.data.secret, stepAt()) }, cookie)).status, 200);
  assert.equal((await call("/api/assets", "GET", undefined, cookie)).status, 200, "everything opens once it is set up");
  // From now on the password alone is not enough to log in.
  const login = await call("/api/login", "POST", { email: "ngozi@example.com", password: "Ngozi-Long-Password-1" });
  assert.equal(login.data.needCode, true);
  assert.equal(login.cookie, "");
});

test("an account stuck before setting up its authenticator can still delete itself, and the email is free again", async () => {
  const s = await call("/api/signup", "POST", { name: "Tayo", email: "tayo@example.com", password: "Tayo-Long-Password-1" });
  const del = await call("/api/account/delete", "POST", { password: "Tayo-Long-Password-1", confirm: "DELETE" }, s.cookie);
  assert.equal(del.status, 200);
  assert.equal((await call("/api/signup", "POST", { name: "Tayo", email: "tayo@example.com", password: "Tayo-Long-Password-2" })).status, 200);
});

test("with the authenticator on, deleting also needs a current code", async () => {
  const s = await call("/api/signup", "POST", { name: "Kemi", email: "kemi@example.com", password: "Kemi-Long-Password-1" });
  const st = await call("/api/account/2fa/start", "POST", {}, s.cookie);
  await call("/api/account/2fa/enable", "POST", { code: codeFor(st.data.secret, stepAt()) }, s.cookie);
  assert.equal((await call("/api/account/delete", "POST", { password: "Kemi-Long-Password-1", confirm: "DELETE", code: "000000" }, s.cookie)).status, 400);
  assert.equal((await call("/api/account/delete", "POST", { password: "Kemi-Long-Password-1", confirm: "DELETE", code: codeFor(st.data.secret, stepAt() + 1) }, s.cookie)).status, 200);
});
