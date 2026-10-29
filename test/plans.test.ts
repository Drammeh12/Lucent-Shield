// Plans: free limits, the Bash Cloud welcome (14 days free, then a discount),
// and the admin switching a plan on after payment.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { entitlement, monitorActive, scanBlocked } from "../src/server/plans.ts";
import type { User } from "../src/server/store.ts";

const ROOT = join(import.meta.dirname, "..");
let proc: ChildProcess, site: Server, base = "", sitePort = 0, dataDir = "";
const tokens = new Map<string, string>();

async function call(path: string, method = "GET", body?: unknown, cookie = "") {
  const r = await fetch(base + path, { method, headers: { ...(body ? { "content-type": "application/json" } : {}), ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, data: await r.json().catch(() => null), cookie: (r.headers.get("set-cookie") ?? "").split(";")[0] };
}

before(async () => {
  // One small site that plays both a customer's website and Bash Cloud's
  // "is this hosted here?" answer: only "localhost" is hosted on Bash Cloud.
  site = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    if (u.pathname === "/api/public/hosted") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ hosted: u.searchParams.get("host") === "localhost" }));
    }
    if (u.pathname === "/.well-known/lucent-verify.txt") {
      res.writeHead(200, { "content-type": "text/plain" });
      return res.end([...tokens.values()].join("\n"));
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<!doctype html><title>Shop</title><p>Hello</p>");
  });
  await new Promise<void>((r) => site.listen(0, "127.0.0.1", r));
  sitePort = (site.address() as { port: number }).port;

  dataDir = mkdtempSync(join(tmpdir(), "ls-plans-"));
  const port = 20000 + Math.floor(Math.random() * 30000);
  base = `http://127.0.0.1:${port}`;
  const env: NodeJS.ProcessEnv = { ...process.env, PORT: String(port), LUCENT_DATA_DIR: dataDir, LUCENT_TICK_MS: "3600000", LUCENT_REQUIRE_2FA: "0",
    LUCENT_ALLOW_INTERNAL: "1", LUCENT_BASHCLOUD_URL: `http://127.0.0.1:${sitePort}`, LUCENT_ADMIN_EMAIL: "boss@example.com", LUCENT_ADMIN_PASSWORD: "Boss-Long-Password-1" };
  delete env.LUCENT_LIMITS;
  proc = spawn(process.execPath, [...process.execArgv, join(ROOT, "src/server/server.ts")], { env, stdio: "ignore" });
  for (let i = 0; i < 100; i++) { try { await fetch(base + "/api/auth"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
});
after(() => { proc?.kill(); site?.close(); rmSync(dataDir, { recursive: true, force: true }); });

async function account(name: string) {
  const s = await call("/api/signup", "POST", { name, email: `${name.toLowerCase()}@example.com`, password: `${name}-Long-Password-1` });
  assert.equal(s.status, 200);
  return s.cookie;
}
async function site_(cookie: string, host: string) {
  const a = await call("/api/assets", "POST", { name: host, kind: "web", target: `http://${host}:${sitePort}`, authorized: true }, cookie);
  const full = await call(`/api/assets/${a.data.asset.id}`, "GET", undefined, cookie);
  tokens.set(a.data.asset.id, full.data.asset.verifyToken);
  assert.equal((await call(`/api/assets/${a.data.asset.id}/verify`, "POST", {}, cookie)).data.verified, true);
  return a.data.asset.id as string;
}
const scan = (cookie: string, id: string) => call(`/api/assets/${id}/scan`, "POST", { authorized: true }, cookie);

test("free accounts get 3 scans and one monitored asset, then are asked to choose a plan", async () => {
  const c = await account("Ada");
  const id = await site_(c, "127.0.0.1");
  let plan = (await call("/api/assets", "GET", undefined, c)).data.plan;
  assert.equal(plan.code, "free");
  assert.equal(plan.bashCloud, false, "a site hosted elsewhere does not count as Bash Cloud");
  for (let i = 0; i < 3; i++) assert.equal((await scan(c, id)).status, 200);
  const fourth = await scan(c, id);
  assert.equal(fourth.status, 402);
  assert.equal(fourth.data.code, "plan_limit");
  assert.match(fourth.data.error, /3 free scans/);
  assert.equal((await call(`/api/assets/${id}/monitor`, "POST", { on: true, authorized: true }, c)).status, 200, "one asset may be monitored for a day");
  plan = (await call("/api/assets", "GET", undefined, c)).data.plan;
  assert.ok(plan.monitorEndsAt, "the free day of monitoring has started");
  assert.equal(plan.plans[0].price.ngn, 5000, "full price outside Bash Cloud");
});

test("verifying a site hosted on Bash Cloud starts 14 free days and a 25% discount", async () => {
  const c = await account("Bayo");
  const id = await site_(c, "localhost");
  const plan = (await call("/api/assets", "GET", undefined, c)).data.plan;
  assert.equal(plan.code, "welcome");
  assert.equal(plan.bashCloud, true);
  assert.equal(plan.scanLimit, 50);
  assert.equal(plan.monitorLimit, 3);
  assert.ok(Math.abs(Date.parse(plan.endsAt) - Date.now() - 14 * 86_400_000) < 60_000);
  assert.equal(plan.discount, 25);
  assert.equal(plan.plans.find((p: { code: string }) => p.code === "solo").price.ngn, 3750);
  for (let i = 0; i < 4; i++) assert.equal((await scan(c, id)).status, 200, "more than the free 3 scans");
});

test("the admin switches a plan on after payment; nobody else can", async () => {
  const c = await account("Chidi");
  const id = await site_(c, "127.0.0.1");
  for (let i = 0; i < 3; i++) await scan(c, id);
  assert.equal((await scan(c, id)).status, 402);
  const users = await call("/api/admin/overview", "GET", undefined, c);
  assert.equal(users.status, 403);
  const admin = await account("Boss");
  const ov = await call("/api/admin/overview", "GET", undefined, admin);
  const chidi = ov.data.users.find((u: { email: string }) => u.email === "chidi@example.com");
  assert.equal((await call("/api/admin/plan", "POST", { userId: chidi.id, plan: "solo", months: 1 }, c)).status, 403);
  assert.equal((await call("/api/admin/plan", "POST", { userId: chidi.id, plan: "solo", months: 1 }, admin)).status, 200);
  const plan = (await call("/api/assets", "GET", undefined, c)).data.plan;
  assert.equal(plan.code, "solo");
  assert.equal(plan.scanLimit, 60);
  assert.equal((await scan(c, id)).status, 200, "scanning works again");
});

test("plan rules", () => {
  const now = Date.parse("2026-11-01T00:00:00Z");
  const u = { id: "u", email: "x@y.z", name: "X", salt: "", hash: "", createdAt: "", lastLoginAt: null, scans: 0 } as User;
  assert.equal(entitlement(u, true, now).scanLimit, null, "the admin has no limits");
  // The welcome ends after 14 days; the discount stays.
  u.bashCloud = { since: "2026-10-01T00:00:00Z", host: "shop.com" };
  const after = entitlement(u, false, now);
  assert.equal(after.code, "free");
  assert.equal(after.discount, 25);
  // A free day of monitoring ends after 24 hours.
  u.freeMonitorAt = "2026-10-30T00:00:00Z";
  assert.equal(monitorActive(entitlement(u, false, now), now), false);
  // A paid plan counts scans per calendar month.
  u.plan = { code: "team", paidUntil: "2026-12-01T00:00:00Z" };
  u.usage = { period: "2026-11", scans: 300 };
  assert.match(scanBlocked(entitlement(u, false, now)) ?? "", /renew on the 1st/);
  u.usage = { period: "2026-10", scans: 300 };
  assert.equal(scanBlocked(entitlement(u, false, now)), null, "last month's scans do not count");
});
