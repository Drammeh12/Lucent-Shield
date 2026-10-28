// Lucent Shield web app — serves the dashboard and the API.
// People create an account (email and password) and each account sees only
// its own assets. The account whose email is LUCENT_ADMIN_EMAIL is the admin
// and also gets the admin view (users, audit trail, sign-ins, server health).
// Start:  npm run web      then open http://localhost:4600

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { store, publicUser, type User } from "./store.ts";
import { ADMIN_EMAIL, ADMIN_PASSWORD, isAdminUser, scanOptionsFor } from "./access.ts";
import { startMonitor } from "./monitor.ts";
import { runScan, isGitUrl, VERSION, type AssetKind } from "../engine.ts";
import { classify } from "../catalog.ts";
import { toHtml, toMarkdown, toJson, type ReportContext } from "../report.ts";
import { sortFindings, type Finding, type ScanResult } from "../types.ts";

const UI_DIR = fileURLToPath(new URL("../ui/", import.meta.url));
const PORT = Number(process.env.PORT) || 4600;
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const HTTPS = process.env.LUCENT_PUBLIC_URL?.startsWith("https://") || TRUST_PROXY;
/** LUCENT_SIGNUPS=closed stops new accounts (the admin can still create theirs). */
const SIGNUPS_OPEN = (process.env.LUCENT_SIGNUPS ?? "open").trim().toLowerCase() !== "closed";
const STARTED = Date.now();
const MIN_PASSWORD = 10;

// Sessions: token -> account and expiry (ms). Expired tokens are dropped on use.
const SESSION_MS = 24 * 60 * 60 * 1000;
const sessions = new Map<string, { userId: string; expiry: number }>();

// New accounts per address: at most 5 an hour, to stop mass sign-ups.
const signups = new Map<string, number[]>();
function signupAllowed(ip: string): boolean {
  const hour = Date.now() - 3_600_000;
  const recent = (signups.get(ip) ?? []).filter((t) => t > hour);
  if (recent.length >= 5) return false;
  recent.push(Date.now());
  signups.set(ip, recent);
  return true;
}

// Login throttle: per-client-IP failed-attempt tracking, to blunt brute force.
const LOGIN_MAX_FAILS = 8;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const loginFails = new Map<string, { fails: number; until: number }>();

/** The visitor's address. Behind Bash Cloud's proxy (TRUST_PROXY=1) it is the
 *  last address the proxy added to X-Forwarded-For, which a visitor cannot forge. */
function clientIp(req: IncomingMessage): string {
  if (TRUST_PROXY) {
    const fwd = String(req.headers["x-forwarded-for"] ?? "").split(",").map((x) => x.trim()).filter(Boolean);
    if (fwd.length) return fwd[fwd.length - 1].slice(0, 64);
  }
  return req.socket.remoteAddress ?? "unknown";
}
function loginLockedFor(ip: string): number {
  const rec = loginFails.get(ip);
  if (rec && rec.until > Date.now()) return Math.ceil((rec.until - Date.now()) / 1000);
  return 0;
}
function noteLoginFail(ip: string): void {
  const rec = loginFails.get(ip) ?? { fails: 0, until: 0 };
  rec.fails++;
  if (rec.fails >= LOGIN_MAX_FAILS) { rec.until = Date.now() + LOGIN_LOCK_MS; rec.fails = 0; }
  loginFails.set(ip, rec);
}
function clearLoginFails(ip: string): void { loginFails.delete(ip); }

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webp": "image/webp",
};

// Public pages reachable without logging in.
const PAGES: Record<string, string> = {
  "/about": "about.html",
  "/terms": "terms.html",
  "/privacy": "privacy.html",
};

function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of String(req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/** The signed-in account, or null. */
function currentUser(req: IncomingMessage): User | null {
  const token = cookies(req)["ls"];
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (s.expiry < Date.now()) { sessions.delete(token); return null; } // expired
  const user = store.user(s.userId);
  if (!user) { sessions.delete(token); return null; }
  return user;
}

function startSession(res: ServerResponse, user: User, body: unknown) {
  const token = randomBytes(24).toString("hex");
  sessions.set(token, { userId: user.id, expiry: Date.now() + SESSION_MS });
  store.touchLogin(user.id);
  if (isAdminUser(user)) store.claimUnowned(user.id);
  return json(res, 200, body, { "Set-Cookie": `ls=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${HTTPS ? "; Secure" : ""}` });
}

/** Constant-time comparison; an unset secret never matches. */
function sameSecret(input: string, secret: string): boolean {
  if (!secret) return false;
  const h = (x: string) => createHash("sha256").update(x).digest();
  return timingSafeEqual(h(input), h(secret));
}

const me = (u: User) => ({ ...publicUser(u), admin: isAdminUser(u) });
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,24}$/i;

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Referrer-Policy": "no-referrer",
    ...headers,
  });
  res.end(data);
}

async function readBody(req: IncomingMessage, limit = 256 * 1024): Promise<any> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw new Error("too large");
    chunks.push(c);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return {};
  }
}

function serveStatic(res: ServerResponse, path: string) {
  const name = path === "/" ? "index.html" : path.replace(/^\//, "");
  if (name.includes("..")) return json(res, 400, { error: "bad path" });
  const file = UI_DIR + name;
  if (!existsSync(file)) return json(res, 404, { error: "not found" });
  const ext = name.slice(name.lastIndexOf("."));
  res.writeHead(200, {
    "Content-Type": TYPES[ext] ?? "application/octet-stream",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  });
  res.end(readFileSync(file));
}

// Proof of domain ownership: the operator either serves a file with the token
// at /.well-known/lucent-verify.txt, or publishes a DNS TXT record
// "lucent-verify=<token>". Either one proves they control the site.
async function verifyDomain(target: string, token: string): Promise<{ ok: boolean; method?: string }> {
  if (!token) return { ok: false };
  let u: URL;
  try { u = new URL(target.includes("://") ? target : `https://${target}`); } catch { return { ok: false }; }

  // File method — use the full host (with port if any); also try plain HTTP.
  const bases = [`${u.protocol}//${u.host}`];
  if (u.protocol === "https:") bases.push(`http://${u.host}`);
  for (const base of bases) {
    try {
      const r = await fetch(`${base}/.well-known/lucent-verify.txt`, { redirect: "manual", signal: AbortSignal.timeout(8000) });
      if (r.ok) { const t = (await r.text()).trim(); if (t.includes(token)) return { ok: true, method: "file" }; }
    } catch { /* try next */ }
  }
  // DNS TXT method (per hostname, no port).
  try {
    const records = await resolveTxt(u.hostname);
    for (const parts of records) { if (parts.join("").includes(`lucent-verify=${token}`)) return { ok: true, method: "dns" }; }
  } catch { /* no record */ }

  return { ok: false };
}


/** Everything the admin view shows, built from the stored data. */
function adminOverview() {
  const assets = store.list();
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byKind: Record<string, number> = { repo: 0, web: 0, artifact: 0 };
  const byShield: Record<string, number> = { secure: 0, at_risk: 0, exposed: 0, scanning: 0, new: 0 };
  for (const a of assets) {
    byKind[a.kind] = (byKind[a.kind] ?? 0) + 1;
    byShield[a.shield] = (byShield[a.shield] ?? 0) + 1;
    for (const k of Object.keys(sev) as (keyof typeof sev)[]) sev[k] += a.counts?.[k] ?? 0;
  }
  const logins = store.listLogins(100);
  const users = store.listUsers();
  const dayAgo = Date.now() - 86_400_000;
  const mem = process.memoryUsage();
  return {
    totals: {
      users: users.length,
      assets: assets.length, byKind, byShield, severity: sev,
      scans: store.scanCount(),
      monitored: assets.filter((a) => a.monitor).length,
      webUnverified: assets.filter((a) => a.kind === "web" && !a.verified).length,
      failedLogins24h: logins.filter((l) => !l.ok && new Date(l.at).getTime() > dayAgo).length,
    },
    users: users.map((u) => ({ ...publicUser(u), admin: isAdminUser(u), assets: assets.filter((a) => a.ownerId === u.id).length })),
    assets: assets.map(({ findings, verifyToken, ...a }) => ({ ...a, owner: users.find((u) => u.id === a.ownerId)?.email ?? null })),
    authorizations: store.listAuthorizations(200),
    logins,
    alerts: store.listAlerts().slice(0, 50),
    system: {
      version: VERSION, node: process.version,
      uptimeSec: Math.round((Date.now() - STARTED) / 1000),
      memoryMb: Math.round(mem.rss / 1e6),
      activeSessions: [...sessions.values()].filter((s) => s.expiry > Date.now()).length,
      settings: {
        signupsOpen: SIGNUPS_OPEN,
        adminEmail: !!ADMIN_EMAIL,
        httpsCookies: !!HTTPS,
        githubToken: !!process.env.LUCENT_GITHUB_TOKEN,
        alertWebhook: !!process.env.LUCENT_ALERT_WEBHOOK,
        internalTargetsAllowed: process.env.LUCENT_ALLOW_INTERNAL === "1",
      },
    },
  };
}

/** If an Origin or Referer is present, it must be this site (CSRF defence). */
function sameSite(req: IncomingMessage): boolean {
  const host = req.headers.host;
  const check = (u?: string) => { if (!u) return undefined; try { return new URL(u).host === host; } catch { return false; } };
  const okOrigin = check(req.headers.origin);
  const okReferer = check(req.headers.referer);
  return !(okOrigin === false || (okOrigin === undefined && okReferer === false));
}

async function api(req: IncomingMessage, res: ServerResponse, path: string) {
  const method = req.method ?? "GET";

  if (path === "/api/auth" && method === "GET") {
    const u = currentUser(req);
    return json(res, 200, { authed: !!u, user: u ? me(u) : null, signups: SIGNUPS_OPEN, version: VERSION });
  }

  // Login and sign-up come from our own page only (same check as below).
  if ((path === "/api/login" || path === "/api/signup") && method === "POST" && !sameSite(req)) return json(res, 403, { error: "Blocked." });

  if (path === "/api/signup" && method === "POST") {
    const ip = clientIp(req);
    const body = await readBody(req);
    const name = String(body.name ?? "").trim();
    const email = String(body.email ?? "").trim().toLowerCase();
    const password = String(body.password ?? "");
    if (!name) return json(res, 400, { error: "Enter your name." });
    if (!EMAIL_RE.test(email) || email.length > 254) return json(res, 400, { error: "Enter a valid email address." });
    if (password.length < MIN_PASSWORD) return json(res, 400, { error: `Use a password of at least ${MIN_PASSWORD} characters.` });
    if (password.length > 200) return json(res, 400, { error: "That password is too long." });
    // The admin email is reserved: only someone who knows LUCENT_ADMIN_PASSWORD can claim it.
    const adminSignup = !!ADMIN_EMAIL && email === ADMIN_EMAIL;
    if (adminSignup && !sameSecret(password, ADMIN_PASSWORD)) {
      store.logLogin({ ip, email, event: "signup", ok: false });
      return json(res, 403, { error: "This email cannot be used to create an account." });
    }
    if (!adminSignup && !SIGNUPS_OPEN) return json(res, 403, { error: "New accounts are closed for now." });
    if (!signupAllowed(ip)) return json(res, 429, { error: "Too many new accounts from your network. Try again later." });
    let user: User;
    try { user = store.createUser({ email, name, password }); }
    catch { return json(res, 409, { error: "An account with this email already exists. Log in instead." }); }
    store.logLogin({ ip, email, event: "signup", ok: true });
    return startSession(res, user, { ok: true, user: me(user) });
  }

  if (path === "/api/login" && method === "POST") {
    const ip = clientIp(req);
    const lockedFor = loginLockedFor(ip);
    if (lockedFor > 0) return json(res, 429, { error: `Too many attempts. Try again in ${Math.ceil(lockedFor / 60)} min.` });
    const body = await readBody(req);
    const email = String(body.email ?? "").trim().toLowerCase().slice(0, 254);
    const user = store.checkPassword(email, String(body.password ?? "").slice(0, 200));
    store.logLogin({ ip, email, event: "login", ok: !!user });
    if (!user) {
      noteLoginFail(ip);
      return json(res, 401, { error: "Wrong email or password." });
    }
    clearLoginFails(ip);
    return startSession(res, user, { ok: true, user: me(user) });
  }

  const user = currentUser(req);
  if (!user) return json(res, 401, { error: "Please log in." });
  const admin = isAdminUser(user);

  if (path === "/api/logout" && method === "POST") {
    const token = cookies(req)["ls"];
    if (token) sessions.delete(token);
    return json(res, 200, { ok: true }, { "Set-Cookie": "ls=; Path=/; Max-Age=0" });
  }

  // State-changing requests must come from our own page (CSRF defence, on top
  // of the SameSite=Lax session cookie). Check Origin, and fall back to Referer.
  if (method !== "GET" && !sameSite(req)) return json(res, 403, { error: "Blocked." });

  // Favicon proxy: fetches the target site's icon server-side so the browser can
  // show it (CSP only allows same-origin images). Cached by the browser for a day.
  if (path === "/api/favicon" && method === "GET") {
    const u = new URL(req.url ?? "/", "http://x").searchParams.get("u") ?? "";
    let host = "";
    try { host = new URL(/^https?:\/\//.test(u) ? u : "https://" + u).hostname; } catch {}
    if (!host) return json(res, 400, { error: "bad host" });
    try {
      const r = await fetch(`https://www.google.com/s2/favicons?domain=${encodeURIComponent(host)}&sz=128`, {
        signal: AbortSignal.timeout(5000),
      });
      if (!r.ok) throw new Error("no icon");
      const buf = Buffer.from(await r.arrayBuffer());
      res.writeHead(200, {
        "Content-Type": r.headers.get("content-type") ?? "image/png",
        "Cache-Control": "public, max-age=86400",
        "X-Content-Type-Options": "nosniff",
      });
      return res.end(buf);
    } catch {
      return json(res, 404, { error: "no icon" });
    }
  }

  // Admin only. Read-only views; nothing here changes stored data.
  if (path.startsWith("/api/admin/")) {
    if (!admin) return json(res, 403, { error: "Admins only." });
    if (path === "/api/admin/overview" && method === "GET") return json(res, 200, adminOverview());
    if (path === "/api/admin/audit.json" && method === "GET") {
      return json(res, 200, store.listAuthorizations(), { "Content-Disposition": `attachment; filename="lucent-authorizations-${new Date().toISOString().slice(0, 10)}.json"` });
    }
    return json(res, 404, { error: "not found" });
  }

  if (path === "/api/alerts" && method === "GET") {
    return json(res, 200, { alerts: store.listAlerts(user.id), unread: store.unreadAlerts(user.id) });
  }
  if (path === "/api/alerts/read-all" && method === "POST") {
    store.markAlertsRead(user.id);
    return json(res, 200, { ok: true });
  }

  if (path === "/api/assets" && method === "GET") {
    return json(res, 200, { assets: store.list(user.id).map(({ findings, ...a }) => a), unread: store.unreadAlerts(user.id), totalScans: user.scans ?? 0 });
  }

  if (path === "/api/assets" && method === "POST") {
    const body = await readBody(req);
    const name = String(body.name ?? "").trim().slice(0, 100);
    const kind = String(body.kind ?? "") as AssetKind;
    const target = String(body.target ?? "").trim().slice(0, 2000);
    if (!name || !target || !["repo", "web", "artifact"].includes(kind)) return json(res, 400, { error: "Give it a name, a kind and a target." });
    if ((kind === "web") && body.authorized !== true) {
      return json(res, 400, { error: "Confirm you own or are authorised to test this site before adding it." });
    }
    // Folders and files on this server are the admin's only: anyone else could read the server itself.
    if (!admin && kind === "artifact") return json(res, 403, { error: "Forensic examination is not available on your account." });
    if (!admin && kind === "repo" && !(isGitUrl(target) && /^https:\/\//i.test(target))) {
      return json(res, 400, { error: "Enter the repository's web address, for example https://github.com/you/your-repo." });
    }
    const asset = store.add({ ownerId: user.id, name, kind, target, authorized: kind === "web" ? true : !!body.authorized });
    const { findings, ...rest } = asset;
    return json(res, 200, { asset: rest });
  }

  const idMatch = path.match(/^\/api\/assets\/([0-9a-f-]{36})(\/scan|\/monitor|\/verify|\/report)?$/);
  if (idMatch) {
    const id = idMatch[1];
    const asset = store.get(id);
    // Another account's asset looks exactly like one that does not exist.
    if (!asset || asset.ownerId !== user.id) return json(res, 404, { error: "Not found." });

    if (idMatch[2] === "/verify" && method === "POST") {
      if (asset.kind !== "web") return json(res, 400, { error: "Only websites need ownership verification." });
      if (asset.verified) return json(res, 200, { verified: true, method: "already" });
      const r = await verifyDomain(asset.target, asset.verifyToken);
      if (r.ok) { store.setVerified(id, true); return json(res, 200, { verified: true, method: r.method }); }
      return json(res, 200, { verified: false });
    }

    if (idMatch[2] === "/scan" && method === "POST") {
      // Every scan needs explicit, per-run authorization — even after the
      // asset was added. This is the operator affirming they may test it.
      const body = await readBody(req);
      if (body.authorized !== true) {
        return json(res, 403, { error: "Explicit authorization is required to run this test. Confirm you own or are authorised to test this target." });
      }
      if (asset.kind === "web" && !asset.authorized) return json(res, 403, { error: "Not authorised to scan this site." });
      // A website must prove domain ownership before it can be scanned.
      if (asset.kind === "web" && !asset.verified) {
        return json(res, 403, { error: "Verify that you own this domain before scanning it." });
      }
      // Forensics carries the heaviest weight: require a legal attestation and a reference.
      if (asset.kind === "artifact" && (body.legal !== true || !String(body.reference ?? "").trim())) {
        return json(res, 403, { error: "Forensic examination requires a legal attestation and an authorization reference." });
      }
      if (!store.beginScan(id)) return json(res, 409, { error: "This asset is already being scanned. Wait for it to finish." });
      try {
        store.logAuthorization({ assetId: asset.id, name: asset.name, kind: asset.kind, target: asset.target, ip: clientIp(req), userId: user.id, email: user.email, reference: String(body.reference ?? "").trim().slice(0, 200) || undefined });
        const result = await runScan(asset.kind, asset.target, scanOptionsFor(asset.ownerId));
        const updated = store.saveScan(id, result);
        return json(res, 200, { asset: updated });
      } finally {
        store.endScan(id);
      }
    }
    if (idMatch[2] === "/monitor" && method === "POST") {
      const body = await readBody(req);
      const updated = store.setMonitor(id, body.on !== false);
      return json(res, 200, { asset: updated });
    }
    // Downloadable report of the last scan: ?format=html|md|json
    if (idMatch[2] === "/report" && method === "GET") {
      if (!asset.lastScanAt) return json(res, 404, { error: "Scan this asset first." });
      const q = new URL(req.url ?? "/", "http://x").searchParams;
      const format = q.get("format") ?? "html";
      const view = format === "html" && q.get("view") === "1";
      const result: ScanResult = { tool: "Lucent Shield", version: VERSION, target: asset.target, mode: asset.kind === "web" ? "web" : "repo",
        startedAt: asset.lastScanAt, finishedAt: asset.lastScanAt, filesScanned: asset.filesScanned ?? 0, findings: asset.findings };
      // The authorization recorded for the most recent scan of this asset goes into the report.
      const auth = store.listAuthorizations().find((a) => a.assetId === asset.id && a.at <= asset.lastScanAt!) ?? store.listAuthorizations().find((a) => a.assetId === asset.id);
      const ctx: ReportContext = {
        assetName: asset.name, kind: asset.kind, verified: asset.verified, view,
        authorization: auth ? { at: auth.at, ip: auth.ip, reference: auth.reference } : null,
      };
      const slug = asset.name.replace(/[^A-Za-z0-9.-]+/g, "-").slice(0, 60) || "asset";
      const day = asset.lastScanAt.slice(0, 10);
      const [body, type, ext] = format === "json" ? [toJson(result, ctx), "application/json; charset=utf-8", "json"]
        : format === "md" ? [toMarkdown(result, ctx), "text/markdown; charset=utf-8", "md"]
        : [toHtml(result, ctx), "text/html; charset=utf-8", "html"];
      const file = `lucent-shield-assessment-${slug}-${day}.${ext}`;
      res.writeHead(200, {
        "Content-Type": type,
        "Content-Disposition": `${view ? "inline" : "attachment"}; filename="${file}"`,
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; img-src data:${view ? "; script-src 'self'" : ""}; frame-ancestors 'none'`,
        "Cache-Control": "no-store",
      });
      return res.end(body);
    }

    if (method === "GET") {
      const findings = sortFindings(asset.findings).map((f: Finding) => ({ ...f, ...(classify(f.rule) ?? {}) }));
      return json(res, 200, { asset: { ...asset, findings } });
    }
    if (method === "DELETE") {
      store.remove(id);
      return json(res, 200, { ok: true });
    }
  }

  return json(res, 404, { error: "Unknown endpoint." });
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    if (path.startsWith("/api/")) return await api(req, res, path);
    if (PAGES[path]) return serveStatic(res, "/" + PAGES[path]);
    return serveStatic(res, path);
  } catch (err) {
    json(res, 500, { error: "Server error." });
    console.error("Request failed:", err instanceof Error ? err.message : err);
  }
});

// Deep scans (clone + dependency lookup) can take a while; don't cut them off.
server.requestTimeout = 15 * 60_000;
server.headersTimeout = 65_000;

server.listen(PORT, () => {
  console.log(`Lucent Shield v${VERSION} running on http://localhost:${PORT}`);
  if (!ADMIN_EMAIL) console.log("  no admin yet: set LUCENT_ADMIN_EMAIL (and LUCENT_ADMIN_PASSWORD to create that account)");
  else console.log(store.userByEmail(ADMIN_EMAIL) ? "  admin account ready" : "  admin account not created yet: sign up with the admin email and LUCENT_ADMIN_PASSWORD");
  if (!SIGNUPS_OPEN) console.log("  new sign-ups are closed (LUCENT_SIGNUPS=closed)");
  startMonitor();
});
