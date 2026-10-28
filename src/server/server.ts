// Lucent Shield web app — serves the dashboard and the API.
// Single operator, protected by one password (set LUCENT_PASSWORD).
// Start:  npm run web      then open http://localhost:4600

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { store } from "./store.ts";
import { startMonitor } from "./monitor.ts";
import { runScan, VERSION, type AssetKind } from "../engine.ts";

const UI_DIR = fileURLToPath(new URL("../ui/", import.meta.url));
const PORT = Number(process.env.PORT) || 4600;
const PASSWORD = (process.env.LUCENT_PASSWORD ?? "").trim();
const HTTPS = process.env.LUCENT_PUBLIC_URL?.startsWith("https://") || process.env.TRUST_PROXY === "1";

// Sessions: token -> expiry (ms). Expired tokens are dropped on use.
const SESSION_MS = 24 * 60 * 60 * 1000;
const sessions = new Map<string, number>();

// Login throttle: per-client-IP failed-attempt tracking, to blunt brute force.
const LOGIN_MAX_FAILS = 8;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const loginFails = new Map<string, { fails: number; until: number }>();

function clientIp(req: IncomingMessage): string {
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

function authed(req: IncomingMessage): boolean {
  if (!PASSWORD) return true; // open in local/dev mode
  const token = cookies(req)["ls"];
  if (!token) return false;
  const expiry = sessions.get(token);
  if (!expiry) return false;
  if (expiry < Date.now()) { sessions.delete(token); return false; } // expired
  return true;
}

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

function passwordOk(input: string): boolean {
  if (!PASSWORD) return false;
  const a = createHash("sha256").update(input).digest();
  const b = createHash("sha256").update(PASSWORD).digest();
  return timingSafeEqual(a, b);
}

async function api(req: IncomingMessage, res: ServerResponse, path: string) {
  const method = req.method ?? "GET";

  if (path === "/api/auth" && method === "GET") {
    return json(res, 200, { required: !!PASSWORD, authed: authed(req), version: VERSION });
  }

  if (path === "/api/login" && method === "POST") {
    const ip = clientIp(req);
    const lockedFor = loginLockedFor(ip);
    if (lockedFor > 0) return json(res, 429, { error: `Too many attempts. Try again in ${Math.ceil(lockedFor / 60)} min.` });
    const body = await readBody(req);
    if (!passwordOk(String(body.password ?? ""))) {
      noteLoginFail(ip);
      return json(res, 401, { error: "Wrong password." });
    }
    clearLoginFails(ip);
    const token = randomBytes(24).toString("hex");
    sessions.set(token, Date.now() + SESSION_MS);
    return json(res, 200, { ok: true }, { "Set-Cookie": `ls=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${HTTPS ? "; Secure" : ""}` });
  }

  if (!authed(req)) return json(res, 401, { error: "Please log in." });

  if (path === "/api/logout" && method === "POST") {
    const token = cookies(req)["ls"];
    if (token) sessions.delete(token);
    return json(res, 200, { ok: true }, { "Set-Cookie": "ls=; Path=/; Max-Age=0" });
  }

  // State-changing requests must come from our own page (CSRF defence, on top
  // of the SameSite=Lax session cookie). Check Origin, and fall back to Referer.
  if (method !== "GET") {
    const host = req.headers.host;
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    const sameHost = (u?: string) => { if (!u) return undefined; try { return new URL(u).host === host; } catch { return false; } };
    const okOrigin = sameHost(origin);
    const okReferer = sameHost(referer);
    // If an Origin or Referer is present, it must match our host.
    if (okOrigin === false || (okOrigin === undefined && okReferer === false)) {
      return json(res, 403, { error: "Blocked." });
    }
  }

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

  if (path === "/api/alerts" && method === "GET") {
    return json(res, 200, { alerts: store.listAlerts(), unread: store.unreadAlerts() });
  }
  if (path === "/api/alerts/read-all" && method === "POST") {
    store.markAlertsRead();
    return json(res, 200, { ok: true });
  }

  if (path === "/api/assets" && method === "GET") {
    return json(res, 200, { assets: store.list().map(({ findings, ...a }) => a), unread: store.unreadAlerts(), totalScans: store.scanCount() });
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
    const asset = store.add({ name, kind, target, authorized: kind === "web" ? true : !!body.authorized });
    const { findings, ...rest } = asset;
    return json(res, 200, { asset: rest });
  }

  const idMatch = path.match(/^\/api\/assets\/([0-9a-f-]{36})(\/scan|\/monitor)?$/);
  if (idMatch) {
    const id = idMatch[1];
    const asset = store.get(id);
    if (!asset) return json(res, 404, { error: "Not found." });

    if (idMatch[2] === "/scan" && method === "POST") {
      // Every scan needs explicit, per-run authorization — even after the
      // asset was added. This is the operator affirming they may test it.
      const body = await readBody(req);
      if (body.authorized !== true) {
        return json(res, 403, { error: "Explicit authorization is required to run this test. Confirm you own or are authorised to test this target." });
      }
      if (asset.kind === "web" && !asset.authorized) return json(res, 403, { error: "Not authorised to scan this site." });
      store.logAuthorization({ assetId: asset.id, name: asset.name, kind: asset.kind, target: asset.target, ip: clientIp(req) });
      const result = await runScan(asset.kind, asset.target);
      const updated = store.saveScan(id, result);
      return json(res, 200, { asset: updated });
    }
    if (idMatch[2] === "/monitor" && method === "POST") {
      const body = await readBody(req);
      const updated = store.setMonitor(id, body.on !== false);
      return json(res, 200, { asset: updated });
    }
    if (method === "GET") return json(res, 200, { asset });
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

server.listen(PORT, () => {
  console.log(`Lucent Shield v${VERSION} running on http://localhost:${PORT}`);
  if (!PASSWORD) console.log("  (no LUCENT_PASSWORD set — open mode, for local use only)");
  startMonitor();
});
