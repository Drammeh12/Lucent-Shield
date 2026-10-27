// Lucent Shield web app — serves the dashboard and the API.
// Single operator, protected by one password (set LUCENT_PASSWORD).
// Start:  npm run web      then open http://localhost:4600

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { store } from "./store.ts";
import { runScan, VERSION, type AssetKind } from "../engine.ts";

const UI_DIR = fileURLToPath(new URL("../ui/", import.meta.url));
const PORT = Number(process.env.PORT) || 4600;
const PASSWORD = (process.env.LUCENT_PASSWORD ?? "").trim();
const HTTPS = process.env.LUCENT_PUBLIC_URL?.startsWith("https://") || process.env.TRUST_PROXY === "1";

const sessions = new Set<string>();

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
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
  return !!token && sessions.has(token);
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
    const body = await readBody(req);
    if (!passwordOk(String(body.password ?? ""))) return json(res, 401, { error: "Wrong password." });
    const token = randomBytes(24).toString("hex");
    sessions.add(token);
    return json(res, 200, { ok: true }, { "Set-Cookie": `ls=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${HTTPS ? "; Secure" : ""}` });
  }

  if (!authed(req)) return json(res, 401, { error: "Please log in." });

  if (path === "/api/logout" && method === "POST") {
    const token = cookies(req)["ls"];
    if (token) sessions.delete(token);
    return json(res, 200, { ok: true }, { "Set-Cookie": "ls=; Path=/; Max-Age=0" });
  }

  // State-changing requests must come from our own page.
  if (method !== "GET") {
    const origin = req.headers.origin;
    const host = req.headers.host;
    if (origin && host && new URL(origin).host !== host) return json(res, 403, { error: "Blocked." });
  }

  if (path === "/api/assets" && method === "GET") {
    return json(res, 200, { assets: store.list().map(({ findings, ...a }) => a) });
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

  const idMatch = path.match(/^\/api\/assets\/([0-9a-f-]{36})(\/scan)?$/);
  if (idMatch) {
    const id = idMatch[1];
    const asset = store.get(id);
    if (!asset) return json(res, 404, { error: "Not found." });

    if (idMatch[2] === "/scan" && method === "POST") {
      if (asset.kind === "web" && !asset.authorized) return json(res, 403, { error: "Not authorised to scan this site." });
      const result = await runScan(asset.kind, asset.target);
      const updated = store.saveScan(id, result);
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
    return serveStatic(res, path);
  } catch (err) {
    json(res, 500, { error: "Server error." });
    console.error("Request failed:", err instanceof Error ? err.message : err);
  }
});

server.listen(PORT, () => {
  console.log(`Lucent Shield v${VERSION} running on http://localhost:${PORT}`);
  if (!PASSWORD) console.log("  (no LUCENT_PASSWORD set — open mode, for local use only)");
});
