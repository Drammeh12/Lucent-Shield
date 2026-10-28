// Black-box web checks — NON-DESTRUCTIVE only. Given a URL the operator has
// confirmed they own or are authorised to test, Lucent Shield makes ordinary
// GET requests and inspects what comes back: security headers, cookie flags,
// HTTPS, and whether sensitive files are exposed. It never fuzzes, brute-forces,
// exploits, or sends anything that could change or damage the target.

import { lookup } from "node:dns/promises";
import type { Finding, Severity } from "../types.ts";

const TIMEOUT_MS = 9000;

// Cloud-metadata SSRF guard. Even though scanning is operator-only, a server on
// a cloud host must never be tricked into fetching its own instance metadata
// (169.254.169.254 / metadata.google.internal), which can leak credentials.
// Set LUCENT_ALLOW_INTERNAL=1 to disable (e.g. to scan internal/LAN assets).
async function isBlockedHost(host: string): Promise<boolean> {
  if (process.env.LUCENT_ALLOW_INTERNAL === "1") return false;
  if (/(^|\.)metadata\.google\.internal$/i.test(host)) return true;
  let ip = host;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    try { ip = (await lookup(host)).address; } catch { return false; }
  }
  return /^169\.254\./.test(ip); // link-local, incl. cloud metadata
}

async function get(url: string): Promise<Response | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "user-agent": "LucentShield/0.2 (+security scan of own asset)" },
    });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

interface HeaderRule {
  rule: string;
  header: string;
  title: string;
  severity: Severity;
  detail: string;
  remediation: string;
}

const HEADER_RULES: HeaderRule[] = [
  {
    rule: "web.header.csp",
    header: "content-security-policy",
    title: "Missing Content-Security-Policy",
    severity: "medium",
    detail: "Without a CSP, an injected script runs with full access to the page. CSP is the strongest defence against cross-site scripting.",
    remediation: "Add a Content-Security-Policy header. Start with default-src 'self' and loosen only what you need.",
  },
  {
    rule: "web.header.hsts",
    header: "strict-transport-security",
    title: "Missing HSTS (Strict-Transport-Security)",
    severity: "medium",
    detail: "Without HSTS, a visitor's first request can be downgraded to plain HTTP and intercepted.",
    remediation: "Add Strict-Transport-Security: max-age=63072000; includeSubDomains once you are fully on HTTPS.",
  },
  {
    rule: "web.header.xcto",
    header: "x-content-type-options",
    title: "Missing X-Content-Type-Options",
    severity: "low",
    detail: "Without nosniff, browsers may guess a file's type and run it as script.",
    remediation: "Add X-Content-Type-Options: nosniff.",
  },
  {
    rule: "web.header.frame",
    header: "x-frame-options",
    title: "Missing clickjacking protection",
    severity: "low",
    detail: "Without a frame policy, your site can be embedded in a hidden iframe and used to trick your users (clickjacking).",
    remediation: "Add X-Frame-Options: DENY, or frame-ancestors 'none' in your CSP.",
  },
  {
    rule: "web.header.referrer",
    header: "referrer-policy",
    title: "Missing Referrer-Policy",
    severity: "info",
    detail: "Without a referrer policy, full URLs (which may contain tokens) can leak to other sites.",
    remediation: "Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
  },
];

// Files that should never be reachable over the web.
const EXPOSED_PATHS: { path: string; title: string; severity: Severity; needle?: RegExp }[] = [
  { path: "/.env", title: "Environment file exposed (.env)", severity: "critical", needle: /=/ },
  { path: "/.git/HEAD", title: "Git repository exposed (.git)", severity: "high", needle: /ref:|[0-9a-f]{40}/ },
  { path: "/.git/config", title: "Git config exposed", severity: "high", needle: /\[core\]|remote/ },
  { path: "/config.json", title: "config.json exposed", severity: "medium" },
  { path: "/backup.sql", title: "Database backup exposed", severity: "critical", needle: /INSERT|CREATE TABLE/i },
  { path: "/.DS_Store", title: ".DS_Store exposed (leaks file names)", severity: "low" },
  { path: "/phpinfo.php", title: "phpinfo() exposed", severity: "medium", needle: /phpinfo|PHP Version/i },
  { path: "/server-status", title: "Apache server-status exposed", severity: "medium", needle: /Apache Server Status/i },
];

export async function scanWeb(rawUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  let url: URL;
  try {
    url = new URL(rawUrl.includes("://") ? rawUrl : `https://${rawUrl}`);
  } catch {
    return [{ rule: "web.bad-url", severity: "info", category: "web", title: "Invalid URL", detail: `Could not read the address "${rawUrl}".`, remediation: "Enter a full address, e.g. https://yoursite.com" }];
  }

  if (await isBlockedHost(url.hostname)) {
    return [{
      rule: "web.blocked-internal", severity: "info", category: "web", location: url.href,
      title: "Address blocked (internal/metadata)",
      detail: "This address points at a cloud metadata or link-local endpoint, which Lucent Shield will not fetch, to avoid leaking server credentials.",
      remediation: "Scan a public address you own. To allow internal targets on a trusted host, set LUCENT_ALLOW_INTERNAL=1.",
    }];
  }

  // HTTPS check.
  if (url.protocol !== "https:") {
    findings.push({
      rule: "web.no-https", severity: "high", category: "web", location: url.href,
      title: "Site is served over plain HTTP",
      detail: "Traffic to this site is not encrypted and can be read or changed in transit.",
      remediation: "Serve the site over HTTPS and redirect all HTTP traffic to it.",
    });
  }

  const res = await get(url.href);
  if (!res) {
    findings.push({ rule: "web.unreachable", severity: "info", category: "web", location: url.href, title: "Site did not respond", detail: "Lucent Shield could not reach the address (timeout or connection error).", remediation: "Check the site is online and the address is correct, then scan again." });
    return findings;
  }

  const h = res.headers;

  // Security headers.
  for (const rule of HEADER_RULES) {
    if (!h.get(rule.header)) {
      findings.push({ rule: rule.rule, severity: rule.severity, category: "web", location: url.href, title: rule.title, detail: rule.detail, remediation: rule.remediation });
    }
  }

  // Information disclosure.
  const server = h.get("server");
  const powered = h.get("x-powered-by");
  if (powered) {
    findings.push({ rule: "web.info.powered-by", severity: "info", category: "web", location: url.href, title: `Technology disclosed: X-Powered-By: ${powered}`, detail: "Advertising your stack and versions helps an attacker target known vulnerabilities.", remediation: "Remove the X-Powered-By header." });
  }
  if (server && /\d/.test(server)) {
    findings.push({ rule: "web.info.server", severity: "info", category: "web", location: url.href, title: `Server version disclosed: ${server}`, detail: "Exposing the exact server version helps an attacker find matching exploits.", remediation: "Hide the server version in your web server configuration." });
  }

  // Cookie flags.
  const setCookie = (h as any).getSetCookie?.() ?? (h.get("set-cookie") ? [h.get("set-cookie")!] : []);
  for (const cookie of setCookie as string[]) {
    const name = cookie.split("=")[0];
    const lower = cookie.toLowerCase();
    const missing: string[] = [];
    if (!lower.includes("httponly")) missing.push("HttpOnly");
    if (url.protocol === "https:" && !lower.includes("secure")) missing.push("Secure");
    if (!lower.includes("samesite")) missing.push("SameSite");
    if (missing.length) {
      findings.push({
        rule: "web.cookie.flags", severity: "medium", category: "web", location: url.href,
        title: `Cookie "${name}" is missing ${missing.join(", ")}`,
        detail: "Cookies without these flags can be stolen by scripts, sent over plain HTTP, or used in cross-site request forgery.",
        remediation: `Set the ${missing.join(", ")} flag${missing.length > 1 ? "s" : ""} on this cookie.`,
      });
    }
  }

  // Exposed sensitive files (GET only, confirmed by content).
  for (const probe of EXPOSED_PATHS) {
    const r = await get(new URL(probe.path, url.origin).href);
    if (!r || r.status !== 200) continue;
    let body = "";
    try { body = (await r.text()).slice(0, 2000); } catch { /* ignore */ }
    if (probe.needle && !probe.needle.test(body)) continue;
    findings.push({
      rule: "web.exposed-file", severity: probe.severity, category: "web", location: new URL(probe.path, url.origin).href,
      title: probe.title,
      detail: "A sensitive file is reachable directly over the web. Anyone can download it.",
      remediation: `Block public access to ${probe.path} at the web server or framework level, and remove the file from the web root if it should not be deployed.`,
    });
  }

  return findings;
}
