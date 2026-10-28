// Black-box web checks, NON-DESTRUCTIVE only. Given a site the operator has
// proved they own, Lucent Shield looks at it the way a visitor (or attacker)
// first would, using ordinary read-only requests:
//
//   - HTTPS, the HTTP-to-HTTPS redirect, and the TLS certificate
//   - security headers (and whether the ones present are actually strong)
//   - cookie flags, CORS behaviour, information leaks, directory listings
//   - sensitive files left reachable (.env, .git, backups, keys, configs)
//   - email spoofing protection for the domain (SPF and DMARC, via DNS)
//
// It never fuzzes, brute-forces, logs in, submits forms, or sends anything
// that could change or damage the target.

import { lookup, resolveTxt } from "node:dns/promises";
import { connect as tlsConnect } from "node:tls";
import { createHash, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type { Finding, Severity } from "../types.ts";

const TIMEOUT_MS = 9000;
const UA = "LucentShield (+authorised, read-only security scan of an owned site)";

// ------------------------------------------------------------------ safety

// Cloud-metadata SSRF guard. Even though scanning is operator-only, a server on
// a cloud host must never be tricked into fetching its own instance metadata
// (169.254.169.254 / metadata.google.internal), which can leak credentials.
// Set LUCENT_ALLOW_INTERNAL=1 to disable (e.g. to scan internal/LAN assets).
export async function isBlockedHost(host: string): Promise<boolean> {
  if (process.env.LUCENT_ALLOW_INTERNAL === "1") return false;
  if (/(^|\.)metadata\.google\.internal$/i.test(host)) return true;
  let ip = host;
  if (!isIP(host)) {
    try { ip = (await lookup(host)).address; } catch { return false; }
  }
  return /^169\.254\./.test(ip) || /^fe80:/i.test(ip); // link-local, incl. cloud metadata
}

// ---------------------------------------------------------------- requests

async function get(url: string, headers: Record<string, string> = {}): Promise<Response | null> {
  try {
    return await fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS), headers: { "user-agent": UA, accept: "*/*", ...headers } });
  } catch {
    return null;
  }
}

/** Reads at most `max` bytes of a body, so a huge file can never stall a scan. */
async function readCapped(res: Response, max = 262_144): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    while (n < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      n += value.length;
    }
  } catch { /* partial body is fine */ } finally {
    reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString("latin1");
}

const bare = (h: string) => h.replace(/^www\./i, "").toLowerCase();
const sameSite = (a: URL, b: URL) => bare(a.hostname) === bare(b.hostname);

/** Follows redirects that stay on the same site (up to 5), re-checking each hop against the SSRF guard. */
async function getFollowing(start: URL): Promise<{ res: Response | null; final: URL }> {
  let cur = start;
  for (let hop = 0; hop < 5; hop++) {
    const res = await get(cur.href);
    if (!res) return { res: null, final: cur };
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      let next: URL;
      try { next = new URL(loc, cur); } catch { return { res, final: cur }; }
      if (!sameSite(next, start) || (await isBlockedHost(next.hostname))) return { res, final: cur };
      res.body?.cancel().catch(() => {});
      cur = next;
      continue;
    }
    return { res, final: cur };
  }
  return { res: null, final: cur };
}

interface TlsInfo { authorized: boolean; error?: string; validTo?: Date }

/** Opens a TLS connection only to read the certificate. Nothing is sent. */
function tlsInfo(host: string, port: number): Promise<TlsInfo | null> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: TlsInfo | null) => { if (!done) { done = true; resolve(v); } };
    try {
      const sock = tlsConnect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: TIMEOUT_MS }, () => { // lucent-ignore: inspects the certificate, then reports it
        const cert = sock.getPeerCertificate();
        finish({ authorized: sock.authorized, error: sock.authorizationError ? String((sock.authorizationError as any).code ?? sock.authorizationError) : undefined, validTo: cert?.valid_to ? new Date(cert.valid_to) : undefined });
        sock.end();
      });
      sock.on("error", () => finish(null));
      sock.on("timeout", () => { sock.destroy(); finish(null); });
    } catch { finish(null); }
  });
}

function certProblem(code: string): string {
  if (/EXPIRED/i.test(code)) return "the certificate has expired";
  if (/SELF_SIGNED/i.test(code)) return "the certificate is self-signed";
  if (/ALTNAME|HOSTNAME|IP: /i.test(code)) return "the certificate was issued for a different name";
  if (/UNABLE_TO_(?:VERIFY|GET_ISSUER)/i.test(code)) return "the certificate chain is incomplete or from an unknown authority";
  if (/NOT_YET_VALID/i.test(code)) return "the certificate is not valid yet";
  return `the certificate could not be verified (${code})`;
}

// ------------------------------------------------------------ the checks

interface HeaderRule { rule: string; header: string; title: string; severity: Severity; httpsOnly?: boolean; detail: string; remediation: string }

const HEADER_RULES: HeaderRule[] = [
  { rule: "web.header.csp", header: "content-security-policy", title: "Missing Content-Security-Policy", severity: "medium",
    detail: "Without a CSP, any injected script runs with full access to the page. CSP is the strongest defence against cross-site scripting.",
    remediation: "Add a Content-Security-Policy header. Start with default-src 'self' and loosen only what the site needs." },
  { rule: "web.header.hsts", header: "strict-transport-security", title: "Missing HSTS (Strict-Transport-Security)", severity: "medium", httpsOnly: true,
    detail: "Without HSTS, a visitor's first request can be downgraded to plain HTTP and intercepted.",
    remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains once the whole site is on HTTPS." },
  { rule: "web.header.xcto", header: "x-content-type-options", title: "Missing X-Content-Type-Options", severity: "low",
    detail: "Without nosniff, browsers may guess a file's type and run it as script.",
    remediation: "Add X-Content-Type-Options: nosniff." },
  { rule: "web.header.referrer", header: "referrer-policy", title: "Missing Referrer-Policy", severity: "info",
    detail: "Without a referrer policy, full URLs (which may contain tokens) can leak to other sites.",
    remediation: "Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)." },
];

// Sensitive files that should never be reachable. Every probe needs proof in
// the content (a "needle"), so a site that answers every path with its home
// page cannot produce a false alarm.
interface Probe { path: string; title: string; severity: Severity; needle: RegExp; detail?: string }
const KEY_DETAIL = "Anyone can download this file. It typically holds passwords, keys or source code.";
const PROBES: Probe[] = [
  { path: "/.env", title: "Environment file exposed (.env)", severity: "critical", needle: /^[A-Z][A-Z0-9_]*\s*=/m },
  { path: "/.env.local", title: "Environment file exposed (.env.local)", severity: "critical", needle: /^[A-Z][A-Z0-9_]*\s*=/m },
  { path: "/.env.production", title: "Environment file exposed (.env.production)", severity: "critical", needle: /^[A-Z][A-Z0-9_]*\s*=/m },
  { path: "/.git/HEAD", title: "Git repository exposed (.git)", severity: "high", needle: /^ref:\s*refs\/|^[0-9a-f]{40}\s*$/m, detail: "The .git folder is public, so the full source code and its history (often including old secrets) can be downloaded." },
  { path: "/.git/config", title: "Git configuration exposed", severity: "high", needle: /\[core\]/ },
  { path: "/.svn/entries", title: "Subversion metadata exposed (.svn)", severity: "high", needle: /^\d{1,2}\s*\n(?:dir|\s*\n)/ },
  { path: "/backup.sql", title: "Database backup exposed", severity: "critical", needle: /INSERT INTO|CREATE TABLE/i },
  { path: "/dump.sql", title: "Database dump exposed", severity: "critical", needle: /INSERT INTO|CREATE TABLE/i },
  { path: "/database.sql", title: "Database export exposed", severity: "critical", needle: /INSERT INTO|CREATE TABLE/i },
  { path: "/wp-config.php.bak", title: "WordPress config backup exposed", severity: "critical", needle: /DB_PASSWORD/ },
  { path: "/wp-config.php~", title: "WordPress config backup exposed", severity: "critical", needle: /DB_PASSWORD/ },
  { path: "/.aws/credentials", title: "AWS credentials file exposed", severity: "critical", needle: /aws_access_key_id/i },
  { path: "/id_rsa", title: "Private SSH key exposed", severity: "critical", needle: /BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY/ },
  { path: "/.ssh/id_rsa", title: "Private SSH key exposed", severity: "critical", needle: /BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY/ },
  { path: "/.npmrc", title: "npm configuration exposed (.npmrc)", severity: "high", needle: /_authToken|always-auth|registry\s*=/ },
  { path: "/.htpasswd", title: "Password file exposed (.htpasswd)", severity: "high", needle: /^[\w.-]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|[\w./]{13})/m },
  { path: "/.vscode/sftp.json", title: "Editor deploy settings exposed (sftp.json)", severity: "high", needle: /"(?:password|host|privateKeyPath)"\s*:/ },
  { path: "/docker-compose.yml", title: "docker-compose.yml exposed", severity: "medium", needle: /^services\s*:|^version\s*:\s*["']?\d/m, detail: "The service layout is public, and these files often hold passwords and internal addresses." },
  { path: "/config.json", title: "Configuration file with secrets exposed (config.json)", severity: "high", needle: /"[^"]*(?:pass(?:word)?|secret|token|api_?key|private_?key)[^"]*"\s*:\s*"[^"]{4,}"/i },
  { path: "/web.config", title: "web.config exposed", severity: "high", needle: /<configuration[\s>]/i },
  { path: "/phpinfo.php", title: "phpinfo() page exposed", severity: "medium", needle: /PHP Version|phpinfo\(\)/i, detail: "phpinfo reveals server paths, settings and sometimes environment secrets." },
  { path: "/info.php", title: "phpinfo() page exposed", severity: "medium", needle: /PHP Version|phpinfo\(\)/i },
  { path: "/server-status", title: "Apache server-status exposed", severity: "medium", needle: /Apache Server Status/i, detail: "Shows live requests, client addresses and internal URLs." },
  { path: "/server-info", title: "Apache server-info exposed", severity: "medium", needle: /Apache Server Information/i },
  { path: "/actuator/env", title: "Spring Boot actuator exposed", severity: "high", needle: /"activeProfiles"|"propertySources"/, detail: "The actuator lists configuration and environment values, often including secrets." },
  { path: "/elmah.axd", title: "ELMAH error log exposed", severity: "medium", needle: /Error Log for/i },
  { path: "/storage/logs/laravel.log", title: "Laravel log file exposed", severity: "medium", needle: /^\[\d{4}-\d{2}-\d{2} [\d:]+\] \w+\.(?:ERROR|INFO|WARNING|DEBUG)/m },
  { path: "/.DS_Store", title: ".DS_Store exposed (lists file names)", severity: "low", needle: /Bud1/ },
  { path: "/swagger.json", title: "API description is public (swagger.json)", severity: "info", needle: /"swagger"\s*:|"openapi"\s*:/, detail: "The full list of API endpoints is published. That is fine for a public API, but it maps the attack surface for everyone else." },
  { path: "/openapi.json", title: "API description is public (openapi.json)", severity: "info", needle: /"openapi"\s*:/ },
];

/** Runs async jobs with a small concurrency limit. */
async function pool<T>(items: T[], limit: number, job: (item: T) => Promise<void>): Promise<void> {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (i < items.length) await job(items[i++]); }));
}

// ------------------------------------------------------------------- scan

export async function scanWeb(rawUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "category">) => findings.push({ category: "web", ...f });

  let url: URL;
  try {
    url = new URL(rawUrl.includes("://") ? rawUrl : `https://${rawUrl}`);
    if (!/^https?:$/.test(url.protocol)) throw new Error("scheme");
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

  // 1) Transport: HTTPS, certificate, and the plain-HTTP redirect.
  let tls: TlsInfo | null = null;
  if (url.protocol === "https:") {
    tls = await tlsInfo(url.hostname, Number(url.port) || 443);
    if (tls && !tls.authorized && tls.error) {
      add({ rule: "web.tls.untrusted", severity: "high", location: url.origin, title: "TLS certificate is not trusted",
        detail: `Browsers will warn visitors because ${certProblem(tls.error)}. People learn to click through warnings, which makes interception easy.`,
        remediation: "Install a valid certificate for this exact domain from a trusted authority (Let's Encrypt is free) including the full chain." });
    } else if (tls?.validTo) {
      const days = Math.floor((tls.validTo.getTime() - Date.now()) / 86_400_000);
      if (days <= 14) add({ rule: "web.tls.expiring", severity: days <= 3 ? "high" : "medium", location: url.origin, title: `TLS certificate expires in ${Math.max(days, 0)} day${days === 1 ? "" : "s"}`,
        detail: "When it expires, every visitor gets a full-page security error and the site effectively goes down.",
        remediation: "Renew the certificate now and set up automatic renewal (certbot or your host's auto-renew)." });
    }
    if (!url.port) {
      const plain = await get(`http://${url.host}${url.pathname}`);
      if (plain) {
        const loc = plain.headers.get("location") ?? "";
        if (plain.status >= 200 && plain.status < 300) {
          add({ rule: "web.http-no-redirect", severity: "medium", location: `http://${url.host}/`, title: "Plain HTTP does not redirect to HTTPS",
            detail: "The site still answers over unencrypted HTTP, so anyone who types the address without https:// is exposed.",
            remediation: "Redirect every HTTP request to HTTPS with a 301, and add HSTS." });
        } else if (plain.status >= 300 && plain.status < 400 && /^http:/i.test(loc)) {
          add({ rule: "web.http-no-redirect", severity: "low", location: `http://${url.host}/`, title: "HTTP redirect does not go to HTTPS",
            detail: "The plain-HTTP address redirects, but not to an HTTPS address.", remediation: "Make the redirect point to the https:// version of the site." });
        }
        plain.body?.cancel().catch(() => {});
      }
    }
  } else {
    add({ rule: "web.no-https", severity: "high", location: url.href, title: "Site is served over plain HTTP",
      detail: "Traffic to this site is not encrypted and can be read or changed in transit.",
      remediation: "Serve the site over HTTPS and redirect all HTTP traffic to it." });
  }

  // 2) The page itself (following same-site redirects such as example.com -> www.example.com).
  const { res, final } = await getFollowing(url);
  if (!res) {
    add({ rule: "web.unreachable", severity: "info", location: url.href, title: "Site did not respond",
      detail: tls && !tls.authorized ? "The site could not be loaded, most likely because its certificate is not trusted (see above)." : "Lucent Shield could not reach the address (timeout or connection error).",
      remediation: "Check the site is online and the address is correct, then scan again." });
    return findings;
  }
  const h = res.headers;
  const onHttps = final.protocol === "https:";
  const body = await readCapped(res);

  // Headers that are missing...
  for (const rule of HEADER_RULES) {
    if (rule.httpsOnly && !onHttps) continue;
    if (!h.get(rule.header)) add({ rule: rule.rule, severity: rule.severity, location: final.href, title: rule.title, detail: rule.detail, remediation: rule.remediation });
  }
  const csp = h.get("content-security-policy") ?? "";
  if (!h.get("x-frame-options") && !/frame-ancestors/i.test(csp)) {
    add({ rule: "web.header.frame", severity: "low", location: final.href, title: "Missing clickjacking protection",
      detail: "The site can be embedded in a hidden frame on another site and used to trick your users into clicking (clickjacking).",
      remediation: "Add frame-ancestors 'none' (or 'self') to the CSP, or X-Frame-Options: DENY." });
  }
  // ...and headers that are present but weak.
  if (csp) {
    const scriptSrc = (/(?:^|;)\s*script-src\s+([^;]*)/i.exec(csp) ?? /(?:^|;)\s*default-src\s+([^;]*)/i.exec(csp))?.[1] ?? "";
    const weak: string[] = [];
    if (/'unsafe-inline'/i.test(scriptSrc) && !/'nonce-|'sha(?:256|384|512)-|'strict-dynamic'/i.test(scriptSrc)) weak.push("'unsafe-inline' lets any injected inline script run");
    if (/'unsafe-eval'/i.test(scriptSrc)) weak.push("'unsafe-eval' allows eval-style code");
    if (/(?:^|\s)(?:\*|https?:|data:)(?:\s|$)/i.test(scriptSrc)) weak.push("scripts may load from any site");
    if (scriptSrc && weak.length) add({ rule: "web.header.csp-weak", severity: "low", location: final.href, title: "Content-Security-Policy is too permissive",
      evidence: `script-src ${scriptSrc.trim().slice(0, 140)}`, detail: `The policy exists but ${weak.join(", and ")}, which removes most of its protection against cross-site scripting.`,
      remediation: "Use nonces or hashes for inline scripts, drop 'unsafe-eval', and list specific script origins instead of wildcards." });
  }
  const hsts = h.get("strict-transport-security");
  const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts ?? "")?.[1] ?? NaN);
  if (onHttps && hsts && !Number.isNaN(maxAge) && maxAge < 15_552_000) {
    add({ rule: "web.header.hsts-short", severity: "low", location: final.href, title: "HSTS lifetime is short", evidence: `strict-transport-security: ${hsts}`,
      detail: "A short max-age means browsers forget the HTTPS-only rule quickly, reopening the downgrade window.",
      remediation: "Use max-age of at least 15552000 (180 days), ideally 31536000, with includeSubDomains." });
  }

  // Information disclosure.
  const powered = h.get("x-powered-by");
  if (powered) add({ rule: "web.info.powered-by", severity: "info", location: final.href, title: `Technology disclosed: X-Powered-By: ${powered}`,
    detail: "Advertising your stack and versions helps an attacker look up matching vulnerabilities.", remediation: "Remove the X-Powered-By header (in Express: app.disable('x-powered-by'))." });
  const server = h.get("server");
  if (server && /\d/.test(server)) add({ rule: "web.info.server", severity: "info", location: final.href, title: `Server version disclosed: ${server}`,
    detail: "The exact server version helps an attacker find matching exploits.", remediation: "Hide the version in your web server configuration (e.g. server_tokens off in nginx)." });
  const aspnet = h.get("x-aspnet-version");
  if (aspnet) add({ rule: "web.info.aspnet", severity: "info", location: final.href, title: `ASP.NET version disclosed: ${aspnet}`,
    detail: "The framework version helps an attacker target known flaws.", remediation: "Set enableVersionHeader=\"false\" in web.config." });
  if (/<title>\s*Index of \//i.test(body)) add({ rule: "web.directory-listing", severity: "medium", location: final.href, title: "Directory listing is switched on",
    detail: "The server lists every file in the folder, exposing backups and files that were never meant to be linked.", remediation: "Turn off auto-indexing (Options -Indexes in Apache, autoindex off in nginx)." });

  // Cookies.
  const setCookie = (h as any).getSetCookie?.() ?? (h.get("set-cookie") ? [h.get("set-cookie")!] : []);
  for (const cookie of setCookie as string[]) {
    const name = cookie.split("=")[0].trim();
    const lower = cookie.toLowerCase();
    const sensitive = /sess|sid|token|auth|jwt|login|remember/i.test(name);
    const missing: string[] = [];
    if (!/;\s*httponly/.test(lower)) missing.push("HttpOnly");
    if (onHttps && !/;\s*secure/.test(lower)) missing.push("Secure");
    if (!/;\s*samesite/.test(lower)) missing.push("SameSite");
    if (/;\s*samesite\s*=\s*none/.test(lower) && !/;\s*secure/.test(lower)) missing.push("Secure (required with SameSite=None)");
    if (missing.length) add({ rule: "web.cookie.flags", severity: sensitive ? "medium" : "low", location: final.href,
      title: `Cookie "${name}" is missing ${missing.join(", ")}`,
      detail: "Cookies without these flags can be read by scripts, sent over plain HTTP, or used in cross-site request forgery." + (sensitive ? " This one looks like a login or session cookie." : ""),
      remediation: `Set ${missing.join(", ")} on this cookie.` });
  }

  // 3) CORS: does the site trust any website that asks? (one read-only GET with an Origin header)
  const evil = "https://lucent-shield-cors-check.invalid";
  const cors = await get(final.href, { origin: evil });
  if (cors) {
    const acao = cors.headers.get("access-control-allow-origin");
    const creds = /true/i.test(cors.headers.get("access-control-allow-credentials") ?? "");
    if (acao === evil || acao === "null") {
      add({ rule: "web.cors.reflected", severity: creds ? "high" : "medium", location: final.href, title: creds ? "CORS trusts any website, with credentials" : "CORS trusts any website",
        evidence: `access-control-allow-origin: ${acao}${creds ? "; access-control-allow-credentials: true" : ""}`,
        detail: creds ? "The site echoes back whatever origin asks and allows cookies, so any website a user visits can read their data from this site while they are logged in." : "The site echoes back whatever origin asks, so any website can read its responses from a visitor's browser.",
        remediation: "Only return Access-Control-Allow-Origin for an allow list of your own front-end origins, never by echoing the request's Origin." });
    }
    cors.body?.cancel().catch(() => {});
  }

  // 4) Sensitive files. First learn what a missing page looks like, so a site
  // that answers every path with its home page can't trigger false alarms.
  const fingerprint = (s: string) => createHash("sha256").update(s).digest("hex");
  const missing = await get(new URL(`/lucent-shield-${randomBytes(6).toString("hex")}-missing`, final.origin).href);
  const missingBody = missing && missing.status === 200 ? await readCapped(missing) : null;
  const missingPrint = missingBody !== null ? fingerprint(missingBody) : null;
  missing?.body?.cancel().catch(() => {});

  await pool(PROBES, 6, async (probe) => {
    const target = new URL(probe.path, final.origin).href;
    const r = await get(target);
    if (!r) return;
    if (r.status !== 200) { r.body?.cancel().catch(() => {}); return; }
    const text = await readCapped(r, 131_072);
    if (missingPrint && fingerprint(text) === missingPrint) return; // the generic "every path" page
    if (!probe.needle.test(text)) return;
    add({ rule: "web.exposed-file", severity: probe.severity, location: target, title: probe.title,
      detail: probe.detail ?? KEY_DETAIL,
      remediation: `Block public access to ${probe.path} at the web server or framework level, remove the file from the web root, and rotate any secrets it contained.` });
  });

  // 5) Email spoofing protection for the domain (DNS only; the site is not contacted).
  const domain = bare(final.hostname);
  if (!isIP(domain) && domain.includes(".") && !/\.(?:local|localhost|internal|test|invalid)$/i.test(domain)) {
    const txt = async (name: string): Promise<string[] | null> => {
      try { return (await resolveTxt(name)).map((p) => p.join("")); }
      catch (e: any) { return e?.code === "ENODATA" || e?.code === "ENOTFOUND" ? [] : null; }
    };
    const [root, dmarc] = await Promise.all([txt(domain), txt(`_dmarc.${domain}`)]);
    if (root && !root.some((r) => /^v=spf1\b/i.test(r))) add({ rule: "web.email.no-spf", severity: "low", location: domain, title: "No SPF record for the domain",
      detail: "Without SPF, anyone can send email that claims to come from this domain, which is how most phishing in your name would start.",
      remediation: `Publish a TXT record on ${domain} such as v=spf1 include:<your mail provider> -all (or v=spf1 -all if the domain never sends email).` });
    if (dmarc && !dmarc.some((r) => /^v=DMARC1\b/i.test(r))) add({ rule: "web.email.no-dmarc", severity: "low", location: `_dmarc.${domain}`, title: "No DMARC policy for the domain",
      detail: "DMARC tells receiving mail servers to reject mail that fakes your domain. Without it, spoofed emails usually get delivered.",
      remediation: `Publish a TXT record on _dmarc.${domain}: v=DMARC1; p=quarantine; rua=mailto:<your address>, then move to p=reject.` });
    else if (dmarc?.some((r) => /^v=DMARC1\b.*\bp\s*=\s*none\b/i.test(r))) add({ rule: "web.email.dmarc-none", severity: "info", location: `_dmarc.${domain}`, title: "DMARC is in monitor-only mode (p=none)",
      detail: "The policy only reports spoofing; it does not stop it.", remediation: "After checking the reports, move to p=quarantine and then p=reject." });
  }

  return findings;
}
