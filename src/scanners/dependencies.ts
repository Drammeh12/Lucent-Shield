// Checks a project's dependencies against OSV (osv.dev, run by Google and
// OpenSSF), the open database of known published vulnerabilities.
//
// It reads the exact versions you ship from lockfiles wherever they live in
// the project (monorepo folders included), across eight ecosystems:
//   npm      package-lock.json, yarn.lock, pnpm-lock.yaml (package.json as a fallback)
//   PyPI     requirements*.txt, Pipfile.lock, poetry.lock
//   Go       go.mod
//   RubyGems Gemfile.lock
//   Packagist composer.lock
//   crates.io Cargo.lock
//   Maven    pom.xml
//   NuGet    packages.lock.json, *.csproj
//
// Only package names and versions are sent to OSV. No code leaves the machine.

import { readFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import type { Finding, Severity } from "../types.ts";
import type { ScanFile } from "../util/walk.ts";
import { SEVERITY_RANK } from "../types.ts";

export type Ecosystem = "npm" | "PyPI" | "Go" | "RubyGems" | "Packagist" | "crates.io" | "Maven" | "NuGet";
export interface Dep { name: string; version: string; ecosystem: Ecosystem; source: string }

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";
const BATCH_SIZE = 500;
const MAX_DETAILS = 400;
const DETAIL_CONCURRENCY = 8;

const exact = (v: string) => /^\d+(?:\.\d+){0,3}(?:[-+.][0-9A-Za-z.-]+)?$/.test(v);
function cleanRange(range: string): string {
  const m = /(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)/.exec(range);
  return m ? m[1] : "";
}
function json(text: string): any { try { return JSON.parse(text); } catch { return null; } }

// ------------------------------- parsers -------------------------------
// Each parser takes the file text and returns dependencies (source filled in later).

export function parsePackageLock(text: string): Omit<Dep, "source">[] {
  const j = json(text); if (!j) return [];
  const out: Omit<Dep, "source">[] = [];
  if (j.packages && typeof j.packages === "object") {
    for (const [path, info] of Object.entries<any>(j.packages)) {
      if (!path || !info?.version || info.link) continue;
      const name = info.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      if (name && exact(info.version)) out.push({ name, version: info.version, ecosystem: "npm" });
    }
  } else if (j.dependencies) { // lockfile v1: nested tree
    const walkTree = (deps: any) => {
      for (const [name, info] of Object.entries<any>(deps ?? {})) {
        if (info?.version && exact(info.version)) out.push({ name, version: info.version, ecosystem: "npm" });
        if (info?.dependencies) walkTree(info.dependencies);
      }
    };
    walkTree(j.dependencies);
  }
  return out;
}

export function parseYarnLock(text: string): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  let names: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line) && line.trimEnd().endsWith(":")) {
      // "lodash@^4.17.0", lodash@~4.17.1:   or   "@babel/core@npm:7.0.0":
      names = line.replace(/:$/, "").split(/,\s*/).map((s) => s.replace(/^"|"$/g, "")).map((s) => s.slice(0, s.lastIndexOf("@"))).filter(Boolean);
    } else {
      const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
      if (v && names.length) { for (const n of new Set(names)) if (exact(v[1])) out.push({ name: n, version: v[1], ecosystem: "npm" }); names = []; }
    }
  }
  return out;
}

export function parsePnpmLock(text: string): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  // keys like "  /lodash@4.17.21:" (v6) or "  lodash@4.17.21:" (v9), scoped "/@scope/name@1.0.0(peer@2):"
  for (const m of text.matchAll(/^ {2}['"]?\/?((?:@[^/@\s]+\/)?[^@\s'"/]+)@(\d[^(:'"\s]*)/gm)) {
    if (exact(m[2])) out.push({ name: m[1], version: m[2], ecosystem: "npm" });
  }
  return out;
}

export function parsePackageJson(text: string): Omit<Dep, "source">[] {
  const j = json(text); if (!j) return [];
  const out: Omit<Dep, "source">[] = [];
  for (const block of [j.dependencies, j.devDependencies]) {
    for (const [name, range] of Object.entries<any>(block ?? {})) {
      const v = cleanRange(String(range));
      if (v) out.push({ name, version: v, ecosystem: "npm" });
    }
  }
  return out;
}

export function parseRequirements(text: string): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][0-9A-Za-z.\-+]*)/.exec(raw);
    if (m) out.push({ name: m[1], version: m[2], ecosystem: "PyPI" });
  }
  return out;
}

export function parsePipfileLock(text: string): Omit<Dep, "source">[] {
  const j = json(text); if (!j) return [];
  const out: Omit<Dep, "source">[] = [];
  for (const section of [j.default, j.develop]) {
    for (const [name, info] of Object.entries<any>(section ?? {})) {
      const v = String(info?.version ?? "").replace(/^==/, "");
      if (exact(v)) out.push({ name, version: v, ecosystem: "PyPI" });
    }
  }
  return out;
}

/** poetry.lock and Cargo.lock share the [[package]] name/version shape. */
function parseTomlPackages(text: string, ecosystem: Ecosystem): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  for (const block of text.split(/^\[\[package\]\]/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (name && version && exact(version)) out.push({ name, version, ecosystem });
  }
  return out;
}
export const parsePoetryLock = (t: string) => parseTomlPackages(t, "PyPI");
export const parseCargoLock = (t: string) => parseTomlPackages(t, "crates.io");

export function parseGoMod(text: string): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  for (const m of text.matchAll(/^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+\/[^\s]+)\s+v(\d[^\s]*)/gm)) {
    out.push({ name: m[1], version: m[2].replace(/\+incompatible$/, ""), ecosystem: "Go" });
  }
  return out;
}

export function parseGemfileLock(text: string): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  let inSpecs = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) inSpecs = false;
    if (/^\s{2}specs:\s*$/.test(line)) { inSpecs = true; continue; }
    const m = inSpecs && /^ {4}([A-Za-z0-9_.\-]+) \(([0-9][^)\s-]*)(?:-[^)]*)?\)\s*$/.exec(line);
    if (m) out.push({ name: m[1], version: m[2], ecosystem: "RubyGems" });
  }
  return out;
}

export function parseComposerLock(text: string): Omit<Dep, "source">[] {
  const j = json(text); if (!j) return [];
  return [...(j.packages ?? []), ...(j["packages-dev"] ?? [])]
    .map((p: any) => ({ name: String(p?.name ?? ""), version: String(p?.version ?? "").replace(/^v/, ""), ecosystem: "Packagist" as const }))
    .filter((d) => d.name && exact(d.version));
}

export function parsePomXml(text: string): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(m[1])?.[1];
    const a = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(m[1])?.[1];
    const v = /<version>\s*([^<\s]+)\s*<\/version>/.exec(m[1])?.[1];
    if (g && a && v && !v.includes("${") && exact(v)) out.push({ name: `${g}:${a}`, version: v, ecosystem: "Maven" });
  }
  return out;
}

export function parseNuget(text: string): Omit<Dep, "source">[] {
  const out: Omit<Dep, "source">[] = [];
  const j = json(text);
  if (j?.dependencies) { // packages.lock.json
    for (const fw of Object.values<any>(j.dependencies)) for (const [name, info] of Object.entries<any>(fw ?? {})) if (info?.resolved && exact(info.resolved)) out.push({ name, version: info.resolved, ecosystem: "NuGet" });
    return out;
  }
  for (const m of text.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/g)) if (exact(m[2])) out.push({ name: m[1], version: m[2], ecosystem: "NuGet" });
  return out;
}

const PARSERS: { match: (base: string) => boolean; parse: (t: string) => Omit<Dep, "source">[]; lock: boolean; eco: Ecosystem }[] = [
  { match: (b) => b === "package-lock.json" || b === "npm-shrinkwrap.json", parse: parsePackageLock, lock: true, eco: "npm" },
  { match: (b) => b === "yarn.lock", parse: parseYarnLock, lock: true, eco: "npm" },
  { match: (b) => b === "pnpm-lock.yaml", parse: parsePnpmLock, lock: true, eco: "npm" },
  { match: (b) => b === "package.json", parse: parsePackageJson, lock: false, eco: "npm" },
  { match: (b) => /^requirements.*\.txt$/.test(b), parse: parseRequirements, lock: true, eco: "PyPI" },
  { match: (b) => b === "pipfile.lock", parse: parsePipfileLock, lock: true, eco: "PyPI" },
  { match: (b) => b === "poetry.lock", parse: parsePoetryLock, lock: true, eco: "PyPI" },
  { match: (b) => b === "go.mod", parse: parseGoMod, lock: true, eco: "Go" },
  { match: (b) => b === "gemfile.lock", parse: parseGemfileLock, lock: true, eco: "RubyGems" },
  { match: (b) => b === "composer.lock", parse: parseComposerLock, lock: true, eco: "Packagist" },
  { match: (b) => b === "cargo.lock", parse: parseCargoLock, lock: true, eco: "crates.io" },
  { match: (b) => b === "pom.xml", parse: parsePomXml, lock: true, eco: "Maven" },
  { match: (b) => b === "packages.lock.json" || b.endsWith(".csproj"), parse: parseNuget, lock: true, eco: "NuGet" },
];

/**
 * Collects dependencies from every manifest in the project. A package.json is
 * only used where its folder has no npm lockfile (the lockfile has the real
 * installed versions, including indirect dependencies).
 */
export function collectDeps(files: { rel: string; text: string }[]): Dep[] {
  const lockedNpmDirs = new Set<string>();
  const found: Dep[] = [];
  const dirOf = (rel: string) => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "");
  const sorted = [...files].sort((a, b) => Number(basename(a.rel) === "package.json") - Number(basename(b.rel) === "package.json"));
  for (const f of sorted) {
    const base = basename(f.rel).toLowerCase();
    const p = PARSERS.find((x) => x.match(base));
    if (!p) continue;
    if (p.eco === "npm" && p.lock) lockedNpmDirs.add(dirOf(f.rel));
    if (base === "package.json" && lockedNpmDirs.has(dirOf(f.rel))) continue;
    for (const d of p.parse(f.text)) found.push({ ...d, source: f.rel });
  }
  const seen = new Set<string>();
  return found.filter((d) => { const k = `${d.ecosystem}|${d.name}|${d.version}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

// ------------------------------ OSV lookup ------------------------------

function mapSeverity(vuln: any): Severity {
  const label = String(vuln?.database_specific?.severity ?? "").toUpperCase();
  if (label.includes("CRIT")) return "critical";
  if (label === "HIGH") return "high";
  if (label === "MODERATE" || label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";
  const sev = vuln?.severity?.find((s: any) => s.type?.startsWith("CVSS"));
  const base = Number(String(sev?.score ?? "").match(/^(\d+(?:\.\d+)?)$/)?.[1] ?? NaN);
  if (!Number.isNaN(base)) return base >= 9 ? "critical" : base >= 7 ? "high" : base >= 4 ? "medium" : "low";
  return "medium";
}

function fixedVersion(vuln: any, name: string): string | null {
  for (const aff of vuln?.affected ?? []) {
    if (aff?.package?.name !== name) continue;
    for (const range of aff?.ranges ?? []) for (const ev of range?.events ?? []) if (ev.fixed) return ev.fixed;
  }
  return null;
}

/** Picks the highest version string among candidates (numeric, part by part). */
function highestVersion(vs: string[]): string | null {
  const parse = (v: string) => v.split(/[.+-]/).map((p) => (Number.isNaN(Number(p)) ? 0 : Number(p)));
  return vs.reduce<string | null>((best, v) => {
    if (!best) return v;
    const a = parse(v), b = parse(best);
    for (let i = 0; i < Math.max(a.length, b.length); i++) { if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0) ? v : best; }
    return best;
  }, null);
}

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

/** Scans dependencies. Pass the walked files to find manifests anywhere; `fetcher` is injectable for tests. */
export async function scanDependencies(root: string, files?: ScanFile[], fetcher: Fetch = fetch): Promise<Finding[]> {
  const manifestFiles = files
    ? files.filter((f) => PARSERS.some((p) => p.match(basename(f.rel).toLowerCase())))
    : ["package-lock.json", "package.json", "requirements.txt"].filter((n) => existsSync(join(root, n))).map((n) => ({ rel: n, text: readFileSync(join(root, n), "utf8") }));
  const deps = collectDeps(manifestFiles);
  if (deps.length === 0) return [];

  // 1) Which packages have known vulnerabilities (batched).
  const vulnIds: string[][] = [];
  try {
    for (let i = 0; i < deps.length; i += BATCH_SIZE) {
      const chunk = deps.slice(i, i + BATCH_SIZE);
      const res = await fetcher(OSV_BATCH, {
        method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(30_000),
        body: JSON.stringify({ queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }),
      });
      if (!res.ok) throw new Error(`OSV responded ${res.status}`);
      const batch: any = await res.json();
      for (const r of batch?.results ?? []) vulnIds.push((r?.vulns ?? []).map((v: any) => v.id));
    }
  } catch (err) {
    return [{
      rule: "dependency.osv-unreachable", severity: "info", category: "dependency",
      title: "Could not check dependencies for known vulnerabilities",
      detail: `Lucent Shield found ${deps.length} dependencies but could not reach the OSV vulnerability database (${err instanceof Error ? err.message : String(err)}), so this check was skipped.`,
      remediation: "Check the server's internet access and scan again. OSV is at api.osv.dev.",
    }];
  }

  // 2) Details (severity, summary, fixed version) for each distinct vulnerability, a few at a time.
  const unique = [...new Set(vulnIds.flat())].slice(0, MAX_DETAILS);
  const details = new Map<string, any>();
  let next = 0;
  await Promise.all(Array.from({ length: DETAIL_CONCURRENCY }, async () => {
    while (next < unique.length) {
      const id = unique[next++];
      try {
        const r = await fetcher(OSV_VULN + encodeURIComponent(id), { signal: AbortSignal.timeout(15_000) });
        details.set(id, r.ok ? await r.json() : { id });
      } catch { details.set(id, { id }); }
    }
  }));

  // 3) One finding per vulnerable package version, rated by its worst issue.
  const findings: Finding[] = [];
  deps.forEach((dep, i) => {
    const ids = vulnIds[i] ?? [];
    if (!ids.length) return;
    const vulns = ids.map((id) => details.get(id) ?? { id });
    const sevs = vulns.map(mapSeverity);
    const worst = sevs.reduce((a, b) => (SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a), "low" as Severity);
    const fixes = vulns.map((v) => fixedVersion(v, dep.name)).filter((x): x is string => !!x);
    const target = highestVersion(fixes);
    const named = vulns.slice(0, 5).map((v) => {
      const alias = (v.aliases ?? []).find((a: string) => a.startsWith("CVE-"));
      return `${alias ?? v.id}${v.summary ? `: ${String(v.summary).slice(0, 110)}` : ""}`;
    });
    findings.push({
      rule: "dependency.known-vuln", severity: worst, category: "dependency",
      title: `${dep.name}@${dep.version} has ${ids.length} known vulnerabilit${ids.length === 1 ? "y" : "ies"}`,
      location: dep.source, evidence: `${dep.ecosystem}: ${dep.name} ${dep.version}`,
      detail: `${named.join("; ")}${ids.length > 5 ? `; and ${ids.length - 5} more` : ""}.`,
      remediation: target
        ? `Upgrade ${dep.name} to ${target} or later, which fixes all the listed issues, then re-run your tests.`
        : `Upgrade ${dep.name} to a patched release. Details: https://osv.dev/vulnerability/${ids[0]}`,
    });
  });
  return findings;
}
