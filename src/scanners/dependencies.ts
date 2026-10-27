// Checks the project's dependencies against the OSV database
// (osv.dev, run by Google/OpenSSF) for known published vulnerabilities.
// Reads package.json (npm) and requirements.txt (PyPI). Network is only
// used to reach OSV; no code or package contents leave the machine.

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Severity } from "../types.ts";

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";

interface Dep {
  name: string;
  version: string;
  ecosystem: "npm" | "PyPI";
  source: string;
}

function cleanVersion(range: string): string {
  // Turn "^1.2.3", "~1.2.3", ">=1.2.3", "1.2.3 - 2.0.0" into a single version.
  const m = /(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)/.exec(range);
  return m ? m[1] : "";
}

function readNpmDeps(root: string): Dep[] {
  const pkgPath = join(root, "package.json");
  if (!existsSync(pkgPath)) return [];
  let pkg: any;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch {
    return [];
  }
  const deps: Dep[] = [];
  const add = (obj: Record<string, string> | undefined) => {
    for (const [name, range] of Object.entries(obj ?? {})) {
      const version = cleanVersion(String(range));
      if (version) deps.push({ name, version, ecosystem: "npm", source: "package.json" });
    }
  };
  add(pkg.dependencies);
  add(pkg.devDependencies);
  return deps;
}

function readPyDeps(root: string): Dep[] {
  const reqPath = join(root, "requirements.txt");
  if (!existsSync(reqPath)) return [];
  const deps: Dep[] = [];
  for (const raw of readFileSync(reqPath, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)/.exec(line);
    if (m) deps.push({ name: m[1], version: m[2], ecosystem: "PyPI", source: "requirements.txt" });
  }
  return deps;
}

function mapSeverity(vuln: any): Severity {
  // Prefer an explicit database severity label, then CVSS score.
  const label = String(vuln?.database_specific?.severity ?? "").toUpperCase();
  if (label.includes("CRIT")) return "critical";
  if (label === "HIGH") return "high";
  if (label === "MODERATE" || label === "MEDIUM") return "medium";
  if (label === "LOW") return "low";
  const sev = vuln?.severity?.find((s: any) => s.type?.startsWith("CVSS"));
  if (sev?.score) {
    const base = Number(String(sev.score).match(/(\d+(\.\d+)?)/)?.[1]);
    if (!Number.isNaN(base)) {
      if (base >= 9) return "critical";
      if (base >= 7) return "high";
      if (base >= 4) return "medium";
      return "low";
    }
  }
  return "medium";
}

function fixedVersion(vuln: any, ecosystem: string, name: string): string | null {
  for (const aff of vuln?.affected ?? []) {
    if (aff?.package?.name !== name) continue;
    for (const range of aff?.ranges ?? []) {
      for (const ev of range?.events ?? []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

export async function scanDependencies(root: string): Promise<Finding[]> {
  const deps = [...readNpmDeps(root), ...readPyDeps(root)];
  if (deps.length === 0) return [];

  let batch: any;
  try {
    const res = await fetch(OSV_BATCH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: deps.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
      }),
    });
    if (!res.ok) throw new Error(`OSV responded ${res.status}`);
    batch = await res.json();
  } catch (err) {
    return [
      {
        rule: "dependency.osv-unreachable",
        severity: "info",
        category: "dependency",
        title: "Could not check dependencies for known vulnerabilities",
        detail: `Lucent Shield could not reach the OSV vulnerability database (${err instanceof Error ? err.message : String(err)}). Dependency checking was skipped.`,
        remediation: "Check your internet connection and run the scan again. OSV is at api.osv.dev.",
      },
    ];
  }

  const results: any[] = batch?.results ?? [];
  const findings: Finding[] = [];
  const detailCache = new Map<string, any>();

  for (let i = 0; i < deps.length; i++) {
    const dep = deps[i];
    const vulns: any[] = results[i]?.vulns ?? [];
    for (const v of vulns) {
      let detail = detailCache.get(v.id);
      if (!detail) {
        try {
          const r = await fetch(OSV_VULN + encodeURIComponent(v.id));
          detail = r.ok ? await r.json() : v;
        } catch {
          detail = v;
        }
        detailCache.set(v.id, detail);
      }
      const fixed = fixedVersion(detail, dep.ecosystem, dep.name);
      findings.push({
        rule: "dependency.known-vuln",
        severity: mapSeverity(detail),
        category: "dependency",
        title: `${dep.name}@${dep.version} — ${detail.id}`,
        location: dep.source,
        detail:
          (detail.summary || detail.details || "A known vulnerability affects this version.").slice(0, 300) +
          ` (${detail.id}).`,
        remediation: fixed
          ? `Upgrade ${dep.name} to ${fixed} or later.`
          : `Upgrade ${dep.name} to a patched version. See https://osv.dev/vulnerability/${detail.id}`,
      });
    }
  }

  return findings;
}
