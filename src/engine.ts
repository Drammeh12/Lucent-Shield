// The engine: runs the right scanners for an asset and returns one result,
// plus the shield state the dashboard shows.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, existsSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walk } from "./util/walk.ts";
import { scanSecrets } from "./scanners/secrets.ts";
import { scanCode } from "./scanners/code.ts";
import { scanDependencies } from "./scanners/dependencies.ts";
import { scanWeb } from "./scanners/web.ts";
import { scanArtifact } from "./scanners/forensics.ts";
import { countBySeverity, type Finding, type ScanResult } from "./types.ts";

const pexec = promisify(execFile);

export const VERSION = "0.5.0";

export type AssetKind = "repo" | "web" | "artifact";
export type Shield = "secure" | "at_risk" | "exposed" | "scanning" | "new";

/** Green when clean, amber on medium/low, red (exposed) on critical/high. */
export function shieldFor(findings: Finding[]): Shield {
  const c = countBySeverity(findings);
  if (c.critical > 0 || c.high > 0) return "exposed";
  if (c.medium > 0 || c.low > 0) return "at_risk";
  return "secure";
}

/** A git remote we can clone (GitHub, GitLab, Bitbucket, or any .git URL). */
export function isGitUrl(t: string): boolean {
  return /^(https?:\/\/[\w.-]+\/[\w./-]+?|git@[\w.-]+:[\w./-]+?)(\.git)?\/?$/i.test(t.trim())
    && !existsSync(t);
}

/** Shallow-clone a repo to a throwaway dir. Private repos use LUCENT_GITHUB_TOKEN. */
async function cloneRepo(url: string): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "lucent-"));
  let clone = url.trim().replace(/\/$/, "");
  const token = process.env.LUCENT_GITHUB_TOKEN;
  if (token && /^https:\/\/github\.com\//i.test(clone)) {
    clone = clone.replace(/^https:\/\//i, `https://${token}@`);
  }
  await pexec("git", ["clone", "--depth", "1", "--quiet", clone, dir], {
    timeout: 180_000,
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "true" },
  });
  return dir;
}

async function runRepo(dir: string): Promise<Finding[]> {
  const files = walk(dir);
  return [...scanSecrets(files), ...scanCode(files), ...(await scanDependencies(dir))];
}

export async function runScan(kind: AssetKind, target: string): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  let findings: Finding[] = [];
  let filesScanned = 0;

  if (kind === "repo") {
    let dir = target;
    let cleanup = false;
    if (isGitUrl(target)) {
      try {
        dir = await cloneRepo(target);
        cleanup = true;
      } catch {
        findings = [{
          rule: "repo.clone-failed", severity: "info", category: "code", location: target,
          title: "Could not access the repository",
          detail: "Lucent Shield could not clone this repository. If it is private, set a LUCENT_GITHUB_TOKEN on the server. Otherwise check the URL.",
          remediation: "Confirm the repository URL is correct and reachable, and that a token is set for private repositories.",
        }];
        return { tool: "Lucent Shield", version: VERSION, target, mode: "repo", startedAt, finishedAt: new Date().toISOString(), filesScanned: 0, findings };
      }
    } else if (!existsSync(target) || !statSync(target).isDirectory()) {
      findings = [{
        rule: "repo.not-found", severity: "info", category: "code", location: target,
        title: "Path or repository not found",
        detail: "This target is neither a folder on the server nor a git URL Lucent Shield can clone.",
        remediation: "Enter a local folder path on the server, or a repository URL such as https://github.com/owner/repo.",
      }];
      return { tool: "Lucent Shield", version: VERSION, target, mode: "repo", startedAt, finishedAt: new Date().toISOString(), filesScanned: 0, findings };
    }
    try {
      findings = await runRepo(dir);
      filesScanned = walk(dir).length;
    } finally {
      if (cleanup) { try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
    }
  } else if (kind === "web") {
    findings = await scanWeb(target);
  } else {
    findings = scanArtifact(target);
    filesScanned = findings.filter((f) => f.rule === "forensic.hash").length;
  }

  return {
    tool: "Lucent Shield",
    version: VERSION,
    target,
    mode: kind === "web" ? "web" : "repo",
    startedAt,
    finishedAt: new Date().toISOString(),
    filesScanned,
    findings,
  };
}
