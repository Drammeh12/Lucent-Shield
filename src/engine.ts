// The engine: runs the right scanners for an asset and returns one result,
// plus the shield state the dashboard shows.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, existsSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walkWithStats, WALK_LIMITS } from "./util/walk.ts";
import { scanSecrets } from "./scanners/secrets.ts";
import { scanCode } from "./scanners/code.ts";
import { scanDependencies } from "./scanners/dependencies.ts";
import { scanWeb } from "./scanners/web.ts";
import { scanArtifact } from "./scanners/forensics.ts";
import { countBySeverity, type Finding, type ScanResult } from "./types.ts";

const pexec = promisify(execFile);

export const VERSION = "0.19.0";

export type AssetKind = "repo" | "web" | "artifact";
export type Shield = "secure" | "at_risk" | "exposed" | "scanning" | "new";

/** Green when clean, amber on medium/low, red (exposed) on critical/high. */
/** Results that mean the target was never actually examined. */
const UNREACHED = new Set(["web.unreachable", "web.bad-url", "web.blocked-internal", "repo.clone-failed", "repo.not-found", "scan.failed"]);

export function shieldFor(findings: Finding[]): Shield {
  // A site that did not answer has not been checked, so it is not "clean".
  if (findings.some((f) => UNREACHED.has(f.rule))) return "new";
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

/** Shallow-clone a repo to a throwaway dir. A token, when given, reaches private GitHub repos. */
async function cloneRepo(url: string, token?: string): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "lucent-"));
  let clone = url.trim().replace(/\/$/, "");
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

export interface RepoScanOptions {
  /** Skip the network-backed dependency lookup. */
  offline?: boolean;
  /** HTTP client for the vulnerability database (swappable in tests). */
  fetcher?: (url: string, init?: RequestInit) => Promise<Response>;
}

const note = (rule: string, title: string, detail: string, remediation: string): Finding =>
  ({ rule, severity: "info", category: "code", title, detail, remediation });

/** Scans a folder with every source check. One failing check never stops the others. */
export async function scanRepoFolder(dir: string, opts: RepoScanOptions = {}): Promise<{ findings: Finding[]; filesScanned: number }> {
  const { files, truncated, skippedLarge } = walkWithStats(dir);
  const findings: Finding[] = [];
  const guard = (name: string, run: () => Finding[]) => {
    try { findings.push(...run()); }
    catch (err) { findings.push(note(`scan.${name.toLowerCase()}-failed`, `The ${name.toLowerCase()} check could not finish`, `It stopped with: ${err instanceof Error ? err.message : String(err)}. The other checks still ran.`, "Scan again. If it keeps happening, report it with the repository layout.")); }
  };
  guard("Secrets", () => scanSecrets(files));
  guard("Code", () => scanCode(files));
  if (!opts.offline) {
    try { findings.push(...(await scanDependencies(dir, files, opts.fetcher))); }
    catch (err) { findings.push(note("scan.dependencies-failed", "The dependency check could not finish", String(err instanceof Error ? err.message : err), "Scan again later.")); }
  }
  if (truncated) findings.push(note("scan.truncated", "Very large project: part of it was not scanned", `To protect the server, a scan reads at most ${WALK_LIMITS.maxFiles.toLocaleString()} files and ${Math.round(WALK_LIMITS.maxTotalBytes / 1e6)} MB. This project is bigger, so some files were skipped.`, "Scan the main application folders separately, or remove generated and vendored files from the repository."));
  if (skippedLarge > 0) findings.push(note("scan.large-files-skipped", `${skippedLarge} very large file${skippedLarge === 1 ? " was" : "s were"} not read`, "Files over 2 MB (usually generated code, data or bundles) are skipped to keep scans fast.", "Keep secrets and source code out of large generated files."));
  return { findings, filesScanned: files.length };
}

/** Runs the source scanners over a folder and returns the findings. */
export async function runRepoScan(dir: string, opts: RepoScanOptions = {}): Promise<Finding[]> {
  return (await scanRepoFolder(dir, opts)).findings;
}

export interface RunOptions {
  /** Token for private GitHub repositories. */
  githubToken?: string;
}

export async function runScan(kind: AssetKind, target: string, opts: RunOptions = {}): Promise<ScanResult> {
  try {
    return await runScanInner(kind, target, opts);
  } catch (err) {
    const now = new Date().toISOString();
    return { tool: "Lucent Shield", version: VERSION, target, mode: kind === "web" ? "web" : "repo", startedAt: now, finishedAt: now, filesScanned: 0,
      findings: [note("scan.failed", "The scan could not finish", `It stopped with: ${err instanceof Error ? err.message : String(err)}`, "Scan again. If it keeps failing, check the target is reachable.")] };
  }
}

async function runScanInner(kind: AssetKind, target: string, opts: RunOptions): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  let findings: Finding[] = [];
  let filesScanned = 0;

  if (kind === "repo") {
    let dir = target;
    let cleanup = false;
    if (isGitUrl(target)) {
      try {
        dir = await cloneRepo(target, opts.githubToken);
        cleanup = true;
      } catch {
        findings = [{
          rule: "repo.clone-failed", severity: "info", category: "code", location: target,
          title: "Could not access the repository",
          detail: "Lucent Shield could not download this repository. Check the URL. Private repositories cannot be read yet, so make it public for the scan or scan a copy you can share.",
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
      ({ findings, filesScanned } = await scanRepoFolder(dir));
    } finally {
      if (cleanup) { try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
    }
  } else if (kind === "web") {
    findings = await scanWeb(target);
  } else {
    findings = await scanArtifact(target);
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
