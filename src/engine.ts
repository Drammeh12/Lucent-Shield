// The engine: runs the right scanners for an asset and returns one result,
// plus the shield state the dashboard shows.

import { walk } from "./util/walk.ts";
import { scanSecrets } from "./scanners/secrets.ts";
import { scanCode } from "./scanners/code.ts";
import { scanDependencies } from "./scanners/dependencies.ts";
import { scanWeb } from "./scanners/web.ts";
import { scanArtifact } from "./scanners/forensics.ts";
import { countBySeverity, type Finding, type ScanResult } from "./types.ts";

export const VERSION = "0.4.0";

export type AssetKind = "repo" | "web" | "artifact";
export type Shield = "secure" | "at_risk" | "exposed" | "scanning" | "new";

/** Green when clean, amber on medium/low, red (exposed) on critical/high. */
export function shieldFor(findings: Finding[]): Shield {
  const c = countBySeverity(findings);
  if (c.critical > 0 || c.high > 0) return "exposed";
  if (c.medium > 0 || c.low > 0) return "at_risk";
  return "secure";
}

async function runRepo(target: string): Promise<Finding[]> {
  const files = walk(target);
  return [...scanSecrets(files), ...scanCode(files), ...(await scanDependencies(target))];
}

export async function runScan(kind: AssetKind, target: string): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  let findings: Finding[] = [];
  let filesScanned = 0;

  if (kind === "repo") {
    findings = await runRepo(target);
    filesScanned = walk(target).length;
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
