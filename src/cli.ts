#!/usr/bin/env -S npx tsx
// Lucent Shield — defensive application-security scanner (Bash Lucent).
//
// Usage:
//   npm run scan -- <path-to-your-repo> [options]
//
// Options:
//   --format json|md|html   output format (default: md to the terminal)
//   --out <file>            write the report to a file instead of stdout
//   --min <severity>        only report this severity and above
//                           (critical|high|medium|low|info)
//
// It scans code you own: secrets, vulnerable dependencies, and insecure
// patterns. It never changes your files and never sends your code anywhere
// (only dependency names/versions go to the OSV vulnerability database).

import { writeFileSync, existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { walk } from "./util/walk.ts";
import { scanSecrets } from "./scanners/secrets.ts";
import { scanCode } from "./scanners/code.ts";
import { scanDependencies } from "./scanners/dependencies.ts";
import { toJson, toMarkdown, toHtml } from "./report.ts";
import { SEVERITY_RANK, SEVERITY_ORDER, countBySeverity, type ScanResult, type Severity } from "./types.ts";

const VERSION = "0.1.0";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "help" || command === "--help") {
    console.log(
      `Lucent Shield v${VERSION} — defensive security scanner by Bash Lucent\n\n` +
        `  npm run scan -- <path> [--format json|md|html] [--out file] [--min severity]\n\n` +
        `Scans a repository you own for secrets, vulnerable dependencies and insecure code.\n` +
        `Only scan systems you own or are authorised to test.`
    );
    return;
  }

  // Default command is a repo scan; the path can be the first arg.
  const target = resolve(command === "scan" ? args[1] ?? "." : command);
  if (!existsSync(target) || !statSync(target).isDirectory()) {
    console.error(`Not a folder: ${target}`);
    process.exit(2);
  }

  const format = (arg("--format") ?? "md") as "json" | "md" | "html";
  const outFile = arg("--out");
  const min = (arg("--min") ?? "info") as Severity;
  const minRank = SEVERITY_RANK[min] ?? SEVERITY_RANK.info;

  const startedAt = new Date().toISOString();
  console.error(`Lucent Shield: scanning ${target} …`);

  const files = walk(target);
  console.error(`  reading ${files.length} files`);

  const findings = [
    ...scanSecrets(files),
    ...scanCode(files),
    ...(await scanDependencies(target)),
  ].filter((f) => SEVERITY_RANK[f.severity] <= minRank);

  const result: ScanResult = {
    tool: "Lucent Shield",
    version: VERSION,
    target,
    mode: "repo",
    startedAt,
    finishedAt: new Date().toISOString(),
    filesScanned: files.length,
    findings,
  };

  const output = format === "json" ? toJson(result) : format === "html" ? toHtml(result) : toMarkdown(result);

  if (outFile) {
    writeFileSync(outFile, output);
    console.error(`  report written to ${outFile}`);
  } else {
    process.stdout.write(output + "\n");
  }

  const counts = countBySeverity(findings);
  const summary = SEVERITY_ORDER.map((s) => `${counts[s]} ${s}`).join(" · ");
  console.error(`\nDone: ${summary}`);

  // Exit non-zero when something serious is found, so CI can fail the build.
  if (counts.critical > 0 || counts.high > 0) process.exit(1);
}

main().catch((err) => {
  console.error("Lucent Shield failed:", err instanceof Error ? err.message : err);
  process.exit(2);
});
