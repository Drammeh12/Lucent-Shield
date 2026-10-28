// Benchmark: plants known vulnerabilities in a temp project, runs Lucent
// Shield's source scanners over it, and reports what was caught, what was
// missed, and any false alarms on the safe decoy files.
//
//   npx tsx test/bench.ts

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFixture } from "./fixture.ts";
import { runRepoScan } from "../src/engine.ts";

const dir = mkdtempSync(join(tmpdir(), "lucent-bench-"));
try {
  const { expected, decoys } = buildFixture(dir);
  const findings = await runRepoScan(dir, { offline: true });

  const hits = (e: (typeof expected)[number]) =>
    findings.filter((f) => f.location === e.file && (f.line === undefined || (f.line >= e.start && f.line <= e.end)));

  let lineCaught = 0, exact = 0;
  const missed: string[] = [];
  for (const e of expected) {
    const h = hits(e);
    if (h.length) lineCaught++;
    if (h.some((f) => f.rule === e.rule)) exact++;
    else missed.push(`${e.rule.padEnd(34)} ${e.file}:${e.start}${h.length ? `   (got: ${h.map((f) => f.rule).join(", ")})` : ""}`);
  }
  const falseAlarms = findings.filter((f) => decoys.some((d) => f.location === d));

  console.log(`Planted issues:        ${expected.length}`);
  console.log(`Caught (any finding):  ${lineCaught}  (${Math.round((lineCaught / expected.length) * 100)}%)`);
  console.log(`Caught (exact rule):   ${exact}  (${Math.round((exact / expected.length) * 100)}%)`);
  console.log(`False alarms (decoys): ${falseAlarms.length}`);
  if (missed.length) console.log(`\nMissed:\n  ${missed.join("\n  ")}`);
  if (falseAlarms.length) console.log(`\nFalse alarms:\n  ${falseAlarms.map((f) => `${f.rule} ${f.location}:${f.line ?? ""}`).join("\n  ")}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
