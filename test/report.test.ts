// The Security Assessment Report: structure, ratings, references, and safety.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReport, toHtml, toMarkdown, toJson } from "../src/report.ts";
import type { Finding, ScanResult } from "../src/types.ts";

const f = (rule: string, severity: Finding["severity"], extra: Partial<Finding> = {}): Finding =>
  ({ rule, severity, category: "code", title: rule, detail: "d", remediation: "r", ...extra });

const result = (findings: Finding[]): ScanResult => ({
  tool: "Lucent Shield", version: "0.9.0", target: "https://shop.example", mode: "web",
  startedAt: "2026-10-28T10:00:00.000Z", finishedAt: "2026-10-28T10:01:00.000Z", filesScanned: 0, findings,
});

test("findings get IDs, CWE and OWASP references, a score and a deadline", () => {
  const r = buildReport(result([f("web.header.csp", "medium", { category: "web" }), f("code.js.sql-injection", "critical"), f("code.js.nosql-injection", "high")]));
  assert.deepEqual(r.findings.map((x) => x.id), ["LS-001", "LS-002", "LS-003"]);
  assert.equal(r.findings[0].rule, "code.js.sql-injection", "most severe first");
  assert.equal(r.findings[0].cwe, "CWE-89");
  assert.equal(r.findings[1].cwe, "CWE-943", "NoSQL is not mistaken for SQL injection");
  assert.equal(r.findings[2].likelihood, "High", "internet-facing issues are more likely");
  assert.equal(r.findings[0].deadline, "Immediately, within 24 hours");
  assert.equal(r.overall.rating, "Critical");
});

test("scan notes are limitations, not findings, and a clean scan is rated Clean", () => {
  const r = buildReport(result([f("scan.truncated", "info")]));
  assert.equal(r.findings.length, 0);
  assert.equal(r.notes.length, 1);
  assert.equal(r.overall.rating, "Clean");
});

test("the report has every standard section and records the authorization", () => {
  const ctx = { assetName: "Shop", kind: "web" as const, verified: true, authorization: { at: "2026-10-28T09:59:00.000Z", ip: "203.0.113.9" } };
  const html = toHtml(result([f("web.header.csp", "medium", { category: "web" })]), ctx);
  for (const s of ["Security Assessment Report", "Executive summary", "Scope and authorization", "Methodology", "Findings summary", "Detailed findings", "Remediation plan", "Limitations", "Reviewer notes and sign-off"]) {
    assert.ok(html.includes(s), s);
  }
  assert.ok(html.includes("203.0.113.9"));
  assert.ok(html.includes("Proven before testing"));
  assert.ok(!/penetration test report/i.test(html), "never claims to be a penetration test");
  const md = toMarkdown(result([]), ctx);
  assert.ok(md.includes("## 8. Reviewer notes and sign-off"));
  const json = JSON.parse(toJson(result([f("code.js.eval", "high")]), ctx));
  assert.equal(json.report.overallRisk, "High");
  assert.equal(json.findings[0].id, "LS-001");
});

test("finding text cannot inject markup into the report", () => {
  const html = toHtml(result([f("code.js.xss", "high", { title: "<script>alert(1)</script>", evidence: "<img src=x onerror=alert(1)>" })]));
  assert.ok(!html.includes("<script>alert(1)</script>"));
  assert.ok(!html.includes("<img src=x"));
  assert.ok(!html.includes('src="/report.js"'), "no script unless opened in the browser view");
});
