// Shared types for Lucent Shield.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type Category = "secret" | "dependency" | "code" | "web";

export interface Finding {
  /** Stable short id for the rule that produced this, e.g. "secret.aws-key". */
  rule: string;
  severity: Severity;
  category: Category;
  title: string;
  /** Where it was found (file path, or a URL for web findings). */
  location?: string;
  line?: number;
  /** A short, already-redacted snippet of evidence. Never a full secret. */
  evidence?: string;
  /** One or two sentences on what the issue is and why it matters. */
  detail: string;
  /** Concrete steps to fix it. */
  remediation: string;
}

export interface ScanResult {
  tool: string;
  version: string;
  target: string;
  mode: "repo" | "web";
  startedAt: string;
  finishedAt: string;
  filesScanned: number;
  findings: Finding[];
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      a.rule.localeCompare(b.rule) ||
      (a.location ?? "").localeCompare(b.location ?? "") ||
      (a.line ?? 0) - (b.line ?? 0)
  );
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
