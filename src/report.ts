// Turns a scan result into a Security Assessment Report, in the structure
// auditors and clients expect: cover, executive summary, scope and
// authorization, methodology, findings summary, detailed findings with
// CWE / OWASP references and risk ratings, a remediation plan, limitations,
// and a reviewer sign-off. Three formats: a print-ready HTML document (save
// it as PDF from any browser), Markdown, and JSON for tooling.
//
// Lucent Shield finds and explains weaknesses; it never exploits them. So the
// report is titled "Security Assessment Report", not a penetration test, and
// it leaves a section for a human tester to add anything they confirmed by hand.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ScanResult, Finding, Severity } from "./types.ts";
import { SEVERITY_ORDER, sortFindings, countBySeverity } from "./types.ts";
import { classify, CATEGORY_LABEL } from "./catalog.ts";

export type AssessmentKind = "repo" | "web" | "artifact";

/** Facts about the engagement that do not live in the scan result itself. */
export interface ReportContext {
  /** A friendly name for what was assessed. */
  assetName?: string;
  kind?: AssessmentKind;
  /** Web targets: ownership of the domain was proven (file or DNS token). */
  verified?: boolean;
  /** The explicit authorization recorded for this scan. */
  authorization?: { at: string; ip?: string; reference?: string } | null;
  /** Who ran it, e.g. "Command line, run by the code owner". */
  runBy?: string;
  reportId?: string;
  generatedAt?: string;
  /** Opened in the browser (adds the Save as PDF button). */
  view?: boolean;
}

const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" };
const SEV_COLOR: Record<Severity, string> = { critical: "#a3151b", high: "#c2410c", medium: "#a16207", low: "#1d4ed8", info: "#526079" };
/** How quickly each severity should be fixed. */
const SEV_DEADLINE: Record<Severity, string> = {
  critical: "Immediately, within 24 hours",
  high: "Within 7 days",
  medium: "Within 30 days",
  low: "Within 90 days",
  info: "Review when convenient",
};
const SEV_SCORE: Record<Severity, number> = { critical: 9.5, high: 7.8, medium: 5.4, low: 2.8, info: 0 };
const KIND_LABEL: Record<AssessmentKind, string> = { repo: "White box (source code)", web: "Black box (live website)", artifact: "Forensic (file or artifact)" };

// ---------- the analysis every format shares ----------

export interface ReportFinding extends Finding {
  id: string;
  cwe?: string;
  cweName?: string;
  owasp?: string;
  impact: "Severe" | "Significant" | "Moderate" | "Minor" | "None";
  likelihood: "High" | "Medium" | "Low";
  score: number;
  deadline: string;
  categoryLabel: string;
}

export interface Report {
  id: string;
  title: string;
  generatedAt: string;
  target: string;
  assetName: string;
  kind: AssessmentKind;
  overall: { rating: "Critical" | "High" | "Medium" | "Low" | "Clean"; sentence: string };
  counts: Record<Severity, number>;
  findings: ReportFinding[];
  notes: Finding[];
  result: ScanResult;
  ctx: ReportContext;
}

/** Scan notes (truncation, a check that could not run) are limits of the scan, not findings. */
const isNote = (f: Finding) => f.rule.startsWith("scan.") || f.rule.startsWith("repo.");

function likelihoodOf(f: Finding): ReportFinding["likelihood"] {
  // Reachable from outside, or already in an attacker's hands once leaked.
  if (f.category === "web" || f.category === "secret") return "High";
  if (/traces back to request input/i.test(f.detail)) return "High";
  if (f.category === "dependency") return "Medium";
  if (f.severity === "low" || f.severity === "info") return "Low";
  return "Medium";
}

const IMPACT: Record<Severity, ReportFinding["impact"]> = { critical: "Severe", high: "Significant", medium: "Moderate", low: "Minor", info: "None" };

export function buildReport(result: ScanResult, ctx: ReportContext = {}): Report {
  const all = sortFindings(result.findings);
  const notes = all.filter(isNote);
  const findings: ReportFinding[] = all.filter((f) => !isNote(f)).map((f, i) => {
    const c = classify(f.rule);
    const likelihood = likelihoodOf(f);
    const bump = likelihood === "High" ? 0.4 : likelihood === "Low" ? -0.6 : 0;
    const score = f.severity === "info" ? 0 : Math.max(0.1, Math.min(10, Math.round((SEV_SCORE[f.severity] + bump) * 10) / 10));
    return {
      ...f, id: `LS-${String(i + 1).padStart(3, "0")}`,
      cwe: c?.cwe, cweName: c?.cweName, owasp: c?.owasp,
      impact: IMPACT[f.severity], likelihood, score,
      deadline: SEV_DEADLINE[f.severity],
      categoryLabel: CATEGORY_LABEL[f.category] ?? f.category,
    };
  });
  const counts = countBySeverity(findings);
  const kind: AssessmentKind = ctx.kind ?? (result.mode === "web" ? "web" : "repo");
  const generatedAt = ctx.generatedAt ?? new Date().toISOString();
  const day = result.finishedAt.slice(0, 10).replace(/-/g, "");
  const tail = Buffer.from(`${result.target}|${result.finishedAt}`).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(-6).toUpperCase();
  const id = ctx.reportId ?? `LSR-${day}-${tail}`;

  const rating: Report["overall"]["rating"] = counts.critical ? "Critical" : counts.high ? "High" : counts.medium ? "Medium" : counts.low ? "Low" : "Clean";
  const serious = counts.critical + counts.high;
  const sentence =
    rating === "Clean" ? "No security weaknesses were found by this assessment. Keep monitoring on, because new code and new vulnerabilities appear over time."
    : rating === "Critical" ? `The target is at serious risk. ${serious} critical or high issue${serious === 1 ? "" : "s"} could let an attacker reach data or take control, and should be fixed before anything else.`
    : rating === "High" ? `The target has ${counts.high} high-risk issue${counts.high === 1 ? "" : "s"} that should be fixed within a week. Nothing critical was found.`
    : rating === "Medium" ? "No critical or high issues were found. The medium issues weaken the target's defences and should be planned into the next month of work."
    : "Only low-risk issues were found. The target is in good shape; fix these as part of normal maintenance.";

  return {
    id, title: "Security Assessment Report", generatedAt, target: result.target,
    assetName: ctx.assetName ?? result.target, kind, overall: { rating, sentence },
    counts, findings, notes, result, ctx,
  };
}

function methodology(kind: AssessmentKind): { name: string; text: string }[] {
  if (kind === "web") return [
    { name: "Transport security", text: "HTTPS availability, redirect from HTTP, certificate validity and expiry, and HSTS." },
    { name: "Security headers", text: "Content Security Policy, clickjacking protection, MIME sniffing, referrer policy and cross-origin rules." },
    { name: "Cookies", text: "Secure, HttpOnly and SameSite flags on cookies the site sets." },
    { name: "Information disclosure", text: "Server and framework versions, error pages and directory listings." },
    { name: "Exposed files", text: "Files that should never be public, such as .env, .git, backups and config files." },
    { name: "Email authentication", text: "SPF and DMARC records that stop others sending mail as the domain." },
    { name: "Rules of engagement", text: "Every request was a read-only GET. No fuzzing, brute force, exploitation or changes were made." },
  ];
  if (kind === "artifact") return [
    { name: "Integrity", text: "A SHA-256 fingerprint of each file, so the evidence can be matched later." },
    { name: "Secrets", text: "Credentials, keys and tokens inside the artifact." },
    { name: "Indicators", text: "Known signs of malicious code or tampering." },
    { name: "Rules of engagement", text: "Files were read only. Nothing was executed or changed." },
  ];
  return [
    { name: "Secrets", text: "Keys, tokens, passwords and private keys committed to the code, across 23 providers plus generic patterns. Evidence is redacted." },
    { name: "Insecure code", text: "Over 80 rules for injection, unsafe deserialization, weak cryptography, disabled TLS checks, debug settings and risky infrastructure (Docker, Kubernetes, Terraform, CI workflows)." },
    { name: "Data flow", text: "In PHP, Python and JavaScript, request input is followed through variables to dangerous sinks. Input that is sanitised or validated first is treated as safe." },
    { name: "Dependencies", text: "Lockfiles for 8 ecosystems checked against the OSV database of known vulnerabilities, with the version that fixes each one." },
    { name: "Rules of engagement", text: "Source code was read only. Nothing was executed, changed or sent anywhere except dependency names and versions to OSV." },
  ];
}

const fmtDate = (iso: string) => {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("en-GB", { day: "numeric", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
};

function authorizationText(r: Report): string {
  const a = r.ctx.authorization;
  if (a) return `Explicit authorization was given for this scan on ${fmtDate(a.at)}${a.ip ? ` from ${a.ip}` : ""}${a.reference ? `, legal reference ${a.reference}` : ""}. The record is kept in Lucent Shield's authorization audit trail.`;
  if (r.ctx.runBy) return `${r.ctx.runBy}.`;
  return "Run by the operator, who confirmed they own the target or are authorised to test it.";
}

// ---------- JSON ----------

export function toJson(result: ScanResult, ctx: ReportContext = {}): string {
  const r = buildReport(result, ctx);
  return JSON.stringify({
    report: { id: r.id, title: r.title, generatedAt: r.generatedAt, assetName: r.assetName, kind: r.kind, overallRisk: r.overall.rating, summary: r.overall.sentence, counts: r.counts, authorization: ctx.authorization ?? null, verified: ctx.verified ?? null },
    ...result,
    findings: r.findings,
    scanNotes: r.notes,
  }, null, 2);
}

// ---------- Markdown ----------

export function toMarkdown(result: ScanResult, ctx: ReportContext = {}): string {
  const r = buildReport(result, ctx);
  const out: string[] = [];
  const p = (s = "") => out.push(s);
  p(`# ${r.title}`);
  p();
  p(`**${r.assetName}**  `);
  p(`Report ${r.id} · Confidential · Lucent Shield v${result.version} by Bash Lucent`);
  p();
  p("## 1. Executive summary");
  p();
  p(`**Overall risk: ${r.overall.rating}.** ${r.overall.sentence}`);
  p();
  p("| Critical | High | Medium | Low | Informational |");
  p("|---|---|---|---|---|");
  p(`| ${r.counts.critical} | ${r.counts.high} | ${r.counts.medium} | ${r.counts.low} | ${r.counts.info} |`);
  p();
  const top = r.findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);
  if (top.length) {
    p("Most urgent:");
    p();
    for (const f of top) p(`- **${f.id}** ${f.title} (${SEV_LABEL[f.severity]})`);
    p();
  }
  p("## 2. Scope and authorization");
  p();
  p(`- **Target:** \`${r.target}\``);
  p(`- **Assessment type:** ${KIND_LABEL[r.kind]}`);
  p(`- **Scan window:** ${fmtDate(result.startedAt)} to ${fmtDate(result.finishedAt)}`);
  if (r.kind !== "web" && result.filesScanned) p(`- **Files examined:** ${result.filesScanned.toLocaleString()}`);
  if (r.kind === "web") p(`- **Domain ownership:** ${ctx.verified ? "Proven before testing (verification token published by the owner)" : "Not recorded"}`);
  p(`- **Authorization:** ${authorizationText(r)}`);
  p();
  p("## 3. Methodology");
  p();
  for (const m of methodology(r.kind)) p(`- **${m.name}:** ${m.text}`);
  p();
  p("Severity follows the impact if the issue were exploited. Likelihood is raised for issues reachable from the internet, leaked secrets, and code where request input reaches the weakness directly. The risk score (0 to 10) combines the two.");
  p();
  p("## 4. Findings summary");
  p();
  if (!r.findings.length) p("No findings.");
  else {
    p("| ID | Finding | Severity | Score | CWE | OWASP Top 10 | Fix by |");
    p("|---|---|---|---|---|---|---|");
    for (const f of r.findings) p(`| ${f.id} | ${f.title.replace(/\|/g, "/")} | ${SEV_LABEL[f.severity]} | ${f.score.toFixed(1)} | ${f.cwe ?? "-"} | ${f.owasp ?? "-"} | ${f.deadline} |`);
  }
  p();
  p("## 5. Detailed findings");
  p();
  if (!r.findings.length) p("No issues were found by this assessment. A clean automated assessment is good news, not a guarantee.");
  for (const f of r.findings) {
    p(`### ${f.id}: ${f.title}`);
    p();
    p(`- **Severity:** ${SEV_LABEL[f.severity]} · **Impact:** ${f.impact} · **Likelihood:** ${f.likelihood} · **Risk score:** ${f.score.toFixed(1)}`);
    p(`- **Category:** ${f.categoryLabel}`);
    if (f.cwe) p(`- **Reference:** ${f.cwe} ${f.cweName} · OWASP ${f.owasp}`);
    if (f.location) p(`- **Location:** \`${f.location}\`${f.line ? ` line ${f.line}` : ""}`);
    if (f.evidence) p(`- **Evidence:** \`${f.evidence.replace(/`/g, "'")}\``);
    p(`- **Description:** ${f.detail}`);
    p(`- **Recommendation:** ${f.remediation}`);
    p(`- **Fix by:** ${f.deadline}`);
    p(`- **Rule:** \`${f.rule}\``);
    p();
  }
  p("## 6. Remediation plan");
  p();
  for (const s of SEVERITY_ORDER) {
    const list = r.findings.filter((f) => f.severity === s);
    if (!list.length) continue;
    p(`**${SEV_DEADLINE[s]}** (${SEV_LABEL[s].toLowerCase()}): ${list.map((f) => f.id).join(", ")}`);
    p();
  }
  if (!r.findings.length) { p("Nothing to fix. Keep continuous monitoring on."); p(); }
  p("After fixing, scan again to confirm each issue is closed.");
  p();
  p("## 7. Limitations");
  p();
  p("This is an automated security assessment. Lucent Shield identifies weaknesses and explains them; it does not exploit them, so findings are strong leads to confirm rather than proof of exploitation. It is not a substitute for a manual penetration test, and a clean result is not a guarantee of security. Results reflect the target at the time of the scan.");
  for (const n of r.notes) p(`- **Scan note:** ${n.title}. ${n.detail}`);
  p();
  p("## 8. Reviewer notes and sign-off");
  p();
  p("_For a security professional reviewing this report: add any issues confirmed by hand, then sign._");
  p();
  p("| Reviewed by | Role | Date | Signature |");
  p("|---|---|---|---|");
  p("|  |  |  |  |");
  p();
  p("---");
  p(`Generated ${fmtDate(r.generatedAt)} by Lucent Shield v${result.version}, a product of Bash Lucent. Confidential: share only with people responsible for this system.`);
  return out.join("\n");
}

// ---------- HTML (print-ready; save as PDF from the browser) ----------

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

let LOGO: string | null = null;
function logo(): string {
  if (LOGO !== null) return LOGO;
  try { LOGO = "data:image/png;base64," + readFileSync(fileURLToPath(new URL("./assets/report-logo.png", import.meta.url))).toString("base64"); }
  catch { LOGO = ""; }
  return LOGO;
}

const RATING_COLOR: Record<Report["overall"]["rating"], string> = { Critical: SEV_COLOR.critical, High: SEV_COLOR.high, Medium: SEV_COLOR.medium, Low: SEV_COLOR.low, Clean: "#0f8a5f" };

export function toHtml(result: ScanResult, ctx: ReportContext = {}): string {
  const r = buildReport(result, ctx);
  const sevPill = (s: Severity) => `<span class="pill" style="--c:${SEV_COLOR[s]}">${SEV_LABEL[s]}</span>`;
  const total = r.findings.length;

  const bars = SEVERITY_ORDER.map((s) => {
    const n = r.counts[s];
    const w = total ? Math.max(n ? 2 : 0, Math.round((n / total) * 100)) : 0;
    return `<div class="bar"><span class="bl">${SEV_LABEL[s]}</span><span class="bt"><i style="width:${w}%;background:${SEV_COLOR[s]}"></i></span><b>${n}</b></div>`;
  }).join("");

  const top = r.findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 5);

  const rows = r.findings.map((f) => `<tr>
      <td class="mono">${f.id}</td><td>${esc(f.title)}</td><td>${sevPill(f.severity)}</td>
      <td class="num">${f.score.toFixed(1)}</td><td class="mono">${esc(f.cwe ?? "")}</td><td>${esc(f.owasp?.replace(/^A\d\d /, (m) => m) ?? "")}</td></tr>`).join("");

  const details = r.findings.map((f) => `<section class="finding" style="--c:${SEV_COLOR[f.severity]}">
      <header><span class="fid">${f.id}</span><h3>${esc(f.title)}</h3>${sevPill(f.severity)}</header>
      <dl class="facts">
        <div><dt>Risk score</dt><dd><b>${f.score.toFixed(1)}</b> / 10</dd></div>
        <div><dt>Impact</dt><dd>${f.impact}</dd></div>
        <div><dt>Likelihood</dt><dd>${f.likelihood}</dd></div>
        <div><dt>Fix by</dt><dd>${f.deadline}</dd></div>
      </dl>
      <table class="kv">
        <tr><th>Category</th><td>${esc(f.categoryLabel)}</td></tr>
        ${f.cwe ? `<tr><th>Reference</th><td><span class="mono">${esc(f.cwe)}</span> ${esc(f.cweName)}<br>OWASP Top 10: ${esc(f.owasp)}</td></tr>` : ""}
        ${f.location ? `<tr><th>Location</th><td class="mono">${esc(f.location)}${f.line ? `, line ${f.line}` : ""}</td></tr>` : ""}
        <tr><th>Rule</th><td class="mono">${esc(f.rule)}</td></tr>
      </table>
      ${f.evidence ? `<div class="lbl">Evidence</div><pre>${esc(f.evidence)}</pre>` : ""}
      <div class="lbl">Description</div><p>${esc(f.detail)}</p>
      <div class="lbl">Recommendation</div><p class="rec">${esc(f.remediation)}</p>
    </section>`).join("");

  const plan = SEVERITY_ORDER.map((s) => {
    const list = r.findings.filter((f) => f.severity === s);
    if (!list.length) return "";
    return `<tr><td>${sevPill(s)}</td><td><b>${SEV_DEADLINE[s]}</b></td><td>${list.length}</td><td class="mono ids">${list.map((f) => f.id).join(", ")}</td></tr>`;
  }).join("");

  const pdfBtn = ctx.view ? `<div class="toolbar"><button id="savePdf" type="button">Save as PDF</button><span>Choose "Save as PDF" as the printer.</span></div><script src="/report.js"></script>` : "";

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(r.id)} Security Assessment Report: ${esc(r.assetName)}</title>
<style>
  @page { size: A4; margin: 18mm 16mm 20mm; @bottom-left { content: "${esc(r.id)} · Confidential"; font: 8pt system-ui, sans-serif; color: #6b7690; } @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt system-ui, sans-serif; color: #6b7690; } }
  @page :first { margin: 0; @bottom-left { content: none; } @bottom-right { content: none; } }
  :root { --ink: #101a33; --muted: #5a6784; --line: #dfe4ee; --soft: #f4f6fb; --navy: #0b1730; --blue: #1d4ed8; --green: #0f8a5f; }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0; background: #e9edf4; color: var(--ink); font: 10.5pt/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .doc { max-width: 210mm; margin: 0 auto; background: #fff; }
  .page { padding: 16mm 16mm 12mm; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 9pt; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  h2 { font-size: 15pt; margin: 0 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--navy); break-after: avoid; }
  h2 small { color: var(--muted); font-weight: 500; font-size: 10pt; margin-right: 8px; }
  .sec { margin-bottom: 26px; }
  p { margin: 0 0 8px; }

  /* cover */
  .cover { background: var(--navy); color: #fff; min-height: 297mm; padding: 22mm 18mm; display: flex; flex-direction: column; break-after: page; position: relative; overflow: hidden; }
  .cover::after { content: ""; position: absolute; right: -40mm; top: 70mm; width: 150mm; height: 150mm; border-radius: 50%; border: 1px solid rgba(255,255,255,.08); box-shadow: 0 0 0 18mm rgba(255,255,255,.02), 0 0 0 36mm rgba(255,255,255,.015); }
  .brandrow { display: flex; align-items: center; gap: 12px; }
  .brandrow img { width: 46px; height: 46px; border-radius: 10px; }
  .brandrow b { display: block; letter-spacing: .5px; font-size: 13pt; }
  .brandrow span { color: #9fb2d8; font-size: 9pt; }
  .cover h1 { font-size: 34pt; line-height: 1.1; margin: 62mm 0 6mm; font-weight: 750; max-width: 150mm; }
  .cover .asset { font-size: 15pt; color: #cfe0ff; margin-bottom: 2mm; }
  .cover .tgt { font-family: ui-monospace, Menlo, monospace; font-size: 9.5pt; color: #8fa3c9; word-break: break-all; }
  .cover .risk { margin-top: 12mm; display: inline-flex; align-items: center; gap: 10px; background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.14); border-radius: 10px; padding: 10px 16px; align-self: flex-start; }
  .cover .risk i { width: 12px; height: 12px; border-radius: 50%; background: var(--rc); box-shadow: 0 0 0 4px color-mix(in srgb, var(--rc) 30%, transparent); }
  .cover .meta { margin-top: auto; display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px 24px; font-size: 9.5pt; border-top: 1px solid rgba(255,255,255,.14); padding-top: 8mm; position: relative; z-index: 1; }
  .cover .meta dt { color: #8fa3c9; font-size: 8pt; }
  .cover .meta dd { margin: 0; }
  .conf { margin-top: 6mm; color: #8fa3c9; font-size: 8.5pt; position: relative; z-index: 1; }

  /* summary */
  .verdict { display: grid; grid-template-columns: 170px 1fr; gap: 18px; align-items: stretch; margin-bottom: 14px; }
  .rating { border-radius: 10px; background: var(--rc); color: #fff; padding: 14px; display: flex; flex-direction: column; justify-content: center; }
  .rating small { opacity: .8; font-size: 8.5pt; }
  .rating b { font-size: 22pt; line-height: 1.1; }
  .bars { display: grid; gap: 6px; margin: 4px 0 14px; }
  .bar { display: grid; grid-template-columns: 96px 1fr 30px; align-items: center; gap: 10px; font-size: 9.5pt; }
  .bar .bt { height: 9px; background: var(--soft); border-radius: 5px; overflow: hidden; }
  .bar .bt i { display: block; height: 100%; border-radius: 5px; }
  .bar b { text-align: right; }
  .urgent { background: var(--soft); border-radius: 8px; padding: 10px 14px; }
  .urgent ul { margin: 4px 0 0; padding-left: 18px; }

  table { width: 100%; border-collapse: collapse; font-size: 9.5pt; }
  .grid th { text-align: left; font-size: 8.5pt; color: var(--muted); font-weight: 600; border-bottom: 1.5px solid var(--ink); padding: 6px 8px 6px 0; }
  .grid td { border-bottom: 1px solid var(--line); padding: 7px 8px 7px 0; vertical-align: top; }
  .grid td.mono { white-space: nowrap; }
  .grid tr { break-inside: avoid; }
  .scope th { width: 32%; text-align: left; color: var(--muted); font-weight: 600; padding: 7px 10px 7px 0; vertical-align: top; border-bottom: 1px solid var(--line); }
  .scope td { padding: 7px 0; border-bottom: 1px solid var(--line); }
  .method { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .method div { border: 1px solid var(--line); border-radius: 8px; padding: 9px 12px; break-inside: avoid; }
  .method b { display: block; font-size: 9.5pt; }
  .method span { color: var(--muted); font-size: 9pt; }
  .note { color: var(--muted); font-size: 9pt; margin-top: 10px; }

  .pill { display: inline-block; font-size: 8pt; font-weight: 700; color: var(--c); background: color-mix(in srgb, var(--c) 11%, #fff); border: 1px solid color-mix(in srgb, var(--c) 35%, #fff); padding: 1px 8px; border-radius: 999px; white-space: nowrap; }

  .finding { border: 1px solid var(--line); border-left: 4px solid var(--c); border-radius: 8px; padding: 12px 14px; margin-bottom: 12px; }
  .finding header, .facts, .kv tr, pre, .finding p { break-inside: avoid; }
  .finding header { break-after: avoid; } .lbl { break-after: avoid; }
  .finding header { display: flex; align-items: baseline; gap: 10px; margin-bottom: 8px; }
  .finding h3 { font-size: 11.5pt; margin: 0; flex: 1; }
  .fid { font-family: ui-monospace, Menlo, monospace; font-size: 9pt; color: var(--muted); }
  .facts { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; margin: 0 0 10px; background: var(--soft); border-radius: 6px; }
  .facts div { padding: 6px 10px; } .facts div + div { border-left: 1px solid var(--line); }
  .facts dt { font-size: 7.5pt; color: var(--muted); } .facts dd { margin: 0; font-size: 9.5pt; }
  .kv th { width: 22%; text-align: left; color: var(--muted); font-weight: 600; padding: 3px 10px 3px 0; vertical-align: top; }
  .kv td { padding: 3px 0; word-break: break-word; }
  .lbl { font-size: 8pt; font-weight: 700; color: var(--muted); margin: 9px 0 3px; }
  pre { background: #0f172a; color: #dbe4ff; border-radius: 6px; padding: 8px 10px; font: 8.5pt/1.45 ui-monospace, Menlo, monospace; white-space: pre-wrap; word-break: break-all; margin: 0; }
  .rec { border-left: 3px solid var(--green); padding-left: 10px; }
  .ids { word-break: break-word; }
  .clean { border: 1px solid #bfe7d6; background: #effaf5; color: #0b5e42; border-radius: 8px; padding: 14px; }

  .sign { border: 1.5px dashed #b7c0d3; border-radius: 10px; padding: 14px; }
  .sign .lines { min-height: 90px; background: repeating-linear-gradient(to bottom, transparent 0 27px, var(--line) 27px 28px); margin: 8px 0 14px; }
  .sign .who { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
  .sign .who div { border-top: 1px solid var(--ink); padding-top: 4px; font-size: 8.5pt; color: var(--muted); margin-top: 26px; }

  footer.end { border-top: 1px solid var(--line); margin-top: 20px; padding-top: 10px; color: var(--muted); font-size: 8.5pt; }
  .toolbar { position: sticky; top: 0; z-index: 5; background: var(--navy); color: #cbd6ef; display: flex; gap: 14px; align-items: center; padding: 10px 16px; font-size: 13px; }
  .toolbar button { background: #2fe6a6; color: #04241a; border: 0; border-radius: 8px; padding: 8px 16px; font-weight: 700; cursor: pointer; }
  .toolbar button:focus-visible { outline: 3px solid #fff; outline-offset: 2px; }
  @media print { body { background: #fff; } .doc { max-width: none; } .toolbar { display: none; } .page { padding: 0; } .sec.break { break-before: page; } }
  @media (max-width: 640px) { .page { padding: 18px 14px; } .cover { min-height: auto; padding: 28px 18px; } .cover h1 { margin-top: 60px; font-size: 26pt; } .verdict, .method { grid-template-columns: 1fr; } .facts { grid-template-columns: 1fr 1fr; } .facts div + div { border-left: 0; } .grid { display: block; overflow-x: auto; } }
</style></head>
<body>${pdfBtn}<div class="doc">

<div class="cover" style="--rc:${RATING_COLOR[r.overall.rating]}">
  <div class="brandrow">${logo() ? `<img src="${logo()}" alt="">` : ""}<div><b>LUCENT SHIELD</b><span>by Bash Lucent</span></div></div>
  <h1>Security Assessment Report</h1>
  <div class="asset">${esc(r.assetName)}</div>
  ${r.assetName !== r.target ? `<div class="tgt">${esc(r.target)}</div>` : ""}
  <div class="risk"><i></i>Overall risk: <b>${r.overall.rating}</b></div>
  <dl class="meta">
    <div><dt>Report ID</dt><dd>${esc(r.id)}</dd></div>
    <div><dt>Assessment type</dt><dd>${KIND_LABEL[r.kind]}</dd></div>
    <div><dt>Assessment date</dt><dd>${fmtDate(result.finishedAt)}</dd></div>
    <div><dt>Report generated</dt><dd>${fmtDate(r.generatedAt)}</dd></div>
    <div><dt>Prepared by</dt><dd>Lucent Shield v${esc(result.version)}, Bash Lucent</dd></div>
    <div><dt>Findings</dt><dd>${total} (${r.counts.critical} critical, ${r.counts.high} high)</dd></div>
  </dl>
  <div class="conf">Confidential. This report describes security weaknesses. Share it only with people responsible for this system.</div>
</div>

<div class="page">

<div class="sec">
  <h2><small>1</small>Executive summary</h2>
  <div class="verdict" style="--rc:${RATING_COLOR[r.overall.rating]}">
    <div class="rating"><small>Overall risk</small><b>${r.overall.rating}</b></div>
    <div><p>${esc(r.overall.sentence)}</p>
    <p>This assessment examined <b>${esc(r.assetName)}</b> using ${KIND_LABEL[r.kind].toLowerCase()} checks and found <b>${total}</b> issue${total === 1 ? "" : "s"}. Each one is listed below with where it is, why it matters, and how to fix it.</p></div>
  </div>
  <div class="bars">${bars}</div>
  ${top.length ? `<div class="urgent"><b>Fix these first</b><ul>${top.map((f) => `<li><span class="mono">${f.id}</span> ${esc(f.title)} (${SEV_LABEL[f.severity].toLowerCase()})</li>`).join("")}</ul></div>` : ""}
</div>

<div class="sec">
  <h2><small>2</small>Scope and authorization</h2>
  <table class="scope">
    <tr><th>Target</th><td class="mono">${esc(r.target)}</td></tr>
    <tr><th>Assessment type</th><td>${KIND_LABEL[r.kind]}</td></tr>
    <tr><th>Scan window</th><td>${fmtDate(result.startedAt)} to ${fmtDate(result.finishedAt)}</td></tr>
    ${r.kind !== "web" && result.filesScanned ? `<tr><th>Files examined</th><td>${result.filesScanned.toLocaleString()}</td></tr>` : ""}
    ${r.kind === "web" ? `<tr><th>Domain ownership</th><td>${ctx.verified ? "Proven before testing: the owner published a verification token on the domain." : "Not recorded."}</td></tr>` : ""}
    <tr><th>Authorization</th><td>${esc(authorizationText(r))}</td></tr>
    <tr><th>Out of scope</th><td>Exploitation, denial of service, social engineering, and any system other than the target above.</td></tr>
  </table>
</div>

<div class="sec">
  <h2><small>3</small>Methodology</h2>
  <div class="method">${methodology(r.kind).map((m) => `<div><b>${esc(m.name)}</b><span>${esc(m.text)}</span></div>`).join("")}</div>
  <p class="note">Severity reflects the damage if an issue were exploited. Likelihood is raised for issues reachable from the internet, leaked secrets, and code where request input reaches the weakness directly. The risk score from 0 to 10 combines the two. Each finding is mapped to its CWE weakness and OWASP Top 10 (2021) category.</p>
</div>

<div class="sec">
  <h2><small>4</small>Findings summary</h2>
  ${total ? `<table class="grid"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th class="num">Score</th><th>CWE</th><th>OWASP Top 10</th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div class="clean">No issues were found by this assessment. A clean automated assessment is good news, not a guarantee, so keep continuous monitoring on.</div>`}
</div>

${total ? `<div class="sec"><h2><small>5</small>Detailed findings</h2>${details}</div>` : ""}

<div class="sec">
  <h2><small>${total ? 6 : 5}</small>Remediation plan</h2>
  ${total ? `<table class="grid"><thead><tr><th>Severity</th><th>Fix by</th><th>Count</th><th>Findings</th></tr></thead><tbody>${plan}</tbody></table>
  <p class="note">After fixing, scan again in Lucent Shield to confirm each issue is closed. Turn on continuous monitoring so new problems are caught as they appear.</p>`
    : `<p>Nothing to fix. Keep continuous monitoring on so new problems are caught as they appear.</p>`}
</div>

<div class="sec">
  <h2><small>${total ? 7 : 6}</small>Limitations</h2>
  <p>This is an automated security assessment. Lucent Shield identifies weaknesses and explains them; it does not exploit them, so findings are strong leads to confirm rather than proof of exploitation. It is not a substitute for a manual penetration test, and a clean result is not a guarantee of security. Results describe the target at the time of the scan.</p>
  ${r.notes.map((n) => `<p class="note"><b>Scan note:</b> ${esc(n.title)}. ${esc(n.detail)}</p>`).join("")}
</div>

<div class="sec" style="break-inside: avoid">
  <h2><small>${total ? 8 : 7}</small>Reviewer notes and sign-off</h2>
  <div class="sign">
    <p class="note" style="margin:0">For a security professional reviewing this report: record any issues you confirmed or tested by hand, then sign.</p>
    <div class="lines"></div>
    <div class="who"><div>Reviewed by</div><div>Role</div><div>Date</div><div>Signature</div></div>
  </div>
</div>

<footer class="end">Report ${esc(r.id)}, generated ${fmtDate(r.generatedAt)} by Lucent Shield v${esc(result.version)}, a product of Bash Lucent. Scan only systems you own or are authorised to test.</footer>
</div></div></body></html>`;
}
