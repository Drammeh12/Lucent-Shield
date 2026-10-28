// Turns a scan result into a report: JSON (for tooling), Markdown (for a
// PR or an email), or a styled HTML page (to read or share).

import type { ScanResult, Finding, Severity } from "./types.ts";
import { SEVERITY_ORDER, sortFindings, countBySeverity } from "./types.ts";

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};
const SEV_COLOR: Record<Severity, string> = {
  critical: "#b91c1c", high: "#c2410c", medium: "#b45309", low: "#2563eb", info: "#475569",
};

export function toJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function toMarkdown(result: ScanResult): string {
  const findings = sortFindings(result.findings);
  const counts = countBySeverity(findings);
  const out: string[] = [];
  out.push(`# Lucent Shield report`);
  out.push("");
  out.push(`**Target:** ${result.target}  `);
  out.push(`**Scanned:** ${result.finishedAt}  `);
  out.push(`**Files scanned:** ${result.filesScanned}`);
  out.push("");
  out.push(
    "**Findings:** " +
      SEVERITY_ORDER.map((s) => `${counts[s]} ${SEV_LABEL[s].toLowerCase()}`).join(" · ")
  );
  out.push("");
  if (findings.length === 0) {
    out.push("No issues found by this scan. (A clean automated scan is good news, not a guarantee.)");
    return out.join("\n");
  }
  for (const f of findings) {
    out.push(`## [${SEV_LABEL[f.severity]}] ${f.title}`);
    out.push("");
    if (f.location) out.push(`- **Where:** \`${f.location}\`${f.line ? ` line ${f.line}` : ""}`);
    out.push(`- **Rule:** \`${f.rule}\``);
    if (f.evidence) out.push(`- **Evidence:** \`${f.evidence}\``);
    out.push(`- **What it means:** ${f.detail}`);
    out.push(`- **How to fix:** ${f.remediation}`);
    out.push("");
  }
  return out.join("\n");
}

export function toHtml(result: ScanResult): string {
  const findings = sortFindings(result.findings);
  const counts = countBySeverity(findings);

  const tiles = SEVERITY_ORDER.map(
    (s) => `<div class="tile" style="--c:${SEV_COLOR[s]}">
      <div class="n">${counts[s]}</div><div class="l">${SEV_LABEL[s]}</div></div>`
  ).join("");

  const cards =
    findings.length === 0
      ? `<p class="clean">No issues found by this scan. A clean automated scan is good news, but it is not a guarantee, so keep monitoring on.</p>`
      : findings
          .map(
            (f) => `<div class="card">
      <div class="chead"><span class="sev" style="background:${SEV_COLOR[f.severity]}">${SEV_LABEL[f.severity]}</span>
        <span class="ctitle">${esc(f.title)}</span><span class="rule">${esc(f.rule)}</span></div>
      ${f.location ? `<div class="loc">${esc(f.location)}${f.line ? `:<b>${f.line}</b>` : ""}</div>` : ""}
      ${f.evidence ? `<pre class="ev">${esc(f.evidence)}</pre>` : ""}
      <p class="detail">${esc(f.detail)}</p>
      <p class="fix"><b>How to fix:</b> ${esc(f.remediation)}</p>
    </div>`
          )
          .join("\n");

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lucent Shield report: ${esc(result.target)}</title>
<style>
  :root { --bg:#0b1220; --panel:#131c33; --line:#26314f; --text:#e7ecf7; --muted:#9aa6c9; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.6 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif; }
  .wrap { max-width:860px; margin:0 auto; padding:32px 20px 80px; }
  .brand { font-size:12px; letter-spacing:2px; text-transform:uppercase; color:#60a5fa; font-weight:700; }
  h1 { font-size:26px; margin:6px 0 2px; }
  .meta { color:var(--muted); font-size:13px; }
  .tiles { display:flex; gap:10px; flex-wrap:wrap; margin:22px 0 28px; }
  .tile { flex:1; min-width:90px; background:var(--panel); border:1px solid var(--line); border-top:3px solid var(--c); border-radius:10px; padding:12px; text-align:center; }
  .tile .n { font-size:26px; font-weight:800; color:var(--c); }
  .tile .l { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; margin:12px 0; }
  .chead { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .sev { color:#fff; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.5px; padding:2px 9px; border-radius:5px; }
  .ctitle { font-weight:700; }
  .rule { margin-left:auto; font:12px ui-monospace,monospace; color:var(--muted); }
  .loc { font:12px ui-monospace,monospace; color:#9fd0ff; margin:8px 0 0; }
  .ev { background:#0a1020; border:1px solid var(--line); border-radius:7px; padding:8px 10px; font:12px ui-monospace,monospace; color:#c7d2fe; overflow-x:auto; margin:8px 0; }
  .detail { color:var(--text); margin:8px 0 6px; }
  .fix { color:var(--muted); margin:0; }
  .fix b { color:#86efac; }
  .clean { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:20px; color:#86efac; }
  footer { color:var(--muted); font-size:12px; margin-top:28px; border-top:1px solid var(--line); padding-top:12px; }
</style></head>
<body><div class="wrap">
  <div class="brand">Lucent Shield · Bash Lucent</div>
  <h1>Security scan report</h1>
  <div class="meta">${esc(result.target)} · ${result.mode} scan · ${esc(result.finishedAt)} · ${result.filesScanned} files</div>
  <div class="tiles">${tiles}</div>
  ${cards}
  <footer>Automated scan by Lucent Shield v${esc(result.version)}. Findings are leads to confirm, not proof of exploitability, and a clean scan is not a guarantee. Scan only systems you own or are authorised to test.</footer>
</div></body></html>`;
}
