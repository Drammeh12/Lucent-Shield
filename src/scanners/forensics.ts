// Forensic artifact inspection. Point it at a file or a folder you are
// investigating (logs, a dump, a suspicious download, an exported chat) and it
// reports what an analyst looks for first: a tamper-proof hash of each file,
// any leaked credentials, and indicators of compromise — URLs, IP addresses,
// encoded commands, and download-and-run patterns.
//
// This reads artifacts you already hold. It does not touch any live system.

import { statSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { extname } from "node:path";
import type { Finding } from "../types.ts";
import { walk, type ScanFile } from "../util/walk.ts";
import { scanSecrets } from "./secrets.ts";
import { redactLine } from "../util/redact.ts";

const IOC_RULES: { rule: string; title: string; regex: RegExp; detail: string }[] = [
  {
    rule: "forensic.ioc.download-exec",
    title: "Download-and-run command",
    regex: /\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|python|powershell)\b|Invoke-WebRequest[^\n]*\|\s*iex/i,
    detail: "A command fetches something from the internet and runs it immediately — a very common malware installer pattern.",
  },
  {
    rule: "forensic.ioc.encoded-command",
    title: "Encoded PowerShell / shell command",
    regex: /powershell[^\n]*-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{30,}|base64\s+-d\s*\|\s*(sh|bash)/i,
    detail: "An encoded command hides what it does from casual inspection — often used to evade detection.",
  },
  {
    rule: "forensic.ioc.ip",
    title: "Hard-coded IP address",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b(?::\d{2,5})?/,
    detail: "An IP address embedded in an artifact can be a command-and-control endpoint worth checking against threat intelligence.",
  },
  {
    rule: "forensic.ioc.onion",
    title: "Tor .onion address",
    regex: /\b[a-z2-7]{16,56}\.onion\b/i,
    detail: "A .onion address points to a Tor hidden service, often used by malware for anonymous command-and-control.",
  },
];

function sha256(file: ScanFile): string {
  return createHash("sha256").update(file.text).digest("hex");
}

export function scanArtifact(path: string): Finding[] {
  const findings: Finding[] = [];

  let isDir = false;
  try {
    isDir = statSync(path).isDirectory();
  } catch {
    return [{ rule: "forensic.not-found", severity: "info", category: "forensic", title: "Artifact not found", detail: `Could not open "${path}".`, remediation: "Check the path to the file or folder you want to inspect." }];
  }

  const files = isDir ? walk(path) : singleFile(path);

  // 1) Hash manifest — evidence integrity. Capped so a big folder stays readable.
  const manifestLimit = 40;
  files.slice(0, manifestLimit).forEach((f) => {
    findings.push({
      rule: "forensic.hash",
      severity: "info",
      category: "forensic",
      title: `${f.rel} — ${extname(f.path) || "file"}`,
      location: f.rel,
      evidence: `sha256: ${sha256(f)}`,
      detail: "Cryptographic hash of the artifact, for your evidence record and to check against threat-intelligence databases.",
      remediation: "Record this hash with the date and where the artifact came from, to prove it has not changed.",
    });
  });
  if (files.length > manifestLimit) {
    findings.push({ rule: "forensic.hash.more", severity: "info", category: "forensic", title: `${files.length - manifestLimit} more files not listed`, detail: "Only the first 40 file hashes are shown. Run on a single file for its full record.", remediation: "Narrow the inspection to the files of interest." });
  }

  // 2) Leaked credentials inside the artifacts.
  for (const f of scanSecrets(files)) findings.push({ ...f, category: "forensic", rule: f.rule.replace("secret.", "forensic.secret.") });

  // 3) Indicators of compromise.
  for (const file of files) {
    file.lines.forEach((line, i) => {
      if (line.length > 4000) return;
      for (const rule of IOC_RULES) {
        if (!rule.regex.test(line)) continue;
        findings.push({
          rule: rule.rule,
          severity: rule.rule === "forensic.ioc.ip" ? "low" : "medium",
          category: "forensic",
          title: rule.title,
          location: file.rel,
          line: i + 1,
          evidence: redactLine(line),
          detail: rule.detail,
          remediation: "Verify the indicator against threat intelligence (e.g. VirusTotal, AbuseIPDB) and preserve the artifact as evidence.",
        });
      }
    });
  }

  return findings;
}

function singleFile(path: string): ScanFile[] {
  try {
    const text = readFileSync(path, "utf8");
    return [{ path, rel: path.split("/").pop() || path, lines: text.split(/\r?\n/), text }];
  } catch {
    return [];
  }
}
