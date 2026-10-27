// Finds credentials that should never be committed: API keys, tokens,
// private keys, passwords. Each hit is reported with the file and line,
// and the value itself is redacted so the report is safe to share.

import type { Finding, Severity } from "../types.ts";
import type { ScanFile } from "../util/walk.ts";
import { redactLine, entropy } from "../util/redact.ts";

interface SecretRule {
  rule: string;
  title: string;
  severity: Severity;
  regex: RegExp;
  remediation: string;
}

const RULES: SecretRule[] = [
  {
    rule: "secret.aws-access-key",
    title: "AWS access key ID",
    severity: "critical",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
    remediation:
      "Revoke this key in the AWS IAM console immediately and issue a new one. Load it from an environment variable or a secrets manager, never from code.",
  },
  {
    rule: "secret.private-key",
    title: "Private key block",
    severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    remediation:
      "Remove the private key from the repository and rotate it. Store keys outside the codebase (a secrets manager or a file ignored by git).",
  },
  {
    rule: "secret.stripe-live",
    title: "Stripe live secret key",
    severity: "critical",
    regex: /\bsk_live_[0-9a-zA-Z]{20,}\b/,
    remediation: "Roll this key in the Stripe dashboard now and move it to an environment variable.",
  },
  {
    rule: "secret.github-token",
    title: "GitHub token",
    severity: "high",
    regex: /\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/,
    remediation: "Revoke the token in GitHub settings and replace it with a short-lived, least-privilege token kept out of code.",
  },
  {
    rule: "secret.google-api-key",
    title: "Google API key",
    severity: "high",
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/,
    remediation: "Restrict or regenerate the key in Google Cloud, add API and referrer restrictions, and load it from config.",
  },
  {
    rule: "secret.slack-token",
    title: "Slack token",
    severity: "high",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    remediation: "Revoke the token in the Slack admin and store the replacement as an environment variable.",
  },
  {
    rule: "secret.jwt",
    title: "Hard-coded JSON Web Token",
    severity: "medium",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    remediation: "Do not commit real tokens. If this is a live session token, treat it as leaked and invalidate it.",
  },
  {
    rule: "secret.paystack-live",
    title: "Paystack live secret key",
    severity: "critical",
    regex: /\bsk_live_[0-9a-f]{30,}\b/,
    remediation: "Roll this key in the Paystack dashboard immediately and load it from an environment variable only.",
  },
  {
    rule: "secret.generic-assignment",
    title: "Hard-coded secret in an assignment",
    severity: "high",
    // password = "....", api_key: '....', SECRET_TOKEN="...."
    regex:
      /\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?token|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/i,
    remediation:
      "Move the value into an environment variable or secrets manager and read it at runtime. If it is a real credential, rotate it.",
  },
];

// Lines that are clearly not real secrets: examples, placeholders, env reads.
const IGNORE_LINE =
  /(process\.env|os\.environ|getenv|import\.meta\.env|example|placeholder|dummy|changeme|your[_-]?key|xxxx+|<[^>]+>|\$\{[^}]+\})/i;

export function scanSecrets(files: ScanFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    file.lines.forEach((line, i) => {
      if (line.length > 2000) return; // skip minified / data lines
      for (const rule of RULES) {
        const match = rule.regex.exec(line);
        if (!match) continue;

        // The generic assignment rule needs more care: skip env reads,
        // placeholders, and low-entropy values that are plainly not secrets.
        if (rule.rule === "secret.generic-assignment") {
          if (IGNORE_LINE.test(line)) continue;
          const value = match[1] ?? "";
          if (entropy(value) < 3) continue; // "password", "localhost" etc.
        }

        findings.push({
          rule: rule.rule,
          severity: rule.severity,
          category: "secret",
          title: rule.title,
          location: file.rel,
          line: i + 1,
          evidence: redactLine(line),
          detail:
            "A credential appears to be committed to the repository. Anyone who can read the code (or its git history) can use it.",
          remediation: rule.remediation,
        });
        break; // one finding per line is enough
      }
    });
  }

  return findings;
}
