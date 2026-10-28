// Finds credentials that should never be committed: cloud keys, payment
// keys, API tokens, webhooks, private keys, database passwords and committed
// .env files. Each hit is reported with the file and line, and the value
// itself is redacted so the report is safe to share.

import type { Finding, Severity } from "../types.ts";
import type { ScanFile } from "../util/walk.ts";
import { redactLine, entropy } from "../util/redact.ts";
import { isTestPath, looksFake, isSuppressed } from "../util/source.ts";

interface SecretRule {
  rule: string;
  title: string;
  severity: Severity;
  regex: RegExp;
  remediation: string;
}

const ROTATE = "Treat it as leaked: revoke or rotate it now, remove it from the code and the git history, and load the new value from an environment variable or a secrets manager.";

// Most specific first: the first rule to match a line wins.
const RULES: SecretRule[] = [
  { rule: "secret.private-key", title: "Private key", severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
    remediation: "Remove the private key from the repository and replace the key pair. Keep keys in a secrets manager or a file that git ignores." },
  { rule: "secret.aws-access-key", title: "AWS access key ID", severity: "critical",
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/,
    remediation: "Deactivate this key in AWS IAM immediately and issue a new one. " + ROTATE },
  { rule: "secret.aws-secret-key", title: "AWS secret access key", severity: "critical",
    regex: /aws_?secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/i,
    remediation: "Deactivate the key pair in AWS IAM now. " + ROTATE },
  { rule: "secret.azure-storage-key", title: "Azure storage account key", severity: "critical",
    regex: /AccountKey=[A-Za-z0-9+/]{80,}={0,2}/,
    remediation: "Regenerate the storage account key in the Azure portal. " + ROTATE },
  { rule: "secret.live-payment-key", title: "Live payment secret key (Stripe or Paystack)", severity: "critical",
    regex: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/,
    remediation: "Roll this key in your Stripe or Paystack dashboard right away. Anyone holding it can move money. " + ROTATE },
  { rule: "secret.flutterwave", title: "Flutterwave live secret key", severity: "critical",
    regex: /\bFLWSECK-[0-9a-f]{32}-X\b/,
    remediation: "Regenerate the key in the Flutterwave dashboard. " + ROTATE },
  { rule: "secret.github-token", title: "GitHub access token", severity: "critical",
    regex: /\b(?:gh[pousr]_[0-9A-Za-z]{36,255}|github_pat_[0-9A-Za-z_]{22,255})\b/,
    remediation: "Revoke the token in GitHub settings and replace it with a short-lived, least-privilege token. " + ROTATE },
  { rule: "secret.gitlab-token", title: "GitLab access token", severity: "critical",
    regex: /\bglpat-[0-9A-Za-z_-]{20,}\b/,
    remediation: "Revoke the token in GitLab and issue a narrower one. " + ROTATE },
  { rule: "secret.anthropic-key", title: "Anthropic API key", severity: "high",
    regex: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/,
    remediation: "Delete the key in the Anthropic console and create a new one. " + ROTATE },
  { rule: "secret.openai-key", title: "OpenAI API key", severity: "high",
    regex: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/,
    remediation: "Revoke the key in the OpenAI dashboard and create a new one. " + ROTATE },
  { rule: "secret.google-api-key", title: "Google API key", severity: "high",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/,
    remediation: "Regenerate the key in Google Cloud and add API and referrer restrictions. " + ROTATE },
  { rule: "secret.sendgrid-key", title: "SendGrid API key", severity: "high",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
    remediation: "Delete the key in SendGrid and create a restricted one. " + ROTATE },
  { rule: "secret.twilio-key", title: "Twilio API key", severity: "high",
    regex: /\bSK[0-9a-f]{32}\b/,
    remediation: "Delete the key in the Twilio console. " + ROTATE },
  { rule: "secret.npm-token", title: "npm access token", severity: "high",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
    remediation: "Revoke the token on npmjs.com; it can publish packages under your name. " + ROTATE },
  { rule: "secret.slack-token", title: "Slack token", severity: "high",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    remediation: "Revoke the token in the Slack admin. " + ROTATE },
  { rule: "secret.telegram-bot", title: "Telegram bot token", severity: "high",
    regex: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/,
    remediation: "Revoke the token with @BotFather (/revoke). " + ROTATE },
  { rule: "secret.slack-webhook", title: "Slack incoming webhook", severity: "medium",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{6,}\/B[0-9A-Z]{6,}\/[0-9A-Za-z]{20,}/,
    remediation: "Delete the webhook in Slack and create a new one; anyone with the URL can post to your channel. " + ROTATE },
  { rule: "secret.discord-webhook", title: "Discord webhook", severity: "medium",
    regex: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[\w-]{50,}/,
    remediation: "Delete the webhook in the Discord channel settings and create a new one. " + ROTATE },
  { rule: "secret.database-url", title: "Database connection string with a password", severity: "high",
    regex: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql):\/\/[^\s:@/"'`]+:([^\s@/"'`]{3,})@[^\s"'`]+/i,
    remediation: "Change the database password, then read the connection string from an environment variable. " + ROTATE },
  { rule: "secret.mailgun-key", title: "Mailgun API key", severity: "medium",
    regex: /\bkey-[0-9a-f]{32}\b/,
    remediation: "Rotate the key in the Mailgun dashboard. " + ROTATE },
  { rule: "secret.jwt", title: "Hard-coded JSON Web Token", severity: "medium",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    remediation: "Do not commit real tokens. If this is a live session or API token, invalidate it." },
  { rule: "secret.generic-assignment", title: "Hard-coded secret in the code", severity: "high",
    // password = "....", api_key: '....', SECRET_KEY="...."
    regex: /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?key|db[_-]?pass(?:word)?|passwd|password|pwd|secret|token)["']?\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]/i,
    remediation: "Move the value into an environment variable or a secrets manager and read it at runtime. If it is a real credential, rotate it." },
];

// Lines that are clearly not real secrets: examples, placeholders, env reads.
const PLACEHOLDER =
  /(process\.env|os\.environ|getenv|import\.meta\.env|ENV\[|System\.getenv|example|placeholder|dummy|changeme|change_me|your[_-]?(?:api[_-]?)?(?:key|token|secret|password)|xxxx+|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|redacted|\*{4,}|sample|test[_-]?key|fake)/i;

// A database URL whose "password" is obviously a placeholder or an injected variable.
const WEAK_DB_PASSWORD = /^(?:password|pass|passwd|pwd|secret|changeme|root|admin|postgres|user|example|test|\$.*|\{.*|<.*|\*+)$/i;

// .env files that are real (not templates) and the variables in them that hold secrets.
const ENV_FILE = /(?:^|\/)\.env(?:\.[\w-]+)?$/;
const ENV_TEMPLATE = /\.(?:example|sample|template|dist|defaults?)$/i;
const ENV_SECRET_NAME = /(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|DATABASE_URL|DB_URL|CONNECTION_STRING)/i;

// Rules that guess from context (rather than a provider's exact key format).
// In test files these are skipped, since tests are full of made-up passwords.
const CONTEXT_RULES = new Set(["secret.generic-assignment", "secret.database-url", "secret.jwt"]);

/** A value that reads like a real secret rather than a word or a label. */
function looksSecret(v: string): boolean {
  if (/^[a-z]+(?:[-_.][a-z0-9]+)*$/i.test(v) && !/\d/.test(v)) return false; // new-password, current_user
  let classes = 0;
  if (/[a-z]/.test(v)) classes++;
  if (/[A-Z]/.test(v)) classes++;
  if (/\d/.test(v)) classes++;
  if (/[^A-Za-z0-9\-_.]/.test(v)) classes++;
  return classes >= 2 && entropy(v) >= 3;
}

const DETAIL = "A credential appears to be committed to the repository. Anyone who can read the code, or its git history, can use it.";

export function scanSecrets(files: ScanFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    const isEnv = ENV_FILE.test(file.rel) && !ENV_TEMPLATE.test(file.rel);
    const inTest = isTestPath(file.rel);
    let envReported = false;

    file.lines.forEach((line, i) => {
      if (line.length > 2000) return; // minified or data lines
      if (isSuppressed(file.lines, i)) return; // reviewed and accepted

      for (const rule of RULES) {
        const match = rule.regex.exec(line);
        if (!match) continue;

        if (inTest && CONTEXT_RULES.has(rule.rule)) continue;
        if (looksFake(match[0])) continue;
        if (rule.rule === "secret.generic-assignment") {
          if (PLACEHOLDER.test(line)) continue;
          if (!looksSecret(match[1] ?? "")) continue; // labels, words and other non-secrets
        }
        if (rule.rule === "secret.database-url") {
          const pw = match[1] ?? "";
          if (WEAK_DB_PASSWORD.test(pw) || /localhost|127\.0\.0\.1/.test(line)) continue;
        }
        if (PLACEHOLDER.test(match[0])) continue;

        findings.push({
          rule: rule.rule, severity: rule.severity, category: "secret", title: rule.title,
          location: file.rel, line: i + 1, evidence: redactLine(line), detail: DETAIL, remediation: rule.remediation,
        });
        return; // one finding per line is enough
      }

      // Unquoted KEY=value pairs in a committed .env file.
      if (isEnv) {
        const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\s#]+)/.exec(line);
        if (m && ENV_SECRET_NAME.test(m[1]) && m[2].length >= 6 && !PLACEHOLDER.test(m[2]) && entropy(m[2]) >= 2.5) {
          if (!envReported) {
            envReported = true;
            findings.push({
              rule: "secret.env-file", severity: "high", category: "secret", title: "Environment file with secrets committed",
              location: file.rel, line: i + 1,
              detail: "A real .env file is in the repository. These files are meant to stay on the machine that runs the app, and this one contains live-looking secrets.",
              remediation: "Delete the file from the repository and its history, add .env to .gitignore, rotate every secret it held, and commit a .env.example with empty values instead.",
            });
          }
          findings.push({
            rule: "secret.env-value", severity: "high", category: "secret", title: `Secret value for ${m[1]}`,
            location: file.rel, line: i + 1, evidence: redactLine(line), detail: DETAIL, remediation: ROTATE,
          });
        }
      }
    });
  }

  return findings;
}
