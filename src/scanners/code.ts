// Flags insecure code patterns: the common mistakes that turn into real
// vulnerabilities. These are heuristics, so each finding is a lead to
// confirm, not a proven exploit — but they catch the usual suspects fast.

import type { Finding, Severity } from "../types.ts";
import type { ScanFile } from "../util/walk.ts";
import { redactLine } from "../util/redact.ts";
import { extname } from "node:path";

interface CodeRule {
  rule: string;
  title: string;
  severity: Severity;
  /** Which file extensions this rule applies to. */
  exts: string[];
  regex: RegExp;
  detail: string;
  remediation: string;
}

const JS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];
const PY = [".py"];

const RULES: CodeRule[] = [
  // ---- JavaScript / TypeScript ----
  {
    rule: "code.js.eval",
    title: "Use of eval() or the Function constructor",
    severity: "high",
    exts: JS,
    regex: /\beval\s*\(|\bnew\s+Function\s*\(/,
    detail: "eval and new Function run arbitrary code. If any part of the input is attacker-influenced, this is remote code execution.",
    remediation: "Remove eval/Function. Parse data with JSON.parse, and use a lookup table or explicit logic instead of running strings as code.",
  },
  {
    rule: "code.js.child-process-concat",
    title: "Shell command built from a string (command injection)",
    severity: "critical",
    exts: JS,
    regex: /\b(exec|execSync)\s*\(\s*[`"'][^`"')]*\$\{|\b(exec|execSync)\s*\(\s*[^,)]*\+/,
    detail: "A shell command is assembled with interpolation or concatenation. User input in that string can run extra commands.",
    remediation: "Use execFile/spawn with an argument array (no shell), and never build the command string from user input.",
  },
  {
    rule: "code.js.innerhtml",
    title: "Assigning untrusted HTML (XSS sink)",
    severity: "medium",
    exts: JS,
    regex: /\.innerHTML\s*=|dangerouslySetInnerHTML/,
    detail: "Writing raw HTML from a variable can inject scripts into the page (cross-site scripting).",
    remediation: "Set textContent instead, or sanitise the HTML with a vetted library (e.g. DOMPurify) before inserting it.",
  },
  {
    rule: "code.js.cors-wildcard",
    title: "CORS open to any origin",
    severity: "medium",
    exts: JS,
    regex: /Access-Control-Allow-Origin["'`]\s*[:,]\s*["'`]\*|cors\(\s*\)/,
    detail: "A wildcard CORS policy lets any website call this API from a victim's browser.",
    remediation: "Restrict CORS to the exact front-end origins you trust instead of '*' or a bare cors().",
  },
  {
    rule: "code.js.jwt-no-alg",
    title: "jwt.verify without a pinned algorithm",
    severity: "medium",
    exts: JS,
    regex: /jwt\.verify\s*\((?:[^)]*)\)/,
    detail: "Verifying a token without specifying the allowed algorithm leaves the door open to algorithm-confusion attacks.",
    remediation: "Pass { algorithms: ['HS256'] } (or your real signing algorithm) to jwt.verify.",
  },
  {
    rule: "code.js.tls-disabled",
    title: "TLS certificate checking disabled",
    severity: "high",
    exts: JS,
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'`]?0|rejectUnauthorized\s*:\s*false/,
    detail: "Turning off certificate verification exposes every outbound request to interception (man-in-the-middle).",
    remediation: "Leave TLS verification on. If a cert is failing, fix the certificate or add the proper CA, do not disable the check.",
  },
  {
    rule: "code.js.math-random-token",
    title: "Math.random() used for something security-sensitive",
    severity: "medium",
    exts: JS,
    regex: /(token|secret|password|otp|nonce|session|reset|key)[^;=\n]{0,40}Math\.random\s*\(/i,
    detail: "Math.random is predictable and must not generate tokens, passwords or session ids.",
    remediation: "Use crypto.randomBytes / crypto.randomUUID for anything that must be unguessable.",
  },

  // ---- Python ----
  {
    rule: "code.py.subprocess-shell",
    title: "subprocess with shell=True",
    severity: "high",
    exts: PY,
    regex: /subprocess\.(?:call|run|Popen|check_output)\([^)]*shell\s*=\s*True/,
    detail: "shell=True runs the command through the shell; input in the command string can inject extra commands.",
    remediation: "Pass the command as a list of arguments and leave shell=False (the default).",
  },
  {
    rule: "code.py.os-system",
    title: "os.system with a built string",
    severity: "high",
    exts: PY,
    regex: /os\.system\s*\(\s*(?:f["']|[^)]*[+%])/,
    detail: "Building an os.system command from variables allows command injection.",
    remediation: "Use subprocess.run([...]) with an argument list instead of os.system.",
  },
  {
    rule: "code.py.yaml-load",
    title: "yaml.load without SafeLoader",
    severity: "high",
    exts: PY,
    regex: /yaml\.load\s*\((?![^)]*Safe)/,
    detail: "yaml.load can construct arbitrary Python objects, which is an RCE risk on untrusted input.",
    remediation: "Use yaml.safe_load(...) instead.",
  },
  {
    rule: "code.py.pickle",
    title: "pickle used to load data",
    severity: "high",
    exts: PY,
    regex: /pickle\.loads?\s*\(/,
    detail: "Unpickling untrusted data runs arbitrary code. pickle is unsafe for anything received from outside.",
    remediation: "Use JSON (or another safe format) for data you did not create yourself.",
  },
  {
    rule: "code.py.debug-true",
    title: "Debug mode enabled",
    severity: "medium",
    exts: PY,
    regex: /\bDEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True/,
    detail: "Debug mode leaks stack traces and, in Flask, exposes an interactive console. It must be off in production.",
    remediation: "Set DEBUG/False from an environment variable and keep it off in production.",
  },
  {
    rule: "code.py.weak-hash",
    title: "Weak hash (md5/sha1) for passwords",
    severity: "medium",
    exts: PY,
    regex: /hashlib\.(?:md5|sha1)\s*\([^)]*(?:password|passwd|pwd)/i,
    detail: "MD5 and SHA-1 are fast and broken for password storage.",
    remediation: "Hash passwords with bcrypt, scrypt or argon2.",
  },
];

export function scanCode(files: ScanFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    const ext = extname(file.path).toLowerCase();
    const applicable = RULES.filter((r) => r.exts.includes(ext));
    if (applicable.length === 0) continue;

    file.lines.forEach((line, i) => {
      if (line.length > 2000) return;
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) return;

      for (const rule of applicable) {
        // The jwt rule should only fire when no algorithms are pinned.
        if (rule.rule === "code.js.jwt-no-alg" && /algorithms\s*:/.test(line)) continue;
        if (!rule.regex.test(line)) continue;
        findings.push({
          rule: rule.rule,
          severity: rule.severity,
          category: "code",
          title: rule.title,
          location: file.rel,
          line: i + 1,
          evidence: redactLine(line),
          detail: rule.detail,
          remediation: rule.remediation,
        });
      }
    });
  }

  return findings;
}
