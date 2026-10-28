// Maps every Lucent Shield rule to the industry references auditors use:
// the CWE weakness it represents and its OWASP Top 10 (2021) category.
// Rules are matched by id pattern, most specific first.

export interface Classification { cwe: string; cweName: string; owasp: string }

const OWASP = {
  A01: "A01 Broken Access Control",
  A02: "A02 Cryptographic Failures",
  A03: "A03 Injection",
  A05: "A05 Security Misconfiguration",
  A06: "A06 Vulnerable and Outdated Components",
  A07: "A07 Identification and Authentication Failures",
  A08: "A08 Software and Data Integrity Failures",
  A09: "A09 Security Logging and Monitoring Failures",
  A10: "A10 Server-Side Request Forgery",
};

const MAP: [RegExp, string, string, string][] = [
  [/sql-injection/, "CWE-89", "SQL Injection", OWASP.A03],
  [/nosql-injection/, "CWE-943", "Improper Neutralization in Data Query Logic", OWASP.A03],
  [/command-injection|subprocess-shell|os-system|spawn-shell|gha\.script-injection/, "CWE-78", "OS Command Injection", OWASP.A03],
  [/file-inclusion/, "CWE-98", "PHP Remote File Inclusion", OWASP.A03],
  [/ssti/, "CWE-1336", "Template Injection", OWASP.A03],
  [/\.eval$|vm-run/, "CWE-95", "Eval Injection", OWASP.A03],
  [/regex-injection/, "CWE-1333", "Inefficient Regular Expression (ReDoS)", OWASP.A03],
  [/\.xss$|autoescape-off|request-validation-off/, "CWE-79", "Cross-site Scripting", OWASP.A03],
  [/path-traversal/, "CWE-22", "Path Traversal", OWASP.A01],
  [/open-redirect/, "CWE-601", "Open Redirect", OWASP.A01],
  [/csrf-disabled/, "CWE-352", "Cross-Site Request Forgery", OWASP.A01],
  [/mass-assignment/, "CWE-915", "Mass Assignment", OWASP.A08],
  [/ssrf/, "CWE-918", "Server-Side Request Forgery", OWASP.A10],
  [/unsafe-deserialize|yaml-load/, "CWE-502", "Deserialization of Untrusted Data", OWASP.A08],
  [/weak-hash/, "CWE-328", "Use of Weak Hash", OWASP.A02],
  [/weak-cipher/, "CWE-327", "Broken or Risky Cryptographic Algorithm", OWASP.A02],
  [/insecure-random/, "CWE-338", "Weak Pseudo-Random Number Generator", OWASP.A02],
  [/tls-disabled|tls\.untrusted/, "CWE-295", "Improper Certificate Validation", OWASP.A07],
  [/tls\.expiring/, "CWE-298", "Improper Validation of Certificate Expiration", OWASP.A02],
  [/no-https|http-no-redirect|hsts/, "CWE-319", "Cleartext Transmission of Sensitive Information", OWASP.A02],
  [/jwt-no-alg/, "CWE-347", "Improper Verification of Cryptographic Signature", OWASP.A02],
  [/jwt-hardcoded-secret|^secret\.|forensic\.secret/, "CWE-798", "Use of Hard-coded Credentials", OWASP.A07],
  [/cookie/, "CWE-1004", "Sensitive Cookie Without HttpOnly", OWASP.A05],
  [/cors/, "CWE-942", "Permissive Cross-domain Policy", OWASP.A05],
  [/header\.csp/, "CWE-1021", "Missing or Weak Content Security Policy", OWASP.A05],
  [/header\.frame/, "CWE-1021", "Improper Restriction of Rendered UI Layers (Clickjacking)", OWASP.A05],
  [/exposed-file|directory-listing/, "CWE-538", "Insertion of Sensitive Information into Externally-Accessible File", OWASP.A05],
  [/web\.info\.|header\.referrer|header\.xcto/, "CWE-200", "Exposure of Sensitive Information", OWASP.A05],
  [/email\./, "CWE-290", "Authentication Bypass by Spoofing", OWASP.A07],
  [/debug|allowed-hosts/, "CWE-489", "Active Debug Code", OWASP.A05],
  [/insecure-temp/, "CWE-377", "Insecure Temporary File", OWASP.A05],
  [/privileged|docker-socket|host-namespace|privilege-escalation|runs-as-root/, "CWE-250", "Execution with Unnecessary Privileges", OWASP.A05],
  [/open-to-internet|public-bucket|world-writable/, "CWE-732", "Incorrect Permission Assignment", OWASP.A05],
  [/secret-in-image/, "CWE-798", "Use of Hard-coded Credentials", OWASP.A07],
  [/curl-pipe-shell|add-remote|unpinned-action|latest-tag|pull-request-target/, "CWE-494", "Download of Code Without Integrity Check", OWASP.A08],
  [/dependency\.known-vuln/, "CWE-1395", "Dependency on Vulnerable Third-Party Component", OWASP.A06],
  [/forensic\.ioc/, "CWE-506", "Embedded Malicious Code (indicator)", OWASP.A09],
];

export function classify(rule: string): Classification | null {
  for (const [re, cwe, cweName, owasp] of MAP) if (re.test(rule)) return { cwe, cweName, owasp };
  return null;
}

/** Plain-English names for the finding categories. */
export const CATEGORY_LABEL: Record<string, string> = {
  secret: "Leaked secrets",
  code: "Insecure code",
  dependency: "Vulnerable dependencies",
  web: "Website security",
  forensic: "Forensic findings",
};
