// Flags insecure code patterns: the common mistakes that turn into real
// vulnerabilities, across JavaScript/TypeScript, Python, PHP, Java/Kotlin,
// Go, Ruby and C#, plus infrastructure files (Dockerfiles, Compose and
// Kubernetes YAML, Terraform, GitHub Actions). These are careful heuristics,
// so each finding is a strong lead to confirm rather than a proven exploit.

import type { Finding, Severity } from "../types.ts";
import type { ScanFile } from "../util/walk.ts";
import { redactLine } from "../util/redact.ts";
import { extname } from "node:path";
import { insideLiteral, isTestPath, isSuppressed } from "../util/source.ts";

type Lang = "js" | "py" | "php" | "java" | "go" | "rb" | "cs" | "docker" | "yaml" | "gha" | "tf" | "shell";

interface CodeRule {
  rule: string;
  title: string;
  severity: Severity;
  langs: Lang[];
  regex: RegExp;
  /** Skip the line if this also matches (a sign the code is already safe). */
  unless?: RegExp;
  /** Only apply when the whole file matches this. */
  fileHas?: RegExp;
  /** Raise the severity when the line also matches this. */
  escalate?: { when: RegExp; to: Severity };
  /** Ignore matches that sit inside a string, regex or comment (text, not code). */
  codeOnly?: boolean;
  /** Final judgement with the surrounding lines: return a severity, or null to drop the finding. */
  refine?: (line: string, lines: string[], i: number, severity: Severity) => Severity | null;
  detail: string;
  remediation: string;
}

const SQL = String.raw`\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|FROM)\b`;
// A single- or double-quoted string literal that contains SQL (it may itself contain the other quote).
const QSQL = String.raw`(?:"[^"]*${SQL}[^"]*"|'[^']*${SQL}[^']*')`;
const USER_INPUT_JS = String.raw`req\.(?:query|body|params|headers|cookies)`;
const PHP_INPUT = String.raw`\$_(?:GET|POST|REQUEST|COOKIE)`;

// Shared explanations, so wording stays consistent across languages.
const SQLI = {
  title: "SQL injection: query built from variables",
  detail: "The SQL text is assembled by joining strings or interpolating values. If any part comes from a user, they can change the query and read or destroy data.",
  remediation: "Use parameterised queries (placeholders such as ?, $1 or :name) and pass the values separately. Never build SQL by joining strings.",
};
const CMDI = {
  title: "Command injection: shell command built from variables",
  detail: "A shell command is assembled from variables. Input that reaches it can add extra commands and take over the server.",
  remediation: "Call the program directly with an argument list and no shell, validate inputs against an allow list, and never build the command from user input.",
};
const DESER = {
  title: "Unsafe deserialisation",
  detail: "Deserialising data with this mechanism can construct arbitrary objects. On untrusted input that usually means remote code execution.",
  remediation: "Use a data-only format such as JSON with a schema. If you must keep this format, only accept data you created and signed yourself.",
};
const WEAKHASH = {
  title: "Weak hash algorithm (MD5 or SHA-1)",
  detail: "MD5 and SHA-1 are broken for security use. Collisions are practical, and for passwords they are far too fast to resist cracking.",
  remediation: "Use SHA-256 or better for integrity, and bcrypt, scrypt or Argon2 for passwords.",
};
const TLSOFF = {
  title: "TLS certificate checks switched off",
  detail: "Certificate verification is disabled, so anyone on the network path can impersonate the server and read or change the traffic.",
  remediation: "Leave verification on. If a certificate fails, fix the certificate or trust the correct CA instead of disabling the check.",
};

/** Template-literal SQL: drop fixed fragments, soften dynamic identifiers with bound values. */
function judgeSqlTemplate(line: string, _lines: string[], _i: number, sev: Severity): Severity | null {
  const parts = [...line.matchAll(/\$\{([^{}]*)\}/g)].map((m) => m[1]);
  if (parts.length === 0) return sev; // string concatenation or a raw-unsafe call
  const fixedText = /^\s*(?:[\w.!()]+\s*\?\s*(["'`])[^"'`]*\1\s*:\s*(["'`])[^"'`]*\2|(["'`])[^"'`]*\3)\s*$/;
  if (parts.every((p) => fixedText.test(p))) return null; // only constant SQL text is inserted
  if (/(?:=|IN\s*\(|VALUES\s*\(|,)\s*(?:\?|\$\d+)/i.test(line)) return "medium"; // values bound; identifiers are dynamic
  return sev;
}

/** HTML sinks: writes of whole views are a review lead, sinks fed from the URL are serious. */
function judgeXss(line: string, _lines: string[], _i: number, sev: Severity): Severity | null {
  if (/\blocation\.(?:hash|search|href)|document\.(?:URL|referrer|cookie|documentURI)|window\.name|req\.(?:query|body|params)|URLSearchParams|searchParams/.test(line)) return "high";
  if (/\.(?:inner|outer)HTML\s*=/.test(line) && !/document\.write|insertAdjacentHTML|dangerouslySetInnerHTML|v-html/.test(line)) return "low";
  return sev;
}

const R = (rule: Omit<CodeRule, "title" | "detail" | "remediation">, text: { title: string; detail: string; remediation: string }): CodeRule => ({ ...rule, ...text });

const RULES: CodeRule[] = [
  // ======================= JavaScript / TypeScript =======================
  R({ rule: "code.js.sql-injection", severity: "critical", langs: ["js"],
      regex: new RegExp(String.raw`\b(?:query|execute|exec|raw|run|all|get|prepare|sql|unsafe)\s*\(\s*(?:\x60[^\x60]*${SQL}[^\x60]*\$\{|${QSQL}\s*\+)|\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(`, "i"), refine: judgeSqlTemplate }, SQLI),
  R({ rule: "code.js.command-injection", severity: "critical", langs: ["js"],
      regex: /(?:^|[^.\w]|(?:child_process|childProcess|cp|proc)\.)(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"'`]*["']\s*\+|[A-Za-z_$][\w.$]*\s*\+)/, codeOnly: true }, CMDI),
  { rule: "code.js.spawn-shell", title: "Process started through a shell", severity: "high", langs: ["js"],
    regex: /\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true/, codeOnly: true,
    detail: "shell: true hands the command to a shell, so any variable part of it can add extra commands.",
    remediation: "Drop shell: true and pass the program and its arguments as a list. If a shell is truly needed, never let user input reach the command." },
  { rule: "code.js.eval", title: "eval() or the Function constructor", severity: "high", langs: ["js"],
    regex: /(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(/, codeOnly: true,
    detail: "eval and new Function run a string as code. If any part of that string is influenced by a user, this is remote code execution.",
    remediation: "Remove eval. Parse data with JSON.parse and use explicit logic or a lookup table instead of running strings." },
  { rule: "code.js.vm-run", title: "Code run through the vm module", severity: "high", langs: ["js"],
    regex: /\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|new\s+vm\.Script\s*\(/, codeOnly: true,
    detail: "Node's vm module is not a security boundary. Code it runs can escape the sandbox and reach the host.",
    remediation: "Do not run untrusted code. If you must, use a real isolate (a separate process or container with no privileges)." },
  { rule: "code.js.nosql-injection", title: "NoSQL injection: $where with dynamic code", severity: "high", langs: ["js"],
    regex: /\$where\s*:/,
    detail: "MongoDB's $where runs JavaScript on the database server. Building it from input lets an attacker run their own logic.",
    remediation: "Replace $where with normal query operators ($eq, $gt and so on) and validate input types before querying." },
  { rule: "code.js.path-traversal", title: "Path traversal: file path from user input", severity: "high", langs: ["js"],
    regex: new RegExp(String.raw`\b(?:readFile|readFileSync|createReadStream|sendFile|download|unlink|unlinkSync|writeFile|writeFileSync|rmSync|appendFile)\s*\([^;]*${USER_INPUT_JS}`),
    detail: "A file path is taken from the request. Values like ../../etc/passwd let an attacker read or overwrite files outside the intended folder.",
    remediation: "Map the input to an allow list of files, or resolve the path and check it stays inside a fixed base directory before using it." },
  { rule: "code.js.ssrf", title: "Server-side request forgery: URL from user input", severity: "high", langs: ["js"],
    regex: new RegExp(String.raw`\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got|needle|superagent|request|https?\.(?:get|request))\s*\(\s*(?:\x60[^\x60]*\$\{\s*)?${USER_INPUT_JS}`),
    detail: "The server fetches a URL chosen by the user. That can be pointed at internal services or cloud metadata to steal credentials.",
    remediation: "Only fetch from an allow list of hosts, resolve and reject private and link-local addresses, and never pass a raw user URL to the HTTP client." },
  { rule: "code.js.open-redirect", title: "Open redirect", severity: "medium", langs: ["js"],
    regex: new RegExp(String.raw`\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?${USER_INPUT_JS}`),
    detail: "The redirect target comes from the request, so your domain can be used to send people to phishing pages.",
    remediation: "Redirect only to relative paths or to an allow list of known destinations." },
  { rule: "code.js.xss", title: "Cross-site scripting: raw HTML written to the page", severity: "medium", langs: ["js"], codeOnly: true, refine: judgeXss,
    regex: /\.(?:innerHTML|outerHTML)\s*=(?!=)|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML|document\.write(?:ln)?\s*\(|\bv-html=/,
    unless: /DOMPurify|sanitize|escapeHtml|\besc\(|\.(?:inner|outer)HTML\s*=\s*(["'`])[^"'`$]*\1\s*;?\s*$/,
    detail: "Raw HTML is inserted from a variable. If it holds user content, an attacker can run scripts in your users' browsers.",
    remediation: "Use textContent for text, or sanitise the HTML with a vetted library such as DOMPurify before inserting it." },
  { rule: "code.js.regex-injection", title: "Regular expression built from user input", severity: "medium", langs: ["js"],
    regex: new RegExp(String.raw`new\s+RegExp\s*\(\s*${USER_INPUT_JS}`),
    detail: "A user-supplied pattern can be crafted to make the regex engine hang (ReDoS), taking the service down.",
    remediation: "Escape user input before putting it in a pattern, or match with plain string functions instead." },
  R({ rule: "code.js.unsafe-deserialize", severity: "critical", langs: ["js"],
      regex: /require\(\s*["']node-serialize["']\)|\.unserialize\s*\(/ }, DESER),
  { rule: "code.js.jwt-hardcoded-secret", title: "JWT signed with a hard-coded secret", severity: "high", langs: ["js"],
    regex: /jwt\.sign\s*\([^,]+,\s*["'`][^"'`]{3,}["'`]/,
    detail: "The signing secret is in the source code. Anyone who sees it can mint valid tokens and log in as any user.",
    remediation: "Load a long random signing secret from an environment variable or secrets manager, and rotate it now." },
  { rule: "code.js.jwt-no-alg", title: "jwt.verify without a pinned algorithm", severity: "medium", langs: ["js"],
    regex: /jwt\.verify\s*\(/, codeOnly: true,
    refine: (_line, lines, i, sev) => (/algorithms\s*:/.test(lines.slice(i, i + 8).join(" ")) ? null : sev),
    detail: "Verifying a token without fixing the accepted algorithm leaves room for algorithm-confusion attacks.",
    remediation: "Pass { algorithms: ['HS256'] } (or your real signing algorithm) to jwt.verify." },
  { rule: "code.js.cookie-insecure", title: "Cookie readable by page scripts (httpOnly off)", severity: "medium", langs: ["js"],
    regex: /httpOnly\s*:\s*false/i,
    detail: "Without httpOnly, any cross-site scripting bug can read this cookie and hijack the session.",
    remediation: "Set httpOnly: true, secure: true and sameSite: 'lax' (or 'strict') on session cookies." },
  { rule: "code.js.cors-wildcard", title: "CORS open to any origin", severity: "medium", langs: ["js"],
    regex: /Access-Control-Allow-Origin["'`]\s*[:,]\s*["'`]\*|\bcors\(\s*\)|cors\(\s*\{[^}]*origin\s*:\s*(?:["']\*["']|true)/,
    refine: (line, _l, _i, sev) => (/\bcors\(/.test(line) && insideLiteral(line, line.search(/\bcors\(/)) ? null : sev),
    detail: "Any website can call this API from a visitor's browser. Combined with cookies, that can expose user data.",
    remediation: "List the exact front-end origins you trust instead of '*', true, or a bare cors()." },
  R({ rule: "code.js.tls-disabled", severity: "high", langs: ["js"],
      regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["'`]?0|rejectUnauthorized\s*:\s*false/ }, TLSOFF),
  R({ rule: "code.js.weak-hash", severity: "low", langs: ["js"],
      regex: /createHash\s*\(\s*["'](?:md5|sha1)["']/i, escalate: { when: /pass(?:word|wd)?|pwd/i, to: "medium" } }, WEAKHASH),
  { rule: "code.js.weak-cipher", title: "Broken or deprecated encryption", severity: "high", langs: ["js"],
    regex: /\bcreateCipher\s*\(|\bcreateDecipher\s*\(|createCipheriv\s*\(\s*["'](?:des|des-ede3?|rc4|bf|aes-\d+-ecb)/i,
    detail: "createCipher derives keys weakly and reuses IVs, and DES, RC4 and ECB mode do not protect data properly.",
    remediation: "Use createCipheriv with aes-256-gcm, a random 12-byte IV per message, and a key from a proper KDF." },
  { rule: "code.js.insecure-random", title: "Math.random() used for a secret value", severity: "medium", langs: ["js"],
    regex: /(token|secret|password|passwd|otp|nonce|session|reset|salt|api_?key)[^;\n]{0,60}Math\.random\s*\(/i,
    detail: "Math.random is predictable. Tokens, passwords and reset codes made with it can be guessed.",
    remediation: "Use crypto.randomBytes or crypto.randomUUID for anything that must be unguessable." },

  // ================================ Python ================================
  R({ rule: "code.py.sql-injection", severity: "critical", langs: ["py"],
      regex: new RegExp(String.raw`\.(?:execute|executemany|executescript|raw)\s*\(\s*(?:f(?:"[^"]*${SQL}[^"]*\{|'[^']*${SQL}[^']*\{)|${QSQL}\s*(?:%|\+|\.format\b))`, "i") }, SQLI),
  R({ rule: "code.py.subprocess-shell", severity: "high", langs: ["py"],
      regex: /subprocess\.(?:call|run|Popen|check_output|check_call)\([^)]*shell\s*=\s*True/ }, CMDI),
  R({ rule: "code.py.os-system", severity: "high", langs: ["py"],
      regex: /os\.(?:system|popen)\s*\(\s*(?:f["']|[^)]*[+%]|[^)]*\.format\b)/ }, CMDI),
  { rule: "code.py.eval", title: "eval() or exec() on dynamic input", severity: "high", langs: ["py"],
    regex: /(?<![\w.])(?:eval|exec)\s*\(/,
    detail: "eval and exec run a string as Python code. Anything a user can influence becomes remote code execution.",
    remediation: "Use ast.literal_eval for simple values, or explicit parsing logic. Never run user strings." },
  { rule: "code.py.yaml-load", title: "yaml.load without the safe loader", severity: "high", langs: ["py"],
    regex: /yaml\.(?:load|load_all)\s*\((?![^)]*(?:Safe|safe))|yaml\.unsafe_load\s*\(/,
    detail: "yaml.load can build arbitrary Python objects, which is remote code execution on untrusted input.",
    remediation: "Use yaml.safe_load instead." },
  R({ rule: "code.py.unsafe-deserialize", severity: "high", langs: ["py"],
      regex: /\b(?:pickle|cPickle|dill|shelve|marshal|jsonpickle)\.(?:loads?|open|decode|Unpickler)\s*\(/ }, DESER),
  R({ rule: "code.py.tls-disabled", severity: "high", langs: ["py"],
      regex: /verify\s*=\s*False|ssl\._create_unverified_context|cert_reqs\s*=\s*ssl\.CERT_NONE/ }, TLSOFF),
  { rule: "code.py.ssti", title: "Server-side template injection risk", severity: "high", langs: ["py"],
    regex: /render_template_string\s*\(/,
    detail: "Rendering a template built at runtime lets anyone who controls part of it run code on the server through template syntax.",
    remediation: "Use render_template with a fixed template file, and pass user data as variables, never as template text." },
  { rule: "code.py.debug", title: "Debug mode switched on", severity: "medium", langs: ["py"],
    regex: /\bDEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True/,
    detail: "Debug mode leaks stack traces and settings, and in Flask it exposes an interactive console that runs code.",
    remediation: "Read DEBUG from an environment variable and keep it off in production." },
  { rule: "code.py.allowed-hosts-wildcard", title: "Django ALLOWED_HOSTS accepts any host", severity: "medium", langs: ["py"],
    regex: /ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/,
    detail: "A wildcard host list enables host-header attacks such as poisoned password-reset links.",
    remediation: "List the exact domains the site is served on." },
  { rule: "code.py.autoescape-off", title: "Template autoescaping switched off", severity: "medium", langs: ["py"],
    regex: /autoescape\s*=\s*False/,
    detail: "Without autoescaping, any user content rendered in a template can inject scripts.",
    remediation: "Keep autoescape on (select_autoescape) and mark only trusted strings as safe." },
  R({ rule: "code.py.weak-hash", severity: "low", langs: ["py"],
      regex: /hashlib\.(?:md5|sha1)\s*\(/, escalate: { when: /pass(?:word|wd)?|pwd/i, to: "medium" } }, WEAKHASH),
  { rule: "code.py.insecure-temp", title: "Race-prone temporary file (mktemp)", severity: "low", langs: ["py"],
    regex: /tempfile\.mktemp\s*\(/,
    detail: "mktemp returns a name without creating the file, so another process can create it first and hijack it.",
    remediation: "Use tempfile.mkstemp or NamedTemporaryFile, which create the file safely." },
  { rule: "code.py.insecure-random", title: "random module used for a secret value", severity: "medium", langs: ["py"],
    regex: /(token|secret|password|otp|nonce|salt|key)\w*\s*=.*\brandom\.(?:random|randint|choice|choices|getrandbits)\s*\(/i,
    detail: "Python's random module is predictable and must not generate secrets.",
    remediation: "Use the secrets module (secrets.token_urlsafe, secrets.choice)." },

  // ================================= PHP ==================================
  R({ rule: "code.php.sql-injection", severity: "critical", langs: ["php"],
      regex: new RegExp(String.raw`\b(?:mysqli_query|mysql_query|pg_query|sqlsrv_query)\s*\([^;]*${PHP_INPUT}|->(?:query|exec)\s*\([^;]*${PHP_INPUT}|${QSQL}\s*\.\s*${PHP_INPUT}`, "i") }, SQLI),
  R({ rule: "code.php.command-injection", severity: "critical", langs: ["php"],
      regex: new RegExp(String.raw`\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^;]*${PHP_INPUT}|\x60[^\x60]*${PHP_INPUT}`) }, CMDI),
  { rule: "code.php.xss", title: "Cross-site scripting: request data echoed", severity: "high", langs: ["php"],
    regex: new RegExp(String.raw`\b(?:echo|print)\b[^;]*(?:${PHP_INPUT}|\$_SERVER\[)`),
    unless: /htmlspecialchars|htmlentities|esc_html|esc_attr|strip_tags|intval|filter_var/,
    detail: "Request data is printed into the page without escaping, so a crafted link can run scripts for whoever opens it.",
    remediation: "Escape output with htmlspecialchars($value, ENT_QUOTES, 'UTF-8') or use a templating engine that escapes by default." },
  { rule: "code.php.file-inclusion", title: "File inclusion from request data", severity: "critical", langs: ["php"],
    regex: new RegExp(String.raw`\b(?:include|require)(?:_once)?\b\s*\(?\s*${PHP_INPUT}`),
    detail: "The file to include comes from the request, which lets attackers load local secrets or run remote code.",
    remediation: "Map the input to a fixed allow list of pages and include only those." },
  R({ rule: "code.php.unsafe-deserialize", severity: "high", langs: ["php"],
      regex: new RegExp(String.raw`\bunserialize\s*\(\s*(?:base64_decode\s*\(\s*)?${PHP_INPUT}`) }, DESER),
  { rule: "code.php.eval", title: "eval() or assert() on a variable", severity: "critical", langs: ["php"],
    regex: /\b(?:eval|assert|create_function)\s*\(\s*\$/,
    detail: "Running a variable as PHP code is remote code execution if that variable can be influenced by a user.",
    remediation: "Remove eval and replace it with explicit logic." },
  R({ rule: "code.php.weak-hash", severity: "medium", langs: ["php"],
      regex: /\b(?:md5|sha1)\s*\(\s*\$(?:_POST\[['"]pass|pass(?:word)?|pwd)/i }, WEAKHASH),

  // ============================ Java / Kotlin =============================
  R({ rule: "code.java.sql-injection", severity: "critical", langs: ["java"],
      regex: new RegExp(String.raw`\.(?:executeQuery|executeUpdate|execute|addBatch|prepareStatement|createQuery|createNativeQuery|createSQLQuery)\s*\(\s*"[^"]*${SQL}[^"]*"\s*\+`, "i") }, SQLI),
  R({ rule: "code.java.command-injection", severity: "critical", langs: ["java"],
      regex: /Runtime\.getRuntime\(\)\.exec\s*\([^;]*\+|new\s+ProcessBuilder\s*\([^;]*\+/ }, CMDI),
  R({ rule: "code.java.unsafe-deserialize", severity: "high", langs: ["java"],
      regex: /new\s+ObjectInputStream\s*\(|new\s+XMLDecoder\s*\(|new\s+XStream\s*\(\s*\)|enableDefaultTyping\s*\(/ }, DESER),
  R({ rule: "code.java.weak-hash", severity: "medium", langs: ["java"],
      regex: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|MD2|SHA-?1)"/i }, WEAKHASH),
  { rule: "code.java.weak-cipher", title: "Broken encryption mode or algorithm", severity: "high", langs: ["java"],
    regex: /Cipher\.getInstance\s*\(\s*"(?:DES[^"]*|RC4|RC2|Blowfish[^"]*|[^"]*\/ECB\/[^"]*|AES)"/,
    detail: "DES, RC4 and ECB mode (which plain \"AES\" defaults to) leak patterns in the data and are easy to break.",
    remediation: "Use AES/GCM/NoPadding with a random 12-byte IV per message." },
  R({ rule: "code.java.tls-disabled", severity: "critical", langs: ["java"],
      regex: /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|setHostnameVerifier\s*\(\s*\([^)]*\)\s*->\s*true|checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}|[tT]rustAllCerts/ }, TLSOFF),
  { rule: "code.java.csrf-disabled", title: "CSRF protection switched off", severity: "medium", langs: ["java"],
    regex: /csrf\(\)\.disable\(\)|csrf\s*\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)|AbstractHttpConfigurer::disable/,
    detail: "With CSRF protection off, another site can make a logged-in user's browser perform actions on their behalf.",
    remediation: "Keep CSRF protection on for any cookie-based session, and only disable it for stateless token APIs." },
  { rule: "code.java.insecure-random", title: "java.util.Random used for a secret value", severity: "medium", langs: ["java"],
    regex: /(token|secret|password|otp|nonce|session|salt|key)[^;\n]{0,60}new\s+(?:java\.util\.)?Random\s*\(/i,
    detail: "java.util.Random is predictable and must not generate secrets.",
    remediation: "Use java.security.SecureRandom." },

  // ================================== Go ==================================
  R({ rule: "code.go.sql-injection", severity: "critical", langs: ["go"],
      regex: new RegExp(String.raw`\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw)\s*\(\s*(?:ctx\s*,\s*)?(?:fmt\.Sprintf\s*\(\s*"[^"]*${SQL}|"[^"]*${SQL}[^"]*"\s*\+)`, "i") }, SQLI),
  R({ rule: "code.go.command-injection", severity: "critical", langs: ["go"],
      regex: /exec\.Command(?:Context)?\s*\(\s*(?:ctx\s*,\s*)?"(?:sh|bash|zsh|cmd|cmd\.exe|powershell)"\s*,\s*"(?:-c|\/c|\/C|-Command)"\s*,\s*(?:fmt\.Sprintf|[^)]*\+)/ }, CMDI),
  R({ rule: "code.go.tls-disabled", severity: "high", langs: ["go"],
      regex: /InsecureSkipVerify\s*:\s*true/ }, TLSOFF),
  R({ rule: "code.go.weak-hash", severity: "low", langs: ["go"],
      regex: /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/ }, WEAKHASH),
  { rule: "code.go.xss", title: "Template escaping bypassed", severity: "medium", langs: ["go"],
    regex: /template\.(?:HTML|JS|URL|HTMLAttr)\s*\(/,
    detail: "Wrapping a value in template.HTML (or JS/URL) tells html/template not to escape it. With user content, that is cross-site scripting.",
    remediation: "Pass plain strings to the template and let html/template escape them." },
  { rule: "code.go.insecure-random", title: "math/rand used for a secret value", severity: "medium", langs: ["go"],
    regex: /(token|secret|password|otp|nonce|key)[^\n]{0,60}\brand\.(?:Int|Intn|Int63|Read|Uint32)\s*\(/i, fileHas: /"math\/rand"/,
    detail: "math/rand is predictable and must not generate secrets.",
    remediation: "Use crypto/rand." },

  // ================================= Ruby =================================
  R({ rule: "code.rb.sql-injection", severity: "critical", langs: ["rb"],
      regex: /\.(?:where|find_by_sql|order|group|having|joins|select|pluck|exists\?|count_by_sql|execute|exec_query)\s*\(\s*"[^"]*#\{/ }, SQLI),
  R({ rule: "code.rb.command-injection", severity: "critical", langs: ["rb"],
      regex: /\b(?:system|exec|spawn|IO\.popen|Open3\.\w+)\s*\(?\s*"[^"]*#\{|`[^`]*#\{|%x\([^)]*#\{/ }, CMDI),
  R({ rule: "code.rb.unsafe-deserialize", severity: "high", langs: ["rb"],
      regex: /\bMarshal\.load\s*\(|\bYAML\.(?:unsafe_load|load)\s*\(|\bOj\.load\s*\(/ }, DESER),
  { rule: "code.rb.mass-assignment", title: "All request parameters permitted", severity: "medium", langs: ["rb"],
    regex: /\.permit!/,
    detail: "permit! lets a request set any attribute, including admin flags or ownership fields.",
    remediation: "Permit only the exact fields the form should change." },
  { rule: "code.rb.eval", title: "Dynamic code or method call from input", severity: "high", langs: ["rb"],
    regex: /(?<![\w.:])eval\s*\(|\.(?:send|public_send|constantize|safe_constantize)\s*\(\s*params/,
    detail: "Running strings as code, or calling methods named by the request, lets attackers invoke anything in the app.",
    remediation: "Replace dynamic calls with an explicit allow list of methods." },
  { rule: "code.rb.xss", title: "Escaping bypassed in a view", severity: "medium", langs: ["rb"],
    regex: /\.html_safe\b|\braw\s*\(|<%==/,
    detail: "html_safe and raw switch off Rails escaping. With user content, that is cross-site scripting.",
    remediation: "Let Rails escape output, or sanitise with sanitize() before marking content safe." },

  // ================================== C# ==================================
  R({ rule: "code.cs.sql-injection", severity: "critical", langs: ["cs"],
      regex: new RegExp(String.raw`new\s+SqlCommand\s*\(\s*"[^"]*${SQL}[^"]*"\s*\+|\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync)\s*\(\s*(?:\$"|"[^"]*"\s*\+)|CommandText\s*=\s*"[^"]*${SQL}[^"]*"\s*\+`, "i") }, SQLI),
  R({ rule: "code.cs.command-injection", severity: "high", langs: ["cs"],
      regex: /Process\.Start\s*\([^;]*\+/ }, CMDI),
  R({ rule: "code.cs.unsafe-deserialize", severity: "critical", langs: ["cs"],
      regex: /\b(?:BinaryFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter|ObjectStateFormatter)\b|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)/ }, DESER),
  R({ rule: "code.cs.weak-hash", severity: "medium", langs: ["cs"],
      regex: /\b(?:MD5|SHA1)\.Create\s*\(|new\s+(?:MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider)\s*\(/ }, WEAKHASH),
  R({ rule: "code.cs.tls-disabled", severity: "critical", langs: ["cs"],
      regex: /(?:ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*\+?=[^;]*=>\s*true|DangerousAcceptAnyServerCertificateValidator/ }, TLSOFF),
  { rule: "code.cs.request-validation-off", title: "ASP.NET request validation switched off", severity: "medium", langs: ["cs"],
    regex: /ValidateRequest\s*=\s*"?false|\[ValidateInput\(false\)\]/i,
    detail: "Request validation is a safety net against script injection; turning it off removes that layer.",
    remediation: "Leave validation on and encode output properly where HTML input is genuinely needed." },

  // ======================= Docker, YAML, Terraform, CI ====================
  { rule: "code.docker.curl-pipe-shell", title: "Script downloaded and run in one step", severity: "medium", langs: ["docker", "shell"],
    regex: /(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?)\b/,
    detail: "Piping a download straight into a shell runs whatever the server returns, with no integrity check.",
    remediation: "Download the file, verify its checksum or signature, then run it, or install from a package manager." },
  { rule: "code.docker.secret-in-image", title: "Secret baked into the image", severity: "high", langs: ["docker"],
    regex: /^\s*(?:ENV|ARG)\s+\w*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY)\w*\s*[= ]\s*\S{4,}/i,
    detail: "Values set with ENV or ARG are stored in the image layers, where anyone who pulls the image can read them.",
    remediation: "Pass secrets at run time (environment variables or mounted secrets), not at build time." },
  { rule: "code.docker.add-remote", title: "ADD from a remote URL", severity: "low", langs: ["docker"],
    regex: /^\s*ADD\s+https?:\/\//i,
    detail: "ADD fetches remote files without any integrity check.",
    remediation: "Download with a pinned checksum in a RUN step, or COPY a verified local file." },
  { rule: "code.any.world-writable", title: "World-writable permissions (chmod 777)", severity: "low", langs: ["docker", "shell"],
    regex: /chmod\s+(?:-R\s+)?0?777\b/,
    detail: "777 lets every user on the system modify the files, which helps an attacker who gains any foothold.",
    remediation: "Grant only the permissions needed, such as 755 for folders and 644 for files." },
  { rule: "code.container.privileged", title: "Privileged container", severity: "high", langs: ["yaml"],
    regex: /^\s*privileged\s*:\s*true\b/,
    detail: "A privileged container has almost full access to the host. A compromise inside it is a compromise of the server.",
    remediation: "Remove privileged mode and grant only the specific capabilities the container needs." },
  { rule: "code.container.docker-socket", title: "Docker socket mounted into a container", severity: "high", langs: ["yaml"],
    regex: /\/var\/run\/docker\.sock/,
    detail: "Access to the Docker socket is equivalent to root on the host.",
    remediation: "Do not mount the socket. If a tool truly needs it, use a restricted socket proxy." },
  { rule: "code.container.host-namespace", title: "Container shares the host network or processes", severity: "medium", langs: ["yaml"],
    regex: /^\s*(?:network_mode\s*:\s*["']?host|hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostIPC\s*:\s*true)/,
    detail: "Sharing host namespaces removes isolation between the container and the server.",
    remediation: "Use normal container networking and keep host namespaces unshared." },
  { rule: "code.container.privilege-escalation", title: "Container allowed to gain more privileges", severity: "medium", langs: ["yaml"],
    regex: /allowPrivilegeEscalation\s*:\s*true|runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0\b/,
    detail: "The container can run as root or raise its privileges, which makes escapes far easier.",
    remediation: "Set runAsNonRoot: true and allowPrivilegeEscalation: false." },
  { rule: "code.tf.open-to-internet", title: "Network rule open to the whole internet", severity: "medium", langs: ["tf"],
    regex: /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|ipv6_cidr_blocks\s*=\s*\[[^\]]*"::\/0"|source_address_prefix\s*=\s*"(?:\*|0\.0\.0\.0\/0|Internet)"/,
    detail: "This rule accepts traffic from any address. That is fine for a public web port, and dangerous for SSH, databases or admin panels.",
    remediation: "Restrict the source range to known addresses, or put the service behind a VPN or bastion." },
  { rule: "code.tf.public-bucket", title: "Storage bucket open to the public", severity: "high", langs: ["tf"],
    regex: /acl\s*=\s*"public-read(?:-write)?"|block_public_(?:acls|policy)\s*=\s*false/,
    detail: "Files in a public bucket can be listed or downloaded by anyone, a frequent cause of data leaks.",
    remediation: "Keep buckets private, enable the public access block, and serve public files through a CDN with signed URLs if needed." },
  { rule: "code.gha.pull-request-target", title: "Workflow runs on pull_request_target", severity: "medium", langs: ["gha"],
    regex: /\bpull_request_target\b/,
    detail: "pull_request_target runs with your secrets and write access. If it checks out or runs code from the pull request, a stranger's PR can steal them.",
    remediation: "Use pull_request instead, or never check out or execute the PR's code in this workflow." },
  { rule: "code.gha.script-injection", title: "Untrusted input injected into a workflow script", severity: "high", langs: ["gha"],
    regex: /\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|head_commit\.(?:message|author\.(?:name|email))|commits\b[^}]*|pages\b[^}]*)|head_ref)\s*\}\}/,
    unless: /^\s*if\s*:/,
    detail: "Text such as a pull request title is pasted into a shell command. Anyone can open a PR with a title that runs their own commands, with your secrets.",
    remediation: "Pass the value through an environment variable (env: TITLE: ${{ ... }}) and reference \"$TITLE\" in the script." },
  { rule: "code.gha.unpinned-action", title: "Action pinned to a moving branch", severity: "low", langs: ["gha"],
    regex: /uses:\s*[\w.-]+\/[\w./-]+@(?:main|master|latest|dev)\b/,
    detail: "A branch reference can change under you. If that action is compromised, your workflow runs the new code.",
    remediation: "Pin third-party actions to a release tag or, better, a full commit SHA." },
];

const HASH_COMMENT: Lang[] = ["py", "rb", "yaml", "gha", "tf", "shell", "docker"];
const SLASH_COMMENT: Lang[] = ["js", "java", "go", "cs", "php", "tf"];

export function langsFor(rel: string): Set<Lang> {
  const base = (rel.split("/").pop() ?? rel).toLowerCase();
  const ext = extname(base);
  const s = new Set<Lang>();
  if ([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"].includes(ext)) s.add("js");
  if (ext === ".py") s.add("py");
  if ([".php", ".phtml"].includes(ext)) s.add("php");
  if ([".java", ".kt", ".kts", ".scala"].includes(ext)) s.add("java");
  if (ext === ".go") s.add("go");
  if ([".rb", ".erb", ".rake"].includes(ext)) s.add("rb");
  if ([".cs", ".cshtml", ".aspx", ".ascx"].includes(ext)) s.add("cs");
  if (base === "dockerfile" || base.startsWith("dockerfile.") || ext === ".dockerfile" || base === "containerfile") s.add("docker");
  if ([".yml", ".yaml"].includes(ext)) s.add("yaml");
  if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(rel)) s.add("gha");
  if ([".tf", ".tfvars"].includes(ext)) s.add("tf");
  if ([".sh", ".bash", ".zsh"].includes(ext)) s.add("shell");
  return s;
}

function isComment(trimmed: string, langs: Set<Lang>): boolean {
  if (HASH_COMMENT.some((l) => langs.has(l)) && trimmed.startsWith("#")) return true;
  if (SLASH_COMMENT.some((l) => langs.has(l)) && /^(?:\/\/|\/\*|\*(?!\*?\/?\S*=))/.test(trimmed)) return true;
  return false;
}

/** Whole-file Dockerfile checks: floating base images and running as root. */
function dockerChecks(file: ScanFile): Finding[] {
  const out: Finding[] = [];
  const stages = new Set<string>();
  let lastFromLine = 0;
  let user: string | null = null;
  file.lines.forEach((line, i) => {
    const t = line.trim();
    const from = /^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(t);
    if (from) {
      const image = from[1].toLowerCase();
      lastFromLine = i + 1;
      user = null; // USER does not carry into the next stage
      const floating = !image.includes("@") && !image.includes("$") && (!/:[^/]+$/.test(image) || image.endsWith(":latest"));
      if (image !== "scratch" && !stages.has(image) && floating) {
        out.push({ rule: "code.docker.latest-tag", severity: "low", category: "code", title: "Base image not pinned to a version",
          location: file.rel, line: i + 1, evidence: redactLine(line),
          detail: "Without a fixed tag (or with :latest), every build can pull a different image, including one with new vulnerabilities.",
          remediation: "Pin the base image to a specific version tag, ideally with its digest (image:tag@sha256:...)." });
      }
      if (from[2]) stages.add(from[2].toLowerCase());
    }
    const u = /^USER\s+(\S+)/i.exec(t);
    if (u) user = u[1];
  });
  if (lastFromLine && (user === null || /^(?:root|0)(?::|$)/i.test(user))) {
    out.push({ rule: "code.docker.runs-as-root", severity: "low", category: "code", title: "Container runs as root",
      location: file.rel, line: lastFromLine,
      detail: "The final image has no non-root USER, so the app runs as root. Any bug that gives code execution then has full control of the container.",
      remediation: "Create an unprivileged user and switch to it with USER (for Node images, USER node)." });
  }
  return out;
}

export function scanCode(files: ScanFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    const langs = langsFor(file.rel);
    if (langs.size === 0) continue;
    // Test code is never deployed, so code patterns there are not reported
    // (real credentials in tests are still caught by the secrets check).
    if (isTestPath(file.rel)) continue;
    const applicable = RULES.filter((r) => r.langs.some((l) => langs.has(l)) && (!r.fileHas || r.fileHas.test(file.text)));

    if (langs.has("docker")) findings.push(...dockerChecks(file));
    if (applicable.length === 0) continue;

    file.lines.forEach((line, i) => {
      if (line.length > 2000) return;
      const trimmed = line.trim();
      if (!trimmed || isComment(trimmed, langs) || isSuppressed(file.lines, i)) return;

      for (const rule of applicable) {
        const m = rule.regex.exec(line);
        if (!m) continue;
        if (rule.unless && rule.unless.test(line)) continue;
        if (rule.codeOnly && insideLiteral(line, m.index + (m[0].length - m[0].trimStart().length))) continue;
        let severity: Severity | null = rule.escalate && rule.escalate.when.test(line) ? rule.escalate.to : rule.severity;
        if (rule.refine) severity = rule.refine(line, file.lines, i, severity);
        if (!severity) continue;
        findings.push({
          rule: rule.rule, severity, category: "code", title: rule.title,
          location: file.rel, line: i + 1, evidence: redactLine(line), detail: rule.detail, remediation: rule.remediation,
        });
      }
    });
  }

  return findings;
}
