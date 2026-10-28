// Follows request input through variables to dangerous calls ("taint
// tracking") inside one file. The line rules only see input used in the same
// expression where it arrives. Real code almost always copies it into a
// variable first, and often builds a second variable from that:
//
//   $id = $_GET['id'];
//   $query = "SELECT * FROM users WHERE id = '$id'";
//   mysqli_query($db, $query);                 <- reported here
//
// The pass is deliberately conservative, so a hit is a strong lead:
//   - values passed through a sanitiser (intval, int(), escapeshellarg,
//     encodeURIComponent and similar) are clean;
//   - for SQL and shell calls only the query or command argument is checked,
//     so parameterised queries and argument lists are left alone;
//   - outbound requests and redirects are reported only when the request
//     controls the start of the address, not just a path segment;
//   - a variable that is reassigned to a clean value is clean again, and
//     each named function starts with nothing tainted.

export type TaintLang = "php" | "py" | "js";

/** A call where request input arrives but was proven sanitised or validated first. */
export interface TaintClear { rule: string; line: number; end: number }

export interface TaintResult { hits: TaintHit[]; cleared: TaintClear[] }

export interface TaintHit {
  rule: string;
  /** Zero-based line where the dangerous call starts. */
  line: number;
  /** Zero-based last line of that statement. */
  end: number;
  /** Zero-based line where the request input entered, or -1 when it comes from another file. */
  origin: number;
  /** A severity to use instead of the rule's own. */
  severity?: "critical" | "high" | "medium" | "low";
}

interface Origin { line: number; dom: boolean; prefix: boolean }

interface Sink {
  re: RegExp;
  rule: string;
  /** Which part to inspect: the first argument, every argument, or the rest of the statement. */
  arg: "first" | "all" | "rest";
  /** The whole call must also match this (for example shell=True). */
  when?: RegExp;
  /** Only in files that match this (for example ones that use MongoDB). */
  fileHas?: RegExp;
  /** The request must control the start of the value (outbound URLs, redirects). */
  needPrefix?: boolean;
  /** The argument must build text, not pass a value or object through. */
  textArg?: boolean;
  /** Browser sources (location, document.cookie) count for this sink. */
  dom?: boolean;
  /** A severity to use instead of the rule's own. */
  severity?: TaintHit["severity"];
}

interface Cfg {
  source: RegExp;
  domSource?: RegExp;
  sanitizer: RegExp;
  assign: RegExp;
  destructure?: RegExp;
  ref: (name: string) => string;
  scope?: RegExp;
  sinks: Sink[];
}

const esc = (s: string) => s.replace(/[$]/g, "\\$");

// ================================ PHP ======================================
const PHP: Cfg = {
  source: /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*["'](?:HTTP_\w+|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO)["']|php:\/\/input/,
  sanitizer: /(?<![\w>:$])(?:intval|floatval|boolval|filter_var|filter_input|mysqli_real_escape_string|mysql_real_escape_string|real_escape_string|pg_escape_string|pg_escape_literal|escapeshellarg|escapeshellcmd|basename|htmlspecialchars|htmlentities|ctype_digit|ctype_alnum|is_numeric|in_array|md5|sha1|hash|password_hash|count|strlen|preg_match)\s*\(|->(?:quote|real_escape_string|escape_string)\s*\(/g,
  assign: /^\s*\$(\w+)\s*(\.=|=(?![=>]))\s*([\s\S]+)$/,
  ref: (n) => String.raw`\$${n}\b`,
  scope: /\bfunction\s+\w+\s*\(/,
  sinks: [
    { re: /(?<![\w>:$])(?:mysqli_query|mysql_query|mysqli_multi_query|mysqli_real_query|pg_query|pg_send_query|sqlsrv_query|odbc_exec|sqlite_query)\s*\(/g, rule: "code.php.sql-injection", arg: "all" },
    { re: /->\s*(?:query|exec|multi_query|real_query)\s*\(/g, rule: "code.php.sql-injection", arg: "first" },
    { re: /(?<![\w>:$])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/g, rule: "code.php.command-injection", arg: "first" },
    { re: /(?<![\w>:$])(?:include|require)(?:_once)?\b/g, rule: "code.php.file-inclusion", arg: "rest" },
    { re: /(?<![\w>:$])(?:eval|assert)\s*\(/g, rule: "code.php.eval", arg: "first" },
    { re: /(?<![\w>:$])unserialize\s*\(/g, rule: "code.php.unsafe-deserialize", arg: "first" },
    { re: /(?<![\w>:$])(?:file_get_contents|fopen|readfile|file|unlink|file_put_contents|show_source|highlight_file)\s*\(/g, rule: "code.php.path-traversal", arg: "first" },
    { re: /(?<![\w>:$])curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,/g, rule: "code.php.ssrf", arg: "rest", needPrefix: true },
    { re: /(?<![\w>:$])header\s*\(\s*"Location:\s*/g, rule: "code.php.open-redirect", arg: "rest", needPrefix: true },
    { re: /(?<![\w>:$])(?:echo|print)\b/g, rule: "code.php.xss", arg: "rest", textArg: false },
  ],
};

// =============================== Python ====================================
const PY: Cfg = {
  source: /\brequest\.(?:GET|POST|args|form|values|json|data|files|FILES|COOKIES|cookies|headers|META|query_params|body|get_json)\b/,
  sanitizer: /(?<![\w.])(?:int|float|bool|escape|quote|quote_plus|secure_filename|UUID)\s*\(|\b(?:shlex\.quote|html\.escape|re\.escape|bleach\.clean|os\.path\.basename|markupsafe\.escape|urllib\.parse\.quote(?:_plus)?|validators\.\w+)\s*\(/g,
  assign: /^\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?(\+=|=(?!=))\s*([\s\S]+)$/,
  ref: (n) => String.raw`(?<![\w.])${n}(?!\w)`,
  scope: /^\s*(?:async\s+)?def\s+\w+\s*\(/,
  sinks: [
    { re: /\.(?:execute|executemany|executescript|raw|extra)\s*\(/g, rule: "code.py.sql-injection", arg: "first" },
    { re: /\bRawSQL\s*\(/g, rule: "code.py.sql-injection", arg: "first" },
    { re: /\bos\.(?:system|popen)\s*\(/g, rule: "code.py.os-system", arg: "first" },
    { re: /\bsubprocess\.(?:Popen|call|run|check_output|check_call)\s*\(/g, rule: "code.py.subprocess-shell", arg: "first", when: /\bshell\s*=\s*True\b/ },
    { re: /\bsubprocess\.(?:getoutput|getstatusoutput)\s*\(/g, rule: "code.py.subprocess-shell", arg: "first" },
    { re: /(?<![\w.])(?:render_template_string|from_string)\s*\(|(?<![\w.])Template\s*\(/g, rule: "code.py.ssti", arg: "first" },
    { re: /(?<![\w.])(?:eval|exec)\s*\(/g, rule: "code.py.eval", arg: "first" },
    { re: /\b(?:pickle|cPickle|dill|marshal|jsonpickle)\.(?:loads?|decode)\s*\(|\byaml\.(?:load|unsafe_load)\s*\(/g, rule: "code.py.unsafe-deserialize", arg: "first" },
    { re: /\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|stream)\s*\(|\burllib\.request\.urlopen\s*\(|(?<![\w.])urlopen\s*\(/g, rule: "code.py.ssrf", arg: "first", needPrefix: true },
    { re: /(?<![\w.])open\s*\(|(?<![\w.])send_file\s*\(|\bos\.(?:remove|unlink|rmdir)\s*\(|\bshutil\.(?:rmtree|copy|copyfile|move)\s*\(/g, rule: "code.py.path-traversal", arg: "first" },
    { re: /(?<![\w.])(?:redirect|HttpResponseRedirect)\s*\(/g, rule: "code.py.open-redirect", arg: "first", needPrefix: true },
    { re: /(?<![\w.])(?:mark_safe|Markup|SafeString)\s*\(/g, rule: "code.py.xss", arg: "first" },
    { re: /(?<![\w.])HttpResponse\s*\(/g, rule: "code.py.xss", arg: "first", textArg: true },
  ],
};

// ========================= JavaScript / TypeScript =========================
const JS: Cfg = {
  source: /\b(?:req|request)\.(?:query|body|params|headers|cookies|signedCookies|files?)\b|\bctx\.(?:query|params|request\.(?:body|query))\b/,
  domSource: /\blocation\.(?:search|hash|href)\b|\bdocument\.(?:URL|documentURI|referrer|cookie)\b|\bwindow\.name\b/,
  sanitizer: /(?<![\w$.])(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escape|escapeHtml|escapeRegExp|sanitize\w*|xss|mongoSanitize)\s*\(|\b(?:DOMPurify\.sanitize|validator\.\w+|path\.basename|sqlstring\.escape|mysql\.escape|connection\.escape|pool\.escape|db\.escape)\s*\(/g,
  assign: /^\s*(?:export\s+)?(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>[\]|. ]+\s*)?(\+=|=(?![=>]))\s*([\s\S]+)$/,
  destructure: /^\s*(?:export\s+)?(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*([\s\S]+)$/,
  ref: (n) => String.raw`(?<![\w$.])${esc(n)}(?![\w$])`,
  scope: /\bfunction\s+[\w$]+\s*\(/,
  sinks: [
    { re: /\.(?:query|execute|raw|unsafe)\s*\(|\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(/g, rule: "code.js.sql-injection", arg: "first" },
    { re: /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\s*\(/g, rule: "code.js.nosql-injection", arg: "first", fileHas: /require\(\s*["'](?:mongoose|mongodb)["']\)|from\s+["'](?:mongoose|mongodb)["']/ },
    { re: /(?<![\w$.])(?:exec|execSync)\s*\(|\b(?:child_process|cp|childProcess)\.(?:exec|execSync)\s*\(/g, rule: "code.js.command-injection", arg: "first" },
    { re: /\bspawn(?:Sync)?\s*\(/g, rule: "code.js.command-injection", arg: "first", when: /\bshell\s*:\s*true\b/ },
    { re: /\b(?:axios|got|needle|superagent|request|http|https|undici)\.(?:get|post|put|patch|delete|head|request|options)\s*\(|(?<![\w$.])(?:fetch|axios|got|needle|request|superagent)\s*\(/g, rule: "code.js.ssrf", arg: "first", needPrefix: true },
    { re: /\bfs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|readdir|readdirSync)\s*\(|\bres\.(?:sendFile|download)\s*\(/g, rule: "code.js.path-traversal", arg: "first" },
    { re: /\bres\.redirect\s*\(/g, rule: "code.js.open-redirect", arg: "all", needPrefix: true },
    { re: /(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|runInContext)\s*\(/g, rule: "code.js.eval", arg: "first", dom: true },
    { re: /\.(?:innerHTML|outerHTML)\s*\+?=|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(/g, rule: "code.js.xss", arg: "rest", dom: true, severity: "high" },
    { re: /\bres\.(?:send|write|end)\s*\(/g, rule: "code.js.xss", arg: "first", textArg: true, severity: "medium" },
  ],
};

const CFG: Record<TaintLang, Cfg> = { php: PHP, py: PY, js: JS };

// Checks that validate a value's content (not just that it is present).
const VALIDATOR: Record<TaintLang, RegExp> = {
  php: /(?<![\w>:$])(?:is_numeric|is_int|ctype_digit|ctype_alnum|ctype_alpha|filter_var|preg_match|in_array|checkdate)\s*\(/,
  py: /\b(?:re\.(?:match|fullmatch)|validators\.\w+|ipaddress\.ip_\w+)\s*\(|\.(?:isdigit|isalnum|isnumeric|isdecimal|isalpha)\s*\(/,
  js: /\b(?:Number\.isInteger|Number\.isSafeInteger|validator\.is\w+|isValid\w*|isUUID)\s*\(|\.test\s*\(|\.includes\s*\(|\.has\s*\(/,
};
const EXITS = /\b(?:exit|die|return|throw|raise|abort|continue|break)\b/;

// ------------------------------- lexing ------------------------------------

/** Text inside interpolations: f"..{x}.." or `..${x}..`, in order, as code pieces. */
function pieces(body: string, open: "{" | "${"): string[] {
  const out: string[] = [];
  let lit = false;
  for (let i = 0; i < body.length; ) {
    if (open === "{" && body.startsWith("{{", i)) { lit = true; i += 2; continue; }
    if (body.startsWith(open, i)) {
      let depth = 1, j = i + open.length;
      for (; j < body.length && depth > 0; j++) {
        if (body[j] === "{") depth++;
        else if (body[j] === "}") depth--;
      }
      if (lit) out.push("''");
      lit = false;
      out.push("(" + body.slice(i + open.length, j - 1) + ")");
      i = j;
      continue;
    }
    lit = true;
    i++;
  }
  if (lit) out.push("''");
  return out.length ? out : ["''"];
}

/**
 * Removes the text of string literals so that words inside them are never
 * mistaken for code, while keeping what interpolates: PHP "double-quoted"
 * strings stay as they are, and f-strings or template literals become their
 * interpolated expressions joined with "+", in order.
 */
export function lexStrip(s: string, lang: TaintLang): string {
  let out = "";
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    // Comments to the end of the line (code outside strings only).
    if (startsComment(s, i, lang)) {
      const nl = s.indexOf("\n", i);
      i = nl === -1 ? s.length : nl;
      continue;
    }
    if (c !== '"' && c !== "'" && c !== "`") { out += c; i++; continue; }

    if (lang === "py") {
      const pre = /(?:^|[^\w])([rRbBuUfF]{1,2})$/.exec(out)?.[1] ?? "";
      const isF = /[fF]/.test(pre);
      if (pre) out = out.slice(0, out.length - pre.length);
      const q = s.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      let j = i + q.length, body = "";
      while (j < s.length && !s.startsWith(q, j)) {
        if (s[j] === "\\") { body += s.slice(j, j + 2); j += 2; continue; }
        if (q.length === 1 && s[j] === "\n") break;
        body += s[j++];
      }
      out += isF ? pieces(body, "{").join(" + ") : "''";
      i = j + q.length;
      continue;
    }
    if (c === "`" && lang === "js") {
      let j = i + 1, body = "", depth = 0;
      while (j < s.length && (s[j] !== "`" || depth > 0)) {
        if (s[j] === "\\") { body += s.slice(j, j + 2); j += 2; continue; }
        if (s.startsWith("${", j)) depth++;
        else if (s[j] === "}" && depth > 0) depth--;
        body += s[j++];
      }
      out += pieces(body, "${").join(" + ");
      i = j + 1;
      continue;
    }
    if (c === '"' && lang === "php") {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === "\\" ? 2 : 1;
      out += s.slice(i, j + 1); // variables interpolate, so keep the text
      i = j + 1;
      continue;
    }
    let j = i + 1;
    while (j < s.length && s[j] !== c && !(s[j] === "\n" && c !== "`")) j += s[j] === "\\" ? 2 : 1;
    out += "''";
    i = j + 1;
  }
  return out;
}

/** A line comment starts here: # in Python and PHP, // in PHP and JavaScript (in Python // is division). */
function startsComment(s: string, i: number, lang: TaintLang): boolean {
  if (s[i] === "#") return lang !== "js";
  return s[i] === "/" && s[i + 1] === "/" && lang !== "py";
}

/** Open brackets and whether the text ends inside a string, so a statement can continue. */
function openState(s: string, lang: TaintLang): { depth: number; inString: boolean } {
  let depth = 0;
  let q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === "\\") { i++; continue; }
      if (q.length === 3 ? s.startsWith(q, i) : c === q) { i += q.length - 1; q = null; }
      else if (c === "\n" && q.length === 1 && q !== "`" && !(lang === "php" && q === '"')) q = null;
      continue;
    }
    if (startsComment(s, i, lang)) {
      const nl = s.indexOf("\n", i);
      if (nl === -1) break;
      i = nl;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      q = lang === "py" && s.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
      i += q.length - 1;
      continue;
    }
    if (c === "(" || c === "[") depth++;
    else if ((c === ")" || c === "]") && depth > 0) depth--;
  }
  return { depth, inString: q !== null };
}

/** Line i joined with the lines that continue its statement. */
function statementAt(lines: string[], i: number, lang: TaintLang): { text: string; end: number } {
  let text = lines[i];
  let end = i;
  for (let n = 0; n < 12 && end + 1 < lines.length && text.length < 4000; n++) {
    const st = openState(text, lang);
    // Judge the trailing operator on code only, so "http://" in a string is not read as a comment.
    const last = st.inString ? "" : lexStrip(lines[end], lang).trimEnd();
    const continues = st.depth > 0 || st.inString || (/(?:[=+.(,?]|&&|\|\||\\)$/.test(last) && !/=>$/.test(last));
    if (!continues) break;
    end++;
    text += "\n" + lines[end];
  }
  return { text, end };
}

/** End of the bracket group that opens at `open`, or of the first argument inside it. */
function argText(s: string, open: number, mode: "first" | "all"): string {
  let depth = 0, q: string | null = null, i = open;
  for (; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === "\\") i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === "`") { q = c; continue; }
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") { depth--; if (depth === 0) break; }
    else if (c === "," && depth === 1 && mode === "first") break;
  }
  return s.slice(open + 1, i);
}

function restText(s: string, from: number): string {
  let depth = 0, q: string | null = null, i = from;
  for (; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === "\\") i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === "`") { q = c; continue; }
    if (c === "(" || c === "[") depth++;
    else if (c === ")" || c === "]") { if (depth === 0) break; depth--; }
    else if (c === ";" && depth === 0) break;
  }
  return s.slice(from, i);
}

/** Replaces sanitiser calls (and everything inside them) with a constant. */
function dropSanitised(expr: string, re: RegExp): string {
  // Numeric casts in PHP: (int)$x, (float) $_GET['n'].
  let out = expr.replace(/\(\s*(?:int|integer|float|double|bool|boolean)\s*\)\s*(?:\$\w+(?:\s*\[[^\]]*\])*|[\w$]+\s*\([^)]*\))/g, "0");
  for (let n = 0; n < 20; n++) {
    re.lastIndex = 0;
    const m = re.exec(out);
    if (!m) break;
    const open = m.index + m[0].lastIndexOf("(");
    const inner = argText(out, open, "all");
    out = out.slice(0, m.index) + "0" + out.slice(open + 1 + inner.length + 1);
  }
  return out;
}

// ------------------------------- guards ------------------------------------

const indentOf = (s: string) => (/^\s*/.exec(s)?.[0] ?? "").replace(/\t/g, "    ").length;

/** True when `cond` validates one of the variables (or the raw input) the sink depends on. */
function validates(cond: string, chain: string[], cfg: Cfg, lang: TaintLang, viaSource: boolean): boolean {
  if (!cond.trim()) return false;
  const hasValidator = VALIDATOR[lang].test(cond);
  for (const name of chain) {
    const ref = cfg.ref(name);
    if (hasValidator && new RegExp(ref).test(cond)) return true;
    // A comparison with a fixed value is an allow list: $ext == 'jpg', x === "a".
    if (new RegExp(ref + String.raw`\s*\)?\s*(?:===?|!==?)\s*(?:['"\d]|true\b|false\b|null\b|None\b)`).test(cond)) return true;
    if (lang === "py" && new RegExp(ref + String.raw`\s+(?:not\s+)?in\s+`).test(cond)) return true;
  }
  return viaSource && hasValidator && cfg.source.test(cond);
}

/** Conditions of the if-blocks that enclose line i (not else branches, which are the failure path). */
function enclosingConditions(lines: string[], i: number, lang: TaintLang, cfg: Cfg): string[] {
  const out: string[] = [];
  if (lang === "py") {
    let cur = indentOf(lines[i]);
    for (let j = i - 1, n = 0; j >= 0 && n < 80 && cur > 0; j--, n++) {
      const t = lines[j].trim();
      if (!t || t.startsWith("#")) continue;
      const d = indentOf(lines[j]);
      if (d >= cur) continue;
      cur = d;
      if (/^(?:async\s+)?def\b|^class\b/.test(t)) break;
      if (/^(?:if|elif)\b/.test(t)) out.push(lexStrip(t, lang));
    }
    return out;
  }
  let depth = 0;
  for (let j = i - 1, n = 0; j >= 0 && n < 80; j--, n++) {
    if (cfg.scope && cfg.scope.test(lines[j])) break;
    const code = lexStrip(lines[j], lang);
    for (let k = code.length - 1; k >= 0; k--) {
      if (code[k] === "}") depth++;
      else if (code[k] === "{") {
        if (depth > 0) { depth--; continue; }
        // This "{" opens a block around line i: collect its header, which may span lines.
        let head = code.slice(0, k);
        for (let s = j - 1; s >= 0 && j - s <= 6 && !/\b(?:if|elseif|else|while|for|foreach|switch|function|try|catch)\b/.test(head); s--) {
          head = lexStrip(lines[s], lang) + "\n" + head;
        }
        const own = head.slice(head.lastIndexOf("}") + 1);
        if (!/\belse\b(?!\s*if)/.test(own)) out.push(own);
      }
    }
  }
  return out;
}

/** An earlier "if (!valid(x)) exit/return" in the same function. */
function earlyExitGuard(lines: string[], i: number, lang: TaintLang, cfg: Cfg, chain: string[], viaSource: boolean): boolean {
  for (let j = i - 1, n = 0; j >= 0 && n < 40; j--, n++) {
    const line = lines[j];
    if (cfg.scope && cfg.scope.test(line)) break;
    const code = lexStrip(line, lang);
    const negated = lang === "py" ? /^\s*(?:if|elif)\s+not\b|\bnot\s+in\b/.test(code) : /\bif\s*\(\s*!|\bif\s*\(.*(?:===?\s*false|!==?)/.test(code);
    if (!negated || !validates(code, chain, cfg, lang, viaSource)) continue;
    const body = lines.slice(j, Math.min(lines.length, j + 4)).map((l) => lexStrip(l, lang)).join("\n");
    if (EXITS.test(body)) return true;
  }
  return false;
}

// ------------------------------- tracing -----------------------------------

/**
 * Traces request input to dangerous calls in one file. `skip(i)` says whether
 * line i should be ignored (comments, reviewed suppressions, huge lines).
 */
export function traceTaint(lines: string[], lang: TaintLang, fileText: string, skip: (i: number) => boolean): TaintResult {
  const cfg = CFG[lang];
  const includesVariable = lang === "php" && /\b(?:include|require)(?:_once)?\b\s*\(?\s*\$\w+\s*\)?\s*;/.test(fileText);
  if (!cfg.source.test(fileText) && !(cfg.domSource && cfg.domSource.test(fileText)) && !includesVariable) return { hits: [], cleared: [] };

  const sinks = cfg.sinks.filter((s) => !s.fileHas || s.fileHas.test(fileText));
  const tainted = new Map<string, Origin>();
  // The tainted variables each one was built from, so a check on any of them counts.
  const lineage = new Map<string, Set<string>>();
  // PHP: variables given a value somewhere in this file (assignments, loop
  // variables, parameters). An include of a variable that is never set here
  // was set in another file, so its source cannot be checked from this one.
  const localPhp = new Set<string>();
  if (lang === "php") {
    for (const m of fileText.matchAll(/\$(\w+)\s*(?:\.=|=(?![=>]))|\bas\s+(?:\$\w+\s*=>\s*)?\$(\w+)|\bfunction\s*[\w&]*\s*\(([^)]*)\)/g)) {
      if (m[1]) localPhp.add(m[1]);
      if (m[2]) localPhp.add(m[2]);
      if (m[3]) for (const p of m[3].matchAll(/\$(\w+)/g)) localPhp.add(p[1]);
    }
  }
  const hits: TaintHit[] = [];
  const cleared: TaintClear[] = [];
  const seen = new Set<string>();
  // Variables that came from request input but were sanitised on the way (x = int(request.GET["n"])).
  const madeSafe = new Set<string>();

  const refRe = (n: string, start = false) => new RegExp((start ? "^" : "") + cfg.ref(n));
  const sourceAt = (expr: string, i: number, start: boolean): Origin | null => {
    const m = cfg.source.exec(expr);
    if (m && (!start || m.index === 0)) return { line: i, dom: false, prefix: m.index === 0 };
    if (cfg.domSource) {
      const d = cfg.domSource.exec(expr);
      if (d && (!start || d.index === 0)) return { line: i, dom: true, prefix: d.index === 0 };
    }
    return null;
  };

  /** Tainted variables an expression uses (after removing sanitised parts). */
  const usedIn = (expr: string): string[] => [...tainted.keys()].filter((n) => refRe(n).test(expr));

  /** The raw expression carries request input somewhere, sanitised or not. */
  const touchesRequest = (raw: string, i: number): boolean =>
    !!sourceAt(raw, i, false) || usedIn(raw).length > 0 || [...madeSafe].some((n) => refRe(n).test(raw));

  /** Where the expression carries request input, if it does. */
  const taintOf = (raw: string, i: number): Origin | null => {
    const expr = dropSanitised(raw, cfg.sanitizer);
    const direct = sourceAt(expr, i, false);
    if (direct) return direct;
    let found: Origin | null = null;
    for (const name of usedIn(expr)) {
      const o = tainted.get(name)!;
      if (!o.dom) return o;
      found ??= o;
    }
    return found;
  };

  /** True when the request controls the very start of the value. */
  const prefixOf = (raw: string, i: number): boolean => {
    let e = dropSanitised(raw, cfg.sanitizer).trimStart();
    for (let n = 0; n < 6; n++) {
      const peel = /^(?:\(|await\s+|new\s+URL\s*\(|String\s*\(|str\s*\(|f?["`])/.exec(e);
      if (!peel) break;
      e = e.slice(peel[0].length).trimStart();
    }
    if (sourceAt(e, i, true)) return true;
    for (const [name, o] of tainted) if (o.prefix && refRe(name, true).test(e)) return true;
    return false;
  };

  /** The variables a sink argument depends on, including what they were built from. */
  const chainOf = (raw: string): string[] => {
    const out = new Set<string>();
    for (const n of usedIn(dropSanitised(raw, cfg.sanitizer))) {
      out.add(n);
      for (const a of lineage.get(n) ?? []) out.add(a);
    }
    return [...out];
  };

  const guarded = (i: number, codeBefore: string, arg: string): boolean => {
    const chain = chainOf(arg);
    const viaSource = cfg.source.test(dropSanitised(arg, cfg.sanitizer));
    const conds = [codeBefore, ...enclosingConditions(lines, i, lang, cfg)];
    if (conds.some((c) => validates(c, chain, cfg, lang, viaSource))) return true;
    return earlyExitGuard(lines, i, lang, cfg, chain, viaSource);
  };

  for (let i = 0; i < lines.length; i++) {
    if (skip(i)) continue;
    const line = lines[i];
    if (cfg.scope && cfg.scope.test(line)) { tainted.clear(); lineage.clear(); madeSafe.clear(); }

    const { text, end } = statementAt(lines, i, lang);
    const code = lexStrip(text, lang);
    const firstLen = (() => { const nl = code.indexOf("\n"); return nl === -1 ? code.length : nl; })();

    // 1) Sinks that start on this line, judged with what is tainted so far.
    for (const sink of sinks) {
      sink.re.lastIndex = 0;
      for (let m = sink.re.exec(code); m; m = sink.re.exec(code)) {
        if (m.index >= firstLen) break;
        const after = m.index + m[0].length;
        const isCall = m[0].trimEnd().endsWith("(");
        const arg = sink.arg === "rest" || !isCall ? restText(code, after) : argText(code, after - 1, sink.arg);
        if (sink.when && !sink.when.test(isCall ? argText(code, after - 1, "all") : arg)) continue;
        if (sink.textArg && !/['"`]/.test(arg)) continue;
        const key = `${sink.rule}:${i}`;
        if (seen.has(key)) continue;
        const origin = taintOf(arg, i);
        if (!origin) {
          // Request input does reach here, but only through a sanitiser.
          if (touchesRequest(arg, i)) cleared.push({ rule: sink.rule, line: i, end });
          // include $page where $page was set in another file: a lead worth confirming.
          const v = sink.rule === "code.php.file-inclusion" ? /^\s*\(?\s*\$(\w+)\s*\)?\s*$/.exec(arg) : null;
          if (v && !localPhp.has(v[1]) && !/^(?:this|GLOBALS)$/.test(v[1])) {
            seen.add(key);
            hits.push({ rule: sink.rule, line: i, end, origin: -1, severity: "medium" });
          }
          continue;
        }
        if (origin.dom && !sink.dom) continue;
        if (sink.needPrefix && !prefixOf(arg, i)) continue;
        if (guarded(i, code.slice(0, m.index), arg)) { cleared.push({ rule: sink.rule, line: i, end }); continue; }
        seen.add(key);
        hits.push({ rule: sink.rule, line: i, end, origin: origin.line, severity: sink.severity });
      }
    }

    // 2) Assignments update what is tainted from here on.
    const d = cfg.destructure?.exec(code);
    if (d) {
      const origin = taintOf(d[2], i);
      const from = chainOf(d[2]);
      for (const part of d[1].split(",")) {
        const name = (part.includes(":") ? part.split(":")[1] : part).replace(/=.*/s, "").replace(/^\s*\.\.\./, "").trim();
        if (!/^[A-Za-z_$][\w$]*$/.test(name)) continue;
        if (origin) { tainted.set(name, { ...origin, prefix: true }); lineage.set(name, new Set(from)); }
        else { tainted.delete(name); lineage.delete(name); }
      }
      continue;
    }
    const a = cfg.assign.exec(code);
    if (a) {
      const [, name, op, rhs] = a;
      const origin = taintOf(rhs, i);
      if (!origin && op === "=" && touchesRequest(rhs, i)) madeSafe.add(name);
      else if (op === "=" || origin) madeSafe.delete(name);
      if (origin) {
        const prev = tainted.get(name);
        const append = op !== "=";
        const prefix = append ? prev?.prefix ?? false : prefixOf(rhs, i);
        const from = new Set(chainOf(rhs));
        if (append && prev) { from.add(name); for (const x of lineage.get(name) ?? []) from.add(x); }
        from.delete(name);
        if (!append) for (const x of chainOf(rhs)) if (x === name) for (const y of lineage.get(name) ?? []) from.add(y);
        tainted.set(name, { line: append && prev ? prev.line : origin.line, dom: origin.dom, prefix });
        lineage.set(name, from);
      } else if (op === "=") {
        tainted.delete(name);
        lineage.delete(name);
      }
    }
  }
  return { hits, cleared };
}
