// Data-flow (taint) tracking: request input followed through variables to
// dangerous calls, and every guard that keeps it from crying wolf.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCode } from "../src/scanners/code.ts";
import { lexStrip } from "../src/scanners/taint.ts";
import type { ScanFile } from "../src/util/walk.ts";
import type { Finding } from "../src/types.ts";

const file = (rel: string, text: string): ScanFile => ({ path: rel, rel, text, lines: text.split("\n") });
const scan = (rel: string, text: string) => scanCode([file(rel, text)]);
const rules = (fs: Finding[]) => fs.map((f) => f.rule).sort();
const has = (fs: Finding[], rule: string, line?: number) => fs.some((f) => f.rule === rule && (line === undefined || f.line === line));

test("lexing: plain string text is dropped, interpolations are kept as code", () => {
  assert.equal(lexStrip(`x = "request.args"`, "py"), "x = ''");
  assert.match(lexStrip(`q = f"SELECT {name} FROM t"`, "py"), /\(name\)/);
  assert.match(lexStrip("q = `SELECT ${id}`", "js"), /\(id\)/);
  assert.match(lexStrip(`$q = "WHERE id = '$id'";`, "php"), /\$id/, "PHP double quotes interpolate");
  assert.doesNotMatch(lexStrip(`$q = 'WHERE id = $id';`, "php"), /\$id/, "PHP single quotes do not");
  assert.equal(lexStrip("a = b // 2", "py"), "a = b // 2", "in Python // is division, not a comment");
});

test("php: input copied into a variable and then into SQL two steps later is caught, with its origin", () => {
  const fs = scan("u.php", "<?php\n$id = $_GET['id'];\n$sql = \"SELECT * FROM users WHERE id = '$id'\";\nmysqli_query($db, $sql);");
  const f = fs.find((x) => x.rule === "code.php.sql-injection");
  assert.ok(f, "SQL injection should be reported");
  assert.equal(f!.line, 4);
  assert.match(f!.detail, /line 2/, "the finding names the line where the input came in");
});

test("php: sanitisers and numeric casts make the value clean", () => {
  assert.deepEqual(rules(scan("a.php", "<?php\n$id = intval($_GET['id']);\nmysqli_query($db, \"SELECT 1 WHERE id = $id\");")), []);
  assert.deepEqual(rules(scan("b.php", "<?php\n$n = (int) $_GET['n'];\n$pdo->query(\"SELECT 1 LIMIT $n\");")), []);
  assert.deepEqual(rules(scan("c.php", "<?php\n$t = $_POST['t'];\n$o = shell_exec('ping ' . escapeshellarg($t));")), []);
});

test("php: a validating if protects the call, but its else branch does not", () => {
  const guarded = "<?php\n$ip = $_POST['ip'];\nif (filter_var($ip, FILTER_VALIDATE_IP)) {\n  shell_exec('ping ' . $ip);\n}";
  assert.ok(!has(scan("g.php", guarded), "code.php.command-injection"));
  const elseBranch = "<?php\n$ip = $_POST['ip'];\nif (filter_var($ip, FILTER_VALIDATE_IP)) {\n  echo 'ok';\n} else {\n  shell_exec('ping ' . $ip);\n}";
  assert.ok(has(scan("e.php", elseBranch), "code.php.command-injection", 6));
});

test("php: a check on what the value was built from counts (validated octets rebuilt into an IP)", () => {
  const src = [
    "<?php",
    "$target = $_REQUEST['ip'];",
    "$octet = explode('.', $target);",
    "if (is_numeric($octet[0]) && is_numeric($octet[1]) && is_numeric($octet[2]) && is_numeric($octet[3])) {",
    "  $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];",
    "  shell_exec('ping ' . $target);",
    "}",
  ].join("\n");
  assert.ok(!has(scan("ip.php", src), "code.php.command-injection"));
});

test("php: failing validation that exits early protects what follows", () => {
  const src = "<?php\n$p = $_GET['p'];\nif (!in_array($p, ['home', 'about'], true)) { exit; }\ninclude($p . '.php');";
  assert.ok(!has(scan("x.php", src), "code.php.file-inclusion"));
});

test("php: including a variable that is set in another file is a medium lead", () => {
  const f = scan("i.php", "<?php\nrequire_once 'source/level.php';\ninclude($file);").find((x) => x.rule === "code.php.file-inclusion");
  assert.equal(f?.severity, "medium");
  assert.match(f!.detail, /another file/);
  assert.ok(!has(scan("j.php", "<?php\nforeach ($parts as $part) { include($part); }"), "code.php.file-inclusion"), "a loop variable is local");
});

test("python: multi-line f-string SQL and multi-line shell=True calls are followed", () => {
  const sql = scan("v.py", "def v(request):\n    u = request.POST.get('u')\n    q = (\n        f\"SELECT * FROM a WHERE n = '{u}'\"\n    )\n    cur.execute(q)");
  assert.ok(has(sql, "code.py.sql-injection", 6));
  const sh = scan("s.py", "def s(request):\n    h = request.GET['h']\n    c = f\"dig {h}\"\n    subprocess.Popen(\n        c, shell=True\n    )");
  assert.ok(has(sh, "code.py.subprocess-shell", 4));
});

test("python: parameterised queries, argument lists and validated values are left alone", () => {
  assert.deepEqual(rules(scan("p.py", "def p(request):\n    uid = request.GET.get('id')\n    cur.execute(\"SELECT * FROM u WHERE id = %s\", (uid,))")), []);
  assert.deepEqual(rules(scan("l.py", "def l(request):\n    h = request.GET['h']\n    subprocess.run(['ping', '-c', '1', h])")), []);
  assert.deepEqual(rules(scan("d.py", "def d(request):\n    n = request.GET['n']\n    if n.isdigit():\n        os.system('sleep ' + n)")), [], "the line rule is resolved too");
  assert.deepEqual(rules(scan("i.py", "def i(request):\n    n = int(request.GET['n'])\n    os.system('sleep ' + str(n))")), [], "a sanitised value resolves the line rule");
});

test("python: each function starts clean", () => {
  const src = "def a(request):\n    cmd = request.GET['c']\n    return cmd\n\ndef b():\n    out = subprocess.getoutput(cmd)";
  assert.ok(!has(scan("f.py", src), "code.py.subprocess-shell"));
});

test("javascript: destructured input reaching an outbound request is SSRF; a fixed host is not", () => {
  const bad = "app.get('/f', async (req, res) => {\n  const { url } = req.query;\n  await axios.get(url);\n});";
  assert.ok(has(scan("a.js", bad), "code.js.ssrf", 3));
  const fixedHost = "app.get('/u', async (req, res) => {\n  const id = req.params.id;\n  await fetch(`${API}/users/${id}`);\n  res.redirect(`/profile/${id}`);\n});";
  assert.deepEqual(rules(scan("b.js", fixedHost)), [], "a path segment is not SSRF, and a relative redirect is not open");
});

test("javascript: browser input only counts for browser sinks", () => {
  const dom = "const q = location.hash.slice(1);\nel.innerHTML = q;\ndb.query(q);";
  const fs = scan("c.js", dom);
  const xss = fs.find((f) => f.rule === "code.js.xss");
  assert.ok(xss && xss.severity === "high", "location.hash into innerHTML is DOM XSS");
  assert.ok(!has(fs, "code.js.sql-injection"), "a browser value is not server-side SQL");
});

test("javascript: NoSQL injection is only judged in files that use MongoDB", () => {
  const body = "app.post('/l', async (req, res) => {\n  const { user } = req.body;\n  await Users.findOne({ user });\n});";
  assert.ok(has(scan("m.js", "const mongoose = require('mongoose');\n" + body), "code.js.nosql-injection"));
  assert.ok(!has(scan("p.js", "import { PrismaClient } from '@prisma/client';\n" + body), "code.js.nosql-injection"));
});

test("reviewed lines and comments are never reported", () => {
  const src = "<?php\n$ip = $_POST['ip'];\n// shell_exec('ping ' . $ip);\nshell_exec('ping ' . $ip); // lucent-ignore: lab exercise";
  assert.deepEqual(rules(scan("r.php", src)), []);
});
