// A deliberately vulnerable test project. Every planted issue lists the rule
// Lucent Shield should report for it, and the "decoy" files hold look-alike
// code that is safe and must NOT be reported. Secrets are assembled at
// runtime so no real-looking credential is ever stored in this repository.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface Expect { rule: string; file: string; start: number; end: number }

const j = (...p: string[]) => p.join("");
const rep = (c: string, n: number) => c.repeat(n);

export function buildFixture(root: string): { expected: Expect[]; decoys: string[] } {
  const expected: Expect[] = [];
  const files: Record<string, string> = {};
  const add = (file: string, body: string, ...rules: string[]) => {
    const before = files[file] ?? "";
    const start = before ? before.split("\n").length : 1;
    const end = start + body.split("\n").length - 1;
    files[file] = before + body + "\n";
    for (const rule of rules) expected.push({ rule, file, start, end });
  };

  // ---------------- secrets ----------------
  add("config/aws.js", `const key = "${j("AKIA", "Q3R7NV2KZ7KD2M4W")}";`, "secret.aws-access-key");
  add("config/aws.js", `aws_secret_access_key = "${j("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYzq8Rk2mQ7v")}"`, "secret.aws-secret-key");
  add("keys/id_rsa", j("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"), "secret.private-key");
  add("pay/stripe.js", `const s = "${j("sk_", "live_", "51HxQ2bD9kLm8Np4Rt7Vw3Yz")}";`, "secret.live-payment-key");
  add("pay/paystack.js", `const p = "${j("sk_", "live_", "a3f9c2e8b1d7406f5e2c9a8b7d6e5f4a3b2c1d0e")}";`, "secret.live-payment-key");
  add("pay/flutter.js", `const f = "${j("FLWSECK-", "9f8e7d6c5b4a39281706f5e4d3c2b1a0", "-X")}";`, "secret.flutterwave");
  add("ci/gh.js", `const t = "${j("ghp_", "R8kLm2Np4Qs6Tu8Vw0Xy2Za4Bc6De8Fg0Hi2")}";`, "secret.github-token");
  add("ci/gh2.js", `const t = "${j("github_pat_", "11ABCDE2F0", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3")}";`, "secret.github-token");
  add("ci/gitlab.js", `const t = "${j("glpat-", "x7Rk2mQ9vT3bL8nP4wZs")}";`, "secret.gitlab-token");
  add("web/maps.js", `const g = "${j("AIza", "SyD3k9Lm2Np4Qs6Tu8Vw0Xy2Za4Bc6De8Fg")}";`, "secret.google-api-key");
  add("bots/slack.js", `const s = "${j("xox", "b-2938475610-9182736450-aB3dE5fG7hJ9kL1m")}";`, "secret.slack-token");
  add("bots/hook.js", `const h = "${j("https://hooks.slack.com/services/", "T024BE7LD/B08KX2M4N/", "q7Rk2mQ9vT3bL8nP4wZs6Y1u")}";`, "secret.slack-webhook");
  add("bots/discord.js", `const d = "${j("https://discord.com/api/webhooks/", "112233445566778899/", rep("aB3dE5fG7h", 7))}";`, "secret.discord-webhook");
  add("bots/telegram.py", `TOKEN = "${j("6918274503:", "AA", "Fk2mQ9vT3bL8nP4wZs6Y1uR8kLm2Np4Qs")}"`, "secret.telegram-bot");
  add("ai/openai.py", `client = OpenAI(api_key="${j("sk-", "proj-", rep("Rk2mQ9vT3bL8nP4w", 4))}")`, "secret.openai-key");
  add("ai/claude.py", `k = "${j("sk-ant-", "api03-", rep("Rk2mQ9vT3bL8nP4w_", 6))}"`, "secret.anthropic-key");
  add("mail/sg.js", `const k = "${j("SG.", "aB3dE5fG7hJ9kL1mN3pQ5r", ".", "sT7uV9wX1yZ3aB5cD7eF9gH1jK3lM5nP7qR9sT1uV3w")}";`, "secret.sendgrid-key");
  add("sms/twilio.js", `const k = "${j("SK", "9f8e7d6c5b4a39281706f5e4d3c2b1a0")}";`, "secret.twilio-key");
  add(".npmrc", `//registry.npmjs.org/:_authToken=${j("npm_", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5")}`, "secret.npm-token");
  add("cloud/azure.cs", `var c = "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=${rep("aB3dE5fG7hJ9kL1m", 6)}==;";`, "secret.azure-storage-key");
  add("db/conn.js", `const url = "postgres://admin:${j("Zx9", "vQ2#mK")}@db.internal:5432/app";`, "secret.database-url");
  add("auth/jwt.js", `const demo = "${j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")}";`, "secret.jwt");
  add("app/settings.py", `SECRET_KEY = "${j("k9#Vm2", "@Lq8xR!t7Wz3")}"`, "secret.generic-assignment");
  add(".env", `DATABASE_PASSWORD=${j("Qm8", "vR2kL9xZ")}\nSTRIPE_SECRET=${j("rk7", "Nq2Wb8Xc")}`, "secret.env-file", "secret.env-value");

  // ---------------- JavaScript / TypeScript ----------------
  add("src/api.js", "app.get('/run', (req, res) => { eval(req.query.code); });", "code.js.eval");
  add("src/api.js", "exec(`convert ${req.query.file} out.png`);", "code.js.command-injection");
  add("src/api.js", "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);", "code.js.sql-injection");
  add("src/api.js", "pool.query(\"SELECT * FROM orders WHERE email = '\" + email + \"'\");", "code.js.sql-injection");
  add("src/api.js", "const rows = await prisma.$queryRawUnsafe(sql);", "code.js.sql-injection");
  add("src/api.js", "User.find({ $where: 'this.age > ' + age });", "code.js.nosql-injection");
  add("src/api.js", "res.redirect(req.query.next);", "code.js.open-redirect");
  add("src/api.js", "res.sendFile(path.join(__dirname, req.query.name));", "code.js.path-traversal");
  add("src/api.js", "const page = await fetch(req.body.url);", "code.js.ssrf");
  add("src/api.js", "const token = jwt.sign(payload, 'super-secret-signing-key');", "code.js.jwt-hardcoded-secret");
  add("src/api.js", "jwt.verify(token, key);", "code.js.jwt-no-alg");
  add("src/api.js", "res.cookie('sid', id, { httpOnly: false });", "code.js.cookie-insecure");
  add("src/api.js", "app.use(cors());", "code.js.cors-wildcard");
  add("src/api.js", "const re = new RegExp(req.query.pattern);", "code.js.regex-injection");
  add("src/api.js", "vm.runInNewContext(userCode, sandbox);", "code.js.vm-run");
  add("src/api.js", "const obj = serialize.unserialize(req.cookies.profile);", "code.js.unsafe-deserialize");
  add("src/ui.js", "el.innerHTML = message;", "code.js.xss");
  add("src/ui.js", "document.write(location.hash);", "code.js.xss");
  add("src/crypto.js", "const h = crypto.createHash('md5').update(pw).digest('hex');", "code.js.weak-hash");
  add("src/crypto.js", "const c = crypto.createCipher('aes192', secret);", "code.js.weak-cipher");
  add("src/crypto.js", "const resetToken = Math.random().toString(36);", "code.js.insecure-random");
  add("src/net.js", "const agent = new https.Agent({ rejectUnauthorized: false });", "code.js.tls-disabled");

  // ---------------- Python ----------------
  add("py/app.py", "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")", "code.py.sql-injection");
  add("py/app.py", "cursor.execute(\"DELETE FROM t WHERE id = %s\" % uid)", "code.py.sql-injection");
  add("py/app.py", "subprocess.run(cmd, shell=True)", "code.py.subprocess-shell");
  add("py/app.py", "os.system(f\"ping {host}\")", "code.py.os-system");
  add("py/app.py", "result = eval(request.args.get('expr'))", "code.py.eval");
  add("py/app.py", "data = yaml.load(body)", "code.py.yaml-load");
  add("py/app.py", "obj = pickle.loads(blob)", "code.py.unsafe-deserialize");
  add("py/app.py", "r = requests.get(url, verify=False)", "code.py.tls-disabled");
  add("py/app.py", "return render_template_string(request.args['tpl'])", "code.py.ssti");
  add("py/app.py", "app.run(debug=True)", "code.py.debug");
  add("py/app.py", "h = hashlib.md5(password.encode()).hexdigest()", "code.py.weak-hash");
  add("py/app.py", "path = tempfile.mktemp()", "code.py.insecure-temp");
  add("py/settings.py", "ALLOWED_HOSTS = ['*']", "code.py.allowed-hosts-wildcard");

  // ---------------- PHP ----------------
  add("php/index.php", "<?php $r = mysqli_query($db, \"SELECT * FROM users WHERE id = \" . $_GET['id']);", "code.php.sql-injection");
  add("php/index.php", "<?php system('ping ' . $_GET['host']);", "code.php.command-injection");
  add("php/index.php", "<?php echo $_GET['name'];", "code.php.xss");
  add("php/index.php", "<?php include($_GET['page']);", "code.php.file-inclusion");
  add("php/index.php", "<?php $o = unserialize($_COOKIE['data']);", "code.php.unsafe-deserialize");
  add("php/index.php", "<?php eval($code);", "code.php.eval");

  // ---------------- Java ----------------
  add("java/Dao.java", "ResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id);", "code.java.sql-injection");
  add("java/Dao.java", "Runtime.getRuntime().exec(\"ping \" + host);", "code.java.command-injection");
  add("java/Dao.java", "ObjectInputStream in = new ObjectInputStream(socket.getInputStream());", "code.java.unsafe-deserialize");
  add("java/Dao.java", "MessageDigest md = MessageDigest.getInstance(\"MD5\");", "code.java.weak-hash");
  add("java/Dao.java", "Cipher c = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");", "code.java.weak-cipher");
  add("java/Dao.java", "conn.setHostnameVerifier((h, s) -> true);", "code.java.tls-disabled");

  // ---------------- Go ----------------
  add("go/main.go", "rows, _ := db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id))", "code.go.sql-injection");
  add("go/main.go", "out, _ := exec.Command(\"sh\", \"-c\", \"ping \"+host).Output()", "code.go.command-injection");
  add("go/main.go", "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}", "code.go.tls-disabled");
  add("go/main.go", "h := md5.Sum(data)", "code.go.weak-hash");

  // ---------------- Ruby ----------------
  add("rb/users_controller.rb", "User.where(\"name = '#{params[:name]}'\")", "code.rb.sql-injection");
  add("rb/users_controller.rb", "system(\"convert #{params[:file]}\")", "code.rb.command-injection");
  add("rb/users_controller.rb", "obj = Marshal.load(data)", "code.rb.unsafe-deserialize");
  add("rb/users_controller.rb", "params.require(:user).permit!", "code.rb.mass-assignment");

  // ---------------- C# ----------------
  add("cs/Repo.cs", "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = \" + id, conn);", "code.cs.sql-injection");
  add("cs/Repo.cs", "var f = new BinaryFormatter();", "code.cs.unsafe-deserialize");
  add("cs/Repo.cs", "ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;", "code.cs.tls-disabled");
  add("cs/Repo.cs", "using var md5 = MD5.Create();", "code.cs.weak-hash");

  // ---------------- infrastructure / CI ----------------
  add("Dockerfile", "FROM node:latest\nRUN curl -fsSL https://get.example.sh | sh\nCMD [\"node\", \"server.js\"]", "code.docker.latest-tag", "code.docker.curl-pipe-shell", "code.docker.runs-as-root");
  add("docker-compose.yml", "services:\n  app:\n    image: app\n    privileged: true", "code.container.privileged");
  add("infra/main.tf", "resource \"aws_security_group_rule\" \"ssh\" {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\nresource \"aws_s3_bucket_acl\" \"b\" {\n  acl = \"public-read\"\n}", "code.tf.open-to-internet", "code.tf.public-bucket");
  add(".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  t:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"", "code.gha.pull-request-target", "code.gha.script-injection");

  // ---------------- dependencies (parsed offline) ----------------
  files["package-lock.json"] = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "x" }, "node_modules/lodash": { version: "4.17.4" }, "node_modules/minimist": { version: "0.0.8" } } });
  files["go.mod"] = "module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)\n";
  files["Gemfile.lock"] = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (5.2.0)\n    nokogiri (1.10.0)\n";
  files["composer.lock"] = JSON.stringify({ packages: [{ name: "guzzlehttp/guzzle", version: "6.5.0" }] });
  files["Cargo.lock"] = "[[package]]\nname = \"hyper\"\nversion = \"0.14.10\"\n";

  // ------- data flow: request input reaches a dangerous call through variables -------
  add("flow/ping.php", "<?php\n$ip = $_POST['ip'];\n$out = shell_exec('ping -c 1 ' . $ip);", "code.php.command-injection");
  add("flow/user.php", "<?php\n$id = $_GET['id'];\n$sql = \"SELECT name FROM users WHERE id = '$id'\";\n$res = mysqli_query($db, $sql);", "code.php.sql-injection");
  add("flow/page.php", "<?php\n$page = $_GET['page'];\ninclude($page);", "code.php.file-inclusion");
  add("flow/view.php", "<?php\nrequire_once 'source/level.php';\ninclude($file);", "code.php.file-inclusion");
  add("flow/login.py", "def login(request):\n    user = request.POST.get(\"user\")\n    query = (\n        f\"SELECT * FROM accounts WHERE name = '{user}'\"\n    )\n    cursor.execute(query)", "code.py.sql-injection");
  add("flow/lookup.py", "def lookup(request):\n    host = request.GET[\"host\"]\n    cmd = f\"nslookup {host}\"\n    proc = subprocess.Popen(\n        cmd, shell=True, stdout=subprocess.PIPE\n    )", "code.py.subprocess-shell");
  add("flow/proxy.py", "def proxy(request):\n    target = request.args.get(\"url\")\n    return requests.get(target).text", "code.py.ssrf");
  add("flow/read.py", "def read(request):\n    name = request.args[\"f\"]\n    with open(\"/srv/files/\" + name) as fh:\n        return fh.read()", "code.py.path-traversal");
  add("flow/fetch.js", "app.get(\"/fetch\", async (req, res) => {\n  const { url } = req.query;\n  const r = await axios.get(url);\n  res.json(r.data);\n});", "code.js.ssrf");
  add("flow/zip.js", "app.post(\"/zip\", (req, res) => {\n  const name = req.body.name;\n  const cmd = \"zip out.zip \" + name;\n  exec(cmd);\n});", "code.js.command-injection");
  add("flow/file.js", "app.get(\"/file\", (req, res) => {\n  const f = req.params.name;\n  res.sendFile(path.join(__dirname, \"files\", f));\n});", "code.js.path-traversal");
  add("flow/go.js", "app.get(\"/go\", (req, res) => {\n  const next = req.query.next;\n  res.redirect(next);\n});", "code.js.open-redirect");

  // ---------------- decoys: safe code that must NOT be flagged ----------------
  const decoys: Record<string, string> = {
    "safe/env.js": "const key = process.env.STRIPE_SECRET_KEY;\nconst password = process.env.DB_PASSWORD;",
    "safe/example.js": "const apiKey = \"your-api-key-here\";\nconst token = \"<YOUR_TOKEN>\";",
    "safe/db.js": "pool.query('SELECT * FROM users WHERE id = $1', [id]);\ndb.query(\"SELECT 1\");",
    "safe/redirect.js": "res.redirect('/dashboard');",
    "safe/ui.js": "el.textContent = message;",
    "safe/hash.js": "const h = crypto.createHash('sha256').update(x).digest('hex');",
    "safe/random.js": "const token = crypto.randomBytes(32).toString('hex');",
    "safe/verify.js": "jwt.verify(token, key, { algorithms: ['HS256'] });",
    "safe/sub.py": "subprocess.run([\"ls\", \"-l\"])\nmodel.eval()\ndata = yaml.safe_load(body)",
    "safe/query.py": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
    "safe/Safe.java": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");",
    "safe/main.go": "rows, _ := db.Query(\"SELECT * FROM users WHERE id = $1\", id)",
    "safe/mailer.js": "const transport = nodemailer.createTransport({ host, port: 587, secure: false });",
    "safe/conn.js": "const url = \"postgres://user:password@localhost:5432/dev\";\nconst u2 = `postgres://${user}:${pass}@${host}/db`;",
    "safe/.env.example": "DATABASE_PASSWORD=changeme\nSTRIPE_SECRET=",
    "safe/Dockerfile": "FROM node:22-slim\nUSER node\nCMD [\"node\", \"server.js\"]",
    "safe/echo.php": "<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES);",
    // Data flow that is safe: sanitised, validated, parameterised, or not controlling the target.
    "safe/flow-int.php": "<?php\n$id = intval($_GET['id']);\nmysqli_query($db, \"SELECT * FROM u WHERE id = $id\");",
    "safe/flow-cast.php": "<?php\n$n = (int)$_GET['n'];\n$r = $pdo->query(\"SELECT * FROM t LIMIT $n\");",
    "safe/flow-guard.php": "<?php\n$ip = $_POST['ip'];\nif (filter_var($ip, FILTER_VALIDATE_IP)) {\n    $out = shell_exec('ping -c 1 ' . $ip);\n}",
    "safe/flow-exit.php": "<?php\n$page = $_GET['page'];\nif (!in_array($page, ['home', 'about'], true)) { exit; }\ninclude($page . '.php');",
    "safe/flow-escape.php": "<?php\n$name = $_GET['name'];\necho htmlspecialchars($name, ENT_QUOTES);",
    "safe/flow-param.py": "def get_user(request):\n    uid = request.GET.get(\"id\")\n    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
    "safe/flow-list.py": "def ping(request):\n    host = request.GET[\"host\"]\n    subprocess.run([\"ping\", \"-c\", \"1\", host])",
    "safe/flow-scope.py": "def a(request):\n    cmd = request.GET[\"c\"]\n    return cmd\n\ndef b():\n    os.system(cmd)",
    "safe/flow-digits.py": "def run(request):\n    n = request.GET[\"n\"]\n    if n.isdigit():\n        os.system(\"sleep \" + n)",
    "safe/flow-relative.js": "app.get(\"/u/:id\", async (req, res) => {\n  const id = req.params.id;\n  const data = await fetch(`${API_BASE}/users/${id}`);\n  res.redirect(`/profile/${id}`);\n});",
    "safe/flow-number.js": "app.get(\"/sleep\", (req, res) => {\n  const n = Number(req.query.n);\n  const cmd = \"sleep \" + n;\n  execSync(cmd);\n});",
    "safe/flow-prisma.js": "import { PrismaClient } from \"@prisma/client\";\napp.get(\"/posts\", async (req, res) => {\n  const authorId = req.query.author;\n  const n = await prisma.post.count({ where: { authorId } });\n  res.json({ n });\n});",
    "safe/flow-db.js": "app.get(\"/u\", async (req, res) => {\n  const id = req.query.id;\n  const rows = await db.query(\"SELECT * FROM users WHERE id = ?\", [id]);\n  res.json(rows);\n});",
  };

  for (const [file, body] of Object.entries({ ...files, ...decoys })) {
    const full = join(root, file);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  }
  return { expected, decoys: Object.keys(decoys) };
}
