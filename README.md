# Lucent Shield

Security you can actually see. Built by **Bash Lucent**.

Lucent Shield watches the code and websites you own, tells you in plain words what is exposed, and shows you the fix right next to the problem. It runs as a command line tool and as a live web dashboard with a big padlock that stays green when you are safe and turns red the moment something changes.

> Only test systems you own or have explicit permission to test. Scanning other people's systems without authorisation is illegal in most places. Lucent Shield is a defensive tool. It inspects and reports, it never attacks.

## What it does

**White box, your code.** Point it at a GitHub repository (or, from the command line, a local folder) and it looks for:

- Leaked secrets: API keys, tokens, private keys and passwords committed to code (AWS, Stripe, Paystack, GitHub, Google, Slack, JWTs, and generic assignments). Evidence is redacted, so the report is safe to share.
- Vulnerable dependencies: npm (`package.json`) and PyPI (`requirements.txt`) checked against the [OSV](https://osv.dev) database of known vulnerabilities, with the fixed version to move to.
- Insecure code patterns: command injection, `eval`, XSS sinks, wildcard CORS, unpinned `jwt.verify`, disabled TLS checks, weak randomness, `subprocess(shell=True)`, `yaml.load`, `pickle`, debug mode, weak password hashing, and more.
- Data flow: in PHP, Python and JavaScript it follows request input through your variables, even across several lines, to where it is used. If it reaches a database query, a shell command, a file path, an outbound request or a redirect without being cleaned or checked first, that is reported along with the line where the input came in. Input that passes through a sanitiser (like `intval` or `int()`) or a validation check (like `is_numeric` or an allow list) is recognised as safe.

**Black box, your website.** Give it a site you own and it checks the outside view the way a visitor's browser sees it: security headers, TLS, cookie flags, information disclosure, and files that should never be public. Every request is read only. It never fuzzes, brute forces or changes anything.

**Forensics.** Inspect a file or an artifact, capture its fingerprint, and surface anything that looks out of place.

**Live dashboard.** A web app with a big padlock that beeps green and closed when every asset is protected, and red and open the moment one is exposed. Add a site and watch the scan run live, with the real findings streaming in, then press Secure to get the exact fix for each one and turn on continuous monitoring.

**Continuous monitoring.** Keep watching your assets on a schedule and get an alert when protection slips or recovers. Alerts show in the dashboard, and can also go to Slack or Discord.

## Reports

Every scan produces a **Security Assessment Report** in the structure clients and auditors expect:

1. Executive summary with an overall risk rating
2. Scope and authorization, including the recorded permission for the scan and proof of domain ownership
3. Methodology and rules of engagement
4. Findings summary, each with an ID, severity, risk score, CWE number and OWASP Top 10 category
5. Detailed findings with location, evidence, description and recommendation
6. Remediation plan with a fix-by deadline for each severity
7. Limitations
8. Reviewer notes and sign-off, for a security professional to add anything confirmed by hand

In the dashboard, open an asset's report and choose **Full assessment report (PDF)**, then **Save as PDF**. HTML, Markdown and JSON downloads are there too. Lucent Shield never exploits what it finds, so the report is an assessment, not a penetration test.

## Only test what you own

Lucent Shield is strict about who may test what.

- Every scan asks for explicit authorisation at the moment you run it, and records it with a timestamp.
- A website cannot be scanned until you prove you control the domain, by publishing a token we give you as a file on the site or as a DNS record.
- Forensic examination asks you to attest to lawful authority (ownership, written permission, or a warrant or court order) and to record a reference for it.

## Run the command line tool

```bash
git clone https://github.com/Drammeh12/Lucent-Shield
cd Lucent-Shield
npm install
```

Needs Node.js 22.13 or newer. The only dependency is `tsx`, so there is nothing to build.

```bash
# scan a repository you own and read the report in your terminal
npm run scan -- /path/to/your/project

# write the assessment report as a print-ready HTML page (save it as PDF from a browser)
npm run scan -- /path/to/your/project --format html --out report.html

# only show high and critical issues, and fail CI if any are found
npm run scan -- /path/to/your/project --min high
```

Report formats are `md` (the default), `html` and `json`. The scanner never changes your files, and it never sends your code anywhere. Only dependency names and versions go to the OSV database to check for known vulnerabilities. It exits with code `1` when a critical or high issue is found, so it drops straight into a CI pipeline.

## Run the web dashboard

```bash
npm run web
# then open http://localhost:4600
```

Open it and create an account. Each account sees only its own assets, scans and alerts.

To become the admin, set an admin email and password before you start, then create your account with exactly that email and that password:

```bash
LUCENT_ADMIN_EMAIL="you@yourcompany.com" LUCENT_ADMIN_PASSWORD="a-long-admin-password" npm run web
```

Nobody else can create an account with the admin email, because it needs the admin password. The admin account also gets the Admin tab.

Any account can turn on **two-step login** in Settings: scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy), and from then on logging in needs a 6-digit code as well as the password. Ten one-time recovery codes cover a lost phone. Turn it on for the admin account first.

## Deploy

A Dockerfile is ready for Bash Cloud or any Docker host.

```bash
docker build -t lucent-shield .
docker run -p 4600:4600 -e LUCENT_ADMIN_EMAIL="you@yourcompany.com" -e LUCENT_ADMIN_PASSWORD="a-long-admin-password" -v lucent-data:/data lucent-shield
```

Settings you pass through the environment:

- `LUCENT_ADMIN_EMAIL`: the email of the admin account. Create your account with this email to get the Admin tab: every account, the authorization audit trail (with a download), sign-in and sign-up attempts, all assets, and the server's health and safety settings.
- `LUCENT_ADMIN_PASSWORD`: needed once, to create the admin account. Without it, nobody can sign up with the admin email.
- `LUCENT_SIGNUPS=closed`: stop new accounts (the admin can still create theirs).
- `TRUST_PROXY=1`: mark the login cookie Secure when you serve over HTTPS behind a proxy.
- `LUCENT_GITHUB_TOKEN`: a token so the admin's white box scans can reach private GitHub repositories. Other accounts never use it.
- `LUCENT_ALERT_WEBHOOK`: a Slack or Discord webhook to also receive monitoring alerts.
- `LUCENT_DATA_DIR`: where to keep your assets and history (defaults to `/data` in Docker).

## How well it works

Lucent Shield is checked two ways, and you can run both yourself with `npm test` and `npm run bench`.

- A built-in benchmark plants 104 known issues in a sample project, next to safe code that looks almost the same. It catches all 104 and raises no false alarms on the safe code.
- It is also run against well-known, deliberately vulnerable open-source apps: OWASP NodeGoat, DVWA and PyGoat. It finds their documented SQL injection, command injection, file inclusion, SSRF and path traversal flaws, and leaves their secure reference code alone. On real production codebases the data-flow checks add no false alarms.

## Honest limits

An automated scan catches a lot of common problems quickly, but it is not a replacement for a human penetration test. A clean scan is good news, not a promise. Treat findings as leads to confirm, and fix the ones that matter.

## About

Lucent Shield is a product of Bash Lucent, built alongside Bash Cloud, ClearKobo and Naija Campus. It is not affiliated with any other product that shares a name.
