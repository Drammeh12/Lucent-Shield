# Lucent Shield

A defensive application-security scanner, by **Bash Lucent**.

Lucent Shield scans code and sites **you own or are explicitly authorised to test**,
finds vulnerabilities, and tells you how to fix each one. Think of it as an
automated, repeatable version of a security review: point it at your repository
and it reports leaked secrets, vulnerable dependencies, and insecure code
patterns, with a clear fix for every issue.

> **Use it only on systems you own or have written permission to test.**
> Scanning other people's systems without authorisation is illegal in most
> countries. Lucent Shield is a defensive tool: it inspects and reports, it
> does not attack.

## What it checks today (white-box / source scan)

- **Secrets** — API keys, tokens, private keys and passwords committed to code
  (AWS, Stripe, Paystack, GitHub, Google, Slack, JWTs, generic assignments).
  Evidence is always redacted, so the report is safe to share.
- **Vulnerable dependencies** — npm (`package.json`) and PyPI
  (`requirements.txt`) checked against the [OSV](https://osv.dev) database of
  known published vulnerabilities, with the fixed version to upgrade to.
- **Insecure code patterns** — command injection, `eval`, XSS sinks, wildcard
  CORS, unpinned `jwt.verify`, disabled TLS checks, weak randomness,
  `subprocess(shell=True)`, `yaml.load`, `pickle`, debug mode, weak password
  hashing, and more.

## Install

```bash
git clone https://github.com/Drammeh12/lucent-shield
cd lucent-shield
npm install
```

Needs Node.js 22.13 or newer. The only dependency is `tsx` (to run TypeScript
directly) — there is nothing to build.

## Use

```bash
# scan a repository you own and read the report in your terminal
npm run scan -- /path/to/your/project

# write a shareable HTML report
npm run scan -- /path/to/your/project --format html --out report.html

# only show high and critical issues, and fail CI if any are found
npm run scan -- /path/to/your/project --min high
```

Formats: `md` (default), `html`, `json`. The scanner **never changes your
files**, and it **never sends your code anywhere** — only dependency names and
versions are sent to the OSV database to check for known vulnerabilities.

The command exits with code `1` when a critical or high issue is found, so you
can drop it into a CI pipeline and fail the build on new problems.

## Honest limits

An automated scan catches a meaningful set of common issues quickly, but it is
**not** a replacement for a human penetration test. A clean scan is good news,
not a guarantee. Treat findings as leads to confirm, and keep the ones that
matter.

## Roadmap

- **Black-box web scan** — non-destructive checks of a site you own (security
  headers, TLS, cookie flags, exposed files, email/DNS security records).
- **Continuous monitoring** — re-scan your live site on a schedule and alert on
  new issues.
- **GitHub connection** — scan straight from a connected repository.
- Optional graphical interface on top of the same engine.

---

Built by Bash Lucent. Not affiliated with any other product that shares a name.
