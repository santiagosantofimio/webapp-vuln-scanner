# Argus Sentinel

A defensive web application vulnerability scanner. Point it at a URL and it crawls the site within the same origin, runs a set of **non-destructive** security checks, and produces a report that lists every finding with its severity, the affected URL, the evidence, and concrete remediation advice.

Argus Sentinel only **detects**. It never exploits, deletes, or modifies data, and it never runs denial-of-service style payloads.

> The console output and the generated report are in Spanish. The code and this README are in English.

## Authorization and scope

Scanning a system you do not own, without written permission, is illegal in most jurisdictions. Use Argus Sentinel **only against systems you own or are explicitly authorized to test.**

- The default allowed target is `localhost` / `127.0.0.1`. Any other host is refused unless you confirm ownership with `--i-own-this` or list it in an authorized-hosts file (`--authorized-hosts`).
- Argus Sentinel stays on the **same origin** as the target. It never follows links to other domains.
- It sends **detection probes only**. It never attempts to exploit, delete, or modify data.
- Requests are rate-limited (bounded concurrency and a configurable delay) so the scan does not behave like an attack.

## Checks (MVP)

Every finding is mapped to its OWASP Top 10 (2025) category.

| Check | What it looks for | OWASP |
|-------|-------------------|-------|
| Security headers | Presence and sanity of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` | A02 |
| Cookies | `HttpOnly`, `Secure`, and `SameSite` flags on every `Set-Cookie` | A02 |
| Transport | Whether the site is served over HTTPS and redirects HTTP → HTTPS | A04 |
| Reflected XSS | Injects a benign marker into parameters and checks whether it returns unescaped | A05 |
| SQL injection (detection only) | Sends a single quote and boolean payloads; looks for SQL error signatures or boolean response differences. No destructive or time-based payloads | A05 |
| CSRF | `POST` forms with no anti-CSRF token field | A01 |
| Sensitive paths | Probes a short, safe list: `/actuator/env`, `/actuator/beans`, `/h2-console`, `/.git/`, `/.env`, `/admin` | A01 / A02 |
| Information leakage | Error pages with full stack traces, and server version in the `Server` header | A02 |

### Optional checks

These run only when their flags are given.

| Check | What it does | OWASP |
|-------|--------------|-------|
| Authenticated scan | Logs in through a form (auto-carrying hidden/CSRF fields), keeps the session, and crawls private zones | — |
| Assisted IDOR | With two sessions, flags id-based resources reachable from a second session (needs manual confirmation) | A01 |
| Rate limiting | Sends a small, bounded burst and reports the absence of `429` / `Retry-After` | A06 / A07 |

## Install

Requires Python 3.12+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
argus http://localhost:8080
argus http://localhost:8080 --html report.html --json report.json --sarif report.sarif
argus http://localhost:8080 --max-depth 3 --max-pages 100 --delay 0.3
```

Authenticated scan, assisted IDOR (two sessions), and rate-limiting check:

```bash
argus http://localhost:8080 \
  --username alice --password secret \
  --second-username bob --second-password hunter2 \
  --check-rate-limit
```

Or without installing:

```bash
python -m argus http://localhost:8080
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--max-depth` | `2` | Maximum crawl depth |
| `--max-pages` | `50` | Maximum number of pages to crawl |
| `--delay` | `0.2` | Delay between requests, in seconds |
| `--concurrency` | `5` | Maximum concurrent requests |
| `--timeout` | `10.0` | Per-request timeout, in seconds |
| `--json PATH` | — | Write a JSON report |
| `--html PATH` | — | Write an HTML report |
| `--sarif PATH` | — | Write a SARIF 2.1.0 report for GitHub code scanning |
| `--i-own-this` | off | Confirm ownership/authorization for non-local targets |
| `--authorized-hosts PATH` | — | File with authorized hosts, one per line |
| `--no-verify-tls` | off | Skip TLS verification (local labs only) |
| `--fail-on {info,baja,media,alta}` | `info` | Minimum severity that makes the process exit non-zero |
| `--login-url URL` | `<target>/login` | Login form URL for an authenticated scan |
| `--username` / `--password` | — | Credentials for the authenticated session |
| `--username-field` / `--password-field` | `username` / `password` | Form field names for the credentials |
| `--second-username` / `--second-password` | — | Second account, for the assisted IDOR check |
| `--check-rate-limit` | off | Send a bounded burst to detect missing rate limiting |
| `--rate-limit-requests` | `15` | Number of requests for the rate-limiting check |

## Output

Argus Sentinel emits three report formats from the same set of findings: **JSON** (for machines), **HTML** (for people), and **SARIF 2.1.0** (for GitHub code scanning). Each finding carries its OWASP category, severity (`info` / `baja` / `media` / `alta`), affected URL, evidence, and remediation.

The exit code is **CI-friendly**: `0` when nothing at or above the `--fail-on` threshold is found, non-zero otherwise.

## Publish a report

`scripts/deploy-report.sh` scans a target of your choice and publishes its HTML report to Cloudflare Pages. It needs an authenticated [`wrangler`](https://developers.cloudflare.com/workers/wrangler/) (run `npx wrangler login` once).

```bash
scripts/deploy-report.sh http://localhost:8080
scripts/deploy-report.sh https://your-own-site.com -- --i-own-this
```

Anything after `--` is forwarded to the scanner (for example `--i-own-this` or `--username/--password`). The project name defaults to `argus-sentinel`; override it with `ARGUS_PAGES_PROJECT`.

## Architecture

Each check is an independent detector module implementing a common interface (`run(context) -> list[Finding]`), so new checks can be added without touching the core. A bounded crawler (same origin, configurable depth, page limit, and inter-request delay) feeds the detectors the pages it discovers.

```
argus/
  cli.py            argument parsing and console output
  scanner.py        orchestration: authenticate, crawl, run detectors
  crawler.py        same-origin bounded crawler
  http_client.py    async httpx client with concurrency limit and delay
  authorization.py  target authorization guard
  auth.py           form login and session handling
  models.py         Finding, Severity, Page, forms
  owasp.py          OWASP Top 10 2025 categories
  report.py         JSON and HTML rendering
  sarif.py          SARIF 2.1.0 rendering
  detectors/        one module per check
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT.
