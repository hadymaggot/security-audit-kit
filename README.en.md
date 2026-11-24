[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](README.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](README.de.md)

# Security Audit Kit

![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
[![Sponsor on GitHub](https://img.shields.io/badge/Sponsor_on-GitHub-ea4aaa?style=flat&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/hadymaggot)
[![Support on Saweria](https://img.shields.io/badge/Support_on-Saweria-faae2b?style=flat&logo=buymeacoffee&logoColor=white)](https://saweria.co/hadymaggot)

A file-configured security testing toolkit for web apps: it turns pentest findings into automated tests, then rolls the results up into a report you can stand behind.

- Tests more than 20 modules: headers, TLS, access control, upload, injection, JWT, CORS, dependencies, and more.
- Non-destructive by default. Modules that write data (`mass-assignment`, `ratelimit`, `session-mgmt`) and active ZAP scans with a `snapshot` block are restored automatically through rollback.
- Consultant-grade report in HTML, Markdown, and slides: evidence, severity rationale, recommendations with example fixes, and OWASP/BSSN references.

> Only for systems you own or have written permission to test. Point active scans at dev/staging, not production.

## Quick start

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
python audit.py --project my-app init
# edit projects/my-app/config/targets.yml: base_url: "https://dev.example.com"
python audit.py --project my-app headers
python audit.py --project my-app report
```

Expected: each header is printed as `ok`, `MISS`, or `LEAK` (exit code 1 if anything is found), then `projects/my-app/reports/laporan.html` is created. Open it in a browser.

## Modules

Run with `python audit.py --project my-app <module>`. `all` runs every module that has a config, then the report and rollback.

| Module | Checks | Credentials? |
|---|---|---|
| `headers` | Missing security headers; `Server`/`X-Powered-By` disclosure | No |
| `tls` | Outdated TLS protocols/ciphers and TLS vulnerabilities (testssl.sh) | No |
| `webstack` | Version from `Server`/`X-Powered-By` banners mapped to CVEs | No |
| `zap` | OWASP ZAP: `baseline` (passive), `api` from OpenAPI, `full` (active) | Optional |
| `deps` | Dependency CVEs (Trivy), SAST (semgrep), committed secrets (gitleaks) | No |
| `recon` | Passive OSINT (subfinder, dnsx, httpx); port scan and nuclei only if enabled in config | No |
| `clientleak` | Sensitive response caching, secrets/source maps in JS and HTML, exposed files (`.env`, `.git/`) | Optional |
| `cookie-flags` | `HttpOnly`, `Secure`, `SameSite`, and cookie lifetime | Optional |
| `cors` | Reflected origin, wildcard with credentials, Origin `null` | Optional |
| `open-redirect` | Redirect parameters (`next`, `url`, `redirect`) pointing to external hosts | Optional |
| `response-leak` | Sensitive keys, secrets, stack traces, and internal IPs in API responses | Optional |
| `openapi-coverage` | GET operations protected per OpenAPI but open without login | No |
| `captcha` | Captcha answers leaked in the challenge response | No |
| `auth-policy` | Password strength, captcha must change every time | Optional |
| `authz` | Per-role access control: privilege escalation, IDOR, forged `X-Auth-*` headers | Yes |
| `upload` | Rejection of dangerous uploads: PDF with JS, polyglot, double extension | Optional |
| `injection` | SQL injection: error-based, boolean-based, and time-based (optional) | Optional |
| `jwt` | `none` algorithm, weak secrets, forged tokens or tokens without `exp` | Yes |
| `ssrf` | Endpoints that accept URLs, tested with a local canary listener | Optional |
| `mass-assignment` | Forbidden fields (`role`, `is_admin`) on your own objects; restored automatically | Yes |
| `ratelimit` | Rate limit, account lockout, and account enumeration on a disposable test account | Yes |
| `session-mgmt` | Sessions revoked after logout and password change | Yes |

Other commands: `init`, `report`, `rollback`, `clean`. Full list: `python audit.py --help`. Scanner results still need verification; business-logic flaws are only detected if a test is written for that case.

## Requirements

- [ ] Python 3.10+ and `pip install -r requirements.txt`
- [ ] Docker for `zap`, `tls`, and `deps`
- [ ] Optional: Playwright for browser cache verification in `clientleak`
- [ ] Credentials via environment variables, not in files

## Documentation

| Document | Contents |
|---|---|
| [Usage guide](docs/panduan-penggunaan.en.md) | Installation, config, authentication, scans, report, rollback, troubleshooting |
| [Autonomous runner](docs/runner.en.md) | Runs the whole audit from scan to report with no manual steps and no AI; reusable for new projects through one config |
| [Glossary](docs/glosarium.en.md) | Technical terms per language and the `--lang` option |
| [Methodology](docs/metodologi.en.md) | Test stages and standards reference (OWASP, ASVS) |
| [Finding-to-test mapping](docs/temuan-to-test-mapping.en.md) | Turning pentest findings into test cases |
| [Example report](docs/contoh-laporan.md) | Sample output with fictional data ([HTML](docs/contoh-laporan.html), [slides](docs/contoh-laporan-slides.html)) |
| [Contributing](CONTRIBUTING.en.md) | Contribution flow and how to add a check |
| [Site](https://hadymaggot.github.io/security-audit-kit/) | Project page and passive open scanner ([Worker setup](worker/README.md)) |

Advanced options (in the guide): [multiple projects](docs/panduan-penggunaan.en.md#multiple-projects-in-parallel), [running from any directory](docs/panduan-penggunaan.en.md#running-from-any-directory), [console colors](docs/panduan-penggunaan.en.md#console-colors), [language and terms](docs/panduan-penggunaan.en.md#language-and-technical-terms).

## Project layout

```text
audit.py, audit.ps1, Makefile   # cross-OS entry point and short wrappers
runner.py                       # autonomous runner: scan to report from one config
report.py                       # combined report assembler
remediation.py                  # remediation knowledge base and severity rationale
glossary.py, glosarium.yml      # glossary loader and data
config/                         # targets.example.yml (the real targets.yml is gitignored)
tests/<modul>/                  # runner and example config per module
tests/unit/                     # unit tests
scanners/                       # wrapper scripts for ZAP, testssl, headers, deps
projects/                       # projects created by init (gitignored)
docs/                           # guides and the built site
site/                           # templates, id/en/de dictionaries, site glossary
worker/                         # Cloudflare Worker for the open scanner
.github/workflows/              # CI pipelines
```

## Contributing

See [CONTRIBUTING.en.md](CONTRIBUTING.en.md) for the flow, how to add a check, and commit conventions.

## License

Apache-2.0, see [LICENSE](LICENSE).
