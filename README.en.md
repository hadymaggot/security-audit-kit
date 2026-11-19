[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](README.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](README.de.md)

# Security Audit Kit

A file-configured security testing toolkit for web apps that runs on both Windows
and Linux and can be reused across projects. The idea: turn pentest findings into
automated tests that keep running in CI, then roll them up into a report you can
stand behind — with methodology, evidence, severity rationale, recommendations plus
example fixes, and references to OWASP/BSSN.

> ⚠️ Only for systems you own or have written permission to test. Point active
> scans at dev/staging, not at production that users are actively using.

## Modules

| Module | Function |
|---|---|
| `authz` | Access control per role: privilege escalation, status jumping, IDOR, forged `X-Auth-*` headers from the client |
| `zap` | OWASP ZAP — passive scan / API scan from OpenAPI, can run behind a login |
| `clientleak` | Sensitive response caching, secrets/endpoints embedded in JS & HTML bundles, source maps, exposed files (`.env`, `.git/`, dumps, backups) — still runs even when the app uses no JS |
| `upload` | Rejecting dangerous file uploads: JS-bearing PDFs, polyglots, double extensions, oversized files |
| `auth-policy` | Password strength, captcha must regenerate on every failure |
| `mass-assignment` | Mass assignment / privilege escalation (BOPLA): injecting forbidden fields (`role`, `is_admin`, `company_id`) into objects you own. **Destructive but reversible** — every write is recorded to a journal & restored automatically after the report (`audit.py rollback` to replay) |
| `cors` | CORS misconfiguration: reflected origin, wildcard+credentials, `null` Origin accepted |
| `open-redirect` | Redirect parameters (`next`/`url`/`redirect`/…) pointing to an external host |
| `tls` / `headers` | Outdated TLS protocols/ciphers, missing security headers or ones that leak info |
| `webstack` | Detect versions from the `Server`/`X-Powered-By` banners then map them to known CVEs (e.g. Apache mod_http2, NGINX HTTP/2, PHP2Shell); supports `min_version` ranges, non-destructive, `known_vulnerable` can be updated via config |
| `injection` | SQL injection (error-based, boolean-based, optional time-based); non-destructive (read probing, does not modify data) |
| `deps` | Dependency CVEs (Trivy) + OWASP Top 10 SAST (semgrep) + committed secrets (gitleaks) |
| `report` | Combine all results into `reports/laporan.html` & `.md` |

This automation is not a replacement for manual pentesting: scanner findings still
have to be verified, and business-logic flaws are only detected when a test is written
specifically for that case.

## Prerequisites

Python 3.10+, Docker (for ZAP/Trivy/semgrep/gitleaks/testssl). `make` optional.

## Usage

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
cp config/targets.example.yml config/targets.yml      # fill in the target base URL
python audit.py all                                   # -> reports/laporan.html
```

Credentials go through environment variables, not stored in files (the real `*.yml`
files are gitignored). One entry point for every OS: `python audit.py <module>`. For
short commands, use `make <module>` on Linux/macOS or `.\audit.ps1 <module>` on Windows.

## Structure

```
audit.py            cross-OS entry point (single door)
report.py           combined report assembler
remediation.py      remediation & rationale knowledge base
config/             targets (example; the real one is gitignored)
scanners/           ZAP, testssl, header, trivy/semgrep/gitleaks wrappers
tests/              authz-matrix, client-leak, upload-safety, auth-policy
docs/               methodology & finding -> test mapping
.github/workflows/  example CI pipeline
Makefile, audit.ps1 short-command wrappers per OS
```

More detail in [docs/metodologi.en.md](docs/metodologi.en.md) and
[docs/temuan-to-test-mapping.en.md](docs/temuan-to-test-mapping.en.md). Example of the
final report shape: [docs/contoh-laporan.md](docs/contoh-laporan.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/panduan-penggunaan.en.md](docs/panduan-penggunaan.en.md) | Step-by-step guide: installation, configuration, authentication, running scans, reading the report, rollback, troubleshooting |
| [docs/metodologi.en.md](docs/metodologi.en.md) | Testing methodology & standards reference (OWASP, ASVS, Risk Rating) |
| [docs/temuan-to-test-mapping.en.md](docs/temuan-to-test-mapping.en.md) | Translating pentest report findings into test cases per module |
| [docs/contoh-laporan.md](docs/contoh-laporan.md) · [contoh-laporan.html](docs/contoh-laporan.html) · [slides](docs/contoh-laporan-slides.html) | Example report output (fictional data) — consultant format + presentation/slide variant |
| [CONTRIBUTING.en.md](CONTRIBUTING.en.md) · [SECURITY.en.md](SECURITY.en.md) · [CODE_OF_CONDUCT.en.md](CODE_OF_CONDUCT.en.md) | Contributing, security policy, code of conduct |

## Contributing

The contribution flow, how to add a check, and commit conventions are in
[CONTRIBUTING.en.md](CONTRIBUTING.en.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
