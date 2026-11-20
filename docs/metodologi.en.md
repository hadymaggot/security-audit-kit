[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](metodologi.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](metodologi.de.md)

# Methodology

The kit turns an OWASP-based pentest flow into automated regression tests: a vulnerability class once found must not return undetected, and mechanical classes (security headers, TLS, password policy, vulnerable dependencies) are swept on every run.

## References

| Topic | Standard or tool |
|---|---|
| Severity | OWASP Risk Rating (Likelihood x Impact) |
| Finding categories | OWASP Top 10 2021, OWASP API Security Top 10 2023 |
| Controls under test | OWASP ASVS |
| DAST | OWASP ZAP |
| Dependency CVEs and secrets | Trivy |
| TLS | testssl.sh |
| SAST and committed secrets | semgrep, gitleaks |

## Stages

**Static scan first:** `python audit.py deps`. It needs no live target, so it is safe on a PR: dependency CVEs, OWASP Top 10 SAST, and committed secrets.

**Dynamic tests** once a dev/staging target is available:

| Module | What it tests |
|---|---|
| `zap baseline` | Passive scan, does not attack. |
| `zap api` | Scan from an OpenAPI definition; can run behind a login via `ZAP_AUTH_HEADER`. |
| `authz` | Access control regression per role: privilege escalation, IDOR, forged `X-Auth-*` headers from the client, bypassing the gateway straight to the service port. |
| `mass-assignment` | Mass assignment / Broken Object Property Level Authorization (BOPLA). |
| `clientleak` | Sensitive response caching, secrets/endpoints in JS and HTML bundles, source maps, exposed files. |
| `upload` | Rejecting dangerous file uploads. |
| `auth-policy` | Password strength and captcha regeneration. |
| `cors`, `open-redirect` | CORS misconfiguration and open redirect. |
| `injection` | SQL injection (error-based, boolean-based, optional time-based); non-destructive, read probing only. |
| `webstack` | Web server version from the banner, mapped to known CVEs (e.g. Apache mod_http2, NGINX HTTP/2); non-destructive. |
| `tls`, `headers` | Outdated TLS protocols/ciphers and missing security headers. |

**Report:** `python audit.py report` assembles `reports/laporan.html`, `laporan.md`, and `laporan-slides.html`. `audit.py all` calls report automatically at the end.

Other modules in `PY_MODULES`: `cookie-flags`, `response-leak`, `openapi-coverage`, `ratelimit`, `session-mgmt`, `captcha`, `jwt`, `ssrf`, plus `recon`.

## Non-destructive and rollback

Most runners send ordinary requests and read the response status/body: no exploitation, no deleting data, no brute-forcing. Upload payloads are deliberately benign (markers only) to test validation.

`zap full` (active scan) is separated and comes with a warning; run it only on an environment you own, never production.

Some modules write to the target (`mass-assignment` injects forbidden fields) or create test data (`ratelimit`, `session-mgmt`). For them:

1. Every write is recorded in the rollback journal right after it executes.
2. As the final stage after the report is generated, the target is restored automatically to its original state.
3. The restoration log is kept in `reports/rollback.json`; `python audit.py rollback` re-runs the restoration if needed.

So destructive testing still leaves the target as it was.

## Cross-OS

All commands run through `python audit.py ...`, so behavior is identical on Windows and Linux. The scanners use official Docker images. The `.sh` scripts in `scanners/` are optional for Linux users; `.gitattributes` forces LF line endings so they are safe to bind-mount into a container from Windows.

## Limitations

- The report is the result of automation, not a replacement for manual pentesting.
- Scanner findings can be false positives; verify them before setting a final severity.
- Business-logic flaws are detected only when a test is written specifically for them.
- Coverage is limited to the targets and endpoints configured at run time.
