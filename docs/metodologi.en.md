[🇮🇩 Indonesia](metodologi.md) · **🇬🇧 English** · [🇩🇪 Deutsch](metodologi.de.md)

# Methodology

This kit adapts an OWASP-based pentest flow into automated regression testing. There
are two goals: making sure a class of vulnerability once found does not reappear
undetected, and sweeping the mechanical classes of vulnerability (security headers,
TLS, password policy, vulnerable dependencies).

## References

Severity follows OWASP Risk Rating (Likelihood x Impact), finding categories follow
OWASP Top 10 2021 and OWASP API Security Top 10 2023, and the controls under test are
based on OWASP ASVS. Tooling used: OWASP ZAP for DAST, Trivy for dependency CVEs and
secrets, testssl.sh for TLS, and semgrep and gitleaks for SAST and detecting secrets
that have been committed.

## Stages

The static scan runs first — `python audit.py deps` — which is safe to run on a PR
because it needs no live target: dependency CVEs, OWASP Top 10 SAST, and committed
secrets.

Once a dev/staging target is available, the dynamic tests run:

- `zap baseline` — passive scan, does not attack.
- `zap api` — scan from an OpenAPI definition, can run behind a login via `ZAP_AUTH_HEADER`.
- `authz` — access control regression per role: privilege escalation, IDOR, forged
  `X-Auth-*` headers from the client, and bypassing the gateway straight to the service port.
- `mass-assignment` — mass assignment / Broken Object Property Level Authorization (BOPLA).
- `clientleak` — sensitive response caching, secrets/endpoints in JS and HTML bundles,
  source maps, and exposed files.
- `upload` — rejecting dangerous file uploads.
- `auth-policy` — password strength and captcha regeneration.
- `cors` and `open-redirect` — CORS misconfiguration and open redirect.
- `injection` — SQL injection (error-based, boolean-based, optional time-based);
  non-destructive, read probing only.
- `webstack` — detect the web server version from the banner then map it to known CVEs
  (e.g. Apache mod_http2, NGINX HTTP/2); non-destructive.
- `tls` and `headers` — outdated TLS protocols/ciphers and missing security headers.

In the final stage, `python audit.py report` assembles `reports/laporan.html` and
`laporan.md`. The `audit.py all` command invokes report automatically at the end.

## Non-destructive and rollback

Most runners only send ordinary requests and then read the status/body of the response —
no exploitation, no deleting data, and no brute-forcing. Upload payloads are deliberately
made benign (markers only) to test validation. `zap full` (active scan) is separated and
comes with a warning; run it only on an environment you own, not production.

Some modules are destructive because they must write to the target (e.g.
`mass-assignment` injects forbidden fields). For such modules, every write is recorded
to the rollback journal immediately after it executes, then restored automatically to
its original state as the final stage after the report is generated. This way destructive
testing still "feels non-destructive": the target returns to how it was. The restoration
log is kept in `reports/rollback.json`, and `python audit.py rollback` can re-run the
restoration if needed.

## Cross-OS

All commands run through `python audit.py ...`, so the behavior is identical on Windows
and Linux. The scanners use official Docker images. The `.sh` scripts in `scanners/` are
optional for Linux users; `.gitattributes` forces LF line endings so they are safe when
bind-mounted into a container from Windows.

## Limitations

This report is the result of automation, not a replacement for manual pentesting.
Scanner findings can be false positives and must be verified before a final severity is
set. Business-logic flaws are only detected when a test is written specifically for them.
Test coverage is limited to the targets and endpoints configured at run time.
