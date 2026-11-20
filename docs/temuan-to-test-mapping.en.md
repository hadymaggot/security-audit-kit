[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](temuan-to-test-mapping.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](temuan-to-test-mapping.de.md)

# Translating a pentest report into tests

Lock in a finding from a pentest report (for example from BSSN/Gov-CSIRT) so it does not recur: pick the matching module per finding, then add its case.

## Finding class to module

| Finding class | Module | How to add the case |
|---|---|---|
| Broken Access Control / privilege escalation | `authz` | Add the sensitive endpoint, `expect: { regular_user: deny }` |
| Lack of authorization status / flow jumping | `authz` | Status-change endpoint + status body, `deny` for the unauthorized role |
| IDOR | `authz` | Endpoint using another account's id, `deny` |
| Authz header trusted from the client | `authz` | Fill in the `forged_headers` block |
| Microservice directly exposed (gateway/ForwardAuth bypass) | `authz` | Endpoint with `base_url` on the service port + `expect: { anon: deny }`, and a `forged_headers` block with `as_role: anon` to that port (see `authz_matrix.traefik-sanctum.example.yml`) |
| SQL Injection | `injection` (or `zap api`) | Fill in `targets` (path, param, location, baseline); detects error/boolean-based, time-based optional. Non-destructive; verify the finding before final severity |
| Stored/Reflected XSS | `zap` + `upload` | Scan; if the XSS is via upload use the upload module |
| Dangerous upload (JS in PDF, polyglot, double extension, oversize) | `upload` | Already covered; adjust `allow_only`/`max_bytes`, use `endpoint.data` for required fields, and fill in `cleanup` so accepted test files are deleted automatically |
| Mass assignment / privilege escalation (BOPLA) | `mass-assignment` | Fill in `targets` (get/update/inject/fields). DESTRUCTIVE but reversible: every write is recorded to the journal & restored automatically after the report (`audit.py rollback` for a manual replay) |
| Weak Password Policy | `auth-policy` | Fill in `register` or `password_checks` + `weak_passwords`; add `strong_password` as a control. Only a 422 on the password field counts as rejected |
| Improper Captcha | `auth-policy` | Fill in the `captcha` block |
| CORS misconfiguration | `cors` | Fill in `paths`; check reflected ACAO / wildcard+creds / null origin |
| Open redirect | `open-redirect` | Fill in `paths` + `params`; check Location to an external host |
| Deprecated Cryptography | `tls` | `python audit.py tls` |
| Missing Security Header | `headers` | `python audit.py headers` |
| Vulnerable web server/component version (CVE) | `webstack` | Fill in `known_vulnerable` (server, max_version, cve); non-destructive, reads the `Server`/`X-Powered-By` banner + HTTP/2. Update when a new CVE appears (e.g. Apache mod_http2, NGINX HTTP/2) |
| Sensitive response caching | `clientleak` | Fill in `sensitive_paths`; check `Cache-Control: no-store` |
| Sensitive response caching (evidence stored in the browser) | `clientleak` | `browser_cache.enabled: true` (needs Playwright + Chromium) |
| Admin secret/endpoint leaked in JS (the original BSSN finding) | `clientleak` | `auto_discover_js` + `internal_endpoints` |
| Secret/endpoint leaked in HTML (app without JS) | `clientleak` | `scan_html: true` |
| Sensitive file exposed (`.env`, `.git/`, dump, backup) | `clientleak` | `probe_sensitive_files: true` |
| Source map (.map) exposed in production | `clientleak` | Automatic while sweeping JS |
| Outdated dependency (CVE) | `deps` | Automatic; the CVE appears in the report |

## The flow

1. Read the report and list each finding with its location (endpoint/parameter).
2. Map it to a module in the table above, then add the case in that module's `*.yml`. Do not put credentials there; use environment variables.
3. Run `python audit.py all`. The old finding must now fail (red): the test really catches the flaw.
4. Fix the app, run again until it passes (green), then wire it into CI so regressions are detected automatically.

`reports/laporan.html` contains, per finding: description, evidence, impact, severity rationale, recommendations with an example fix, and the standards reference. It is ready to attach as follow-up evidence.
