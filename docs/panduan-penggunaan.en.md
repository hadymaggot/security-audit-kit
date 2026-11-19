[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](panduan-penggunaan.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](panduan-penggunaan.de.md)

# Usage Guide — Step by Step

This guide explains how to run the Security Audit Kit against a target, from installation
to reading the report. All commands run through a single entry point
`python audit.py <module>`, identical on Windows and Linux.

> Only for systems you own or systems you have written permission to test. Testing
> without permission is against the law.

## 1. Prerequisites

- **Python 3.10+**.
- **Docker** — used by the scanner modules (ZAP, Trivy, semgrep, gitleaks, testssl.sh)
  via official Docker images. The internal testing modules (authz, upload, etc.) do not require Docker.
- Optional: **Playwright** for browser-based cache verification in the `clientleak` module
  (`pip install playwright && python -m playwright install chromium`).

Install the Python dependencies:

```
pip install -r requirements.txt
```

## 2. Target configuration

Copy the example file then fill it in for your target. The real `*.yml` files are already
in `.gitignore` so credentials are not committed.

```
cp config/targets.example.yml config/targets.yml
```

Minimum to fill in `config/targets.yml`:

| Field | Description |
|---|---|
| `base_url` | Target base URL, e.g. `http://localhost:8080` |
| `tls_host` | Host for the TLS check (`tls` module) |
| `header_probe_path` | Path for the security-header check (`headers` module) |
| `code_path` | Repo path for the dependency/secret scan (`deps` module) |

## 3. Per-module test configuration

The internal testing modules (`authz`, `upload`, `auth-policy`, `clientleak`, `cors`,
`open-redirect`, `mass-assignment`) each have their own configuration file. Copy from the
available `.example` file, then adjust:

```
cp tests/authz-matrix/authz_matrix.example.yml tests/authz-matrix/authz_matrix.yml
cp tests/upload-safety/upload_safety.example.yml tests/upload-safety/upload_safety.yml
# ...and so on for the modules you will use
```

Modules whose configuration file does not exist yet are skipped when running `all`.

### Credentials via environment variables

The configuration references credentials via `${VARIABLE_NAME}`, not by writing them in
the file. Set the environment variable before running a scan.

Linux/macOS:

```
export AUTHZ_ADMIN_USER="admin@contoh.test"
export AUTHZ_PASS="..."
```

Windows (PowerShell):

```
$env:AUTHZ_ADMIN_USER = "admin@contoh.test"
$env:AUTHZ_PASS = "..."
```

The variable names follow those listed in each `.example.yml` file.

### Authentication (Bearer or Laravel Sanctum)

Two modes are supported:

- **Static token (Bearer/JWT or custom header)** — fill in the `auth.header` and
  `auth.value` blocks, e.g. `value: "${TOKEN}"` with `TOKEN="Bearer xxx"`. How to obtain
  the token: log in once to the login endpoint, take the token from the response.
- **Laravel Sanctum (SPA, session cookie + CSRF)** — enable the `auth.sanctum` block
  (`enabled: true`, `csrf_path`, `origin`) and `auth.login`. The runner will fetch the
  CSRF cookie, log in, then include the `X-XSRF-TOKEN` and `Origin` headers automatically.
  `origin` must match `SANCTUM_STATEFUL_DOMAINS` on the server.

## 4. Running a scan

### Running a single module

```
python audit.py <module>
```

Available modules:

| Module | Function | Requires |
|---|---|---|
| `deps` | Dependency CVEs (Trivy) + SAST (semgrep) + committed secrets (gitleaks) | Docker |
| `zap baseline` | OWASP ZAP passive scan | Docker, live target |
| `zap api` | OWASP ZAP scan from OpenAPI | Docker, live target, OpenAPI |
| `zap full` | OWASP ZAP active scan (destructive, use only on your own environment) | Docker, live target |
| `authz` | Access control per role: privilege escalation, IDOR, forged header, gateway bypass | Live target, config |
| `mass-assignment` | Mass assignment / BOPLA — destructive but reversible (see the Rollback section) | Live target, config |
| `upload` | Rejecting dangerous file uploads | Live target, config |
| `auth-policy` | Password strength and captcha regeneration | Live target, config |
| `clientleak` | Sensitive response caching, secrets/endpoints in JS/HTML, source maps, exposed files | Live target, config |
| `cors` | CORS misconfiguration | Live target, config |
| `open-redirect` | Open redirect | Live target, config |
| `webstack` | Detect web server version from the banner → known CVEs (Apache mod_http2, NGINX HTTP/2); non-destructive | Live target, config |
| `injection` | SQL injection (error/boolean-based, optional time-based); non-destructive, read probing | Live target, config |
| `tls` / `headers` | Outdated TLS protocols/ciphers, missing security headers | Live target |
| `report` | Assemble all results into a report | Scan results in `reports/` |
| `rollback` | Re-run restoration of destructive actions from the rollback journal | — |

### Running the whole scan

```
python audit.py all
```

This command runs `headers`, `deps`, `zap baseline`, then every testing module whose
configuration is available, then assembles the report automatically, and finally runs
rollback if there are any recorded destructive actions.

### Alternatives

- `make <module>` (Linux/macOS, if `make` is available).
- `./audit.ps1 <module>` (Windows PowerShell).

## 5. Reading the report

After `report` or `all`, the results are stored in:

- `reports/laporan.html` — a full ZAP-style report: risk summary, alert list, details of
  each finding along with instances (the endpoints tested as evidence), confidence level,
  impact, severity rationale, recommendations, and references.
- `reports/laporan.md` — the same content in Markdown format.
- `reports/laporan-slides.html` — a standalone presentation (slide deck) variant for a
  concise briefing to stakeholders; navigate with the left/right arrows.
- `reports/evidence/` — evidence screenshots (e.g. from the browser-based `clientleak`
  module), embedded in the report & slides. This folder must accompany the report files when shared.

See example output at [contoh-laporan.md](contoh-laporan.md) /
[contoh-laporan.html](contoh-laporan.html).

The **Controls That Passed (PASS)** section details the checks that were tested and
behaved correctly — evidence of test coverage, not a finding.

## 6. Rollback (destructive modules)

Destructive modules like `mass-assignment` write to the target, then restore the original
state automatically as the final stage after the report is generated. The process:

1. Snapshot the object's original values.
2. Inject the forbidden field (write to the target).
3. Record how to restore to `reports/rollback_journal.json` immediately (crash-safe).
4. Verify whether the forbidden field was accepted (a finding if yes).
5. After the report is generated, `audit.py` restores all changes to their original values.

If the automatic restoration stage fails (e.g. the connection drops), re-run it:

```
python audit.py rollback
```

The restoration log is stored in `reports/rollback.json`.

## 7. CI integration

- The static scan (`deps`) is safe to run on every PR because it needs no live target.
- The dynamic tests (DAST, access control, upload, etc.) need a live target; run them on a
  schedule against dev/staging, not production. Credentials via GitHub Secrets.

## 8. Translating findings into tests

To "lock in" a finding from a pentest report so it does not reappear, see
[temuan-to-test-mapping.en.md](temuan-to-test-mapping.en.md): mapping finding classes to
modules along with how to add their test cases.

## 9. Troubleshooting

| Symptom | Possible cause & solution |
|---|---|
| `config/targets.yml belum ada` | Copy from `config/targets.example.yml`. |
| `<config> belum ada — salin dari contoh .example-nya` | Copy the relevant module's `.example.yml` file. |
| Sanctum login fails 500 "Session store not set" | `auth.sanctum.origin` does not yet match the server's `SANCTUM_STATEFUL_DOMAINS`. |
| Scanner fails | Make sure Docker is running and the image can be pulled. |
| `clientleak` module skips the browser check | Playwright is not installed (optional). |
| Many login requests rejected with 429 | The target's login rate limit; add a delay between requests. |
