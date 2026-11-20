[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](panduan-penggunaan.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](panduan-penggunaan.de.md)

# Usage Guide

Step-by-step guide to running the Security Audit Kit, from installation to reading the report.
All commands use one entry point, `python audit.py <module>`, identical on Windows and Linux.

> Only for systems you own or have written permission to test.
> Testing without permission is against the law.

## 1. Prerequisites

| Requirement | Used for | Check |
|---|---|---|
| Python 3.10+ | All modules | `python --version` |
| Docker | `deps`, `zap`, `tls` (other modules do not need it) | `docker --version` |
| make (optional) | Short commands on Linux/macOS | `make --version` |
| Playwright (optional) | Browser cache verification in `clientleak` | `python -m playwright --version` |

Install Playwright with `pip install playwright`, then `python -m playwright install chromium`.

## 2. Install

```
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
```

## 3. Quick start: first scan in 5 minutes

These steps use the `headers` module: passive, pure Python, no Docker needed.

1. Create a project.

   ```
   python audit.py --project my-app init
   ```

   Expected: folder `projects/my-app/` with `config/targets.yml` and `reports/`.

2. Set `base_url` in `projects/my-app/config/targets.yml`.

   ```yaml
   base_url: "http://localhost:8080"
   ```

   Expected: the target points to your application (use dev/staging, not production).

3. Run the `headers` module.

   ```
   python audit.py --project my-app headers
   ```

   Expected: each header is marked `ok`, `MISS` (missing), or `LEAK` (discloses information); results are saved to `reports/headers.json`.

4. Build the report.

   ```
   python audit.py --project my-app report
   ```

   Expected: `projects/my-app/reports/laporan.html`. Open it in a browser.

## 4. Configuration

The real `*.yml` files are already in `.gitignore`, so credentials are not committed.

### targets.yml

Main fields (full list in [config/targets.example.yml](../config/targets.example.yml)):

| Field | Description |
|---|---|
| `base_url` | Target base URL, e.g. `http://localhost:8080` |
| `openapi` | URL or path of the OpenAPI specification (for `zap api`) |
| `tls_host` | Host without scheme for the `tls` module |
| `header_probe_path` | Path for the `headers` module (default `/`) |
| `code_path` | Repository folder for the `deps` module |
| `docker_network` | Docker network for ZAP and testssl; required for `localhost` targets |
| `snapshot` | Data dump and restore around `zap api` and `zap full` |
| `report` | Author, company, report language (see section 8) |

### Per-module configuration

Each test module has its own config file, `tests/<folder>/<name>.yml`.
Copy it from the example with `init`, which never overwrites existing files:

```
python audit.py --project my-app init authz,upload,cors
```

- Without `--project`, copy manually: `tests/<folder>/<name>.example.yml` to `tests/<folder>/<name>.yml`.
- `all` skips modules without a config. Running such a module directly fails with a "not found" error.

### Credentials: environment variables only

Config files reference credentials as `${VARIABLE_NAME}`. The variable names are listed in each `.example.yml`.
A variable that is not set is silently replaced by an empty string.

```
export AUTHZ_ADMIN_USER="admin@example.com"
export AUTHZ_ADMIN_PASS="..."
```

```
$env:AUTHZ_ADMIN_USER = "admin@example.com"
$env:AUTHZ_ADMIN_PASS = "..."
```

The first block is for Linux/macOS, the second for Windows PowerShell.
For ZAP behind a login, set `ZAP_AUTH_HEADER` to `Authorization: Bearer <token>`.

### Authentication

| Mode | Config |
|---|---|
| Bearer/JWT or custom header | `auth.header` and `auth.value`, e.g. `value: "${TOKEN}"` with `TOKEN="Bearer xxx"` |
| Laravel Sanctum (session cookie + CSRF) | `auth.sanctum` (`enabled`, `csrf_path`, `origin`) and `auth.login` |

- In Sanctum mode, the runner fetches the CSRF cookie, logs in, and sends `X-XSRF-TOKEN` and `Origin` automatically.
- `origin` must match `SANCTUM_STATEFUL_DOMAINS` on the server.
- The `authz` module uses `auth.mode` (`bearer` or `session_cookie`) with a list of roles; see the examples in `tests/authz-matrix/`.

## 5. Running scans

```
python audit.py authz
python audit.py all
```

| Module | What it checks | Needs |
|---|---|---|
| `headers` | Missing or information-disclosing security headers | Live target |
| `tls` | Outdated TLS protocols and ciphers | Docker, live target |
| `deps` | Dependency CVEs (Trivy), SAST (semgrep), committed secrets (gitleaks) | Docker |
| `zap baseline` | OWASP ZAP passive scan | Docker, live target |
| `zap api` | ZAP active scan from OpenAPI; destructive | Docker, live target, `openapi` |
| `zap full` | ZAP active scan; destructive, only on your own environment | Docker, live target |
| `authz` | Per-role access control: privilege escalation, IDOR, forged headers, gateway bypass | Live target, config |
| `mass-assignment` | Mass assignment (BOPLA); destructive but reversible | Live target, config |
| `upload` | Rejection of malicious file uploads | Live target, config |
| `auth-policy` | Password strength and captcha regeneration | Live target, config |
| `clientleak` | Sensitive response caching, secrets in JS/HTML, source maps, exposed files | Live target, config |
| `cors` | CORS misconfiguration | Live target, config |
| `open-redirect` | Open redirect | Live target, config |
| `webstack` | Web server version from banner mapped to CVEs; non-destructive | Live target, config |
| `injection` | SQL injection (error, boolean, optional time-based); read-only probing | Live target, config |
| `cookie-flags` | Cookie attributes (HttpOnly, Secure, SameSite); passive | Live target, config |
| `response-leak` | Sensitive data, secrets, and stack traces in API responses; passive | Live target, config |
| `openapi-coverage` | Operations declared as protected but open without login | Live target, config |
| `ratelimit` | Rate limit, account lockout, account enumeration; uses a disposable test account | Live target, config |
| `session-mgmt` | Session revocation on logout and password change; disposable test account | Live target, config |
| `captcha` | Static analysis of the captcha challenge: does the response leak the answer | Live target, config |
| `jwt` | JWT weaknesses: alg none, missing exp, weak secret, forged tokens | Live target, config |
| `ssrf` | SSRF via a local canary listener | Live target, config |
| `recon` | Subdomain OSINT; active phases (port scan, nuclei) only when enabled | Recon tools installed, optional config |
| `report` | Builds the report from the results in `reports/` | Scan results |
| `rollback` | Restores destructive actions from the journal | Rollback journal |
| `clean` | Deletes files in `reports/` | - |

- `all` runs `headers`, `deps`, `zap baseline`, every module whose config exists, and `recon` if `recon.yml` exists. It then builds the report and runs rollback.
- Each test module run on its own also builds the report automatically.
- Sub-commands: `zap baseline|api|full`, `deps gitleaks|semgrep|trivy` (one tool per run, saves memory).
- `recon` accepts free arguments: `python audit.py recon example.com -d osint -m fast --active`.
- Alternatives: `.\audit.ps1 <module>` on Windows (all modules), `make <target>` on Linux/macOS (only some modules; see `make help`).

## 6. Reading the report

After `report` or `all`, the results are in `reports/`:

| File | Content |
|---|---|
| `laporan.html` | Full report: risk summary, alert list, instances as evidence, confidence, impact, severity justification, recommendation, references |
| `laporan.md` | The same content in Markdown |
| `laporan-slides.html` | Standalone slide deck for stakeholder briefings; navigate with the left/right arrows |
| `evidence/` | Evidence screenshots (e.g. from `clientleak`); include it when sharing the report |

Severity: Critical, High, Medium, Low, Info. The "Kontrol yang Lolos (PASS)" section (passed controls) lists checks that behave correctly, as proof of coverage, not findings.

How to use the findings:

1. Start with Critical and High in the risk summary.
2. Verify each finding manually; automated results do not replace a pentest.
3. Apply the recommendation, then rerun the same module.
4. Lock the finding so it does not return (section 10).

Example output: [contoh-laporan.md](contoh-laporan.md) and [contoh-laporan.html](contoh-laporan.html).

## 7. Rollback

Destructive modules (`mass-assignment`, `ratelimit`, `session-mgmt`, and `zap api` and `zap full` with `snapshot`) restore the target automatically as the final phase, after the report is built.

1. The runner records how to restore to `reports/rollback_journal.json` immediately after each write (crash-safe).
2. After the report is built, `audit.py` restores all changes.
3. The restore log is in `reports/rollback.json`.

If the automatic restore fails (e.g. the connection drops), repeat it:

```
python audit.py rollback
```

For `zap api` and `zap full`, a failed backup cancels the scan. Without a `snapshot` block, data changes cannot be restored.

## 8. Advanced options

The global options `--project`, `--color`, and `--lang` can be placed anywhere and apply to all modules.

### Multiple projects (in parallel)

Without `--project`, the kit uses `config/`, `tests/<module>/*.yml`, and `reports/` in the kit folder (one project).
Give each project its own folder so several projects can be audited at once from separate terminals:

```
python audit.py --project my-app init authz,upload
python audit.py --project my-app all
python audit.py --project client-b headers
```

- A bare name (e.g. `my-app`) means `projects/<name>/` inside the kit (already gitignored). An absolute or relative path means that folder.
- `init` copies `targets.example.yml` and the config of the named modules, and creates `reports/`.
- Equivalents: env `SAK_PROJECT_DIR`, `make <target> PROJECT=<name|folder>`, `.\audit.ps1 <module> -Project <name|folder>`.
- Credentials stay in environment variables, so each terminal can use different values.

When running concurrently:

- Trivy uses a shared DB cache (`~/.cache/sak-trivy`); parallel runs are queued by a file lock. Set `trivy_cache_dir` for a separate cache.
- ZAP full, Trivy, and semgrep are heavy on RAM; run them in turn if memory is limited.
- Never run two destructive modules against the same target at the same time.

### Running from any directory

`python audit.py` only works from the kit folder. From another folder, use the full path to `audit.py`.
The project folder can be anywhere because config is read from the project folder.

```
python C:\tools\security-audit-kit\audit.py --project C:\Users\you\sak-projects\my-app all
& C:\tools\security-audit-kit\audit.ps1 all -Project C:\Users\you\sak-projects\my-app
python3 /opt/security-audit-kit/audit.py --project ~/sak-projects/my-app all
make -C /opt/security-audit-kit all PROJECT=/home/you/sak-projects/my-app
```

Lines 1-2 are for Windows PowerShell, lines 3-4 for Linux/macOS. With `make -C`, use an absolute path because `make` changes into the kit folder.

The `sak` shortcut saves typing the long path. Install it once:

```
function sak { python C:\tools\security-audit-kit\audit.py @args }
alias sak='python3 /opt/security-audit-kit/audit.py'
sak --project C:\Users\you\sak-projects\my-app all
sak --project C:\Users\you\sak-projects\client-b headers
```

Add line 1 to your PowerShell profile (`notepad $PROFILE`), line 2 to `~/.bashrc` or `~/.zshrc`. Lines 3-4: usage from any folder.

A relative project path is resolved from the folder where you run the command. Keep project folders outside the kit folder so they are not lost when the kit folder is deleted.

### Report author and company

The "Disusun oleh" (prepared by) line in the HTML, Markdown, and slide reports comes from the `report:` block in `targets.yml`.
The Security Audit Kit credit always stays on the "Alat" (tool) line.

```yaml
report:
  prepared_by: "Jane Doe"
  organization: "Example Corp"      # "" hides the company
  contact: "audit@example.com"      # "" hides the contact
  version: "1.0"
```

- Fields left out fall back to the kit defaults: author "Sapto Hadi", company "PT. Wahana Reka Tekindo", contact "wahanarekatekindo@gmail.com" (the contact only applies to the default company). Fill in the block above so reports carry your identity.
- Env `SAK_REPORT_AUTHOR`, `SAK_REPORT_ORG`, and `SAK_REPORT_CONTACT` override `targets.yml`.

### Console colors

Colors appear only in an interactive terminal (`auto`) and never reach JSON files or reports.

| Method | Effect |
|---|---|
| `--color always` (or just `--color`) | Force on, also into a pipe |
| `--no-color` or `--color never` | Turn off |
| env `NO_COLOR=1` | Turn off |
| env `SAK_COLOR=always\|never\|auto` | Same as `--color`; overrides `NO_COLOR` and `FORCE_COLOR` |
| env `FORCE_COLOR=1` or `CLICOLOR_FORCE=1` | Force on |

Git Bash is often not detected as a terminal; use `--color always`.

### Language and technical terms

Technical terms stay in English and are set in italics in reports; the list is in `glosarium.yml` (id, en, de).

- Choose the language with `--lang id|en|de`, env `SAK_LANG`, or `report.language` in `targets.yml` (default `en`).
- The complete text catalog currently exists only for `id`; other languages use the `id` text with the chosen language's glossary.
- Details and how to add terms: [Glossary and language](glosarium.en.md).

## 9. CI integration

- `deps` is safe to run on every PR because it needs no live target. Its result is informational (exit code 0).
- Dynamic tests need a live target; run them on a schedule against dev/staging, not production.
- Credentials go through GitHub Secrets. Test modules return exit code 1 when there are failures.

Example pipeline: [security-audit.yml](../.github/workflows/security-audit.yml).

## 10. Turning findings into tests

To lock in a finding from a pentest report, see [temuan-to-test-mapping.en.md](temuan-to-test-mapping.en.md): it maps finding classes to modules and shows how to add the test case.

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `can't open file '...\audit.py'` | Run from outside the kit folder. Use the full path, `audit.ps1`, or the `sak` shortcut (section 8). |
| `config/targets.yml belum ada` or `<folder>\config\targets.yml belum ada (project: ...)` | Config not created or wrong project path. Run `python audit.py --project <name> init`. |
| `<config> belum ada - salin dari contoh .example-nya` | Module config missing. Run `init <module>` or copy the `.example.yml` file. |
| `Docker tidak ditemukan di PATH` or scanner fails | Install Docker and make sure it is running and can pull images. |
| ZAP or testssl `Connection refused` on a `localhost` target | Inside the container, `localhost` points to the container itself. Set `docker_network` in `targets.yml`. |
| Sanctum login fails with 500 "Session store not set" | `auth.sanctum.origin` does not match the server's `SANCTUM_STATEFUL_DOMAINS`. |
| Login fails although credentials are correct | Environment variable not set (empty value). Set it in the same terminal. |
| Many login requests rejected with 429 | Target rate limit. Add a delay between requests. |
| Certificate error on a dev target with a self-signed certificate | Set `SAK_INSECURE_TLS=1` (applies to `headers` and the Python runners; not to ZAP and `tls`). |
| `clientleak` skips the browser check | Playwright is not installed (optional). |
| `semgrep` exceeds its time limit | Narrow `semgrep_paths` or raise `semgrep_timeout_minutes`. |
| Odd text such as `^[[32m`, or no color at all | Terminal does not support ANSI: use `--no-color`. No color because output is redirected or the terminal is not detected: use `--color always` and make sure `NO_COLOR` is not set. |
