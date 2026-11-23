[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](README.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](README.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Security Audit Kit

![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
[![Sponsern auf GitHub](https://img.shields.io/badge/Sponsern_auf-GitHub-ea4aaa?style=flat&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/hadymaggot)
[![Unterstützen auf Saweria](https://img.shields.io/badge/Unterst%C3%BCtzen_auf-Saweria-faae2b?style=flat&logo=buymeacoffee&logoColor=white)](https://saweria.co/hadymaggot)

Ein per Datei konfiguriertes Security-Testing-Toolkit für Webanwendungen: Es überführt Pentest-Befunde in automatisierte Tests und fasst die Ergebnisse zu einem nachvollziehbaren Bericht zusammen.

- Prüft mehr als 20 Module: Header, TLS, Zugriffskontrolle, Upload, Injection, JWT, CORS, Abhängigkeiten und mehr.
- Standardmäßig nicht-destruktiv. Module, die Daten schreiben (`mass-assignment`, `ratelimit`, `session-mgmt`), und aktive ZAP-Scans mit `snapshot`-Block werden per Rollback automatisch wiederhergestellt.
- Bericht auf Beraterniveau als HTML, Markdown und Slides: Nachweise, Begründung der Severity, Empfehlungen mit Lösungsbeispielen und Verweise auf OWASP/BSSN.

> Nur für eigene Systeme oder Systeme, für deren Prüfung Sie eine schriftliche Erlaubnis besitzen. Aktive Scans auf dev/staging richten, nicht auf Production.

## Quick start

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
python audit.py --project my-app init
# projects/my-app/config/targets.yml bearbeiten: base_url: "https://dev.example.com"
python audit.py --project my-app headers
python audit.py --project my-app report
```

Erwartet: Jeder Header wird als `ok`, `MISS` oder `LEAK` ausgegeben (Exit-Code 1 bei Befunden), danach entsteht `projects/my-app/reports/laporan.html`. Die Datei im Browser öffnen.

## Modules

Aufruf mit `python audit.py --project my-app <modul>`. `all` führt jedes Modul mit vorhandener Config aus, danach Bericht und Rollback.

| Modul | Prüfungen | Zugangsdaten? |
|---|---|---|
| `headers` | Fehlende Security-Header; Offenlegung über `Server`/`X-Powered-By` | Nein |
| `tls` | Veraltete TLS-Protokolle/-Cipher und TLS-Schwachstellen (testssl.sh) | Nein |
| `webstack` | Version aus `Server`/`X-Powered-By`-Bannern auf CVEs abgebildet | Nein |
| `zap` | OWASP ZAP: `baseline` (passiv), `api` aus OpenAPI, `full` (aktiv) | Optional |
| `deps` | CVEs in Abhängigkeiten (Trivy), SAST (semgrep), committete Secrets (gitleaks) | Nein |
| `recon` | Passives OSINT (subfinder, dnsx, httpx); Portscan und nuclei nur bei Aktivierung in der Config | Nein |
| `clientleak` | Caching sensibler Responses, Secrets/Source Maps in JS und HTML, offengelegte Dateien (`.env`, `.git/`) | Optional |
| `cookie-flags` | `HttpOnly`, `Secure`, `SameSite` und Laufzeit von Cookies | Optional |
| `cors` | Reflektierter Origin, Wildcard mit Credentials, Origin `null` | Optional |
| `open-redirect` | Weiterleitungsparameter (`next`, `url`, `redirect`) auf externe Hosts | Optional |
| `response-leak` | Sensible Schlüssel, Secrets, Stack Traces und interne IPs in API-Responses | Optional |
| `openapi-coverage` | GET-Operationen, die laut OpenAPI geschützt, aber ohne Login offen sind | Nein |
| `captcha` | Captcha-Antworten, die in der Challenge-Response preisgegeben werden | Nein |
| `auth-policy` | Passwortstärke, Captcha muss sich jedes Mal ändern | Optional |
| `authz` | Zugriffskontrolle je Rolle: Privilege Escalation, IDOR, gefälschte `X-Auth-*`-Header | Ja |
| `upload` | Abweisung gefährlicher Uploads: PDF mit JS, Polyglot, doppelte Dateiendung | Optional |
| `injection` | SQL Injection: error-based, boolean-based und time-based (optional) | Optional |
| `jwt` | Algorithmus `none`, schwache Secrets, gefälschte Tokens oder Tokens ohne `exp` | Ja |
| `ssrf` | Endpoints, die URLs annehmen, geprüft mit lokalem Canary-Listener | Optional |
| `mass-assignment` | Verbotene Felder (`role`, `is_admin`) an eigenen Objekten; automatisch wiederhergestellt | Ja |
| `ratelimit` | Rate Limit, Account-Lockout und Account-Enumeration an einem Einweg-Testkonto | Ja |
| `session-mgmt` | Sessions werden nach Logout und Passwortwechsel widerrufen | Ja |

Weitere Befehle: `init`, `report`, `rollback`, `clean`. Vollständige Liste: `python audit.py --help`. Scanner-Ergebnisse müssen weiterhin verifiziert werden; Business-Logic-Lücken werden nur erkannt, wenn ein Test für diesen Fall geschrieben wurde.

## Requirements

- [ ] Python 3.10+ und `pip install -r requirements.txt`
- [ ] Docker für `zap`, `tls` und `deps`
- [ ] Optional: Playwright für die Browser-Cache-Prüfung in `clientleak`
- [ ] Zugangsdaten über Umgebungsvariablen, nicht in Dateien

## Documentation

| Dokument | Inhalt |
|---|---|
| [Benutzerhandbuch](docs/panduan-penggunaan.de.md) | Installation, Config, Authentifizierung, Scans, Bericht, Rollback, Troubleshooting |
| [Glossar](docs/glosarium.de.md) | Technische Begriffe je Sprache und die Option `--lang` |
| [Methodik](docs/metodologi.de.md) | Prüfphasen und Normverweise (OWASP, ASVS) |
| [Zuordnung Befund zu Test](docs/temuan-to-test-mapping.de.md) | Pentest-Befunde in Testfälle überführen |
| [Beispielbericht](docs/contoh-laporan.md) | Beispielausgabe mit fiktiven Daten ([HTML](docs/contoh-laporan.html), [Slides](docs/contoh-laporan-slides.html)) |
| [Contributing](CONTRIBUTING.de.md) | Beitragsablauf und Hinzufügen eines Checks |
| [Website](https://hadymaggot.github.io/security-audit-kit/de/) | Projektseite und passiver Open Scanner ([Worker-Setup](worker/README.md)) |

Erweiterte Optionen (im Handbuch): [mehrere Projekte](docs/panduan-penggunaan.de.md#mehrere-projekte-parallel), [aus beliebigem Verzeichnis ausführen](docs/panduan-penggunaan.de.md#aus-einem-beliebigen-verzeichnis-ausführen), [Konsolenfarben](docs/panduan-penggunaan.de.md#farben-in-der-konsole), [Sprache und Begriffe](docs/panduan-penggunaan.de.md#sprache-und-technische-begriffe).

## Project layout

```text
audit.py, audit.ps1, Makefile   # OS-übergreifender Entry Point und kurze Wrapper
report.py                       # Zusammenführung des Berichts
remediation.py                  # Wissensbasis für Behebung und Severity-Begründung
glossary.py, glosarium.yml      # Glossar-Loader und -Daten
config/                         # targets.example.yml (echte targets.yml ist gitignored)
tests/<modul>/                  # Runner und Beispiel-Config je Modul
tests/unit/                     # Unit-Tests
scanners/                       # Wrapper-Skripte für ZAP, testssl, Header, deps
projects/                       # per init erzeugte Projekte (gitignored)
docs/                           # Handbücher und gebaute Website
site/                           # Templates, id/en/de-Wörterbücher, Website-Glossar
worker/                         # Cloudflare Worker für den Open Scanner
.github/workflows/              # CI-Pipelines
```

## Contributing

Ablauf, Hinzufügen eines Checks und Commit-Konventionen: [CONTRIBUTING.de.md](CONTRIBUTING.de.md).

## License

Apache-2.0, siehe [LICENSE](LICENSE).
