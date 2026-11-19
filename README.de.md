[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](README.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](README.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Security Audit Kit

Ein per Datei konfigurierbares Security-Testing-Toolkit für Webanwendungen, das unter
Windows wie unter Linux läuft und projektübergreifend wiederverwendbar ist. Die Idee:
Pentest-Befunde in automatisierte Tests überführen, die dauerhaft in der CI laufen, und
sie anschließend zu einem nachvollziehbaren Bericht zusammenfassen — mit Methodik,
Nachweisen, Begründung der Severity, Empfehlungen samt Lösungsbeispielen sowie Verweisen
auf OWASP/BSSN.

> ⚠️ Nur für eigene Systeme oder Systeme, für deren Prüfung Sie eine schriftliche
> Erlaubnis besitzen. Aktive Scans auf dev/staging richten, nicht auf eine Production,
> die gerade von Nutzern verwendet wird.

## Module

| Modul | Funktion |
|---|---|
| `authz` | Zugriffskontrolle je Rolle: Privilege Escalation, Statussprünge, IDOR, gefälschte `X-Auth-*`-Header vom Client |
| `zap` | OWASP ZAP — Passive Scan / API-Scan aus OpenAPI, kann hinter einem Login laufen |
| `clientleak` | Caching sensibler Responses, in JS- & HTML-Bundles eingestreute Secrets/Endpoints, Source Maps, offengelegte Dateien (`.env`, `.git/`, Dumps, Backups) — läuft auch, wenn die App kein JS nutzt |
| `upload` | Abweisung gefährlicher Datei-Uploads: PDF mit JS, Polyglots, doppelte Dateiendung, zu groß |
| `auth-policy` | Passwortstärke, Captcha muss nach jedem Fehlversuch neu generiert werden |
| `mass-assignment` | Mass Assignment / Privilege Escalation (BOPLA): Einschleusen verbotener Felder (`role`, `is_admin`, `company_id`) in eigene Objekte. **Destruktiv, aber reversibel** — jeder Schreibvorgang wird in ein Journal protokolliert und nach dem Bericht automatisch zurückgesetzt (`audit.py rollback` zum erneuten Abspielen) |
| `cors` | CORS-Fehlkonfiguration: reflektierter Origin, Wildcard+Credentials, akzeptierter Origin `null` |
| `open-redirect` | Weiterleitungsparameter (`next`/`url`/`redirect`/…), die auf externe Hosts zeigen |
| `tls` / `headers` | Veraltete TLS-Protokolle/-Cipher, fehlende oder Informationen preisgebende Security-Header |
| `webstack` | Versionserkennung aus `Server`/`X-Powered-By`-Bannern und Abgleich mit bekannten CVEs (z. B. Apache mod_http2, NGINX HTTP/2, PHP2Shell); unterstützt `min_version`-Bereiche, nicht-destruktiv, `known_vulnerable` per Config aktualisierbar |
| `injection` | SQL Injection (error-based, boolean-based, optional time-based); nicht-destruktiv (lesendes Probing, verändert keine Daten) |
| `deps` | CVE-Abhängigkeiten (Trivy) + SAST OWASP Top 10 (semgrep) + committete Secrets (gitleaks) |
| `report` | Fasst alle Ergebnisse zu `reports/laporan.html` & `.md` zusammen |

Diese Automatisierung ersetzt keinen manuellen Pentest: Scanner-Befunde müssen weiterhin
verifiziert werden, und Business-Logic-Lücken werden nur erkannt, wenn ein Test eigens für
diesen Fall geschrieben wurde.

## Voraussetzungen

Python 3.10+, Docker (für ZAP/Trivy/semgrep/gitleaks/testssl). `make` optional.

## Verwendung

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
cp config/targets.example.yml config/targets.yml      # Basis-URL des Ziels eintragen
python audit.py all                                   # -> reports/laporan.html
```

Zugangsdaten über Umgebungsvariablen, nicht in Dateien ablegen (die echten `*.yml`-Dateien
stehen bereits in der gitignore). Ein Entry Point für alle Betriebssysteme:
`python audit.py <modul>`. Für kurze Befehle `make <modul>` unter Linux/macOS oder
`.\audit.ps1 <modul>` unter Windows verwenden.

## Struktur

```
audit.py            OS-übergreifender Entry Point (ein Zugang)
report.py           Zusammenbau des Gesamtberichts
remediation.py      Knowledge Base für Remediation & Begründung
config/             Ziele (Beispiel; die echten per gitignore ausgeschlossen)
scanners/           Wrapper für ZAP, testssl, Header, trivy/semgrep/gitleaks
tests/              authz-matrix, client-leak, upload-safety, auth-policy
docs/               Methodik & Zuordnung Befund -> Test
.github/workflows/  Beispiel-CI-Pipeline
Makefile, audit.ps1 Wrapper für kurze Befehle je OS
```

Mehr Details in [docs/metodologi.de.md](docs/metodologi.de.md) und
[docs/temuan-to-test-mapping.de.md](docs/temuan-to-test-mapping.de.md). Beispiel für die
Form des Endberichts: [docs/contoh-laporan.md](docs/contoh-laporan.md).

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/panduan-penggunaan.de.md](docs/panduan-penggunaan.de.md) | Schritt-für-Schritt-Anleitung: Installation, Konfiguration, Authentifizierung, Scans ausführen, Berichte lesen, Rollback, Troubleshooting |
| [docs/metodologi.de.md](docs/metodologi.de.md) | Prüfmethodik & Standardreferenzen (OWASP, ASVS, Risk Rating) |
| [docs/temuan-to-test-mapping.de.md](docs/temuan-to-test-mapping.de.md) | Befunde eines Pentest-Berichts in Testfälle je Modul übersetzen |
| [docs/contoh-laporan.md](docs/contoh-laporan.md) · [contoh-laporan.html](docs/contoh-laporan.html) · [Slides](docs/contoh-laporan-slides.html) | Beispielhafte Berichtsausgabe (fiktive Daten) — Beratungsformat + Präsentations-/Slide-Variante |
| [CONTRIBUTING.de.md](CONTRIBUTING.de.md) · [SECURITY.de.md](SECURITY.de.md) · [CODE_OF_CONDUCT.de.md](CODE_OF_CONDUCT.de.md) | Beitragen, Sicherheitsrichtlinie, Verhaltenskodex |

## Beitragen

Ablauf für Beiträge, Vorgehen zum Hinzufügen eines Checks und Commit-Konventionen stehen in
[CONTRIBUTING.de.md](CONTRIBUTING.de.md).

## Lizenz

Apache-2.0 — siehe [LICENSE](LICENSE).
