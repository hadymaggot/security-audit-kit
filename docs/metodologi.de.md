[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](metodologi.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](metodologi.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Methodik

Das Kit macht aus einem OWASP-basierten Pentest-Ablauf automatisierte Regressionstests: Eine einmal gefundene Schwachstellenklasse darf nicht unbemerkt wiederkehren, und mechanische Klassen (Security-Header, TLS, Password Policy, verwundbare Abhängigkeiten) werden bei jedem Lauf abgedeckt.

## Referenzen

| Thema | Standard oder Tool |
|---|---|
| Severity | OWASP Risk Rating (Likelihood x Impact) |
| Befundkategorien | OWASP Top 10 2021, OWASP API Security Top 10 2023 |
| Geprüfte Controls | OWASP ASVS |
| DAST | OWASP ZAP |
| CVE-Abhängigkeiten und Secrets | Trivy |
| TLS | testssl.sh |
| SAST und committete Secrets | semgrep, gitleaks |

## Phasen

**Statischer Scan zuerst:** `python audit.py deps`. Er benötigt kein laufendes Ziel und ist daher auf einem PR gefahrlos ausführbar: CVE-Abhängigkeiten, SAST OWASP Top 10 und committete Secrets.

**Dynamische Prüfungen**, sobald ein dev/staging-Ziel verfügbar ist:

| Modul | Was geprüft wird |
|---|---|
| `zap baseline` | Passive Scan, greift nicht an. |
| `zap api` | Scan aus einer OpenAPI-Definition; kann über `ZAP_AUTH_HEADER` hinter einem Login laufen. |
| `authz` | Regression der Zugriffskontrolle je Rolle: Privilege Escalation, IDOR, gefälschte `X-Auth-*`-Header vom Client, Gateway-Bypass direkt zum Service-Port. |
| `mass-assignment` | Mass Assignment / Broken Object Property Level Authorization (BOPLA). |
| `clientleak` | Caching sensibler Responses, Secrets/Endpoints in JS- und HTML-Bundles, Source Maps, offengelegte Dateien. |
| `upload` | Abweisung gefährlicher Datei-Uploads. |
| `auth-policy` | Passwortstärke und Captcha-Regenerierung. |
| `cors`, `open-redirect` | CORS-Fehlkonfiguration und Open Redirect. |
| `injection` | SQL Injection (error-based, boolean-based, optional time-based); nicht-destruktiv, nur lesendes Probing. |
| `webstack` | Webserver-Version aus dem Banner, abgeglichen mit bekannten CVEs (z. B. Apache mod_http2, NGINX HTTP/2); nicht-destruktiv. |
| `tls`, `headers` | Veraltete TLS-Protokolle/-Cipher und fehlende Security-Header. |

**Bericht:** `python audit.py report` baut `reports/laporan.html`, `laporan.md` und `laporan-slides.html` zusammen. `audit.py all` ruft report am Ende automatisch auf.

Weitere Module in `PY_MODULES`: `cookie-flags`, `response-leak`, `openapi-coverage`, `ratelimit`, `session-mgmt`, `captcha`, `jwt`, `ssrf` sowie `recon`.

## Nicht-destruktiv und Rollback

Die meisten Runner senden gewöhnliche Requests und lesen Status/Inhalt der Response: kein Exploit, kein Löschen von Daten, kein Brute-Force. Upload-Payloads sind bewusst harmlos (nur Marker), um die Validierung zu prüfen.

`zap full` (Active Scan) ist abgetrennt und mit einer Warnung versehen; nur in einem eigenen Environment ausführen, nie in Production.

Einige Module schreiben ins Ziel (`mass-assignment` injiziert verbotene Felder) oder erzeugen Testdaten (`ratelimit`, `session-mgmt`). Für sie gilt:

1. Jeder Schreibvorgang wird unmittelbar nach der Ausführung ins Rollback-Journal protokolliert.
2. Als letzter Schritt nach der Berichterstellung wird das Ziel automatisch in den Ausgangszustand zurückversetzt.
3. Das Wiederherstellungsprotokoll liegt in `reports/rollback.json`; `python audit.py rollback` führt die Wiederherstellung bei Bedarf erneut aus.

So hinterlässt auch destruktives Testen das Ziel unverändert.

## OS-übergreifend

Alle Befehle laufen über `python audit.py ...`, daher ist das Verhalten unter Windows und Linux identisch. Die Scanner nutzen offizielle Docker-Images. Die `.sh`-Skripte in `scanners/` sind für Linux-Nutzer optional; `.gitattributes` erzwingt das Zeilenende LF, damit ein Bind-Mount in Container von Windows aus unproblematisch bleibt.

## Grenzen

- Der Bericht ist das Ergebnis einer Automatisierung, kein Ersatz für einen manuellen Pentest.
- Scanner-Befunde können False Positives sein; vor der finalen Severity verifizieren.
- Business-Logic-Lücken werden nur erkannt, wenn ein Test eigens dafür geschrieben wurde.
- Der Prüfumfang beschränkt sich auf die beim Lauf konfigurierten Ziele und Endpoints.
