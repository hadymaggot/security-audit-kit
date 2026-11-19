[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](panduan-penggunaan.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](panduan-penggunaan.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Benutzerhandbuch — Schritt für Schritt

Dieses Handbuch erklärt, wie man das Security Audit Kit gegen ein Ziel ausführt — von der
Installation bis zum Lesen des Berichts. Alle Befehle laufen über einen einzigen Entry Point
`python audit.py <modul>`, identisch unter Windows wie unter Linux.

> Nur für eigene Systeme oder Systeme, für deren Prüfung Sie eine schriftliche Erlaubnis
> besitzen. Prüfungen ohne Erlaubnis verstoßen gegen das Gesetz.

## 1. Voraussetzungen

- **Python 3.10+**.
- **Docker** — wird von den Scanner-Modulen (ZAP, Trivy, semgrep, gitleaks, testssl.sh) über
  offizielle Docker-Images genutzt. Die internen Prüfmodule (authz, upload usw.) benötigen kein
  Docker.
- Optional: **Playwright** für die browserbasierte Cache-Verifikation im Modul `clientleak`
  (`pip install playwright && python -m playwright install chromium`).

Installation der Python-Abhängigkeiten:

```
pip install -r requirements.txt
```

## 2. Ziel konfigurieren

Die Beispieldatei kopieren und dann dem Ziel entsprechend ausfüllen. Die echten
`*.yml`-Dateien stehen bereits in der `.gitignore`, sodass keine Zugangsdaten mitcommittet
werden.

```
cp config/targets.example.yml config/targets.yml
```

Minimalangaben in `config/targets.yml`:

| Feld | Beschreibung |
|---|---|
| `base_url` | Basis-URL des Ziels, z. B. `http://localhost:8080` |
| `tls_host` | Host für die TLS-Prüfung (Modul `tls`) |
| `header_probe_path` | Pfad für die Security-Header-Prüfung (Modul `headers`) |
| `code_path` | Repo-Pfad für den Abhängigkeits-/Secret-Scan (Modul `deps`) |

## 3. Konfiguration je Prüfmodul

Die internen Prüfmodule (`authz`, `upload`, `auth-policy`, `clientleak`, `cors`,
`open-redirect`, `mass-assignment`) besitzen jeweils eine eigene Konfigurationsdatei. Aus der
vorhandenen `.example`-Datei kopieren und dann anpassen:

```
cp tests/authz-matrix/authz_matrix.example.yml tests/authz-matrix/authz_matrix.yml
cp tests/upload-safety/upload_safety.example.yml tests/upload-safety/upload_safety.yml
# ...und so weiter für die zu verwendenden Module
```

Module, deren Konfigurationsdatei noch nicht existiert, werden beim Ausführen von `all`
übersprungen.

### Zugangsdaten über Umgebungsvariablen

Die Konfiguration verweist über `${VARIABLENNAME}` auf Zugangsdaten, statt sie in die Datei zu
schreiben. Die Umgebungsvariablen vor dem Scan setzen.

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

Die Variablennamen folgen denen, die in der jeweiligen `.example.yml`-Datei angegeben sind.

### Authentifizierung (Bearer oder Laravel Sanctum)

Zwei Modi werden unterstützt:

- **Statisches Token (Bearer/JWT oder Custom-Header)** — die Blöcke `auth.header` und
  `auth.value` ausfüllen, z. B. `value: "${TOKEN}"` mit `TOKEN="Bearer xxx"`. Token beschaffen:
  einmal am Login-Endpoint anmelden und das Token aus der Response entnehmen.
- **Laravel Sanctum (SPA, Session-Cookie + CSRF)** — den Block `auth.sanctum` aktivieren
  (`enabled: true`, `csrf_path`, `origin`) sowie `auth.login`. Der Runner holt das CSRF-Cookie,
  meldet sich an und setzt dann automatisch die Header `X-XSRF-TOKEN` und `Origin`. `origin`
  muss mit `SANCTUM_STATEFUL_DOMAINS` auf dem Server übereinstimmen.

## 4. Scan ausführen

### Ein einzelnes Modul ausführen

```
python audit.py <modul>
```

Verfügbare Module:

| Modul | Funktion | Benötigt |
|---|---|---|
| `deps` | CVE-Abhängigkeiten (Trivy) + SAST (semgrep) + committete Secrets (gitleaks) | Docker |
| `zap baseline` | OWASP ZAP Passive Scan | Docker, laufendes Ziel |
| `zap api` | OWASP ZAP Scan aus OpenAPI | Docker, laufendes Ziel, OpenAPI |
| `zap full` | OWASP ZAP Active Scan (destruktiv, nur im eigenen Environment nutzen) | Docker, laufendes Ziel |
| `authz` | Zugriffskontrolle je Rolle: Privilege Escalation, IDOR, gefälschte Header, Gateway-Bypass | Laufendes Ziel, Config |
| `mass-assignment` | Mass Assignment / BOPLA — destruktiv, aber reversibel (siehe Abschnitt Rollback) | Laufendes Ziel, Config |
| `upload` | Abweisung gefährlicher Datei-Uploads | Laufendes Ziel, Config |
| `auth-policy` | Passwortstärke und Captcha-Regenerierung | Laufendes Ziel, Config |
| `clientleak` | Caching sensibler Responses, Secrets/Endpoints in JS/HTML, Source Maps, offengelegte Dateien | Laufendes Ziel, Config |
| `cors` | CORS-Fehlkonfiguration | Laufendes Ziel, Config |
| `open-redirect` | Open Redirect | Laufendes Ziel, Config |
| `webstack` | Versionserkennung des Webservers aus Bannern → bekannte CVEs (Apache mod_http2, NGINX HTTP/2); nicht-destruktiv | Laufendes Ziel, Config |
| `injection` | SQL Injection (error/boolean-based, optional time-based); nicht-destruktiv, lesendes Probing | Laufendes Ziel, Config |
| `tls` / `headers` | Veraltete TLS-Protokolle/-Cipher, fehlende Security-Header | Laufendes Ziel |
| `report` | Fasst alle Ergebnisse zu einem Bericht zusammen | Scan-Ergebnisse in `reports/` |
| `rollback` | Setzt destruktive Aktionen aus dem Rollback-Journal erneut zurück | — |

### Den gesamten Scan ausführen

```
python audit.py all
```

Dieser Befehl führt `headers`, `deps`, `zap baseline` und dann jedes Prüfmodul aus, dessen
Konfiguration vorliegt, baut anschließend automatisch den Bericht zusammen und führt zuletzt
den Rollback aus, falls eine destruktive Aktion protokolliert wurde.

### Alternativen

- `make <modul>` (Linux/macOS, sofern `make` verfügbar).
- `./audit.ps1 <modul>` (Windows PowerShell).

## 5. Den Bericht lesen

Nach `report` oder `all` liegen die Ergebnisse unter:

- `reports/laporan.html` — vollständiger Bericht im ZAP-Stil: Risikozusammenfassung,
  Alert-Liste, Details je Befund samt Instanz (der als Nachweis geprüfte Endpoint),
  Konfidenzgrad, Auswirkung, Severity-Begründung, Empfehlung und Referenzen.
- `reports/laporan.md` — derselbe Inhalt im Markdown-Format.
- `reports/laporan-slides.html` — eigenständige Präsentationsvariante (Slide Deck) für eine
  knappe Vorstellung vor Stakeholdern; Navigation mit Pfeil links/rechts.
- `reports/evidence/` — Screenshot-Nachweise (z. B. vom browserbasierten Modul `clientleak`),
  in Bericht & Slides eingebettet. Dieser Ordner muss die Berichtsdateien beim Teilen
  begleiten.

Beispielausgabe siehe [contoh-laporan.md](contoh-laporan.md) /
[contoh-laporan.html](contoh-laporan.html).

Der Abschnitt **Bestandene Controls (LULUS)** listet die geprüften und korrekt arbeitenden
Prüfungen auf — ein Nachweis des Prüfumfangs, kein Befund.

## 6. Rollback (destruktive Module)

Destruktive Module wie `mass-assignment` schreiben ins Ziel und stellen anschließend als
letzter Schritt nach der Berichterstellung automatisch den Ausgangszustand wieder her. Der
Ablauf:

1. Snapshot der Originalwerte des Objekts.
2. Verbotenes Feld injizieren (Schreibvorgang ins Ziel).
3. Den Weg zur Wiederherstellung sofort in `reports/rollback_journal.json` protokollieren
   (crash-safe).
4. Prüfen, ob das verbotene Feld akzeptiert wurde (Befund, falls ja).
5. Nach der Berichterstellung setzt `audit.py` alle Änderungen auf die Originalwerte zurück.

Falls die automatische Wiederherstellung fehlschlägt (z. B. Verbindungsabbruch), erneut
ausführen:

```
python audit.py rollback
```

Das Wiederherstellungsprotokoll liegt in `reports/rollback.json`.

## 7. CI-Integration

- Der statische Scan (`deps`) ist auf jedem PR gefahrlos ausführbar, da er kein laufendes Ziel
  benötigt.
- Die dynamischen Prüfungen (DAST, Zugriffskontrolle, Upload usw.) benötigen ein laufendes
  Ziel; geplant gegen dev/staging ausführen, nicht gegen Production. Zugangsdaten über GitHub
  Secrets.

## 8. Befunde in Tests übersetzen

Um einen Befund aus einem Pentest-Bericht zu „fixieren", damit er nicht wiederkehrt, siehe
[temuan-to-test-mapping.md](temuan-to-test-mapping.md): die Zuordnung von Befundklassen zu
Modulen samt Vorgehen zum Hinzufügen des Testfalls.

## 9. Troubleshooting

| Symptom | Mögliche Ursache & Lösung |
|---|---|
| `config/targets.yml belum ada` | Aus `config/targets.example.yml` kopieren. |
| `<config> belum ada — salin dari contoh .example-nya` | Die `.example.yml`-Datei des betreffenden Moduls kopieren. |
| Sanctum-Login scheitert mit 500 „Session store not set" | `auth.sanctum.origin` stimmt noch nicht mit `SANCTUM_STATEFUL_DOMAINS` des Servers überein. |
| Scanner schlägt fehl | Sicherstellen, dass Docker läuft und das Image heruntergeladen werden kann. |
| Modul `clientleak` überspringt die Browserprüfung | Playwright ist nicht installiert (optional). |
| Viele Login-Requests werden mit 429 abgewiesen | Rate-Limit beim Login des Ziels; zwischen den Requests pausieren. |
