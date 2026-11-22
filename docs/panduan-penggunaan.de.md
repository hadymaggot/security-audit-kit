[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](panduan-penggunaan.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](panduan-penggunaan.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Benutzerhandbuch

Schritt-für-Schritt-Anleitung zum Ausführen des Security Audit Kit, von der Installation bis zum Lesen des Berichts.
Alle Befehle nutzen einen Entry Point, `python audit.py <modul>`, identisch unter Windows und Linux.

> Nur für eigene Systeme oder Systeme, für deren Prüfung Sie eine schriftliche Erlaubnis besitzen.
> Prüfungen ohne Erlaubnis verstoßen gegen das Gesetz.

## 1. Voraussetzungen

| Voraussetzung | Verwendet für | Prüfen |
|---|---|---|
| Python 3.10+ | Alle Module | `python --version` |
| Docker | `deps`, `zap`, `tls` (andere Module benötigen es nicht) | `docker --version` |
| make (optional) | Kurzbefehle unter Linux/macOS | `make --version` |
| Playwright (optional) | Browser-Cache-Prüfung in `clientleak` | `python -m playwright --version` |

Playwright installieren Sie mit `pip install playwright`, danach `python -m playwright install chromium`.

## 2. Installation

```
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
```

## 3. Schnellstart: erster Scan in 5 Minuten

Diese Schritte nutzen das Modul `headers`: passiv, reines Python, ohne Docker.

1. Projekt anlegen.

   ```
   python audit.py --project my-app init
   ```

   Erwartet: Ordner `projects/my-app/` mit `config/targets.yml` und `reports/`.

2. `base_url` in `projects/my-app/config/targets.yml` setzen.

   ```yaml
   base_url: "http://localhost:8080"
   ```

   Erwartet: das Ziel zeigt auf Ihre Anwendung (Dev/Staging verwenden, nicht Produktion).

3. Das Modul `headers` ausführen.

   ```
   python audit.py --project my-app headers
   ```

   Erwartet: jeder Header ist mit `ok`, `MISS` (fehlt) oder `LEAK` (gibt Informationen preis) markiert; das Ergebnis liegt in `reports/headers.json`.

4. Den Bericht erstellen.

   ```
   python audit.py --project my-app report
   ```

   Erwartet: `projects/my-app/reports/laporan.html`. Im Browser öffnen.

## 4. Konfiguration

Die echten `*.yml`-Dateien stehen bereits in `.gitignore`, damit Zugangsdaten nicht committet werden.

### targets.yml

Wichtigste Felder (vollständige Liste in [config/targets.example.yml](../config/targets.example.yml)):

| Feld | Beschreibung |
|---|---|
| `base_url` | Basis-URL des Ziels, z. B. `http://localhost:8080` |
| `openapi` | URL oder Pfad der OpenAPI-Spezifikation (für `zap api`) |
| `tls_host` | Host ohne Schema für das Modul `tls` |
| `header_probe_path` | Pfad für das Modul `headers` (Standard `/`) |
| `code_path` | Repository-Ordner für das Modul `deps` |
| `docker_network` | Docker-Netzwerk für ZAP und testssl; erforderlich bei `localhost`-Zielen |
| `snapshot` | Datensicherung und Wiederherstellung rund um `zap api` und `zap full` |
| `report` | Autor, Unternehmen, Berichtssprache (siehe Abschnitt 8) |

### Konfiguration je Modul

Jedes Testmodul hat eine eigene Konfigurationsdatei, `tests/<ordner>/<name>.yml`.
Kopieren Sie sie mit `init` aus dem Beispiel; vorhandene Dateien werden nicht überschrieben:

```
python audit.py --project my-app init authz,upload,cors
```

- Ohne `--project` manuell kopieren: `tests/<ordner>/<name>.example.yml` nach `tests/<ordner>/<name>.yml`.
- `all` überspringt Module ohne Konfiguration. Wird ein solches Modul direkt ausgeführt, endet es mit einem Fehler „belum ada" (nicht vorhanden).

### Zugangsdaten: nur über Umgebungsvariablen

Konfigurationen verweisen auf Zugangsdaten mit `${VARIABLENNAME}`. Die Variablennamen stehen in jeder `.example.yml`.
Eine nicht gesetzte Variable wird ohne Warnung durch einen leeren String ersetzt.

```
export AUTHZ_ADMIN_USER="admin@example.com"
export AUTHZ_ADMIN_PASS="..."
```

```
$env:AUTHZ_ADMIN_USER = "admin@example.com"
$env:AUTHZ_ADMIN_PASS = "..."
```

Der erste Block gilt für Linux/macOS, der zweite für Windows PowerShell.
Für ZAP hinter einem Login setzen Sie `ZAP_AUTH_HEADER` auf `Authorization: Bearer <token>`.

### Authentifizierung

| Modus | Konfiguration |
|---|---|
| Bearer/JWT oder eigener Header | `auth.header` und `auth.value`, z. B. `value: "${TOKEN}"` mit `TOKEN="Bearer xxx"` |
| Laravel Sanctum (Session-Cookie + CSRF) | `auth.sanctum` (`enabled`, `csrf_path`, `origin`) und `auth.login` |

- Im Sanctum-Modus holt der Runner das CSRF-Cookie, meldet sich an und sendet `X-XSRF-TOKEN` und `Origin` automatisch.
- `origin` muss mit `SANCTUM_STATEFUL_DOMAINS` auf dem Server übereinstimmen.
- Das Modul `authz` nutzt `auth.mode` (`bearer` oder `session_cookie`) mit einer Liste von Rollen; siehe die Beispiele in `tests/authz-matrix/`.

## 5. Scans ausführen

```
python audit.py authz
python audit.py all
```

| Modul | Was geprüft wird | Benötigt |
|---|---|---|
| `headers` | Fehlende oder Informationen preisgebende Security-Header | Laufendes Ziel |
| `tls` | Veraltete TLS-Protokolle und -Cipher | Docker, laufendes Ziel |
| `deps` | CVEs in Dependencies (Trivy), SAST (semgrep), committete Secrets (gitleaks) | Docker |
| `zap baseline` | OWASP ZAP Passive Scan | Docker, laufendes Ziel |
| `zap api` | ZAP Active Scan aus OpenAPI; destruktiv | Docker, laufendes Ziel, `openapi` |
| `zap full` | ZAP Active Scan; destruktiv, nur in der eigenen Umgebung | Docker, laufendes Ziel |
| `authz` | Zugriffskontrolle je Rolle: Privilege Escalation, IDOR, gefälschte Header, Gateway-Bypass | Laufendes Ziel, Konfiguration |
| `mass-assignment` | Mass Assignment (BOPLA); destruktiv, aber umkehrbar | Laufendes Ziel, Konfiguration |
| `upload` | Ablehnung gefährlicher Datei-Uploads | Laufendes Ziel, Konfiguration |
| `auth-policy` | Passwortstärke und Captcha-Neugenerierung | Laufendes Ziel, Konfiguration |
| `clientleak` | Caching sensibler Responses, Secrets in JS/HTML, Source Maps, offene Dateien | Laufendes Ziel, Konfiguration |
| `cors` | CORS-Fehlkonfiguration | Laufendes Ziel, Konfiguration |
| `open-redirect` | Open Redirect | Laufendes Ziel, Konfiguration |
| `webstack` | Webserver-Version aus dem Banner, zugeordnet zu CVEs; nicht destruktiv | Laufendes Ziel, Konfiguration |
| `injection` | SQL-Injection (Error, Boolean, optional Time-based); nur lesende Probes | Laufendes Ziel, Konfiguration |
| `cookie-flags` | Cookie-Attribute (HttpOnly, Secure, SameSite); passiv | Laufendes Ziel, Konfiguration |
| `response-leak` | Sensible Daten, Secrets und Stack Traces in API-Responses; passiv | Laufendes Ziel, Konfiguration |
| `openapi-coverage` | Operationen, die als geschützt deklariert, aber ohne Login offen sind | Laufendes Ziel, Konfiguration |
| `ratelimit` | Rate Limit, Account-Sperre, Account-Enumeration; nutzt ein Einweg-Testkonto | Laufendes Ziel, Konfiguration |
| `session-mgmt` | Widerruf von Sessions bei Logout und Passwortänderung; Einweg-Testkonto | Laufendes Ziel, Konfiguration |
| `captcha` | Statische Analyse der Captcha-Aufgabe: verrät die Response die Lösung | Laufendes Ziel, Konfiguration |
| `jwt` | JWT-Schwächen: alg none, fehlendes exp, schwaches Secret, gefälschte Token | Laufendes Ziel, Konfiguration |
| `ssrf` | SSRF über einen lokalen Canary-Listener | Laufendes Ziel, Konfiguration |
| `recon` | Subdomain-OSINT; aktive Phasen (Portscan, nuclei) nur wenn aktiviert | Recon-Tools installiert, optionale Konfiguration |
| `report` | Erstellt den Bericht aus den Ergebnissen in `reports/` | Scan-Ergebnisse |
| `rollback` | Stellt destruktive Aktionen aus dem Journal wieder her | Rollback-Journal |
| `clean` | Löscht Dateien in `reports/` | - |

- `all` führt `headers`, `deps`, `zap baseline`, jedes Modul mit vorhandener Konfiguration und `recon` aus, falls `recon.yml` existiert. Danach erstellt `all` den Bericht und führt den Rollback aus.
- Jedes einzeln ausgeführte Testmodul erstellt den Bericht ebenfalls automatisch.
- Unterbefehle: `zap baseline|api|full`, `deps gitleaks|semgrep|trivy` (ein Tool pro Lauf, spart Speicher).
- `recon` akzeptiert freie Argumente: `python audit.py recon example.com -d osint -m fast --active`.
- Alternativen: `.\audit.ps1 <modul>` unter Windows (alle Module), `make <target>` unter Linux/macOS (nur einige Module; siehe `make help`).

## 6. Den Bericht lesen

Nach `report` oder `all` liegen die Ergebnisse in `reports/`:

| Datei | Inhalt |
|---|---|
| `laporan.html` | Vollständiger Bericht: Risikoübersicht, Alert-Liste, Instanzen als Nachweis, Konfidenz, Auswirkung, Begründung der Severity, Empfehlung, Referenzen |
| `laporan.md` | Derselbe Inhalt als Markdown |
| `laporan-slides.html` | Eigenständige Foliensätze für Stakeholder-Präsentationen; Navigation mit Pfeil links/rechts |
| `evidence/` | Screenshots als Nachweis (z. B. von `clientleak`); beim Weitergeben des Berichts mitliefern |

Severity: Critical, High, Medium, Low, Info. Der Abschnitt „Kontrol yang Lolos (PASS)" (bestandene Controls) listet Prüfungen, die korrekt arbeiten, als Nachweis der Abdeckung, nicht als Befunde.

So nutzen Sie die Befunde:

1. Beginnen Sie mit Critical und High in der Risikoübersicht.
2. Prüfen Sie jeden Befund manuell; automatische Ergebnisse ersetzen keinen Pentest.
3. Setzen Sie die Empfehlung um und führen Sie dasselbe Modul erneut aus.
4. Sichern Sie den Befund ab, damit er nicht wiederkehrt (Abschnitt 10).

Beispielausgabe: [contoh-laporan.md](contoh-laporan.md) und [contoh-laporan.html](contoh-laporan.html).

## 7. Rollback

Destruktive Module (`mass-assignment`, `ratelimit`, `session-mgmt` sowie `zap api` und `zap full` mit `snapshot`) stellen das Ziel automatisch als letzte Phase wieder her, nachdem der Bericht erstellt wurde.

1. Der Runner protokolliert die Wiederherstellung unmittelbar nach jedem Schreibzugriff in `reports/rollback_journal.json` (absturzsicher).
2. Nach der Berichtserstellung stellt `audit.py` alle Änderungen wieder her.
3. Das Wiederherstellungsprotokoll liegt in `reports/rollback.json`.

Schlägt die automatische Wiederherstellung fehl (z. B. Verbindungsabbruch), wiederholen Sie sie:

```
python audit.py rollback
```

Bei `zap api` und `zap full` bricht eine fehlgeschlagene Sicherung den Scan ab. Ohne `snapshot`-Block lassen sich Datenänderungen nicht wiederherstellen.

## 8. Erweiterte Optionen

Die globalen Optionen `--project`, `--color` und `--lang` können an beliebiger Stelle stehen und gelten für alle Module.

### Mehrere Projekte (parallel)

Ohne `--project` nutzt das Kit `config/`, `tests/<modul>/*.yml` und `reports/` im Kit-Ordner (ein Projekt).
Geben Sie jedem Projekt einen eigenen Ordner, damit mehrere Projekte gleichzeitig aus getrennten Terminals geprüft werden können:

```
python audit.py --project my-app init authz,upload
python audit.py --project my-app all
python audit.py --project client-b headers
```

- Ein reiner Name (z. B. `my-app`) bedeutet `projects/<name>/` im Kit (bereits in `.gitignore`). Ein absoluter oder relativer Pfad bedeutet genau diesen Ordner.
- `init` kopiert `targets.example.yml` und die Konfiguration der genannten Module und legt `reports/` an.
- Gleichwertig: Env `SAK_PROJECT_DIR`, `make <target> PROJECT=<name|ordner>`, `.\audit.ps1 <modul> -Project <name|ordner>`.
- Zugangsdaten bleiben in Umgebungsvariablen, sodass jedes Terminal andere Werte nutzen kann.

Bei gleichzeitigem Betrieb:

- Trivy nutzt einen gemeinsamen DB-Cache (`~/.cache/sak-trivy`); parallele Läufe werden per Dateisperre eingereiht. Mit `trivy_cache_dir` erhalten Sie einen eigenen Cache.
- ZAP full, Trivy und semgrep belasten den RAM stark; führen Sie sie bei knappem Speicher nacheinander aus.
- Führen Sie nie zwei destruktive Module gleichzeitig gegen dasselbe Ziel aus.

### Aus einem beliebigen Verzeichnis ausführen

`python audit.py` funktioniert nur im Kit-Ordner. Aus einem anderen Ordner nutzen Sie den vollständigen Pfad zu `audit.py`.
Der Projektordner kann beliebig liegen, da die Konfiguration aus dem Projektordner gelesen wird.

```
python C:\tools\security-audit-kit\audit.py --project C:\Users\you\sak-projects\my-app all
& C:\tools\security-audit-kit\audit.ps1 all -Project C:\Users\you\sak-projects\my-app
python3 /opt/security-audit-kit/audit.py --project ~/sak-projects/my-app all
make -C /opt/security-audit-kit all PROJECT=/home/you/sak-projects/my-app
```

Zeile 1-2 gelten für Windows PowerShell, Zeile 3-4 für Linux/macOS. Bei `make -C` einen absoluten Pfad verwenden, da `make` in den Kit-Ordner wechselt.

Die Abkürzung `sak` erspart den langen Pfad. Einmalig einrichten:

```
function sak { python C:\tools\security-audit-kit\audit.py @args }
alias sak='python3 /opt/security-audit-kit/audit.py'
sak --project C:\Users\you\sak-projects\my-app all
sak --project C:\Users\you\sak-projects\client-b headers
```

Zeile 1 gehört in das PowerShell-Profil (`notepad $PROFILE`), Zeile 2 in `~/.bashrc` oder `~/.zshrc`. Zeile 3-4: Aufruf aus jedem Ordner.

Ein relativer Projektpfad wird vom Ordner aus aufgelöst, in dem der Befehl ausgeführt wird. Legen Sie Projektordner außerhalb des Kit-Ordners ab, damit sie beim Löschen des Kit-Ordners nicht verloren gehen.

### Bug-Bounty-Modus

Für Programme auf HackerOne, Bugcrowd, Intigriti und ähnlichen Plattformen. Scope und Rate-Limit von der Programmseite übernehmen und den Block `bounty:` in der `targets.yml` des Projekts aktivieren.

```yaml
bounty:
  enabled: true
  in_scope: ["app.example.com", "*.example.com"]
  out_of_scope: ["admin.example.com"]
  max_rps: 5
  allow_active: []
```

- `in_scope` verwendet Hostnamen. `*.example.com` passt nur auf Subdomains, nicht auf die Apex-Domain; diese separat eintragen. `out_of_scope` gewinnt immer.
- Jedes Modul lehnt Hosts außerhalb des Scopes ab, auch die `base_url` in der Modulkonfiguration.
- Module mit aktivem Datenverkehr werden abgelehnt: `injection`, `ratelimit`, `session-mgmt`, `mass-assignment`, `upload`, `ssrf`, `auth-policy`, `jwt`, `zap api`/`zap full` sowie Portscan, nuclei, Crawl und Fuzzing in `recon`. Den Namen nur dann in `allow_active` eintragen (`recon-active`, `zap-api`, `zap-full` für die Nicht-Python-Fälle), wenn die Programmregeln es erlauben.
- `recon` verwirft Subdomains außerhalb des Scopes vor dem Probing und übergibt `max_rps` an httpx (`-rl`). Python-Module drosseln sich nicht selbst; Konfigurationen klein halten.

Empfohlener Ablauf:

```
python audit.py --project acme-h1 init recon,clientleak,cors,open-redirect,cookie-flags,response-leak,webstack
python audit.py --project acme-h1 scope https://app.example.com
python audit.py --project acme-h1 recon
python audit.py --project acme-h1 clientleak
```

`scope` ohne Argument zeigt den aktiven Scope; mit Host oder URL antwortet es *in scope* oder *out of scope* (Exit-Code 1). Scanner-Ergebnisse sind nur eine erste Karte: vor dem Melden manuell verifizieren und einen PoC schreiben, da automatische Funde oft als Duplicate gelten.

### Autor und Unternehmen im Bericht

Die Zeile „Disusun oleh" (erstellt von) in den HTML-, Markdown- und Folienberichten stammt aus dem Block `report:` in `targets.yml`.
Der Kredit für das Security Audit Kit bleibt immer in der Zeile „Alat" (Werkzeug).

```yaml
report:
  prepared_by: "Jane Doe"
  organization: "Example Corp"      # "" blendet das Unternehmen aus
  contact: "audit@example.com"      # "" blendet den Kontakt aus
  version: "1.0"
```

- Nicht gesetzte Felder übernehmen die Standardwerte des Kits: Autor „Sapto Hadi", Firma „PT. Wahana Reka Tekindo", Kontakt „wahanarekatekindo@gmail.com" (der Kontakt gilt nur für die Standardfirma). Den Block oben ausfüllen, damit Berichte Ihre Identität tragen.
- Die Env `SAK_REPORT_AUTHOR`, `SAK_REPORT_ORG` und `SAK_REPORT_CONTACT` überschreiben `targets.yml`.

### Farben in der Konsole

Farben erscheinen nur in einem interaktiven Terminal (`auto`) und gelangen nie in JSON-Dateien oder Berichte.

| Methode | Wirkung |
|---|---|
| `--color always` (oder nur `--color`) | Erzwingt Farben, auch in eine Pipe |
| `--no-color` oder `--color never` | Ausschalten |
| Env `NO_COLOR=1` | Ausschalten |
| Env `SAK_COLOR=always\|never\|auto` | Wie `--color`; überschreibt `NO_COLOR` und `FORCE_COLOR` |
| Env `FORCE_COLOR=1` oder `CLICOLOR_FORCE=1` | Erzwingt Farben |

Git Bash wird oft nicht als Terminal erkannt; verwenden Sie `--color always`.

### Sprache und technische Begriffe

Technische Begriffe bleiben englisch und werden in Berichten kursiv gesetzt; die Liste steht in `glosarium.yml` (id, en, de).

- Wählen Sie die Sprache mit `--lang id|en|de`, der Env `SAK_LANG` oder `report.language` in `targets.yml` (Standard `en`).
- Der vollständige Textkatalog existiert derzeit nur für `id`; andere Sprachen verwenden den `id`-Text mit dem Glossar der gewählten Sprache.
- Details und Ergänzen von Begriffen: [Glossar und Sprache](glosarium.de.md).

## 9. CI-Integration

- `deps` kann bei jedem PR laufen, da kein laufendes Ziel nötig ist. Das Ergebnis ist informativ (Exit-Code 0).
- Dynamische Tests benötigen ein laufendes Ziel; führen Sie sie geplant gegen Dev/Staging aus, nicht gegen Produktion.
- Zugangsdaten über GitHub Secrets. Testmodule liefern Exit-Code 1, wenn Fehler auftreten.

Beispiel-Pipeline: [security-audit.yml](../.github/workflows/security-audit.yml).

## 10. Befunde in Tests übersetzen

Um einen Befund aus einem Pentest-Bericht abzusichern, siehe [temuan-to-test-mapping.de.md](temuan-to-test-mapping.de.md): Zuordnung von Befundklassen zu Modulen samt Hinweis, wie der Testfall ergänzt wird.

## 11. Troubleshooting

| Symptom | Ursache und Lösung |
|---|---|
| `can't open file '...\audit.py'` | Ausführung außerhalb des Kit-Ordners. Vollständigen Pfad, `audit.ps1` oder die Abkürzung `sak` verwenden (Abschnitt 8). |
| `config/targets.yml belum ada` oder `<ordner>\config\targets.yml belum ada (project: ...)` | Konfiguration nicht angelegt oder falscher Projektpfad. `python audit.py --project <name> init` ausführen. |
| `<config> belum ada - salin dari contoh .example-nya` | Modulkonfiguration fehlt. `init <modul>` ausführen oder die `.example.yml` kopieren. |
| `Docker tidak ditemukan di PATH` oder Scanner schlägt fehl | Docker installieren und sicherstellen, dass es läuft und Images laden kann. |
| ZAP oder testssl `Connection refused` bei `localhost`-Ziel | Im Container zeigt `localhost` auf den Container selbst. `docker_network` in `targets.yml` setzen. |
| Sanctum-Login schlägt mit 500 „Session store not set" fehl | `auth.sanctum.origin` stimmt nicht mit `SANCTUM_STATEFUL_DOMAINS` des Servers überein. |
| Login schlägt trotz korrekter Zugangsdaten fehl | Umgebungsvariable nicht gesetzt (leerer Wert). Im selben Terminal setzen. |
| Viele Login-Requests mit 429 abgelehnt | Rate Limit des Ziels. Pause zwischen den Requests einlegen. |
| Zertifikatsfehler bei Dev-Ziel mit selbstsigniertem Zertifikat | `SAK_INSECURE_TLS=1` setzen (gilt für `headers` und die Python-Runner; nicht für ZAP und `tls`). |
| `clientleak` überspringt die Browser-Prüfung | Playwright ist nicht installiert (optional). |
| `semgrep` überschreitet das Zeitlimit | `semgrep_paths` einengen oder `semgrep_timeout_minutes` erhöhen. |
| Seltsamer Text wie `^[[32m` oder gar keine Farbe | Terminal unterstützt kein ANSI: `--no-color` verwenden. Keine Farbe, weil die Ausgabe umgeleitet ist oder das Terminal nicht erkannt wird: `--color always` verwenden und sicherstellen, dass `NO_COLOR` nicht gesetzt ist. |
