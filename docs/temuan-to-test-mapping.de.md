[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](temuan-to-test-mapping.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](temuan-to-test-mapping.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Einen Pentest-Bericht in Tests übersetzen

Einen Befund aus einem Pentest-Bericht (etwa von BSSN/Gov-CSIRT) fixieren, damit er nicht wiederkehrt: pro Befund das passende Modul bestimmen und dann den Fall hinzufügen.

## Befundklasse zu Modul

| Befundklasse | Modul | Fall hinzufügen |
|---|---|---|
| Broken Access Control / Privilege Escalation | `authz` | Sensiblen Endpoint ergänzen, `expect: { regular_user: deny }` |
| Lack of authorization status / Ablaufsprung | `authz` | Endpoint zur Statusänderung + Status-Body, `deny` für die nicht berechtigte Rolle |
| IDOR | `authz` | Endpoint, der die id eines fremden Accounts verwendet, `deny` |
| Authz-Header vom Client vertraut | `authz` | Block `forged_headers` ausfüllen |
| Microservice direkt exponiert (Gateway/ForwardAuth umgangen) | `authz` | Endpoint mit `base_url` auf dem Service-Port + `expect: { anon: deny }` und Block `forged_headers` `as_role: anon` zu diesem Port (siehe `authz_matrix.traefik-sanctum.example.yml`) |
| SQL Injection | `injection` (oder `zap api`) | `targets` ausfüllen (path, param, location, baseline); Erkennung error/boolean-based, time-based optional. Nicht-destruktiv; Befund vor finaler Severity verifizieren |
| Stored/Reflected XSS | `zap` + `upload` | Scannen; falls XSS über Upload, das Upload-Modul verwenden |
| Gefährlicher Upload (JS in PDF, Polyglot, doppelte Endung, oversize) | `upload` | Bereits abgedeckt; `allow_only`/`max_bytes` anpassen, `endpoint.data` für Pflichtfelder nutzen und `cleanup` ausfüllen, damit akzeptierte Testdateien automatisch gelöscht werden |
| Mass Assignment / Privilege Escalation (BOPLA) | `mass-assignment` | `targets` ausfüllen (get/update/inject/fields). DESTRUKTIV, aber reversibel: jeder Schreibvorgang wird ins Journal protokolliert & nach dem Bericht automatisch zurückgesetzt (`audit.py rollback` für manuelles Replay) |
| Weak Password Policy | `auth-policy` | `register` oder `password_checks` + `weak_passwords` ausfüllen; `strong_password` als Control ergänzen. Nur ein 422 im Passwortfeld gilt als abgelehnt |
| Improper Captcha | `auth-policy` | Block `captcha` ausfüllen |
| CORS-Fehlkonfiguration | `cors` | `paths` ausfüllen; reflektierten ACAO / Wildcard+Creds / Origin null prüfen |
| Open Redirect | `open-redirect` | `paths` + `params` ausfüllen; Location auf externen Host prüfen |
| Deprecated Cryptography | `tls` | `python audit.py tls` |
| Missing Security Header | `headers` | `python audit.py headers` |
| Verwundbare Version von Webserver/Komponente (CVE) | `webstack` | `known_vulnerable` ausfüllen (server, max_version, cve); nicht-destruktiv, liest `Server`/`X-Powered-By`-Banner + HTTP/2. Bei neuem CVE aktualisieren (z. B. Apache mod_http2, NGINX HTTP/2) |
| Caching sensibler Responses | `clientleak` | `sensitive_paths` ausfüllen; `Cache-Control: no-store` prüfen |
| Caching sensibler Responses (Nachweis im Browser gespeichert) | `clientleak` | `browser_cache.enabled: true` (benötigt Playwright + Chromium) |
| Admin-Secret/-Endpoint in JS geleakt (ursprünglicher BSSN-Befund) | `clientleak` | `auto_discover_js` + `internal_endpoints` |
| Secret/Endpoint in HTML geleakt (App ohne JS) | `clientleak` | `scan_html: true` |
| Sensible Datei offengelegt (`.env`, `.git/`, Dump, Backup) | `clientleak` | `probe_sensitive_files: true` |
| Source Map (.map) in Production offengelegt | `clientleak` | Automatisch beim Durchsuchen von JS |
| Veraltete Abhängigkeit (CVE) | `deps` | Automatisch; CVE erscheint im Bericht |

## Der Ablauf

1. Den Bericht lesen und jeden Befund samt Ort auflisten (Endpoint/Parameter).
2. Auf ein Modul in der obigen Tabelle abbilden und den Fall in der `*.yml` dieses Moduls ergänzen. Dort keine Zugangsdaten ablegen; Umgebungsvariablen verwenden.
3. `python audit.py all` ausführen. Der alte Befund muss jetzt fehlschlagen (rot): Der Test fängt die Lücke tatsächlich ab.
4. Die App korrigieren, erneut ausführen, bis es besteht (grün), und dann in der CI einrichten, damit Regressionen automatisch erkannt werden.

`reports/laporan.html` enthält je Befund: Beschreibung, Nachweis, Auswirkung, Severity-Begründung, Empfehlung samt Lösungsbeispiel und Standardverweis. Bereit, als Nachweis der Nachverfolgung beigelegt zu werden.
