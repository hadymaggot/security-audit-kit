[🇮🇩 Indonesia](metodologi.md) · [🇬🇧 English](metodologi.en.md) · **🇩🇪 Deutsch**

# Methodik

Das Kit passt einen OWASP-basierten Pentest-Ablauf zu automatisiertem Regressionstesting an.
Es verfolgt zwei Ziele: sicherzustellen, dass eine einmal gefundene Schwachstellenklasse nicht
unbemerkt wiederkehrt, und mechanische Schwachstellenklassen flächig abzudecken
(Security-Header, TLS, Password Policy, verwundbare Abhängigkeiten).

## Referenzen

Die Severity folgt dem OWASP Risk Rating (Likelihood x Impact), die Befundkategorien folgen den
OWASP Top 10 2021 und den OWASP API Security Top 10 2023, und die geprüften Controls basieren
auf OWASP ASVS. Eingesetztes Tooling: OWASP ZAP für DAST, Trivy für CVE-Abhängigkeiten und
Secrets, testssl.sh für TLS sowie semgrep und gitleaks für SAST und das Aufspüren bereits
committeter Secrets.

## Phasen

Der statische Scan läuft zuerst — `python audit.py deps` — und ist auf einem PR gefahrlos
ausführbar, da er kein laufendes Ziel benötigt: CVE-Abhängigkeiten, SAST OWASP Top 10 und
committete Secrets.

Sobald ein dev/staging-Ziel verfügbar ist, werden die dynamischen Prüfungen ausgeführt:

- `zap baseline` — Passive Scan, greift nicht an.
- `zap api` — Scan aus einer OpenAPI-Definition, kann über `ZAP_AUTH_HEADER` hinter einem Login laufen.
- `authz` — Regression der Zugriffskontrolle je Rolle: Privilege Escalation, IDOR, gefälschte
  `X-Auth-*`-Header vom Client und Gateway-Bypass direkt zum Service-Port.
- `mass-assignment` — Mass Assignment / Broken Object Property Level Authorization (BOPLA).
- `clientleak` — Caching sensibler Responses, Secrets/Endpoints in JS- und HTML-Bundles, Source
  Maps sowie offengelegte Dateien.
- `upload` — Abweisung gefährlicher Datei-Uploads.
- `auth-policy` — Passwortstärke und Captcha-Regenerierung.
- `cors` und `open-redirect` — CORS-Fehlkonfiguration und Open Redirect.
- `injection` — SQL Injection (error-based, boolean-based, optional time-based);
  nicht-destruktiv, nur lesendes Probing.
- `webstack` — Versionserkennung des Webservers aus Bannern und Abgleich mit bekannten CVEs
  (z. B. Apache mod_http2, NGINX HTTP/2); nicht-destruktiv.
- `tls` und `headers` — veraltete TLS-Protokolle/-Cipher und fehlende Security-Header.

In der letzten Phase baut `python audit.py report` die Dateien `reports/laporan.html` und
`laporan.md` zusammen. Der Befehl `audit.py all` ruft report am Ende automatisch auf.

## Nicht-destruktiv und Rollback

Die meisten Runner senden nur gewöhnliche Requests und lesen dann Status/Inhalt der Response —
kein Exploit, kein Löschen von Daten, kein Brute-Force. Upload-Payloads sind bewusst harmlos
gehalten (nur Marker), um die Validierung zu prüfen. `zap full` (Active Scan) ist abgetrennt
und mit einer Warnung versehen; nur in einem eigenen Environment ausführen, nicht in
Production.

Einige Module sind destruktiv, da sie ins Ziel schreiben müssen (z. B. injiziert
`mass-assignment` verbotene Felder). Für solche Module wird jeder Schreibvorgang unmittelbar
nach der Ausführung in ein Rollback-Journal protokolliert und anschließend als letzter Schritt
nach der Berichterstellung automatisch in den Ausgangszustand zurückversetzt. So bleibt auch
das destruktive Testen „gefühlt nicht-destruktiv": Das Ziel ist danach wie zuvor. Das
Wiederherstellungsprotokoll liegt in `reports/rollback.json`, und `python audit.py rollback`
kann die Wiederherstellung bei Bedarf erneut ausführen.

## OS-übergreifend

Alle Befehle laufen über `python audit.py ...`, sodass sich das Verhalten unter Windows und
Linux identisch verhält. Die Scanner nutzen offizielle Docker-Images. Die `.sh`-Skripte in
`scanners/` sind für Linux-Nutzer optional; `.gitattributes` erzwingt das Zeilenende LF, damit
ein Bind-Mount in Container von Windows aus unproblematisch bleibt.

## Grenzen

Dieser Bericht ist das Ergebnis einer Automatisierung, kein Ersatz für einen manuellen Pentest.
Scanner-Befunde können False Positives sein und müssen verifiziert werden, bevor die finale
Severity festgelegt wird. Business-Logic-Lücken werden nur erkannt, wenn ein Test eigens dafür
geschrieben wurde. Der Prüfumfang beschränkt sich auf die beim Lauf konfigurierten Ziele und
Endpoints.
