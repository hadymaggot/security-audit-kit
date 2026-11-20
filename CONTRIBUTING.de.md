[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](CONTRIBUTING.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](CONTRIBUTING.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Beitragen

Danke, dass du mithelfen möchtest. Dieses Toolkit wird projektübergreifend wiederverwendet,
daher steht im Vordergrund: Ein neuer Check ist **generisch** (per Datei konfiguriert, kein
hartkodiertes Ziel), **nicht-destruktiv**, und zu jedem Befund gibt es eine
**nachvollziehbare Remediation**.

## Kurzer Ablauf

1. Fork / Branch von `main`. Ein Branch = ein Issue/Thema.
2. Änderung + zugehörigen Test erstellen.
3. `python -m pytest -q tests/unit` muss grün sein (das ist zugleich das CI-Gate).
4. PR gegen `main` öffnen, dem Template entsprechend ausfüllen. Die CI läuft automatisch.

## Prinzipien eines Checks

- **Generisch & config-getrieben.** Ziel, Endpoint und Zugangsdaten kommen in `*.yml`-Dateien
  (Beispiele `*.example.yml`) oder Umgebungsvariablen — nicht im Code verankern.
  Zugangsdaten **immer** über Umgebungsvariablen, niemals committen.
- **Nicht-destruktiv.** Standardmäßig nur `GET`/Lesen. Wenn ein Check tatsächlich eine
  zustandsändernde Aktion braucht, standardmäßig deaktivieren und deutlich warnen.
- **Timeout = Skip, kein Befund.** Wenn das Ziel nicht erreichbar ist, als `ok` mit der Notiz
  `skip:` markieren; nicht als Lücke zählen.
- **Eigenes / autorisiertes Ziel.** Aktive Scans auf dev/staging richten.

## Einen neuen Check hinzufügen

Ein Check = ein Runner in `tests/<name>/run_<name>.py` + ein Eintrag in `remediation.py`.

1. **Runner.** Config über `--config` lesen, `--json <out>` unterstützen. Ausgabemuster je
   Element: `{"label", "status", "ok": bool, "note"}`. `tests/cors/run_cors.py` als
   kompaktestes Beispiel ansehen. `<name>.example.yml` beilegen.
2. **Remediation (Pflicht).** Einen `KB`-Eintrag in `remediation.py` mit `description`,
   `impact`, `severity`, `severity_basis`, `recommendation` (Liste, gern mit
   Lösungs-/Codebeispiel) und `references` (OWASP/BSSN) ergänzen. In `classify()` zuordnen.
3. **report.py.** Die JSON-Datei in `collect()` registrieren, damit sie in den Gesamtbericht
   einfließt.
4. **audit.py.** Das Modul registrieren, damit `python audit.py <name>` funktioniert.
5. **Test.** Einen Unit-Test in `tests/unit/` ergänzen — die Runner-Logik wird ohne Netzwerk
   geprüft (siehe `_Sess`/`_Resp` in `test_report.py`). `classify()` und die Vollständigkeit
   der `KB` müssen durch Tests abgedeckt sein.
6. **Docs.** Die Modultabelle in `README.md` und `docs/temuan-to-test-mapping.md`
   aktualisieren.

## Sprache und Glossar

- **Code-Kommentare und Docstrings sind auf Englisch**, kurz und klar (das *Warum* erklären, den
  Code nicht wiederholen). Variablen-, Funktions- und Schemaschlüssel-Namen sind ebenfalls englisch.
- **Angezeigter Text** (Konsole, Berichte, Empfehlungen) folgt dem [Glossar](docs/glosarium.de.md):
  Sätze in der Dokumentsprache, technische Begriffe bleiben englisch und werden in Berichten kursiv gesetzt.
- Einen Begriff zu ergänzen braucht eine Zeile in `glosarium.yml`; `tests/unit/test_glosarium.py`
  schlägt fehl, wenn angezeigter Text noch ein bereits vereinheitlichtes Wort verwendet.

## Commit & PR

- **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`,
  `chore:`. Scope optional, z. B. `feat(cors): …`. `feat` → minor, `fix` → patch,
  `!`/`BREAKING CHANGE` → major (Release & SemVer-Tag werden automatisch erstellt).
- Kurze, klare Nachricht: eine Betreffzeile, Details bei Bedarf im Body.
- Ein PR konzentriert sich auf eine Sache. Das zugehörige Issue angeben (`Closes #N`).

## Beispielausgabe

Siehe [docs/contoh-laporan.md](docs/contoh-laporan.md) für einen Eindruck der Form des
Endberichts — Severity-Zusammenfassung, Befunddetails + Empfehlungen und die CVE-Liste.
