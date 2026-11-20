[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](CONTRIBUTING.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](CONTRIBUTING.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Beitragen

Dieses Toolkit wird projektübergreifend wiederverwendet. Ein neuer Check muss **generisch** sein (per Datei konfiguriert, kein hartkodiertes Ziel), **nicht-destruktiv** und mit einer **nachvollziehbaren Remediation** geliefert werden.

## In 3 Minuten einrichten

Voraussetzungen: Python 3.10+ (die CI nutzt 3.12) und git. Docker wird nur zum Ausführen der Scanner (ZAP, Trivy, ...) benötigt, nicht für die Unit-Tests.

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/unit -q
```

Erwartet: Alle Tests bestehen in etwa einer Minute, ohne laufendes Ziel. Danach einen Branch von `main` anlegen, ein Branch pro Thema.

## Projektstruktur

| Pfad | Inhalt |
|---|---|
| `audit.py` | CLI-Einstiegspunkt; die Modulregistrierung `PY_MODULES` |
| `tests/<folder>/` | Ein Check: Runner `run_<x>.py` + Konfiguration `<x>.example.yml` (Vorbild: `tests/cors/`) |
| `tests/_*.py` | Gemeinsame Helfer (Farbe, Fixture, Rollback, Snapshot, Sanctum-Login, Screenshot) |
| `tests/unit/` | Unit-Tests; das ist das CI-Gate |
| `config/targets.example.yml` | Beispiel-Zielkonfiguration; nach `config/targets.yml` kopieren (von git ignoriert) |
| `scanners/` | Wrapper für ZAP, testssl, Header, trivy/semgrep/gitleaks |
| `remediation.py` | Remediation-Wissensbasis `KB` und `classify()` |
| `report.py` | `collect()` und der HTML-/Markdown-/Folienbericht |
| `glossary.py`, `glosarium.yml` | Glossar-Lader und Glossardaten je Sprache |
| `site/`, `scripts/` | Website-Quellen; `build_site.py`, `italicize_docs.py` |
| `docs/` | Markdown-Dokumente (von Hand geschrieben) und die gebaute Website |
| `worker/` | Cloudflare Worker für die Demo des passiven Open Scanners |
| `.github/workflows/` | `ci.yml`, `release.yml`, `security-audit.yml` |

Form des Endberichts: [docs/contoh-laporan.md](docs/contoh-laporan.md).

## Neuen Check hinzufügen

Regeln für jeden Check:

- **Config-getrieben.** Ziele und Endpoints gehören in `*.yml`; Zugangsdaten nur über Umgebungsvariablen, niemals committen.
- **Standardmäßig nur lesend.** Nur `GET`/Lesen. Eine zustandsändernde Aktion ist standardmäßig deaktiviert, mit deutlicher Warnung, und ihre Schreibvorgänge laufen über `tests/_rollback.py`.
- **Timeout = Skip, kein Befund.** Als `ok` mit der Notiz `skip:` markieren.
- **Nur autorisierte Ziele.** Aktive Scans auf dev/staging richten.

Checkliste (`<x>` = Dateinamensteil, `<folder>` = Ordner unter `tests/`, `<kind>` = KB-Schlüssel):

1. **Runner.** `tests/<folder>/run_<x>.py` und `tests/<folder>/<x>.example.yml` anlegen. Der Runner akzeptiert `--config` und `--json <out>`, gibt eine Tabelle aus und endet mit Exit-Code 1, wenn es Befunde gibt. Jedes Ergebnis ist `{"label", "status", "ok": bool, "note"}`; die JSON-Datei ist `{"module", "failures", "results"}`.
2. **audit.py.** Einen Eintrag in `PY_MODULES` ergänzen. Damit funktionieren `python audit.py <name>`, `init` und `all` (führt das Modul aus, wenn seine Config im Projekt vorhanden ist). Schreibt der Check ins Ziel, zusätzlich `<name>` in `ROLLBACK_AFTER` aufnehmen.
3. **report.py.** `("<x>.json", "<folder>")` im Tupel in `collect()` ergänzen.
4. **remediation.py, KB (Pflicht).** `KB["<kind>"]` mit genau diesen Schlüsseln ergänzen.
5. **remediation.py, classify.** Das Ergebnis in `classify(module, title)` auf `<kind>` abbilden. Alternativ `kind` an jedem Ergebnis setzen und das Modul im Kind-Hint-Zweig in `collect()` eintragen. Ein nicht zugeordnetes Ergebnis fällt auf `zap-generic` zurück.
6. **Tests.** `tests/unit/test_<x>.py` für die Runner-Logik ohne Netzwerk ergänzen (gefälschte Session, siehe `_Sess`/`_Resp` in `tests/unit/test_authz_matrix.py`), dazu eine `classify()`-Assertion und einen `collect()`-Fall in `tests/unit/test_report.py`. `test_all_kb_entries_wellformed` prüft bereits jeden KB-Eintrag.
7. **Docs.** Eine Zeile in der Modultabelle von `README.md`/`.en.md`/`.de.md`, in `docs/temuan-to-test-mapping*.md` und in den Phasen von `docs/metodologi*.md` ergänzen (alle drei Sprachen). Ein Shortcut in `Makefile` oder `audit.ps1` ist optional.

```python
"<name>": ("<folder>", "run_<x>.py", "<x>.yml", "<x>.json"),
```

```python
"<kind>": {
    "description": "...",
    "impact": "...",
    "severity": "Medium",
    "severity_basis": "...",
    "recommendation": ["...", "..."],
    "references": ["..."],
},
```

KB-Regeln: `severity` ist eines von Critical, High, Medium, Low, Info; `severity_basis` nennt Likelihood x Impact; `recommendation` ist eine nicht leere Liste, die ein Lösungsbeispiel enthalten darf; `references` ist eine nicht leere Liste (OWASP, BSSN).

## Sprach- und Glossarregeln

1. Code-Kommentare und Docstrings sind auf Englisch, kurz, und erklären das Warum.
2. Identifier und Schemaschlüssel (Config, JSON, KB) sind englisch. `tests/unit/test_english_code.py` sichert das ab.
3. Angezeigter Text (Konsole, Berichte, Empfehlungen) folgt dem [Glossar](docs/glosarium.de.md): Sätze in der Dokumentsprache, technische Begriffe englisch. Derzeit gibt es den Text-Katalog nur auf Indonesisch.
4. Ein Begriff braucht eine Zeile in `glosarium.yml`. `tests/unit/test_glosarium.py` schlägt fehl, wenn angezeigter Text noch ein vom Glossar vereinheitlichtes Wort verwendet.
5. Dokumente: `tests/unit/test_docs.py` verlangt dieselben `##`-Abschnitte und dieselben Befehle in allen drei Sprachen sowie gültige Links. Nach dem Bearbeiten eines indonesischen Dokuments ausführen:

```bash
python scripts/italicize_docs.py
```

## Website

`docs/index.html`, `docs/scan.html`, `docs/id/`, `docs/de/` und `docs/sitemap.xml` werden generiert; nicht direkt bearbeiten. Die Quellen liegen in `site/`: Vorlagen (`*.template.html`), Wörterbücher (`site/i18n/id|en|de.json`) und das Seiten-Glossar (`site/glosarium.yml`), das vom Kit-Glossar getrennt ist.

1. Vorlage oder Wörterbuch ändern. Denselben Schlüssel in allen drei Sprachen ergänzen.
2. Die Website bauen.
3. Den Website-Test ausführen; er schlägt fehl, wenn der Build veraltet oder ein Wörterbuch unvollständig ist.

```bash
python scripts/build_site.py
python -m pytest tests/unit/test_site.py -q
```

## Commits und PRs

1. Conventional Commits verwenden: `type(scope): description`, mit den Typen `feat`, `fix`, `docs`, `test`, `ci`, `refactor`, `chore`. `feat` erhöht minor, `fix` patch, `!` oder `BREAKING CHANGE` major.
2. Betreff kurz halten; einen Body nur, um das Warum zu erklären. Ein PR, eine Absicht; das Issue mit `Closes #N` angeben.
3. Die Checkliste des PR-Templates ausfüllen.
4. Die CI (`ci.yml`) läuft bei jedem PR und Push auf `main`: `py_compile` für `audit.py`, `report.py`, `remediation.py` und alle Runner, danach `pytest -q tests/unit`. `security-audit.yml` führt bei PRs zusätzlich den statischen Scan (`deps`) aus; er ist rein informativ.
5. Release und SemVer-Tag werden jeden Monat automatisch erstellt, wenn `main` neue Commits hat (`release.yml`).
