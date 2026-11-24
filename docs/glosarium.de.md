# Glossar und Sprache

Das Kit führt ein Glossar pro Sprache, [`glosarium.yml`](../glosarium.yml), damit technische Begriffe in Konsole, Berichten und Dokumentation einheitlich bleiben.

## Schreibregeln

- Sätze verwenden die Dokumentsprache; **technische Begriffe behalten ihre ursprüngliche (englische) Form**, z. B. Response, Request, Session, Upload, Header, Endpoint.
- In anderen Sprachen als Englisch werden technische Begriffe in HTML-, Markdown- und Folienberichten kursiv gesetzt. Produktnamen (OWASP ZAP, Docker, Trivy) und Abkürzungen (CVE, XSS, RCE) bleiben unkursiv; Code, URLs sowie Header- und Pfadnamen bleiben unformatiert.
- Ein Konzept, ein Begriff. Die indonesischen Wörter `respons`, `sandi`, `sesi`, `galat` und `berkas` werden immer als Response, Password, Session, Error und File geschrieben; die „bocor"-Gruppe wird auf Information Disclosure, exposed oder expose vereinheitlicht.
- Code-Kommentare und Docstrings sind auf Englisch, kurz und klar.

## Sprache wählen

Priorität: Option `--lang id|en|de`, Umgebungsvariable `SAK_LANG`, `report.language` in der `targets.yml` des Projekts, dann der Glossar-Standard (`id`).

```
python audit.py --project my-app --lang de report
```

Das Glossar gibt es für `id`, `en` und `de`. Der Text-Katalog für Berichte ist für `id`, `en` und `de` vollständig. Der Quelltext steht auf Indonesisch im Code; die Übersetzungen liegen in `locales/text.<sprache>.yml` (Berichtstext) und `locales/kb.<sprache>.yml` (Beschreibung, Auswirkung und Empfehlung je Befundtyp) und funktionieren wie gettext oder Transifex. Prüfungsnamen und Belege je Instanz, die die Testmodule zur Laufzeit schreiben, werden über geordnete Regex-Regeln in `locales/evidence.<sprache>.yml` übersetzt, da diese Sätze Werte wie URLs und Status enthalten; Beispiele stehen in `tests/unit/evidence_examples.yml`. Texte von Drittwerkzeugen (zum Beispiel ZAP-Beschreibungen), Daten aus der Config und Konsolenmeldungen werden nicht übersetzt. Sprachen mit vollständigem Katalog stehen in `complete_text` in `glosarium.yml`.

## Schlüssel in `glosarium.yml`

| Schlüssel | Zweck |
|---|---|
| `default` | Standardsprache (`id`). |
| `complete_text` | Sprachen mit vollständigem Text-Katalog für Bericht/Konsole. |
| `languages.<code>.italic` | `false`, wenn der Text bereits englisch ist und nichts kursiv gesetzt wird (Standard `true`). |
| `languages.<code>.terms` | Kursiv gesetzte Begriffe; ohne Groß-/Kleinschreibung, Plurale und mehrteilige Begriffe werden erkannt. |
| `languages.<code>.map` | Lokales Wort auf kanonischen Begriff; vom Prüf-Test verwendet. |
| `languages.<code>.phrases` | Geordnete `[Regex, Ersetzung]`-Paare für kontextabhängige Wörter. |

## Begriffe, Sprachen oder Projekt-Glossar ergänzen

Einen Begriff ergänzen:

1. Eine Zeile in `terms` der passenden Sprache ergänzen.
2. Muss ein lokales Wort durch diesen Begriff ersetzt werden, ein Paar `wort: begriff` in `map` ergänzen.
3. `python -m pytest tests/unit/test_glosarium.py` ausführen. Der Test schlägt fehl, wenn angezeigter Text (Konsole, Bericht, Empfehlungen) noch ein in `map` oder `phrases` abgebildetes Wort verwendet.

Weitere Fälle:

- **Neue Sprache:** einen Block unter `languages` ergänzen (ISO-639-1-Code).
- **Nur ein Projekt:** `<projektordner>/config/glosarium.yml` mit gleicher Struktur anlegen; es wird mit dem Kit-Glossar zusammengeführt.
- **Die Website:** hat ein eigenes Glossar in `site/glosarium.yml` (gleiche Struktur, nicht mit dem Kit-Glossar zusammengeführt); siehe den Website-Abschnitt im [Beitragsleitfaden](../CONTRIBUTING.de.md).

## Sprach-Roadmap

1. Glossar pro Sprache, Begriffsvereinheitlichung und Kursivsatz (erledigt).
2. Englischer und deutscher Text-Katalog für Berichte (erledigt). Prüfung mit `python scripts/catalog_status.py`, das nicht übersetzte, veraltete oder in den Platzhaltern abweichende Texte meldet.
3. Übersetzung der Prüfungsnamen und Belege je Instanz aus den Testmodulen (erledigt). Konsolenmeldungen bleiben indonesisch, weil der Runner sie liest.
