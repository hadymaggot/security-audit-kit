# Glossar und Sprache

Das Kit verwendet ein Glossar pro Sprache, [`glosarium.yml`](../glosarium.yml), damit technische
Begriffe in Konsole, Berichten und Dokumentation einheitlich bleiben.

## Schreibregeln

- Sätze verwenden die Dokumentsprache; **technische Begriffe behalten ihre ursprüngliche
  (englische) Form**, z. B. Response, Request, Session, Upload, Header, Endpoint.
- In anderen Sprachen als Englisch werden technische Begriffe in HTML-, Markdown- und
  Folienberichten *kursiv* gesetzt. Produktnamen (OWASP ZAP, Docker, Trivy) und Abkürzungen (CVE,
  XSS, RCE) bleiben unkursiv; Code, URLs sowie Header- und Pfadnamen bleiben unformatiert.
- Ein Konzept, ein Begriff. Die indonesischen Wörter `respons`, `sandi`, `sesi`, `galat` und
  `berkas` werden z. B. immer als Response, Password, Session, Error und File geschrieben, und die
  „bocor"-Gruppe wird auf Information Disclosure, exposed oder expose vereinheitlicht.
- Code-Kommentare und Docstrings werden auf Englisch geschrieben, kurz und klar.

## Sprache wählen

Priorität: Option `--lang id|en|de`, Umgebungsvariable `SAK_LANG`, `report.language` in der
`targets.yml` des Projekts, dann der Glossar-Standard (`en`).

```
python audit.py --project my-app --lang de report
```

Das Glossar gibt es für `id`, `en` und `de` (die Dokumentationssprachen). Der Text-Katalog für
Berichte und Konsole ist derzeit nur für `id` vollständig; andere Sprachen verwenden vorübergehend
den `id`-Text, nutzen aber bereits ihr eigenes Glossar. Ist der Katalog einer Sprache fertig, wird
ihr Code in `complete_text` in `glosarium.yml` ergänzt.

## Schlüssel in `glosarium.yml`

| Schlüssel | Zweck |
|---|---|
| `default` | Standardsprache (`en`). |
| `complete_text` | Sprachen mit vollständigem Text-Katalog für Bericht/Konsole. |
| `languages.<code>.italic` | `false`, wenn der Text bereits englisch ist und nichts kursiv gesetzt wird (Standard `true`). |
| `languages.<code>.terms` | Kursiv gesetzte Begriffe; ohne Groß-/Kleinschreibung, Plurale und mehrteilige Begriffe werden erkannt. |
| `languages.<code>.map` | Lokales Wort auf kanonischen Begriff; vom Prüf-Test verwendet. |
| `languages.<code>.phrases` | Geordnete `[Regex, Ersetzung]`-Paare für kontextabhängige Wörter. |

## Begriffe, Sprachen oder Projekt-Glossar ergänzen

- **Neuer Begriff:** eine Zeile in `terms` der passenden Sprache ergänzen.
- **Zu vereinheitlichendes Wort:** ein Paar `wort: begriff` in `map` ergänzen.
- **Neue Sprache:** einen Block unter `languages` ergänzen (ISO-639-1-Code).
- **Nur ein Projekt:** `<projektordner>/config/glosarium.yml` mit gleicher Struktur anlegen; es wird
  mit dem Kit-Glossar zusammengeführt.
- **Die Website:** hat ein eigenes Glossar in `site/glosarium.yml` (gleiche Struktur, nicht mit dem
  Kit-Glossar zusammengeführt); siehe den Website-Abschnitt im Beitragsleitfaden.

Danach `python -m pytest tests/unit/test_glosarium.py` ausführen. Der Test schlägt fehl, wenn
angezeigter Text (Konsole, Bericht, Empfehlungen) noch ein in `map` oder `phrases` abgebildetes Wort
verwendet, sodass nichts übersehen wird.

## Sprach-Roadmap

1. Glossar pro Sprache, Begriffsvereinheitlichung und Kursivsatz (erledigt).
2. Englischer Text-Katalog für Bericht und Konsole, danach `en` in `complete_text` ergänzen.
3. Deutscher Katalog.
