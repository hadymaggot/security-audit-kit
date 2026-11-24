[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](runner.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](runner.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Autonomer Audit-Runner

`runner.py` führt den gesamten Audit-Ablauf vom Start bis zum Report ohne manuelle Schritte und ohne KI aus: Er startet den Stack, meldet alle Konten an, erzeugt die Modul-Configs, führt die Scans und die dynamischen Tests aus und erstellt dann den Report. Alles, was vom Projekt abhängt, steht in einer einzigen YAML-Datei, sodass derselbe Runner für bestehende und neue Projekte genutzt werden kann.

## Voraussetzungen

- [ ] Python 3.10+ und `pip install -r requirements.txt`.
- [ ] Docker für `zap`, `tls`, `deps` und für Ziele mit einem Container-Stack.
- [ ] Eine Projekt-Config-Datei (siehe [Neues Projekt hinzufügen](#neues-projekt-hinzufügen)).
- [ ] Zugangsdaten der Testkonten in einer Env-Datei oder einem Seeder, niemals in der Config.

## Schnellstart

```bash
python runner.py init --config projects/example-app/audit.config.yml
python runner.py check --config projects/example-app/audit.config.yml
python runner.py run --config projects/example-app/audit.config.yml --target local
python runner.py run --config projects/example-app/audit.config.yml --target dev --skip ratelimit
python runner.py down --config projects/example-app/audit.config.yml
```

Ergebnis: ein eindeutig benannter Report-Ordner unter `project.output` mit HTML, Markdown, Folien, Belegen je Modul und einer Zusammenfassung des Laufs. Exit-Code 2 bedeutet, dass ein Fehler den Lauf gestoppt hat; Sicherheitsbefunde ändern den Exit-Code nicht, da sie im Report stehen.

## Ablauf eines Laufs

1. Prüft die Voraussetzungen und lädt die Config.
2. Ziel `stack`: startet den Stack über die Schritte in `stack.up`. Die Schritte sind idempotent, ein gesunder Dienst bleibt unberührt.
3. Meldet alle Konten an, mit Pacing um das Login-Rate-Limit, und liest dann die tatsächlichen Berechtigungen jedes Kontos.
4. Erzeugt die Modul-Configs und die Zugriffsmatrix aus diesen Berechtigungen.
5. Führt die Module in der Reihenfolge von `pipeline` aus. Ein fehlschlagendes Modul stoppt die anderen nicht.
6. Erstellt den Report, prüft ihn auf durchgesickerte Geheimnisse und kopiert das Ergebnis in den Ausgabeordner.
7. Optional `--down-after`: stoppt den Stack.

## Konfiguration

Ein vollständiges kommentiertes Beispiel steht in [config/runner.example.yml](../config/runner.example.yml).

Legen Sie die Config unter `projects/<name>/audit.config.yml` im Toolkit ab, einem Ordner, der wie jedes andere Toolkit-Projekt nicht eingecheckt wird, und setzen Sie `project.repo` auf den Ort des Anwendungs-Repos. Dieses Repo erhält die Report-Kopie und ist die Basis der Pfade der `stack`-Schritte.

`project.language` wählt die Sprache des Reports (`id`, `en` oder `de`) und ist standardmäßig `id`; die Option `--lang` überschreibt sie. Der Reporttext ist derzeit nur auf Indonesisch vollständig, daher wechseln `en` und `de` vorerst nur das Glossar der Fachbegriffe. Die Zusammenfassung des Laufs und die Konsolenmeldungen des Runners selbst sind auf Indonesisch.

| Abschnitt | Inhalt |
|---|---|
| `project` | Name, Kurzschlüssel für Dateinamen und Ausgabeordner |
| `api` | Endpunkte für Login, Profil, Refresh, Logout, Passwortwechsel und Ort der OpenAPI |
| `accounts` | Kontoquelle je Zieltyp, Rollen mit niedrigen und hohen Rechten |
| `stack` | Schritte zum Starten und Stoppen des Stacks sowie Datenbankzugriff |
| `targets` | Ziele mit `kind` `stack` oder `remote` |
| `pipeline` | Reihenfolge der Module |
| `modules` | Einstellungen je Modul, die `targets`, die es ausführen, und `by_target` |

```yaml
modules:
  injection:
    targets: [local, dev]
    time_based: false
    by_target: { local: { time_based: true } }
```

## Ziele und Sicherheitsstufen

- **`stack`:** Der Runner startet den Stack und testet ihn. Konten werden über die Abfrage in `accounts.stack` aus der Datenbank gelesen.
- **`remote`:** testet einen bestehenden Host. URL, Stufe und Konten werden aus der Env-Datei des Ziels gelesen: `APP_USER_<ROLE>` und `APP_PASS_<ROLE>`.
- **Stufe `prod`:** Es laufen nur passive Module (`safety.passive_modules`). Verwenden Sie `--force-active` nur, wenn Sie das System besitzen und eine schriftliche Genehmigung haben.
- **Module, die Daten schreiben:** `upload`, `mass-assignment`, `ssrf`, `session`, `auth-policy` und `zap` laufen nur auf Zielen, die Sie in der Config selbst aktivieren, und meist nur auf `stack`.

## Reportnamen und Ablageort

Jeder Lauf erstellt einen neuen Ordner und neue Dateien nach dem Muster `security-audit-kit_<project>_<target>_<YYYYMMDD-HHMMSS>`, sodass ein erneuter Lauf nach einer Korrektur einen früheren Report nie überschreibt. Er enthält:

- `<name>.html`, `<name>.md` und `<name>-slides.html`: den vollständigen Report und die Folien.
- `<name>-ringkasan.md`: welche Module liefen, übersprungen wurden oder fehlschlugen, samt Toolkit-Version.
- Einen Ordner `data/` mit der Rohausgabe jedes Moduls (JSON und ZAP-Ausgabe) samt einer statischen README in drei Sprachen (`README.md`, `README.en.md`, `README.de.md`), die den Inhalt erklärt. Der Belegordner bleibt, falls Screenshots vorhanden sind, auf oberster Ebene, weil der Report darauf verweist.

`RIWAYAT.md` im übergeordneten Ordner enthält eine Zeile je Lauf, damit sich Läufe leicht vergleichen lassen. Vor dem Kopieren wird der gesamte Report auf bekannte Passwörter, Token und Schlüssel geprüft; ist etwas durchgesickert, wird nur der Ordner dieses Laufs gelöscht.

## Rate Limit und Login-Kontingent

Der Login an einer Anwendung, die Versuche begrenzt, kann mit HTTP 429 fehlschlagen. Der Runner liest `Retry-After` und wartet, und `authz` wiederholt eine Anfrage mit 429, statt sie als Befund zu melden. Bei einem Ziel mit Dutzenden Konten kann ein Lauf dauern, weil er auf Rate-Limit-Fenster wartet. Verwenden Sie `--roles-limit`, wenn nur ein Teil der Konten nötig ist.

## Neues Projekt hinzufügen

1. Führen Sie `init` aus, um das Config-Gerüst aus dem Beispiel zu erstellen.
2. Füllen Sie `api`, `accounts`, `targets` und die relevanten Module aus. Beginnen Sie mit den passiven Modulen und ergänzen Sie den Rest schrittweise.
3. Führen Sie `check` aus, bis keine Probleme mehr gemeldet werden.
4. Führen Sie `run` auf einem sicheren Ziel aus und lesen Sie dann die Zusammenfassung des Laufs.

Ein neues Ziel, etwa Staging, wird unter `targets` mit eigener Env-Datei ergänzt.

## Einschränkungen

- Scanner-Ergebnisse müssen weiterhin verifiziert werden; Geschäftslogikfehler werden nur gefunden, wenn der Fall in der Config steht.
- `session` prüft Bearer-Authentifizierung mit Refresh-Token und braucht ein Konto mit hohen Rechten, um ein einmaliges Testkonto anzulegen.
- `tls` ist nur für HTTPS-Ziele gedacht, und `deps` scannt Code, läuft also meist auf dem Ziel `stack`.
- Der Runner legt seine Arbeitsprojekte unter `work/kit/` neben der Config an, sodass `projects/` einen Ordner je Projekt behält.
