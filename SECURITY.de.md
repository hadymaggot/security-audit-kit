[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](SECURITY.md) · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](SECURITY.en.md) · **<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch**

# Sicherheitsrichtlinie

Danke, dass du hilfst, die Sicherheit von **Security Audit Kit** zu wahren.

## Unterstützte Versionen

Sicherheitsfixes werden auf dem neuesten Release und dem Branch `main` angewendet.

| Version | Unterstützt |
|---|---|
| Neuestes stabiles Release | ✅ |
| `main` | ✅ |
| Ältere Versionen | ❌ |

## Eine Schwachstelle melden

**Öffne kein** öffentliches Issue für eine Sicherheitslücke.

Verwende **GitHub Private Vulnerability Reporting**:

1. Den Tab **Security** dieses Repos öffnen.
2. Auf **Report a vulnerability** klicken.
3. Details ausfüllen: Reproduktionsschritte, Auswirkung, betroffene Version/Commit und, falls
   vorhanden, Nachweise.

Die Meldung bleibt privat zwischen dir und den Maintainern, bis ein Fix verfügbar ist.

### Was du erwarten kannst

- **Eingangsbestätigung:** in der Regel innerhalb von 3 Werktagen.
- **Erste Bewertung & Triage:** innerhalb von 7 Werktagen.
- **Fix & Disclosure:** gemeinsam mit der meldenden Person koordiniert; Credit wird auf Wunsch
  vergeben.

## Geltungsbereich

Dieses Toolkit **prüft die Sicherheit anderer Systeme**. Die hier gemeinten Meldungen
betreffen Schwachstellen **im Kit selbst** (z. B. unbeabsichtigte Codeausführung beim Parsen
von Ausgaben, Preisgabe von Zugangsdaten aus Config/Berichten oder ein Fehler, der das Kit ein
nicht angefordertes Ziel angreifen lässt).

## Verantwortungsvolle Nutzung

Dieses Kit dient nur der Prüfung von Systemen, die **du besitzt oder zu prüfen berechtigt
bist**. Das Prüfen fremder Systeme ohne Erlaubnis verstößt in vielen Rechtsordnungen gegen das
Gesetz und liegt außerhalb des Zwecks dieses Projekts. Zugangsdaten des Ziels immer über
Umgebungsvariablen, nicht in committeten Dateien.
