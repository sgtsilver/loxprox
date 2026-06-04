**Sprache:** Deutsch · [English](CONTRIBUTING.md)

# Mitarbeit an LoxProx

Eine spezialisierte Security-Appliance für den Loxone Miniserver Gen 1. Beiträge sind willkommen, aber der Scope bleibt fokussiert.

## KI-generierte Beiträge

KI-gestützter Code und Reports sind willkommen — **aber nur, wenn ein Mensch sie auf echter Hardware reviewt, verstanden und verifiziert hat**. Schlampig KI-generierter Murks — kopierte Vulnerability-Reports, ungetestete PRs, Issues ohne Reproduktionsschritte — wird kommentarlos geschlossen.

Wenn du KI verwendet hast, um einen Bug zu finden: füge den tatsächlichen Testoutput und die Reproduktionsschritte bei. Wenn du KI verwendet hast, um einen Fix zu schreiben: lass ihn auf einem echten System laufen, bevor du submittest. Die Qualitätshürde ist dieselbe, egal ob der Code von Mensch oder Modell kommt.

> **Works on my machine. Funktioniert's bei dir nicht — frag deine KI.**

## Was gesucht wird

- **Bugfixes** im Deploy-Script oder den Monitoring-Tools
- **Neue CrowdSec-Szenarien** für Loxone-spezifische Threats
- **Doku-Verbesserungen** — inkl. das bilinguale Paar synchron halten (siehe unten)
- **Pi-Kompatibilitätsfixes** für andere ARM-Boards
- **Test-Coverage** für Edge-Cases

## Was nicht gesucht wird

- Generische Hardening-Tipps, die CrowdSec / Debian-Basisdoku duplizieren
- Breaking Changes am Deployment-Flow ohne starke Begründung
- Features, die den Ressourcenverbrauch deutlich erhöhen (Target: 1 GB RAM)

## Vor dem Submit

1. `bash -n` auf alle modifizierten Shell-Scripts laufen lassen
2. Auf einer frischen Debian-12-VM oder einem Raspberry Pi testen, wenn möglich
3. `SECURITY.md` aktualisieren, wenn sich das Threat-Modell ändert — und `SECURITY.de.md` parallel
4. Änderungen chirurgisch halten — dieses Projekt setzt auf Simplicity vor Vollständigkeit

## Code-Style

- 4-Space-Einrückung
- `set -euo pipefail` in allen Scripts
- F-Strings in Python (falls vorhanden)
- Kommentare erklären das *Warum*, nicht das *Was*

## Bilinguale Dokumentation

Jede tracked Markdown-Doku existiert sowohl auf Deutsch als auch auf Englisch. Die beiden Dateien müssen semantisch synchron gehalten werden — wenn du eine änderst, ändere die andere im selben PR.

Naming-Konvention (folgt dem existierenden `README.md` / `README.en.md`-Muster):

| Pattern | Sprache |
|---|---|
| `README.md` | Deutsch (primär — historische Ausnahme) |
| `README.en.md` | Englisch |
| `<other>.md` | Englisch (Pfad bleibt aus Backwards-Compat-Gründen ohne Suffix) |
| `<other>.de.md` | Deutsch |

Jede Datei trägt einen Sprach-Switcher-Banner direkt oben:

- Englische Datei: `**Language:** [Deutsch](<file>.de.md) · English`
- Deutsche Datei: `**Sprache:** Deutsch · [English](<file>.md)`

Wenn du eine neue Doku nur in einer Sprache beiträgst, muss die Übersetzung vor dem Merge nachkommen. Match den existierenden Voice: knapp, operator-fokussiert, `du`-Form auf Deutsch; direkt und technical-reader auf Englisch. Code-Blöcke, Pfade, Command-Namen und CVE- / Config-Key-Identifier werden **nie** übersetzt. Anglizismen im deutschen Text sind okay, wo sie in diesem Repo der Arbeitsbegriff sind (`nginx`, `Reverse Proxy`, `Port-Forward`, `Cert`, `Renewal`, `AppSec`, `Bouncer`, …).

Übersetzungsprobleme / Drift kannst du als eigene Issues anlegen, getaggt mit `docs:translation`.

## Fragen?

Issue aufmachen. Miniserver-Firmware-Version, Gateway-Specs und Ziel beilegen.
