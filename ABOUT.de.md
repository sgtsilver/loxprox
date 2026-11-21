**Sprache:** Deutsch · [English](ABOUT.md)

# Über LoxProx

Such dir die Länge aus, die zu deinem Kontext passt.

---

## One-Liner (Tagline)

> Abgesichertes Security-Gateway für den Loxone Miniserver Gen 1: nginx Reverse Proxy, CrowdSec IDS + AppSec WAF, nftables-Firewall, Scanner-Falle und Alerts, installiert von einem idempotenten Script auf einer Debian-12-VM. Dein Smart Home verdient einen Riegel.

---

## GitHub Repo Description

> Abgesichertes Security-Gateway für den Loxone Miniserver Gen 1: nginx Reverse Proxy, CrowdSec IDS + AppSec WAF, nftables-Firewall, Scanner-Falle und Alerts, installiert von einem idempotenten Script auf einer Debian-12-VM. Dein Smart Home verdient einen Riegel.

---

## Elevator Pitch (2 Sätze)

Der Loxone Miniserver Gen 1 hat kein TLS, kein Rate Limiting, keine native Auth-Härtung und eine Firmware, die seit 2020 keinen bekannten Security-Patch mehr gesehen hat. LoxProx ist ein Drop-in-Debian-12-Gateway, das jeden Schutz nachrüstet, den die Hardware vermissen lässt — transparent und ohne dein LAN anzufassen.

---

## README About-Abschnitt (Absatz)

**LoxProx** ist ein Security-Gateway, gebaut speziell für den Loxone Miniserver Gen 1 — Legacy-Hardware der ersten Generation, die sich selbst nicht schützen kann. Es sitzt zwischen dem Internet und deinem Miniserver und ergänzt optionale TLS-Termination (standardmäßig aus), Rate Limiting, eine Scanner-Falle, die Crawler lange sperrt, eine Web Application Firewall (CrowdSec AppSec), Intrusion Detection (CrowdSec IDS), nftables-Firewall-Regeln, ein AppArmor-Profil für nginx, Audit-Logging und Echtzeit-Discord-Alerting. LAN-Traffic umgeht das Gateway vollständig, lokale Nutzer sind also nicht betroffen. Nur externer Traffic wird inspiziert und gehärtet. Deployment: ein Script auf einer Debian-12-VM.

---

## Social Media / Blog-Post (mittlere Länge)

**Dein Smart Home hat eine Hintertür. Das hier ist der Riegel.**

Der Loxone Miniserver Gen 1 ist das Gehirn tausender europäischer Smart Homes — Licht, Heizung, Alarmanlagen, Kameras, Türschlösser. Er ist gleichzeitig Legacy-Hardware der ersten Generation, ohne TLS-Support, ohne Rate Limiting, ohne eingebautes IP-Filtering und mit einer Firmware, die seit 2020 keinen bekannten Security-Patch mehr erhalten hat. Loxone hat das Gerät zwar nicht formal als EOL erklärt, neue Sicherheits-Features (TLS, Remote Connect, Trusts) gibt es aber nur ab Gen 2.

Das hat mich gestört.

Also habe ich **LoxProx** gebaut: ein gehärtetes Debian-12-Security-Gateway, das zwischen Internet und Miniserver sitzt und jeden Schutz nachrüstet, den die Hardware vermissen lässt. nginx Reverse Proxy mit Rate Limiting. CrowdSec IDS + AppSec WAF mit Virtual Patching für bekannte CVEs. nftables-Firewall mit GeoIP-Blocking. AppArmor. Audit-Logging. Discord-Alerts, wenn jemand am Perimeter probiert.

LAN-Traffic geht direkt zum Miniserver — lokale Nutzer merken nichts davon. Nur externer Traffic wird inspiziert. Ein Script deployt den kompletten Stack. Eine Validierungs-Suite mit 100+ Checks sagt dir, ob etwas falsch konfiguriert ist.

Es ist Source-available und kostenlos für nicht-kommerzielle Nutzung, und gebaut für eine Debian-12-VM (Raspberry-Pi-Hardware ist im Scope, aber kein getestetes Ziel).

---

## Hacker News / Reddit Post (technisch)

**Show HN: LoxProx — Security-Gateway für den Loxone Miniserver Gen 1**

Der Loxone Miniserver Gen 1 ist Legacy-IoT-Hardware der ersten Generation, auf der ziemlich viele europäische Smart Homes laufen. Kein TLS (CPU schafft das nicht), kein Rate Limiting, keine native Auth-Härtung und kein bekannter Security-Patch seit 2020. Die Antwort des Herstellers lautet "kauf Gen 2". Das heißt neue Hardware und eine komplette Config-Migration.

LoxProx ist eine selbst gehostete Alternative: eine Debian-12-VM als transparentes Security-Gateway.

Stack:
- nginx Reverse Proxy + Rate Limiting
- CrowdSec IDS (Community Threat Intel) + AppSec WAF (Virtual Patching für bekannte CVEs)
- Host/SNI-Gate mit Scanner-Falle (444) und HARD-/SOFT-Ban-Leitern (7 d → 90 d → 365 d für Scanner)
- nftables-Firewall mit GeoIP-Drop-Regeln
- AppArmor-Profil für nginx
- auditd für die Erkennung von Config-Tampering
- Discord-Alerting bei Security-Events

Deploy: ein Script (`deploy.sh`, ~6200 Zeilen, idempotent). Validierung: 100+ automatisierte Checks. Die Härtung folgt den CIS-Debian-12-Empfehlungen; ein externes Audit oder eine Zertifizierung gibt es nicht (ein KI-gestütztes, rein repo-basiertes Selbst-Audit von v1.3.3 aus 2026-05 liegt in `audits/`).

LAN umgeht das Gateway vollständig — nur internet-facing Traffic wird gehärtet. Läuft auf einer 1 vCPU / 1 GB VM (2 vCPU / 2 GB empfohlen für Angriffs-Reserve); Raspberry-Pi-Hardware ist im Scope, aber kein getestetes Ziel. **Nur VM — LXC wird nicht unterstützt**, weil sich mehrere Kernel-Level-Verteidigungen (Sysctls inklusive der Fragnesia-Mitigation, auditd, AppArmor-Enforcement, nftables) aus einem Container heraus nicht anwenden lassen und stillschweigend zu No-Ops würden.

Source-available, nicht-kommerzielle Lizenz. Feedback von allen willkommen, die CrowdSec auf ressourcenarmen Gateways betreiben.

---

## LinkedIn / Professional

**LoxProx** veröffentlicht — ein Source-available-Security-Gateway für die Smart-Home-Controller Loxone Miniserver Gen 1. Das Projekt adressiert eine reale Lücke: Legacy-Hardware der ersten Generation, ohne TLS, ohne Rate Limiting und ohne native Security-Härtung — was tausende Haushalte exponiert lässt.

LoxProx deployt einen mehrschichtigen Verteidigungsstack (nftables → nginx → CrowdSec IDS → AppSec WAF → Firewall Bouncer → AppArmor/auditd) auf einer Debian-12-VM und schützt den externen Zugriff transparent, ohne LAN-Nutzer zu beeinträchtigen.

Technische Highlights:
- Idempotentes Deploy-Script mit ~6200 Zeilen
- Validierungs-Suite mit 100+ automatisierten Checks
- Scanner-Falle mit eskalierenden HARD-/SOFT-Ban-Leitern
- Raspberry-Pi-Hardware im Scope (kein getestetes Ziel)
- Source-available, nicht-kommerzielle Lizenz

Entstanden als Experiment in KI-gestützter, menschlich kuratierter Infrastruktur-Härtung: [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) lieferte die ursprüngliche Architektur und den Großteil des Codes, [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviewt und übernimmt Folgearbeiten, und ein menschlicher Sysadmin hat das letzte Wort.

Repository: https://github.com/sgtsilver/loxprox

---

## Ein-Satz-Varianten

- **Für Engineers:** LoxProx ist ein Debian-12-Security-Gateway, das den Loxone Miniserver Gen 1 per einzelnem idempotenten Deploy-Script um optionales TLS, WAF, IDS und Firewall-Regeln ergänzt.
- **Für Hausbesitzer:** LoxProx setzt einen Riegel vor dein Loxone Smart Home — blockt Hacker, ohne dein Licht langsamer zu machen.
- **Für die Zyniker:** Dein Smart Home läuft auf einer Box der ersten Generation, die seit 2020 keinen bekannten Security-Patch mehr gesehen hat. LoxProx fixt das.
