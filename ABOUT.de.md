**Sprache:** Deutsch · [English](ABOUT.md)

# Über LoxProx

Such dir die Länge aus, die zu deinem Kontext passt.

---

## One-Liner (Tagline)

> Ein abgesichertes Security-Gateway für Loxone Miniserver. Reverse Proxy + WAF + IDS + Firewall + Monitoring — weil dein Smart Home einen Riegel verdient hat.

---

## GitHub Repo Description

> Abgesichertes Security-Gateway für Loxone Miniserver. Reverse Proxy + WAF + IDS + Firewall + Monitoring — weil dein Smart Home einen Riegel verdient hat.

---

## Elevator Pitch (2 Sätze)

Der Loxone Miniserver Gen 1 hat kein TLS, kein Rate Limiting, keine native Auth-Härtung und eine Firmware, die seit 2020 keinen bekannten Security-Patch mehr gesehen hat. LoxProx ist ein Drop-in-Debian-12-Gateway, das jeden Schutz nachrüstet, den die Hardware vermissen lässt — transparent und ohne dein LAN anzufassen.

---

## README About-Abschnitt (Absatz)

**LoxProx** ist ein Security-Gateway, gebaut speziell für den Loxone Miniserver Gen 1 — Legacy-Hardware der ersten Generation, die sich selbst nicht schützen kann. Es sitzt zwischen dem Internet und deinem Miniserver und ergänzt TLS-Termination, Rate Limiting, eine Web Application Firewall (CrowdSec AppSec), Intrusion Detection (CrowdSec IDS), nftables-Firewall-Regeln, AppArmor-Confinement, Audit-Logging und Echtzeit-Discord-Alerting. LAN-Traffic umgeht das Gateway vollständig, lokale Nutzer sind also nicht betroffen. Nur externer Traffic wird inspiziert und gehärtet. Deployment: ein Script auf einer Debian-12-VM.

---

## Social Media / Blog-Post (mittlere Länge)

**Dein Smart Home hat eine Hintertür. Das hier ist der Riegel.**

Der Loxone Miniserver Gen 1 ist das Gehirn tausender europäischer Smart Homes — Licht, Heizung, Alarmanlagen, Kameras, Türschlösser. Er ist gleichzeitig Legacy-Hardware der ersten Generation, ohne TLS-Support, ohne Rate Limiting, ohne eingebautes IP-Filtering und mit einer Firmware, die seit 2020 keinen bekannten Security-Patch mehr erhalten hat. Loxone hat das Gerät zwar nicht formal als EOL erklärt, neue Sicherheits-Features (TLS, Remote Connect, Trusts) gibt es aber nur ab Gen 2.

Das hat mich gestört.

Also habe ich **LoxProx** gebaut: ein gehärtetes Debian-12-Security-Gateway, das zwischen Internet und Miniserver sitzt und jeden Schutz nachrüstet, den die Hardware vermissen lässt. nginx Reverse Proxy mit Rate Limiting. CrowdSec IDS + AppSec WAF mit 200+ CVE-Virtual-Patches. nftables-Firewall mit GeoIP-Blocking. AppArmor. Audit-Logging. Discord-Alerts, wenn jemand am Perimeter probiert.

LAN-Traffic geht direkt zum Miniserver — lokale Nutzer merken nichts davon. Nur externer Traffic wird inspiziert. Ein Script deployt den kompletten Stack. Eine Validierungs-Suite mit 50+ Checks sagt dir, ob etwas falsch konfiguriert ist.

Es ist Open Source, non-commercial lizensiert und läuft auf allem von einer Proxmox-VM bis zum Raspberry Pi 4.

---

## Hacker News / Reddit Post (technisch)

**Show HN: LoxProx — Security-Gateway für den Loxone Miniserver Gen 1**

Der Loxone Miniserver Gen 1 ist Legacy-IoT-Hardware der ersten Generation, auf der ziemlich viele europäische Smart Homes laufen. Kein TLS (CPU schafft das nicht), kein Rate Limiting, keine native Auth-Härtung und kein bekannter Security-Patch seit 2020. Die Antwort des Herstellers lautet "kauf Gen 2". Das sind 500+ € und eine komplette Config-Migration.

LoxProx ist eine selbst gehostete Alternative: eine Debian-12-VM als transparentes Security-Gateway.

Stack:
- nginx Reverse Proxy + Rate Limiting
- CrowdSec IDS (Community Threat Intel) + AppSec WAF (200+ CVE-Virtual-Patches)
- nftables-Firewall mit GeoIP-Drop-Regeln
- AppArmor-Profil für nginx
- auditd für die Erkennung von Config-Tampering
- Discord-Alerting bei Security-Events

Deploy: ein Script (`deploy.sh`, ~1265 Zeilen, idempotent). Validierung: 50+ automatisierte Checks. Note: A- über CIS Debian 12, OWASP Top 10 und OWASP IoT Top 10.

LAN umgeht das Gateway vollständig — nur internet-facing Traffic wird gehärtet. Läuft auf einer 1 vCPU / 1 GB VM (2 vCPU / 2 GB empfohlen für Angriffs-Reserve) oder einem Raspberry Pi 4. **Nur VM — LXC wird nicht unterstützt**, weil sich mehrere Kernel-Level-Verteidigungen (Sysctls inklusive der Fragnesia-Mitigation, auditd, AppArmor-Enforcement, nftables) aus einem Container heraus nicht anwenden lassen und stillschweigend zu No-Ops würden.

Non-commercial lizensiert. Feedback von allen willkommen, die CrowdSec auf ressourcenarmen Gateways betreiben.

---

## LinkedIn / Professional

**LoxProx** veröffentlicht — ein Open-Source-Security-Gateway für die Smart-Home-Controller Loxone Miniserver Gen 1. Das Projekt adressiert eine reale Lücke: Legacy-Hardware der ersten Generation, ohne TLS, ohne Rate Limiting und ohne native Security-Härtung — was tausende Haushalte exponiert lässt.

LoxProx deployt einen Sechs-Schichten-Verteidigungsstack (nftables → nginx → CrowdSec IDS → AppSec WAF → Firewall Bouncer → AppArmor/auditd) auf einer Debian-12-VM und schützt den externen Zugriff transparent, ohne LAN-Nutzer zu beeinträchtigen.

Technische Highlights:
- Idempotentes Deploy-Script mit ~1265 Zeilen
- Validierungs-Suite mit 50+ automatisierten Checks
- Self-contained HTML-Security-Report (Note A-)
- Raspberry Pi 4/5 kompatibel
- Non-commercial lizensiert

Entstanden in Zusammenarbeit mit [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) als Experiment in KI-geführter Infrastruktur-Härtung.

Repository: https://github.com/sgtsilver/loxprox

---

## Ein-Satz-Varianten

- **Für Engineers:** LoxProx ist ein Debian-12-Security-Gateway, das den Loxone Miniserver Gen 1 per einzelnem idempotenten Deploy-Script um TLS, WAF, IDS und Firewall-Regeln ergänzt.
- **Für Hausbesitzer:** LoxProx setzt einen Riegel vor dein Loxone Smart Home — blockt Hacker, ohne dein Licht langsamer zu machen.
- **Für die Zyniker:** Dein 3.000-€-Smart-Home läuft auf einer 200-€-Box von 2014, die seit 2020 keinen Security-Patch mehr gesehen hat. LoxProx fixt das.
