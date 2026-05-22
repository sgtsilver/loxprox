**Sprache:** Deutsch · [English](README.en.md)

# LoxProx — Abgesichertes Gateway für Loxone Miniserver

[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-red.svg)](#lizenz)
[![Validation: A-](https://img.shields.io/badge/Validation-A--_brightgreen)]()
[![Debian 12](https://img.shields.io/badge/Debian-12-A81D33?logo=debian)]()
[![CIS Hardened](https://img.shields.io/badge/CIS-Hardened-blue)]()
[![Shellcheck](https://img.shields.io/badge/Shellcheck-passing-brightgreen)]()

> **Ein sofort einsatzbereites Security-Gateway für den Loxone Miniserver Gen 1.** Kein TLS, keine eingebaute Auth, keine Rate Limits — dieses Gateway ergänzt transparent jeden Schutz, den die Hardware vermissen lässt.

## Über das Projekt

**Idee, Hardware und das letzte Wort:** [sgtsilver](https://github.com/sgtsilver) — IT-Systemadministrator. Weiß, wie Angreifer wirklich vorgehen, weiß, wie man Infrastruktur dagegen verteidigt, schreibt selbst keinen Code. Bringt das Netz, den Miniserver, die realen Constraints und das operative Bauchgefühl, mit dem sich ein wirklich solides Design von einem nur clever klingenden unterscheiden lässt.

**Design und Implementierung: ein rotierendes KI-Panel.** [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) lieferte die ursprüngliche Architektur und den Großteil des Codes. [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviewt, fact-checkt, findet und fixt Bugs und übernimmt Folgearbeiten (unter anderem das v1.3.4-Release rund um Supply-Chain und Kernel-Härtung). Weitere Modelle (GPT, Gemini etc.) werden hinzugezogen, wenn einzelne Entscheidungen wirklich gegengelesen werden müssen.

**Die Regel:** KIs schlagen vor. KIs grillen sich gegenseitig. In den Code kommt nichts, weil ein Modell das sagt — sondern nur, wenn die Kreuzprüfung nicht gebrochen hat *und* das Sysadmin-Bauchgefühl eines Menschen "ja, so verteidigt man Infrastruktur wirklich" gesagt hat. Ein clever klingender Vorschlag, der einen der beiden Filter nicht überlebt, fliegt raus — egal, welches Modell ihn vorgeschlagen hat.

Das hier ist ein Experiment in **KI-gestützter, menschlich kuratierter Infrastruktur-Absicherung**. Mehrere KIs, keine davon allein die Architektin; ein Mensch mit dem Veto und der operativen Verantwortung.

---

## Das Problem

Der Loxone Miniserver Gen 1 ist **Hardware der ersten Generation** mit:
- ❌ Keine HTTPS/TLS-Unterstützung (CPU zu schwach für SSL)
- ❌ Kein natives Rate Limiting
- ❌ Keine IP-basierte Zugriffskontrolle
- ❌ Kein Audit-Logging
- ❌ Keine Multi-Faktor-Authentifizierung für Web/API-Zugriff
- ❌ Passwörter in der Config-XML sind verschlüsselt, nicht gehasht
- ⚠️ Firmware-Updates kommen nur noch im Schneckentempo; der letzte bekannte Security-Patch war 2020 (Cloud-DNS-Lücke CVE-2020-27488). Neue Sicherheits-Features (TLS, Remote Connect, Trusts) gibt es ausschließlich ab Gen 2.

Die Definition eines *Legacy-Geräts, das auf der Netzwerkebene geschützt werden muss*.

Dieses Gateway existiert, weil der Miniserver sich selbst nicht schützen kann.

---

## Architektur

```
Internet ──► Router:1080 ──► Security-Gateway:1080 ──► Loxone:80
                                    │
                                    ├── nginx (Proxy, Rate Limits, Header)
                                    ├── CrowdSec (IDS, CAPI-Blocks, AppSec WAF)
                                    ├── nftables (Input DROP, erlaubt :1080 + SSH)
                                    ├── AppArmor (nginx-Profil aktiv)
                                    ├── auditd (Config-Änderungs-Überwachung)
                                    └── Discord-Alerts (Echtzeit-Benachrichtigungen)

LAN (192.168.x.0/24) ──────► Loxone:80  (direkt, am Gateway vorbei)
```

**Design-Prinzip:** LAN-Geräte erreichen den Miniserver direkt. Nur Internet-Traffic läuft durch das Gateway. Heißt: LAN-Geräte bleiben unberührt, und das Gateway kann sich voll auf externe Bedrohungen konzentrieren.

> 🕵️ **Was kommt als Nächstes?** Wir haben überlegt, ob LoxProx eines Tages Gen-1-Miniserver ohne VPN und ohne Hardware-Upgrade nach außen anbinden könnte. Die Recherche ging tiefer als erwartet. Wer neugierig ist — in [#4](https://github.com/sgtsilver/loxprox/issues/4) steht die ganze Geschichte (samt aller Vorbehalte).

---

## Projekt-Struktur

```
loxprox/
├── deploy.sh                          # ★ HAUPT-DEPLOY-SCRIPT — auf der Ziel-VM laufen lassen
├── detect-loxone.sh                   # ★ AUTO-ERKENNUNG deines Miniservers
├── test-gateway.sh                    # ★ VALIDIERUNGS-SUITE — 50+ automatisierte Checks
├── progressive-ban.py                 # CrowdSec Progressive-Ban-Eskalator (Cron, 15 Min)
├── set-static-ip.sh                   # Netzwerk-Vorkonfiguration der VM
├── CONFIGURATION-GUIDE.md             # ★ Erklärt jede Einstellung in deploy.sh
├── .env.example                       # Konfigurations-Template
├── README.md                          # Diese Datei (Deutsch)
├── README.en.md                       # English version
├── SECURITY.md                        # Bedrohungsmodell, Incident Response, Härtung
├── VALIDATION-REPORT.html             # Unabhängiges Security-Audit (Frameworks 2026)
├── LICENSE                            # Non-Commercial
├── CONTRIBUTING.md                    # Beitrags-Richtlinien
├── CHANGELOG.md                       # Versionshistorie
├── phase1-hardening.md                # Proxmox-Firewall + Loxone-Härtung
├── phase2-gateway/
│   ├── nginx-loxone.conf              # nginx Reverse-Proxy-Config (Referenz)
│   ├── crowdsec-acquis.yaml           # CrowdSec Log-Quellen (Referenz)
│   └── sysctls.conf                   # Kernel-Tuning (Referenz)
├── phase3-cutover.md                  # Router- und Firewall-Umstellung
├── phase4-monitoring.md               # Monitoring, Log-Rotation, Tuning
├── security-monitoring/
│   ├── discord-alert.sh               # Discord-Webhook-Dispatcher
│   ├── gateway-monitor.sh             # Security-Monitor (60-Sek-Zyklus)
│   ├── network-watchdog.sh            # Selbstheilender Netzwerk-Watchdog
│   ├── network-watchdog.service       # systemd-Service (root)
│   ├── network-watchdog.timer         # systemd-Timer (60 s)
│   ├── gateway-backup.sh              # Config-Backup-Script
│   ├── geoip-block.sh                 # GeoIP-Blocking (optional)
│   ├── loxprox-monitor.service        # systemd-Service
│   └── loxprox-monitor.timer          # systemd-Timer (60 s)
└── assets/                            # Diagramme, Screenshots
```

---

## Schnellstart

1. **Lege eine Debian-12-VM oder einen LXC an** (mindestens 1 vCPU, 512 MB RAM, 5 GB Disk).
2. **Statische IP setzen:** Kopiere `set-static-ip.sh` in die Ziel-VM und führe es dort aus.
3. **Kopiere `deploy.sh`**, `detect-loxone.sh` und `.env.example` in die Ziel-VM.
4. **Finde deinen Loxone:** `chmod +x detect-loxone.sh && ./detect-loxone.sh`
   - Scannt dein Netz und gibt dir die exakte IP, MAC, Firmware-Version und passende Config-Werte aus.
5. **Konfigurieren:** Öffne `deploy.sh` und passe die `[REQUIRED]`-Werte oben an. Unsicher? Lies `CONFIGURATION-GUIDE.md` — dort wird jede Einstellung mit Beispielen erklärt.
6. **Deploy:** `chmod +x deploy.sh && sudo ./deploy.sh`
7. **Validieren:** `sudo bash test-gateway.sh` (50+ automatisierte Checks)
8. **Umschalten:** Folge `phase3-cutover.md`, um das Router-Forwarding umzuziehen.
9. **Monitoren:** Folge `phase4-monitoring.md` für Tuning und Beobachtung.

Das Deploy-Script ist **idempotent** — kannst du gefahrlos erneut laufen lassen.

---

## Was deployt wird

| Schicht | Komponente | Zweck |
|---------|------------|-------|
| 1 | **nftables** | Input DROP per Default; SSH nur aus dem LAN; :1080 fürs Internet offen |
| 2 | **nginx** | Reverse-Proxy, 10 req/s Rate Limit, Connection-Caps, Security-Header, Slowloris-Timeouts |
| 3 | **CrowdSec** | IDS, parst nginx- und SSH-Logs; CAPI-Community-Feed (~26k bekannte Bad IPs) |
| 4 | **Firewall Bouncer** | Holt CrowdSec-Entscheidungen ab → setzt sie dynamisch in nftables durch |
| 5 | **AppSec WAF** | Virtual Patching (200+ CVE-spezifische Regeln); prüft jeden Request, bevor er weitergereicht wird |
| 6 | **AppArmor** | nginx-Profil aktiv |
| 7 | **auditd** | Überwacht Config-Änderungen an nginx, crowdsec, nftables, ssh, sudoers |
| 8 | **unattended-upgrades** | Auto-Reboot um 03:00 für Kernel-Patches |
| 9 | **Security-Monitor** | 60-Sek-Zyklus: CrowdSec-Blocks, nginx-Fehler, Auth-Versuche, Resource-Alarme → Discord |
| 10 | **Network Watchdog** | Selbstheilender Monitor: erkennt Netzwerk-Ausfälle (dhclient-Death-Spiral, Routing-Korruption) und repariert automatisch per Service-Restart oder Reboot |
| 11 | **Log-Rotation** | 14 Tage nginx-Log-Aufbewahrung |
| 12 | **Config-Backup** | Tägliche automatische Backups nach `/root/loxprox-backups/` |

---

## Hardware-Anforderungen

### Minimum (getestete Konfiguration)

| Resource | Minimum | Empfohlen |
|----------|---------|-----------|
| CPU | 1 Core | 1–2 Cores |
| RAM | 512 MB | 1 GB |
| Disk | 5 GB | 10 GB |
| OS | Debian 12 (Bookworm) 64-bit | Debian 12 oder Ubuntu 22.04 LTS |

Die Referenz-Installation läuft auf einem **1 vCPU, 512 MB RAM Proxmox-LXC** mit Luft nach oben. Der gesamte Security-Stack (nginx + CrowdSec + AppSec + Bouncer) frisst bei normaler Home-Automation-Last etwa **100–150 MB RAM**.

### Raspberry Pi

Der Stack ist **leichtgewichtig genug für Raspberry-Pi-Deployments** im Home-Automation-Umfeld.

| Modell | Architektur | RAM | Kompatibilität | Hinweis |
|--------|-------------|-----|----------------|---------|
| **Pi 5** | ARMv8 (64-bit) | 2–8 GB | ✅ Voll | Overkill. Läuft mühelos. |
| **Pi 4** | ARMv8 (64-bit) | 1–8 GB | ✅ Voll | Ideal. Offizielle ARM64-Pakete von CrowdSec verfügbar. |
| **Pi 3** | ARMv8 (64-bit) | 1 GB | ✅ Voll | Guter Fit. 64-bit Raspberry Pi OS verwenden. |
| **Pi 2** | ARMv7 (32-bit) | 1 GB | ⚠️ Teilweise | CrowdSec verlangt offiziell 64-bit. Community berichtet Erfolge mit 64-bit-Kernel oder manuellem ARMv7-Build. Ohne Tests für Produktion nicht empfohlen. |
| **Pi 1 / Zero (original)** | ARMv6 | 512 MB | ❌ Nein | Keine ARMv6-Binaries von CrowdSec. |
| **Pi Zero 2 W** | ARMv8 (64-bit) | 512 MB | ⚠️ Knapp | 64-bit OS möglich, 512 MB RAM aber knapp. Swap und Scenario-Reduktion vermutlich nötig. |

**Vergleichbare Projekte auf Pi mit ähnlichem Stack:**

- [CrowdSec on Raspberry Pi 3 with DietPi](https://it-security.dnit.fr/en/crowdsec-installation-on-rpi3-with-dietpi-raspberry-os/) — CrowdSec + nftables auf Pi 3 seit 2021 im Einsatz
- [Home Assistant community](https://community.learnlinux.tv/t/reverse-proxy-for-home-automation/4325) — 18+ Docker-Container (inkl. nginx Reverse-Proxy) auf Pi 4 bei ~18 % CPU, 2,5 GB RAM
- [CrowdSec + Nginx on Raspberry Pi](https://www.polimetro.com/en/How-to-protect-your-Raspberry-Pi-with-CrowdSec/) — umfassende 2025er-Anleitung für Pi 3/4/5
- [CrowdSec Firewall Bouncer on low-end VPS](https://github.com/crowdsecurity/crowdsec/issues/3641) — 2-Core, 2 GB RAM OpenCloudOS mit nginx + ModSecurity + CrowdSec

**Resource-Schätzung auf dem Pi:**

| Service | RAM (typisch) |
|---------|---------------|
| nginx (1 Worker) | ~5–10 MB |
| CrowdSec-Agent | ~30–50 MB |
| CrowdSec Firewall Bouncer | ~10–20 MB |
| AppSec WAF | ~20–40 MB |
| OS-Overhead | ~100–200 MB |
| **Gesamt** | **~165–320 MB** |

Ein Pi 3 oder Pi 4 schafft das mit Reserve. Pi 2 läuft eventuell mit 64-bit-Kernel oder Source-Build, klar empfohlen ist aber Pi 3+.

---

## Abgewehrte Bedrohungen

| Bedrohung | Mitigation |
|-----------|-----------|
| Internet-Scanning / Reconnaissance | nftables DROP-Default + CrowdSec CAPI |
| Brute-Force gegen Web-UI | nginx Rate Limits + CrowdSec `http-generic-bf` |
| Application-Layer-DDoS | nginx Connection-Limits, Timeouts, CrowdSec |
| Credential Stuffing | Rate Limits + CrowdSec `http-cve` |
| Ausnutzung von Loxone-CVEs | AppSec WAF (200+ Virtual Patches) |
| SSH-Brute-Force | CrowdSec `ssh-bf` + nftables-Source-Beschränkung |
| Slowloris / Slow-Read | aggressive nginx-Timeouts (10–15 s) |
| Config-Manipulation | auditd + AppArmor |

**Nicht abgedeckt:** Volumetrischer DDoS (Leitungssättigung). Ein 512-MB-RAM-Gateway kann eine pipe-füllende Attacke nicht abfangen. Dafür brauchst du ISP-Scrubbing oder einen Cloud-Service.

---

## Konfiguration

Alle Schalter stehen oben in `deploy.sh`:

```bash
LOXONE_IP="192.168.1.100"           # IP deines Miniservers
GATEWAY_IP="192.168.1.50"           # statische IP dieses Gateways
LAN_SUBNET="192.168.1.0/24"         # LAN, das SSH erreichen darf
SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")
RATE_LIMIT_REQ_PER_SEC="10"
RATE_LIMIT_BURST="100"
ENABLE_APPSEC="true"
APPSEC_MODE="enforce"                # "monitor" oder "enforce"
```

Discord-Alerting ist optional. Setze `DISCORD_WEBHOOK_URL` im Config-Bereich oder lass das Feld leer, um es zu überspringen.

---

## Tests

Nach dem Deploy die Validierungs-Suite laufen lassen:

```bash
sudo bash test-gateway.sh
```

Sie führt **50+ automatisierte Checks** durch — Services, Firewall, Proxy, CrowdSec, AppSec, Monitoring, Kernel-Härtung und Backups. Sie fügt außerdem einen Test-Ban hinzu und entfernt ihn wieder, um die komplette Blocking-Kette zu prüfen.

---

## Betrieb

```bash
# Alle Komponenten prüfen
sudo bash test-gateway.sh

# CrowdSec-Blocks anzeigen
sudo cscli decisions list

# AppSec-Metriken
sudo cscli metrics | grep -A3 Appsec

# Live-nginx-Access-Log
sudo tail -f /var/log/nginx/loxone-access.log

# IP manuell sperren
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual"

# IP entsperren
sudo cscli decisions delete --ip 1.2.3.4

# Network-Watchdog-Status
sudo systemctl status network-watchdog.timer
sudo journalctl -u network-watchdog -f

# Network-Watchdog deaktivieren / aktivieren
sudo systemctl stop network-watchdog.timer
sudo systemctl enable --now network-watchdog.timer

# Deploy nochmal laufen lassen (idempotent)
sudo bash deploy.sh
```

Das komplette Incident-Response-Playbook steht in `SECURITY.md`.

---

## Mitarbeit

Siehe [CONTRIBUTING.md](CONTRIBUTING.md). Das hier ist eine spezialisierte Security-Appliance — Beiträge sollten beim Härten des Loxone-Gateways, Pi-Kompatibilität und Test-Coverage bleiben.

---

## Lizenz

**Non-Commercial Use Only** — siehe [LICENSE](LICENSE).

Die Software darf für persönliche, schulische, Forschungs- und nicht-kommerzielle Zwecke frei genutzt, verändert und weiterverteilt werden. Kommerzielle Nutzung — direkt oder indirekt, ganz oder teilweise — ist ausdrücklich untersagt.

---

## Danksagungen

- [CrowdSec](https://www.crowdsec.net/) — die kollaborative IDS/WAF-Engine, die Community-getriebenes Blocking überhaupt erst möglich macht
- [Loxone](https://www.loxone.com/) — die Home-Automation-Plattform, die dieses Gateway schützt (auch wenn sie Gen 1 nicht mehr patcht)
- Die Home-Automation-Community — fürs so saubere Dokumentieren der Gen-1-Grenzen, dass eine KI darum herum bauen konnte
