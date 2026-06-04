**Sprache:** Deutsch · [English](README.en.md)

# LoxProx — Abgesichertes Gateway für Loxone Miniserver

[![Release](https://img.shields.io/github/v/release/sgtsilver/loxprox?label=release&color=brightgreen)](https://github.com/sgtsilver/loxprox/releases)
[![CI](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml/badge.svg)](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml)
[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-red.svg)](#lizenz)
[![Validation: A-](https://img.shields.io/badge/Validation-A--_brightgreen)](#)
[![Debian 12](https://img.shields.io/badge/Debian-12-A81D33?logo=debian)](#)
[![CIS Hardened](https://img.shields.io/badge/CIS-Hardened-blue)](#)

> **Ein sofort einsatzbereites Security-Gateway für den Loxone Miniserver Gen 1.** Kein TLS, keine eingebaute Auth, keine Rate Limits — LoxProx ergänzt transparent jeden Schutz, den die Hardware vermissen lässt. Deine App läuft weiter; das Gateway steckt die Treffer ein.

```
Internet ──► Router:1080 ──► LoxProx-Gateway:1080 ──► Loxone:80
                                   │
                                   ├── nginx (Proxy, Rate Limits, Header)
                                   ├── CrowdSec (IDS, CAPI-Blocks, AppSec WAF)
                                   ├── nftables (Input DROP, erlaubt :1080 + SSH)
                                   ├── AppArmor (nginx-Profil aktiv)
                                   ├── auditd (Config-Änderungs-Überwachung)
                                   └── Discord-Alerts (Echtzeit)

LAN (192.168.x.0/24) ──────────► Loxone:80   (direkt — am Gateway vorbei)
```

---

## Inhalt

- [Warum LoxProx?](#warum-loxprox)
- [Schnellstart](#schnellstart)
- [Wie es funktioniert](#wie-es-funktioniert)
- [Sicherheits-Schichten](#sicherheits-schichten)
- [Konfiguration](#konfiguration)
- [Hardware-Anforderungen](#hardware-anforderungen)
- [Abgewehrte Bedrohungen](#abgewehrte-bedrohungen)
- [Betrieb & Tests](#betrieb--tests)
- [Dokumentation](#dokumentation)
- [Wie dieses Projekt entsteht](#wie-dieses-projekt-entsteht)
- [Mitarbeit](#mitarbeit) · [Lizenz](#lizenz) · [Danksagungen](#danksagungen)

---

## Warum LoxProx?

Der Loxone Miniserver Gen 1 ist **Hardware der ersten Generation**, die sich selbst nicht schützen kann — kein HTTPS (die CPU ist zu schwach für SSL), kein Rate Limiting, keine IP-Zugriffskontrolle, kein Audit-Logging, keine MFA, Passwörter in der Config-XML sind verschlüsselt statt gehasht, und der letzte bekannte Security-Patch war **2020** (Cloud-DNS-Lücke [CVE-2020-27488](https://nvd.nist.gov/vuln/detail/CVE-2020-27488)). Neue Sicherheits-Features (TLS, Remote Connect, Trusts) gibt es ausschließlich ab Gen 2.

LoxProx setzt sich davor und liefert die gesamte fehlende Sicherheitsschicht.

**Auf einen Blick**

- **Drop-in & idempotent** — ein Script; `git pull && sudo bash deploy.sh` läuft gefahrlos erneut und übersteht Upgrades (inkl. deiner nginx-Handanpassungen).
- **Defense in Depth** — nginx Reverse-Proxy + CrowdSec IDS + AppSec WAF + nftables + AppArmor + auditd, geschichtet.
- **Transparent** — LAN-Traffic geht direkt zum Miniserver; nur Internet-Traffic wird geprüft, lokale Nutzer werden also nie ausgebremst.
- **Optional HTTPS auf `:1080`** — TLS-Terminierung per `acme.sh` + Let's Encrypt, deckt das No-TLS-Gerät dahinter ab.
- **Leichtgewichtig** — läuft auf einer 1-GB-VM oder einem Raspberry Pi 3+.
- **Selbstheilend** — ein Netzwerk-Watchdog erkennt und repariert Stack-Ausfälle automatisch.
- **Echtzeit-Alerts** — optionale Discord-Benachrichtigungen bei Blocks, Fehlern und Anomalien.
- **Unabhängig validiert** — A- gegen CIS Debian 12 + OWASP IoT Top 10.

---

## Schnellstart

> **Neu bei Linux?** Du hast einen Loxone Miniserver, aber noch nie ein Terminal benutzt? Kein Problem — wir urteilen nicht und grenzen niemanden aus. Folge stattdessen der sanften Schritt-für-Schritt-Anleitung zum Kopieren: **[Installation für Linux-Einsteiger](docs/INSTALL-FOR-NEWBIES.de.md)**.

1. **Lege eine Debian-12-VM an** — mindestens 1 vCPU, 1 GB RAM, 5 GB Disk (siehe [Hardware-Anforderungen](#hardware-anforderungen)). **Nur VM — kein LXC** (mehrere Schutzmechanismen laufen im Container ins Leere; `deploy.sh` bricht ab, außer du setzt `ALLOW_LXC=1`).
2. **Statische IP setzen** — `set-static-ip.sh` in die Ziel-VM kopieren und dort ausführen.
3. **Repo auf die Ziel-VM holen** (`git clone` oder scp).
4. **Finde deinen Miniserver** — `chmod +x detect-loxone.sh && ./detect-loxone.sh` gibt IP, MAC, Firmware und passende Config-Werte aus.
5. **Konfiguration anlegen:**
   ```bash
   sudo install -d -m 0750 /etc/loxprox
   sudo cp deploy.conf.example /etc/loxprox/deploy.conf
   sudo $EDITOR /etc/loxprox/deploy.conf      # [REQUIRED]-Werte eintragen
   ```
6. **Deploy** — `chmod +x deploy.sh && sudo ./deploy.sh`
7. **Validieren** — `sudo bash test-gateway.sh` (50+ automatisierte Checks)
8. **Umschalten** — folge [`phase3-cutover.md`](phase3-cutover.md), um das Router-Forwarding aufs Gateway umzuziehen.
9. **Monitoren** — folge [`phase4-monitoring.md`](phase4-monitoring.md) für Tuning und Beobachtung.

Das Deploy-Script ist **idempotent** und upgrade-sicher — `git pull && sudo bash deploy.sh` reicht, und Operator-Anpassungen an `/etc/nginx/sites-available/loxone` (z. B. ein WebSocket-Block) überleben jedes Redeploy.

**Gut zu wissen:**
- **Upgrade von v1.3.x?** Einmalig `sudo bash deploy.sh --bootstrap-config` ausführen — liest deine aktiven Werte zurück nach `/etc/loxprox/deploy.conf`. Anleitung: [`docs/UPGRADE-to-v1.5.md`](docs/UPGRADE-to-v1.5.md).
- **HTTPS gewünscht?** `ENABLE_TLS="true"` setzen (braucht öffentlichen DNS-Namen + eine `WAN:80 → Gateway:80`-Weiterleitung für ACME). Runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).
- **SSH sperrt dich nicht aus.** Existiert beim ersten Lauf kein `authorized_keys`, zeigt der Installer ein interaktives Menü (Key einfügen, Hilfe beim Anlegen, oder Passwort-Auth mit Warnung behalten) und fällt bei nicht-interaktiven Deploys in einen sicheren Modus. Details: [`CONFIGURATION-GUIDE.de.md`](CONFIGURATION-GUIDE.de.md) → „SSH Key Bootstrap".

---

## Wie es funktioniert

```
Internet ──► Router:1080 ──► LoxProx-Gateway:1080 ──► Loxone:80
LAN ────────────────────────────────────────────────► Loxone:80   (direkt)
```

**Design-Prinzip:** LAN-Geräte erreichen den Miniserver direkt; nur Internet-Traffic läuft durch das Gateway. Heißt: lokale Nutzer bleiben unberührt, und das Gateway konzentriert sich voll auf externe Bedrohungen. Jeder externe Request wird rate-limitiert, durch die CrowdSec-AppSec-WAF geschickt und gegen die Community-Blocklist geprüft, bevor nginx ihn überhaupt an den Miniserver weiterreicht.

> **Was kommt als Nächstes?** Wir haben überlegt, ob LoxProx eines Tages Gen-1-Miniserver ohne VPN und ohne Hardware-Upgrade nach außen anbinden könnte. Die Recherche ging tiefer als erwartet. Die ganze Geschichte (samt aller Vorbehalte) steht in [#4](https://github.com/sgtsilver/loxprox/issues/4).

---

## Sicherheits-Schichten

| # | Schicht | Zweck |
|---|---------|-------|
| 1 | **nftables** | Input DROP per Default; SSH nur aus dem LAN; `:1080` fürs Internet offen |
| 2 | **nginx** | Reverse-Proxy, 10 req/s Rate Limit, Connection-Caps, Security-Header, Slowloris-Timeouts |
| 3 | **CrowdSec** | IDS, parst nginx- und SSH-Logs; CAPI-Community-Feed (~26k bekannte Bad IPs) |
| 4 | **Firewall Bouncer** | Holt CrowdSec-Entscheidungen ab → setzt sie dynamisch in nftables durch |
| 5 | **AppSec WAF** | Virtual Patching (200+ CVE-spezifische Regeln); prüft jeden Request vor dem Weiterreichen |
| 6 | **AppArmor** | nginx-Profil aktiv |
| 7 | **auditd** | Überwacht Config-Änderungen an nginx, crowdsec, nftables, ssh, sudoers |
| 8 | **unattended-upgrades** | Auto-Reboot um 03:00 für Kernel-Patches |
| 9 | **Security-Monitor** | 60-Sek-Zyklus: CrowdSec-Blocks, nginx-Fehler, Auth-Versuche, Resource-Alarme → Discord |
| 10 | **Network Watchdog** | Selbstheilend: erkennt Netzwerk-Ausfälle (dhclient-Death-Spiral, Routing-Korruption) und repariert per Service-Restart oder Reboot |
| 11 | **Log-Rotation** | 14 Tage nginx-Log-Aufbewahrung |
| 12 | **Config-Backup** | Tägliche automatische Backups nach `/root/loxprox-backups/` |

---

## Konfiguration

Die Per-Host-Einstellungen liegen in **`/etc/loxprox/deploy.conf`** (Mode 0640) — `deploy.sh` liest sie beim Start, du editierst also nie das Script selbst. Starte vom getrackten Template `deploy.conf.example`; jeder Wert hat einen Inline-Kommentar, die vollständige Referenz ist [`CONFIGURATION-GUIDE.de.md`](CONFIGURATION-GUIDE.de.md).

Die Werte, die du tatsächlich setzt:

```bash
LOXONE_IP="192.168.1.100"                 # dein Miniserver
GATEWAY_IP="192.168.1.50"                  # statische IP dieses Gateways
LAN_SUBNET="192.168.1.0/24"                # vertrauenswürdiges LAN
SSH_ALLOWED_SUBNETS=("192.168.1.0/24")     # wer SSH erreichen darf
RATE_LIMIT_REQ_PER_SEC="10"
RATE_LIMIT_BURST="100"
ENABLE_APPSEC="true"
APPSEC_MODE="enforce"                      # „monitor" oder „enforce"
ENABLE_TLS="false"                         # optionales HTTPS auf :1080 (siehe TLS-SETUP)
DISCORD_WEBHOOK_URL=""                     # optionales Alerting — leer lassen zum Überspringen
```

---

## Hardware-Anforderungen

### Minimum (getestete Konfiguration)

| Resource | Minimum | Empfohlen |
|----------|---------|-----------|
| CPU | 1 vCPU | **2 vCPU** |
| RAM | **1 GB** | **2 GB** |
| Disk | 5 GB | 10 GB |
| OS | Debian 12 (Bookworm) 64-bit | Debian 12 |

Die Referenz-Installation läuft auf einer **Proxmox-VM mit 1 vCPU und 1 GB RAM** und liegt im normalen Betrieb bei **~850 MB RSS**. Der Stack selbst (nginx + CrowdSec + AppSec + Bouncer) verbraucht im Leerlauf 100–150 MB; den Rest holen sich Debian-Basis und Page-Cache.

**Warum 2 vCPU / 2 GB empfohlen sind:** CrowdSecs Leaky-Bucket-Speicher skaliert mit der Anzahl gleichzeitig aktiver Angreifer-IPs — 256 IPs ≈ 150 MB, 15 000 IPs ≈ 1,2–1,5 GB ([Quelle](https://www.crowdsec.net/blog/how-to-process-billions-daily-events-with-crowdsec)). Bei einem breit gestreuten Scan wächst der RAM-Bedarf entsprechend. AppSec WAF kostet pro Request rund **5 ms / 50 mc CPU** mit aktiviertem Virtual-Patching-Ruleset ([Quelle](https://docs.crowdsec.net/docs/appsec/benchmark/)) — eine zweite vCPU hält `nginx` für legitime Nutzer responsiv, während der Bouncer in den ersten 30–60 Sekunden eines Angriffs aufholt und Angreifer schon auf nftables-Ebene gedroppt werden. 1 vCPU / 1 GB funktionieren bei reinem Home-Automation-Traffic einwandfrei; die empfohlene Konfiguration ist die Reserve, die im Angriffsfall den Unterschied macht.

> ⚠️ **Substrat: VM, nicht LXC.** In einem unprivilegierten Proxmox-LXC schlagen mehrere Härtungs-Schritte ohne Fehlermeldung fehl, weil sie auf Host-Kernel-State schreiben, den der Container nicht erreicht:
>
> - `kernel.unprivileged_userns_clone = 0` — die **Fragnesia/CVE-2026-46300-Mitigation** läuft in EPERM und greift nicht (die Knob ist global, nicht per-netns).
> - `kernel.dmesg_restrict`, `kernel.kptr_restrict`, `kernel.randomize_va_space`, `fs.protected_*` — alle host-weit, vom Container aus nicht beschreibbar.
> - **auditd** — der Kernel hat genau einen Audit-Consumer pro Netlink-Socket, und der gehört dem Host; `augenrules --load` schlägt fehl, die Config-Tamper-Detection ist weg.
> - **AppArmor-Enforcement** — `aa-enforce` lädt Profile in das Subsystem des Hosts; der Container kann das nicht.
> - **nftables** — das Capability-Set eines unprivilegierten LXC lässt das Anlegen der `inet filter`-Tabelle nicht zu.
>
> `deploy.sh` erkennt LXC und bricht **standardmäßig ab**. `ALLOW_LXC=1 sudo ./deploy.sh` übergeht das — die dokumentierte CIS-Debian-12-/OWASP-IoT-Top-10-Posture gilt dann aber nicht mehr.

### Raspberry Pi

Der Stack ist **leichtgewichtig genug für Raspberry-Pi-Deployments** im Home-Automation-Umfeld.

| Modell | Architektur | RAM | Kompatibilität | Hinweis |
|--------|-------------|-----|----------------|---------|
| **Pi 5** | ARMv8 (64-bit) | 2–8 GB | ✅ Voll | Overkill. Läuft mühelos. |
| **Pi 4** | ARMv8 (64-bit) | 1–8 GB | ✅ Voll | Ideal. Offizielle ARM64-Pakete von CrowdSec. |
| **Pi 3** | ARMv8 (64-bit) | 1 GB | ✅ Voll | Guter Fit. 64-bit Raspberry Pi OS verwenden. |
| **Pi 2** | ARMv7 (32-bit) | 1 GB | ⚠️ Teilweise | CrowdSec verlangt offiziell 64-bit. Community-Erfolge mit 64-bit-Kernel oder Build; ohne Tests nicht für Produktion. |
| **Pi 1 / Zero (original)** | ARMv6 | 512 MB | ❌ Nein | Keine ARMv6-Binaries von CrowdSec. |
| **Pi Zero 2 W** | ARMv8 (64-bit) | 512 MB | ⚠️ Knapp | 64-bit OS möglich, 512 MB aber knapp — Swap und Scenario-Reduktion vermutlich nötig. |

Typischer Fußabdruck auf dem Pi: nginx ~5–10 MB · CrowdSec-Agent ~30–50 MB · Firewall-Bouncer ~10–20 MB · AppSec ~20–40 MB · OS ~100–200 MB → **~165–320 MB gesamt**. Ein Pi 3 oder Pi 4 schafft das mit Reserve. Vorbilder: [CrowdSec auf einem Pi 3 (DietPi)](https://it-security.dnit.fr/en/crowdsec-installation-on-rpi3-with-dietpi-raspberry-os/), [CrowdSec + nginx auf dem Raspberry Pi (2025)](https://www.polimetro.com/en/How-to-protect-your-Raspberry-Pi-with-CrowdSec/).

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

**Nicht abgedeckt:** volumetrischer DDoS (Leitungssättigung). Ein 1–2-GB-Gateway kann eine pipe-füllende Attacke nicht abfangen — dafür brauchst du ISP-Scrubbing oder einen Cloud-Service.

---

## Betrieb & Tests

Nach dem Deploy die Validierungs-Suite laufen lassen — **50+ automatisierte Checks** über Services, Firewall, Proxy, CrowdSec, AppSec, Monitoring, Kernel-Härtung und Backups (inklusive eines Test-Bans, der hinzugefügt und wieder entfernt wird, um die komplette Blocking-Kette zu prüfen):

```bash
sudo bash test-gateway.sh
```

Befehle für den Alltag:

```bash
sudo cscli decisions list                       # aktive Blocks anzeigen
sudo cscli metrics | grep -A3 Appsec            # AppSec-Metriken
sudo tail -f /var/log/nginx/loxone-access.log   # Live-Access-Log
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual"   # sperren
sudo cscli decisions delete --ip 1.2.3.4        # entsperren
sudo systemctl status network-watchdog.timer    # Watchdog-Status
sudo bash deploy.sh                              # Deploy erneut (idempotent)
```

Das komplette Incident-Response-Playbook steht in [`SECURITY.de.md`](SECURITY.de.md).

---

## Dokumentation

| Doc | Inhalt |
|-----|--------|
| [Installation für Linux-Einsteiger](docs/INSTALL-FOR-NEWBIES.de.md) · [EN](docs/INSTALL-FOR-NEWBIES.md) | Sanfte, jargonfreie Schritt-für-Schritt-Anleitung |
| [Konfigurations-Guide](CONFIGURATION-GUIDE.de.md) · [EN](CONFIGURATION-GUIDE.md) | Jede `deploy.conf`-Einstellung erklärt |
| [TLS-Setup](docs/TLS-SETUP.de.md) · [EN](docs/TLS-SETUP.md) | HTTPS auf `:1080` per acme.sh aktivieren |
| [Upgrade auf v1.5](docs/UPGRADE-to-v1.5.de.md) · [EN](docs/UPGRADE-to-v1.5.md) | Migration von v1.3.x (Config-Bootstrap) |
| [Security](SECURITY.de.md) · [EN](SECURITY.md) | Bedrohungsmodell, Incident Response, Härtung |
| [Phasen-Guides](phase1-hardening.de.md) | [1: Härtung](phase1-hardening.de.md) · [3: Cutover](phase3-cutover.de.md) · [4: Monitoring](phase4-monitoring.de.md) |
| [Changelog](CHANGELOG.md) · [Mitarbeit](CONTRIBUTING.de.md) | Versionshistorie · Beitragen |

---

## Wie dieses Projekt entsteht

Das hier ist ein Experiment in **KI-gestützter, menschlich kuratierter Infrastruktur-Absicherung** — mehrere KIs, keine davon allein die Architektin; ein Mensch mit dem Veto und der operativen Verantwortung.

- **Idee, Hardware und das letzte Wort:** [sgtsilver](https://github.com/sgtsilver) — IT-Systemadministrator. Weiß, wie Angreifer wirklich vorgehen und wie man Infrastruktur dagegen verteidigt; schreibt selbst keinen Code. Bringt das Netz, den Miniserver, die realen Constraints und das operative Bauchgefühl, mit dem sich ein wirklich solides Design von einem nur clever klingenden unterscheiden lässt.
- **Design und Implementierung — ein rotierendes KI-Panel:** [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) lieferte die ursprüngliche Architektur und den Großteil des Codes. [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviewt, fact-checkt, findet und fixt Bugs und übernimmt Folgearbeiten (u. a. das v1.3.4-Release rund um Supply-Chain und Kernel-Härtung). Weitere Modelle (GPT, Gemini, …) werden hinzugezogen, wenn einzelne Entscheidungen wirklich gegengelesen werden müssen.
- **Die Regel:** KIs schlagen vor, KIs grillen sich gegenseitig, und in den Code kommt nichts, weil ein Modell das sagt — sondern nur, wenn die Kreuzprüfung nicht gebrochen hat *und* das Sysadmin-Bauchgefühl eines Menschen „ja, so verteidigt man Infrastruktur wirklich" gesagt hat. Ein clever klingender Vorschlag, der einen der Filter nicht überlebt, fliegt raus — egal, welches Modell ihn vorgeschlagen hat.

---

## Mitarbeit

Siehe [CONTRIBUTING.de.md](CONTRIBUTING.de.md). Das hier ist eine spezialisierte Security-Appliance — Beiträge sollten beim Härten des Loxone-Gateways, Pi-Kompatibilität und Test-Coverage bleiben. Jedes getrackte Markdown-Dokument ist zweisprachig (Deutsch + Englisch); halte beide im selben PR synchron.

---

## Lizenz

**Non-Commercial Use Only** — siehe [LICENSE](LICENSE). Die Software darf für persönliche, schulische, Forschungs- und nicht-kommerzielle Zwecke frei genutzt, verändert und weiterverteilt werden. Kommerzielle Nutzung — direkt oder indirekt, ganz oder teilweise — ist ausdrücklich untersagt.

---

## Danksagungen

- [CrowdSec](https://www.crowdsec.net/) — die kollaborative IDS/WAF-Engine, die Community-getriebenes Blocking überhaupt erst möglich macht.
- [Loxone](https://www.loxone.com/) — die Home-Automation-Plattform, die dieses Gateway schützt (auch wenn sie Gen 1 nicht mehr patcht).
- Die Home-Automation-Community — fürs so saubere Dokumentieren der Gen-1-Grenzen, dass ein KI-Panel darum herum bauen konnte.
