**Sprache:** Deutsch · [English](README.en.md)

# LoxProx — Abgesichertes Gateway für Loxone Miniserver

[![Release](https://img.shields.io/github/v/release/sgtsilver/loxprox?label=release&color=brightgreen)](https://github.com/sgtsilver/loxprox/releases)
[![CI](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml/badge.svg)](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml)
[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-red.svg)](#lizenz)
[![Debian 12](https://img.shields.io/badge/Debian-12-A81D33?logo=debian)](#)

> **Ein sofort einsatzbereites Security-Gateway für den Loxone Miniserver Gen 1.** Kein TLS, keine eingebaute Auth, keine Rate Limits — LoxProx ergänzt transparent jeden Schutz, den die Hardware vermissen lässt. Deine App läuft weiter; das Gateway steckt die Treffer ein.

```
Internet ──► Router:1080 ──► LoxProx-Gateway:1080 ──► Loxone:80
                                   │
                                   ├── nginx (Host/SNI-Gate + Scanner-Falle, Proxy, Rate Limits, Header)
                                   ├── CrowdSec (IDS, CAPI-Blocks, AppSec WAF, HARD-/SOFT-Ban-Leitern)
                                   ├── nftables (Input DROP, GeoIP-Drop, erlaubt :1080 + SSH; :80 mit TLS)
                                   ├── AppArmor (nginx-Profil: Complain → Enforce per Opt-in)
                                   ├── auditd (Config-Änderungs-Überwachung)
                                   ├── LoxProx Panel (:1081, nur LAN)
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

- **Drop-in & idempotent** — ein Script; `git pull && sudo bash deploy.sh` läuft gefahrlos erneut. Die nginx-Site `/etc/nginx/sites-available/loxone` wird neu erzeugt, sobald sie vom Template oder von deiner `deploy.conf` abweicht (vorher gesichert; ein fehlschlagendes `nginx -t` stellt das Backup wieder her) — Handanpassungen überleben ein Redeploy also **nicht**. Mit `LOXPROX_KEEP_NGINX_SITE=1` friert du eine handgepflegte Site ein ([Details](CONFIGURATION-GUIDE.de.md#deploysh-erneut-laufen-lassen--nginx-site-regenerierung--exit-codes)).
- **Defense in Depth** — nginx Reverse-Proxy + CrowdSec IDS + AppSec WAF + nftables + AppArmor + auditd, geschichtet.
- **Scanner-Abwehr (v3.0)** — mit TLS bedienen `:1080` und `:80` nur deinen echten Hostnamen (`TLS_DOMAIN` + `EXTRA_SERVER_NAMES`). Eine nackte IP, fehlendes SNI, ein fremder `Host` oder ein Scanner-Pfad landen in einer Falle (444 + Log) und bekommen einen **HARD-Ban**: 7 Tage, dann 90, dann 365. Andere Verstöße laufen auf einer **SOFT-Leiter** (24 h → 7 → 30 → 90 Tage); `progressive-ban.py` verlängert Wiederholungstäter. Jede App nutzt `https://<hostname>:1080`, nie die IP; rolle zuerst mit `TRAP_BAN_MODE="observe"` aus und trage einen bekannten Prober bei Bedarf in `TRAP_EXEMPT_IPS` ein.
- **Admin-Pfade gesperrt (v3.0)** — die einfachen Loxone-Admin-Webservices (`fsget`, `fsdel`, `sys/reboot`, …) antworten aus dem Internet mit `403` (`REMOTE_ADMIN_PATHS="allow"` öffnet sie wieder); LAN und `TRUSTED_SOURCES` sind ausgenommen. Das filtert nur einfache HTTP-Pfade — die eigenen Zugangsdaten des Miniservers bleiben die eigentliche Kontrolle.
- **Nie gebannt heißt nicht vertrauenswürdig (v3.0)** — `CROWDSEC_WHITELIST_IPS` verhindert nur Bans; nginx vertraut ausschließlich Loopback, `LAN_SUBNET` und dem neuen `TRUSTED_SOURCES`.
- **GeoIP-Drop** — nftables verwirft CN, RU, KP und IR (IPv4 + IPv6). Auch Reisende in diesen Ländern sind damit ausgesperrt.
- **Transparent** — LAN-Traffic geht direkt zum Miniserver; nur Internet-Traffic wird geprüft, lokale Nutzer werden also nie ausgebremst.
- **Optional HTTPS auf `:1080`** — TLS-Terminierung per `acme.sh` + Let's Encrypt (mit ZeroSSL-Fallback), deckt das No-TLS-Gerät dahinter ab.
- **Optional Fernzugriff ohne offene Ports (v2.0)** — frp-Tunnel über einen eigenen Relay-VPS für CGNAT-/DS-Lite-Anschlüsse; selbst gehostet, ohne Abo, mit eigenem Watchdog. Siehe [Tunnel-Setup](docs/TUNNEL-SETUP.de.md).
- **LAN-only Web-Panel (v2.1, standardmäßig an)** — Status-Kacheln, Log-Ansicht, Config-Editor und Ein-Klick-Support-Aktionen (entbannen, neu starten, TLS erneuern) unter `http://<gateway-ip>:1081`, erreichbar nur aus `LAN_SUBNET` und `SSH_ALLOWED_SUBNETS`. `GUI_PASSWORD` ist standardmäßig leer — setze eins. Siehe [GUI Panel](docs/GUI-PANEL.de.md).
- **Leichtgewichtig** — läuft auf einer VM mit 1 vCPU / 1 GB (empfohlen: 2 vCPU / 2 GB); Raspberry-Pi-Hardware ist im Scope, aber kein getestetes Ziel (siehe [Hardware-Anforderungen](#hardware-anforderungen)).
- **Selbstheilend** — ein Netzwerk-Watchdog erkennt und repariert Stack-Ausfälle automatisch.
- **Echtzeit-Alerts** — optionale Discord-Benachrichtigungen bei Blocks, Fehlern und Anomalien.
- **CIS-orientierte Härtung** — SSH, Kernel-Sysctls, auditd und unattended-upgrades folgen den CIS-Debian-12-Empfehlungen. Das ist keine Zertifizierung; ein KI-gestütztes, rein repo-basiertes Selbst-Audit von v1.3.3 (2026-05) liegt in [`audits/`](audits/2026-05-23-skills-audit.md).

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
7. **Validieren** — `sudo bash test-gateway.sh` (100+ automatisierte Checks)
8. **Umschalten** — folge [`phase3-cutover.de.md`](phase3-cutover.de.md), um das Router-Forwarding aufs Gateway umzuziehen. (Die Phasen-Guides stammen aus der Zeit vor der VM-only-Entscheidung: Das Gateway ist eine VM, führe deren Befehle also in der VM aus statt per `pct exec`.)
9. **Monitoren** — folge [`phase4-monitoring.de.md`](phase4-monitoring.de.md) für Tuning und Beobachtung. (Gleicher Hinweis: Befehle in der VM ausführen statt per `pct exec`; auf Proxmox `qm` statt `pct` nutzen.)

Das Deploy-Script ist **idempotent** — `git pull && sudo bash deploy.sh` läuft gefahrlos erneut. Es bewahrt aber keine Handanpassungen: Seit v2.3.0 erzeugt es `/etc/nginx/sites-available/loxone` aus dem Template neu, sobald die Datei oder deine `deploy.conf` abweicht (mit Backup und Rückfall, wenn `nginx -t` fehlschlägt). Mit `LOXPROX_KEEP_NGINX_SITE=1` friert du eine handgepflegte Site ein — Template-Fixes und `deploy.conf`-Änderungen erreichen sie dann nicht mehr. Siehe den [Konfigurations-Guide](CONFIGURATION-GUIDE.de.md#deploysh-erneut-laufen-lassen--nginx-site-regenerierung--exit-codes).

### Upgrade auf v3.0.0 (von v2.3.0)

Upgrade vor Ort mit `sudo bash deploy.sh` per SSH. Lies vorher die [Upgrade-Hinweise](CHANGELOG.md#upgrade-notes--from-v230) und **Behaviour changes you must act on** am Anfang des [Changelogs](CHANGELOG.md) (englisch). Die Kurzfassung:

- **Starte im Observe-Modus.** Setze `TRAP_BAN_MODE="observe"` (`ban` ist der Default) in `/etc/loxprox/deploy.conf` und deploye: Die Falle antwortet weiter mit 444 und loggt, aber `loxprox/scanner-trap` bannt niemanden (Standard-Szenarien von CrowdSec, etwa für Zugriffe auf sensible Dateien, bannen weiterhin). Prüfe nach ein paar Tagen `sudo cscli alerts list -s loxprox/scanner-trap --limit 0` und `/var/log/nginx/loxprox-trap-hosts.log` auf eigene Geräte, korrigiere sie, setze dann `"ban"` und deploye erneut.
- **Trage jede Loxone-App und jedes Gerät mit dem Hostnamen neu ein** (`https://<dein-host>:1080`) und trage jeden weiteren Namen, den sie verwenden (alter DDNS-Name, CNAME), in `EXTRA_SERVER_NAMES` ein. Mit TLS ist eine nackte IP, fehlendes SNI oder ein fremder `Host` ein Fallen-Treffer: 444 und ein HARD-Ban (7 Tage beim ersten Verstoß).
- **Admin-Webservice-Pfade antworten aus dem Internet mit `403`.** `REMOTE_ADMIN_PATHS="allow"` reicht sie wieder durch; das LAN und `TRUSTED_SOURCES` sind ohnehin ausgenommen.
- **Root-SSH-Login ist im HARD-Modus aus**, sobald ein Nicht-Root-Konto einen Key, eine Login-Shell und funktionierendes sudo hat (nutzbares Passwort oder NOPASSWD-Regel). Lege zuerst deinen Key auf einem sudo-User ab, prüfe in einer zweiten Sitzung, dass `sudo -v` funktioniert, und führe dann `sudo bash deploy.sh --finalize-ssh` aus; sonst bleibt Root bei `prohibit-password`, und der Deploy warnt.
- **`TRUSTED_SOURCES` vs. `CROWDSEC_WHITELIST_IPS`.** Ein Whitelist-Eintrag heißt nur „nie gebannt“; nginx vertraut allein Loopback, `LAN_SUBNET` und `TRUSTED_SOURCES`. Eine Whitelist-Adresse außerhalb des LANs bekommt wie jeder Internet-Client das `403` auf den Admin-Pfaden und die Auth-/WebSocket-Limits. Administriert ein Whitelist-Netz den Miniserver tatsächlich über das Gateway, trage es *vor* dem Deploy in `TRUSTED_SOURCES` ein.

Weitere Änderungen (deutlich längere Bans, wieder installierende Security-Updates, wie du `:1080` auf dem Gateway selbst prüfst) stehen in den Upgrade-Hinweisen.

**Gut zu wissen:**
- **Upgrade von v1.3.x oder älter?** Einmalig `sudo bash deploy.sh --bootstrap-config` ausführen — liest deine aktiven Werte zurück nach `/etc/loxprox/deploy.conf`. Anleitung: [`docs/UPGRADE-to-v1.5.de.md`](docs/UPGRADE-to-v1.5.de.md). Danach die v3.0.0-Hinweise oben befolgen.
- **HTTPS gewünscht?** `ENABLE_TLS="true"` setzen (braucht öffentlichen DNS-Namen + eine `WAN:80 → Gateway:80`-Weiterleitung für ACME). Mit TLS muss jede App und jedes Gerät `https://<hostname>:1080` nutzen — nie die IP, die ein Fallen-Treffer und ein HARD-Ban wäre. Runbook: [`docs/TLS-SETUP.de.md`](docs/TLS-SETUP.de.md).
- **Hinter CGNAT / DS-Lite (keine Portweiterleitung möglich)?** Den v2.0-Tunnel aktivieren: ein kleiner Relay-VPS wird zum öffentlichen Einstiegspunkt, das Gateway wählt sich ausgehend ein. Runbook: [`docs/TUNNEL-SETUP.de.md`](docs/TUNNEL-SETUP.de.md).
- **SSH sperrt dich nicht aus.** Existiert beim ersten Lauf kein `authorized_keys`, zeigt der Installer ein interaktives Menü (Key einfügen, Hilfe beim Anlegen, oder Passwort-Auth mit Warnung behalten) und fällt bei nicht-interaktiven Deploys in einen sicheren Modus. Details: [`CONFIGURATION-GUIDE.de.md`](CONFIGURATION-GUIDE.de.md) → „SSH Key Bootstrap".

---

## Wie es funktioniert

```
Internet ──► Router:1080 ──► LoxProx-Gateway:1080 ──► Loxone:80
LAN ────────────────────────────────────────────────► Loxone:80   (direkt)
```

**Design-Prinzip:** LAN-Geräte erreichen den Miniserver direkt; nur Internet-Traffic läuft durch das Gateway. Heißt: lokale Nutzer bleiben unberührt, und das Gateway konzentriert sich voll auf externe Bedrohungen. Jeder externe Request wird rate-limitiert, durch die CrowdSec-AppSec-WAF geschickt und gegen die Community-Blocklist geprüft, bevor nginx ihn überhaupt an den Miniserver weiterreicht.

**Kein Port-Forward möglich (CGNAT / DS-Lite)?** Seit v2.0 gibt es einen zweiten Weg nach draußen — die in [#4](https://github.com/sgtsilver/loxprox/issues/4) angeteaserte Recherche ist jetzt Feature:

```
App ──► https://deine-domain (Relay-VPS:443) ──► frp-Tunnel ──► Gateway:1080 ──► Loxone:80
                                                  (ausgehend von zu Hause aufgebaut)
```

Das Gateway wählt sich ausgehend bei einem selbst gehosteten Relay-VPS ein; am Router muss kein einziger Port geöffnet werden. TLS terminiert am Relay, der komplette Security-Stack des Gateways bleibt auf dem Pfad, und das Relay ergänzt einen eigenen CrowdSec-Perimeter. Einrichtung in zwei Schritten: [`tunnel-relay/install-relay.sh`](tunnel-relay/README.de.md) auf dem VPS, dann `ENABLE_TUNNEL="true"` auf dem Gateway. Vollständiges Runbook: [Tunnel-Setup](docs/TUNNEL-SETUP.de.md).

### Familien-Zugriff & das LoxProx Panel

Willst du die Miniserver-Verbindung an Familienmitglieder weitergeben? Der
QR-Code-Onboarding-Flow in
[`docs/FAMILY-ONBOARDING.de.md`](docs/FAMILY-ONBOARDING.de.md) verbindet ein
Handy in unter einer Minute. Seit v2.1 stehen derselbe QR-Code, der
Verbindungsstatus und ein Ein-Klick-Unban-Button auch über das
gateway-eigene **LoxProx Panel** zur Verfügung — eine LAN-only Web-UI unter
`http://<gateway-ip>:1081`. Siehe [`docs/GUI-PANEL.de.md`](docs/GUI-PANEL.de.md).

---

## Sicherheits-Schichten

| # | Schicht | Zweck |
|---|---------|-------|
| 1 | **nftables** | Input DROP per Default; SSH nur aus dem LAN; `:1080` fürs Internet offen (mit TLS zusätzlich `:80` für ACME); das LoxProx Panel `:1081` nur aus dem LAN; GeoIP-Drop von CN, RU, KP und IR (IPv4 + IPv6) |
| 2 | **nginx** | Reverse-Proxy, 10 req/s Rate Limit, Connection-Caps, Security-Header, Slowloris-Timeouts; mit TLS ein Host/SNI-Gate mit Scanner-Falle (444 + Log); Admin-Webservice-Pfade antworten aus dem Internet mit `403` (`REMOTE_ADMIN_PATHS`); Auth- und WebSocket-Limits pro nicht vertrauenswürdiger Adresse |
| 3 | **CrowdSec** | IDS, parst nginx- und SSH-Logs; CAPI-Community-Blocklist; HARD- (7 d → 90 d → 365 d) und SOFT-Ban-Leitern (24 h → 7 → 30 → 90 d), für Wiederholungstäter verlängert von `progressive-ban.py` |
| 4 | **Firewall Bouncer** | Holt CrowdSec-Entscheidungen ab → setzt sie dynamisch in nftables durch |
| 5 | **AppSec WAF** | Virtual Patching für bekannte CVEs in gängiger Software (CrowdSec-Hub-Regeln); prüft jeden Request vor dem Weiterreichen |
| 6 | **AppArmor** | nginx-Profil — läuft im Complain-Modus (protokolliert, blockiert nicht), bis du nach dem Soak mit `APPARMOR_NGINX_MODE="enforce"` auf Enforce umschaltest ([ADR 0006](docs/adr/0006-apparmor-nginx-profile-complain-first.md)) |
| 7 | **auditd** | Überwacht Config-Änderungen an nginx, crowdsec, nftables, ssh, sudoers, an der LoxProx-Config, der AppArmor-Policy und den Scripts unter `/opt/loxprox` |
| 8 | **unattended-upgrades** | Debian-Security-Updates; Auto-Reboot für Kernel-Patches zu `AUTOREBOOT_TIME` (Default 03:00) |
| 9 | **Security-Monitor** | 60-Sek-Zyklus: CrowdSec-Blocks, nginx-Fehler, Auth-Versuche, Resource-Alarme → Discord |
| 10 | **Network Watchdog** | Selbstheilend: erkennt Netzwerk-Ausfälle (dhclient-Death-Spiral, Routing-Korruption) und repariert per Service-Restart oder Reboot |
| 11 | **Log-Rotation** | nginx-Access-, Trap- und Unknown-Path-Logs 90 Tage, Error- und AppSec-Logs 14 Tage; LoxProx-eigene Logs wöchentlich bzw. ab 10 MB (8 Generationen); Journal auf 300 MB begrenzt |
| 12 | **Config-Backup** | Tägliche automatische Backups nach `/root/loxprox-backups/` — enthält `deploy.conf`, TLS-Cert+Key, Tunnel-Config und das SSH-Drop-in; Restore via `deploy.sh --restore <tarball>` |

---

## Konfiguration

Die Per-Host-Einstellungen liegen in **`/etc/loxprox/deploy.conf`** (Mode 0640) — `deploy.sh` liest sie beim Start, du editierst also nie das Script selbst. Starte vom getrackten Template `deploy.conf.example`; jeder Wert hat einen Inline-Kommentar, die vollständige Referenz ist [`CONFIGURATION-GUIDE.de.md`](CONFIGURATION-GUIDE.de.md).

Die Werte, die du tatsächlich setzt:

```bash
LOXONE_IP="192.168.1.100"                 # dein Miniserver
GATEWAY_IP="192.168.1.50"                  # statische IP dieses Gateways
LAN_SUBNET="192.168.1.0/24"                # vertrauenswürdiges LAN (nginx vertraut ihm: kein Admin-Pfad-403, keine Auth-/WebSocket-Limits)
SSH_ALLOWED_SUBNETS=("192.168.1.0/24")     # wer SSH erreichen darf
CROWDSEC_WHITELIST_IPS=("192.168.1.0/24")  # nie gebannt (nginx vertraut nicht); lass dein LAN hier drin, ergänze die WAN-IP deines Haushalts
RATE_LIMIT_REQ_PER_SEC="10"
RATE_LIMIT_BURST="100"
ENABLE_APPSEC="true"
APPSEC_MODE="enforce"                      # „monitor" oder „enforce"
ENABLE_TLS="false"                         # optionales HTTPS auf :1080 (siehe TLS-SETUP)
TLS_DOMAIN=""                              # nötig bei ENABLE_TLS="true": der öffentliche Hostname, den jede App nutzen muss
TLS_EMAIL=""                               # nötig bei ENABLE_TLS="true": E-Mail für das ACME-Konto
TRAP_BAN_MODE="ban"                        # „observe" für den ersten Rollout: das Fallen-Szenario bannt nicht (444 + Log)
ENABLE_GUI="true"                          # LoxProx Panel auf :1081, nur LAN
GUI_PASSWORD=""                            # leer = kein Passwort: setze eins
ENABLE_TUNNEL="false"                      # optionaler Fernzugriff ohne offene Ports (siehe TUNNEL-SETUP)
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

**Unterstütztes Ziel: eine Debian-12-VM (Bookworm).** Darauf laufen die Referenz-Installation und die Tests des Projekts. Das CrowdSec-Paket-Repository ist auf `bookworm` festgenagelt, und `deploy.sh` warnt bei jedem anderen OS nur („continuing“). Debian 13 und das aktuelle Raspberry Pi OS sind ungetestet.

**Miniserver:** Gen 1 (reines HTTP auf Port 80) ist das getestete Ziel. `detect-loxone.sh` erkennt an der HTTPS-Antwort auch einen Gen 2 oder neuer und empfiehlt dann nur, TLS auf dem Gateway zu aktivieren; ein Setup mit Gen 2 oder neuer ist nicht getestet.

Die Referenz-Installation ist eine **Proxmox-VM mit 1 vCPU und 1 GB RAM**. Der Speicherverbrauch wurde zuletzt auf v1.x gemessen und seit dem Panel, den Log-Watchern und den zusätzlichen CrowdSec-Szenarien nicht neu bestimmt — prüfe `free -m` auf deinem eigenen Gateway, bevor du die VM unter die Empfehlung verkleinerst.

**Warum 2 vCPU / 2 GB empfohlen sind:** CrowdSecs Leaky-Bucket-Speicher skaliert mit der Anzahl gleichzeitig aktiver Angreifer-IPs — 256 IPs ≈ 150 MB, 15 000 IPs ≈ 1,2–1,5 GB ([Quelle](https://www.crowdsec.net/blog/how-to-process-billions-daily-events-with-crowdsec)). Bei einem breit gestreuten Scan wächst der RAM-Bedarf entsprechend. AppSec WAF kostet pro Request rund **5 ms / 50 mc CPU** mit aktiviertem Virtual-Patching-Ruleset ([Quelle](https://docs.crowdsec.net/docs/appsec/benchmark/)) — eine zweite vCPU hält `nginx` für legitime Nutzer responsiv, während der Bouncer in den ersten 30–60 Sekunden eines Angriffs aufholt und Angreifer schon auf nftables-Ebene gedroppt werden. 1 vCPU / 1 GB funktionieren bei reinem Home-Automation-Traffic einwandfrei; die empfohlene Konfiguration ist die Reserve, die im Angriffsfall den Unterschied macht.

> ⚠️ **Substrat: VM, nicht LXC.** In einem unprivilegierten Proxmox-LXC schlagen mehrere Härtungs-Schritte ohne Fehlermeldung fehl, weil sie auf Host-Kernel-State schreiben, den der Container nicht erreicht:
>
> - `kernel.unprivileged_userns_clone = 0` — die **Fragnesia/CVE-2026-46300-Mitigation** läuft in EPERM und greift nicht (die Knob ist global, nicht per-netns).
> - `kernel.dmesg_restrict`, `kernel.kptr_restrict`, `kernel.randomize_va_space`, `fs.protected_*` — alle host-weit, vom Container aus nicht beschreibbar.
> - **auditd** — der Kernel hat genau einen Audit-Consumer pro Netlink-Socket, und der gehört dem Host; `augenrules --load` schlägt fehl, die Config-Tamper-Detection ist weg.
> - **AppArmor-Enforcement** — `aa-enforce` lädt Profile in das Subsystem des Hosts; der Container kann das nicht.
> - **nftables** — das Capability-Set eines unprivilegierten LXC lässt das Anlegen der `inet filter`-Tabelle nicht zu.
>
> `deploy.sh` erkennt LXC und bricht **standardmäßig ab**. `ALLOW_LXC=1 sudo ./deploy.sh` übergeht das — die dokumentierte Härtungs-Posture gilt dann aber nicht mehr.

### Raspberry Pi

Raspberry-Pi-Hardware ist im Scope, aber **kein getestetes Ziel**: Die Tests und die Referenz-Installation des Projekts laufen auf einer x86-64-Debian-12-VM. Die Tabelle folgt der von CrowdSec veröffentlichten Architektur-Unterstützung, nicht LoxProx-Testläufen. Nimm ein 64-bit-OS auf Debian-12-Basis (Bookworm); das aktuelle Raspberry Pi OS (Debian-13-Basis) ist ungetestet. Lass nach dem Deploy `sudo bash test-gateway.sh` laufen.

| Modell | Architektur | RAM | Erwartete Kompatibilität | Hinweis |
|--------|-------------|-----|----------------|---------|
| **Pi 5** | ARMv8 (64-bit) | 2–8 GB | ✅ Voll | Overkill. Läuft mühelos. |
| **Pi 4** | ARMv8 (64-bit) | 1–8 GB | ✅ Voll | Ideal. Offizielle ARM64-Pakete von CrowdSec. |
| **Pi 3** | ARMv8 (64-bit) | 1 GB | ✅ Voll | Guter Fit. 64-bit Raspberry Pi OS verwenden. |
| **Pi 2** | ARMv7 (32-bit) | 1 GB | ⚠️ Teilweise | CrowdSec verlangt offiziell 64-bit. Community-Erfolge mit 64-bit-Kernel oder Build; ohne Tests nicht für Produktion. |
| **Pi 1 / Zero (original)** | ARMv6 | 512 MB | ❌ Nein | Keine ARMv6-Binaries von CrowdSec. |
| **Pi Zero 2 W** | ARMv8 (64-bit) | 512 MB | ⚠️ Knapp | 64-bit OS möglich, 512 MB aber knapp — Swap und Scenario-Reduktion vermutlich nötig. |

Pro-Prozess-Speicherwerte für einen Pi nennen wir hier nicht: Die Zahlen früherer README-Versionen stammten von v1.x und sind älter als das Panel und die Härtung vom 2026-10. Miss auf deinem eigenen Board. Vorbilder: [CrowdSec auf einem Pi 3 (DietPi)](https://it-security.dnit.fr/en/crowdsec-installation-on-rpi3-with-dietpi-raspberry-os/), [CrowdSec + nginx auf dem Raspberry Pi (2025)](https://www.polimetro.com/en/How-to-protect-your-Raspberry-Pi-with-CrowdSec/).

---

## Abgewehrte Bedrohungen

| Bedrohung | Mitigation |
|-----------|-----------|
| Internet-Scanning / Reconnaissance (Shodan-/Censys-artige Crawler) | nftables DROP-Default, Host/SNI-Gate + Falle (444, kein Fingerprint), HARD-Ban-Leiter (7 d → 90 d → 365 d), GeoIP-Drop (CN/RU/KP/IR), CrowdSec-Community-Blocklist |
| Fernnutzung der Loxone-Admin-Webservices (Dateisystem, Reboot) | `403` aus dem Internet auf den einfachen Pfaden (`REMOTE_ADMIN_PATHS`); LAN und `TRUSTED_SOURCES` ausgenommen |
| Brute-Force gegen Web-UI | nginx Rate Limits + CrowdSec `http-generic-bf` |
| Application-Layer-DDoS | nginx Connection-Limits, Timeouts, CrowdSec |
| Credential Stuffing | Rate Limits, Auth-Endpoint-Limits (3 req/s pro nicht vertrauenswürdiger Adresse) + CrowdSec `http-cve` |
| Ausnutzung bekannter Web-CVEs | AppSec-WAF-Virtual-Patching (CrowdSec-Hub-Regeln — die Abdeckung ist, was der Hub liefert, nicht Loxone-spezifisch) |
| SSH-Brute-Force | CrowdSec `ssh-bf` + nftables-Source-Beschränkung |
| Slowloris / Slow-Read | aggressive nginx-Timeouts (10–15 s) |
| Config-Manipulation | auditd (+ AppArmor, sobald enforced) |

**Nicht abgedeckt:** volumetrischer DDoS (Leitungssättigung). Ein 1–2-GB-Gateway kann eine pipe-füllende Attacke nicht abfangen — dafür brauchst du ISP-Scrubbing oder einen Cloud-Service.

---

## Betrieb & Tests

Nach dem Deploy die Validierungs-Suite laufen lassen — **100+ automatisierte Checks** über Services, Firewall, Proxy, CrowdSec, AppSec, Monitoring, Kernel-Härtung und Backups (inklusive eines Test-Bans, der hinzugefügt und wieder entfernt wird, um die komplette Blocking-Kette zu prüfen):

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
| [Tunnel-Setup](docs/TUNNEL-SETUP.de.md) · [EN](docs/TUNNEL-SETUP.md) | v2.0: Fernzugriff ohne offene Ports (CGNAT/DS-Lite) über einen Relay-VPS |
| [Familien-Onboarding](docs/FAMILY-ONBOARDING.de.md) · [EN](docs/FAMILY-ONBOARDING.md) | QR-Code-Anbindung für Familien-Handys, Split-Horizon-DNS-Hinweise |
| [LoxProx Panel](docs/GUI-PANEL.de.md) · [EN](docs/GUI-PANEL.md) | v2.1: LAN-only-Web-GUI — Familien-QR, Status, Config, Entsperren |
| [Upgrade auf v1.5](docs/UPGRADE-to-v1.5.de.md) · [EN](docs/UPGRADE-to-v1.5.md) | Migration von v1.3.x (Config-Bootstrap) |
| [Security](SECURITY.de.md) · [EN](SECURITY.md) | Bedrohungsmodell, Incident Response, Härtung |
| [Phasen-Guides](phase1-hardening.de.md) | [1: Härtung](phase1-hardening.de.md) · [3: Cutover](phase3-cutover.de.md) · [4: Monitoring](phase4-monitoring.de.md) |
| [Changelog](CHANGELOG.md) (englisch) · [Mitarbeit](CONTRIBUTING.de.md) | Versionshistorie (inkl. der [Upgrade-Hinweise ab v2.3.0](CHANGELOG.md#upgrade-notes--from-v230)) · Beitragen |

---

## Wie dieses Projekt entsteht

Das hier ist ein Experiment in **KI-gestützter, menschlich kuratierter Infrastruktur-Absicherung** — mehrere KIs, keine davon allein die Architektin; ein Mensch mit dem Veto und der operativen Verantwortung.

- **Idee, Hardware und das letzte Wort:** [sgtsilver](https://github.com/sgtsilver) — IT-Systemadministrator. Weiß, wie Angreifer wirklich vorgehen und wie man Infrastruktur dagegen verteidigt; schreibt selbst keinen Code. Bringt das Netz, den Miniserver, die realen Constraints und das operative Bauchgefühl, mit dem sich ein wirklich solides Design von einem nur clever klingenden unterscheiden lässt.
- **Design und Implementierung — ein rotierendes KI-Panel:** [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) lieferte die ursprüngliche Architektur und den Großteil des Codes. [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviewt, fact-checkt, findet und fixt Bugs und übernimmt Folgearbeiten (u. a. das v1.3.4-Release rund um Supply-Chain und Kernel-Härtung). Weitere Modelle (GPT, Gemini, …) werden hinzugezogen, wenn einzelne Entscheidungen wirklich gegengelesen werden müssen.
- **Die Regel:** KIs schlagen vor, KIs grillen sich gegenseitig, und in den Code kommt nichts, weil ein Modell das sagt — sondern nur, wenn die Kreuzprüfung nicht gebrochen hat *und* das Sysadmin-Bauchgefühl eines Menschen „ja, so verteidigt man Infrastruktur wirklich" gesagt hat. Ein clever klingender Vorschlag, der einen der Filter nicht überlebt, fliegt raus — egal, welches Modell ihn vorgeschlagen hat.

---

## Mitarbeit

Siehe [CONTRIBUTING.de.md](CONTRIBUTING.de.md). Das hier ist eine spezialisierte Security-Appliance — Beiträge sollten beim Härten des Loxone-Gateways, Pi-Kompatibilität und Test-Coverage bleiben. Nutzer-Doku ist zweisprachig (Deutsch + Englisch); halte beide im selben PR synchron. Changelog, Rundown, ADRs und Audit-Berichte gibt es nur auf Englisch.

**Hilfe bekommen:** Eröffne für Fragen und Bugs ein [GitHub-Issue](https://github.com/sgtsilver/loxprox/issues); bei Sicherheitsproblemen folge [SECURITY.de.md](SECURITY.de.md) (Responsible Disclosure).

---

## Lizenz

**Source-available, kostenlos für nicht-kommerzielle Nutzung** — siehe [LICENSE](LICENSE). Die Software darf für persönliche, schulische, Forschungs- und nicht-kommerzielle Zwecke frei genutzt, verändert und weiterverteilt werden. Kommerzielle Nutzung — direkt oder indirekt, ganz oder teilweise — ist ausdrücklich untersagt.

---

## Danksagungen

- [CrowdSec](https://www.crowdsec.net/) — die kollaborative IDS/WAF-Engine, die Community-getriebenes Blocking überhaupt erst möglich macht.
- [Loxone](https://www.loxone.com/) — die Home-Automation-Plattform, die dieses Gateway schützt (auch wenn sie Gen 1 nicht mehr patcht).
- Die Home-Automation-Community — fürs so saubere Dokumentieren der Gen-1-Grenzen, dass ein KI-Panel darum herum bauen konnte.
