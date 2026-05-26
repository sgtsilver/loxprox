**Sprache:** Deutsch · [English](SECURITY.md)

# Loxone Miniserver Gen 1 — Security Posture & Threat Model

## Responsible Disclosure

**Kein Bug Bounty — kein Geld.** Wer eine Vulnerability findet, öffnet einen Pull Request mit dem Fix. Jeder Beitrag wird reviewt und analysiert. Das hier ist ein community-gehärtetes Projekt: Der Code ist die Verteidigung, und besserer Code macht alle sicherer.

Wer keinen Fix liefern kann, öffnet ein Issue mit Reproduktionsschritten, dann kümmern wir uns darum.

---

## Executive Summary

Der Loxone Miniserver Gen 1 ist **Legacy-Hardware der ersten Generation** ohne **TLS-Support**, ohne **native Auth-Härtung** und ohne **neue Security-Features** (TLS, Remote Connect, Trusts gibt es nur ab Gen 2). Loxone hat das Gerät zwar nicht formal als EOL erklärt, Firmware-Updates kommen aber nur noch im Schneckentempo — der letzte bekannte Security-Patch war 2020 (CVE-2020-27488). Das ist die Definition eines "Legacy-Geräts, das auf der Netzwerkebene geschützt werden muss".

Dieses Gateway existiert, weil der Miniserver sich selbst nicht schützen kann.

---

## Threat Model

### Wovor wir schützen

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| **Internet-Scanning / Reconnaissance** | Sicher | Hoch | nftables DROP per Default, CrowdSec CAPI |
| **Brute Force gegen Web-UI** | Hoch | Kritisch | nginx Rate Limits, CrowdSec-Scenarios |
| **Application-Layer-DDoS** | Mittel | Hoch | nginx Connection-Limits, Timeouts, CrowdSec |
| **Volumetrischer DDoS** | Niedrig | Kritisch | *Am Gateway nicht stoppbar — nur ISP/Cloud* |
| **Credential Stuffing** | Hoch | Kritisch | Rate Limits + CrowdSec http-cve |
| **Ausnutzung von Loxone-CVEs** | Mittel | Kritisch | AppSec WAF (Virtual Patching), WAF-Regeln |
| **Lateral Movement (LAN → Miniserver)** | Niedrig | Hoch | Proxmox-Firewall, VLAN-Isolation |
| **Lateral Movement (LAN → Gateway via SSH)** | Niedrig | Kritisch | `setup_ssh_hardening` — CIS §5.2 Drop-in, Key-only, `PermitRootLogin no`, `MaxAuthTries 4` |
| **Passwort-Extraktion aus Config-Datei** | Mittel | Hoch | *Nur physische Zugangskontrolle* |
| **Cloud-DNS-Hijacking (CVE-2020-27488)** | Niedrig | Hoch | Cloud DNS abschalten, statische IP verwenden |

### SSH-Modell — nur LAN-seitig

Das Gateway exponiert `:22` ausschließlich gegenüber `SSH_ALLOWED_SUBNETS` via nftables. Aus dem Internet ist SSH auf diesem Host nie sichtbar — es gibt **keinen** `endlessh`-artigen Tarpit, weil es auf Port 22 keine öffentliche Angriffsfläche gibt, die ihn absorbieren müsste. Die Härtung greift ausschließlich im Inside-the-LAN-Angreifer-Szenario: ein kompromittiertes Laptop, Smart-TV oder IoT-Toaster, der vom LAN aufs Gateway pivotieren will. `deploy.sh` liefert ein CIS-Debian-12-§5.2-Drop-in (Key-only, kein Root, VERBOSE-Log) inklusive First-Deploy-Bootstrap, der das Lock-yourself-out-Henne-Ei-Problem verhindert (siehe `CONFIGURATION-GUIDE.md` → "SSH Key Bootstrap").

### Was der Miniserver NICHT kann (Gen-1-Grenzen)

- Kein HTTPS/TLS (Hardware verkraftet die SSL-CPU-Last nicht)
- Kein WebSocket über WSS
- Passwörter in der Config-XML sind verschlüsselt, nicht gehasht — im Speicher entschlüsselbar
- Keine Multi-Faktor-Authentifizierung
- Keine Session-Timeout-Kontrollen
- Kein eingebautes Rate Limiting
- Keine IP-basierte Zugriffskontrolle
- Kein Audit-Logging
- Firmware-Updates kommen nur noch sehr langsam; der letzte bekannte Security-Patch war 2020 (Cloud-DNS-Lücke CVE-2020-27488). Neue Sicherheits-Features (TLS, Remote Connect, Trusts) gibt es nur ab Gen 2.

### Was das Gateway TUT

Das Gateway ist die **gesamte Security-Schicht**. Jeder Schutz, den der Miniserver vermissen lässt, wird hier implementiert.

---

## Architektur

```
Internet ──► Router:1080 ──► Gateway VM:1080 ──► Loxone:80
                    │              │
                    │              ├── nginx (proxy, rate limits, headers)
                    │              ├── CrowdSec (IDS, CAPI blocks, AppSec WAF)
                    │              ├── nftables (input DROP, allow :1080 + SSH)
                    │              ├── AppArmor (nginx profile enforced)
                    │              ├── auditd (config change monitoring)
                    │              ├── Discord alerts (real-time notifications)
                    │              └── Network watchdog (self-healing monitor)
                    │
                    └── LAN:<LAN_SUBNET> ──► Loxone:80 (direct, bypass)
```

---

## Implementierte Schutzmechanismen

### Layer 1: Network Firewall (nftables)

- Input Policy: **DROP**
- Erlaubter Inbound-Traffic: SSH (nur LAN + Site-to-Site), :1080 (jede Quelle)
- Forward Policy: DROP
- CrowdSec Bouncer verwaltet die dynamische `table ip crowdsec` für Live-Blocks
- Statische Regeln in `table inet filter` werden bei Reload nie überschrieben

### Layer 2: Reverse Proxy (nginx)

- Rate Limit: 10 req/s pro IP, Burst 100
- Connection Limit: 20 gleichzeitig pro IP
- Slowloris-Schutz: aggressive Timeouts (10–15 s)
- Security Headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, **Content-Security-Policy**, **Permissions-Policy**
- `server_tokens off`; `proxy_hide_header Server` und `proxy_hide_header X-Powered-By`, damit keine Backend-Versionen leaken
- Buffer-Limits gegen Memory Exhaustion
- AppSec-Subrequest: jeder Request wird von der CrowdSec WAF geprüft, bevor er weitergeproxyt wird

### Layer 3: Intrusion Detection (CrowdSec)

- CAPI-Community-Feed: ~26k bekannte Bad IPs werden automatisch geblockt
- Lokale Scenarios: nginx Bad Requests, SSH-Brute-Force, HTTP-CVEs
- AppSec WAF: Virtual Patching für bekannte CVEs, SQLi, XSS, Path Traversal
- Whitelist: LAN, Site-to-Site, Uptime-Monitor, Heroku-Prowl-IPs
- SSH-Acquisition via `/var/log/auth.log`

### Layer 4: Application Security (AppSec WAF)

- Modus: **enforce** (geblockte Requests werden mit 403 abgewiesen)
- Collection: `crowdsecurity/appsec-virtual-patching` (200+ CVE-spezifische Regeln)
- Lauscht auf `127.0.0.1:7422`
- Prüft jeden Request, bevor er Loxone erreicht
- **Authentifizierung**: AppSec verlangt den API-Key des CrowdSec Firewall Bouncers im Header `X-Crowdsec-Appsec-Api-Key`
- **Pflicht-Header**: `X-Crowdsec-Appsec-Ip`, `X-Crowdsec-Appsec-Uri`, `X-Crowdsec-Appsec-Verb`
- Der nginx-`auth_request`-Subrequest setzt diese Header automatisch via `/etc/nginx/crowdsec-appsec.conf`
- **Risiko-Hinweis**: Der AppSec-API-Key liegt in `/etc/nginx/crowdsec-appsec.conf` (Mode 640, root:www-data). Falls ein Angreifer lokales File-Read erreicht (z. B. via LFI in Loxone oder einen kompromittierten nginx-Worker), kann er den Key extrahieren und die WAF umgehen. Das ist ein bekanntes, akzeptiertes Risiko dieser Architektur. Mitigation: Loxone und nginx vollständig patchen; alternativ systemd `LoadCredential=` für reine Memory-Secret-Injection (benötigt njs/Lua in nginx).
- AppSec-Metriken: `cscli metrics | grep -A3 Appsec`

### Layer 5: System Hardening

- AppArmor: nginx-Profil aktiv
- systemd: PrivateTmp, NoNewPrivileges, ProtectKernelTunables etc.
- Kernel: syncookies, rp_filter, dmesg_restrict, kptr_restrict, ASLR
- auditd: überwacht Config-Änderungen an nginx/crowdsec/nftables, Auth-Dateien, sudo
- unattended-upgrades: Auto-Reboot um 03:00 für Kernel-Patches

### Layer 6: Monitoring & Alerting

- **Discord-Webhook**: Echtzeit-Alerts für Blocks, Anomalien, Service-Failures
- **Security Monitor** (60-Sek-Zyklus): CrowdSec-Decisions, nginx-Fehler, Auth-Versuche, AppSec-Detections, System-Ressourcen
- **Network Watchdog** (60-Sek-Zyklus): erkennt Netzwerk-Layer-Ausfälle (dhclient-Death-Spiral, Kernel-Routing-Korruption, Interface-Desync), die Prozess-Level-Checks nicht sehen. Selbstheilung per Service-Restart; Reboot als letzte Maßnahme mit Pre-/Post-Reboot-Discord-Reporting und Anti-Loop-Schutz.
- **Log-Rotation**: 14 Tage Aufbewahrung für nginx-Logs
- **Config-Backup**: tägliches automatisches Backup nach `/root/loxprox-backups/`
- **Test-Suite**: `sudo ./test-gateway.sh` validiert alle Komponenten nach dem Deploy

---

## Was noch hinzukommen könnte (Future Hardening)

### Geo-Blocking
- High-Risk-Länder via ipdeny.com + nftables-Set blocken
- Status: Script existiert, per Default nicht aktiv (kann reisende Nutzer ausschließen)
- Aktivieren: `GEOIP_ENABLED=true /opt/loxprox/geoip-block.sh`

### Fail2ban (redundant, aber zusätzliche Schicht)
- SSH: max. 3 fehlgeschlagene Logins in 10 Min = 1 Stunde Ban
- nginx: 404-Scanning-Erkennung
- Status: Nicht installiert — CrowdSec macht das nativ

### TLS-Termination auf :1080 (ab v1.5.0 ausgeliefert, opt-in)

Der Miniserver selbst kann nach wie vor kein TLS (Gen-1-CPU-Constraint — unverändert), das No-TLS-Gerät hinter dem Gateway bleibt also architektonische Realität. Was sich in v1.5.0 geändert hat: **das Gateway kann jetzt HTTPS auf `:1080` zur öffentlichen Seite terminieren** via `acme.sh` + HTTP-01, mit automatischem Renewal-Cron, der nach jedem Deploy verifiziert wird. Der acme.sh-Installer ist per SHA256 gepinnt (kein `curl|bash`), das ausgestellte Cert liegt in `/etc/loxprox/tls/` (Mode 0640), und die öffentliche Angriffsfläche wächst um exakt einen Listener — `:80`, eingeschränkt auf `/.well-known/acme-challenge/` plus einen 301-Redirect nach HTTPS-on-1080. Per Default aus; geschaltet durch einen einzigen `ENABLE_TLS`-Key in `/etc/loxprox/deploy.conf`. Der Disable-Pfad setzt die Site zurück und bricht den Renewal-Cron ab, behält aber die Cert-Dateien — das Zurückschalten geht entsprechend schnell. Vollständiges Runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).

### Volumetric DDoS Protection
- **An diesem Gateway nicht machbar** — 512 MB RAM / 1 vCPU
- Optionen: Cloudflare Spectrum, AWS Shield, ISP-Level-Scrubbing
- Status: dokumentierte Limitierung

### Netzwerk-Segmentierung
- Loxone in ein isoliertes VLAN setzen
- Gateway in DMZ-VLAN
- Firewall-Regeln: nur Gateway-IP → Loxone:80
- Status: erfordert Änderungen an Router/Proxmox

### Honeypot-Endpoints
- Fake `/admin`, `/wp-login.php` etc. auf dem Gateway
- CrowdSec erkennt Scanner, die Honeypots treffen → sofortiger Ban
- Status: leicht via nginx-Location-Blöcke ergänzbar

---

## Operative Kommandos

```bash
# Alle Komponenten prüfen
sudo bash /tmp/test-gateway.sh

# CrowdSec-Decisions anzeigen
sudo cscli decisions list

# CrowdSec-Alerts anzeigen
sudo cscli alerts list

# AppSec-Metriken anzeigen
sudo cscli metrics | grep -A3 Appsec

# nftables-Regeln anzeigen
sudo nft list ruleset

# Live-nginx-Access-Log
sudo tail -f /var/log/nginx/loxone-access.log

# Monitor-Log anzeigen
sudo tail -f /var/log/loxprox-monitor.log

# IP manuell bannen
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual-ban"

# IP entbannen
sudo cscli decisions delete --ip 1.2.3.4

# Vollständigen Deploy nochmal laufen lassen
sudo bash /tmp/deploy.sh
```

---

## Incident-Response-Playbook

### Gateway antwortet nicht mehr

1. Proxmox-Konsole prüfen: `systemctl status nginx crowdsec`
2. Wenn überlastet: Router-Forwarding wieder direkt auf die Loxone-IP umstellen
3. Logs später analysieren, Gateway wiederherstellen, erneut umschalten

### Legitimer Nutzer geblockt

1. `cscli decisions list` → IP heraussuchen
2. `cscli decisions delete --ip <IP>`
3. Bei Wiederholung in die Whitelist eintragen

### Loxone von außen nicht erreichbar

1. Router-Forwarding prüfen: extern 1080 → `<GATEWAY_IP>:1080`
2. Gateway-Status prüfen: `systemctl status nginx`
3. Gateway → Loxone-Erreichbarkeit prüfen: `curl http://<LOXONE_IP>:80/jdev/cfg/api`
4. nginx-Error-Log auf Backend-Timeouts prüfen
5. Test-Suite laufen lassen: `sudo bash /tmp/test-gateway.sh`

### Discord-Webhook-Rotation

Wenn eine Webhook-URL kompromittiert ist oder Credentials rotiert werden müssen:
1. In Discord: Server-Einstellungen → Integrationen → Webhooks → alten Webhook löschen
2. Neuen Webhook anlegen und die URL kopieren
3. `DISCORD_WEBHOOK_URL` in `deploy.sh` aktualisieren (oder direkt in `/etc/loxprox/config.env`)
4. `deploy.sh` erneut ausführen oder den Monitor-Timer neu starten: `systemctl restart loxprox-monitor.timer`
5. Verifizieren: Test-Alert auslösen (z. B. `sudo /opt/loxprox/discord-alert.sh INFO "Test" "Rotation verified"`)

**Hinweis**: Die Webhook-URL liegt in `/etc/loxprox/config.env` mit Mode 640. Nur root und die Gruppe `loxprox` können sie lesen.

### AppSec liefert 401-Fehler

Wenn im nginx-Log AppSec-401-Fehler auftauchen, hat sich vermutlich der Bouncer-API-Key geändert:
1. Aktuellen Key auslesen: `awk '/^api_key:/ {print $2}' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local`
2. `/etc/nginx/crowdsec-appsec.conf` mit dem neuen Key aktualisieren
3. `sudo nginx -s reload`
4. Oder einfach `deploy.sh` erneut laufen lassen — der regeneriert die Include-Datei automatisch

---

## Compliance-Hinweise

- **Keine GDPR/Privacy-Compliance** auf dem Miniserver selbst — Logs enthalten IP-Adressen
- Gateway-Logs enthalten Quell-IPs (für die Security-Analyse erforderlich)
- Discord-Alerts enthalten IP-Adressen und Request-Details
- Aufbewahrung: 14 Tage für nginx, System-Logs werden von journald verwaltet
