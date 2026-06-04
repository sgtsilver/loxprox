**Sprache:** Deutsch · [English](phase4-monitoring.md)

# Phase 4 — Monitoring, Tuning & Wartung

> ⚠️ **Substrat-Hinweis:** Dieses Runbook wurde ursprünglich für ein LXC-basiertes Deployment geschrieben und nutzt stellenweise noch `LXC` / `pct`-Terminologie. **LoxProx ist inzwischen VM-only** — `deploy.sh` bricht auf LXC standardmäßig ab, weil sich mehrere Verteidigungen (Kernel-Sysctls, Fragnesia-Mitigation, auditd, AppArmor-Enforcement, nftables) aus einem Container heraus nicht anwenden lassen. Für ein neues Deployment einfach "Gateway VM" statt "Gateway LXC" lesen und für den Host-seitigen Backup-Schritt auf Proxmox `qm config <vmid>` statt `pct config <ctid>` benutzen. Die Monitoring-Kommandos innerhalb des Gateways selbst sind substrat-unabhängig.

## Tägliche Checks (erste Woche nach dem Cutover)

In der Security-Gateway-VM täglich laufen lassen:

```bash
# Geblockte IPs anzeigen
cscli decisions list

# CrowdSec-Metriken anzeigen
cscli metrics

# nginx-Error-Log auf Auffälligkeiten prüfen
tail -n 200 /var/log/nginx/loxone-error.log

# Aktivste Quell-IPs anzeigen (Scanner aufspüren)
awk '{print $1}' /var/log/nginx/loxone-access.log | sort | uniq -c | sort -rn | head -n 20
```

---

## Rate Limits tunen

Die Default-Config nutzt:
- **10 req/s** pro IP mit Burst 100
- **20 gleichzeitige Verbindungen** pro IP

Wenn legitime Nutzer geblockt werden (z. B. weil die Loxone-App viele schnelle Requests feuert):

1. `/etc/nginx/sites-available/loxone` editieren
2. `rate=` in der `limit_req_zone`-Zeile anpassen:
   - Locker:  `rate=30r/s` burst=50
   - Streng:  `rate=5r/s`  burst=10
3. `limit_conn` anpassen:
   - Locker:  `limit_conn loxone_conn 50;`
   - Streng:  `limit_conn loxone_conn 10;`
4. Testen und reloaden:
   ```bash
   nginx -t && systemctl reload nginx
   ```

> 💡 Nach jeder Änderung 24 h beobachten. Balance zwischen Sicherheit und Nutzbarkeit halten.

---

## CrowdSec-Wartung

### Hub-Collections aktualisieren

```bash
cscli hub update
cscli hub upgrade
systemctl reload crowdsec
```

### Mehr Scenarios installieren (optional)

```bash
# HTTP-Probing / Crawling
cscli scenarios install crowdsecurity/http-probing

# Bekannte schlechte User-Agents
cscli scenarios install crowdsecurity/http-bad-user-agent

# Brute Force auf generische HTTP-Auth
cscli scenarios install crowdsecurity/http-bf-wordpress
```

### Eigene IPs whitelisten

Falls du dich beim Testen aus Versehen selbst sperrst:

```bash
# Im LXC
cscli decisions delete --ip YOUR_PUBLIC_IP
```

Um das LAN dauerhaft zu whitelisten:

```bash
cat > /etc/crowdsec/parsers/s02-enrich/whitelist-lan.yaml <<'EOF'
name: whitelist-lan
description: "Whitelist LAN traffic"
whitelist:
  reason: "LAN source"
  ip:
    - "<LAN_SUBNET>"
EOF

systemctl reload crowdsec
```

---

## Wenn TLS aktiv ist (v1.5.0+)

Nur relevant, wenn `ENABLE_TLS="true"` in `/etc/loxprox/deploy.conf`. Sonst überspringen.

### Renewal-Cron prüfen

`acme.sh` installiert beim ersten Issuance einen täglichen Cron in **roots** Crontab. Er überlebt Reboots, aber ein unglücklicher `crontab -e` kann ihn killen. Der v1.5.0-Schritt `_loxprox_ensure_acme_cron` setzt ihn nach jedem TLS-Deploy neu — trotzdem regelmäßig prüfen:

```bash
crontab -l | grep acme.sh
# Erwartet: eine Zeile, die auf '"/root/.acme.sh"/acme.sh --cron --home …' endet
```

Wenn er fehlt, ist der sauberste Weg ein erneuter Deploy: `sudo bash deploy.sh`. Nur den Cron ohne kompletten Deploy zurückholen:

```bash
sudo /root/.acme.sh/acme.sh --install-cronjob
```

### Ablauf prüfen und manuell force-renewen

```bash
# Alle von acme.sh verwalteten Certs mit Ablaufdatum anzeigen:
sudo /root/.acme.sh/acme.sh --list

# Manuelles Force-Renew (z. B. beim Key-Rotieren oder Testen des Reload-Hooks):
sudo bash deploy.sh --renew-tls
```

`--renew-tls` ruft `acme.sh --renew … --force` auf und führt den Install-Schritt erneut aus (damit `systemctl reload nginx` greift). Jederzeit gefahrlos aufrufbar.

### TLS sauber abschalten

Zwei Optionen, je nach Gründlichkeit:

```bash
# Soft Disable: Site fällt zurück auf plain :1080, ACME-:80-Listener entfernt,
# Per-Domain-Renewal in acme.sh deaktiviert. Cert-Files unter /etc/loxprox/tls/
# bleiben liegen, damit das Wiedereinschalten schnell geht.
sudo $EDITOR /etc/loxprox/deploy.conf       # ENABLE_TLS="false" setzen
sudo bash deploy.sh

# Komplett platt machen: wie oben plus acme.sh --uninstall, /etc/loxprox/tls/
# wird gelöscht, Cron deaktiviert. Restliche Operator-Aktion: die
# WAN:80 → gateway:80-Router-Weiterleitung entfernen.
sudo bash deploy.sh --remove-tls
```

---

## Log-Rotation

Bereits von `deploy.sh` (`setup_logrotate`) konfiguriert. Funktion verifizieren:

```bash
logrotate -d /etc/logrotate.d/loxone-nginx
```

Logs werden **14 Tage** aufbewahrt, danach komprimiert und ausrotiert.

---

## Gateway-Config backupen

Wenn alles stabil läuft, diese Dateien sichern:

```bash
# Im LXC
mkdir -p /root/gateway-backup
cp /etc/nginx/sites-available/loxone /root/gateway-backup/
cp /etc/crowdsec/acquis.d/nginx.yaml /root/gateway-backup/
cp /etc/sysctl.d/99-security-gateway.conf /root/gateway-backup/
cp /etc/logrotate.d/loxone-nginx /root/gateway-backup/
```

Außerdem die Proxmox-LXC-Config vom Host exportieren:

```bash
# Auf dem Proxmox-Host
pct config 200 > /root/loxone-gateway-lxc-config-backup.txt
```

---

## Alerting (optional, aber empfohlen)

### Simpel: E-Mail bei hoher Fehlerrate

`mailutils` installieren und einen Cronjob einrichten, der mailt, wenn das nginx-Error-Log ausschlägt:

```bash
apt-get install -y mailutils
```

Cron-Eintrag (`crontab -e`):
```cron
# Alle 15 Min prüfen; alerten wenn > 100 Fehler in den letzten 5 Min
*/15 * * * * [ $(tail -n 500 /var/log/nginx/loxone-error.log | wc -l) -gt 100 ] && echo "High error rate on Loxone gateway" | mail -s "Loxone Gateway Alert" admin@yourdomain.com
```

### Fortgeschritten: Promtail + Loki / Grafana

Wenn du einen Home-Monitoring-Stack betreibst, die nginx-Logs nach Loki/Grafana shippen für Dashboards und Alerting.

---

## Incident-Response-Playbook

### Szenario: Gateway reagiert nicht

1. Vom Proxmox-Host: `pct exec 200 -- systemctl status nginx crowdsec`
2. Ressourcen prüfen: `pct exec 200 -- htop` (oder `top`)
3. Wenn das Gateway überlastet ist, temporär umgehen:
   - Router-Forwarding zurück direkt auf die Loxone-IP.
   - Logs später untersuchen.
   - Gateway neu starten und Cutover wiederholen, wenn stabil.

### Szenario: Legitime Nutzer geblockt

1. `cscli decisions list` auf die jeweilige IP prüfen.
2. Bei Bedarf whitelisten (siehe oben).
3. Rate Limits entspannen, falls der Block von nginx kam.

### Szenario: Loxone von außen nicht erreichbar

1. Verifizieren, dass das Router-Forwarding noch auf die Gateway-IP zeigt.
2. Verifizieren, dass der Gateway-LXC läuft: `pct status 200`
3. Verifizieren, dass das Gateway den Loxone erreicht: `pct exec 200 -- curl -v http://LOXONE_IP:80/jdev/cfg/api`
4. nginx-Error-Log auf Backend-Timeouts prüfen.

---

## Monatliche Wartungs-Checkliste

- [ ] CrowdSec-Hub aktualisiert (`cscli hub update && cscli hub upgrade`)
- [ ] LXC-OS-Pakete aktualisiert (`apt-get update && apt-get upgrade`)
- [ ] Geblockte IPs und False Positives reviewt
- [ ] Disk-Usage im LXC geprüft (`df -h`)
- [ ] Backups vorhanden verifiziert
- [ ] nginx-Access-Logs auf ungewöhnliche Muster reviewt
- [ ] Verifiziert, dass das SSH-Banner **nicht** die rote "Password Auth still enabled"-Warnung zeigt. Falls doch: Public Key installieren (`ssh-copy-id root@<gateway>`) und `sudo bash deploy.sh --finalize-ssh` laufen lassen, um vom SOFT- aufs HARD-Profil umzuschalten.
- [ ] AppSec-Detections plausibilisiert: `tail /var/log/nginx/appsec-detections.log` — sollte unter Angriff wachsen und bei Normaltraffic leer bleiben.
- [ ] **Wenn `ENABLE_TLS=true`:** Cert-Ablauf prüfen — `sudo /root/.acme.sh/acme.sh --list`. Sollte > 30 Tage Restlaufzeit zeigen; der tägliche Cron von `acme.sh` erneuert automatisch innerhalb des 30-Tage-Fensters.
- [ ] **Wenn `ENABLE_TLS=true`:** Verifizieren, dass der Auto-Renewal-Cron noch in roots Crontab steht — `crontab -l | grep acme.sh`. Wenn weg, `sudo bash deploy.sh` erneut laufen lassen (der v1.5.0-Schritt `_loxprox_ensure_acme_cron` installiert ihn neu).

---

## Bekannte Grenzen & zurückgestellte Arbeit

Punkte, die das Skills-Audit (`audits/2026-05-23-skills-audit.md`) aufgeworfen hat, die aber durch das aktuelle `deploy.sh` nicht gefixt werden. Hier festgehalten, damit sie nicht in jedem Audit-Zyklus erneut hochkommen.

### Port-Scan-Sichtbarkeit

nftables droppt Scans auf `:22` von außerhalb der `SSH_ALLOWED_SUBNETS` lautlos — keine Log-Zeile, kein CrowdSec-Event, kein Offender-Counter. CrowdSec sieht nur, was nginx und `auth.log` hergeben; ein langsamer TCP-Fan-Scan auf die Gateway-Ports landet damit nie im Access-Log, weil nginx ihn am Listen-Socket gar nicht erst annimmt.

Sauber zu fixen ist invasiv: entweder eine nftables-Regel `limit rate over … log prefix "portscan: "`, die in einen Custom-CrowdSec-Parser auf `kern.log` streamt, oder `crowdsecurity/iptables` installieren und füttern. Beides bringt Lärm und einen zusätzlichen Parser. Das Bedrohungsmodell des Gateways behandelt Internet-Scans als bereits mitigiert (`:1080` ist nach außen der einzige Listener, und CrowdSecs HTTP-Scenarios fangen die wirklich interessanten Probes ab). Zurückgestellt, bis es einen konkreten Grund für Scanner-Telemetrie auf der Ebene gibt.

### Kein Host File-Integrity-Monitoring (AIDE)

Das Audit hat das Fehlen von AIDE moniert. Die Entscheidung, es wegzulassen, steht:

- `auditd` beobachtet bereits jeden Config-Pfad, den AIDE schützen würde — in Echtzeit, mit Event-Granularität. AIDEs Mehrwert ist **Offline-Tampering** (Rootkit, Live-CD-Manipulation der Disk während die VM aus ist) — eine Klasse, die auditd nicht sehen kann.
- Der nächtliche `aide --check` über `/etc + /bin + /sbin + /usr/bin + /boot` zieht auf der Mindesthardware (1 GB / 1 vCPU) rund 200 MB RSS und 5–10 Min Wandzeit. Beides reißt das Toleranzfenster von `network-watchdog.sh` — ein zur Unzeit laufender Check sieht aus, als würde die Box hängen.
- Die Offline-Tampering-Bedrohung setzt entweder physischen Zugriff auf den Proxmox-Host oder Root auf dem Host-Kernel voraus. Beides sind Out-of-Band-Ausfälle, die AIDE nur im Nachhinein bestätigen würde, und an dem Punkt heißt der Recovery-Pfad "VM aus bekanntem guten Snapshot zurückspielen", nicht "gegen die AIDE-DB diffen".

Neu bewerten, wenn die Hardware-Baseline jemals fest auf ≥ 2 GB RAM und ≥ 2 vCPU rückt (nicht nur der empfohlene Floor).

### IoT-Assessment-Skill betrifft den Loxone, nicht das Gateway

Der Audit-Befund `performing-iot-security-assessment` zielt auf den Loxone Miniserver Gen 1 selbst (UART/JTAG, Firmware-Extraktion, Default-Credential-Audit) — nicht auf LoxProx. LoxProx **ist** der kompensierende Schutz für dieses Legacy-Gerät. Ein echtes Assessment des Miniservers würde physischen Zugang zur Gen-1-Einheit erfordern und ist außerhalb des Scopes des Gateway-Repos.
