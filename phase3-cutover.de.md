**Sprache:** Deutsch · [English](phase3-cutover.md)

# Phase 3 — Umstellung auf das Security-Gateway

> ⚠️ **Substrat-Hinweis:** Dieses Runbook wurde ursprünglich für ein LXC-basiertes Deployment geschrieben und nutzt stellenweise noch `LXC` / `pct`-Terminologie. **LoxProx ist inzwischen VM-only** — `deploy.sh` bricht auf LXC standardmäßig ab, weil sich mehrere Verteidigungen (Kernel-Sysctls, Fragnesia-Mitigation, auditd, AppArmor-Enforcement, nftables) aus einem Container heraus nicht anwenden lassen. Für ein neues Deployment einfach "Gateway VM" statt "Gateway LXC" lesen und auf Proxmox `qm` statt `pct` verwenden. Die Cutover-Schritte selbst sind substrat-unabhängig.

## Voraussetzungen

- [ ] Phase-1-Härtung abgeschlossen (Proxmox-Firewall, Loxone-Passwörter, Firmware).
- [ ] Phase-2-Gateway-LXC läuft und ist gesund.
- [ ] Du hast **von innerhalb des LXC** verifiziert, dass es den Loxone erreicht:
  ```bash
  curl -v http://<LOXONE_IP>:80/jdev/cfg/api
  ```
  (IP an deinen Loxone anpassen. Du solltest eine HTTP-Antwort bekommen.)
- [ ] Du hast einen Weg, im Notfall an den Proxmox-Host oder ins LAN zu kommen (z. B. VPN, TeamViewer oder physischer Zugang).

---

## Schritt-für-Schritt-Cutover

### Schritt 1: Gateway-Listener prüfen

Im LXC:
```bash
ss -tlnp | grep 1080
# Erwartet: LISTEN 0.0.0.0:1080 (nginx)
```

Proxy lokal testen:
```bash
curl -v http://127.0.0.1:1080/jdev/cfg/api
```

Wenn das fehlschlägt, **nicht weitermachen**. Erst die Nginx-Config fixen.

---

### Schritt 2: Proxmox-Firewall aktualisieren (wenn Loxone eine VM ist)

Im Proxmox-Web-UI → Loxone-VM → Firewall:

1. Die Regel aktualisieren, die auf die Security-Gateway-IP zeigt:
   - Source: `<GATEWAY_IP>` (Security-Gateway-LXC)
   - Dest Port: `1080`
   - Action: `ACCEPT`

2. Sicherstellen, dass diese Regeln in der richtigen Reihenfolge existieren:
   1. `<LAN_SUBNET>` → ACCEPT 1080
   2. `<GATEWAY_IP>` → ACCEPT 1080
   3. `any` → DROP 1080

---

### Schritt 3: Router-Port-Forwarding umstellen

Im Router-Admin-Panel einloggen.

**Alte Regel:**
- Externer Port `1080` → `<LOXONE_IP>:80` (Loxone-IP — der Router hat 1080→80 übersetzt)

**Neue Regel:**
- Externer Port `1080` → `<GATEWAY_IP>:1080` (Security-Gateway-IP)

Speichern und anwenden.

> ⚠️ **Die alte Regel noch NICHT löschen.** Manche Router erlauben Notizen. Die alte Ziel-IP für alle Fälle aufschreiben.

---

### Schritt 4: Externen Zugriff testen

Von einem Gerät **außerhalb des LAN** (z. B. Smartphone auf Mobilfunk):

```
http://<YOUR_DOMAIN>:1080
```

Du solltest die Loxone-Oberfläche erreichen.

Auch die **Loxone-App** testen, falls Nutzer auf sie angewiesen sind.

---

### Schritt 5: LAN-Zugriff testen

Von einem Gerät **innerhalb des LAN** (`<LAN_HOST>`):

```
http://<LOXONE_IP>:80
```

Das sollte weiterhin direkt funktionieren, am Gateway vorbei.

---

### Schritt 6: Rollback-Plan (falls etwas bricht)

Wenn der externe Zugriff fehlschlägt:

1. Router-Port-Forwarding zurück auf die Loxone-IP setzen.
2. Gateway-Logs prüfen:
   ```bash
   # Im LXC
   tail -f /var/log/nginx/loxone-error.log
   journalctl -u nginx -f
   ```
3. Verifizieren, dass das Gateway den Loxone erreicht:
   ```bash
   curl -v http://<LOXONE_IP>:80/jdev/cfg/api
   ```
4. Problem fixen, dann Schritt 3 erneut versuchen.

---

## Verifikation nach dem Cutover

- [ ] Externer Zugriff funktioniert über `<YOUR_DOMAIN>:1080`
- [ ] Loxone-App verbindet sich erfolgreich von außen
- [ ] LAN-Zugriff funktioniert direkt zur Loxone-IP
- [ ] Nginx-Access-Logs zeigen Traffic: `tail -f /var/log/nginx/loxone-access.log`
- [ ] CrowdSec läuft: `cscli metrics`
- [ ] CrowdSec-Bouncer ist aktiv: `systemctl status crowdsec-firewall-bouncer`
