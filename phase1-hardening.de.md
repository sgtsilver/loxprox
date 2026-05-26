**Sprache:** Deutsch · [English](phase1-hardening.md)

# Phase 1 — Proxmox-Firewall & Loxone-Härtung

Diese Schritte **vor** dem Deploy des Gateways ausführen. Sie senken das Risiko sofort.

---

## 1.1 Bestehendes Router-Forwarding dokumentieren

Im Router-Admin-Panel einloggen und festhalten:

- Externer Port: `1080`
- Interne IP: `<LOXONE_IP>` (Loxone Miniserver)
- Protokoll: `TCP` (verifizieren; Loxone nutzt TCP)

Notieren. Du brauchst es für Phase 3.

---

## 1.2 Proxmox-Firewall auf der Loxone-VM/-Device aktivieren

Wenn der Loxone eine **VM auf Proxmox** ist:

1. Im Proxmox-Web-UI die Loxone-VM auswählen → **Firewall**-Tab.
2. **Enable Firewall** auf VM-Ebene klicken.
3. Diese Regeln hinzufügen (Reihenfolge zählt — spezifischere Regeln zuerst):

| Direction | Type    | Action | Source              | Dest Port | Protocol | Kommentar         |
|-----------|---------|--------|---------------------|-----------|----------|-------------------|
| in        | IPSet   | ACCEPT | <LAN_SUBNET>    | 1080      | tcp      | LAN-Direktzugriff |
| in        | IPSet   | ACCEPT | SECURITY_GATEWAY_IP | 1080      | tcp      | Gateway (Platzhalter) |
| in        | Group   | DROP   | any                 | 1080      | tcp      | Alles andere blocken |

> **Hinweis:** `SECURITY_GATEWAY_IP` nach Phase 2 durch die echte Gateway-IP ersetzen. Bis dahin weglassen oder eine Dummy-IP eintragen, die du später vergibst.

4. Sicherstellen, dass die **Datacenter-Firewall** aktiv ist und auf **Input Policy: DROP** steht (mindestens aber, dass die VM-Regeln greifen).

Wenn der Loxone ein **physisches Gerät** ist (keine Proxmox-VM):

- Die Proxmox-Firewall kann es nicht direkt filtern.
- Du musst dich auf die **Gateway- plus Router-Firewall** für externen Schutz verlassen.
- MAC- oder IP-basierte Firewall-Regeln am Router aktivieren, falls er das unterstützt.

---

## 1.3 Loxone-Miniserver-Härtung

Per **Loxone Config** vom LAN aus auf den Miniserver verbinden.

### A. Remote Configuration deaktivieren (wenn nicht benötigt)

1. **Configure Miniserver** öffnen.
2. Auf den Tab **External Access** oder **Network** wechseln.
3. **Häkchen weg bei:**
   - `Allow this Miniserver to be configured remotely with Loxone Config over the internet`
4. **Apply and send to Miniserver.** Der Miniserver rebootet.

### B. Alle Passwörter ändern

1. **User Management** öffnen.
2. Das **admin**-Passwort auf eine starke Passphrase setzen (16+ Zeichen, Groß-/Kleinschreibung, Zahlen, Sonderzeichen).
3. Ungenutzte Accounts entfernen oder deaktivieren.
4. Default-Usernames möglichst vermeiden.

### C. Firmware aktualisieren

1. In Loxone Config **Help → Check for Updates** wählen.
2. Die **neueste verfügbare Gen-1-Firmware** installieren.
3. Miniserver neu starten.

> ⚠️ Gen 1 wird nicht mehr aktiv weiterentwickelt. Das ist die letzte Verteidigungslinie gegen bekannte CVEs.

### D. Unnötige Dienste deaktivieren

- **FTP Server:** Wenn nicht genutzt, auf `Disabled` setzen (Loxone Config → Network → FTP Server).
- **HTTP External:** Da Gen 1 kein HTTPS kann, bleibt nur HTTP. Port 80 nicht zusätzlich nach außen weiterleiten, falls er offen ist.

---

## 1.4 Router-Härtung (falls unterstützt)

Wenn der Router eine eingebaute Firewall oder Intrusion Detection hat:

1. **SPI Firewall** (Stateful Packet Inspection) aktivieren.
2. **UPnP** deaktivieren, wenn nicht benötigt (verhindert unautorisierte Port-Öffnungen).
3. **DoS Protection** aktivieren, falls der Router sie anbietet (einfacher SYN-Flood-Schutz).
4. Den Miniserver **NICHT** in eine DMZ stellen.

---

## Phase-1-Checkliste

- [ ] Router-Forwarding-Regel dokumentiert
- [ ] Proxmox-Firewall auf Loxone-VM aktiviert (falls zutreffend)
- [ ] Remote Configuration deaktiviert
- [ ] Alle Passwörter geändert
- [ ] Firmware aktualisiert
- [ ] Unnötige Dienste deaktiviert
- [ ] Router-UPnP deaktiviert
