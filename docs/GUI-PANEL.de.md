**Sprache:** Deutsch · [English](GUI-PANEL.md)

# LoxProx Panel — LAN-only Web-GUI (v2.1)

> **Für wen das ist:** für alle, die eine Klick-Ansicht des Gateway-Zustands
> wollen, eine Ein-Klick-Einladung für Familien-Handys, oder eine Möglichkeit,
> eine IP zu entbannen, ohne eine SSH-Sitzung zu öffnen. Alles hier ist
> optional — das Panel ist per Default aktiv, aber das Gateway funktioniert
> genauso gut, wenn es aus ist.

Das LoxProx Panel ist eine kleine, in sich geschlossene Web-UI, die auf dem
Gateway selbst läuft und ausschließlich aus deinem LAN erreichbar ist. Es
vergrößert die Angriffsfläche auf der Internet-Seite des Gateways nicht —
es ist eine Komfort-Schicht über denselben Tools, die du sonst per SSH
erreichst (`cscli`, `systemctl`, `openssl`, `deploy.sh`).

## Was du bekommst

- Default: **an** (`ENABLE_GUI="true"`), lauscht auf `GUI_PORT="1081"`.
- Erreichbar unter `http://<gateway-ip>:1081` von jedem Gerät in
  `LAN_SUBNET` oder `SSH_ALLOWED_SUBNETS` — sonst nirgendwo.

## Feature-Tour

**Familien-Einladung.** `/invite` ist eine druckbare Seite mit dem QR-Code
(siehe [`FAMILY-ONBOARDING.de.md`](FAMILY-ONBOARDING.de.md)) plus denselben
DE/EN-Onboarding-Schritten — ins Technikschränkchen kleben statt
`loxone-qr.png` von Hand zu erzeugen.

**Status-Kacheln** (die Startseite des Panels, `/`):

| Kachel | Zeigt |
|---|---|
| Services | nginx, CrowdSec, Firewall-Bouncer, frpc (wenn der Tunnel an ist), `loxprox-monitor.timer`, `network-watchdog.timer` |
| Cert-Ablauf | Verbleibende Tage von `/etc/loxprox/tls/fullchain.pem` (wenn TLS an ist) |
| Miniserver-Erreichbarkeit | Live-TCP-Check gegen `LOXONE_IP:LOXONE_PORT` |
| CrowdSec-Decisions | Anzahl + letzte 10 (Herkunft, Land, Dauer) |
| AppSec-Detections | Anzahl heute geblockter Requests |
| Backup-Alter | Alter + Größe des neuesten `/root/loxprox-backups/*.tar.gz` |
| System | Disk, RAM, Load |
| Tunnel | frpc-Verbindungsstatus, wenn `ENABLE_TUNNEL=true` |

**Logs.** Read-only Tail-Ansicht der nginx-, CrowdSec- und
Monitor-/Watchdog-Logs — kein `journalctl`/`tail -f` per SSH mehr für einen
schnellen Blick.

**Config-Editor.** Eine gewhitelistete Teilmenge der Werte in
`/etc/loxprox/deploy.conf` per Formular bearbeiten (Rate Limits, Timeouts,
AppSec-Modus, CrowdSec-Whitelist, TLS, Tunnel, GUI-Einstellungen) und mit
einem Klick **anwenden** — das Panel legt zuerst ein zeitgestempeltes
Backup von `deploy.conf` an, führt dann `deploy.sh` im Hintergrund aus und
zeigt das Job-Log. `GATEWAY_IP`, `LAN_SUBNET` und `SSH_ALLOWED_SUBNETS` sind
hier bewusst **nicht** editierbar — ein Fehler in einem dieser drei Werte
ist ein SSH-Lockout-Risiko und bleibt eine SSH-only-Änderung.

**Support-Aktionen.** Je ein Button für: eine IP entbannen (`cscli
decisions delete`), einen Service neu starten (nginx / CrowdSec / Bouncer /
frpc), eine TLS-Erneuerung erzwingen (`deploy.sh --renew-tls`), und einen
Test-Alert senden (prüft den Discord-Webhook Ende-zu-Ende).

## Security-Modell

Das Panel tauscht Komfort gegen einen größeren Footprint auf der Box, ist
also auf Fail-Closed gebaut:

- **Nie aus dem Internet erreichbar.** `deploy.sh` fügt eine nftables-Regel
  hinzu, die exakt auf `LAN_SUBNET` + `SSH_ALLOWED_SUBNETS` (dedupliziert)
  als Quelle beschränkt ist — dieselbe Vertrauensgrenze, die SSH schon
  nutzt. Es gibt keinen Pfad vom öffentlichen `:1080`-Listener ins Panel.
- **Host-Header-Whitelist.** Das Panel beantwortet nur Requests, deren
  `Host`-Header der Gateway-IP, `127.0.0.1`, `localhost` oder Varianten mit
  explizitem Port entspricht — das schließt die DNS-Rebinding-Flanke auch
  dann, wenn jemand ein LAN-Gerät dazu bringen könnte, eine feindliche
  Domain auf die Gateway-IP aufzulösen.
- **CSRF-Header bei jeder Mutation.** Jeder `POST`-Request muss den Header
  `X-LoxProx-Gui: 1` mitschicken; es gibt keine CORS-Konfiguration, die es
  einem anderen Origin erlauben würde, das aus einem Browser zu fälschen.
- **Optionales Passwort für mutierende Aktionen.** `GUI_PASSWORD` ist per
  Default leer (keine Auth) — auf einem LAN, das du vollständig
  kontrollierst, vertretbar. Setzt du es, muss jeder
  Unban-/Restart-/Renew-/Apply-/Config-Write-Call es über den Header
  `X-LoxProx-Auth` mitschicken (Prüfung per Constant-Time-Vergleich).
  **Empfohlen, wenn untrusted Geräte — Gäste, IoT, Kinder-Tablets — dein
  `LAN_SUBNET` oder ein geroutetes VLAN teilen, das das Gateway erreicht.**
- **Läuft als root.** Das Panel ruft `cscli`, `systemctl` auf, liest
  `/etc/loxprox/deploy.conf` (Mode 0640) und führt `deploy.sh` selbst aus —
  alles davon braucht ohnehin root. Es ist nicht mit `ProtectSystem=strict`
  gesandboxt wie frpc, weil der Config-Apply-Job System-State schreiben
  muss; die kompensierenden Kontrollen sind die LAN-only-Erreichbarkeit und
  die Auth-Option oben, nicht Prozess-Isolation.
- **Ganz deaktivieren:** `ENABLE_GUI="false"` in `/etc/loxprox/deploy.conf`
  setzen und `sudo bash deploy.sh` erneut laufen lassen. Das stoppt und
  deaktiviert den Service `loxprox-gui` und entfernt die nftables-Regel;
  die installierte Datei bleibt liegen (harmlos, unerreichbar), damit ein
  Wieder-Aktivieren sofort geht.

## Config-Keys

| Key | Default | Zweck |
|-----|---------|-------|
| `ENABLE_GUI` | `"true"` | Master-Toggle. |
| `GUI_PORT` | `"1081"` | TCP-Port, auf dem das Panel lauscht. |
| `GUI_PASSWORD` | `""` | Leer = keine Auth. Setzen, um `X-LoxProx-Auth` bei jedem mutierenden Request zu verlangen. Im Config-Editor write-only (wird nie zurückangezeigt). |

## QR-Code / Host-Erkennung

Das Panel leitet den Host für QR-Code und Einladungsseite genauso her, wie
ein Operator ihn von Hand wählen würde:

1. `ENABLE_TUNNEL="true"` → nutzt `TUNNEL_PUBLIC_HOST`.
2. Sonst `ENABLE_TLS="true"` → nutzt `TLS_DOMAIN:1080`.
3. Sonst → ein vom Operator eingetragener Host, gespeichert in
   `/var/lib/loxprox/gui-settings.json` (einmalig im Panel setzen — den
   öffentlichen DNS-Namen eines reinen Port-Forwards kann niemand
   automatisch erraten).

Der erkannte Wert lässt sich im Panel jederzeit überschreiben.

## Troubleshooting

**Panel unter `http://<gateway-ip>:1081` nicht erreichbar:**
1. Prüfen, ob es an ist: `grep ENABLE_GUI /etc/loxprox/deploy.conf`.
2. Prüfen, ob der Service läuft: `systemctl status loxprox-gui` /
   `journalctl -u loxprox-gui -n 50`.
3. Prüfen, ob die Firewall-Regel existiert und du von einer erlaubten
   Quelle aus zugreifst: `sudo nft list ruleset | grep -A2 "dport
   $GUI_PORT"` — du musst in `LAN_SUBNET` oder `SSH_ALLOWED_SUBNETS` sein.

**QR-Code/Einladungsseite zeigt den falschen Host:** die Erkennungs-
Reihenfolge oben bedeutet, dass ein veraltetes `TUNNEL_PUBLIC_HOST` oder
`TLS_DOMAIN` gegenüber dem, was du manuell eingetragen hast, gewinnt. Prüfe,
welcher Modus wirklich aktiv ist (`ENABLE_TUNNEL`/`ENABLE_TLS` in
`deploy.conf`) und korrigiere entweder diesen Wert oder überschreibe den
Host direkt im Panel.

## Verweise

- **Familien-Onboarding-Flow:** [`FAMILY-ONBOARDING.de.md`](FAMILY-ONBOARDING.de.md)
- **Vollständige Config-Key-Referenz:** [`../CONFIGURATION-GUIDE.de.md`](../CONFIGURATION-GUIDE.de.md#loxprox-panel-gui) → "LoxProx Panel (GUI)"
