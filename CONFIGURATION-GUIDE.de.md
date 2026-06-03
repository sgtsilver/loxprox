**Sprache:** Deutsch · [English](CONFIGURATION-GUIDE.md)

# Konfigurations-Guide

Dieses Dokument erklärt jeden Wert, den LoxProx braucht. Seit v1.5.0 liegen diese Werte in `/etc/loxprox/deploy.conf` (nicht mehr am Anfang von `deploy.sh` wie in v1.4 und früher — siehe `docs/UPGRADE-to-v1.5.de.md`, falls du migrierst).

---

## TL;DR: Setup in drei Schritten (v1.5.0+)

```bash
# Schritt 1: Loxone automatisch finden
./detect-loxone.sh

# Schritt 2: Per-Host-Config aus dem Template anlegen
sudo install -d -m 0750 /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf       # die [REQUIRED]-Werte eintragen

# Schritt 3: Deploy starten
sudo bash deploy.sh
```

`deploy.sh` sourcet `/etc/loxprox/deploy.conf` beim Start. Wenn die Datei fehlt **und** keine bestehende Installation erkannt wird, weigert sich das Script zu laufen — damit du nicht versehentlich mit den Platzhalterwerten aus dem Example deployst.

**Upgrade von v1.3.x?** Einmalig `sudo bash deploy.sh --bootstrap-config` laufen lassen. Das Script liest deine aktiven Werte aus dem laufenden nftables- / nginx- / CrowdSec-Zustand zurück und schreibt sie in `/etc/loxprox/deploy.conf`. Komplette Anleitung: [`docs/UPGRADE-to-v1.5.de.md`](docs/UPGRADE-to-v1.5.de.md).

---

## Erforderliche Werte (6 Einstellungen)

Diese **müssen** angepasst werden, sonst funktioniert das Deployment in deinem Netz nicht.

### `LOXONE_IP` — die LAN-IP deines Miniservers

**Was es ist:** Die interne IP-Adresse des Loxone Miniservers in deinem Heimnetz.

**Wie du sie findest:**
- **Am einfachsten:** `./detect-loxone.sh` auf der Gateway-VM laufen lassen. Scannt das Netz und meldet IP, MAC, Firmware-Version und Generation.
- **Router:** In den Router einloggen und in der DHCP-Lease-Tabelle nach einem Gerät namens "Loxone" oder einer MAC-Adresse suchen, die mit `EE:E0:00` beginnt.
- **Manuell:** Von einem beliebigen Gerät im gleichen LAN: `curl http://CANDIDATE_IP/jdev/cfg/mac`. Wenn du eine JSON-Antwort mit `"control": "dev/cfg/mac"` bekommst, ist das dein Loxone.

**Beispiel:**
```bash
LOXONE_IP="192.168.1.100"
```

**Häufiger Fehler:** Die externe/öffentliche IP oder die WAN-IP des Routers eintragen. Es muss die **interne** LAN-IP sein.

---

### `LOXONE_PORT` — HTTP-Port des Miniservers

**Was es ist:** Der TCP-Port, auf dem der Miniserver innerhalb deines LANs lauscht.

**Default:** `80`

**Wann ändern:** Nur, wenn du den Miniserver manuell auf einen anderen Port umkonfiguriert hast. Gen-1-Geräte laufen ohne Modifikation immer auf Port 80. Gen-2-Geräte leiten 80 → 443 weiter, der interne Port bleibt aber 80 — und genau den proxyt das Gateway.

**Wie du es prüfst:**
```bash
curl -I http://$LOXONE_IP:$LOXONE_PORT/
# Sollte HTTP/1.1 200 OK zurückgeben
```

---

### `GATEWAY_IP` — die statische IP dieser VM

**Was es ist:** Die IP-Adresse der VM, auf der dieses Gateway-Script läuft.

> **Hinweis:** LoxProx ist ein **VM-only** Deployment. `deploy.sh` bricht in einem LXC standardmäßig ab, weil sich mehrere Verteidigungen (Kernel-Sysctls, Fragnesia-Mitigation, auditd, AppArmor-Enforcement, nftables) aus einem Container heraus nicht anwenden lassen und stillschweigend zum No-Op werden würden. Die volle Begründung steht im README-Abschnitt *Hardware-Anforderungen*, oder du umgehst es auf eigene Verantwortung mit `ALLOW_LXC=1`.

**Warum es wichtig ist:** Der Router leitet den externen Port 1080 auf diese IP weiter. Ändert sich diese IP (DHCP), bricht das Port-Forwarding und dein Loxone ist aus dem Internet nicht mehr erreichbar.

**Wie du sie setzt:**
1. Wähle eine IP in deinem LAN-Subnetz, die **außerhalb** des DHCP-Bereichs des Routers liegt.
   - Beispiel: Wenn dein Router 192.168.1.100–192.168.1.200 vergibt, nimm 192.168.1.50.
2. Führe `./set-static-ip.sh` vor `deploy.sh` aus, oder konfiguriere die statische IP manuell in `/etc/network/interfaces` bzw. über eine DHCP-Reservierung im Router.

**Beispiel:**
```bash
GATEWAY_IP="192.168.1.50"
```

**Wie du es nach dem Deploy prüfst:**
```bash
ip addr show | grep "inet "
```

---

### `LAN_SUBNET` — der Bereich deines Heimnetzes

**Was es ist:** Die CIDR-Notation deines gesamten LANs. Wird für die CrowdSec-Whitelist und die SSH-Restriktionen verwendet.

**Wie du es findest:**
```bash
ip route | grep default
# Schau dir den Interface-Namen an (z. B. eth0), dann:
ip -o -f inet addr show eth0
# Output: 192.168.1.50/24 → dein Subnetz ist 192.168.1.0/24
```

**Häufige Home-Subnetze:**
- `192.168.1.0/24` (am häufigsten)
- `192.168.0.0/24` (TP-Link-, D-Link-Defaults)
- `10.0.0.0/24` (manche Router)

**Beispiel:**
```bash
LAN_SUBNET="192.168.1.0/24"
```

---

### `SSH_ALLOWED_SUBNETS` — wer per SSH auf das Gateway darf

**Was es ist:** Eine Liste von IP-Netzen, die per SSH auf dieses Gateway zugreifen dürfen. Alles andere wird von nftables gedroppt.

**⚠️ KRITISCH:** Hier **nicht** `0.0.0.0/0` eintragen. Das öffnet SSH für das gesamte Internet.

**Was rein gehört:**
- Dein Heim-LAN: `"192.168.1.0/24"`
- Ein Site-to-Site-VPN: `"192.168.100.0/24"`
- Eine konkrete Jump-Box: `"203.0.113.45"`
- Ein OpenVPN/WireGuard-Subnetz: `"10.8.0.0/24"`

**Beispiel:**
```bash
SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "192.168.100.0/24")
```

**Wie du es nach dem Deploy testest:**
```bash
# Von einer Maschine innerhalb eines erlaubten Subnetzes:
ssh loxone@$GATEWAY_IP

# Aus dem Internet (sollte timeouten oder hängen):
ssh loxone@$GATEWAY_IP
```

---

## SSH Key Bootstrap — was `deploy.sh` beim ersten Lauf macht

`deploy.sh` härtet den SSH-Daemon (CIS Debian 12 §5.2: `PermitRootLogin no`, `PasswordAuthentication no`, nur Key-Login). Auf einer frischen Box ohne `authorized_keys` würde dich das normalerweise **aussperren** — das klassische Erst-Deploy-Henne-Ei-Problem. Das Deploy-Script kümmert sich darum.

### Bedrohungsmodell — warum das selbst bei LAN-only-SSH zählt

nftables auf dem Gateway droppt `:22` ohnehin für alles außerhalb von `SSH_ALLOWED_SUBNETS`, das öffentliche Internet sieht den SSH-Port also nie. **Die Härtung schützt gegen einen kompromittierten Host innerhalb deines LANs** (dein Laptop, ein Smart-TV, ein IoT-Toaster), der versucht, das Gateway von innen per Brute Force zu übernehmen. Stock-Debian liefert `PasswordAuthentication yes` aus — dieses Fenster bleibt offen, bis die Härtung greift.

> **Anderes Modell als eine öffentliche Hetzner-/AWS-Box.** Manche Self-Hosting-Projekte (z. B. `endlessh`-SSH-Tarpit-Setups) müssen Internet-skalierten SSH-Lärm auf Port 22 abfangen. LoxProx muss das nicht — Port 22 ist hier LAN-seitig, also ist ein gehärteter sshd das richtige Primitiv und kein Tarpit.

### Was bei `sudo ./deploy.sh` passiert

1. Das Script prüft `/root/.ssh/authorized_keys` und jedes `/home/<user>/.ssh/authorized_keys` mit UID ≥ 1000.

2. **Wenn mindestens ein Key vorhanden ist** — wendet sofort das HARD-Profil an:
   ```
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   MaxAuthTries 4
   LogLevel VERBOSE
   ClientAliveInterval 300
   ```
   Aus einem **zweiten Terminal** verifizieren, bevor du dich ausloggst.

3. **Wenn keine Keys vorhanden sind und der Deploy interaktiv läuft (tty)** — pausiert das Script und zeigt ein Menü mit 4 Optionen:

   ```
   ⚠  No SSH authorized_keys found on this gateway.
       Disabling password auth NOW would lock you out of SSH.

       [P] Paste your public key (recommended — we'll wait)
       [H] Show help — how to create a key on your workstation
       [K] Keep password auth for now (insecure; loud login banner until fixed)
       [A] Abort deploy entirely
   ```

   - **`[P]`** — den kompletten Public Key `ssh-ed25519 AAAA… you@host` in einer Zeile einfügen. Das Script validiert ihn (Prefix + `ssh-keygen -l -f`-Round-Trip), spiegelt ihn mit Fingerprint zurück, fragt ein finales `y` zur Bestätigung ab und installiert ihn dann unter `/root/.ssh/authorized_keys` (Mode 0600). Danach wird das HARD-Profil angewendet.
   - **`[H]`** — zeigt die exakten Befehle, die du auf deiner Workstation ausführen musst:
     ```
     macOS / Linux:    ssh-keygen -t ed25519 -C "you@workstation"
     Windows 10/11:    ssh-keygen -t ed25519 -C "you@workstation"   (PowerShell oder Git Bash)
     Public ausgeben:  cat ~/.ssh/id_ed25519.pub
     ```
     Plus Google-Suchbegriffe. Anschließend ohne Positionsverlust auf `[P]` umschalten.
   - **`[K]`** — wendet ein SOFT-Profil an (`PasswordAuthentication yes`, aber `MaxAuthTries 4` + `LogLevel VERBOSE` + Key-Pref bleiben gesetzt) und installiert `/etc/update-motd.d/99-loxprox-ssh-warn` — ein rotes Banner, das bei jedem Login feuert, bis du finalisierst.
   - **`[A]`** — bricht den Deploy ohne SSH-Änderungen ab.

4. **Wenn keine Keys vorhanden sind und der Deploy nicht-interaktiv läuft** (Ansible, CI, piped stdin) — fällt automatisch auf SOFT-Profil + MOTD-Banner zurück. Die Box bleibt erreichbar.

### Finalisieren nach `ssh-copy-id`

Wenn du `[K]` gewählt oder einen unattended Deploy gefahren hast, läuft die Box jetzt im SOFT-Mode (Password-Auth noch an, Banner nervt). Um auf das HARD-Profil umzuschalten:

```bash
# 1. Auf deiner Workstation — den Key installieren:
ssh-copy-id root@<gateway-ip>

# 2. Auf dem Gateway — nur den SSH-Härtungs-Schritt erneut laufen lassen:
sudo bash deploy.sh --finalize-ssh
```

`--finalize-ssh` ist idempotent und führt nur `setup_ssh_hardening()` aus. Es prüft `authorized_keys` erneut, tauscht den Drop-in, entfernt `/var/lib/loxprox/ssh-keys-missing` und das MOTD-Banner und lädt `sshd` neu. Vor dem Logout aus einem zweiten Terminal verifizieren.

### Hinweise

- Private Keys werden **niemals** auf dem Gateway erzeugt. Der Paste-Flow akzeptiert ausschließlich einen Public Key, der bereits auf deiner Workstation existiert. (Server-seitig private Keys generieren ist das Appliance-shipped-with-default-key-Antipattern — hier explizit nicht.)
- Beide Modi nutzen denselben Drop-in-Pfad (`/etc/ssh/sshd_config.d/99-loxprox.conf`).
- Das Stock-`/etc/ssh/sshd_config` wird nicht angefasst; alles, was LoxProx schreibt, lebt im Drop-in-Verzeichnis.

---

## Optionale Werte (bei Bedarf anpassen)

### Rate Limiting

Schutz gegen Brute Force und DDoS. Die Defaults sind auf ein Loxone-Home-Automation-Setup abgestimmt.

| Einstellung | Default | Was sie tut |
|-------------|---------|-------------|
| `RATE_LIMIT_REQ_PER_SEC` | 10 | Jede IP darf dauerhaft 10 Requests pro Sekunde absetzen |
| `RATE_LIMIT_BURST` | 100 | Jede IP darf kurzzeitig bis zu 100 Requests bursten (verhindert 503er beim Laden der Loxone-UI-Assets) |
| `RATE_LIMIT_CONN_PER_IP` | 20 | Jede IP darf maximal 20 gleichzeitige Verbindungen halten |

**Wann ändern:**
- Wenn legitime Nutzer HTTP 503 sehen → Burst auf 150 erhöhen
- Wenn du aktiv angegriffen wirst → req/sec auf 5 senken
- Wenn viele Nutzer hinter einer NAT-IP sitzen (z. B. Office) → Connection-Limit erhöhen

### Proxy-Timeouts

Diese verhindern Slowloris-Angriffe (Angreifer öffnen Connections und senden die Daten extrem langsam, um Server-Ressourcen zu erschöpfen).

| Einstellung | Default | Was sie tut |
|-------------|---------|-------------|
| `PROXY_CONNECT_TIMEOUT` | 10s | Max. Zeit zum Verbindungsaufbau zum Loxone |
| `PROXY_SEND_TIMEOUT` | 15s | Max. Zeit zum Senden des Requests an den Loxone |
| `PROXY_READ_TIMEOUT` | 15s | Max. Zeit für die Antwort vom Loxone |
| `CLIENT_BODY_TIMEOUT` | 10s | Max. Zeit, die der Client zum Senden des Request-Body hat |
| `CLIENT_HEADER_TIMEOUT` | 10s | Max. Zeit, die der Client zum Senden der Header hat |

**Wann ändern:** Selten. Nur erhöhen, wenn Nutzer auf sehr langsamen Mobilverbindungen in Timeouts laufen. Niemals über 30 s.

### CrowdSec AppSec WAF

| Einstellung | Default | Was sie tut |
|-------------|---------|-------------|
| `ENABLE_APPSEC` | true | Prüft jeden HTTP-Request auf CVE-Exploit-Muster |
| `APPSEC_MODE` | enforce | Blockiert getroffene Requests (in der ersten Woche "monitor" verwenden) |

**Empfehlung fürs Erst-Setup:**
```bash
# Woche 1: Monitor-Modus
APPSEC_MODE="monitor"
# Danach: auf False Positives prüfen
cscli alerts list | grep appsec
# Woche 2: auf Enforce umstellen
APPSEC_MODE="enforce"
sudo ./deploy.sh
```

### CrowdSec Whitelist

Diese IPs/Netze werden von CrowdSec **niemals** gebannt, selbst wenn sie Attack-Signaturen auslösen.

**Muss enthalten:**
- Dein LAN-Subnetz (`192.168.1.0/24`)
- VPN-/Tunnel-Subnetze
- **Jedes weitere Trusted-Subnetz/VLAN**, aus dem ein vertrauenswürdiges Gerät das Gateway erreichen könnte (z. B. ein zweites WLAN-VLAN, das via Inter-VLAN-Routing ans Gateway geroutet wird). Steht es nicht in der Liste, kann ein Gerät darin gebannt werden, obwohl es intern ist.

**Bewusst ausschließen:** Gast- und IoT-Segmente — lass sie untrusted, damit sie den vollen Security-Stack durchlaufen wie jeder Remote-Client.

> **Roaming-Mobile-Clients lassen sich hier nicht whitelisten.** Geräte im Mobilfunknetz, hinter iCloud Private Relay oder Cloudflare WARP nutzen rotierende IPs — es gibt keine stabile Adresse zum Eintragen. Wie diese Fälle (reaktiv) behandelt werden, steht in SECURITY.de.md → "Legitimer Nutzer geblockt".

**Sollte enthalten:**
- Uptime-Monitoring-Dienste (z. B. UptimeRobot, Pingdom)
- Cloud-Dienste, die die Loxone-API legitim pollen
- Deine eigene externe IP, wenn du remote zugreifst

**Beispiel:**
```bash
CROWDSEC_WHITELIST_IPS=(
    "192.168.1.0/24"      # Heim-LAN
    "192.168.100.0/24"      # Site-to-Site-VPN zum anderen Standort
    "203.0.113.45"        # Uptime-Monitoring-Service
    "198.51.100.22"       # Notification-Gateway
)
```

### Discord Alerting

**Was es ist:** Echtzeit-Security-Alerts in einen Discord-Channel.

**Wie du eine Webhook-URL bekommst:**
1. Discord öffnen
2. Auf deinem Server → Server-Einstellungen → Integrationen → Webhooks
3. "Neuer Webhook" klicken
4. Channel wählen
5. "Webhook-URL kopieren" klicken
6. In `DISCORD_WEBHOOK_URL` einfügen

**Beispiel:**
```bash
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz"
```

**Zum Deaktivieren:** Leeren String setzen: `DISCORD_WEBHOOK_URL=""`

### Email Alerting

**Was es ist:** Schickt eine E-Mail, wenn das nginx-Error-Log zu schnell wächst.

**Voraussetzung:** Das Paket `mailutils` muss installiert sein.

**Zum Deaktivieren:** Leeren String setzen: `ALERT_EMAIL=""`

### Auto-Reboot-Uhrzeit

**Was es ist:** Wenn `unattended-upgrades` ein Kernel-Security-Update installiert, bootet das System zu dieser Uhrzeit neu, um den neuen Kernel zu laden.

**Wähle eine Uhrzeit**, zu der niemand den Loxone benutzt (z. B. 3 Uhr nachts).

**Auto-Reboot ganz deaktivieren:** Wird über die `unattended-upgrades`-Config geregelt. Nach dem Deploy `/etc/apt/apt.conf.d/50unattended-upgrades` editieren.

---

## Optionales TLS (HTTPS auf :1080) — was `deploy.sh` macht, wenn du es einschaltest

LoxProx v1.5.0 fügt optionale HTTPS-Terminierung am Gateway via `acme.sh` + HTTP-01 hinzu. Standardmäßig aus — das Gateway spricht weiterhin Plain-HTTP auf `:1080`, bis du `ENABLE_TLS="true"` in `/etc/loxprox/deploy.conf` setzt und den Deploy erneut startest. Das Zurückschalten ist genauso sauber (Cert-Dateien bleiben erhalten, damit ein erneutes Einschalten schnell geht).

Das vollständige Operator-Runbook steht in [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md). Dieser Abschnitt ist die Kurzfassung: welche Keys zu setzen sind, was die Voraussetzungen sind und wie die Re-Entry-Flags funktionieren.

### Bedrohungsmodell — warum opt-in und nicht Default

Das Gateway schirmt den TLS-losen Miniserver dahinter ohnehin ab; für viele Home-Deployments ist Plain-HTTP auf `:1080` über einen Router-Port-Forward das etablierte Setup und funktioniert einwandfrei. TLS einschalten erweitert die öffentliche Angriffsfläche um einen zusätzlichen Listener (`:80`, eingeschränkt auf `/.well-known/acme-challenge/` plus 301-Redirect) und führt eine ACME-Renewal-Abhängigkeit ein. Lohnt sich für alle, die HTTPS in der URL-Leiste der Loxone-Web-UI wollen; nicht zwingend.

### Voraussetzungen — einmalig, bevor du `ENABLE_TLS=true` setzt

1. **Öffentliches DNS** — `TLS_DOMAIN` muss **vor** dem Deploy öffentlich auf die WAN-IP deines Routers auflösen. Der ACME-Server validiert das, indem er sich auf `http://<TLS_DOMAIN>/.well-known/acme-challenge/<token>` verbindet. Ein Dynamic-DNS-Hostname (`selfhost.eu`, `ddnss.de`, Cloudflare etc.) oder ein statischer A-Record beim Registrar funktionieren beide.
2. **Router-Forward `WAN:80 → Gateway:80`** — zusätzlich zum bestehenden `WAN:1080 → Gateway:1080`. Wird **ausschließlich** für die ACME-Validierung benutzt; der `:80`-Listener am Gateway beantwortet exakt `/.well-known/acme-challenge/*` und 301t alles andere auf `https://<TLS_DOMAIN>:1080$request_uri`.

### Config-Keys (alle optional, Defaults sind sinnvoll)

| Key | Default | Zweck |
|-----|---------|-------|
| `ENABLE_TLS` | `"false"` | Master-Toggle. Auf `"true"` setzen, um TLS zu aktivieren. |
| `TLS_DOMAIN` | `""` | Vollqualifizierter öffentlicher Hostname (z. B. `loxprox.example.com`). Bei `ENABLE_TLS=true` Pflicht; wird mit klarer Fehlermeldung verweigert, wenn er fehlt oder kein FQDN ist. |
| `TLS_EMAIL` | `""` | Wird beim ACME-Provider registriert. |
| `TLS_ACME_SERVER` | `"letsencrypt"` | Akzeptiert auch `letsencrypt_test` (Staging — zum Debuggen zuerst verwenden), `zerossl`, `buypass`, `buypass_test`, `sslcom` oder eine vollständige Directory-URL. |
| `TLS_ACME_EXTRA` | `""` | Passthrough an `acme.sh --issue` (z. B. `--keylength ec-256`). |

**Beispiel:**

```bash
ENABLE_TLS="true"
TLS_DOMAIN="loxprox.example.com"
TLS_EMAIL="you@example.com"
TLS_ACME_SERVER="letsencrypt"
TLS_ACME_EXTRA=""
```

### Was bei `sudo bash deploy.sh` mit `ENABLE_TLS=true` passiert

1. `acme.sh` wird aus einem SHA256-gepinnten GitHub-Release-Tarball installiert — kein `curl | bash`.
2. Eine kleine `/etc/nginx/conf.d/loxprox-acme.conf` wird geschrieben: `:80` `default_server`, der nur `/.well-known/acme-challenge/` aus `/var/www/acme/` ausliefert und alles andere mit 301 auf `https://$host:1080$request_uri` weiterleitet.
3. Das Cert wird via `acme.sh --issue --webroot --server $TLS_ACME_SERVER` ausgestellt (oder erneuert). "Cert still valid, skipped" wird als Erfolg gewertet.
4. Das Cert wird unter `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (Mode `0640 root`) installiert, mit `--reloadcmd "systemctl reload nginx"` für den Renewal-Cron hinterlegt.
5. Die bestehende Site-Datei wird zwischen expliziten Markern (`# LOXPROX-TLS-BEGIN` / `# LOXPROX-TLS-END`) mutiert, und `listen 1080;` wird zu `listen 1080 ssl;`. Operator-Handedits außerhalb des Marker-Blocks (WebSocket-Location, Custom Header) bleiben unberührt. Die strikte Regex auf der Listen-Zeile akzeptiert ausschließlich das kanonische `listen 1080;` — keine stille Mutation.
6. Der Auto-Renewal-Cron wird nach jedem TLS-aktivierten Deploy **verifiziert** (nicht vorausgesetzt). Fehlt er? Wird via `acme.sh --install-cronjob` wiederhergestellt, und die exakte Cron-Zeile plus Anleitung zum manuellen Renewal wird geloggt.

> ⚠️ **TLS einzuschalten migriert bestehende Clients nicht automatisch.** Sobald `:1080` nur noch HTTPS spricht, läuft jede Loxone-App / jeder Browser, der noch als `http://<host>:1080` konfiguriert ist, in eine `301`-Redirect-Schleife, bis du ihn auf `https://` umstellst. Plane ein, **jede** gespeicherte Verbindung (jedes Handy, Tablet, jeden Browser) anzupassen, wenn du `ENABLE_TLS=true` setzt. Siehe Troubleshooting → "Die Loxone-App verbindet sich nach dem Aktivieren von TLS nicht mehr".

### Verhalten beim Ausschalten (`ENABLE_TLS="false"`)

`ENABLE_TLS="false"` setzen und `sudo bash deploy.sh` erneut laufen lassen. Das Script:

- Entfernt den Marker-Block aus der Site-Datei.
- Setzt die Listen-Zeile zurück auf Plain `listen 1080;`.
- Entfernt den `:80`-ACME-Listener.
- Storniert das Per-Domain-Renewal in `acme.sh`.
- **Behält** die Cert-Dateien unter `/etc/loxprox/tls/`, damit ein späteres Wieder-Einschalten keine erneute Issuance-Zeit kostet.

### Re-Entry-Flags

```bash
# Sofort-Renewal erzwingen (acme.sh --renew … --force):
sudo bash deploy.sh --renew-tls

# Komplett-Abriss — Site-Revert, conf.d-Listener entfernt, acme.sh deinstalliert,
# /etc/loxprox/tls/ gelöscht, Cron storniert. Verbleibende Operator-Aktion:
# den WAN:80 → Gateway:80 Router-Forward entfernen.
sudo bash deploy.sh --remove-tls
```

### Verweise

- **Komplettes TLS-Runbook:** [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md)
- **Upgrade-Anleitung (v1.3.x → v1.5):** [`docs/UPGRADE-to-v1.5.de.md`](docs/UPGRADE-to-v1.5.de.md)

---

## Troubleshooting

### "Ich kenne die IP meines Loxone nicht"

```bash
./detect-loxone.sh
```

Falls das nichts findet:
1. Im Admin-Panel des Routers nachsehen → DHCP-Leases oder verbundene Geräte
2. Nach einem Gerät namens "Loxone" oder mit MAC-Prefix `EE:E0:00` suchen
3. Letzte bekannte IP anpingen: `ping 192.168.1.100`

### "Ich kenne mein LAN-Subnetz nicht"

```bash
ip route | grep default
ip -o -f inet addr show
```

Der Output zeigt etwas wie `192.168.1.50/24`. Dein Subnetz ist `192.168.1.0/24`.

### "Ich kenne mein SSH-Subnetz nicht"

Nimm dasselbe wie `LAN_SUBNET`. Wenn du zusätzlich ein VPN oder einen zweiten Standort hast, ergänze den noch.

### "Ich bekomme nftables-Fehler während des Deploys"

Stell sicher, dass du als root läufst:
```bash
sudo ./deploy.sh
```

### "Das Gateway erreicht den Loxone nicht"

```bash
# Von der Gateway-VM aus:
curl -v http://$LOXONE_IP:$LOXONE_PORT/jdev/cfg/api

# Wenn das fehlschlägt, prüfe:
# 1. Ist der Loxone an?
# 2. Ist das Gateway im selben Subnetz wie der Loxone?
# 3. Blockt eine Proxmox-Firewall den Traffic zwischen VMs?
```

### "Die Loxone-App verbindet sich nach dem Aktivieren von TLS nicht mehr" (301-Redirect-Schleife)

Nachdem du `ENABLE_TLS=true` gesetzt hast, spricht `:1080` nur noch HTTPS. Ein Client, der weiterhin als `http://<host>:1080` konfiguriert ist, schickt Cleartext an den TLS-Port; nginx beantwortet jeden Request mit einem `301` nach `https://…`, und die Loxone-App (die bei ihren API-Calls keinen Redirects folgt) wiederholt das in einer Schleife. Symptom in `loxone-access.log`: derselbe Client trifft `GET /jdev/cfg/api?cacheBstr=…` immer wieder mit Status `301`.

Das ist kein Ban — `cscli decisions list` zeigt nichts für die IP. Der Fix ist client-seitig und gilt für jede App / jeden Browser, der sich verbindet:

1. In der Loxone-App die Miniserver-Verbindung bearbeiten (oder löschen und neu anlegen).
2. Die Adresse auf `https://<your-host>:1080` setzen — verifiziere, dass das Schema `https` ist und der Port `:1080` weiterhin vorhanden ist (die App speichert Schema und Port getrennt).

---

## Konfigurations-Checkliste

Bevor du `deploy.sh` startest, verifiziere:

- [ ] `LOXONE_IP` ist korrekt (mit `curl http://$LOXONE_IP/jdev/cfg/mac` testen)
- [ ] `GATEWAY_IP` ist statisch (kein DHCP)
- [ ] `LAN_SUBNET` passt zu deinem Netz
- [ ] `SSH_ALLOWED_SUBNETS` enthält dein aktuelles Netz
- [ ] Router-Port-Forwarding: extern 1080 → `GATEWAY_IP`:1080
- [ ] Discord-Webhook ist gesetzt (oder bewusst leer gelassen)
