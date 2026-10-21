**Sprache:** Deutsch · [English](CONFIGURATION-GUIDE.md)

# Konfigurations-Guide

Dieses Dokument erklärt jeden Wert, den LoxProx braucht. Seit v1.5.0 liegen diese Werte in `/etc/loxprox/deploy.conf` (nicht mehr am Anfang von `deploy.sh` wie in v1.3.x und früher — siehe `docs/UPGRADE-to-v1.5.de.md`, falls du migrierst).

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

## Erforderliche Werte (5 Einstellungen)

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
# 1. Auf deiner Workstation — den Key für deinen sudo-User installieren
#    (Root-Login wird im HARD-Modus abgeschaltet, sobald ein Nicht-Root-User einen Key hat):
ssh-copy-id <dein-user>@<gateway-ip>

# 2. Auf dem Gateway — nur den SSH-Härtungs-Schritt erneut laufen lassen:
sudo bash deploy.sh --finalize-ssh
```

`--finalize-ssh` ist idempotent und führt nur `setup_ssh_hardening()` aus. Es prüft `authorized_keys` erneut, tauscht den Drop-in, entfernt `/var/lib/loxprox/ssh-keys-missing` und das MOTD-Banner und lädt `sshd` neu. Vor dem Logout aus einem zweiten Terminal verifizieren.

### Hinweise

- Private Keys werden **niemals** auf dem Gateway erzeugt. Der Paste-Flow akzeptiert ausschließlich einen Public Key, der bereits auf deiner Workstation existiert. (Server-seitig private Keys generieren ist das Appliance-shipped-with-default-key-Antipattern — hier explizit nicht.)
- Beide Modi nutzen denselben Drop-in-Pfad (`/etc/ssh/sshd_config.d/99-loxprox.conf`).
- Das Stock-`/etc/ssh/sshd_config` wird nicht angefasst; alles, was LoxProx schreibt, lebt im Drop-in-Verzeichnis.

---

## `deploy.sh` erneut laufen lassen — nginx-Site-Regenerierung & Exit-Codes

Jeder Lauf prüft seit v2.3, ob `/etc/nginx/sites-available/loxone` noch zum
Template passt, aus dem sie erzeugt wurde (ein Versions-Stempel plus ein
Fingerprint der gerenderten `deploy.conf`-Werte), und regeneriert sie, wenn
eines von beidem abweicht — inklusive Template-Fixes und jedem geänderten
Rate Limit, Timeout oder Backend-IP. Die alte Datei wird zuerst gesichert,
der TLS-Block wieder angewendet, falls die Site HTTPS bediente, und ein
fehlgeschlagenes `nginx -t` stellt automatisch das Backup wieder her. Zwei
Umgebungs-Schalter ändern dieses Verhalten:

| Schalter | Effekt |
|---|---|
| `LOXPROX_KEEP_NGINX_SITE=1` | Eine bestehende Site nie anfassen — für eine handgepflegte Datei. Template-Fixes und `deploy.conf`-Änderungen (Rate Limits, Backend-IP, AppSec-Wiring) erreichen sie dann **nicht**, solange der Schalter gesetzt ist. |
| `LOXPROX_FORCE_REGEN_NGINX=1` | Die Site regenerieren, selbst wenn ihr Stempel schon aktuell ist. |

```bash
sudo LOXPROX_FORCE_REGEN_NGINX=1 bash deploy.sh
```

Der Exit-Code von `deploy.sh` sagt Automation (und dir) genau, was passiert
ist:

| Code | Bedeutung |
|---|---|
| `0` | Deploy fertig, alle Checks bestanden. |
| `1` | Ein Health-Check ist fehlgeschlagen, oder ein Kern-Schritt hat den Lauf abgebrochen. |
| `2` | Unbekannte Kommandozeilen-Option. |
| `3` | Deployed, aber ein oder mehrere **optionale** Schritte (TLS, Tunnel, CrowdSec …) sind fehlgeschlagen — am Ende des Laufs aufgelistet. Das Gateway proxied; diese Features sind nur nicht aktiv. Nach Behebung der Ursache erneut laufen lassen. |

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
| `APPSEC_MODE` | enforce | `enforce` blockiert getroffene Requests mit HTTP 403; `monitor` alarmiert bei einem Treffer, blockiert aber nie (in der ersten Woche verwenden) |

Der Wechsel auf `monitor` schreibt eine lokale AppSec-Config
(`/etc/crowdsec/appsec-configs/loxprox-virtual-patching-monitor.yaml`) mit
den Virtual-Patching-Regeln aus dem Hub und `default_remediation: allow`;
der Wechsel zurück auf `enforce` entfernt sie wieder. Treffer im
Monitor-Modus erscheinen in `cscli alerts list`, **nicht** in
`/var/log/nginx/appsec-detections.log` — dort schreibt nginx nur bei einem
BLOCK-Urteil hinein, das der Monitor-Modus nie zurückgibt.

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

### Haushalte hinter einer IP (NAT/CGNAT)

Jedes Handy, Tablet, TV und Smart-Home-Gerät im Haus zeigt dem Gateway
**dieselbe öffentliche IP** (und hinter CGNAT gilt das auch für andere
Haushalte im selben Adress-Pool des ISPs). Rate Limits, CrowdSecs
Ban-Entscheidungen und die Progressive-Ban-Eskalation (unten) hängen alle an
dieser einen Adresse — ein einzelnes störendes Gerät kann ein Limit oder
einen Ban für die ganze Familie auslösen, nicht nur für sich selbst. Wenn du
den Tunnel nutzt, kommen die Limits des Relays aus demselben Grund oben
drauf.

**Primäre Gegenmaßnahme: die WAN-IP des Haushalts whitelisten.**
- Gateway: in `CROWDSEC_WHITELIST_IPS` oben eintragen — finden mit
  `curl -s https://ifconfig.me` von zu Hause aus.
- Relay (beim Tunnel-Setup): in `RELAY_WHITELIST_IPS` in
  `/etc/loxprox-relay/relay.conf` eintragen. Dessen Firewall-Bouncer wirft
  gebannte Quellen auf *jedem* Port raus, auch dem frp-Control-Port — ein
  nicht gewhitelisteter Ban dort kappt also auch SSH auf das Relay. Siehe
  [`docs/TUNNEL-SETUP.de.md`](docs/TUNNEL-SETUP.de.md).

Eine gewhitelistete Adresse ist von CrowdSec **und** von der
Progressive-Ban-Eskalation unten ausgenommen — das ist der dauerhafte Fix,
nicht nur das reaktive Entbannen.

### Progressive-Ban-Eskalation

Zwei Dinge bestimmen, wie lange eine Adresse gebannt bleibt: der erste Ban, den CrowdSec ausspricht (sein Remediation-Profil, das `deploy.sh` nach `/etc/crowdsec/profiles.yaml` schreibt), und `progressive-ban.py` (Cron, alle 15 Minuten, unter `flock`), das die Sperre eines Wiederholungstäters entlang einer **Leiter** verlängert. Es gibt zwei Leitern:

- **HARD** — für Scenarios, die eindeutig Scanner sind (die auf `BAN_HARD_SCENARIOS` passen): `168h 2160h 8760h` = 7 Tage, dann 90 Tage, dann 365 Tage.
- **SOFT** — für alles andere: `24h 168h 720h 2160h` = 24 Stunden, 7 Tage, 30 Tage, dann 90 Tage.

Ein "Verstoß" ist ein eigenständiger **Angriffs-Vorfall**, keine reine Alert-Zählung — nur lokale Scenario-/AppSec-Detections zählen (CAPI-/Community-List-Einträge, manuelle Bans, simulierte Alerts und die eigenen früheren Verlängerungen des Scripts zählen nie), und Alerts innerhalb von `PROGRESSIVE_BAN_DEDUP_MINUTES` zueinander zählen als **ein** Vorfall — unabhängig davon, welches Scenario sie ausgelöst hat. Ein Burst, der fünf verschiedene Regeln auf einmal triggert, ist ein Vorfall, kein sofortiger 90-Tage-Bann. Ein Vorfall ist HARD, wenn irgendein Alert darin auf `BAN_HARD_SCENARIOS` passt. Das Script verkürzt nie einen Ban und eskaliert keine Adressen aus der CrowdSec-Whitelist.

| Key | Default | Was er tut |
|---|---|---|
| `BAN_HARD_LADDER` | `168h 2160h 8760h` | Bandauer für den 1., 2. und 3.+ HARD-Verstoß (Einheiten `m`, `h` oder `d`). Der erste Wert ist das, was CrowdSec ausspricht; der letzte wiederholt sich. Verlängern für weniger Toleranz. |
| `BAN_SOFT_LADDER` | `24h 168h 720h 2160h` | Bandauer für den 1., 2., 3. und 4.+ SOFT-Verstoß. Die ersten Stufen kürzen (z. B. `4h 24h 168h`), wenn der Haushalt immer wieder mehrdeutige Scenarios auslöst. |
| `BAN_HARD_SCENARIOS` | ein regulärer Ausdruck (siehe `deploy.conf.example`) | Welche Scenario-Namen die HARD-Leiter nutzen: der Trap, Virtual-Patching-/CVE-Probes sowie Probing auf sensible Dateien, Backdoors, Path Traversal, Admin-Interfaces und Open Proxies. Ein Regex, der in CrowdSec (Go RE2) und Python funktionieren muss — keine Lookarounds, Anführungszeichen oder Backslashes; `deploy.sh` lehnt alles andere ab. Nur ändern, wenn du weißt, warum. |
| `PROGRESSIVE_BAN_WINDOW_DAYS` | `365` | Ältere Verstöße werden vergessen. CrowdSecs eigener Default (7-Tage-Alert-Flush) wird durch eine Alert-Historie von mindestens 400 Tagen ersetzt, damit das Fenster real ist. Niedriger setzen (z. B. `30`) für einen nachsichtigeren Haushalt. |
| `PROGRESSIVE_BAN_DEDUP_MINUTES` | `60` | Alerts innerhalb dieser Minutenzahl zueinander zählen als ein Vorfall, egal aus welchem Scenario. Höher setzen (z. B. `180`), wenn Bursts unabhängiger Detections noch zu schnell eskalieren. |
| `PROGRESSIVE_BAN_WHITELIST_FILE` | `/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml` | Gewhitelistete IPs (dieselbe Datei, in die `CROWDSEC_WHITELIST_IPS` schreibt) werden nie eskaliert. Nur überschreiben, wenn du eine separate Whitelist-Datei pflegst. |

Die ersten vier Keys gehören in `deploy.conf`; `deploy.sh` prüft sie (ein Tippfehler bricht den Deploy ab), schreibt die erste Stufe jeder Leiter ins CrowdSec-Profil und übernimmt alle in `/etc/loxprox/config.env`. `PROGRESSIVE_BAN_DEDUP_MINUTES` und `PROGRESSIVE_BAN_WHITELIST_FILE` verwaltet `deploy.sh` noch nicht: Von Hand in `/etc/loxprox/config.env` (oder der Umgebung) setzen; nicht gesetzte Werte fallen auf die Defaults oben zurück.

> **Harte Bans sind absichtlich lang.** Ein einjähriger Ban auf eine geteilte Mobilfunk- oder Private-Relay-Adresse kann Unschuldige treffen. Deshalb ist nur eindeutiges Scanner-Verhalten HARD. Wird eine legitime Adresse gebannt, die Decision löschen (`sudo cscli decisions delete --ip <IP>`) — das Verstoß-Gedächtnis bleibt, der nächste Verstoß eskaliert also weiter.

### Scanner-Abwehr & Edge-Filter (Breach-Härtung 2026-10)

Am 2026-10-18 wurde der Hersteller Loxone gehackt. Crawler wie Shodan und Censys fingerprinten Loxone-Endpoints, deshalb beantwortet das Gateway jetzt nur noch, was eine Loxone-App legitim sendet, und bannt alles andere für lange Zeit. Alle Keys unten sind optional und stehen in `/etc/loxprox/deploy.conf`; die Defaults sind die empfohlenen gehärteten Werte. `deploy.sh` prüft sie und bricht bei einem Tippfehler ab, statt stillschweigend ein anderes Verhalten zu wählen.

### Was sich für dich ändert

- **Hostname mit `https://` benutzen, nie die IP.** Mit `ENABLE_TLS=true` bedienen `:1080` und `:80` nur `TLS_DOMAIN` plus `EXTRA_SERVER_NAMES`. Eine Anfrage für die nackte IP, ohne SNI oder für einen fremden `Host` ist ein **Trap-Treffer**: Die Verbindung wird geschlossen (444, es wird nichts gesendet), nach `/var/log/nginx/loxprox-trap.log` geloggt, und die Adresse wird mit der HARD-Leiter gebannt. Jede App, jeder Browser und jede Monitoring-Probe muss den Hostnamen nutzen. (`http://<host>:1080` für den echten Namen bekommt weiter den 301 auf `https://`.)
- **Die einfachen Admin-Webservice-Pfade werden aus dem Internet mit `403` beantwortet** (`fsget`, `fsdel`, `sys/reboot`, `sps/restart`, ...). Siehe `REMOTE_ADMIN_PATHS` — das ist ein Pfadfilter, keine Sperre des Miniservers.
- **Scanner-Pfade sind Fallen.** `/.env`, `/.git`, `*.php`, `/wp-*`, `/cgi-bin/`, `/vendor/phpunit`, `/HNAP1`, `/boaform`, `/actuator` sowie die Methoden `CONNECT`, `TRACE`, `TRACK`, `PROPFIND` werden mit 444 und einem HARD-Ban beim ersten Treffer beantwortet. Kein Loxone-Endpoint passt auf einen davon.
- **Auth- und WebSocket-Limits.** Loxone-Authentifizierungs-Endpoints: 3 Anfragen pro Sekunde je nicht vertrauenswürdiger Adresse (Burst 30). `/ws/`: höchstens 6 gleichzeitige Verbindungen je nicht vertrauenswürdiger Adresse. `LAN_SUBNET` und `CROWDSEC_WHITELIST_IPS` werden nie limitiert, abgewiesen (Admin/unbekannt) oder mitgezählt.

### `EXTRA_SERVER_NAMES` — weitere Hostnamen fürs Gate

| Key | Default | Was er tut |
|---|---|---|
| `EXTRA_SERVER_NAMES` | `""` | Leerzeichengetrennte weitere Hostnamen, die `:1080` neben `TLS_DOMAIN` akzeptiert, z. B. `"home.example.net"`. Ohne TLS wirkungslos (Plain HTTP akzeptiert jeden Host). |

**Wann ändern:** Du erreichst dieselbe WAN-IP unter einem zweiten DNS-Namen. Diese Namen passieren nur das Host/SNI-Gate. Das Zertifikat wird weiter nur für `TLS_DOMAIN` ausgestellt, ein Client mit einem anderen Namen bekommt also einen Zertifikatsfehler, solange du das Zertifikat nicht auch für diesen Namen ausstellst (`TLS_ACME_EXTRA="-d home.example.net"`). Erlaubte Formen: Namen mit Punkt (`home.example.net`), `*.example.com`, `.example.com` (der Name und alle Subdomains) und `www.example.*`; alles andere bricht den Deploy ab. Bei aktivem Tunnel wird `TUNNEL_PUBLIC_HOST` automatisch akzeptiert.

### `UNKNOWN_PATH_MODE` und `REMOTE_ADMIN_PATHS`

| Key | Default | Was er tut |
|---|---|---|
| `UNKNOWN_PATH_MODE` | `log` | Was mit einem Pfad passiert, der weder Trap, Admin noch bekannter App-Endpoint ist. `log` = wie gewohnt durchgereicht **und** nach `/var/log/nginx/loxprox-unknown.log` geschrieben (die Lernphase; das Scenario `loxprox/unknown-path` alarmiert nur). `deny` = nicht vertrauenswürdige Quellen bekommen ein lokales 404 (weiter geloggt), und `loxprox/unknown-path` bannt (SOFT-Leiter). |
| `REMOTE_ADMIN_PATHS` | `deny` | `deny` = Loxone-Admin-/Dateisystem-Webservices antworten Internet-Clients mit `403` (geloggt; kein LoxProx-Scenario bannt deswegen, aber wiederholte 403/404 zählen weiter für das Standard-Scenario `crowdsecurity/http-probing`, das zu einem SOFT-Ban führen kann). `allow` = sie werden wie jeder App-Pfad durchgereicht. Gefiltert werden nur einfache HTTP-Pfade: Dieselben Befehle können den Miniserver weiter in der verschlüsselten Befehlsform (`jdev/sys/enc` / `fenc`, App-Klasse) oder über den authentifizierten WebSocket erreichen — die eigenen Zugangsdaten des Miniservers bleiben die eigentliche Kontrolle. |

**Wann ändern:**
- `UNKNOWN_PATH_MODE="log"` einige Wochen lassen und `loxprox-unknown.log` lesen. Erst auf `deny` umstellen, wenn dort kein Pfad steht, den die Apps deiner Familie wirklich benutzen.
- `REMOTE_ADMIN_PATHS="allow"` nur setzen, wenn du den Miniserver über das Gateway aus der Ferne konfigurierst (Loxone Config übers Internet). Besser aus dem LAN — das ist ohnehin ausgenommen.

### Monitor-Alerts, Updates und GeoIP-IPv6

| Key | Default | Was er tut |
|---|---|---|
| `SESSION_ALERT_ENABLED` | `true` | Discord-Alert, wenn ein Remote-Client eine Session auf dem Loxone-Port aus einem ASN (Providernetz) hält, den das Gateway noch nicht gesehen hat. Client-Adressen sind im Alert maskiert. Braucht `mmdb-bin` und die GeoLite2-Datenbanken, die CrowdSec mitbringt (`deploy.sh` installiert `mmdb-bin`). |
| `ASN_LEARNING_DAYS` | `7` | In den ersten so vielen Tagen nach dem ersten Monitor-Lauf werden ASNs nur still gelernt. Höher setzen, wenn die Familie viel reist oder oft den Anbieter wechselt. |
| `AUTH_RATE_ALERT_PER_CYCLE` | `20` | Alert, wenn in einem 60-Sekunden-Monitor-Zyklus mehr Loxone-Authentifizierungs-Anfragen (`getkey`, `getkey2`, `getjwt`, `gettoken`, `authwithtoken`, `refreshjwt`, in der `jdev/`- und der `dev/`-Schreibweise) als dieser Wert am Gateway ankommen, alle Clients zusammen. Normal sind eine Handvoll pro **Tag**, 20 in einer Minute sind also laut. Höher setzen, wenn ein großer Haushalt gleichzeitig einloggt. |
| `SEC_UPDATE_MAX_AGE_DAYS` | `2` | Alert ("Security Updates Not Installing"), wenn ein ausstehendes Debian-Security-Update nach so vielen Tagen nicht installiert ist — das Symptom, dass unattended-upgrades hängt. |
| `GEOIP_IPV6_ENABLED` | `true` | IPv6-Verkehr aus den gesperrten Ländern (CN, RU, KP, IR) ebenfalls mit dem Set `geoip_blocklist6` verwerfen. `"false"` leert das IPv6-Set beim nächsten GeoIP-Refresh (nur IPv4). `geoip-block.sh` liest den Wert selbst aus `config.env`. |
| `GEOIP_URL_BASE6` | `""` | Quelle der IPv6-Länderlisten. Leer = die IPv6-Listen von ipdeny.com. Muss eine `https://`-URL sein; nur ändern, um einen Mirror zu nutzen. |

Weitere Alerts, für die du keine Keys brauchst:
- **New CrowdSec Ban** (WARNING) betrifft nur SOFT-Bans, höchstens 15 Einträge pro Nachricht. HARD-Bans (Scanner) fasst ein INFO-**Daily HARD Ban Digest** um 08:00 zusammen, auch wenn die Anzahl 0 ist. Mit `TRAP_BAN_MODE="observe"` nennt er zusätzlich die Zahl beobachteter Trap-Treffer und erinnert daran, das Trap-Log zu prüfen.
- **Firewall Integrity Failure**: Input-Policy und Regeln werden in jedem Zyklus geprüft, der Inhalt der GeoIP-Sets stündlich.
- **CrowdSec Log Reading Stopped — Restarted** (WARNING): CrowdSec hatte aufgehört, ein Log zu lesen, die Log-basierte Erkennung (Trap, Unknown-Path, Auth und die HTTP-/CVE-Scenarios) war also blind; AppSec lief weiter. Entweder hat CrowdSec `file reader died` geloggt, oder das Access-, Trap- oder Unknown-Path-Log ist dreimal gewachsen, ohne dass CrowdSec etwas davon gelesen hat. Der Monitor startet crowdsec neu, höchstens einmal pro Stunde (AppSec beantwortet in den Sekunden des Neustarts jede Anfrage mit 500), und nennt Log und Zeitpunkt. Meist ist ein doppelt eingelesenes Log die Ursache; `sudo bash test-gateway.sh` meldet es, `sudo cscli metrics show acquisition` zeigt die gelesenen Zeilen je Log. Eine Wiederholung innerhalb der Stunde ist **CrowdSec Log Reading Still Stopped** (HIGH, ohne Neustart); **CrowdSec Down After a Log-Reading Restart** (CRITICAL) heißt, crowdsec ist nicht wieder hochgekommen: `sudo journalctl -u crowdsec -n 80 --no-pager`, dann `sudo systemctl restart crowdsec`.
- Der **tägliche Hub-Refresh** (04:30) sichert den CrowdSec-Hub als Snapshot, aktualisiert dann alle installierten Hub-Einträge (nie mit `--force`; die letzten 7 Snapshots liegen in `/var/lib/loxprox/hub-snapshots/`) und rollt zurück, wenn CrowdSec nicht wieder hochkommt. Ein erfolgreiches Upgrade meldet nichts; die geänderten Einträge stehen in `/var/log/loxprox-hub-refresh.log`. Geht CrowdSec dabei kaputt, bekommst du **CrowdSec Rule Update Rolled Back**, **CrowdSec Down — Gateway Serving Errors** oder **CrowdSec Rule Rollback Failed** (CRITICAL, mit den geänderten Einträgen). **CrowdSec Hub Snapshot Failed** (WARNING) heißt: Es lief kein Upgrade, weil nicht nachweisbar war, dass der Snapshot den Hub-Index und die Datei jedes installierten Eintrags enthält. **CrowdSec Hub Items Not Upgraded** (INFO) listet Einträge, die das Upgrade nicht angefasst hat: „tainted“ (lokal verändert) oder weiterhin update-available. Der Alert sagt auch, wie du sie auflöst, und kommt erst wieder, wenn sich diese Liste ändert. Den paketeigenen nächtlichen `crowdsec-hubupdate.timer` von CrowdSec (ein ungeschütztes Upgrade aller Hub-Einträge) maskiert `deploy.sh`; `systemctl is-enabled crowdsec-hubupdate.timer` gibt `masked` aus.

Leiterwerte mit der Einheit `d` werden für das CrowdSec-Profil in Stunden umgerechnet (CrowdSec kennt keine Tage-Einheit).

### `TRAP_BAN_MODE` — erst beobachten, dann bannen

| Key | Default | Was er tut |
|---|---|---|
| `TRAP_BAN_MODE` | `ban` | `ban` = ein Trap-Treffer bannt die Adresse (HARD-Leiter). `observe` = `loxprox/scanner-trap` läuft in der CrowdSec-Simulation: Der Trap antwortet weiter mit 444 und loggt nach `loxprox-trap.log`, CrowdSec erzeugt weiter den Alert, aber es wird kein Ban ausgesprochen. |

**Wann ändern:** für den ersten Rollout, um eigene Geräte zu finden, die noch die IP oder einen falschen Namen nutzen, bevor sie einen 7-Tage-Ban bekommen.

1. `TRAP_BAN_MODE="observe"` in `deploy.conf` setzen und deployen.
2. Nach einigen Tagen `sudo cscli alerts list -s loxprox/scanner-trap --limit 0` ausführen (cscli 1.8.1 zeigt standardmäßig nur 50) und `/var/log/nginx/loxprox-trap.log` lesen. Am aufschlussreichsten ist `/var/log/nginx/loxprox-trap-hosts.log`: Es enthält Host, SNI und User-Agent jedes Trap-Treffers (CrowdSec liest es nicht; es wird 90 Tage aufbewahrt). Jede eigene Adresse (Handys der Familie, Monitoring) dort ist ein Client, der korrigiert werden muss: mit `https://<dein-host>:1080` neu anlegen.
3. `TRAP_BAN_MODE="ban"` setzen und neu deployen. Oder sofort umschalten mit `sudo cscli simulation disable loxprox/scanner-trap && sudo systemctl reload crowdsec` — und `deploy.conf` ebenfalls ändern, sonst aktiviert der nächste Deploy den Observe-Modus wieder.

Im Observe-Modus werden Scanner geloggt, aber nicht gebannt.

`loxprox/auth-bf` und (bei `UNKNOWN_PATH_MODE="log"`) `loxprox/unknown-path` laufen immer in der Simulation. Kann `deploy.sh` eine Simulation nicht mit `cscli simulation status` bestätigen, entfernt es dieses Scenario, statt es bannen zu lassen, und meldet den CrowdSec-Schritt als degradiert; beheben mit `sudo cscli simulation enable <scenario>` und erneutem `sudo bash deploy.sh`.

### `TRAP_EXEMPT_IPS` — einen bekannten Prober vom Trap ausnehmen (nicht vertrauenswürdig)

| Key | Default | Was es tut |
|---|---|---|
| `TRAP_EXEMPT_IPS` | `()` | Bash-Array aus IPv4-/IPv6-Adressen oder CIDRs, z. B. `("203.0.113.10" "2001:db8:10::/48")`. Diese Quellen sind vom Trap und von jedem Ban ausgenommen, aber sie sind **nicht vertrauenswürdig**. |

**Wann nutzen:** Ein bekannter Dienst fragt die nackte IP des Gateways ab und darf nicht gebannt werden. Der typische Fall ist ein Cloud-Probe eines Herstellers, der einmal am Tag Klartext-HTTP an `:1080` schickt, mit der nackten IP als `Host`, ohne SNI und ohne User-Agent. Vor dem Host/SNI-Gate bekam er den 301-Redirect auf `https://`; seit dem Gate ist er ein Trap-Treffer und bekommt einen HARD-Ban.

Was eine ausgenommene Quelle bekommt:

- **Kein Trap-Log.** Ihre Anfragen landen nie in `loxprox-trap.log` oder `loxprox-trap-hosts.log`. Ins Access-Log schreiben die Trap-Server sie auch nicht, sie hinterlassen dort also gar keine Spur.
- **Kein Alert, kein Ban.** `deploy.sh` schreibt die CrowdSec-Whitelist `loxprox/trap-exempt` (`/etc/crowdsec/parsers/s02-enrich/whitelist-loxprox-trap-exempt.yaml`). Sie gilt für jedes lokale Scenario, nicht nur für den Trap. Wie `CROWDSEC_WHITELIST_IPS` hebt sie Community-Blocklist-Decisions (CAPI) nicht auf.
- **Den 301 für ihren Klartext-Probe** (TLS-Modus): Klartext-HTTP an `:1080` mit fremdem `Host` bekommt statt der 444 den Redirect des echten Servers auf `https://<TLS_DOMAIN>:1080<Pfad>`. Alles andere auf den Trap-Servern bleibt eine 444: TLS mit fremdem oder fehlendem SNI, `:80` mit fremdem `Host`, `TRACE`/`CONNECT`, Scanner-Pfade.
- **Sonst ändert sich nichts.** Die Rate-Limits und die Auth-/WebSocket-Limits gelten. Die Admin-Pfade antworten mit `403` und `UNKNOWN_PATH_MODE="deny"` mit `404`, genau wie für jeden Internet-Client.

Das unterscheidet den Key von `CROWDSEC_WHITELIST_IPS`, das *vertrauenswürdig* macht: keine Limits, keine Admin-/Unknown-Sperren. Ein Eintrag, der vertrauenswürdig ist oder in einem vertrauenswürdigen Netz liegt (Loopback, `LAN_SUBNET`, `CROWDSEC_WHITELIST_IPS`), bricht den Deploy ab, ebenso ein Eintrag, der keine Adresse und kein CIDR ist. Vor einem Eintrag breiter als `/24` (IPv4) oder `/48` (IPv6) wird gewarnt.

Eine leere Liste (der Default) entfernt die Whitelist-Datei beim nächsten Deploy. Das gilt auch für eine von Hand angelegte Datei unter diesem Pfad: Der Deploy warnt und nennt die Einträge, die er entfernt. Trag die Quellen also *vor* dem Deploy in `TRAP_EXEMPT_IPS` ein. `test-gateway.sh` prüft, dass jeder Eintrag in der Whitelist-Datei und im nginx-Exempt-Geo steht und keiner vertrauenswürdig ist.

### `SSH_ALLOW_USERS` und Root-Login im HARD-Modus

| Key | Default | Was er tut |
|---|---|---|
| `SSH_ALLOW_USERS` | `""` | Leerzeichengetrennte `AllowUsers`-Muster (`user` oder `user@host`). Leer = keine `AllowUsers`-Zeile, jedes Konto mit Key darf sich anmelden. |

**Wann ändern:** setzen (z. B. `"admin"`), um SSH auf dein Admin-Konto zu beschränken. `deploy.sh` verweigert eine Liste, die alle aussperren würde (kein gelistetes Konto mit Login-Shell oder, im HARD-Modus, keines davon mit Authorized Key) und sagt das im Log. `--finalize-ssh` liest `deploy.conf`, die Einstellung gilt dort also ebenfalls.

**Root-Login.** Im HARD-Modus (`--finalize-ssh`, siehe "SSH Key Bootstrap") setzt das Drop-in jetzt `PermitRootLogin no` nur, wenn ein Nicht-Root-Konto einen Authorized Key, sudo-Rechte (`sudo`, `wheel` oder `admin`) und eine Login-Shell hat. Sonst (etwa wenn der Root-Key der einzige Key auf der Box ist) bleibt es bei `prohibit-password`, und der Deploy warnt — kopiere deinen Key auf einen sudo-User (`ssh-copy-id <user>@<gateway-ip>`) und lass `sudo bash deploy.sh --finalize-ssh` erneut laufen. Im SOFT-Modus bleibt Root-Login erlaubt (ein Root-Passwort kann bis zum ersten Key der einzige Zugang sein).

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
| `TLS_ACME_FALLBACK_SERVER` | `"zerossl"` | v2.0: sekundäre CA, die automatisch versucht wird, wenn das primäre `--issue` fehlschlägt (CA-Ausfall, Rate Limit). `""` deaktiviert den Fallback. |
| `TLS_ACME_EXTRA` | `""` | Passthrough an `acme.sh --issue` (z. B. `--keylength ec-256`). |
| `EXTRA_SERVER_NAMES` | `""` | Weitere Hostnamen, die `:1080` neben `TLS_DOMAIN` akzeptiert. Alles andere — auch die nackte IP — ist ein Trap-Treffer und wird gebannt. Siehe "Scanner-Abwehr & Edge-Filter". |

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
2. Eine kleine `/etc/nginx/conf.d/loxprox-acme.conf` wird geschrieben: ein `:80`-Server für deine eigenen Hostnamen (`TLS_DOMAIN` plus `EXTRA_SERVER_NAMES`), der nur `/.well-known/acme-challenge/` aus `/var/www/acme/` ausliefert und alles andere mit 301 auf `https://$host:1080$request_uri` weiterleitet. Jeder andere `Host` auf `:80` (IP-Scans) fällt auf den Trap-Server aus Schritt 5, der mit 444 antwortet.
3. Das Cert wird via `acme.sh --issue --webroot --server $TLS_ACME_SERVER` ausgestellt (oder erneuert). "Cert still valid, skipped" wird als Erfolg gewertet.
4. Das Cert wird unter `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (Mode `0640 root`) installiert, mit `--reloadcmd "systemctl reload nginx"` für den Renewal-Cron hinterlegt.
5. Die bestehende Site-Datei wird zwischen expliziten Markern (`# LOXPROX-TLS-BEGIN` / `# LOXPROX-TLS-END`) mutiert, und `listen 1080;` wird zu `listen 1080 ssl;`. Operator-Handedits außerhalb des Marker-Blocks (WebSocket-Location, Custom Header) bleiben unberührt. Die strikte Regex auf der Listen-Zeile akzeptiert ausschließlich das kanonische `listen 1080;` — keine stille Mutation. Derselbe Schritt schaltet den echten Server auf deine Hostnamen scharf (`server_name` ist nicht mehr `_`) und hängt die Trap-Default-Server für `:1080` und `:80` zwischen `# LOXPROX-TRAP-BEGIN` / `# LOXPROX-TRAP-END` an, mit einem selbstsignierten `CN=invalid`-Zertifikat (`/etc/loxprox/tls/trap-*.pem`), damit Scanner, die per IP verbinden, den Handshake abschließen und geloggt und gebannt werden.
6. Der Auto-Renewal-Cron wird nach jedem TLS-aktivierten Deploy **verifiziert** (nicht vorausgesetzt). Fehlt er? Wird via `acme.sh --install-cronjob` wiederhergestellt, und die exakte Cron-Zeile plus Anleitung zum manuellen Renewal wird geloggt.

> ⚠️ **TLS einzuschalten migriert bestehende Clients nicht automatisch.** Sobald `:1080` nur noch HTTPS spricht, läuft jede Loxone-App / jeder Browser, der noch als `http://<host>:1080` konfiguriert ist, in eine `301`-Redirect-Schleife, bis du ihn auf `https://` umstellst. Plane ein, **jede** gespeicherte Verbindung (jedes Handy, Tablet, jeden Browser) anzupassen, wenn du `ENABLE_TLS=true` setzt. Siehe Troubleshooting → "Die Loxone-App verbindet sich nach dem Aktivieren von TLS nicht mehr".
>
> ⚠️ **Mit aktivem TLS nie die IP-Adresse benutzen.** Seit der Härtung 2026-10 antwortet `:1080` nur noch auf deine Hostnamen. Ein Client, der mit der IP des Gateways konfiguriert ist, bekommt eine geschlossene Verbindung und wird mit der HARD-Leiter gebannt (7 Tage bei der ersten Anfrage). Überall `https://<dein-host>:1080` verwenden.

> **Network-Watchdog während des Deploys.** Mit TLS schaltet der Deploy den Network-Watchdog ab, bis seine Host/SNI-fähige Version installiert ist (ein älterer Watchdog läse das 444 des Traps für `127.0.0.1` als Ausfall und würde die Box neu starten), und scharf am Ende wieder. Ein vorzeitig beendeter Lauf meldet `network-watchdog → NOT ARMED`. Die Lösung ist, `sudo bash deploy.sh` erneut auszuführen — nicht, den Timer von Hand zu starten.

### Verhalten beim Ausschalten (`ENABLE_TLS="false"`)

`ENABLE_TLS="false"` setzen und `sudo bash deploy.sh` erneut laufen lassen. Das Script:

- Entfernt den Marker-Block aus der Site-Datei.
- Setzt die Listen-Zeile zurück auf Plain `listen 1080;`.
- Entfernt den `:80`-ACME-Listener, die Trap-Server und das Hostnamen-Gate (wieder `server_name _` — jeder Host wird bedient).
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

## Optionaler Tunnel (v2.0) — Fernzugriff ohne offene Ports

Für Anschlüsse, an denen keine Portweiterleitung möglich ist (CGNAT /
DS-Lite). Das Gateway wählt sich ausgehend bei einem eigenen Relay-VPS ein;
die Loxone App verbindet sich mit der Domain des Relays. Zuerst das Relay
mit `tunnel-relay/install-relay.sh` einrichten — dessen Zusammenfassung gibt
die exakten Werte unten aus.

> ⚠️ `ENABLE_TUNNEL=true` und `ENABLE_TLS=true` schließen sich in v2.0
> gegenseitig aus — mit dem Tunnel terminiert TLS am Relay. `deploy.sh`
> verweigert die Kombination mit einer klaren Fehlermeldung.

### Config-Schlüssel

| Schlüssel | Default | Zweck |
|-----------|---------|-------|
| `ENABLE_TUNNEL` | `"false"` | Hauptschalter. Auf `"true"` stellen zum Aktivieren. |
| `TUNNEL_SERVER_ADDR` | `""` | Öffentliche IP oder DNS-Name des Relay-VPS. Pflicht bei aktiviertem Tunnel. |
| `TUNNEL_SERVER_PORT` | `"7000"` | frp-Steuerkanal-Port — muss dem `FRP_BIND_PORT` des Relays entsprechen. Dieselbe Nummer bedient tcp UND quic. |
| `TUNNEL_PROTOCOL` | `"quic"` | `quic` (UDP, NAT-freundlich — empfohlen) oder `tcp` (Fallback, wenn UDP verworfen wird). |
| `TUNNEL_TOKEN` | `""` | Gemeinsames Geheimnis, derselbe Wert wie `TUNNEL_TOKEN` am Relay. Erzeugen: `openssl rand -hex 32`. Pflicht bei aktiviertem Tunnel. |
| `TUNNEL_PROXY_NAME` | `"loxone"` | Kosmetischer Proxy-Name in den frps-Logs. |
| `TUNNEL_REMOTE_PORT` | `"8443"` | Loopback-gebundener Port am Relay, der Tunnel-Traffic zu dessen nginx trägt — muss dem Relay-Wert entsprechen. |
| `TUNNEL_PUBLIC_HOST` | `""` | Öffentliche Domain des Relays (`RELAY_DOMAIN`). Aktiviert die Ganzer-Pfad-Probe des Tunnel-Watchdogs. |

### Was bei `sudo bash deploy.sh` mit `ENABLE_TUNNEL=true` passiert

1. frpc wird aus einem SHA256-gepinnten GitHub-Release-Tarball installiert (versionsgepinnt, amd64/arm64) — kein `curl | bash`.
2. `/etc/frp/frpc.toml` wird geschrieben (Mode `0640 root:frpc`) mit dem Token und einem einzelnen TCP-Proxy `127.0.0.1:1080 → Relay:TUNNEL_REMOTE_PORT`.
3. Eine gehärtete `frpc.service` startet unter dem dedizierten, unprivilegierten Benutzer `frpc` (`ProtectSystem=strict`, leeres Capability-Set, Syscall-Filter, `MemoryMax=256M`).
4. `/etc/nginx/conf.d/loxprox-tunnel-realip.conf` stellt echte Client-IPs aus dem `X-Forwarded-For` des Relays wieder her (nur von Loopback vertraut) — Logs, Rate Limits, CrowdSec und AppSec sehen wieder echte Quellen.
5. Der Tunnel-Watchdog wird scharfgestellt (60 s: frpc prüfen + `https://TUNNEL_PUBLIC_HOST/` proben → frpc neu starten → Discord-Alarm, max. 1/Stunde, niemals ein Reboot).

### Verhalten beim Ausschalten (`ENABLE_TUNNEL="false"`)

Stoppt und deaktiviert `frpc` + Watchdog und entfernt die Real-IP-Conf.
Binary und Config bleiben **erhalten** für günstiges Wiederaktivieren.
Vollständige Entfernung (Binary, Config, Units, Benutzer):
`sudo bash deploy.sh --remove-tunnel`.

### Verweise

- **Komplettes Tunnel-Runbook (Setup, Verifikation, Troubleshooting, Bedrohungsmodell):** [`docs/TUNNEL-SETUP.de.md`](docs/TUNNEL-SETUP.de.md)
- **Relay-Seite:** [`tunnel-relay/README.de.md`](tunnel-relay/README.de.md)
- **Familien-Handy-Onboarding:** [`docs/FAMILY-ONBOARDING.de.md`](docs/FAMILY-ONBOARDING.de.md)

---

## LoxProx Panel (GUI)

Optionale (per Default aktive) LAN-only Web-UI für Status-Kacheln,
Log-Ansicht, Config-Bearbeitung und Ein-Klick-Support-Aktionen (IP
entbannen, Service neu starten, TLS-Renewal erzwingen, Test-Alert senden).
Läuft auf dem Gateway selbst und ist ausschließlich aus `LAN_SUBNET` +
`SSH_ALLOWED_SUBNETS` erreichbar — nie aus dem Internet.

### Config-Keys

| Key | Default | Zweck |
|-----|---------|-------|
| `ENABLE_GUI` | `"true"` | Master-Toggle. Auf `"false"` setzen zum Deaktivieren. |
| `GUI_PORT` | `"1081"` | TCP-Port, auf dem das Panel lauscht. |
| `GUI_PASSWORD` | `""` | Leer = keine Auth. Setzen, um bei jedem mutierenden Request den Header `X-LoxProx-Auth` zu verlangen — empfohlen, wenn untrusted Geräte (Gäste, IoT, Kinder-Tablets) dein LAN teilen. |

Vollständige Feature-Tour, Security-Modell und Troubleshooting:
[`docs/GUI-PANEL.de.md`](docs/GUI-PANEL.de.md).

---

## Backup & Restore

`deploy.sh` installiert einen täglichen Backup-Timer, der nach
`/root/loxprox-backups/*.tar.gz` archiviert (Mode `0600` — das Tarball
enthält jetzt Schlüsselmaterial). Seit v2.1 enthält das tägliche Backup
zusätzlich:

- `/etc/loxprox/deploy.conf`
- `/etc/loxprox/tls/fullchain.pem` + `privkey.pem` (wenn TLS aktiv ist)
- `/etc/frp/frpc.toml` (wenn der Tunnel aktiv ist)
- `/etc/ssh/sshd_config.d/99-loxprox.conf`

zusätzlich zu Nginx-Site, CrowdSec-Config und nftables-Ruleset, die es
schon vorher sicherte.

### Aus einem Backup wiederherstellen

```bash
sudo bash deploy.sh --restore /root/loxprox-backups/<tarball>.tar.gz
```

Das legt zuerst einen Vor-Restore-Sicherheits-Snapshot an, extrahiert das
Tarball und schreibt die bekannten Dateien mit den korrekten Modes zurück.
**Danach `sudo bash deploy.sh` erneut ausführen**, um Services,
Firewall-Regeln und Units gegen die wiederhergestellte Config zu
reconcilen — `--restore` legt nur Dateien zurück, wendet sie aber nicht
erneut an.

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

Das ist kein Ban — `cscli decisions list` zeigt nichts für die IP. (Das umgekehrte Symptom — die Verbindung wird sofort geschlossen und die IP **ist** gebannt — bedeutet, dass der Client die IP des Gateways oder einen Namen außerhalb von `TLS_DOMAIN` / `EXTRA_SERVER_NAMES` nutzt: Das Host/SNI-Gate hat ihn für einen Scanner gehalten. Mit `sudo cscli decisions delete --ip <IP>` entbannen und den Client genauso korrigieren.) Der Fix ist client-seitig und gilt für jede App / jeden Browser, der sich verbindet:

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
- [ ] Mit TLS: jede App und jedes Gerät nutzt `https://<dein-host>:1080` — nie die IP
- [ ] Discord-Webhook ist gesetzt (oder bewusst leer gelassen)
