**Sprache:** Deutsch · [English](UPGRADE-to-v1.5.md)

# Upgrade LoxProx v1.3.x → v1.5.0

v1.5.0 verschiebt die REQUIRED-Konfigurationswerte aus `deploy.sh` heraus
in eine eigene Datei unter `/etc/loxprox/deploy.conf`. **Auf jeder
bestehenden Installation musst du einmalig den Bootstrap laufen lassen**,
bevor du `deploy.sh` neu startest — sonst verweigert der neue Safety-Check
den Lauf.

Wenn du frisch auf einer neuen VM installierst, springe ans Ende.

---

## Warum sich das geändert hat

In v1.4.x und früher waren die Werte oben in `deploy.sh` (`LOXONE_IP`,
`SSH_ALLOWED_SUBNETS`, …) Platzhalter, die jeder Operator von Hand
anzupassen hatte, bevor er das Script gestartet hat. Die Produktions-VM
des Maintainers selbst hat den Failure-Mode am 26.05.2026 demonstriert:
Die handangepasste Kopie von `deploy.sh` war nirgendwo dauerhaft auf der
Disk gespeichert. Ein erneuter Lauf von `deploy.sh` aus dem Repo hätte
nftables mit `192.168.1.0/24` neu geschrieben und das LAN vom Gateway
ausgesperrt.

v1.5.0 behebt das endgültig: Die Werte liegen in
`/etc/loxprox/deploy.conf`, die `deploy.sh` zwar einliest, aber nie
verändert. Upgrades sind nur noch `git pull && sudo bash deploy.sh`.

---

## Upgrade-Pfad für bestehende Installs (v1.3.x → v1.5.0)

Drei Kommandos. Das erste ist der einzige neue Schritt, den du jemals
machen wirst.

```bash
git pull                                       # oder das v1.5.0-Tarball herunterladen

sudo bash deploy.sh --bootstrap-config         # Live-Werte → deploy.conf extrahieren
sudo $EDITOR /etc/loxprox/deploy.conf          # nochmal drüberlesen (sehr empfohlen)

sudo bash deploy.sh                            # normaler Deploy, sourcet die Datei
```

### Was `--bootstrap-config` ausliest

Es greppt sich den bestehenden Zustand des Live-Systems zusammen, um
deine Operator-Config zu rekonstruieren:

| Variable | Gelesen aus |
|---|---|
| `LOXONE_IP` / `LOXONE_PORT` | `upstream loxone_backend { server <IP>:<PORT>; }` in `/etc/nginx/sites-available/loxone` |
| `GATEWAY_IP` | `hostname -I` (primäres Interface) |
| `LAN_SUBNET` | Erste `proto kernel scope link`-Route aus `ip route` |
| `SSH_ALLOWED_SUBNETS` | Das Set in `tcp dport 22 ip saddr { … }` in `/etc/nftables.conf` |
| `ENABLE_APPSEC` | Vorhandensein von `auth_request /crowdsec-appsec` in der nginx-Site |
| `APPSEC_MODE` | Key `mode:` in `/etc/crowdsec/acquis.d/appsec.yaml` |
| `CROWDSEC_WHITELIST_IPS` | `/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml` |
| `DISCORD_WEBHOOK_URL` | Zeile `DISCORD_WEBHOOK_URL=` in `/etc/loxprox/config.env` |

Es zeigt die Kandidaten-Datei zum Drüberlesen an und fragt "Write this to
`/etc/loxprox/deploy.conf`? [y/N]". Eine vorhandene Datei wird vor dem
Überschreiben nach `/etc/loxprox/deploy.conf.bak-<timestamp>` gesichert.

Rate Limits, Proxy-Timeouts und Buffer-Größen werden NICHT extrahiert —
`deploy.conf` wird mit den Repo-Defaults geschrieben (die zu jedem
v1.0–v1.4-Deploy passen). Wenn du da etwas angepasst hast, die Datei
von Hand nachziehen.

### Nicht-interaktive Deploys (Ansible, CI etc.)

Wenn `deploy.sh` ohne TTY läuft UND `/etc/loxprox/deploy.conf` fehlt UND
ein bestehender Install erkannt wird, läuft `--bootstrap-config`
automatisch ohne Rückfrage (schreibt die Kandidaten-Datei, fährt mit dem
Deploy fort). `LOXPROX_BOOTSTRAP_YES=1` setzen, wenn du dasselbe
Verhalten über ein TTY haben willst.

### Was, wenn die Extraktion scheitert?

Wenn `/etc/nginx`, `/etc/nftables.conf` etc. nicht den erwarteten Inhalt
haben (stark angepasster Install, Mid-Rollback-State etc.), bricht der
Extractor mit `Could not extract: <names>` ab und bittet dich,
`deploy.conf` von Hand zu schreiben:

```bash
sudo install -d -m 0750 /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf
```

Das Format innerhalb von `deploy.conf` ist dieselbe Bash-Variablen-Syntax,
die früher oben in `deploy.sh` stand — keine neuen Konventionen zu
lernen.

---

## Was v1.5.0 sonst noch ändert (nicht-breaking)

- **`/etc/nginx/sites-available/loxone` bleibt bei jedem Redeploy
  erhalten.** WebSocket-Location-Blöcke und andere Hand-Edits des
  Operators werden nicht mehr überschrieben.
  `LOXPROX_FORCE_REGEN_NGINX=1 sudo bash deploy.sh` nutzen, um aus dem
  Template neu zu regenerieren, falls jemals nötig.
- **AppSec-Map + log_format bleiben inline in der Site-Config** (wie in
  v1.4.0). Ein Split nach `conf.d/loxprox-appsec.conf` wurde probiert
  und wieder zurückgenommen — nginx weist das ab, weil `$appsec_action`
  über `auth_request_set` innerhalb des Location-Blocks registriert
  wird und jede frühere Referenz darauf bei der Parse-Zeit-Validierung
  scheitert. v1.5.0 räumt die conf.d-Datei auf, falls ein
  v1.5.0-rc-Devbuild sie geschrieben hat.
- **`systemctl reload nginx`** (war `restart`) — graceful, hält die
  bestehenden Upstream-Keepalives zum Miniserver am Leben.

---

## Frische-VM-Installation (in v1.5.0 neu formuliert)

```bash
# 1. VM aufsetzen (1 GB+ RAM, 1 vCPU+, Debian 12, statische IP).
#    Bei Bedarf vorher set-static-ip.sh laufen lassen.

# 2. Repo auf die VM kopieren (scp / git clone — deine Entscheidung).

# 3. Deploy-Config aus dem Template erzeugen:
sudo install -d -m 0750 /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf      # [REQUIRED]-Werte ausfüllen

# 4. Deploy:
sudo bash deploy.sh
```

Wenn du Schritt 3 vergisst, verweigert `deploy.sh` den Lauf und gibt
exakt die Copy-Paste-Kommandos oben aus. Die alte Fußangel (vergessen
zu editieren → leise mit `192.168.1.100` deployt) ist nicht mehr
erreichbar.

---

## Rollback

Falls etwas schiefgeht:

```bash
sudo bash deploy.sh --rollback
```

Stellt das jüngste Pre-Deploy-Backup wieder her. `/etc/loxprox/deploy.conf`
selbst wird vom Rollback NICHT angefasst — der nächste Forward-Deploy
benutzt weiterhin die Werte, die du gebootstrappt hast.
