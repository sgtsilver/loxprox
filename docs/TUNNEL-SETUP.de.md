# Tunnel-Einrichtung (v2.0) — Fernzugriff ohne offene Ports

> **Für wen das ist:** alle, deren Internetanschluss keine Portweiterleitung
> kann — CGNAT, DS-Lite, viele deutsche Kabel-/Glasfaseranschlüsse ab Werk.
> Wer Ports weiterleiten KANN, fährt mit dem klassischen Weg (Router-Forward
> + optional `ENABLE_TLS`) einfacher; dieses Dokument wird dann nicht
> gebraucht.

Loxone Gen 1 hat keinen offiziellen Fernzugriffsweg für CGNAT-Anschlüsse:
Cloud DNS braucht öffentliche IP + Portweiterleitung, Remote Connect gibt es
nur für Gen 2. Der v2.0-Tunnel schließt diese Lücke ausschließlich mit
selbst gehosteten Komponenten (ADR-0002).

## So funktioniert es

```
                         DEIN RELAY-VPS (öffentliche IPv4)
                        ┌──────────────────────────────┐
Loxone App ── https ──► │ nginx:443 (TLS, WS, Rate     │
                        │   Limits, CrowdSec)          │
                        │      │                       │
                        │      ▼                       │
                        │ 127.0.0.1:8443 (frps)        │
                        └──────┬───────────────────────┘
                               │  frp-Tunnel (ausgehend von zu Hause,
                               │  QUIC oder TCP, Token-authentifiziert)
                        ┌──────▼───────────────────────┐
                        │ frpc (gesandboxter Dienst)   │
                        │      │                       │
                        │      ▼                       │
                        │ nginx:1080 (Rate Limits,     │   DEINE GATEWAY-VM
                        │   AppSec-WAF, CrowdSec)      │   (Heimnetz)
                        └──────┬───────────────────────┘
                               ▼
                        Loxone Miniserver Gen 1 :80
```

Kerneigenschaften:

- **Keine offenen Ports zu Hause.** Das Gateway wählt sich ausgehend ein;
  die Router-Konfiguration bleibt unangetastet.
- **Der komplette Security-Stack bleibt auf dem Pfad.** Das Relay ergänzt
  einen Perimeter (Rate Limits + CrowdSec); das Gateway behält
  nginx-Härtung, AppSec-WAF, CrowdSec-Erkennung, auditd — alles, was v1.x
  schon hatte.
- **Alles gehört dir.** Das Relay ist dein VPS (beliebiger EU-Anbieter,
  ~3–5 €/Monat); frp ist Open Source; keine Drittanbieter-Cloud im Pfad,
  kein Abo.

## Voraussetzungen

1. Ein **VPS mit öffentlicher IPv4** unter Debian 12 (kleinste Instanz
   reicht: 1 vCPU / 1 GB RAM).
2. Ein **Domain- oder DNS-Name** mit A-Record auf den VPS.
   Datenschutzhinweis: einen neutralen, selbst gewählten Namen nehmen.
   Niemals die Miniserver-Seriennummer oder die eigene Adresse in den
   Hostnamen einbauen — Certificate-Transparency-Logs sind öffentlich.
3. Ein **gemeinsames Token**: `openssl rand -hex 32` — derselbe Wert wird
   auf beiden Seiten eingetragen.

## Schritt 1 — Relay einrichten (auf dem VPS)

```bash
# Repo (oder nur tunnel-relay/) auf den VPS kopieren, dann:
sudo install -d -m 0750 /etc/loxprox-relay
sudo cp tunnel-relay/relay.conf.example /etc/loxprox-relay/relay.conf
sudoedit /etc/loxprox-relay/relay.conf     # RELAY_DOMAIN, RELAY_EMAIL, TUNNEL_TOKEN
sudo bash tunnel-relay/install-relay.sh
```

Der Installer richtet ein: nftables (Input drop), frps (versionsgepinnt,
SHA256-verifiziert, gesandboxte systemd-Unit), nginx mit
Let's-Encrypt-Zertifikat (ZeroSSL-Fallback), CrowdSec mit
Community-Blocklisten und Unattended Upgrades. Am Ende läuft ein Health
Check und die exakten Werte für das Gateway werden ausgegeben.

## Schritt 2 — Tunnel aktivieren (auf dem Gateway)

`/etc/loxprox/deploy.conf` bearbeiten:

```bash
ENABLE_TUNNEL="true"
TUNNEL_SERVER_ADDR="<VPS-IP oder DNS>"
TUNNEL_SERVER_PORT="7000"
TUNNEL_PROTOCOL="quic"            # oder "tcp", falls das Netz UDP verwirft
TUNNEL_TOKEN="<dasselbe Token wie am Relay>"
TUNNEL_REMOTE_PORT="8443"
TUNNEL_PUBLIC_HOST="<RELAY_DOMAIN>"

# v2.0-Einschränkung — siehe unten:
ENABLE_TLS="false"
```

Danach:

```bash
sudo bash deploy.sh
```

Installiert werden: frpc (gepinnt + verifiziert), eine gesandboxte
`frpc.service` unter einem unprivilegierten Benutzer, die
nginx-Real-IP-Wiederherstellung (damit Logs, Rate Limits und CrowdSec echte
Client-IPs statt des Tunnels sehen) und der Tunnel-Watchdog (60-s-Zyklus:
prüfen → frpc neu starten → Discord-Alarm, niemals ein Reboot).

## Schritt 3 — Verifizieren

```bash
# 1. Tunnel verbunden? (auf dem Gateway)
systemctl status frpc
journalctl -u frpc -n 20        # nach "login to server success" schauen

# 2. Relay antwortet? (aus BELIEBIGEM Netz, z. B. Handy über Mobilfunk)
curl -vI https://<RELAY_DOMAIN>/

# 3. Kompletter Pfad? Erwartet wird eine Loxone-JSON-Antwort:
curl -s https://<RELAY_DOMAIN>/jdev/cfg/api

# 4. WebSocket-Upgrade? Erwartet wird HTTP/1.1 101:
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Upgrade: websocket' -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
  https://<RELAY_DOMAIN>/ws/rfc6455

# 5. Loxone App (Handy über Mobilfunk, NICHT im eigenen WLAN): Miniserver
#    mit Host <RELAY_DOMAIN> hinzufügen, Live-Statistik öffnen, Werte
#    beobachten.
```

Für Familien-Handys den QR-Onboarding-Ablauf nutzen:
[FAMILY-ONBOARDING.de.md](FAMILY-ONBOARDING.de.md).

## Betrieb

| Aufgabe | Befehl |
|---|---|
| Tunnel-Status | `systemctl status frpc` (Gateway), `systemctl status frps` (Relay) |
| Watchdog-Log | `cat /var/log/loxprox-tunnel-watchdog.log` |
| Vorübergehend deaktivieren | `ENABLE_TUNNEL="false"` setzen, `deploy.sh` erneut ausführen (Binary+Config bleiben) |
| Komplett entfernen | `sudo bash deploy.sh --remove-tunnel` |
| Token rotieren | neues `openssl rand -hex 32` → BEIDE Configs aktualisieren → erst `install-relay.sh`, dann `deploy.sh` erneut ausführen. Mindestens jährlich rotieren, bei jedem Verdacht sofort. |
| frp aktualisieren | `FRP_VER` + `FRP_SHA256_*` in `deploy.sh` UND `install-relay.sh` anheben (werden im Gleichschritt gepflegt), beide erneut ausführen. frp-Release-Notes beobachten — aktiv gepflegtes Upstream-Projekt. |

Der Tunnel-Watchdog alarmiert über den vorhandenen Discord-Webhook höchstens
einmal pro Stunde und meldet die Wiederherstellung. Ein toter Tunnel startet
niemals das Gateway neu — der LAN-Zugriff läuft weiter, lokale Ausfälle
deckt der Netzwerk-Watchdog ab.

## Hinweise zum Bedrohungsmodell

- **Das Relay ist der Durchsetzungspunkt für Tunnel-Traffic.** Getunnelte
  Pakete erreichen das Gateway über Loopback; ein CrowdSec-Bann auf den
  nftables des *Gateways* kann einen getunnelten Angreifer daher nicht
  aussperren. Das CrowdSec + Firewall-Bouncer des Relays (standardmäßig
  installiert) bannt am Perimeter, wo die echte Quell-IP sichtbar ist. Die
  AppSec-WAF des Gateways inspiziert weiterhin jede getunnelte Anfrage.
  Details: [../SECURITY.de.md](../SECURITY.de.md).
- **Echte Client-IPs werden wiederhergestellt** — via `X-Forwarded-For`, nur
  von Loopback vertraut, mit `real_ip_recursive off`; ein vom Client
  mitgeschickter Header kann die Quelle nicht fälschen.
- **Das Token ist ein Geheimnis.** Es liegt in `/etc/loxprox/deploy.conf`
  (0640) und `/etc/frp/*.toml` (0640, nur Dienstgruppe). Wer das Token hat,
  kann einen fremden frpc mit dem Relay verbinden — `proxyBindAddr =
  127.0.0.1` und `allowPorts` begrenzen den Schaden auf das Kapern des
  einen Loopback-Ports. Bei Verdacht sofort rotieren.
- **frp Upstream** ist ein großes, aktiv gepflegtes Open-Source-Projekt; die
  bekannte `routeByHTTPUser`-Auth-Bypass-CVE betrifft den
  TCP-Passthrough-Modus (unseren Modus) nicht. Den Pin aktuell halten.

## Warum nicht ENABLE_TLS zusammen mit dem Tunnel? (v2.0-Einschränkung)

Mit dem Tunnel terminiert TLS am **Relay** — der :1080-Listener des Gateways
muss Richtung Tunnel klartext-HTTP sprechen. Ein Gateway mit `listen 1080
ssl` würde die HTTP-Frames des Tunnels mit einem TLS-Alert beantworten und
alles kaputt machen; `deploy.sh` verweigert die Kombination deshalb. Die
Roadmap-Lösung ist ein Wildcard-Zertifikat via DNS-01 für beide Listener
(Split-Horizon-DNS: dieselbe Domain zeigt im LAN aufs Gateway, draußen aufs
Relay). Bis dahin gilt: Tunnel-Nutzer bekommen TLS vom Relay; der LAN-Pfad
bleibt klartext-HTTP im eigenen Netz — exakt wie der v1.x-Standard.

## Troubleshooting

**frpc loggt "login to server failed"** — Token-Mismatch oder falsche
`TUNNEL_SERVER_ADDR`/`PORT`. Beide Configs vergleichen; auf dem Relay
`journalctl -u frps` prüfen.

**QUIC verbindet nicht, TCP schon** — ISP/Router verwirft UDP.
`TUNNEL_PROTOCOL="tcp"` setzen und `deploy.sh` erneut ausführen.

**Relay antwortet 502/504** — Tunnel down. `systemctl status frpc` auf dem
Gateway prüfen; der Watchdog startet ihn vermutlich schon neu.

**App verbindet, aber keine Live-Updates** — WebSocket-Pfad kaputt. Den
101-Check aus Schritt 3 ausführen; prüfen, dass beide nginx-Configs die
`/ws/`-Location mit 24-h-Timeouts enthalten (mit
`LOXPROX_FORCE_REGEN_NGINX=1` neu generieren, falls die Site-Datei aus der
Zeit vor v2.0 stammt).

**App hängt bei „Verbindung wird hergestellt"** — bekannte Gen-1-App-Macke.
App-Cache leeren (Android) oder Miniserver-Eintrag löschen und neu anlegen
(iOS), mit `<RELAY_DOMAIN>` als Host.

**Familienmitglied plötzlich blockiert** — auf dem Relay prüfen:
`sudo cscli decisions list` → `sudo cscli decisions delete --ip <deren-ip>`.
