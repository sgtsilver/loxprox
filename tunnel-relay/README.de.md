# tunnel-relay/ — Relay-VPS (v2.0-Tunnel, Serverseite)

Dieses Verzeichnis richtet den **Relay-VPS** für LoxProx' optionalen
Fernzugriff ohne offene Ports ein (ADR-0002). Der `frpc` des Gateways wählt
sich ausgehend beim `frps` hier ein; die Loxone App verbindet sich mit
`https://<deine-domain>` und nginx leitet in den Tunnel weiter. Am heimischen
Router muss nichts geöffnet werden — das ist der Weg für CGNAT-/DS-Lite-
Anschlüsse, bei denen Portweiterleitung unmöglich ist.

| Datei | Zweck |
|---|---|
| `install-relay.sh` | One-Shot-Installer für Debian-12-VPS: nftables, frps (gepinnt + SHA256-verifiziert), nginx-TLS-Einstiegspunkt (Let's Encrypt mit ZeroSSL-Fallback), CrowdSec-Perimeter-Durchsetzung, Unattended Upgrades. Idempotent. |
| `relay.conf.example` | Konfigurationsvorlage. Nach `/etc/loxprox-relay/relay.conf` kopieren und die `[REQUIRED]`-Werte ausfüllen. |

## Schnellstart

```bash
# Auf einem frischen Debian-12-VPS (als root):
install -d -m 0750 /etc/loxprox-relay
cp relay.conf.example /etc/loxprox-relay/relay.conf
$EDITOR /etc/loxprox-relay/relay.conf     # Domain, E-Mail, Token
bash install-relay.sh
```

Danach die Gateway-Seite aktivieren: `ENABLE_TUNNEL="true"` (plus die
passenden `TUNNEL_*`-Werte) in `/etc/loxprox/deploy.conf` setzen und
`deploy.sh` erneut ausführen.

**Vollständiges Runbook, Bedrohungsmodell und Troubleshooting:**
[docs/TUNNEL-SETUP.de.md](../docs/TUNNEL-SETUP.de.md)
