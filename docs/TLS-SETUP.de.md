**Sprache:** Deutsch · [English](TLS-SETUP.md)

# LoxProx TLS — Optionales HTTPS auf :1080

LoxProx v1.5.0 ergänzt optionale HTTPS-Terminierung auf dem Gateway selbst,
via [`acme.sh`](https://github.com/acmesh-official/acme.sh) und der
Standard-HTTP-01-Challenge. Per Default aus — das Gateway spricht weiter
Plain-HTTP auf `:1080`, bis du das aktivierst.

Wenn aktiviert:

- `:1080` ist derselbe Port, den du bereits am Router weiterleitest, nur
  spricht er jetzt HTTPS statt HTTP.
- Renewal läuft vollautomatisch über den Cron von `acme.sh` (täglicher
  Check, erneuert alles innerhalb von ~30 Tagen vor Ablauf, lädt nginx
  bei Erfolg neu).
- Später zwischen HTTP und HTTPS umschalten ist ein einzelnes
  `deploy.conf`-Edit plus ein erneutes `sudo bash deploy.sh`. Cert-Dateien
  überleben ein Deaktivieren, damit du beim Zurückschalten keine erneute
  Issuance-Zeit zahlst.

---

## Voraussetzungen — einmalig, bevor `ENABLE_TLS=true`

### 1. Ein öffentlicher DNS-Name auf die WAN-IP deines Routers

Funktioniert heute z. B. mit:

- Einem Dynamic-DNS-Hostname von einem Provider, den du eh schon nutzt
  (`selfhost.eu`, `ddnss.de`, Cloudflare etc.).
- Einem statischen A-Record bei deinem Registrar, der auf die WAN-IP zeigt.

Der Cert wird für diesen FQDN ausgestellt. Der ACME-Server validiert ihn,
indem er sich zu `http://<deine-domain>/.well-known/acme-challenge/<token>`
verbindet — der Name muss also öffentlich auflösbar sein, **bevor** du das
Deploy startest.

```bash
# Sanity-Check — sollte die öffentliche IP deines Routers zurückgeben:
dig +short A loxprox.example.com
```

### 2. Eine Router-Weiterleitung `WAN:80 → Gateway:80`

Zusätzlich zur bestehenden Weiterleitung `WAN:1080 → Gateway:1080`. Diese
hier wird **ausschließlich für die ACME-Validierung** verwendet. Der
`:80`-Listener des Gateways beantwortet genau eine Sache:
`/.well-known/acme-challenge/*` (ausgeliefert aus `/var/www/acme/`). Alles
andere auf `:80` bekommt einen permanenten 301 auf
`https://<deine-domain>:1080$request_uri` — wer also zufällig
`http://deine-domain/` aufruft, landet auf dem HTTPS-Endpoint auf 1080,
was genau das ist, was du willst.

Die erweiterte öffentliche Angriffsfläche ist nur das Challenge-Verzeichnis;
dasselbe Threat-Profil wie jedes ganz normale Let's-Encrypt-Deployment.

### 3. `deploy.conf` ausfüllen

Diese Keys in `/etc/loxprox/deploy.conf` ergänzen (oder anpassen):

```bash
ENABLE_TLS="true"
TLS_DOMAIN="loxprox.example.com"
TLS_EMAIL="you@example.com"
TLS_ACME_SERVER="letsencrypt"        # oder "letsencrypt_test" beim Debuggen
TLS_ACME_EXTRA=""                    # optional --keylength ec-256 etc.
```

> **Erst `letsencrypt_test` (Staging) verwenden**, wenn du dir bei DNS oder
> der `:80`-Weiterleitung unsicher bist. Staging hat keine Rate Limits und
> verbrennt dein wöchentliches Produktions-Issuance-Budget nicht. Wenn alles
> läuft, auf `letsencrypt` umstellen und neu laufen lassen.

---

## Deploy starten

```bash
sudo bash deploy.sh
```

Was passiert:

1. **Pre-flight + nftables + nginx + CrowdSec + AppArmor** — unverändert
   gegenüber v1.4.x.
2. **TLS-Schritt:**
    - `acme.sh` wird unter `/root/.acme.sh/` aus einem SHA256-gepinnten
      Tarball installiert (Version + Hash in `deploy.sh`; kein
      `curl | bash`).
    - `/etc/nginx/conf.d/loxprox-acme.conf` wird geschrieben — der
      Challenge-Listener auf `:80`.
    - nginx wird neu geladen; der Listener ist live.
    - `acme.sh --issue` führt HTTP-01 aus. Der ACME-Server holt sich das
      Challenge-Token von deinem Gateway. Bei Erfolg wird ein Cert
      ausgestellt und in `~/.acme.sh/<domain>/` abgelegt.
    - `acme.sh --install-cert` kopiert Cert und Key nach
      `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (Mode 0640 root) und
      hinterlegt `systemctl reload nginx` als Reload-Kommando für künftige
      automatische Renewals.
    - Der tägliche Renewal-Cron von `acme.sh` (angelegt beim `--install`)
      wird verifiziert und wiederhergestellt, falls er fehlt.
    - Der nginx-Site (`/etc/nginx/sites-available/loxone`) bekommt einen
      Marker-Block plus einen Swap von `listen 1080;` auf
      `listen 1080 ssl;`. Das ist die einzige Abweichung von der
      v1.5.0-Regel "Site bleibt vollständig erhalten". Deine
      Handanpassungen außerhalb des Marker-Blocks (WebSocket-Location etc.)
      bleiben unberührt.
    - nginx -t, reload. HTTPS ist live.

Nach erfolgreichem Deploy von außerhalb des LAN testen:

```bash
curl -vI https://loxprox.example.com:1080/
```

Du solltest ein `200 OK` sehen (oder was auch immer der Loxone Miniserver
zurückgibt) plus eine gültige TLS-Cert-Kette.

---

## Renewals — vollautomatisch

`acme.sh` bringt einen täglichen Cron-Eintrag mit, der `acme.sh --cron`
ausführt. Das prüft jeden installierten Cert und erneuert alles innerhalb
von ~30 Tagen vor Ablauf, danach läuft bei Erfolg das `--reloadcmd`
(`systemctl reload nginx`). Du musst nichts tun.

**Cron-Eintrag verifizieren** (das Deploy loggt ihn explizit):

```bash
crontab -l | grep acme.sh
# 0 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null
```

**Renewal manuell erzwingen**, falls du den Pfad testen oder Keys rotieren
willst:

```bash
sudo bash deploy.sh --renew-tls
```

---

## Später umschalten

### Abschalten (zurück auf Plain-HTTP)

```bash
sudo $EDITOR /etc/loxprox/deploy.conf      # ENABLE_TLS="false"
sudo bash deploy.sh
```

Was passiert:

- Der Marker-Block in der nginx-Site wird entfernt.
- `listen 1080 ssl;` wird auf `listen 1080;` zurückgesetzt.
- `/etc/nginx/conf.d/loxprox-acme.conf` wird entfernt.
- Der `acme.sh`-Cert für die Domain wird entfernt (der Cron fasst ihn nicht
  mehr an), die Cert-Dateien unter `/etc/loxprox/tls/` bleiben aber
  **erhalten**.
- nginx wird neu geladen.

Ein späteres erneutes Aktivieren ist schnell, weil der Cert noch gültig
ist und `acme.sh` ihn weiterverwendet.

### Wieder einschalten

`ENABLE_TLS="true"` setzen, `sudo bash deploy.sh` neu laufen lassen.
Derselbe Pfad wie beim ersten Mal, nur dass `acme.sh --issue` ein erneutes
Ausstellen überspringt, falls der bestehende Cert noch gut innerhalb seiner
Gültigkeit liegt.

### Domain oder ACME-Provider wechseln

`TLS_DOMAIN` oder `TLS_ACME_SERVER` in `deploy.conf` ändern,
`sudo bash deploy.sh` neu laufen lassen. `acme.sh` stellt einen neuen Cert
aus, und `--install-cert` überschreibt die Dateien unter
`/etc/loxprox/tls/`. Die Cert-Pfade der Site ändern sich nicht (sie zeigen
immer auf dieselben Dateien), also ist keine Site-Mutation nötig.

### Komplett wegräumen — Cert-Dateien, acme.sh, alles

```bash
sudo bash deploy.sh --remove-tls
```

Setzt die Site zurück, entfernt den ACME-Listener aus `conf.d`,
deinstalliert `acme.sh` (und seinen Cron) und löscht `/etc/loxprox/tls/`.
Danach kannst du auch die Router-Weiterleitung `WAN:80 → Gateway:80`
entfernen — sie wird nicht mehr gebraucht.

---

## Troubleshooting

### `acme.sh --issue failed`

Häufigste Ursachen, in der Reihenfolge:

1. **`:80` nicht erreichbar.** Von außerhalb des LAN:
   ```bash
   curl -vI http://loxprox.example.com/.well-known/acme-challenge/test
   ```
   Sollte dein Gateway treffen und `404` zurückgeben (die Challenge-Datei
   existiert noch nicht) — *kein* Timeout. Wenn es ein Timeout gibt, fehlt
   die `WAN:80`-Weiterleitung.

2. **DNS löst nicht auf.** Mit `dig +short A` von einem System außerhalb
   deines LAN verifizieren (Handy im Mobilfunk reicht).

3. **Let's-Encrypt-Rate-Limit.** Wenn du viel retry-st, auf
   `TLS_ACME_SERVER="letsencrypt_test"` umstellen zum Debuggen und
   zurückwechseln, wenn alles geht. Das Rate Limit gilt pro Domain pro
   Woche, nicht pro IP.

4. **CrowdSec / AppSec blockt den ACME-Server.** Mit `cscli alerts list`
   prüfen — die IPs des ACME-Servers tauchen gelegentlich auf, wenn sie
   andere Pfade probiert haben. Bei Bedarf whitelisten.

Detaillierte acme.sh-Logs: `tail -100 /var/log/loxprox-deploy.log`.

### `nginx -t failed after TLS site mutation`

Sollte sich selbst zurücksetzen (der Enable-Pfad hat einen Rollback).
Falls du das siehst und das Gateway kaputt ist, manuelle Recovery:

```bash
sudo /opt/loxprox/gateway-backup.sh        # zur Sicherheit ein Snapshot
# Marker-Block inspizieren:
sudo sed -n '/LOXPROX-TLS-BEGIN/,/LOXPROX-TLS-END/p' /etc/nginx/sites-available/loxone
# Falls verstümmelt, Block löschen + listen-Zeile von Hand reverten, dann:
sudo nginx -t && sudo systemctl reload nginx
```

### Cert-Datei-Permissions / nginx kann Key nicht lesen

Das Deploy setzt `/etc/loxprox/tls/*` auf `0640 root:root`. nginx-Worker
laufen als `www-data` und müssen den Key nicht lesen — nur der
Master-Prozess (root) braucht ihn, vor dem Fork. Falls du nginx so
angepasst hast, dass er früher Privilegien abgibt, die Permissions
entsprechend anpassen.

---

## Was das NICHT mitbringt

- Keine HSTS-Preload-Submission. Der Header
  `Strict-Transport-Security: max-age=31536000` wird gesetzt, aber das
  Eintragen der Domain bei [hstspreload.org](https://hstspreload.org)
  musst du selbst machen, wenn du sie in den Browsern verbacken haben
  willst.
- Keine OCSP-Stapling-Konfiguration. Die modernen Defaults von Let's
  Encrypt + nginx erledigen das brauchbar; in der Site-Config nachziehen,
  wenn du strengere Garantien brauchst.
- Kein CT-Log-Monitoring. Das v1.x-Bedrohungsmodell hat das nicht
  abgedeckt; sobald du einen öffentlichen Hostname und einen Cert hast,
  lohnt sich `certspotter` oder ein Polling von crt.sh auf unerwartete
  Issuance. (In den Known Limits des Skills-Audits als deferred
  vermerkt.)
- Kein Support für DNS-01-Challenge. In v1.5.0 nur HTTP-01. DNS-01 ist
  eine mögliche zukünftige Erweiterung, falls dein Setup `:80` nicht
  öffnen kann.

---

## Referenz

- Source: `setup_tls()` in `deploy.sh`
- acme.sh upstream: https://github.com/acmesh-official/acme.sh
- HTTP-01-Challenge-Spec: RFC 8555 §8.3
- Getestet gegen `letsencrypt` (Produktion) und `letsencrypt_test`
  (Staging). `zerossl` und `buypass` sollten über denselben Code-Pfad
  laufen, sind aber nicht Teil der Regressionsmatrix.
