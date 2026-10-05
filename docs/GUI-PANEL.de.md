**Sprache:** Deutsch · [English](GUI-PANEL.md)

# LoxProx Panel — LAN-only Web-GUI (v2.2)

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
- Das Panel ist eine **ruhige Status-Konsole** mit vier Bereichen —
  Übersicht, Sicherheit, Konfiguration, Logs — auf Deutsch (Standard) oder
  Englisch, mit hellem/dunklem/automatischem Design und einem Handy-Layout
  mit Tab-Leiste unten.
- Alles, was es braucht — die Seite, ihre Skripte, die Schriften Inter /
  Syne / JetBrains Mono — **liefert das Gateway selbst aus**. Es gibt keine
  Fremdbibliotheken, das Panel macht null Internet-Requests und
  funktioniert auch in einem Offline-LAN.

## Feature-Tour

**Übersicht** (die Startseite, `/`). Sie beantwortet zuerst eine Frage:
*Ist alles in Ordnung — und wenn nicht, was ist zu tun?*

- **Status-Zusammenfassung** — eine Zeile in Klartext („Alles in Ordnung“,
  „2 Punkte brauchen deine Aufmerksamkeit“, „Handlungsbedarf“), dazu die
  Verbindungsart und der Zeitpunkt der letzten Aktualisierung. Antwortet das
  Panel nicht mehr, steht das genau so da: die letzten bekannten Werte
  bleiben sichtbar, als veraltet markiert, und das Panel versucht es
  selbstständig weiter.
- **Was zu tun ist** — jeder Punkt, der Aufmerksamkeit braucht, das
  Wichtigste zuerst, jeweils mit Erklärung und passender Aktion: gestoppten
  Dienst neu starten, ablaufendes Zertifikat erneuern, Miniserver-Adresse
  prüfen, Protokoll eines fehlgeschlagenen Anwendens öffnen. Für
  zeitgesteuerte Units, die das Panel nicht neu starten kann, steht der
  passende `systemctl status …`-Befehl für SSH da.
- **Zustand im Detail** — kompakte Kacheln:

| Kachel | Zeigt |
|---|---|
| Dienste | Jede Unit mit Zustand: nginx, CrowdSec, Firewall-Bouncer, `loxprox-monitor.timer`, `network-watchdog.timer`, dazu frpc und `tunnel-watchdog.timer`, wenn der Tunnel an ist |
| Miniserver | Live-TCP-Check gegen `LOXONE_IP:LOXONE_PORT` |
| TLS-Zertifikat | Verbleibende Tage von `/etc/loxprox/tls/fullchain.pem` — Warnung unter 21 Tagen, Problem unter 7 |
| Gesperrte Adressen | Anzahl aktiver CrowdSec-Decisions (zur Info — Sperren heißen: der Schutz arbeitet) |
| Abgewehrte Angriffe heute | AppSec-Detections heute und von wie vielen Adressen |
| Letztes Backup | Alter und Größe des neuesten `/root/loxprox-backups/*.tar.gz` — Warnung, wenn älter als 26 Stunden oder keins da ist |
| System | Speicherplatz, Arbeitsspeicher und Auslastung als beschriftete Balken |
| Verbindungsart | TLS, Tunnel (mit frpc-Zustand) oder direktes HTTP |

- **Letzte 24 Stunden** — Anfragen pro Minute und Systemlast als
  Linien-Charts.

Ein Zustand wird nie nur über Farbe gezeigt: jeder hat ein Icon und ein
Wort, und Screenreader bekommen Änderungen des Gesamtzustands angesagt, ohne
dass der Fokus springt.

**Charts.** Das Panel misst das Gateway einmal pro Minute — Requests pro
Minute (Wachstum des nginx-Access-Logs), Systemlast, RAM/Disk, aktive
CrowdSec-Sperren, AppSec-Treffer, Miniserver-Erreichbarkeit — in einen
24-Stunden-Ringpuffer (`/var/lib/loxprox/gui-history.json`, übersteht
Neustarts, abrufbar unter `/api/history`). Jeder Chart hat eine
Zusammenfassung in einem Satz und eine Ansicht „Werte als Tabelle“ mit
Stundenwerten; per Maus oder Tastatur-Fokus plus Pfeiltasten lassen sich
einzelne Werte ablesen. Eine frische Installation zeigt „Sammle Daten“, bis
die ersten Messpunkte da sind; ein fehlgeschlagener Abruf wird als Fehler
angezeigt statt als leerer Chart.

**Sicherheit.** Charts für aktive Sperren und AppSec-Treffer pro Stunde;
die Liste der gesperrten Adressen mit einem **Entsperren**-Button pro Zeile
plus einem Feld, um eine beliebige andere IP zu entsperren;
Neustart-Buttons für nginx / CrowdSec / Bouncer / frpc (frpc nur im
Tunnel-Modus) mit dem aktuellen Zustand jedes Dienstes; **Testalarm
senden** (prüft den Discord-Webhook Ende-zu-Ende) und **TLS-Zertifikat
erneuern** (`deploy.sh --renew-tls`). Jedes Entsperren und jeder Neustart
fragt vorher nach und meldet das Ergebnis direkt an Ort und Stelle.

**Konfiguration.**

- *Familien-Einladung* — der QR-Code (siehe
  [`FAMILY-ONBOARDING.de.md`](FAMILY-ONBOARDING.de.md)), woher seine
  Adresse kommt, der `loxone://`-Link mit Kopier-Button und die manuelle
  Adresse. Die druckbare Seite `/invite` (DE/EN) ist außerdem oben im
  Kopfbereich mit einem Klick erreichbar — ins Technikschränkchen kleben
  statt `loxone-qr.png` von Hand zu erzeugen.
- *Gateway-Einstellungen* — eine gewhitelistete Teilmenge von
  `/etc/loxprox/deploy.conf` bearbeiten (Rate Limits, Timeouts,
  AppSec-Modus, CrowdSec-Whitelist, TLS, Tunnel, Panel-Einstellungen). Jedes
  Feld ist nach dem Schema des Servers typisiert (Schalter, Auswahl,
  Textfeld mit Format-Hinweis), zeigt seinen `deploy.conf`-Key und wird vor
  dem Speichern geprüft; Fehler stehen gesammelt oben und direkt am Feld.
  Geheimnisse (`TUNNEL_TOKEN`, `GUI_PASSWORD`, `DISCORD_WEBHOOK_URL`) werden
  nie angezeigt — Feld leer lassen behält den Wert, „Gespeicherten Wert
  entfernen“ löscht ihn. **Speichern** schreibt nur die geänderten Keys (mit
  zeitgestempeltem Backup von `deploy.conf`); **Anwenden** führt nach einer
  Rückfrage `deploy.sh` im Hintergrund aus (und bietet an, ungespeicherte
  Änderungen vorher zu speichern). `GATEWAY_IP`, `LAN_SUBNET` und
  `SSH_ALLOWED_SUBNETS` sind hier bewusst **nicht** editierbar — ein Fehler
  in einem dieser Werte ist ein SSH-Lockout-Risiko und bleibt eine
  SSH-only-Änderung.

Anwenden und Zertifikats-Erneuerung laufen als **Hintergrund-Vorgang**, der
oben in jeder Ansicht erscheint: Laufzeit, Live-Ausschnitt des Protokolls
und das Ergebnis. Der Status folgt dem Exit-Code von `deploy.sh`: `0` →
**ok**, `3` → **fertig, mit Einschränkungen** (das Deploy ist
durchgelaufen, aber ein oder mehrere *optionale* Schritte — TLS, Tunnel,
CrowdSec — nicht; das Gateway proxied trotzdem weiter, nur diese Features
sind nicht aktiv), alles andere → **fehlgeschlagen**. Der Job läuft als
eigene systemd-Unit (`loxprox-job-<id>`) und läuft deshalb weiter, wenn das
Anwenden das Panel neu installiert und neu startet; das neu gestartete Panel
übernimmt ihn und zeigt sein echtes Ergebnis. Ein Job, der ohne Exit-Code
endet (z. B. weil das Gateway mitten im Lauf neu gebootet hat), gilt als
**fehlgeschlagen**. Nur wenn das Panel lange nicht erreichbar ist oder den
Job nicht mehr kennt, zeigt es „Ergebnis unbekannt“ und verweist aufs
Deploy-Log, statt zu raten.

**Logs.** Read-only-Ansicht der nginx-Fehler- und Zugriffs-Logs, der
AppSec-Treffer, des Netzwerk- und Tunnel-Watchdogs, der Überwachung, des
Deploy-Logs und des Panel-Logs — mit Zeilenfilter und Folgen-Modus
(Aktualisierung alle 5 s) — kein `tail -f` per SSH mehr für einen schnellen
Blick.

**Passwort-Abfrage.** Ist `GUI_PASSWORD` gesetzt, fragt das Panel bei der
ersten Änderung in einem Dialog danach; es bleibt nur für diesen
Browser-Tab gespeichert. Ein falsches Passwort meldet derselbe Dialog;
Abbrechen bricht die Änderung ab.

**Barrierefreiheit.** Ziel ist WCAG 2.2 AA: semantische Überschriften und
Landmarks, komplette Bedienung per Tastatur mit sichtbarem Fokus und
„Zum Inhalt springen“-Link, Fokus springt beim Bereichswechsel auf die
Überschrift, Textkontrast mindestens 4,5:1 und Zustandsanzeigen mindestens
3:1 in beiden Designs, 44-px-Buttons und -Touch-Ziele auf Touchscreens,
Umbruch bis 320 px Breite, und `prefers-reduced-motion` wird respektiert
(die einzige Bewegung ist ein kurzer Zustandswechsel und ein
Fortschritts-Spinner).

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
- **Keine Inline-Skripte, keine externen Ressourcen.** Die CSP ist
  `script-src 'self'` — jedes Skript ist eine Datei aus der
  `/static/`-Allowlist des Gateways (pfad-eingeschlossen,
  endungs-gewhitelistet), und `connect-src 'self'` heißt: die Seite kann
  nirgendwo sonst hintelefonieren. Das Frontend enthält keinen Fremdcode
  und baut sein DOM ohne HTML-Strings auf, sodass Daten aus der API (IPs,
  Log-Zeilen, Fehlertexte) nie zu Markup werden können. pytest bewacht diese
  Regeln (keine Inline-Skripte/-Handler, keine externen URLs, keine Emoji,
  gleiche DE/EN-Texte).
- **Optionales Passwort für mutierende Aktionen.** `GUI_PASSWORD` ist per
  Default leer (keine Auth) — auf einem LAN, das du vollständig
  kontrollierst, vertretbar. Setzt du es, muss jeder
  Unban-/Restart-/Renew-/Apply-/Config-Write-Call es über den Header
  `X-LoxProx-Auth` mitschicken (Prüfung per Constant-Time-Vergleich); das
  Panel fragt einmal pro Browser-Tab danach. Status und Logs ansehen geht
  ohne Passwort.
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
  deaktiviert den Service `loxprox-gui`, entfernt die nftables-Regel und
  löscht das installierte Skript samt Assets; zurück auf `"true"` setzen
  und `deploy.sh` erneut ausführen installiert alles wieder.

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

Die manuelle Adresse gilt nur, wenn weder Tunnel noch TLS aktiv ist; ist
eins von beiden an, korrigierst du stattdessen `TUNNEL_PUBLIC_HOST` bzw.
`TLS_DOMAIN`. Einen bestimmten Host kannst du jederzeit über
`/invite?host=<host>&lang=de|en` drucken.

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
`deploy.conf`) und korrigiere entweder diesen Wert oder trage im Panel die
manuelle Adresse ein (nur bei reinem Port-Forward).

## Verweise

- **Familien-Onboarding-Flow:** [`FAMILY-ONBOARDING.de.md`](FAMILY-ONBOARDING.de.md)
- **Vollständige Config-Key-Referenz:** [`../CONFIGURATION-GUIDE.de.md`](../CONFIGURATION-GUIDE.de.md#loxprox-panel-gui) → "LoxProx Panel (GUI)"
