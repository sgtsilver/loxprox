**Sprache:** Deutsch · [English](SECURITY.md)

# Loxone Miniserver Gen 1 — Security Posture & Threat Model

## Responsible Disclosure

**Kein Bug Bounty — kein Geld.** Wer eine Vulnerability findet, öffnet einen Pull Request mit dem Fix. Jeder Beitrag wird reviewt und analysiert. Das hier ist ein community-gehärtetes Projekt: Der Code ist die Verteidigung, und besserer Code macht alle sicherer.

Wer keinen Fix liefern kann, öffnet ein Issue mit Reproduktionsschritten, dann kümmern wir uns darum.

---

## Executive Summary

Der Loxone Miniserver Gen 1 ist **Legacy-Hardware der ersten Generation** ohne **TLS-Support**, ohne **native Auth-Härtung** und ohne **neue Security-Features** (TLS, Remote Connect, Trusts gibt es nur ab Gen 2). Loxone hat das Gerät zwar nicht formal als EOL erklärt, Firmware-Updates kommen aber nur noch im Schneckentempo — der letzte bekannte Security-Patch war 2020 (CVE-2020-27488). Das ist die Definition eines "Legacy-Geräts, das auf der Netzwerkebene geschützt werden muss".

Dieses Gateway existiert, weil der Miniserver sich selbst nicht schützen kann.

---

## Scope & Design Invariants

Das sind bewusst gesetzte Grenzen für das **aktuelle (Gen-1-)** Deployment — was dieses Gateway leisten soll und was nicht. Sie gehören nur dann auf den Prüfstand, wenn sich die Hardware ändert (siehe "v2 / Gen 2" weiter unten).

1. **Remote-/Mobile-Zugriff läuft über das öffentliche Gateway — kein Client-VPN.** Geräte erreichen den Miniserver über den öffentlichen Listener des Gateways, nicht über ein VPN, einen Tunnel oder ein Relay auf dem Gerät selbst. Die Security-Obergrenze für diesen Pfad ist daher der Gateway-Stack: TLS + nginx Rate-/Connection-Limits + CrowdSec + AppSec WAF (+ optionales Geo-Blocking). Die native Loxone-App kann keine Client-Zertifikate vorweisen und an keiner Gateway-Layer-Auth teilnehmen (kein Cookie/OAuth/TOTP), eine Per-Device-Authentifizierung ist auf Gen 1 also nicht verfügbar.

2. **LAN und Trusted-Subnetze werden niemals geblockt.** Jedes vertrauenswürdige Netz muss in `CROWDSEC_WHITELIST_IPS` stehen — nicht nur das primäre `LAN_SUBNET`. Wenn ein vertrauenswürdiges Gerät das Gateway aus einem zweiten VLAN erreichen kann (z. B. via Inter-VLAN-Routing), muss auch dieses VLAN gewhitelistet sein, sonst kann das Gerät gebannt werden, obwohl es "intern" ist. Umgekehrt bleiben Gast-/IoT-Segmente bewusst außen vor: Sie sind untrusted und durchlaufen den vollen Security-Stack wie jeder Remote-Client.

3. **Härten auf der vorhandenen Hardware.** Ziel ist maximale Sicherheit auf dem bestehenden Gen-1-Miniserver, ohne neue Hardware zu kaufen. Natives TLS auf dem Miniserver, Remote Connect, Trusts und Per-User-/Per-Device-Identität sind Gen-2+-Features und werden auf ein künftiges "v2" mit neuer Hardware verschoben — hier explizit out of scope.

4. **Der Availability-Trade-off wird akzeptiert, nicht wegdesignt.** Weil Remote-Clients auf geteilten oder rotierenden IPs roamen (Mobilfunk-Provider, iCloud Private Relay / Cloudflare WARP), kann die CAPI-Community-Blocklist gelegentlich einen legitimen Nutzer wegen des Verhaltens eines anderen Tenants blocken — und eine rotierende IP lässt sich nicht vorab whitelisten. Wir behalten die Community-Blocklist wegen ihres Schutzwerts und lösen solche Fälle reaktiv (siehe "Legitimer Nutzer geblockt").

---

## Threat Model

### Wovor wir schützen

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| **Internet-Scanning / Reconnaissance** | Sicher | Hoch | nftables DROP per Default, Host/SNI-Gate + Trap (444, kein Fingerprint), HARD-Ban-Leiter (7 Tage → 90 Tage → 365 Tage), CrowdSec CAPI |
| **Brute Force gegen Web-UI** | Hoch | Kritisch | nginx Rate Limits, CrowdSec-Scenarios |
| **Application-Layer-DDoS** | Mittel | Hoch | nginx Connection-Limits, Timeouts, CrowdSec |
| **Volumetrischer DDoS** | Niedrig | Kritisch | *Am Gateway nicht stoppbar — nur ISP/Cloud* |
| **Credential Stuffing** | Hoch | Kritisch | Rate Limits + CrowdSec http-cve |
| **Ausnutzung von Loxone-CVEs** | Mittel | Kritisch | AppSec WAF (Virtual Patching), WAF-Regeln |
| **Lateral Movement (LAN → Miniserver)** | Niedrig | Hoch | Proxmox-Firewall, VLAN-Isolation |
| **Lateral Movement (LAN → Gateway via SSH)** | Niedrig | Kritisch | `setup_ssh_hardening` — CIS §5.2 Drop-in, Key-only, `PermitRootLogin no` (HARD-Modus, sobald ein sudo-fähiger Nicht-Root-User einen Key hat), `MaxAuthTries 4`, optional `SSH_ALLOW_USERS` |
| **Passives Abgreifen des Tokens auf dem Hop Gateway → Miniserver** | Niedrig | Hoch | *Klartext aus Notwendigkeit — Gen 1 kann kein TLS. Diesen Hop auf einem dedizierten VLAN/Link isolieren, damit der oben modellierte LAN-interne Angreifer das weitergereichte Loxone-Token nicht mitschneiden kann. Siehe Hinweis unten.* |
| **Passwort-Extraktion aus Config-Datei** | Mittel | Hoch | *Nur physische Zugangskontrolle* |
| **Cloud-DNS-Hijacking (CVE-2020-27488)** | Niedrig | Hoch | Cloud DNS abschalten, statische IP verwenden |

### Backend-Hop — Gateway → Miniserver ist Klartext

Das Gateway terminiert TLS auf `:1080` und proxyt **Klartext-HTTP** zum Miniserver auf `:80`, weil die Gen-1-Hardware kein TLS kann. Alles, was das Gateway weiterreicht — der Loxone-`gettoken`-HMAC, die Command-Query-Argumente und das **aktive Session-Token** — quert den Draht Gateway→Miniserver damit unverschlüsselt. Das Gateway hält keine eigene Session; es reicht das Loxone-Token nur durch, das Mitschneiden dieses Tokens auf diesem Hop entspricht also dem Übernehmen der Session. Das ist **derselbe LAN-interne Angreifer**, den die Lateral-Movement-Zeilen oben bereits modellieren (ein kompromittiertes IoT-Gerät, das im LAN pivotiert), und die Exposition lässt sich nicht im Code beseitigen (der Miniserver hat kein TLS). Die kompensierende Maßnahme ist **Netzwerk-Isolation**: den Pfad Gateway↔Miniserver auf ein dediziertes VLAN oder einen Punkt-zu-Punkt-Link legen, sodass kein nicht-vertrauenswürdiges LAN-Gerät dieselbe Broadcast-/Routing-Domäne teilt.

### SSH-Modell — nur LAN-seitig

Das Gateway exponiert `:22` ausschließlich gegenüber `SSH_ALLOWED_SUBNETS` via nftables. Aus dem Internet ist SSH auf diesem Host nie sichtbar — es gibt **keinen** `endlessh`-artigen Tarpit, weil es auf Port 22 keine öffentliche Angriffsfläche gibt, die ihn absorbieren müsste. Die Härtung greift ausschließlich im Inside-the-LAN-Angreifer-Szenario: ein kompromittiertes Laptop, Smart-TV oder IoT-Toaster, der vom LAN aufs Gateway pivotieren will. `deploy.sh` liefert ein CIS-Debian-12-§5.2-Drop-in (Key-only, VERBOSE-Log; Root-Login aus im HARD-Modus, sobald ein sudo-fähiger Nicht-Root-User mit Key existiert, sonst `prohibit-password` mit Warnung, damit du dich nie aussperrst) inklusive First-Deploy-Bootstrap, der das Lock-yourself-out-Henne-Ei-Problem verhindert (siehe `CONFIGURATION-GUIDE.md` → "SSH Key Bootstrap").

### Tunnel-Pfad (v2.0, optional) — wo die Durchsetzung lebt

Mit `ENABLE_TUNNEL=true` (siehe [`docs/TUNNEL-SETUP.de.md`](docs/TUNNEL-SETUP.de.md)) kommt externer Traffic über einen betreibereigenen Relay-VPS herein und erreicht das nginx des Gateways **über Loopback** (den frpc-Prozess). Drei Konsequenzen sind fürs Bedrohungsmodell relevant:

1. **Gateway-seitige nftables-Bans können getunnelte Angreifer nicht aussperren** — deren Pakete kreuzen nie das WAN-Interface des Gateways. Die Perimeter-Durchsetzung lebt deshalb auf dem **Relay** (eigenes CrowdSec + Firewall-Bouncer, von `install-relay.sh` standardmäßig installiert), wo die echte Quell-IP sichtbar ist. AppSec-WAF, Rate Limits und CrowdSec-*Erkennung* des Gateways greifen weiterhin für jede getunnelte Anfrage — echte Client-IPs werden via `X-Forwarded-For` wiederhergestellt, nur von Loopback vertraut, mit `real_ip_recursive off` (ein vom Client mitgeschickter Header kann die Quelle nicht fälschen). Der Firewall-Bouncer des Relays wirft gebannte Quellen auf *jedem* Port raus, den es bedient — auch dem frp-Control-Port. Ein Bann der gemeinsamen Haushalts-WAN-IP kappt damit Tunnel und Operator-SSH gleichzeitig. `RELAY_WHITELIST_IPS` ist das Relay-seitige Gegenstück zu `CROWDSEC_WHITELIST_IPS` am Gateway (siehe `CONFIGURATION-GUIDE.de.md` → "Haushalte hinter einer IP"); wie sein Gateway-Pendant unterdrückt es nur **lokal erzeugte** Decisions — CAPI-/Community-Blocklist-Decisions greifen bei einer gewhitelisteten IP weiterhin.
2. **Das Relay ist Angriffsfläche in eigener Hand.** Es folgt derselben Philosophie wie das Gateway: nftables Input-Drop, versionsgepinnte SHA256-verifizierte Binaries, gesandboxte systemd-Units, Unattended Upgrades, CrowdSec mit Community-Blocklisten. Ein kompromittiertes Relay kann externen Traffic beobachten und manipulieren (es terminiert TLS), besitzt aber keine Miniserver-Zugangsdaten und erreicht im LAN nichts außer dem einen getunnelten Port.
3. **Das Tunnel-Token ist ein Credential.** Wer es besitzt, kann einen fremden frpc mit dem Relay verbinden; `proxyBindAddr = 127.0.0.1` plus `allowPorts` begrenzen den Schaden auf das Kapern des einen Loopback-Ports (Denial of Service / Traffic-Interception am Relay). Auf beiden Seiten 0640 gespeichert; jährlich und bei jedem Verdacht rotieren.

frpc selbst läuft auf dem Gateway als dedizierter unprivilegierter Benutzer in einer strikten systemd-Sandbox (`ProtectSystem=strict`, leeres Capability-Set, `@system-service`-Syscall-Filter, `MemoryMax=256M`) — ein kompromittierter frpc-Prozess kann außerhalb seines Laufzeit-States nichts schreiben und nicht eskalieren.

### Was der Miniserver NICHT kann (Gen-1-Grenzen)

- Kein HTTPS/TLS (Hardware verkraftet die SSL-CPU-Last nicht)
- Kein WebSocket über WSS
- Passwörter in der Config-XML sind verschlüsselt, nicht gehasht — im Speicher entschlüsselbar
- Keine Multi-Faktor-Authentifizierung
- Keine Session-Timeout-Kontrollen
- Kein eingebautes Rate Limiting
- Keine IP-basierte Zugriffskontrolle
- Kein Audit-Logging
- Firmware-Updates kommen nur noch sehr langsam; der letzte bekannte Security-Patch war 2020 (Cloud-DNS-Lücke CVE-2020-27488). Neue Sicherheits-Features (TLS, Remote Connect, Trusts) gibt es nur ab Gen 2.

### Was das Gateway TUT

Das Gateway ist die **gesamte Security-Schicht**. Jeder Schutz, den der Miniserver vermissen lässt, wird hier implementiert.

---

## Architektur

```
Internet ──► Router:1080 ──► Gateway VM:1080 ──► Loxone:80
                    │              │
                    │              ├── nginx (proxy, rate limits, headers)
                    │              ├── CrowdSec (IDS, CAPI blocks, AppSec WAF)
                    │              ├── nftables (input DROP, allow :1080 + SSH)
                    │              ├── AppArmor (nginx-Profil: Complain → Enforce per Opt-in)
                    │              ├── auditd (config change monitoring)
                    │              ├── Discord alerts (real-time notifications)
                    │              └── Network watchdog (self-healing monitor)
                    │
                    └── LAN:<LAN_SUBNET> ──► Loxone:80 (direct, bypass)
```

---

## Implementierte Schutzmechanismen

### Layer 1: Network Firewall (nftables)

- Input Policy: **DROP**
- Erlaubter Inbound-Traffic: SSH (nur LAN + Site-to-Site), :1080 (jede Quelle)
- Forward Policy: DROP
- CrowdSec Bouncer verwaltet die dynamische `table ip crowdsec` für Live-Blocks
- Statische Regeln in `table inet filter` werden bei Reload nie überschrieben
- GeoIP-Drop-Sets (`@geoip_blocklist` für IPv4, `@geoip_blocklist6` für IPv6, `/etc/nftables.d/99-geoip.conf`): ipdeny.com-Listen für CN, RU, KP und IR, beim Deploy geladen und nachts um 03:00 Uhr von `geoip-block.sh` aktualisiert. Jede Liste wird mit Backoff erneut versucht und muss eine Prüfung bestehen, bevor sie die aktive ersetzen darf (nur CIDR-Zeilen, damit eine HTML-Fehlerseite nie in nftables landet; eine Mindestanzahl; nicht mehr als 50 % kleiner als die letzte gültige Liste). Scheitert eine Liste, bleibt das letzte gültige Set geladen, und der Grund je Land (curl-Fehler, HTTP-Status, Prüfung) steht in `/var/log/loxprox-cron.log`. Ist die Liste seit 3 Tagen nicht aktualisiert, gibt es eine Discord-WARNING und einen Eintrag in der "Was zu tun ist"-Liste des Panels; die IPv6-Liste hat eigene Zeitstempel und einen eigenen Alert. `GEOIP_IPV6_ENABLED="false"` leert das IPv6-Set (nur noch IPv4). Hinweis: Ein gesperrtes Land sperrt auch den eigenen Zugriff von dort (Reisen).
- Egress-Beschränkung (Output-Chain-Regeln mit dem Kommentar `loxprox-egress`): Die Policy bleibt accept, weil root ausgehenden Verkehr für acme.sh, apt, die CrowdSec-CAPI und Discord braucht. Der nginx-Worker (`www-data`) — der Prozess mit Internetkontakt — darf nur Loopback (die AppSec-Komponente) und den Miniserver erreichen, sonst nichts; alles andere wird verworfen und höchstens begrenzt geloggt. Ein kompromittierter Worker kann nicht ins LAN pivotieren oder nach Hause telefonieren.

### Layer 2: Reverse Proxy (nginx)

- Rate Limit: 10 req/s pro IP, Burst 100
- Connection Limit: 20 gleichzeitig pro IP
- Slowloris-Schutz: aggressive Timeouts (10–15 s)
- Security Headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, **Content-Security-Policy**, **Permissions-Policy**
- **Host/SNI-Gate (TLS-Modus).** `:1080` bedient nur `TLS_DOMAIN` plus `EXTRA_SERVER_NAMES`. Eine Anfrage für alles andere — eine nackte IP, kein SNI, ein fremder `Host` (so verbinden sich Crawler wie Shodan/Censys) — landet in einem Trap-Default-Server: ein selbstsigniertes `CN=invalid`-Zertifikat, damit der Handshake durchläuft, dann `444` (Verbindung geschlossen, kein einziges Byte Fingerprint) und ein Eintrag in `/var/log/nginx/loxprox-trap.log`. `:80` verhält sich genauso; nur der echte Name behält seinen ACME-HTTP-01-Challenge-Pfad. Klartext-`http://` auf `:1080` für den echten Namen bekommt weiter den 301-Gnadenredirect auf `https://`. **Folge: Jede App und jedes Gerät muss den Hostnamen mit `https://` benutzen, nie die IP** — ein Zugriff über die IP ist ein Trap-Treffer und wird gebannt (HARD-Leiter).
- **Trap-Ausnahme (`TRAP_EXEMPT_IPS`, Default leer).** Für einen bekannten Dienst, der die nackte IP abfragt, etwa einen Cloud-Probe eines Herstellers. Ausgenommene Quellen landen nie in den Trap-Logs, und die CrowdSec-Whitelist `loxprox/trap-exempt` hält jedes lokale Scenario davon ab, für sie zu alarmieren oder sie zu bannen (Community-Blocklist-Decisions greifen weiter). Im TLS-Modus bekommt ihr Klartext-Request an `:1080` den 301 des echten Servers auf `https://<TLS_DOMAIN>:1080`; alles andere auf den Trap-Servern bleibt eine `444`. Ausgenommen heißt **nicht vertrauenswürdig**: Diese Quellen stehen nicht im nginx-Geo `$loxprox_lan`, für sie gelten also die Rate-Limits, die Auth-/WebSocket-Limits und die Admin-/Unknown-Sperren. `deploy.sh` lehnt einen Eintrag ab, der vertrauenswürdig ist oder in einem vertrauenswürdigen Netz liegt.
- **Pfadklassen.** Jede Anfrage fällt in genau eine Klasse: *Trap*-Pfade (`/.env`, `/.git`, `*.php`, `/wp-*`, `/cgi-bin/`, `/vendor/phpunit`, `/HNAP1`, `/boaform`, `/actuator`) und die Methoden `CONNECT`/`TRACE`/`TRACK`/`PROPFIND` bekommen `444`, Trap-Log und einen HARD-Ban; *Admin*-Webservices: Die einfachen Pfade der Dateisystem- und Systemsteuerungs-Befehle (etwa `fsget`, `fsdel`, `sys/reboot`, `sps/restart`) werden aus dem Internet mit `403` beantwortet, solange `REMOTE_ADMIN_PATHS="deny"` gilt (Default; LAN und `CROWDSEC_WHITELIST_IPS` sind ausgenommen). Kein LoxProx-Scenario bannt wegen eines 403, aber wiederholte 403/404 zählen weiter für das Standard-Scenario `crowdsecurity/http-probing`, das zu einem SOFT-Ban führen kann. Das filtert nur einfache HTTP-Pfade: Dieselben Befehle können den Miniserver weiter in der verschlüsselten Befehlsform (`jdev/sys/enc` / `fenc`) oder über den authentifizierten WebSocket erreichen — die eigenen Zugangsdaten des Miniservers bleiben die eigentliche Kontrolle; *App*-Pfade werden durchgereicht; *unbekannte* Pfade werden durchgereicht und in `/var/log/nginx/loxprox-unknown.log` geschrieben (`UNKNOWN_PATH_MODE="log"`, die Lernphase) oder mit einem lokalen `404` beantwortet (`"deny"`). Die Trap-Prüfung läuft vor den Rate-Limits und dem AppSec-Subrequest — ein Scanner-Pfad kostet also nie einen WAF-Roundtrip.
- Authentifizierungs-Endpoints (`getkey`, `getjwt`, `gettoken`, `authwithtoken`, `refreshjwt`) sind auf 3 Req/s pro nicht vertrauenswürdiger Adresse begrenzt (Burst 30), und pro nicht vertrauenswürdiger Adresse sind höchstens 6 gleichzeitige `/ws/`-Verbindungen erlaubt. LAN und `CROWDSEC_WHITELIST_IPS` werden nie mitgezählt.
- `server_tokens off` (seit dem Härtungs-Release 2026-10 im http-Block gesetzt — **frühere Fassungen dieses Dokuments behaupteten es, obwohl nichts es setzte, das Gateway antwortete also mit `Server: nginx/<Version>`**; die Zeile entfällt nur, wenn du `server_tokens` selbst in der `nginx.conf` gesetzt hast); `proxy_hide_header Server` und `proxy_hide_header X-Powered-By`, damit keine Backend-Versionen leaken
- Die eigenen Kopien des Miniservers von den Headern, die das Gateway selbst setzt (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, CSP, `Permissions-Policy`, HSTS), und sein veraltetes `X-XSS-Protection` werden per `proxy_hide_header` verworfen — jeder Security-Header kommt genau einmal beim Client an. Das `X-Frame-Options: deny` des Miniservers neben dem `SAMEORIGIN` des Gateways war ein widersprüchliches Paar
- Buffer-Limits gegen Memory Exhaustion
- AppSec-Subrequest: jeder Request wird von der CrowdSec WAF geprüft, bevor er weitergeproxyt wird

### Layer 3: Intrusion Detection (CrowdSec)

- CAPI-Community-Feed: ~26k bekannte Bad IPs werden automatisch geblockt
- Lokale Scenarios: nginx Bad Requests, SSH-Brute-Force, HTTP-CVEs
- AppSec WAF: Virtual Patching für bekannte CVEs, SQLi, XSS, Path Traversal
- **Zwei Ban-Leitern** (`/etc/crowdsec/profiles.yaml`, von `deploy.sh` verwaltet; das Original bleibt als `profiles.yaml.loxprox-orig` erhalten): Scenarios, die auf `BAN_HARD_SCENARIOS` passen — die eindeutigen Scanner-Scenarios (CVE-/Virtual-Patching-Probes, Probing auf sensible Dateien, Backdoors, Path Traversal und Admin-Interfaces, Open-Proxy-Probing sowie der Trap) —, bannen mit `BAN_HARD_LADDER` = 7 Tage, dann 90 Tage, dann 365 Tage. Alles andere nutzt `BAN_SOFT_LADDER` = 24 Stunden, 7 Tage, 30 Tage, 90 Tage. `progressive-ban.py` (Cron alle 15 Minuten, unter `flock`) verlängert Wiederholungstäter entlang der Leiter und verkürzt nie einen Ban. Seine Verlängerungen tragen den Grund `repeat-offender-hard-<n>` (HARD) bzw. `repeat-offender-<n>` (SOFT).
- **Ein Jahr Offence-Gedächtnis**: Vergehen zählen innerhalb von `PROGRESSIVE_BAN_WINDOW_DAYS` (365). Der Paket-Default von CrowdSec vergaß jeden Alert nach 7 Tagen (und nach 5000 Alerts), ein wiederkehrender Scanner begann also immer ganz unten; `config.yaml.local` hält die Alert-Historie jetzt mindestens 400 Tage vor.
- **Drei LoxProx-Scenarios** (`crowdsec/scenarios/`, installiert nach `/etc/crowdsec/scenarios/`): `loxprox/scanner-trap` (ein Treffer im Trap-Log löst einen HARD-Ban aus; mit `TRAP_BAN_MODE="observe"` läuft es für den ersten Rollout in der Simulation und alarmiert nur), `loxprox/unknown-path` (sechs verschiedene unbekannte Pfade von einer Adresse; SOFT-Leiter) und `loxprox/auth-bf` (Burst von Loxone-Authentifizierungs-Anfragen; SOFT-Leiter). Die letzten beiden laufen in diesem Release im CrowdSec-**Simulationsmodus** — sie alarmieren, bannen aber nicht —, bis ihre Schwellen an echtem Roaming-Handy-Verkehr geprüft sind (`unknown-path` wird nur simuliert, solange `UNKNOWN_PATH_MODE="log"` gilt).
- Täglicher Hub-Refresh (04:30, `hub-refresh.sh`), das einzige unbeaufsichtigte Hub-Update. Er aktualisiert alle installierten Hub-Einträge (`cscli hub upgrade`, nie `--force`). Das ist dieselbe tägliche Aktualität wie bei CrowdSecs eigenem Timer: Neue Ban-Szenarien und Virtual Patches (so kommen neue CVEs in den WAF) kommen weiter jede Nacht an. CrowdSec lädt er nur neu, wenn sich die Version eines Eintrags geändert hat. In Kauf genommen: Eine Parser- oder Scenario-Änderung von upstream kann ohne Prüfung ändern, was gebannt wird. Lokal veränderte („tainted“) Einträge bleiben unangetastet und werden per Discord gemeldet (*CrowdSec Hub Items Not Upgraded*), einmal je Änderung dieser Liste. Vor dem Upgrade sichert er den Hub dort, wo CrowdSec ihn laut `cscli config show` führt, als Snapshot (die letzten 7 liegen in `/var/lib/loxprox/hub-snapshots/`). Er aktualisiert nichts, solange der Snapshot nicht den Hub-Index und die Datei jedes installierten Eintrags enthält; dann kommt stattdessen eine WARNING *CrowdSec Hub Snapshot Failed*. Kommt CrowdSec nicht wieder hoch, rollt er zurück, mit einer CRITICAL *CrowdSec Rule Update Rolled Back*, *CrowdSec Down — Gateway Serving Errors* oder *CrowdSec Rule Rollback Failed*, die die geänderten Einträge nennt. Der paketeigene `crowdsec-hubupdate.timer` von CrowdSec, der jede Nacht alle installierten Hub-Einträge ohne Snapshot und ohne Rollback aktualisierte, wird von `deploy.sh` maskiert.
- Whitelist: LAN, Site-to-Site, Uptime-Monitor, Heroku-Prowl-IPs
- **Jedes Log wird genau einmal eingelesen** (`/etc/crowdsec/acquis.d/`): `nginx.yaml` liest die Access- und Error-Logs des Gateways und nginx' eigene `access.log`/`error.log` (dorthin schreibt der ACME-Server auf `:80`), `loxprox.yaml` die Trap- und Unknown-Path-Logs; `loxprox-trap-hosts.log` wird nicht gelesen. SSH kommt aus dem Journal von sshd (`ssh.yaml`, Unit `ssh.service`), denn Debian 12 hat ohne rsyslog kein `/var/log/auth.log`. `deploy.sh` deaktiviert die paketeigenen `setup.nginx.yaml` und `setup.sshd.yaml` von CrowdSec, die dieselben Logs ein zweites Mal lasen (sie bleiben als `*.loxprox-disabled` erhalten): Ein doppelt gelesenes Log las CrowdSec nach dem nächtlichen Logrotate nicht mehr. `test-gateway.sh` prüft, dass jedes Log genau einmal eingelesen wird

### Layer 4: Application Security (AppSec WAF)

- Modus: `APPSEC_MODE` — **enforce** (Default, geblockte Requests werden mit 403 abgewiesen) oder **monitor** (alarmiert via `cscli alerts list`, blockiert nie; zum Prüfen auf False Positives vor dem Wechsel zu enforce)
- Collection: `crowdsecurity/appsec-virtual-patching` (200+ CVE-spezifische Regeln)
- Lauscht auf `127.0.0.1:7422`
- Prüft jeden Request, bevor er Loxone erreicht
- **Authentifizierung**: AppSec verlangt den API-Key des CrowdSec Firewall Bouncers im Header `X-Crowdsec-Appsec-Api-Key`
- **Pflicht-Header**: `X-Crowdsec-Appsec-Ip`, `X-Crowdsec-Appsec-Uri`, `X-Crowdsec-Appsec-Verb`
- Der nginx-`auth_request`-Subrequest setzt diese Header automatisch via `/etc/nginx/crowdsec-appsec.conf`
- **Risiko-Hinweis**: Der AppSec-API-Key liegt in `/etc/nginx/crowdsec-appsec.conf` (Mode 640, root:www-data). Falls ein Angreifer lokales File-Read erreicht (z. B. via LFI in Loxone oder einen kompromittierten nginx-Worker), kann er den Key extrahieren und die WAF umgehen. Das ist ein bekanntes, akzeptiertes Risiko dieser Architektur. Mitigation: Loxone und nginx vollständig patchen; alternativ systemd `LoadCredential=` für reine Memory-Secret-Injection (benötigt njs/Lua in nginx).
- **Verhalten bei Bootstrap-Fehler**: Lässt sich die AppSec-Komponente beim Deploy nicht hochfahren (z. B. lehnt CrowdSec die Config ab), installiert `deploy.sh` einen Pass-Through-Stub anstelle der WAF-Integration, statt nginx bei jedem Request mit 500 antworten zu lassen — der Traffic fließt weiter, nur ohne WAF-Inspektion, und der Lauf beendet sich mit Exit-Code `3`, um die Degradation zu kennzeichnen. CrowdSecs IP-Level-Erkennung (Layer 3) und der Firewall-Bouncer sind davon nicht betroffen — nur die Inhaltsprüfung der Requests ist aus, bis ein erneuter Lauf die Ursache behebt.
- AppSec-Metriken: `cscli metrics | grep -A3 Appsec`

### Layer 5: System Hardening

- AppArmor: nginx-Profil (`apparmor/usr.sbin.nginx`), bei jedem Deploy im **Complain-Modus** geladen — Verstöße werden protokolliert, nicht blockiert —, bis du nach dem Soak aus [ADR 0006](docs/adr/0006-apparmor-nginx-profile-complain-first.md) `APPARMOR_NGINX_MODE="enforce"` in `deploy.conf` setzt
- systemd: PrivateTmp, NoNewPrivileges, ProtectKernelTunables etc.
- Kernel: syncookies, rp_filter, dmesg_restrict, kptr_restrict, ASLR
- auditd: überwacht Config-Änderungen an nginx/crowdsec/nftables, Auth-Dateien, sudo und den eigenen Zustand von LoxProx — `/etc/loxprox` (Config, TLS), `/etc/apparmor.d` (Policy) und die als root laufenden Scripts unter `/opt/loxprox`
- unattended-upgrades: Auto-Reboot um 03:00 für Kernel-Patches. Die Quellen werden über Codename und Label (`Origins-Pattern`) erkannt, nicht über den Archivnamen: Die alte archivbasierte Form passte auf nichts mehr, seit Debian 12 oldstable wurde (das Security-Archiv heißt jetzt `oldstable-security`) — Sicherheitsupdates waren auf vor diesem Release deployten Gateways still ausgefallen. Das CrowdSec-Paket-Repository ist bewusst ausgenommen — CrowdSec-Upgrades werden von Hand eingespielt (der Monitor meldet, wenn eines verfügbar ist)
- SSH-HARD-Modus (`--finalize-ssh`): `PermitRootLogin no` nur, wenn ein Nicht-Root-Konto einen Authorized Key, sudo-Rechte (`sudo`/`wheel`/`admin`) und eine Login-Shell hat; sonst bleibt es mit Warnung bei `prohibit-password`, damit der Schritt dich nie aussperren kann. `--finalize-ssh` liest `deploy.conf`, daher gilt auch das optionale `SSH_ALLOW_USERS` dort: Es schreibt eine `AllowUsers`-Zeile, die (mit Warnung) verweigert wird, wenn kein gelistetes Konto eine Login-Shell hat (im HARD-Modus zusätzlich einen Key)

### Layer 6: Monitoring & Alerting

- **Discord-Webhook**: Echtzeit-Alerts für Blocks, Anomalien, Service-Failures
- **Security Monitor** (60-Sek-Zyklus): CrowdSec-Decisions, nginx-Fehler, Auth-Versuche, AppSec-Detections, System-Ressourcen
- **Alerts der Breach-Härtung** (gleicher 60-Sek-Zyklus, alle per Discord): *Remote Session From a New ASN* (ein Remote-Client auf dem Loxone-Port aus einem bisher unbekannten Providernetz; in den ersten `ASN_LEARNING_DAYS` Tagen wird nur gelernt; abschaltbar mit `SESSION_ALERT_ENABLED="false"`; Client-Adressen sind im Alert maskiert), *Firewall Integrity Failure* (Input-Policy, GeoIP-Sets oder `loxprox-egress`-Regeln fehlen — ein älteres Deploy, dem nur die neuen Elemente fehlen, löst stattdessen eine WARNING aus), *Security Updates Not Installing* (ein Debian-Security-Update steht länger als `SEC_UPDATE_MAX_AGE_DAYS` aus), *CrowdSec Update Available* (nur Info), *High Loxone Auth Request Rate* (mehr als `AUTH_RATE_ALERT_PER_CYCLE` Anfragen für `getkey`/`getkey2`/`getjwt`/`gettoken`/`authwithtoken`/`refreshjwt`, in der `jdev/`- und der `dev/`-Schreibweise, alle Clients zusammen, in einem Zyklus) und *GeoIP IPv6 Blocklist Stale*. Die Inhaltsprüfung der Firewall-Sets läuft stündlich; Input-Policy und Egress-Regeln werden in jedem Zyklus geprüft. *New CrowdSec Ban* betrifft nur SOFT-Bans (höchstens 15 Einträge pro Nachricht); HARD-Bans fasst ein täglicher *Daily HARD Ban Digest* zusammen (INFO, 08:00, auch bei Anzahl 0; im Observe-Modus mit der Zahl beobachteter Trap-Treffer und einer Prüfzeile)
- **Wächter für das Log-Lesen von CrowdSec** (gleicher 60-Sek-Zyklus): Meldet CrowdSec, dass ein Log-Reader gestorben ist, oder wächst ein überwachtes Log (Access, Trap, Unknown-Path) dreimal, ohne dass CrowdSec etwas davon liest, startet der Monitor crowdsec neu und schickt *CrowdSec Log Reading Stopped — Restarted* (WARNING, mit Log und Zeitpunkt). Er startet höchstens einmal pro Stunde neu und nur auf diesen Befund hin, denn AppSec beantwortet während der Sekunden eines Neustarts jede Anfrage mit 500. Eine Wiederholung innerhalb der Stunde meldet er als *CrowdSec Log Reading Still Stopped* (HIGH), ohne Neustart; kommt crowdsec nicht wieder hoch, *CrowdSec Down After a Log-Reading Restart* (CRITICAL)
- **Network Watchdog** (60-Sek-Zyklus): erkennt Netzwerk-Layer-Ausfälle (dhclient-Death-Spiral, Kernel-Routing-Korruption, Interface-Desync), die Prozess-Level-Checks nicht sehen. Selbstheilung per Service-Restart; Reboot als letzte Maßnahme mit Pre-/Post-Reboot-Discord-Reporting und Anti-Loop-Schutz. Ein `502`/`504` vom lokalen nginx beweist, dass **der Listener lebt** (nur der Miniserver dahinter antwortet nicht) — das zählt daher als gesund und löst nie Heal oder Reboot aus. Ein Miniserver-Ausfall löst stattdessen einen eigenen, nur alarmierenden "Miniserver nicht erreichbar"-Hinweis aus, mit Recovery-Meldung, sobald er wieder antwortet. Im TLS-Modus prüft der Watchdog `:1080` unter dem echten Hostnamen (auf Loopback aufgelöst), weil das Host/SNI-Gate eine Anfrage für `127.0.0.1` mit `444` beantwortet. Während eines Deploys im TLS-Modus ist der Watchdog-Timer abgeschaltet und wird am Ende wieder scharf gestellt; ein vorzeitig beendeter Lauf meldet `network-watchdog → NOT ARMED` — `sudo bash deploy.sh` erneut ausführen, den Timer nicht von Hand starten.
- **Log-Rotation**: 90 Tage Aufbewahrung für die nginx-Access-, Trap- und Unknown-Path-Logs (das forensische Fenster für eine jahrelange Offence-Historie), 14 Tage für die nginx-Error- und AppSec-Logs; die LoxProx-eigenen `/var/log/loxprox-*.log` wöchentlich bzw. ab 10 MB, 8 komprimierte Generationen; das systemd-Journal ist auf 300 MB begrenzt
- **Wächter für geplante Jobs**: Der Health Check von `deploy.sh` und `test-gateway.sh` schlagen fehl, wenn cron `/etc/cron.d/loxprox` seit dem letzten Schreiben abgelehnt hat — cron ignoriert eine abgelehnte Datei komplett, Progressive Ban, das tägliche Backup und das GeoIP-Refresh würden sonst still stehenbleiben
- **Config-Backup**: tägliches automatisches Backup nach `/root/loxprox-backups/`
- **Test-Suite**: `sudo ./test-gateway.sh` validiert alle Komponenten nach dem Deploy

---

## Was noch hinzukommen könnte (Future Hardening)

### Fail2ban (redundant, aber zusätzliche Schicht)
- SSH: max. 3 fehlgeschlagene Logins in 10 Min = 1 Stunde Ban
- nginx: 404-Scanning-Erkennung
- Status: Nicht installiert — CrowdSec macht das nativ

### TLS-Termination auf :1080 (ab v1.5.0 ausgeliefert, opt-in)

Der Miniserver selbst kann nach wie vor kein TLS (Gen-1-CPU-Constraint — unverändert), das No-TLS-Gerät hinter dem Gateway bleibt also architektonische Realität. Was sich in v1.5.0 geändert hat: **das Gateway kann jetzt HTTPS auf `:1080` zur öffentlichen Seite terminieren** via `acme.sh` + HTTP-01, mit automatischem Renewal-Cron, der nach jedem Deploy verifiziert wird. Der acme.sh-Installer ist per SHA256 gepinnt (kein `curl|bash`), das ausgestellte Cert liegt in `/etc/loxprox/tls/` (Mode 0640), und die öffentliche Angriffsfläche wächst um exakt einen Listener — `:80`, eingeschränkt auf `/.well-known/acme-challenge/` plus einen 301-Redirect nach HTTPS-on-1080. Per Default aus; geschaltet durch einen einzigen `ENABLE_TLS`-Key in `/etc/loxprox/deploy.conf`. Der Disable-Pfad setzt die Site zurück und bricht den Renewal-Cron ab, behält aber die Cert-Dateien — das Zurückschalten geht entsprechend schnell. Vollständiges Runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).

### Volumetric DDoS Protection
- **An diesem Gateway nicht machbar** — 1 GB RAM / 1 vCPU
- Optionen: Cloudflare Spectrum, AWS Shield, ISP-Level-Scrubbing
- Status: dokumentierte Limitierung

### Netzwerk-Segmentierung
- Loxone in ein isoliertes VLAN setzen
- Gateway in DMZ-VLAN
- Firewall-Regeln: nur Gateway-IP → Loxone:80
- Status: erfordert Änderungen an Router/Proxmox

### Honeypot-Endpoints
- Mit dem Härtungs-Release 2026-10 als Scanner-Trap ausgeliefert (siehe Layer 2 und Layer 3): Scanner-Pfade, fremde Host/SNI-Werte und Scanner-Methoden enden in `loxprox-trap.log` und einem HARD-Ban
- Keine Fake-Login-Seite: Kein Loxone-Endpoint passt auf einen Trap-Pfad, und der Trap antwortet mit `444` statt mit einem Köder

---

## Operative Kommandos

```bash
# Alle Komponenten prüfen
sudo bash test-gateway.sh

# CrowdSec-Decisions anzeigen
sudo cscli decisions list

# CrowdSec-Alerts anzeigen
sudo cscli alerts list

# AppSec-Metriken anzeigen
sudo cscli metrics | grep -A3 Appsec

# nftables-Regeln anzeigen
sudo nft list ruleset

# Live-nginx-Access-Log
sudo tail -f /var/log/nginx/loxone-access.log

# Monitor-Log anzeigen
sudo tail -f /var/log/loxprox-monitor.log

# IP manuell bannen
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual-ban"

# IP entbannen
sudo cscli decisions delete --ip 1.2.3.4

# Vollständigen Deploy nochmal laufen lassen
sudo bash deploy.sh
```

---

## Incident-Response-Playbook

### Gateway antwortet nicht mehr

1. Proxmox-Konsole prüfen: `systemctl status nginx crowdsec`
2. Wenn überlastet: Router-Forwarding wieder direkt auf die Loxone-IP umstellen
3. Logs später analysieren, Gateway wiederherstellen, erneut umschalten

### Legitimer Nutzer geblockt

1. `cscli decisions list` → IP heraussuchen
2. `cscli decisions delete --ip <IP>`
3. Bei Wiederholung **und stabiler IP** in die Whitelist eintragen (ein festes LAN-/VLAN-Subnetz, ein statisches Remote-Office o. Ä.)

**Roaming-/Shared-Egress-Clients (Mobil).** Ein Remote-Nutzer im Mobilfunknetz, hinter iCloud Private Relay oder Cloudflare WARP geht über eine geteilte, rotierende IP raus (z. B. `104.28.x.x` für Private Relay). Die CAPI-Community-Blocklist kann eine solche IP wegen des Verhaltens eines *anderen* Tenants listen und so deinen Nutzer ohne dessen Verschulden blocken. Eine rotierende IP lässt sich nicht vorab whitelisten — es gibt kein stabiles Ziel. Das ist ein akzeptierter Trade-off, wenn man die Community-Blocklist auf einem öffentlichen No-VPN-Pfad aktiv lässt (siehe "Scope & Design Invariants"). Behandle es reaktiv mit Schritt 2; wird ein vertrauenswürdiger Nutzer wiederholt getroffen, rate ihm, Private Relay / WARP zu deaktivieren, damit er eine stabilere Carrier-IP vorweist.

> **Kein Ban — die `https://`-Migrationsfalle.** Wenn eine Loxone-App "keine Verbindung" bekommt, `cscli decisions list` aber **keine** Decision für ihre IP zeigt, liegt es fast immer am TLS-Schema und nicht an einem Block. Siehe "Die Loxone-App verbindet sich nach dem Aktivieren von TLS nicht mehr" in `CONFIGURATION-GUIDE.md` (im deutschen Dokument: CONFIGURATION-GUIDE.de.md).

> **Ein Ban nach dem Härtungs-Release heißt meist: IP statt Hostname.** Im TLS-Modus trifft eine App oder ein Gerät, das mit der IP-Adresse des Gateways (oder einem Hostnamen außerhalb von `TLS_DOMAIN` / `EXTRA_SERVER_NAMES`) konfiguriert ist, den Trap und wird schon bei der ersten Anfrage mit der HARD-Leiter gebannt — 7 Tage, dann 90, dann 365. Ban aufheben (Schritt 2), dann die Verbindung mit `https://<deine-domain>:1080` neu anlegen. Auch die einfachen Admin-Webservice-Pfade werden aus dem Internet jetzt mit `403` beantwortet (`REMOTE_ADMIN_PATHS="deny"`; wiederholte 403 können weiter `crowdsecurity/http-probing` füttern, ein SOFT-Ban) — konfiguriere aus dem LAN oder setze `REMOTE_ADMIN_PATHS="allow"`, wenn du es brauchst.

### Loxone von außen nicht erreichbar

1. Router-Forwarding prüfen: extern 1080 → `<GATEWAY_IP>:1080`
2. Gateway-Status prüfen: `systemctl status nginx`
3. Gateway → Loxone-Erreichbarkeit prüfen: `curl http://<LOXONE_IP>:80/jdev/cfg/api`
4. Den Gateway-Listener auf dem Gateway selbst prüfen. Im TLS-Modus mit dem echten Namen — eine Anfrage für `127.0.0.1` trifft den Trap: `curl --resolve <domain>:1080:127.0.0.1 https://<domain>:1080/jdev/cfg/api`
5. nginx-Error-Log auf Backend-Timeouts prüfen
6. Test-Suite laufen lassen: `sudo bash test-gateway.sh`

### Discord-Webhook-Rotation

Wenn eine Webhook-URL kompromittiert ist oder Credentials rotiert werden müssen:
1. In Discord: Server-Einstellungen → Integrationen → Webhooks → alten Webhook löschen
2. Neuen Webhook anlegen und die URL kopieren
3. `DISCORD_WEBHOOK_URL` in `/etc/loxprox/config.env` aktualisieren
4. `deploy.sh` erneut ausführen oder den Monitor-Timer neu starten: `systemctl restart loxprox-monitor.timer`
5. Verifizieren: Test-Alert auslösen (z. B. `sudo /opt/loxprox/discord-alert.sh INFO "Test" "Rotation verified"`)

**Hinweis**: Die Webhook-URL liegt in `/etc/loxprox/config.env` mit Mode 640. Nur root und die Gruppe `loxprox` können sie lesen.

### AppSec liefert 401-Fehler

Wenn im nginx-Log AppSec-401-Fehler auftauchen, hat sich vermutlich der Bouncer-API-Key geändert:
1. Aktuellen Key auslesen: `awk '/^api_key:/ {print $2}' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local`
2. `/etc/nginx/crowdsec-appsec.conf` mit dem neuen Key aktualisieren
3. `sudo nginx -s reload`
4. Oder einfach `deploy.sh` erneut laufen lassen — der regeneriert die Include-Datei automatisch

---

## Compliance-Hinweise

- **Keine GDPR/Privacy-Compliance** auf dem Miniserver selbst — Logs enthalten IP-Adressen
- Gateway-Logs enthalten Quell-IPs (für die Security-Analyse erforderlich)
- Discord-Alerts enthalten IP-Adressen und Request-Details
- Aufbewahrung: 90 Tage für die nginx-Access-, Trap- und Unknown-Path-Logs, 14 Tage für die nginx-Error- und AppSec-Logs, System-Logs werden von journald verwaltet; CrowdSec hält seine Alert-Historie (Quelladressen und Scenarios) mindestens 400 Tage vor, um Wiederholungstäter zu erkennen
