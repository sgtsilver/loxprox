**Sprache:** Deutsch · [English](INSTALL-FOR-NEWBIES.md)

# Installation für Linux-Einsteiger

**Du hast einen Loxone Miniserver, kennst dich aber mit Linux kaum aus? Kein Problem. Wir urteilen nicht und halten niemanden draußen — folge einfach Schritt für Schritt mit.**

Jeder fängt mal an. Wer einem Kochrezept folgen kann, schafft auch das hier. Du kopierst eine Handvoll Befehle, tippst ein paar eigene Zahlen ein, und am Ende sitzt dein Miniserver hinter einem richtigen Sicherheits-Gateway, statt offen im Internet zu stehen. Keine Linux-Vorkenntnisse nötig. Lass dir Zeit. Dumme Fragen gibt es hier nicht.

> Wenn ein Wort gruselig aussieht, spring ans **[Glossar in einfacher Sprache](#glossar-in-einfacher-sprache)** ganz unten — dort ist jeder Fachbegriff übersetzt.

---

## Was am Ende dabei herauskommt

Ein kleiner, dauerhaft laufender Computer (eine virtuelle Maschine oder ein Raspberry Pi), der **zwischen dem Internet und deinem Miniserver** sitzt. Die Außenwelt spricht mit dem Gateway; das Gateway prüft alles und lässt nur sicheren Verkehr zum Miniserver durch. Deine Handy-App funktioniert weiter wie bisher — sie verbindet sich nur zum Gateway statt direkt zum Miniserver.

```
Internet  →  dein Router  →  LoxProx-Gateway  →  dein Loxone Miniserver
                             (Firewall, Rate-Limits,
                              Angriffserkennung, HTTPS)
```

## Was du brauchst

- **Einen kleinen Computer dafür.** Drei einfache Optionen — nimm, was du schon hast (Details in [Schritt 1](#schritt-1--einen-kleinen-computer-besorgen)):
  - eine **virtuelle Maschine** auf einem Proxmox-/Heimserver, oder
  - einen **Raspberry Pi 3, 4 oder 5** (mit 64-bit Raspberry Pi OS), oder
  - irgendeinen **alten Mini-PC oder Laptop**, den du löschen und mit Debian neu aufsetzen kannst.
- **Die Daten deines Miniservers** — dafür gibt es ein Tool, das sie für dich findet. Kein Stress, wenn du sie noch nicht kennst.
- **Etwa 30–45 Minuten** und einen Kaffee.
- Mehr nicht. Du musst **kein** Programmierer sein.

Zur Größe: 1 CPU und **1 GB RAM** ist das Minimum; **2 CPU / 2 GB** ist komfortabel. Etwa 5 GB Festplatte.

> ⚠️ **Eine Regel:** Nimm eine echte virtuelle Maschine oder einen echten Pi — **kein** „LXC-Container". In einem Container funktionieren einige Schutzmechanismen still und heimlich nicht, und du würdest dich geschützt wähnen, obwohl du es nicht bist. Falls dieser Satz dir nichts gesagt hat: perfekt — dann benutzt du keinen. Weiter geht's.

---

## Schritt 1 — Einen kleinen Computer besorgen

Du brauchst nur *irgendetwas*, auf dem **Debian 12** läuft (eine beliebte, kostenlose, grundsolide Linux-Version). Wähle den Weg, der zu dir passt:

- **Du hast einen Proxmox- oder anderen Heimserver →** lege eine neue VM an, gib ihr 1–2 CPUs, 1–2 GB RAM, ~5 GB Disk und installiere Debian 12. (Proxmox hat sogar eine „Debian 12"-Vorlage.)
- **Du hast einen Raspberry Pi →** flashe **64-bit Raspberry Pi OS Lite** auf die SD-Karte mit dem offiziellen [Raspberry Pi Imager](https://www.raspberrypi.com/software/). Ein Pi 3/4/5 reicht locker.
- **Du hast einen alten PC/Laptop →** lade Debian 12 von [debian.org](https://www.debian.org/distrib/), schreibe es auf einen USB-Stick und installiere es. Der Debian-Installer nimmt dich an die Hand.

Bei der Installation kannst du einfach die Standardwerte übernehmen. Nur eines merken: **Schreib dir Benutzername und Passwort auf, die du anlegst.**

> Nichts davon zur Hand? Ein Raspberry Pi 4 ist der günstigste, freundlichste Einstieg und verbraucht kaum Strom.

## Schritt 2 — Zum „Terminal" kommen

Das **Terminal** (auch „Kommandozeile" oder „Shell") ist nur ein Textfeld, in das du Befehle tippst. In Filmen wirkt es einschüchternd; in Wirklichkeit ist es ein sehr geduldiger Assistent, der genau das tut, was du ihm sagst.

Zwei Wege dorthin:

- **Auf einem Pi / Mini-PC mit Bildschirm und Tastatur:** melde dich direkt dort an. Der schwarze Bildschirm *ist* das Terminal.
- **Von deinem normalen Computer übers Netzwerk (empfohlen):** per **SSH**. Auf einem Mac oder Linux-Rechner öffnest du die Terminal-App und tippst (ersetze die Beispiel-Adresse durch die deiner Maschine — die Geräteliste deines Routers zeigt sie):
  ```bash
  ssh deinbenutzername@192.168.1.50
  ```
  Unter Windows installierst du das [kostenlose „Windows Terminal"](https://aka.ms/terminal) oder nutzt [PuTTY](https://www.putty.org/) und verbindest dich zur selben Adresse. Beim ersten Mal fragt es „bist du sicher?" — tippe `yes`.

Du bist drin, wenn eine Zeile mit `$` auf dich wartet. Das ist der Assistent, der „bereit" sagt.

## Schritt 3 — Administrator werden

Ein paar Befehle brauchen Administrator-Rechte. Unter Linux heißt das **`sudo`** (sinngemäß „mach das als Chef"). Du stellst einfach `sudo` vor bestimmte Befehle, und beim ersten Mal wird nach deinem Passwort gefragt. Das Passwort erscheint beim Tippen **nicht** auf dem Bildschirm — das ist normal, nicht kaputt. Einfach Enter drücken.

## Schritt 4 — LoxProx herunterladen

Kopiere diese Zeilen einzeln (nach jeder Enter drücken). Die erste installiert das Download-Tool `git`; die zweite lädt LoxProx; die dritte wechselt in dessen Ordner.

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/sgtsilver/loxprox.git
cd loxprox
```

Sagt `git clone`, der Ordner existiere schon, hast du es bereits heruntergeladen — dann einfach `cd loxprox` und weiter.

## Schritt 5 — Den Miniserver automatisch finden

LoxProx bringt einen Scanner mit, der deinen Miniserver findet und alles Wichtige ausgibt:

```bash
chmod +x detect-loxone.sh
./detect-loxone.sh
```

(`chmod +x` heißt nur „erlaube diesem Script, zu laufen".) Es gibt die **IP-Adresse** deines Miniservers, die Firmware-Version und die genauen Werte für den nächsten Schritt aus. **Lass diese Ausgabe stehen** — du kopierst gleich ein paar Zahlen daraus.

## Schritt 6 — Dem Gateway eine feste Adresse geben

Damit das Gateway immer dieselbe Adresse behält, führe aus:

```bash
sudo ./set-static-ip.sh
```

Es stellt ein paar freundliche Fragen und richtet alles ein. Bist du dir bei einer Antwort unsicher, ist der vorgeschlagene Standard in eckigen Klammern fast immer richtig — einfach Enter drücken.

## Schritt 7 — LoxProx von deinem Setup erzählen

LoxProx liest seine Einstellungen aus einer kleinen Datei. Starte von der Vorlage:

```bash
sudo mkdir -p /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo nano /etc/loxprox/deploy.conf
```

`nano` ist ein einsteigerfreundlicher Texteditor, der direkt im Terminal aufgeht. Trage die wenigen Werte oben ein — meist die Zahlen, die `detect-loxone.sh` dir ausgegeben hat:

- `LOXONE_IP` — die Adresse deines Miniservers (aus Schritt 5).
- `GATEWAY_IP` — die eigene Adresse dieses Gateways (aus Schritt 6).
- `LAN_SUBNET` — der Bereich deines Heimnetzes (der Scanner schlägt ihn vor; meist sowas wie `192.168.1.0/24`).
- `SSH_ALLOWED_SUBNETS` — wer sich am Gateway anmelden darf; dein Heimnetz ist für den Anfang in Ordnung.
- `DISCORD_WEBHOOK` *(optional)* — füge hier eine Discord-Webhook-URL ein, um Handy-Benachrichtigungen zu bekommen. Für den Anfang ruhig weglassen.

Über jedem Wert steht ein Kommentar, der erklärt, was er bedeutet. Wenn du fertig bist: **Strg+O** dann **Enter** zum Speichern, dann **Strg+X** zum Beenden. (Bei einem Wert hängengeblieben? Der vollständige [Konfigurations-Guide](../CONFIGURATION-GUIDE.de.md) erklärt jeden einzelnen.)

## Schritt 8 — Den Installer laufen lassen

Das ist der große Moment. Ein Befehl macht alles — installiert Firewall, Proxy, Angriffserkennung und härtet die Maschine:

```bash
sudo bash deploy.sh
```

Es zeigt unterwegs an, was es tut (grün ist gut). Es ist **gefahrlos erneut ausführbar**, falls etwas hakt — es macht einfach dort weiter, wo es aufgehört hat.

**Der eine Moment, bei dem du aufpassen solltest — dein SSH-Schlüssel.** Mittendrin will der Installer Remote-Logins absichern, damit Angreifer kein Passwort durchprobieren können. Damit *du* dich nicht aus Versehen aussperrst, hält er an und bietet ein Menü an. Die einfachen, sicheren Optionen:

- Du meldest dich schon mit einem SSH-Schlüssel an? Wähle **behalten** — fertig.
- Du weißt nicht, was ein SSH-Schlüssel ist? Wähle vorerst **`[K]` Passwort-Login behalten** — du bleibst drin, und das Gateway legt dir einen freundlichen Hinweis vor, bis du später einen Schlüssel einrichtest. Nichts geht kaputt.

Wenn du dem Menü folgst, sperrst du dich **nicht** aus. Im Zweifel: die Option wählen, bei der du angemeldet bleibst.

## Schritt 9 — Prüfen, ob alles geklappt hat

```bash
sudo ./test-gateway.sh
```

Das führt über 50 Prüfungen aus und gibt einen ordentlichen Pass/Fail-Bericht. Viele grüne Häkchen heißt: du bist geschützt. Ist etwas rot, sagt dir die Zeile meist genau, was zu tun ist.

## Schritt 10 — Deine Welt aufs Gateway zeigen lassen

Zwei kleine Änderungen außerhalb des Terminals:

1. **An deinem Router:** leite eingehenden Port **1080** an die Adresse des Gateways weiter (statt direkt an den Miniserver). Hattest du vorher eine Weiterleitung auf den Miniserver, zeig sie jetzt aufs Gateway.
2. **In der Loxone-App:** ändere die Verbindungsadresse des Miniservers auf die Adresse des **Gateways** an Port **1080**. Alles andere in der App bleibt gleich.

Das war's — du bist fertig. Dein Miniserver antwortet dem Internet jetzt nur noch durch ein Gateway, das ihm den Rücken freihält.

## Optional — HTTPS (Verschlüsselung) einschalten

Du willst das Schloss-Symbol und verschlüsselten Verkehr? LoxProx kann automatisches HTTPS. Es braucht einen öffentlichen Domainnamen und eine zusätzliche Router-Einstellung, daher ist es standardmäßig aus. Wenn du bereit bist, folge dem freundlichen [TLS-Setup-Guide](TLS-SETUP.de.md) — er führt dich genauso behutsam durch.

---

## Hoppla — irgendwas sieht kaputt aus

Durchatmen. Fast nichts hier ist endgültig, und du kannst Dinge gefahrlos erneut ausführen.

- **Der Installer ist mit einem roten Fehler gestoppt.** Lies die letzten roten Zeilen — meist benennen sie das Problem. Behebe es und führe einfach wieder `sudo bash deploy.sh` aus.
- **Du glaubst, du hast dich per SSH ausgesperrt.** Mit ziemlicher Sicherheit nicht (der Installer ist genau dafür gebaut, das zu verhindern). Melde dich am Bildschirm/an der Tastatur der Maschine an, wenn möglich, und führe den Installer erneut aus.
- **Die App verbindet sich nicht.** Prüf Schritt 10 doppelt: der Router leitet Port 1080 ans *Gateway*, und die App zeigt auf die Adresse des *Gateways* an Port 1080. Hast du HTTPS aktiviert, muss die App-Adresse mit `https://` beginnen (siehe TLS-Guide).
- **Immer noch hängen?** [Öffne ein Issue auf GitHub](https://github.com/sgtsilver/loxprox/issues) und beschreibe, was du gemacht und gesehen hast. Füge den Fehlertext ein. **Keine Frage ist zu einfach** — genau dafür ist der Tracker da.

Du hast heute eine echte Systemadministrations-Aufgabe erledigt. Das ist nicht nichts. Willkommen an Bord.

---

## Glossar in einfacher Sprache

| Wort | Was es eigentlich bedeutet |
|------|----------------------------|
| **Terminal / Shell / Kommandozeile** | Ein Textfeld, in das du Befehle tippst. Ein geduldiger Assistent. |
| **Linux** | Ein kostenloses Betriebssystem, wie Windows oder macOS, aber für Server gebaut. |
| **Debian** | Eine beliebte, sehr stabile Linux-Variante. Die, die wir nutzen. |
| **VM (virtuelle Maschine)** | Ein „Computer im Computer". Verhält sich wie eine eigene Maschine. |
| **Raspberry Pi** | Ein winziger, günstiger echter Computer, etwa so groß wie ein Kartenspiel. |
| **SSH** | Ein sicherer Weg, das Terminal eines Computers von einem anderen aus übers Netz zu nutzen. |
| **`sudo`** | „Mach das als Administrator." Vor Befehle stellen, die extra Rechte brauchen. |
| **root** | Das Administrator-Konto — der Chef mit voller Kontrolle. |
| **IP-Adresse** | Die Adresse eines Computers im Netz, z. B. `192.168.1.50`. |
| **Port** | Eine nummerierte „Tür" an einem Computer. LoxProx lauscht an Tür `1080`. |
| **Subnetz / `/24`** | Ein Adressbereich in deinem Heimnetz, z. B. `192.168.1.0/24`. |
| **Firewall** | Ein Wächter, der unerwünschten Netzwerkverkehr blockiert. |
| **Proxy / Gateway** | Ein Mittelsmann, der Verkehr erst prüft und dann durchlässt. Das ist LoxProx. |
| **`nano`** | Ein einfacher Texteditor im Terminal. Strg+O speichert, Strg+X beendet. |
| **`git` / clone** | Ein Tool, um Code von GitHub herunterzuladen (und zu aktualisieren). |
| **HTTPS / TLS** | Verschlüsselung — das Schloss im Browser. Hier optional, empfohlen. |
| **CrowdSec / nftables / AppArmor** | Die Sicherheitstools, die LoxProx für dich einrichtet. Du konfigurierst sie nicht von Hand. |

Willst du die tiefere, technischere Version, sobald du dich sicher fühlst? Siehe die Haupt-[README](../README.md) und den [Konfigurations-Guide](../CONFIGURATION-GUIDE.de.md).
