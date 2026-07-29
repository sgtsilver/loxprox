# Familien-Onboarding — Ein QR-Code, funktioniert überall

**Sprache:** Deutsch · [English](FAMILY-ONBOARDING.md)

Das Handy eines Familienmitglieds anzubinden sollte unter einer Minute
dauern und null technische Erklärung brauchen. So geht's.

> ⚠️ **Lies das, bevor du den QR-Code verteilst.** Das klassische
> Port-Forward-Setup hat standardmäßig `ENABLE_TLS="false"` — Klartext-HTTP
> auf `:1080`. Das heißt: der Miniserver-Login und das Passwort jedes
> Familienmitglieds queren das Internet als **Klartext**. Jeder auf dem Weg
> (ein kompromittierter WLAN-Hotspot, ein neugieriger Provider) kann
> mitlesen. Schalte TLS ein ([`TLS-SETUP.de.md`](TLS-SETUP.de.md)) oder nutze
> den Tunnel ([`TUNNEL-SETUP.de.md`](TUNNEL-SETUP.de.md)) — beide
> terminieren HTTPS — bevor du das an Handys ausrollst, die du nicht selbst
> kontrollierst.

## Was du einmalig brauchst

Deinen öffentlichen Hostnamen — entweder den Dynamic-DNS-Namen (klassisches
Port-Forward-Setup, z. B. mit `ENABLE_TLS`) oder deine Relay-Domain
(Tunnel-Setup, siehe [TUNNEL-SETUP.de.md](TUNNEL-SETUP.de.md)). Unten
`<HOST>` genannt.

## QR-Code erzeugen (einmalig, auf einem Linux-/macOS-Rechner)

Die Loxone App versteht Deep-Links der Form `loxone://ms?host=...`:

```bash
sudo apt-get install qrencode        # Debian/Ubuntu; macOS: brew install qrencode
qrencode -o loxone-qr.png "loxone://ms?host=<HOST>"
```

Ausdrucken, an den Kühlschrank oder in den Technikschrank kleben — er
enthält nur den Hostnamen, keine Zugangsdaten.

## Was das Familienmitglied macht

1. **Loxone App** installieren (App Store / Play Store).
2. QR-Code mit der Handykamera scannen → die App öffnet sich mit
   vorausgefüllter Miniserver-Adresse.
3. Einmal Miniserver-Benutzername + Passwort eingeben. Fertig.

> **Wenn Scannen nichts tut:** Das Handy braucht die Loxone App *zuerst*
> installiert — ein nackter `loxone://`-Link tut ohne sie nichts (Schritt 1
> oben, in dieser Reihenfolge). Auf Android kann das Betriebssystem einen
> App-Auswahl-Dialog zeigen, wenn neben der aktuellen App noch eine alte
> "Loxone Classic" installiert ist — wähle die App, die du wirklich nutzen
> willst. Scannt es immer noch nicht? Die Adresse lässt sich immer auch von
> Hand eintippen: App öffnen → Miniserver hinzufügen → `<HOST>` manuell
> eingeben.

Dieselbe URL funktioniert überall — zu Hause, über Mobilfunk, im Urlaub.
Nichts umzuschalten, nichts zu erklären.

> **Tipp zu Zugangsdaten:** jedem Familienmitglied einen eigenen
> Miniserver-Benutzer geben (Loxone Config → Benutzer). Ein geteiltes
> Passwort bedeutet einen geteilten Lockout — und keine Chance
> nachzuvollziehen, wer was geändert hat.

## Handy verbindet nicht? (Checkliste für dich, nicht für sie)

1. **Über Mobilfunk, von außen:** antwortet `curl -vI https://<HOST>/`?
   Falls nein, liegt das Problem am Pfad (Tunnel/Forward/DNS), nicht am
   Handy — siehe Troubleshooting in [TUNNEL-SETUP.de.md](TUNNEL-SETUP.de.md)
   bzw. [TLS-SETUP.de.md](TLS-SETUP.de.md).
2. **Von CrowdSec blockiert?** Geteilte/VPN-IPs landen gelegentlich auf
   Blocklisten. iPhones nutzen standardmäßig **iCloud Private Relay**, dessen
   geteilte Egress-IPs überdurchschnittlich oft auf Blocklisten landen —
   siehe [`SECURITY.de.md`](../SECURITY.de.md#legitimer-nutzer-geblockt)
   ("Roaming-/Shared-Egress-Clients") für die ausführliche Anleitung. Die
   Person `https://ip.sb` öffnen lassen und prüfen:
   `sudo cscli decisions list` → `sudo cscli decisions delete --ip <deren-ip>`
   (auf dem Relay beim Tunnel-Setup, sonst auf dem Gateway).
3. **App hängt bei „Verbindung wird hergestellt":** bekannte
   Gen-1-App-Macke — App-Cache leeren (Android) oder Miniserver löschen und
   neu anlegen (iOS), dann den QR-Code neu scannen.
4. **Der ganze Haushalt teilt sich eine öffentliche IP?** Was Rate Limits
   und Bans angeht, ist jeder hinter demselben Heimrouter diese eine IP. Ein
   einzelnes störendes Gerät (eine hängende Refresh-Schleife, eine
   fehlerhafte Automatisierung) kann das Rate-Limit oder einen Ban für die
   ganze Familie auslösen, nicht nur für sich selbst. Der Fix ist derselbe
   Unban-Flow wie oben — keine Config-Änderung.

## Neu in v2.1 — Self-Service über das LoxProx Panel

Ab v2.1 ist vieles davon auch als Self-Service verfügbar: das
**LoxProx Panel**, eine LAN-only Web-Seite am Gateway unter
`http://<gateway-ip>:1081`, zeigt denselben QR-Code, den aktuellen
Verbindungsstatus und einen Ein-Klick-**Unban**-Button für genau die
„von CrowdSec blockiert"-Fälle oben — kein SSH nötig. Vollständige Tour:
[`GUI-PANEL.de.md`](GUI-PANEL.de.md).

## Bekannte Einschränkung: eine URL pro Miniserver

Die Loxone App speichert exakt **eine** Adresse pro Miniserver — es gibt
kein „lokal + remote"-Paar und kein automatisches Umschalten. Konsequenz:
ist die ausgerollte Adresse die *externe* und das Internet fällt aus,
scheitert die App **auch zu Hause**, obwohl der Miniserver im LAN
erreichbar ist.

Praktische Auswege, nach Aufwand sortiert:

1. **Damit leben.** Internetausfälle sind selten; die Wandtaster
   funktionieren weiter.
2. **DNS-Override im Router/Pi-hole** (Split-Horizon-DNS): `<HOST>` löst im
   eigenen Netz auf die *LAN-IP des Gateways* auf, draußen auf den
   öffentlichen Pfad. Gleiche URL, beide Welten, für die App transparent.
   FRITZ!Box: *Heimnetz → Netzwerk → DNS* kann keine Overrides pro Name —
   stattdessen Pi-hole/AdGuard/unbound als DHCP-DNS verwenden. Achtung:
   beim Tunnel-Setup spricht das interne Ziel klartext-HTTP auf :1080,
   das externe HTTPS auf :443 — der Override hilft nur dort, wo beide
   Pfade dasselbe Schema und denselben Port bedienen.
3. **Auf die Roadmap warten:** ein gateway-lokales DNS + Wildcard-Zertifikat,
   das Split-Horizon als vollwertiges, vom Installer verwaltetes Feature
   liefert, ist der geplante Nachfolger von v2.0.
