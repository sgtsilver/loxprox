# Familien-Onboarding — Ein QR-Code, funktioniert überall

Das Handy eines Familienmitglieds anzubinden sollte unter einer Minute
dauern und null technische Erklärung brauchen. So geht's.

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
   Blocklisten. Die Person `https://ip.sb` öffnen lassen und prüfen:
   `sudo cscli decisions list` → `sudo cscli decisions delete --ip <deren-ip>`
   (auf dem Relay beim Tunnel-Setup, sonst auf dem Gateway).
3. **App hängt bei „Verbindung wird hergestellt":** bekannte
   Gen-1-App-Macke — App-Cache leeren (Android) oder Miniserver löschen und
   neu anlegen (iOS), dann den QR-Code neu scannen.

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
