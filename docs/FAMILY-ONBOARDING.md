# Family Onboarding — One QR Code, Works Everywhere

Getting a family member's phone connected should take under a minute and
require zero technical explanation. This is the flow.

## What you need once

Your public hostname — either your dynamic-DNS name (classic port-forward
setup, e.g. with `ENABLE_TLS`) or your relay domain (tunnel setup, see
[TUNNEL-SETUP.md](TUNNEL-SETUP.md)). Referred to as `<HOST>` below.

## Generate the QR code (once, on any Linux/macOS machine)

The Loxone app understands deep links of the form `loxone://ms?host=...`:

```bash
sudo apt-get install qrencode        # Debian/Ubuntu; macOS: brew install qrencode
qrencode -o loxone-qr.png "loxone://ms?host=<HOST>"
```

Print it, stick it on the fridge or inside the utility cabinet — it contains
only the hostname, no credentials.

## What the family member does

1. Install the **Loxone app** (App Store / Play Store).
2. Scan the QR code with the phone camera → the app opens with the
   Miniserver address pre-filled.
3. Enter their Miniserver username + password once. Done.

The same URL works from everywhere — at home, on cellular, abroad. Nothing
to switch, nothing to explain.

> **Credentials tip:** give each family member their own Miniserver user
> (Loxone Config → Users). One shared password means one shared lockout —
> and no way to tell who changed what.

## Phone won't connect? (checklist for you, not them)

1. **On cellular, from outside:** does `curl -vI https://<HOST>/` answer?
   If not, the problem is the path (tunnel/forward/DNS), not the phone —
   see the troubleshooting section of [TUNNEL-SETUP.md](TUNNEL-SETUP.md) or
   [TLS-SETUP.md](TLS-SETUP.md).
2. **Blocked by CrowdSec?** Shared/VPN IPs occasionally land on blocklists.
   Ask them to open `https://ip.sb` and check:
   `sudo cscli decisions list` → `sudo cscli decisions delete --ip <their-ip>`
   (on the relay if you run the tunnel, on the gateway otherwise).
3. **App stuck on "establishing connection":** known Gen 1 app quirk —
   clear the app cache (Android) or delete + re-add the Miniserver (iOS),
   then rescan the QR code.

## Known limitation: one URL per Miniserver

The Loxone app stores exactly **one** address per Miniserver — there is no
"local + remote" pair and no automatic switching. Consequence: if the
address you rolled out is the *external* one and your internet is down,
the app fails **even at home**, although the Miniserver is reachable in the
LAN.

Practical mitigations, in increasing order of effort:

1. **Live with it.** Internet outages are rare; the wall switches still work.
2. **DNS override in your router/Pi-hole** (split-horizon DNS): make
   `<HOST>` resolve to the *gateway's LAN IP* inside your network and to the
   public path outside. Same URL, both worlds, transparent to the app.
   FRITZ!Box: *Home Network → Network → DNS* has no per-name override — use
   a Pi-hole/AdGuard/unbound instance as DHCP DNS instead. Note that with
   the tunnel setup the internal target speaks plain HTTP on :1080 while the
   external one speaks HTTPS on :443, so the override only helps setups
   where both paths serve the same scheme and port.
3. **Wait for the roadmap:** a gateway-local DNS + wildcard-cert setup that
   makes split-horizon a first-class, installer-managed feature is the
   planned follow-up to v2.0.
