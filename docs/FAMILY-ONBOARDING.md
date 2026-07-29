# Family Onboarding — One QR Code, Works Everywhere

**Language:** [Deutsch](FAMILY-ONBOARDING.de.md) · English

Getting a family member's phone connected should take under a minute and
require zero technical explanation. This is the flow.

> ⚠️ **Read this before you hand out the QR code.** The classic port-forward
> setup defaults to `ENABLE_TLS="false"` — plain HTTP on `:1080`. That means
> the Miniserver login, and every family member's password, crosses the
> internet as **cleartext**. Anyone on the path (a compromised Wi-Fi hotspot,
> a nosy ISP) can read it. Turn on TLS ([`TLS-SETUP.md`](TLS-SETUP.md)) or use
> the tunnel ([`TUNNEL-SETUP.md`](TUNNEL-SETUP.md)) — both terminate HTTPS —
> before you roll this out to phones you don't control yourself.

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

> **If scanning doesn't do anything:** the phone needs the Loxone app
> installed *first* — a bare `loxone://` link does nothing without it (step
> 1 above, in that order). On Android, if an old "Loxone Classic" app is
> still installed alongside the current one, the OS may pop up an
> app-chooser dialog — pick the app you actually want to use. Scan still
> failing? The address can always be typed in by hand: open the app → add
> Miniserver → enter `<HOST>` manually.

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
   iPhones default to **iCloud Private Relay**, whose shared egress IPs land
   on blocklists disproportionately often — see
   [`SECURITY.md`](../SECURITY.md#legitimate-user-blocked) ("Roaming /
   shared-egress clients") for the fuller guidance. Ask them to open
   `https://ip.sb` and check:
   `sudo cscli decisions list` → `sudo cscli decisions delete --ip <their-ip>`
   (on the relay if you run the tunnel, on the gateway otherwise).
3. **App stuck on "establishing connection":** known Gen 1 app quirk —
   clear the app cache (Android) or delete + re-add the Miniserver (iOS),
   then rescan the QR code.
4. **Whole household sharing one public IP?** As far as rate limits and
   bans are concerned, everyone behind the same home router **is** that one
   IP. One misbehaving device (a stuck refresh loop, a buggy automation) can
   trip the rate limiter or a ban for the whole family, not just itself. The
   fix is the same unban flow as above — not a config change.

## New in v2.1 — self-service via the LoxProx Panel

If you're running v2.1+, most of the above is now also self-service: the
**LoxProx Panel**, a LAN-only web page on the gateway at
`http://<gateway-ip>:1081`, shows the same QR code, the current connection
status, and a one-click **unban** button for exactly the "blocked by
CrowdSec" situations above — no SSH needed. Full tour:
[`GUI-PANEL.md`](GUI-PANEL.md).

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
