# Tunnel Setup (v2.0) — Zero-Open-Ports Remote Access

> **Who needs this:** anyone whose internet connection cannot forward a port —
> CGNAT, DS-Lite, most German cable/fiber providers by default. If you CAN
> forward ports, the classic path (router forward + optional `ENABLE_TLS`)
> remains fully supported and is simpler; you don't need this document.

Loxone Gen 1 has no official remote-access path for CGNAT connections:
Cloud DNS needs a public IP + port forward, and Remote Connect is Gen 2 only.
The v2.0 tunnel closes that gap with self-hosted parts only (ADR-0002).

## How it works

```
                         YOUR RELAY VPS (public IPv4)
                        ┌──────────────────────────────┐
Loxone App ── https ──► │ nginx:443 (TLS, WS, rate     │
                        │   limits, CrowdSec)          │
                        │      │                       │
                        │      ▼                       │
                        │ 127.0.0.1:8443 (frps)        │
                        └──────┬───────────────────────┘
                               │  frp tunnel (outbound from home,
                               │  QUIC or TCP, token-authenticated)
                        ┌──────▼───────────────────────┐
                        │ frpc (sandboxed service)     │
                        │      │                       │
                        │      ▼                       │
                        │ nginx:1080 (rate limits,     │   YOUR GATEWAY VM
                        │   AppSec WAF, CrowdSec)      │   (home network)
                        └──────┬───────────────────────┘
                               ▼
                        Loxone Miniserver Gen 1 :80
```

Key properties:

- **No open ports at home.** The gateway dials out; the router config stays
  untouched.
- **The full security stack stays on the path.** The relay adds a perimeter
  (rate limits + CrowdSec); the gateway keeps nginx hardening, AppSec WAF,
  CrowdSec detection, auditd — everything v1.x already had.
- **Everything is yours.** The relay is your VPS (any EU provider, ~€3–5/mo);
  frp is open source; there is no third-party cloud in the path and no
  subscription.

## Prerequisites

1. A **VPS with a public IPv4** running Debian 12 (smallest instance is fine:
   1 vCPU / 1 GB RAM).
2. A **domain or DNS name** with an A record pointing at the VPS.
   Privacy note: choose a neutral, user-chosen name. Never embed the
   Miniserver serial number or your address in the hostname — certificate
   transparency logs are public.
3. A **shared token**: `openssl rand -hex 32` — you will paste the same value
   on both sides.

## Step 1 — Set up the relay (on the VPS)

```bash
# Copy the repo (or just the tunnel-relay/ directory) to the VPS, then:
sudo install -d -m 0750 /etc/loxprox-relay
sudo cp tunnel-relay/relay.conf.example /etc/loxprox-relay/relay.conf
sudoedit /etc/loxprox-relay/relay.conf     # RELAY_DOMAIN, RELAY_EMAIL, TUNNEL_TOKEN
sudo bash tunnel-relay/install-relay.sh
```

The installer sets up: nftables (input drop), frps (version-pinned,
SHA256-verified, sandboxed systemd unit), nginx with a Let's Encrypt
certificate (ZeroSSL fallback), CrowdSec with community blocklists, and
unattended upgrades. It ends with a health check and prints the exact values
the gateway needs.

## Step 2 — Enable the tunnel (on the gateway)

Edit `/etc/loxprox/deploy.conf`:

```bash
ENABLE_TUNNEL="true"
TUNNEL_SERVER_ADDR="<VPS IP or DNS>"
TUNNEL_SERVER_PORT="7000"
TUNNEL_PROTOCOL="quic"            # or "tcp" if your network drops UDP
TUNNEL_TOKEN="<same token as the relay>"
TUNNEL_REMOTE_PORT="8443"
TUNNEL_PUBLIC_HOST="<RELAY_DOMAIN>"

# v2.0 limitation — see below:
ENABLE_TLS="false"
```

Then:

```bash
sudo bash deploy.sh
```

This installs frpc (pinned + verified), a sandboxed `frpc.service` running as
an unprivileged user, the nginx real-IP restoration (so logs, rate limits and
CrowdSec see true client IPs instead of the tunnel), and the tunnel watchdog
(60s cycle: check → restart frpc → Discord alert, never a reboot).

## Step 3 — Verify

```bash
# 1. Tunnel connected? (on the gateway)
systemctl status frpc
journalctl -u frpc -n 20        # look for "login to server success"

# 2. Relay answering? (from ANY network, e.g. phone on cellular)
curl -vI https://<RELAY_DOMAIN>/

# 3. Full path? Expect a Loxone JSON answer:
curl -s https://<RELAY_DOMAIN>/jdev/cfg/api

# 4. WebSocket upgrade? Expect HTTP/1.1 101:
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Upgrade: websocket' -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
  https://<RELAY_DOMAIN>/ws/rfc6455

# 5. Loxone app (phone on cellular, NOT on your WiFi): add the Miniserver
#    with host <RELAY_DOMAIN>, open live stats, watch values update.
```

For family phones, use the QR onboarding flow: [FAMILY-ONBOARDING.md](FAMILY-ONBOARDING.md).

## Operations

| Task | Command |
|---|---|
| Tunnel status | `systemctl status frpc` (gateway), `systemctl status frps` (relay) |
| Watchdog log | `cat /var/log/loxprox-tunnel-watchdog.log` |
| Disable temporarily | set `ENABLE_TUNNEL="false"`, re-run `deploy.sh` (binary+config kept) |
| Remove completely | `sudo bash deploy.sh --remove-tunnel` |
| Rotate the token | new `openssl rand -hex 32` → update BOTH configs → re-run `install-relay.sh`, then `deploy.sh`. Rotate at least yearly, immediately on any suspicion. |
| Upgrade frp | bump `FRP_VER` + `FRP_SHA256_*` in `deploy.sh` AND `install-relay.sh` (kept in lockstep), re-run both. Watch frp release notes — it is an actively maintained upstream. |

The tunnel watchdog alerts to your existing Discord webhook at most once per
hour and reports recovery. A dead tunnel never reboots the gateway — LAN
access keeps working and the network watchdog covers local failures.

## Threat model notes

- **The relay is the enforcement point for tunneled traffic.** Tunneled
  packets reach the gateway from loopback, so a CrowdSec ban on the
  *gateway's* nftables cannot drop a tunneled attacker. The relay's own
  CrowdSec + firewall bouncer (installed by default) bans at the perimeter,
  where the true source IP is visible. The gateway's AppSec WAF still
  inspects every tunneled request. Details: [../SECURITY.md](../SECURITY.md).
- **Real client IPs are restored** on the gateway via `X-Forwarded-For`,
  trusted from loopback only with `real_ip_recursive off` — a client-supplied
  header cannot spoof its source.
- **The token is a secret.** It lives in `/etc/loxprox/deploy.conf` (0640)
  and `/etc/frp/*.toml` (0640, service group only). Anyone with the token can
  connect a rogue frpc to your relay — but `proxyBindAddr = 127.0.0.1` and
  `allowPorts` limit what that yields to hijacking the single loopback port.
  Rotate on any suspicion.
- **frp upstream** is a large, actively maintained open-source project; the
  known `routeByHTTPUser` auth-bypass CVE does not affect TCP-passthrough
  mode (our mode). Keep the pin current.

## Why not ENABLE_TLS together with the tunnel? (v2.0 limitation)

With the tunnel, TLS terminates at the **relay** — the gateway's :1080
listener must speak plain HTTP toward the tunnel. A `listen 1080 ssl` gateway
would answer the tunnel's HTTP frames with a TLS alert and break everything,
so `deploy.sh` refuses the combination. The roadmap fix is a wildcard cert
via DNS-01 shared by both listeners (split-horizon DNS: same domain resolves
to the gateway inside your LAN and to the relay outside). Until then:
tunnel users rely on the relay for TLS; the LAN path stays plain HTTP inside
your own network, exactly like v1.x default.

## Troubleshooting

**frpc logs "login to server failed"** — token mismatch or wrong
`TUNNEL_SERVER_ADDR`/`PORT`. Compare both configs; check the relay's
`journalctl -u frps`.

**QUIC won't connect but TCP does** — your ISP/router drops UDP. Set
`TUNNEL_PROTOCOL="tcp"` and re-run `deploy.sh`.

**Relay answers 502/504** — tunnel down. Check `systemctl status frpc` on the
gateway; the watchdog is probably already restarting it.

**App connects but no live updates** — WebSocket path broken. Run the 101
check from Step 3; verify both nginx configs contain the `/ws/` location
with 24h timeouts (regenerate with `LOXPROX_FORCE_REGEN_NGINX=1` if your
site file predates v2.0).

**App stuck on "establishing connection"** — known Gen 1 app quirk. Clear
the app cache (Android) or delete + re-add the Miniserver entry (iOS), using
`<RELAY_DOMAIN>` as the host.

**Family member suddenly blocked** — check the relay:
`sudo cscli decisions list` → `sudo cscli decisions delete --ip <their-ip>`.
