**Language:** [Deutsch](GUI-PANEL.de.md) · English

# LoxProx Panel — LAN-Only Web GUI (v2.2)

> **Who this is for:** anyone who wants a point-and-click view of gateway
> health, a one-tap way to onboard family phones, or a way to unban an IP
> without opening an SSH session. Everything here is optional — the panel
> ships enabled by default, but the gateway works identically with it off.

The LoxProx Panel is a small, self-contained web UI that runs on the
gateway itself and is reachable only from your LAN. It doesn't add a new
attack surface on the internet-facing side of the gateway — it's a
convenience layer on top of the same tools you'd otherwise reach over SSH
(`cscli`, `systemctl`, `openssl`, `deploy.sh`).

## What you get

- Default: **on** (`ENABLE_GUI="true"`), listening on `GUI_PORT="1081"`.
- Reachable at `http://<gateway-ip>:1081` from any device on `LAN_SUBNET`
  or `SSH_ALLOWED_SUBNETS` — nowhere else.
- Since v2.2 the panel is a **tabbed dashboard** (Overview / Security /
  Configuration / Logs) with live 24-hour charts, an animated 3D status
  scene, light/dark/auto theme, and a mobile layout with a bottom tab bar.
  Everything — three.js, anime.js, the fonts — is **vendored and served
  from the gateway itself**; the panel makes zero internet requests and
  works on an offline LAN.

## Feature tour

**Family invite.** `/invite` is a printable page with the QR code (see
[`FAMILY-ONBOARDING.md`](FAMILY-ONBOARDING.md)) plus the same DE/EN
onboarding steps — stick it in the utility cabinet instead of generating
`loxone-qr.png` by hand.

**Overview tab** (the panel's home page, `/`). A status headline ("all
systems secure" / "attention required") over an animated particle-shield
scene that tints green, amber, or red with gateway state, plus the status
tiles:

| Tile | Shows |
|---|---|
| Services | nginx, CrowdSec, firewall bouncer, frpc (when the tunnel is on), `loxprox-monitor.timer`, `network-watchdog.timer` |
| Cert expiry | Days left on `/etc/loxprox/tls/fullchain.pem` (when TLS is on) |
| Miniserver reachability | Live TCP check against `LOXONE_IP:LOXONE_PORT` |
| CrowdSec decisions | Count + last 10 (origin, country, duration) |
| AppSec detections | Count of blocked requests today |
| Backup age | Age + size of the latest `/root/loxprox-backups/*.tar.gz` |
| System | Disk, RAM, load |
| Tunnel | frpc connection state, when `ENABLE_TUNNEL=true` |

**Charts (v2.2).** The panel samples the gateway once a minute — requests
per minute (nginx access log growth), system load, RAM/disk, active
CrowdSec bans, AppSec hits, Miniserver reachability — into a 24-hour ring
buffer (`/var/lib/loxprox/gui-history.json`, survives restarts, served at
`/api/history`). The Overview tab charts traffic and load; the Security tab
charts bans and AppSec hits. A fresh install shows "collecting data" until
the first samples land.

**Logs tab.** Read-only tail view of nginx, CrowdSec, and monitor/watchdog
logs with a follow mode — no more `journalctl`/`tail -f` over SSH for a
quick look.

**Config editor** (Configuration tab). Edit a whitelisted subset of `/etc/loxprox/deploy.conf`
values in a form (rate limits, timeouts, AppSec mode, CrowdSec whitelist,
TLS, tunnel, and GUI settings) and **apply** with one click — the panel
timestamps a backup of `deploy.conf` first, then runs `deploy.sh` in the
background and shows the job log. `GATEWAY_IP`, `LAN_SUBNET`, and
`SSH_ALLOWED_SUBNETS` are deliberately **not** editable here — a mistake in
any of those three is an SSH lockout risk and stays an SSH-only change.

**Support actions** (Security tab). One button each for: unban an IP
(`cscli decisions delete`), restart a service (nginx / CrowdSec / bouncer /
frpc), force a TLS renewal (`deploy.sh --renew-tls`), and send a test alert
(exercises the Discord webhook end-to-end).

## Security model

The panel trades convenience for a wider footprint on the box, so it's
built to fail closed:

- **Never internet-reachable.** `deploy.sh` adds an nftables rule scoped to
  exactly `LAN_SUBNET` + `SSH_ALLOWED_SUBNETS` (deduplicated) as source —
  the same trust boundary SSH already uses. There is no path from the
  public `:1080` listener into the panel.
- **Host-header allowlist.** The panel only answers requests whose `Host`
  header matches the gateway's IP, `127.0.0.1`, `localhost`, or those with
  an explicit port — closing the DNS-rebinding angle even for someone who
  could get a LAN device to resolve a hostile domain to the gateway's IP.
- **CSRF header on every mutation.** All `POST` requests must carry
  `X-LoxProx-Gui: 1`; there is no CORS configuration that would let another
  origin forge this from a browser.
- **No inline scripts, no external resources.** Since v2.2 the CSP is
  `script-src 'self'` — every script is a file served from the gateway's
  own `/static/` allowlist (path-contained, extension-allowlisted), and
  `connect-src 'self'` means the page cannot phone anywhere else.
- **Optional password on mutating actions.** `GUI_PASSWORD` is empty (no
  auth) by default — reasonable on a LAN you fully control. Set it and
  every unban/restart/renew/apply/config-write call must present it via the
  `X-LoxProx-Auth` header (checked with a constant-time comparison).
  **Recommended if untrusted devices — guests, IoT, kids' tablets — share
  your `LAN_SUBNET` or a routed VLAN that reaches the gateway.**
- **Runs as root.** The panel shells out to `cscli`, `systemctl`, reads
  `/etc/loxprox/deploy.conf` (mode 0640), and runs `deploy.sh` itself — all
  of which need root regardless. It is not sandboxed with
  `ProtectSystem=strict` the way frpc is, because the config-apply job
  needs to write system state; the compensating controls are the LAN-only
  reachability and the auth option above, not process isolation.
- **To disable entirely:** set `ENABLE_GUI="false"` in
  `/etc/loxprox/deploy.conf` and re-run `sudo bash deploy.sh`. This stops
  and disables the `loxprox-gui` service, removes the nftables rule, and
  deletes the installed script and its assets; setting it back to `"true"`
  and re-running `deploy.sh` reinstalls everything.

## Config keys

| Key | Default | Purpose |
|-----|---------|---------|
| `ENABLE_GUI` | `"true"` | Master toggle. |
| `GUI_PORT` | `"1081"` | TCP port the panel listens on. |
| `GUI_PASSWORD` | `""` | Empty = no auth. Set to require `X-LoxProx-Auth` on every mutating request. Write-only in the config editor (never displayed back). |

## QR code / host detection

The panel derives the host it puts in the QR code and invite page the same
way an operator would pick it by hand:

1. `ENABLE_TUNNEL="true"` → uses `TUNNEL_PUBLIC_HOST`.
2. Else `ENABLE_TLS="true"` → uses `TLS_DOMAIN:1080`.
3. Else → an operator-entered host, stored in
   `/var/lib/loxprox/gui-settings.json` (set it once from the panel — there
   is no way to guess a plain port-forward's public DNS name automatically).

You can always override the detected value from the panel.

## Troubleshooting

**Panel unreachable at `http://<gateway-ip>:1081`:**
1. Confirm it's on: `grep ENABLE_GUI /etc/loxprox/deploy.conf`.
2. Confirm the service is up: `systemctl status loxprox-gui` /
   `journalctl -u loxprox-gui -n 50`.
3. Confirm the firewall rule exists and you're calling from an allowed
   source: `sudo nft list ruleset | grep -A2 "dport $GUI_PORT"` — you must
   be on `LAN_SUBNET` or `SSH_ALLOWED_SUBNETS`.

**QR code / invite page shows the wrong host:** the detection order above
means a stale `TUNNEL_PUBLIC_HOST` or `TLS_DOMAIN` wins over whatever you
typed manually. Check which mode is actually active
(`ENABLE_TUNNEL`/`ENABLE_TLS` in `deploy.conf`) and either fix that value or
override the host directly in the panel.

## Pointers

- **Family onboarding flow:** [`FAMILY-ONBOARDING.md`](FAMILY-ONBOARDING.md)
- **Full config key reference:** [`../CONFIGURATION-GUIDE.md`](../CONFIGURATION-GUIDE.md#loxprox-panel-gui) → "LoxProx Panel (GUI)"
