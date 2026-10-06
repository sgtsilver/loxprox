**Language:** [Deutsch](GUI-PANEL.de.md) · English

# LoxProx Panel — LAN-Only Web GUI (v2.3)

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
- The panel is a **calm, status-first console** with four areas —
  Overview, Security, Configuration, Logs — in German (default) or English,
  light/dark/automatic theme, and a phone layout with a bottom tab bar.
- Everything it needs — the page, its scripts, the Inter / Syne /
  JetBrains Mono fonts — is **served from the gateway itself**. There are no
  third-party libraries and the panel makes zero internet requests, so it
  works on an offline LAN.

## Feature tour

**Overview** (the home page, `/`). It answers one question first: *is
everything OK, and if not, what should I do?*

- **Status summary** — one plain-language line ("Everything is OK", "2 items
  need your attention", "Action needed"), the connection type and the time
  of the last update. If the panel stops answering, the summary says so,
  keeps the last known values marked as out of date, and retries on its own.
- **What to do** — every item that needs attention, worst first, each with
  an explanation and the action that fixes it: restart a stopped service,
  renew an expiring certificate, check the Miniserver address, open the log
  of a failed apply. Timer-driven units that can't be restarted from the
  panel show the `systemctl status …` command to run over SSH instead. A
  GeoIP blocklist that has not refreshed for 3 days shows its age, the last
  error and the command to refresh it by hand.
- **Details** — dense tiles:

| Tile | Shows |
|---|---|
| Services | Each unit and its state: nginx, CrowdSec, firewall bouncer, `loxprox-monitor.timer`, `network-watchdog.timer`, plus frpc and `tunnel-watchdog.timer` when the tunnel is on |
| Miniserver | Live TCP check against `LOXONE_IP:LOXONE_PORT` |
| TLS certificate | Days left on `/etc/loxprox/tls/fullchain.pem` — warning under 21 days, problem under 7 |
| Blocked addresses | Number of addresses with an active CrowdSec decision (informational — bans mean the protection works) |
| Attacks blocked today | Requests the AppSec WAF blocked today (`/var/log/nginx/appsec-detections.log`) and from how many addresses |
| Last backup | Age and size of the newest `/root/loxprox-backups/*.tar.gz` — warning when older than 26 hours or missing |
| System | Disk, memory and load as labelled meters |
| Connection | TLS, tunnel (with the frpc state) or direct HTTP |

- **Last 24 hours** — requests per minute and system load as line charts.

Status is never shown by color alone: every state carries an icon and a
word, and screen readers hear overall state changes without focus moving.

**Charts.** The panel samples the gateway once a minute — requests per
minute (nginx access-log growth), system load, RAM/disk, active CrowdSec
bans, AppSec hits, Miniserver reachability — into a 24-hour ring buffer
(`/var/lib/loxprox/gui-history.json`, survives restarts, served at
`/api/history`). Each chart has a one-sentence summary and a "values as a
table" view with hourly figures; hover or focus a chart and use the arrow
keys to read single values. A fresh install shows "collecting data" until
the first samples land; a failed request says so instead of drawing an
empty chart.

**Security.** Charts for active bans and AppSec hits per hour; the list of
blocked addresses with an **Unban** button per row plus a field to unban any
other IP; restart buttons for nginx / CrowdSec / bouncer / frpc (frpc only
in tunnel mode) with each service's current state; **send a test alert**
(exercises the Discord webhook end-to-end) and **renew the TLS
certificate** (`deploy.sh --renew-tls`). Every unban and restart asks for
confirmation first and reports the result in place.

**Configuration.**

- *Family invitation* — the QR code (see
  [`FAMILY-ONBOARDING.md`](FAMILY-ONBOARDING.md)), where its address comes
  from, the `loxone://` link with a copy button, and the manual address
  setting. The printable `/invite` page (DE/EN) is also one click away in
  the header — stick it in the utility cabinet instead of generating
  `loxone-qr.png` by hand.
- *Gateway settings* — edit a whitelisted subset of
  `/etc/loxprox/deploy.conf` (rate limits, timeouts, AppSec mode, CrowdSec
  whitelist, TLS, tunnel, panel settings). Each field is typed from the
  server's schema (switches, selects, text with a format hint), shows its
  `deploy.conf` key, and is checked before saving; errors are listed at the
  top and next to each field. Secrets (`TUNNEL_TOKEN`, `GUI_PASSWORD`,
  `DISCORD_WEBHOOK_URL`) are never displayed — leave the field empty to
  keep the value, or tick "remove the stored value". **Save** writes only
  the changed keys (with a timestamped backup of `deploy.conf`); **Apply**
  runs `deploy.sh` in the background after a confirmation (and offers to
  save unsaved changes first). `GATEWAY_IP`, `LAN_SUBNET`, and
  `SSH_ALLOWED_SUBNETS` are deliberately **not** editable here — a mistake
  in any of those three is an SSH lockout risk and stays an SSH-only change.

Apply and certificate renewal run as a **background job** shown at the top
of every view: running time, a live log tail, and the outcome. The job
status follows `deploy.sh`'s exit code: `0` → **ok**, `3` → **finished with
warnings** (the deploy went through but one or more *optional* steps — TLS,
tunnel, CrowdSec — didn't; the gateway still proxies, those features just
aren't active), anything else → **failed**. The job runs as its own
systemd unit (`loxprox-job-<id>`), so it keeps going when the apply
re-installs and restarts the panel; the restarted panel picks it up again
and shows its real outcome. A job that ended without leaving an exit code
(e.g. the gateway rebooted mid-run) shows as **failed**. Only if the panel
cannot be reached for a long time, or the job is no longer known, does it
show "result unknown" and point to the deploy log rather than guessing.

**Logs.** Read-only tail view of the nginx error/access logs, AppSec hits,
the network and tunnel watchdogs, the monitor, the deploy log and the panel
log — with a line filter and a follow mode (refresh every 5 s) — no more
`tail -f` over SSH for a quick look.

**Password prompt.** When `GUI_PASSWORD` is set, the first change you make
asks for it in a dialog; it is kept for the browser tab only. A wrong
password is reported in the same dialog; cancelling aborts the change.

**Accessibility.** The panel targets WCAG 2.2 AA: semantic headings and
landmarks, full keyboard operation with a visible focus ring and a "skip to
content" link, focus moved to the view heading on navigation, text contrast
of at least 4.5:1 and indicators of at least 3:1 in both themes, 44 px
buttons and touch targets on touch screens, reflow down to 320 px width, and
`prefers-reduced-motion` honored (the only motion is a short state
transition and a progress spinner).

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
- **No inline scripts, no external resources.** The CSP is
  `script-src 'self'` — every script is a file served from the gateway's
  own `/static/` allowlist (path-contained, extension-allowlisted), and
  `connect-src 'self'` means the page cannot phone anywhere else. The
  front-end contains no third-party code and builds its DOM without HTML
  strings, so data from the API (IPs, log lines, error text) can never turn
  into markup. pytest guards these rules (no inline script/handlers, no
  external URLs, no emoji, DE/EN string parity).
- **Optional password on mutating actions.** `GUI_PASSWORD` is empty (no
  auth) by default — reasonable on a LAN you fully control. Set it and
  every unban/restart/renew/apply/config-write call must present it via the
  `X-LoxProx-Auth` header (checked with a constant-time comparison); the
  panel asks for it once per browser tab. Viewing status and logs needs no
  password.
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

The manual address is only used when neither the tunnel nor TLS is on;
with either of them active, fix `TUNNEL_PUBLIC_HOST` / `TLS_DOMAIN`
instead. A specific host can always be printed via
`/invite?host=<host>&lang=de|en`.

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
set the manual address in the panel (plain port-forward setups only).

## Pointers

- **Family onboarding flow:** [`FAMILY-ONBOARDING.md`](FAMILY-ONBOARDING.md)
- **Full config key reference:** [`../CONFIGURATION-GUIDE.md`](../CONFIGURATION-GUIDE.md#loxprox-panel-gui) → "LoxProx Panel (GUI)"
