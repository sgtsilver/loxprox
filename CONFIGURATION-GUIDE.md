**Language:** [Deutsch](CONFIGURATION-GUIDE.de.md) · English

# Configuration Guide

This document explains every value LoxProx needs. As of v1.5.0, those values live in `/etc/loxprox/deploy.conf` (not at the top of `deploy.sh` like in v1.3.x and earlier — see `docs/UPGRADE-to-v1.5.md` if you're migrating).

---

## TL;DR: Three-Step Setup (v1.5.0+)

```bash
# Step 1: Find your Loxone automatically
./detect-loxone.sh

# Step 2: Create your per-host config from the template
sudo install -d -m 0750 /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf       # fill in the [REQUIRED] values

# Step 3: Run the deploy
sudo bash deploy.sh
```

`deploy.sh` sources `/etc/loxprox/deploy.conf` at startup. It refuses to run if the file is missing AND no existing install is detected, so you can't accidentally deploy with the placeholder values that ship in the example.

**Upgrading from v1.3.x?** Run `sudo bash deploy.sh --bootstrap-config` once. It reads back your current values from live nftables / nginx / CrowdSec state and writes them into `/etc/loxprox/deploy.conf` for you. Full walkthrough: [`docs/UPGRADE-to-v1.5.md`](docs/UPGRADE-to-v1.5.md).

---

## Required Values (5 settings)

These **must** be changed or the deployment will not work for your network.

### `LOXONE_IP` — Your Miniserver's LAN IP

**What it is:** The internal IP address of the Loxone Miniserver on your home network.

**How to find it:**
- **Easiest:** Run `./detect-loxone.sh` on the gateway VM. It scans the network and reports the IP, MAC, firmware version, and generation.
- **Router:** Log into your router and look at the DHCP lease table for a device named "Loxone" or with a MAC address starting with `EE:E0:00`.
- **Manually:** From any device on the same LAN, run `curl http://CANDIDATE_IP/jdev/cfg/mac`. If you get a JSON response with `"control": "dev/cfg/mac"`, that's your Loxone.

**Example:**
```bash
LOXONE_IP="192.168.1.100"
```

**Common mistake:** Using the external/public IP or the router's WAN IP. This must be the **internal** LAN IP.

---

### `LOXONE_PORT` — Miniserver's HTTP Port

**What it is:** The TCP port the Miniserver listens on inside your LAN.

**Default:** `80`

**When to change:** Only if you have manually reconfigured the Miniserver to use a different port. Gen 1 units are always port 80 unless modified. Gen 2 units may redirect 80 → 443, but the internal port is still 80 for the gateway to proxy.

**How to verify:**
```bash
curl -I http://$LOXONE_IP:$LOXONE_PORT/
# Should return HTTP/1.1 200 OK
```

---

### `GATEWAY_IP` — This VM's Static IP

**What it is:** The IP address of the VM running this gateway script.

> **Note:** LoxProx is a **VM-only** deployment. `deploy.sh` aborts inside an LXC by default because several defenses (kernel sysctls, Fragnesia mitigation, auditd, AppArmor enforcement, nftables) cannot be applied from inside a container and would silently no-op. See the README's *Hardware Requirements* section for the full reasoning, or `ALLOW_LXC=1` to bypass at your own risk.

**Why it matters:** The router forwards external port 1080 to this IP. If this IP changes (DHCP), the port forwarding breaks and your Loxone becomes unreachable from the internet.

**How to set it:**
1. Choose an IP in your LAN subnet that is **outside** the router's DHCP range.
   - Example: If your router assigns 192.168.1.100–192.168.1.200, use 192.168.1.50.
2. Run `./set-static-ip.sh` before `deploy.sh`, or configure the static IP manually in `/etc/network/interfaces` or via your router's DHCP reservation.

**Example:**
```bash
GATEWAY_IP="192.168.1.50"
```

**How to verify after deploy:**
```bash
ip addr show | grep "inet "
```

---

### `LAN_SUBNET` — Your Home Network Range

**What it is:** The CIDR notation of your entire LAN. This is used for CrowdSec whitelisting and SSH restrictions.

**How to find it:**
```bash
ip route | grep default
# Look at the interface name (e.g., eth0), then:
ip -o -f inet addr show eth0
# Output: 192.168.1.50/24 → your subnet is 192.168.1.0/24
```

**Common home subnets:**
- `192.168.1.0/24` (most common)
- `192.168.0.0/24` (TP-Link, D-Link defaults)
- `10.0.0.0/24` (some routers)

**Example:**
```bash
LAN_SUBNET="192.168.1.0/24"
```

---

### `SSH_ALLOWED_SUBNETS` — Who Can SSH Into the Gateway

**What it is:** A list of IP networks that are allowed to connect to this gateway via SSH. Everyone else is dropped by nftables.

**⚠️ CRITICAL:** Do NOT use `0.0.0.0/0` here. That exposes SSH to the entire internet.

**What to put:**
- Your home LAN: `"192.168.1.0/24"`
- A site-to-site VPN: `"192.168.100.0/24"`
- A specific jump box: `"203.0.113.45"`
- An OpenVPN/WireGuard subnet: `"10.8.0.0/24"`

**Example:**
```bash
SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "192.168.100.0/24")
```

**How to test after deploy:**
```bash
# From a machine inside an allowed subnet:
ssh loxone@$GATEWAY_IP

# From the internet (should time out or hang):
ssh loxone@$GATEWAY_IP
```

---

## SSH Key Bootstrap — what `deploy.sh` does on first run

`deploy.sh` hardens the SSH daemon (CIS Debian 12 §5.2: `PermitRootLogin no`, `PasswordAuthentication no`, key-only). That would normally **lock you out** of a fresh box that has no `authorized_keys` yet — the classic first-deploy chicken-and-egg. The deploy script handles this for you.

### Threat model — why this matters even on LAN-only SSH

nftables on the gateway already drops `:22` from anything outside `SSH_ALLOWED_SUBNETS`, so the public internet never sees the SSH port. **The hardening protects against a compromised host inside your LAN** (your laptop, a smart-TV, an IoT toaster) trying to brute-force the gateway from the inside. Stock Debian ships `PasswordAuthentication yes`, leaving that window open until hardening lands.

> **Different model from a public Hetzner/AWS box.** Some self-hosted projects (e.g. `endlessh` SSH tarpit setups) need to absorb internet-scale SSH noise on port 22. LoxProx does not — port 22 here is LAN-side only, so the hardened sshd is the right primitive instead of a tarpit.

### What happens during `sudo ./deploy.sh`

1. The script checks `/root/.ssh/authorized_keys` and every `/home/<user>/.ssh/authorized_keys` for UID ≥ 1000.

2. **If at least one key is present** — applies the HARD profile immediately:
   ```
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   MaxAuthTries 4
   LogLevel VERBOSE
   ClientAliveInterval 300
   ```
   Verify from a **second terminal** before logging out.

3. **If no keys are present and the deploy is interactive (tty)** — the script pauses and shows a 4-option menu:

   ```
   ⚠  No SSH authorized_keys found on this gateway.
       Disabling password auth NOW would lock you out of SSH.

       [P] Paste your public key (recommended — we'll wait)
       [H] Show help — how to create a key on your workstation
       [K] Keep password auth for now (insecure; loud login banner until fixed)
       [A] Abort deploy entirely
   ```

   - **`[P]`** — paste the entire `ssh-ed25519 AAAA… you@host` public key on one line. The script validates it (prefix + `ssh-keygen -l -f` round-trip), echoes it back with the fingerprint, asks for a final `y` confirmation, then installs it under `/root/.ssh/authorized_keys` (mode 0600). Then applies the HARD profile.
   - **`[H]`** — shows the exact commands to run on your workstation:
     ```
     macOS / Linux:    ssh-keygen -t ed25519 -C "you@workstation"
     Windows 10/11:    ssh-keygen -t ed25519 -C "you@workstation"   (PowerShell or Git Bash)
     Print public:     cat ~/.ssh/id_ed25519.pub
     ```
     Plus Google search terms. Switch to `[P]` afterwards without losing your place.
   - **`[K]`** — applies a SOFT profile (`PasswordAuthentication yes`, but `MaxAuthTries 4` + `LogLevel VERBOSE` + key-pref still set) and installs `/etc/update-motd.d/99-loxprox-ssh-warn` — a red banner that fires on every login until you finalize.
   - **`[A]`** — aborts the deploy with no SSH changes.

4. **If no keys are present and the deploy is non-interactive** (Ansible, CI, piped stdin) — falls back automatically to the SOFT profile + MOTD banner. The box stays reachable.

### Finalizing after `ssh-copy-id`

If you chose `[K]` or ran an unattended deploy, the box is now running SOFT mode (password auth still on, banner nagging). To swap it for the HARD profile:

```bash
# 1. On your workstation — install the key:
ssh-copy-id root@<gateway-ip>

# 2. On the gateway — re-run only the SSH hardening step:
sudo bash deploy.sh --finalize-ssh
```

`--finalize-ssh` is idempotent and re-runs only `setup_ssh_hardening()`. It rechecks `authorized_keys`, swaps the drop-in, removes `/var/lib/loxprox/ssh-keys-missing` and the MOTD banner, and reloads `sshd`. Verify with a second terminal before logging out.

### Notes

- Private keys are **never** generated on the gateway. The paste flow only accepts a public key that already exists on your workstation. (Generating private keys server-side is the appliance-ships-with-default-key antipattern — not done here.)
- The same drop-in path is used by both modes (`/etc/ssh/sshd_config.d/99-loxprox.conf`).
- The stock `/etc/ssh/sshd_config` is untouched; everything LoxProx writes lives in the drop-in directory.

---

## Optional Values (Adjust If Needed)

### Rate Limiting

These protect against brute force and DDoS. The defaults are tuned for a Loxone home automation setup.

| Setting | Default | What It Does |
|---------|---------|--------------|
| `RATE_LIMIT_REQ_PER_SEC` | 10 | Each IP can make 10 requests per second sustained |
| `RATE_LIMIT_BURST` | 100 | Each IP can burst up to 100 requests instantly (prevents 503s on Loxone UI asset loading) |
| `RATE_LIMIT_CONN_PER_IP` | 20 | Each IP can hold max 20 concurrent connections |

**When to change:**
- If legitimate users see HTTP 503 errors → increase burst to 150
- If you are under active attack → lower req/sec to 5
- If you have many users behind one NAT IP (e.g., office) → increase conn limit

### Proxy Timeouts

These prevent slowloris attacks (attackers open connections and send data very slowly to exhaust server resources).

| Setting | Default | What It Does |
|---------|---------|--------------|
| `PROXY_CONNECT_TIMEOUT` | 10s | Max time to establish connection to Loxone |
| `PROXY_SEND_TIMEOUT` | 15s | Max time to send request to Loxone |
| `PROXY_READ_TIMEOUT` | 15s | Max time to wait for Loxone response |
| `CLIENT_BODY_TIMEOUT` | 10s | Max time client has to send request body |
| `CLIENT_HEADER_TIMEOUT` | 10s | Max time client has to send headers |

**When to change:** Rarely. Only increase if users on very slow mobile connections timeout. Never go above 30s.

### CrowdSec AppSec WAF

| Setting | Default | What It Does |
|---------|---------|--------------|
| `ENABLE_APPSEC` | true | Inspects every HTTP request for CVE exploit patterns |
| `APPSEC_MODE` | enforce | Blocks matched requests (use "monitor" for first week) |

**First-time setup recommendation:**
```bash
# Week 1: monitor mode
APPSEC_MODE="monitor"
# Then: check for false positives
cscli alerts list | grep appsec
# Week 2: switch to enforce
APPSEC_MODE="enforce"
sudo ./deploy.sh
```

### CrowdSec Whitelist

These IPs/networks are **never** banned by CrowdSec, even if they trigger attack signatures.

**Must include:**
- Your LAN subnet (`192.168.1.0/24`)
- **Every other trusted subnet/VLAN** a trusted device might reach the gateway from (e.g. a second Wi-Fi VLAN routed to the gateway via inter-VLAN routing). If it isn't listed, a device on it can be banned even though it's internal.
- Any VPN/network tunnel subnets

**Deliberately exclude:** guest and IoT segments — leave them untrusted so they pass through the full security stack like any remote client.

> **Roaming mobile clients cannot be whitelisted here.** Devices on mobile carriers, iCloud Private Relay, or Cloudflare WARP use **rotating** IPs — there is no stable address to list. See `SECURITY.md` → "Legitimate User Blocked" for how those are handled (reactively).

**Should include:**
- Uptime monitoring services (e.g., UptimeRobot, Pingdom)
- Cloud services that legitimately poll the Loxone API
- Your own external IP if you access it remotely

**Example:**
```bash
CROWDSEC_WHITELIST_IPS=(
    "192.168.1.0/24"      # home LAN
    "192.168.100.0/24"      # site-to-site VPN to other location
    "203.0.113.45"        # uptime monitoring service
    "198.51.100.22"       # notification gateway
)
```

### Discord Alerting

**What it is:** Real-time security alerts sent to a Discord channel.

**How to get a webhook URL:**
1. Open Discord
2. Go to your server → Server Settings → Integrations → Webhooks
3. Click "New Webhook"
4. Choose a channel
5. Click "Copy Webhook URL"
6. Paste it into `DISCORD_WEBHOOK_URL`

**Example:**
```bash
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz"
```

**To disable:** Set to empty string `DISCORD_WEBHOOK_URL=""`

### Email Alerting

**What it is:** Sends an email if nginx error log grows too fast.

**Requirements:** `mailutils` package must be installed.

**To disable:** Set to empty string `ALERT_EMAIL=""`

### Auto-Reboot Time

**What it is:** If a kernel security update is installed by `unattended-upgrades`, the system reboots at this time to load the new kernel.

**Pick a time** when nobody uses the Loxone (e.g., 3 AM).

**To disable auto-reboot:** This is handled by `unattended-upgrades` config. Edit `/etc/apt/apt.conf.d/50unattended-upgrades` after deploy.

---

## Optional TLS (HTTPS on :1080) — what `deploy.sh` does when you opt in

LoxProx v1.5.0 adds optional HTTPS termination on the gateway via `acme.sh` + HTTP-01. Off by default — the gateway keeps speaking plain HTTP on `:1080` until you set `ENABLE_TLS="true"` in `/etc/loxprox/deploy.conf` and re-run the deploy. Toggling back off is just as clean (cert files are kept so flipping forward again is fast).

The full operator runbook lives in [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md). This section is the short version: which keys to set, what the prerequisites are, and how the re-entry flags work.

### Threat model — why this is opt-in, not default

The gateway already shields the no-TLS Miniserver behind it; for many home deployments plain HTTP on `:1080` over a router port-forward is the established setup and works fine. Enabling TLS widens the public surface by one extra listener (`:80`, scoped to `/.well-known/acme-challenge/` plus a 301 redirect) and introduces an ACME renewal dependency. Worth it for anyone who wants HTTPS in the URL bar of the Loxone web UI; not mandatory.

### Prerequisites — once, before flipping `ENABLE_TLS=true`

1. **Public DNS** — `TLS_DOMAIN` must resolve publicly to your router's WAN IP **before** the deploy. The ACME server validates it by connecting to `http://<TLS_DOMAIN>/.well-known/acme-challenge/<token>`. A dynamic-DNS hostname (`selfhost.eu`, `ddnss.de`, Cloudflare, etc.) or a static A record at your registrar both work.
2. **Router forward `WAN:80 → gateway:80`** — in addition to the existing `WAN:1080 → gateway:1080` forward. This is **only** used for ACME validation; the gateway's `:80` listener answers exactly `/.well-known/acme-challenge/*` and 301s everything else to `https://<TLS_DOMAIN>:1080$request_uri`.

### Config keys (all optional, defaults are sane)

| Key | Default | Purpose |
|-----|---------|---------|
| `ENABLE_TLS` | `"false"` | Master toggle. Flip to `"true"` to opt in. |
| `TLS_DOMAIN` | `""` | Fully-qualified public hostname (e.g. `loxprox.example.com`). Required when `ENABLE_TLS=true`; refused with a clear error if missing or non-FQDN. |
| `TLS_EMAIL` | `""` | Registered with the ACME provider. |
| `TLS_ACME_SERVER` | `"letsencrypt"` | Also accepts `letsencrypt_test` (staging — use first while debugging), `zerossl`, `buypass`, `buypass_test`, `sslcom`, or a full directory URL. |
| `TLS_ACME_EXTRA` | `""` | Passthrough to `acme.sh --issue` (e.g. `--keylength ec-256`). |

**Example:**

```bash
ENABLE_TLS="true"
TLS_DOMAIN="loxprox.example.com"
TLS_EMAIL="you@example.com"
TLS_ACME_SERVER="letsencrypt"
TLS_ACME_EXTRA=""
```

### What happens on `sudo bash deploy.sh` with `ENABLE_TLS=true`

1. `acme.sh` is installed from a SHA256-pinned GitHub release tarball — no `curl | bash`.
2. A small `/etc/nginx/conf.d/loxprox-acme.conf` is written: `:80` `default_server` that serves only `/.well-known/acme-challenge/` from `/var/www/acme/` and 301s everything else to `https://$host:1080$request_uri`.
3. The cert is issued (or renewed) via `acme.sh --issue --webroot --server $TLS_ACME_SERVER`. "Cert still valid, skipped" is treated as success.
4. The cert is installed at `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (mode `0640 root`), with `--reloadcmd "systemctl reload nginx"` recorded for the renewal cron.
5. The existing site file is mutated between explicit markers (`# LOXPROX-TLS-BEGIN` / `# LOXPROX-TLS-END`) and `listen 1080;` is swapped for `listen 1080 ssl;`. Operator hand-edits outside the marker block (WebSocket location, custom headers) are untouched. The strict regex on the listen line refuses anything other than canonical `listen 1080;` — no silent mutation.
6. The auto-renewal cron is **verified** after every TLS-enabled deploy (not assumed). Missing? It is restored from `acme.sh --install-cronjob` and the exact cron line plus manual-renewal recipe is logged.

> ⚠️ **Enabling TLS does not auto-migrate existing clients.** Once `:1080` is HTTPS-only, every Loxone app/browser still configured as `http://<host>:1080` will fail in a `301` redirect loop until you update it to `https://`. Plan to update **every** saved connection (each phone, tablet, browser) when you flip `ENABLE_TLS=true`. See Troubleshooting → "The Loxone app can't connect after I enabled TLS."

### Toggle-off behavior (`ENABLE_TLS="false"`)

Set `ENABLE_TLS="false"` and re-run `sudo bash deploy.sh`. The script:

- Strips the marker block from the site file.
- Reverts the listen line to plain `listen 1080;`.
- Removes the `:80` ACME listener.
- Cancels the per-domain renewal in `acme.sh`.
- **Keeps** cert files under `/etc/loxprox/tls/` so re-enabling later doesn't pay re-issuance time.

### Re-entry flags

```bash
# Force-renew right now (acme.sh --renew … --force):
sudo bash deploy.sh --renew-tls

# Full nuke — site revert, conf.d listener removed, acme.sh uninstalled,
# /etc/loxprox/tls/ deleted, cron cancelled. Operator action remaining:
# remove the WAN:80 → gateway:80 router forward.
sudo bash deploy.sh --remove-tls
```

### Pointers

- **Full TLS runbook:** [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md)
- **Upgrade walkthrough (v1.3.x → v1.5):** [`docs/UPGRADE-to-v1.5.md`](docs/UPGRADE-to-v1.5.md)

---

## Troubleshooting

### "I don't know my Loxone's IP"

```bash
./detect-loxone.sh
```

If that doesn't find it:
1. Check your router's admin panel → DHCP leases or connected devices
2. Look for a device named "Loxone" or with MAC starting `EE:E0:00`
3. Try pinging the last known IP: `ping 192.168.1.100`

### "I don't know my LAN subnet"

```bash
ip route | grep default
ip -o -f inet addr show
```

The output will show something like `192.168.1.50/24`. Your subnet is `192.168.1.0/24`.

### "I don't know my SSH subnet"

Use the same as `LAN_SUBNET`. If you also have a VPN or second site, add that too.

### "I get nftables errors during deploy"

Make sure you are running as root:
```bash
sudo ./deploy.sh
```

### "The gateway can't reach the Loxone"

```bash
# From the gateway VM:
curl -v http://$LOXONE_IP:$LOXONE_PORT/jdev/cfg/api

# If this fails, check:
# 1. Is the Loxone powered on?
# 2. Is the gateway on the same subnet as the Loxone?
# 3. Is there a Proxmox firewall blocking traffic between VMs?
```

### "The Loxone app can't connect after I enabled TLS" (301 redirect loop)

After flipping `ENABLE_TLS=true`, `:1080` speaks **HTTPS only**. A client still configured as `http://<host>:1080` sends cleartext to the TLS port; nginx answers every request with a `301` to `https://…`, and the Loxone app (which doesn't follow redirects on its API calls) retries in a loop. Symptom in `loxone-access.log`: the same client hitting `GET /jdev/cfg/api?cacheBstr=…` with status `301` over and over.

**This is not a ban** — `cscli decisions list` shows nothing for the IP. The fix is client-side and applies to **every** app/browser that connects:

1. In the Loxone app, edit the Miniserver connection (or delete and re-add it).
2. Set the address to **`https://<your-host>:1080`** — verify the scheme is `https` **and** the `:1080` port is still present (the app stores scheme and port separately).

---

## Configuration Checklist

Before running `deploy.sh`, verify:

- [ ] `LOXONE_IP` is correct (test with `curl http://$LOXONE_IP/jdev/cfg/mac`)
- [ ] `GATEWAY_IP` is static (not DHCP)
- [ ] `LAN_SUBNET` matches your network
- [ ] `SSH_ALLOWED_SUBNETS` includes your current network
- [ ] Router port forwarding: external 1080 → `GATEWAY_IP`:1080
- [ ] Discord webhook is set (or intentionally left empty)
