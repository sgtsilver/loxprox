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
- A site-to-site VPN: `"192.168.2.0/24"`
- A specific jump box: `"203.0.113.45"`
- An OpenVPN/WireGuard subnet: `"10.8.0.0/24"`

**Example:**
```bash
SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "192.168.2.0/24")
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
# 1. On your workstation — install the key for your sudo user
#    (root login is switched off in HARD mode once a non-root user has a key):
ssh-copy-id <your-user>@<gateway-ip>

# 2. On the gateway — re-run only the SSH hardening step:
sudo bash deploy.sh --finalize-ssh
```

`--finalize-ssh` is idempotent and re-runs only `setup_ssh_hardening()`. It rechecks `authorized_keys`, swaps the drop-in, removes `/var/lib/loxprox/ssh-keys-missing` and the MOTD banner, and reloads `sshd`. Verify with a second terminal before logging out.

### Notes

- Private keys are **never** generated on the gateway. The paste flow only accepts a public key that already exists on your workstation. (Generating private keys server-side is the appliance-ships-with-default-key antipattern — not done here.)
- The same drop-in path is used by both modes (`/etc/ssh/sshd_config.d/99-loxprox.conf`).
- The stock `/etc/ssh/sshd_config` is untouched; everything LoxProx writes lives in the drop-in directory.

---

## Re-running `deploy.sh` — nginx site regeneration & exit codes

Every re-run since v2.3 checks whether `/etc/nginx/sites-available/loxone`
still matches the template it was generated from (a version stamp plus a
fingerprint of the `deploy.conf` values it renders) and regenerates it when
either drifted — picking up template fixes and any changed rate limit,
timeout, or backend IP. The old file is backed up first, the TLS block is
re-applied if the site was serving HTTPS, and a failed `nginx -t` reverts
to the backup automatically. Two environment toggles change that behavior:

| Toggle | Effect |
|---|---|
| `LOXPROX_KEEP_NGINX_SITE=1` | Never touch an existing site — for a hand-maintained file. Template fixes and `deploy.conf` changes (rate limits, backend IP, AppSec wiring) then do **not** reach it until you unset it. |
| `LOXPROX_FORCE_REGEN_NGINX=1` | Regenerate the site even when its stamp is already current. |

```bash
sudo LOXPROX_FORCE_REGEN_NGINX=1 bash deploy.sh
```

`deploy.sh`'s own exit code tells automation (and you) what actually
happened:

| Code | Meaning |
|---|---|
| `0` | Deploy finished, all checks passed. |
| `1` | A health check failed, or a core step aborted the run. |
| `2` | Unknown command-line option. |
| `3` | Deployed, but one or more **optional** steps (TLS, tunnel, CrowdSec…) failed — listed at the end of the run. The gateway proxies; those features just aren't active. Re-run once the cause is fixed. |

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
| `APPSEC_MODE` | enforce | `enforce` blocks matched requests with HTTP 403; `monitor` alerts on a match but never blocks (use for the first week) |

Switching to `monitor` writes a local AppSec config
(`/etc/crowdsec/appsec-configs/loxprox-virtual-patching-monitor.yaml`) that
carries the hub's virtual-patching rules with `default_remediation: allow`;
switching back to `enforce` removes it again. Detections in monitor mode
show up in `cscli alerts list`, **not** in
`/var/log/nginx/appsec-detections.log` — nginx only writes to that file on
a BLOCK verdict, which monitor mode never returns.

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
    "192.168.2.0/24"      # site-to-site VPN to other location
    "203.0.113.45"        # uptime monitoring service
    "198.51.100.22"       # notification gateway
)
```

### Households behind one IP (NAT/CGNAT)

Every phone, tablet, TV and smart-home device in the house presents the
**same public IP** to the gateway (and, behind CGNAT, so do other
households sharing your ISP's address pool). Rate limits, CrowdSec's ban
decisions, and progressive-ban escalation (below) all key on that one
address — a single misbehaving device can trip a limit or a ban for the
whole family, not just itself. If you run the tunnel, the relay's own
limits stack on top of the gateway's for the same reason.

**Primary mitigation: whitelist your household's WAN IP.**
- Gateway: add it to `CROWDSEC_WHITELIST_IPS` above — find it with
  `curl -s https://ifconfig.me` from inside the house.
- Relay (if you run the tunnel): add it to `RELAY_WHITELIST_IPS` in
  `/etc/loxprox-relay/relay.conf`. Its firewall bouncer drops banned
  sources on *every* port, including the frp control port, so an
  unwhitelisted ban there also cuts SSH to the relay. See
  [`docs/TUNNEL-SETUP.md`](docs/TUNNEL-SETUP.md).

A whitelisted address is exempt from CrowdSec **and** from progressive-ban
escalation below — this is the durable fix, not just the reactive unban.

### Progressive Ban Escalation

Two things set how long an address stays banned: the first ban CrowdSec issues (its remediation profile, written by `deploy.sh` into `/etc/crowdsec/profiles.yaml`) and `progressive-ban.py` (cron, every 15 minutes, under `flock`), which extends a repeat offender's ban along a **ladder**. There are two ladders:

- **HARD** — for scenarios that are unambiguously scanners (those matching `BAN_HARD_SCENARIOS`): `168h 2160h 8760h` = 7 days, then 90 days, then 365 days.
- **SOFT** — for everything else: `24h 168h 720h 2160h` = 24 hours, 7 days, 30 days, then 90 days.

An "offense" is a distinct **attack incident**, not a raw alert count — only local scenario/AppSec detections count (CAPI/community-list entries, manual bans, simulated alerts and the script's own prior extensions never do), and alerts within `PROGRESSIVE_BAN_DEDUP_MINUTES` of each other count as **one** incident regardless of which scenario triggered them — a burst that trips five different rules at once is one incident, not an instant 90-day ban. An incident is HARD if any alert in it matches `BAN_HARD_SCENARIOS`. The script never shortens a ban and never escalates addresses in the CrowdSec whitelist.

| Key | Default | What it does |
|---|---|---|
| `BAN_HARD_LADDER` | `168h 2160h 8760h` | Ban durations for the 1st, 2nd and 3rd+ HARD offense (`m`, `h` or `d` units). The first value is what CrowdSec issues; the last repeats. Lengthen it for less tolerance. |
| `BAN_SOFT_LADDER` | `24h 168h 720h 2160h` | Ban durations for the 1st, 2nd, 3rd and 4th+ SOFT offense. Shorten the first rungs (e.g. `4h 24h 168h`) if the household keeps tripping ambiguous scenarios. |
| `BAN_HARD_SCENARIOS` | a regular expression (see `deploy.conf.example`) | Which scenario names use the HARD ladder: the trap, virtual-patching/CVE probes, and sensitive-file, backdoor, path-traversal, admin-interface and open-proxy probing. One regex that must work in both CrowdSec (Go RE2) and Python — no lookarounds, quotes or backslashes; `deploy.sh` refuses anything else. Change it only if you know why. |
| `PROGRESSIVE_BAN_WINDOW_DAYS` | `365` | Offenses older than this are forgotten. CrowdSec's own default (7-day alert flush) is replaced by an alert history of at least 400 days so the window is real. Lower it (e.g. `30`) for a more forgiving household. |
| `PROGRESSIVE_BAN_DEDUP_MINUTES` | `60` | Alerts within this many minutes of each other, from any scenario, count as one incident. Raise it (e.g. `180`) if unrelated-detection bursts still escalate too fast. |
| `PROGRESSIVE_BAN_WHITELIST_FILE` | `/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml` | Whitelisted IPs (the same file `CROWDSEC_WHITELIST_IPS` writes to) are never escalated. Override only if you maintain a separate whitelist file. |

The first four keys go in `deploy.conf`; `deploy.sh` validates them (a typo aborts the deploy), writes the first rung of each ladder into the CrowdSec profile and carries all of them into `/etc/loxprox/config.env`. `PROGRESSIVE_BAN_DEDUP_MINUTES` and `PROGRESSIVE_BAN_WHITELIST_FILE` are not managed by `deploy.sh` yet: set them by hand in `/etc/loxprox/config.env` (or the environment); unset values fall back to the defaults above.

> **Hard bans are long on purpose.** A year-long ban on a shared mobile or Private Relay address can hit an innocent user. That is why only unambiguous scanner behavior is HARD. If a legitimate address is banned, delete the decision (`sudo cscli decisions delete --ip <IP>`) — the offense memory stays, so the next offense still escalates.

### Scanner Elimination & Edge Filtering (2026-10 breach hardening)

On 2026-10-18 the vendor Loxone was breached. Crawlers such as Shodan and Censys fingerprint Loxone endpoints, so the gateway now answers only what a Loxone app legitimately sends and bans everything else for a long time. All keys below are optional and live in `/etc/loxprox/deploy.conf`; the defaults are the recommended hardened values. `deploy.sh` validates them and aborts on a typo instead of silently choosing another behavior.

### What changes for you

- **Use the host name with `https://`, never the IP.** With `ENABLE_TLS=true`, `:1080` and `:80` answer only `TLS_DOMAIN` plus `EXTRA_SERVER_NAMES`. A request for the bare IP, without SNI, or for a foreign `Host` is a **trap hit**: the connection is closed (444, nothing is sent), logged to `/var/log/nginx/loxprox-trap.log`, and the address is banned on the HARD ladder. Every app, browser and monitoring probe must use the host name. (`http://<host>:1080` for the real name still gets the 301 redirect to `https://`.)
- **The plain admin webservice paths are answered with `403` from the internet** (`fsget`, `fsdel`, `sys/reboot`, `sps/restart`, ...). See `REMOTE_ADMIN_PATHS` — this is a path filter, not a lock on the Miniserver.
- **Scanner paths are traps.** `/.env`, `/.git`, `*.php`, `/wp-*`, `/cgi-bin/`, `/vendor/phpunit`, `/HNAP1`, `/boaform`, `/actuator`, and the methods `CONNECT`, `TRACE`, `TRACK`, `PROPFIND` are answered with 444 and a HARD ban on the first hit. No Loxone endpoint matches any of them.
- **Auth and WebSocket limits.** Loxone authentication endpoints: 3 requests per second per untrusted address (burst 30). `/ws/`: at most 6 concurrent connections per untrusted address. `LAN_SUBNET` and `CROWDSEC_WHITELIST_IPS` are never limited, denied (admin/unknown) or counted.

### `EXTRA_SERVER_NAMES` — more host names for the gate

| Key | Default | What it does |
|---|---|---|
| `EXTRA_SERVER_NAMES` | `""` | Space-separated extra host names `:1080` accepts besides `TLS_DOMAIN`, e.g. `"home.example.net"`. Ignored without TLS (plain HTTP accepts every Host). |

**When to change:** you reach the same WAN IP under a second DNS name. These names only pass the Host/SNI gate. The certificate is still issued for `TLS_DOMAIN` only, so a client using another name gets a certificate mismatch unless you issue the certificate for that name too (`TLS_ACME_EXTRA="-d home.example.net"`). Allowed forms: dotted names (`home.example.net`), `*.example.com`, `.example.com` (the name and every subdomain) and `www.example.*`; anything else aborts the deploy. With the tunnel on, `TUNNEL_PUBLIC_HOST` is accepted automatically.

### `UNKNOWN_PATH_MODE` and `REMOTE_ADMIN_PATHS`

| Key | Default | What it does |
|---|---|---|
| `UNKNOWN_PATH_MODE` | `log` | What happens to a path that is neither trap, admin nor a known app endpoint. `log` = proxied as usual **and** written to `/var/log/nginx/loxprox-unknown.log` (the learning phase; the `loxprox/unknown-path` scenario only alerts). `deny` = untrusted sources get a local 404 (still logged) and `loxprox/unknown-path` bans (SOFT ladder). |
| `REMOTE_ADMIN_PATHS` | `deny` | `deny` = Loxone admin/file-system webservices answer `403` to internet clients (logged; no LoxProx scenario bans on it, but repeated 403s/404s still count toward the stock `crowdsecurity/http-probing` scenario, which can lead to a SOFT ban). `allow` = they are proxied like any app path. It filters plain HTTP paths only: the same commands can still reach the Miniserver inside the encrypted command form (`jdev/sys/enc` / `fenc`, app class) or over the authenticated WebSocket, so the Miniserver's own credentials remain the real control. |

**When to change:**
- Keep `UNKNOWN_PATH_MODE="log"` for a few weeks and read `loxprox-unknown.log`. Switch to `deny` only when it lists no path your family's apps actually use.
- Set `REMOTE_ADMIN_PATHS="allow"` only if you configure the Miniserver remotely through the gateway (Loxone Config over the internet). Prefer doing that from the LAN, which is exempt anyway.

### Monitor alerts, updates and GeoIP IPv6

| Key | Default | What it does |
|---|---|---|
| `SESSION_ALERT_ENABLED` | `true` | Discord alert when a remote client holds a session on the Loxone port from an ASN (provider network) the gateway has not seen before. Client addresses are masked in the alert. Needs `mmdb-bin` and the GeoLite2 databases CrowdSec ships (`deploy.sh` installs `mmdb-bin`). |
| `ASN_LEARNING_DAYS` | `7` | The first this-many days after the first monitor run only learn ASNs silently. Raise it if the family travels or changes carriers often. |
| `AUTH_RATE_ALERT_PER_CYCLE` | `20` | Alert when more Loxone authentication requests (`getkey`, `getkey2`, `getjwt`, `gettoken`, `authwithtoken`, `refreshjwt`, in both the `jdev/` and `dev/` spellings) than this reach the gateway in one 60-second monitor cycle, all clients together. The normal level is a handful per **day**, so 20 in a minute is loud. Raise it if a large household logs in at once. |
| `SEC_UPDATE_MAX_AGE_DAYS` | `2` | Alert ("Security Updates Not Installing") when a pending Debian-Security update has not been installed after this many days — the symptom of unattended-upgrades being stuck. |
| `GEOIP_IPV6_ENABLED` | `true` | Also drop IPv6 traffic from the denylisted countries (CN, RU, KP, IR) with the `geoip_blocklist6` set. `"false"` empties the IPv6 set at the next GeoIP refresh (IPv4 only). `geoip-block.sh` reads this from `config.env` itself. |
| `GEOIP_URL_BASE6` | `""` | Source of the IPv6 country lists. Empty = the ipdeny.com IPv6 lists. Must be an `https://` URL; change it only to use a mirror. |

Other alerts you will see, no keys needed:
- **New CrowdSec Ban** (WARNING) covers SOFT bans only, at most 15 entries per message. HARD (scanner) bans are summarised in one INFO **Daily HARD Ban Digest** at 08:00, sent even when the count is 0. With `TRAP_BAN_MODE="observe"` it also reports the number of observed trap hits and a line reminding you to review the trap log.
- **Firewall Integrity Failure**: the input policy and the rules are checked every cycle, the content of the GeoIP sets hourly.
- **Daily hub refresh** (04:30) snapshots the CrowdSec hub, then upgrades every installed hub item (never with `--force`; the last 7 snapshots are kept in `/var/lib/loxprox/hub-snapshots/`), and rolls back if CrowdSec does not come back. A successful upgrade sends nothing; the changed items are in `/var/log/loxprox-hub-refresh.log`. If CrowdSec breaks, you get **CrowdSec Rule Update Rolled Back**, **CrowdSec Down — Gateway Serving Errors** or **CrowdSec Rule Rollback Failed** (CRITICAL, naming the changed items). **CrowdSec Hub Snapshot Failed** (WARNING) means no upgrade ran, because the snapshot could not be shown to hold the hub index and every installed item's file. **CrowdSec Hub Items Not Upgraded** (INFO) lists items the upgrade left alone: "tainted" ones (changed locally) or ones still update-available. It also says how to resolve them, and it is sent again only when that list changes. The CrowdSec package's own nightly `crowdsec-hubupdate.timer` (an unprotected upgrade of every hub item) is masked by `deploy.sh`; `systemctl is-enabled crowdsec-hubupdate.timer` prints `masked`.

Ladder values with a `d` unit are converted to hours for the CrowdSec profile (CrowdSec has no day unit).

### `TRAP_BAN_MODE` — observe first, then ban

| Key | Default | What it does |
|---|---|---|
| `TRAP_BAN_MODE` | `ban` | `ban` = a trap hit bans the address (HARD ladder). `observe` = `loxprox/scanner-trap` runs in CrowdSec simulation: the trap still answers 444 and still logs to `loxprox-trap.log`, and CrowdSec still raises the alert, but no ban is issued. |

**When to change:** for the first rollout, to find your own devices that still use the IP or a wrong name before they get a 7-day ban.

1. Set `TRAP_BAN_MODE="observe"` in `deploy.conf` and deploy.
2. After a few days run `sudo cscli alerts list -s loxprox/scanner-trap --limit 0` (cscli 1.8.1 shows only 50 by default) and read `/var/log/nginx/loxprox-trap.log`. `/var/log/nginx/loxprox-trap-hosts.log` is the place to look: it holds the Host, SNI and user agent of every trap hit (CrowdSec does not read it; it is kept 90 days). Any address of your own (family phones, monitoring) in there is a client to fix: re-add it with `https://<your-host>:1080`.
3. Set `TRAP_BAN_MODE="ban"` and redeploy. Or switch immediately with `sudo cscli simulation disable loxprox/scanner-trap && sudo systemctl reload crowdsec` — and change `deploy.conf` as well, otherwise the next deploy re-enables observe mode.

While in observe mode, scanners are logged but not banned.

`loxprox/auth-bf` and (while `UNKNOWN_PATH_MODE="log"`) `loxprox/unknown-path` are always simulated. If `deploy.sh` cannot confirm a simulation with `cscli simulation status`, it removes that scenario rather than let it ban, and reports the CrowdSec step as degraded; fix it with `sudo cscli simulation enable <scenario>` and re-run `sudo bash deploy.sh`.

### `SSH_ALLOW_USERS` and HARD-mode root login

| Key | Default | What it does |
|---|---|---|
| `SSH_ALLOW_USERS` | `""` | Space-separated `AllowUsers` patterns (`user` or `user@host`). Empty = no `AllowUsers` line, so any account with a key may log in. |

**When to change:** set it (e.g. `"admin"`) to restrict SSH to your admin account. `deploy.sh` refuses to write a list that would lock everyone out (no listed account with a login shell, or, in HARD mode, none of them has an authorized key) and says so in the log. `--finalize-ssh` reads `deploy.conf`, so the key applies there too.

**Root login.** In HARD mode (`--finalize-ssh`, see "SSH Key Bootstrap") the drop-in now sets `PermitRootLogin no` only when a non-root account has an authorized key, sudo rights (`sudo`, `wheel` or `admin`) and a login shell. Otherwise (for example when root's key is the only key on the box) it stays `prohibit-password` and the deploy warns — copy your key to a sudo user (`ssh-copy-id <user>@<gateway-ip>`) and re-run `sudo bash deploy.sh --finalize-ssh`. In SOFT mode root login stays allowed (a root password may be the only way in until a key exists).

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
| `TLS_ACME_FALLBACK_SERVER` | `"zerossl"` | v2.0: secondary CA tried automatically when the primary `--issue` fails (CA outage, rate limit). Set `""` to disable. |
| `TLS_ACME_EXTRA` | `""` | Passthrough to `acme.sh --issue` (e.g. `--keylength ec-256`). |
| `EXTRA_SERVER_NAMES` | `""` | Extra host names `:1080` accepts besides `TLS_DOMAIN`. Everything else — the bare IP included — is a trap hit and gets banned. See "Scanner Elimination & Edge Filtering". |

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
2. A small `/etc/nginx/conf.d/loxprox-acme.conf` is written: a `:80` server for your own host names (`TLS_DOMAIN` plus `EXTRA_SERVER_NAMES`) that serves only `/.well-known/acme-challenge/` from `/var/www/acme/` and 301s everything else to `https://$host:1080$request_uri`. Any other `Host` on `:80` (IP scans) falls to the trap server in step 5, which answers 444.
3. The cert is issued (or renewed) via `acme.sh --issue --webroot --server $TLS_ACME_SERVER`. "Cert still valid, skipped" is treated as success.
4. The cert is installed at `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (mode `0640 root`), with `--reloadcmd "systemctl reload nginx"` recorded for the renewal cron.
5. The existing site file is mutated between explicit markers (`# LOXPROX-TLS-BEGIN` / `# LOXPROX-TLS-END`) and `listen 1080;` is swapped for `listen 1080 ssl;`. Operator hand-edits outside the marker block (WebSocket location, custom headers) are untouched. The strict regex on the listen line refuses anything other than canonical `listen 1080;` — no silent mutation. The same step gates the real server on your host names (`server_name` is no longer `_`) and appends the trap default servers for `:1080` and `:80` between `# LOXPROX-TRAP-BEGIN` / `# LOXPROX-TRAP-END`, with a self-signed `CN=invalid` certificate (`/etc/loxprox/tls/trap-*.pem`) so scanners that connect by IP complete the handshake and are logged and banned.
6. The auto-renewal cron is **verified** after every TLS-enabled deploy (not assumed). Missing? It is restored from `acme.sh --install-cronjob` and the exact cron line plus manual-renewal recipe is logged.

> ⚠️ **Enabling TLS does not auto-migrate existing clients.** Once `:1080` is HTTPS-only, every Loxone app/browser still configured as `http://<host>:1080` will fail in a `301` redirect loop until you update it to `https://`. Plan to update **every** saved connection (each phone, tablet, browser) when you flip `ENABLE_TLS=true`. See Troubleshooting → "The Loxone app can't connect after I enabled TLS."
>
> ⚠️ **Never use the IP address with TLS on.** Since the 2026-10 hardening, `:1080` answers only your host name(s). A client configured with the gateway's IP gets a closed connection and is banned on the HARD ladder (7 days on the first request). Use `https://<your-host>:1080` everywhere.

> **Network watchdog during the deploy.** With TLS on, the deploy disables the network watchdog until its Host/SNI-aware version is installed (an older watchdog would read the trap's 444 for `127.0.0.1` as an outage and reboot the box), and re-arms it at the end. A run that stops early prints `network-watchdog → NOT ARMED`. The fix is to re-run `sudo bash deploy.sh`, not to start the timer by hand.

### Toggle-off behavior (`ENABLE_TLS="false"`)

Set `ENABLE_TLS="false"` and re-run `sudo bash deploy.sh`. The script:

- Strips the marker block from the site file.
- Reverts the listen line to plain `listen 1080;`.
- Removes the `:80` ACME listener, the trap servers and the host-name gate (`server_name _` again — every Host is served).
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

## Optional Tunnel (v2.0) — zero-open-ports remote access

For connections where no port can be forwarded (CGNAT / DS-Lite). The gateway
dials OUT to a relay VPS you own; the Loxone app connects to the relay's
domain. Set the relay up first with `tunnel-relay/install-relay.sh` — its
summary prints the exact values below.

> ⚠️ `ENABLE_TUNNEL=true` and `ENABLE_TLS=true` are mutually exclusive in
> v2.0 — with the tunnel, TLS terminates at the relay. `deploy.sh` refuses
> the combination with a clear error.

### Config keys

| Key | Default | Purpose |
|-----|---------|---------|
| `ENABLE_TUNNEL` | `"false"` | Master toggle. Flip to `"true"` to opt in. |
| `TUNNEL_SERVER_ADDR` | `""` | Relay VPS public IP or DNS name. Required when enabled. |
| `TUNNEL_SERVER_PORT` | `"7000"` | frp control-channel port — must match the relay's `FRP_BIND_PORT`. Same number serves tcp AND quic. |
| `TUNNEL_PROTOCOL` | `"quic"` | `quic` (UDP, NAT-friendly — recommended) or `tcp` (fallback when UDP is dropped). |
| `TUNNEL_TOKEN` | `""` | Shared secret, same value as the relay's `TUNNEL_TOKEN`. Generate: `openssl rand -hex 32`. Required when enabled. |
| `TUNNEL_PROXY_NAME` | `"loxone"` | Cosmetic proxy name in frps logs. |
| `TUNNEL_REMOTE_PORT` | `"8443"` | Loopback-bound port on the relay carrying tunneled traffic to its nginx — must match the relay's value. |
| `TUNNEL_PUBLIC_HOST` | `""` | The relay's public domain (`RELAY_DOMAIN`). Enables the tunnel watchdog's full-path probe. |

### What happens on `sudo bash deploy.sh` with `ENABLE_TUNNEL=true`

1. frpc is installed from a SHA256-pinned GitHub release tarball (version-pinned, amd64/arm64) — no `curl | bash`.
2. `/etc/frp/frpc.toml` is written (mode `0640 root:frpc`) with the token and a single TCP proxy `127.0.0.1:1080 → relay:TUNNEL_REMOTE_PORT`.
3. A hardened `frpc.service` starts under the dedicated unprivileged `frpc` user (`ProtectSystem=strict`, empty capability set, syscall filter, `MemoryMax=256M`).
4. `/etc/nginx/conf.d/loxprox-tunnel-realip.conf` restores real client IPs from the relay's `X-Forwarded-For` (trusted from loopback only) — logs, rate limits, CrowdSec and AppSec see true sources again.
5. The tunnel watchdog is armed (60s: check frpc + probe `https://TUNNEL_PUBLIC_HOST/` → restart frpc → Discord alert, max 1/hour, never a reboot).

### Toggle-off behavior (`ENABLE_TUNNEL="false"`)

Stops and disables `frpc` + watchdog and removes the real-IP conf. Binary and
config are **kept** for cheap re-enable. Full removal (binary, config, units,
user): `sudo bash deploy.sh --remove-tunnel`.

### Pointers

- **Full tunnel runbook (setup, verification, troubleshooting, threat model):** [`docs/TUNNEL-SETUP.md`](docs/TUNNEL-SETUP.md)
- **Relay side:** [`tunnel-relay/README.md`](tunnel-relay/README.md)
- **Family phone onboarding:** [`docs/FAMILY-ONBOARDING.md`](docs/FAMILY-ONBOARDING.md)

---

## LoxProx Panel (GUI)

Optional (on by default) LAN-only web UI for status tiles, log viewing,
config editing, and one-click support actions (unban an IP, restart a
service, force a TLS renew, send a test alert). Runs on the gateway itself
and is reachable only from `LAN_SUBNET` + `SSH_ALLOWED_SUBNETS` — never
from the internet.

### Config keys

| Key | Default | Purpose |
|-----|---------|---------|
| `ENABLE_GUI` | `"true"` | Master toggle. Set `"false"` to disable. |
| `GUI_PORT` | `"1081"` | TCP port the panel listens on. |
| `GUI_PASSWORD` | `""` | Empty = no auth. Set to require the `X-LoxProx-Auth` header on every mutating request — recommended if untrusted devices (guests, IoT, kids' tablets) share your LAN. |

Full feature tour, security model, and troubleshooting:
[`docs/GUI-PANEL.md`](docs/GUI-PANEL.md).

---

## Backup & Restore

`deploy.sh` installs a daily backup timer that archives to
`/root/loxprox-backups/*.tar.gz` (mode `0600` — the tarball now contains
key material). As of v2.1 the daily backup also includes:

- `/etc/loxprox/deploy.conf`
- `/etc/loxprox/tls/fullchain.pem` + `privkey.pem` (when TLS is enabled)
- `/etc/frp/frpc.toml` (when the tunnel is enabled)
- `/etc/ssh/sshd_config.d/99-loxprox.conf`

on top of the nginx site, CrowdSec config, and nftables ruleset it already
backed up.

### Restoring from a backup

```bash
sudo bash deploy.sh --restore /root/loxprox-backups/<tarball>.tar.gz
```

This takes a pre-restore safety snapshot, extracts the tarball, and writes
the known files back with their correct modes. **Re-run `sudo bash
deploy.sh` afterwards** to reconcile services, firewall rules, and units
against the restored config — `--restore` only puts files back, it doesn't
re-apply them.

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

**This is not a ban** — `cscli decisions list` shows nothing for the IP. (The opposite symptom — the connection is closed at once and the IP **is** banned — means the client uses the gateway's IP or a name outside `TLS_DOMAIN` / `EXTRA_SERVER_NAMES`: the Host/SNI gate treated it as a scanner. Unban with `sudo cscli decisions delete --ip <IP>` and fix the client the same way.) The fix is client-side and applies to **every** app/browser that connects:

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
- [ ] With TLS on: every app and device uses `https://<your-host>:1080` — never the IP
- [ ] Discord webhook is set (or intentionally left empty)
