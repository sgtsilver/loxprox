# Configuration Guide

This document explains every setting in `deploy.sh` so you know exactly what to put where. No guessing.

---

## TL;DR: Three-Step Setup

```bash
# Step 1: Find your Loxone automatically
./detect-loxone.sh

# Step 2: Open deploy.sh and edit the [REQUIRED] values at the top
nano deploy.sh

# Step 3: Run it
sudo ./deploy.sh
```

---

## Required Values (6 settings)

These **must** be changed or the deployment will not work for your network.

### `LOXONE_IP` — Your Miniserver's LAN IP

**What it is:** The internal IP address of the Loxone Miniserver on your home network.

**How to find it:**
- **Easiest:** Run `./detect-loxone.sh` on the gateway VM. It scans the network and reports the IP, MAC, firmware version, and generation.
- **Router:** Log into your router and look at the DHCP lease table for a device named "Loxone" or with a MAC address starting with `EE:E0:00`.
- **Manually:** From any device on the same LAN, run `curl http://CANDIDATE_IP/jdev/cfg/mac`. If you get a JSON response with `"control": "dev/cfg/mac"`, that's your Loxone.

**Example:**
```bash
LOXONE_IP="192.168.178.20"
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

**What it is:** The IP address of the machine running this gateway script (the VM or LXC you just created).

**Why it matters:** The router forwards external port 1080 to this IP. If this IP changes (DHCP), the port forwarding breaks and your Loxone becomes unreachable from the internet.

**How to set it:**
1. Choose an IP in your LAN subnet that is **outside** the router's DHCP range.
   - Example: If your router assigns 192.168.1.100–192.168.1.200, use 192.168.1.50.
2. Run `./set-static-ip.sh` before `deploy.sh`, or configure the static IP manually in `/etc/network/interfaces` or via your router's DHCP reservation.

**Example:**
```bash
GATEWAY_IP="192.168.178.252"
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
# Output: 192.168.178.252/24 → your subnet is 192.168.178.0/24
```

**Common home subnets:**
- `192.168.1.0/24` (most common)
- `192.168.178.0/24` (Fritz!Box default)
- `10.0.0.0/24` (some routers)

**Example:**
```bash
LAN_SUBNET="192.168.178.0/24"
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
SSH_ALLOWED_SUBNETS=("192.168.178.0/24" "192.168.100.0/24")
```

**How to test after deploy:**
```bash
# From a machine inside an allowed subnet:
ssh loxone@$GATEWAY_IP

# From the internet (should time out or hang):
ssh loxone@$GATEWAY_IP
```

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
- Any VPN/network tunnel subnets

**Should include:**
- Uptime monitoring services (e.g., UptimeRobot, Pingdom)
- Cloud services that legitimately poll the Loxone API
- Your own external IP if you access it remotely

**Example:**
```bash
CROWDSEC_WHITELIST_IPS=(
    "192.168.178.0/24"      # home LAN
    "192.168.100.0/24"      # site-to-site VPN to other location
    "88.99.80.45"           # uptime.heimtanz.de monitoring
    "75.2.97.79"            # Heroku app (prowl notifications)
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

---

## Configuration Checklist

Before running `deploy.sh`, verify:

- [ ] `LOXONE_IP` is correct (test with `curl http://$LOXONE_IP/jdev/cfg/mac`)
- [ ] `GATEWAY_IP` is static (not DHCP)
- [ ] `LAN_SUBNET` matches your network
- [ ] `SSH_ALLOWED_SUBNETS` includes your current network
- [ ] Router port forwarding: external 1080 → `GATEWAY_IP`:1080
- [ ] Discord webhook is set (or intentionally left empty)
