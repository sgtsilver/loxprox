**Language:** [Deutsch](SECURITY.de.md) · English

# Loxone Miniserver Gen 1 — Security Posture & Threat Model

## Responsible Disclosure

**No bug bounty — no money.** If you find a vulnerability, open a Pull Request with the fix. Every contribution is reviewed and analyzed. This is a community-hardened project: the code is the defense, and better code makes everyone safer.

If you can't provide a fix, open an issue with reproduction steps and we'll address it.

---

## Executive Summary

The Loxone Miniserver Gen 1 is **legacy first-generation hardware** with **no TLS support**, **no native authentication hardening**, and **no new security features** (TLS, Remote Connect, Trusts are Gen 2+ only). While Loxone has not formally declared it EOL, firmware updates have slowed significantly — the last known security patch was in 2020 (CVE-2020-27488). It is the definition of a "legacy device that must be protected by the network layer."

This gateway exists because the Miniserver cannot protect itself.

---

## Scope & Design Invariants

These are deliberate boundaries for the **current (Gen 1)** deployment — what this gateway is and isn't trying to do. Revisit them only when the hardware changes (see "v2 / Gen 2" below).

1. **Remote/mobile access goes through the public gateway — no client VPN.** Devices reach the Miniserver via the gateway's public listener, not through a VPN, tunnel, or relay on the device itself. The security ceiling for this path is therefore the gateway stack: TLS + nginx rate/conn limits + CrowdSec + AppSec WAF (+ optional geo-block). The native Loxone app **cannot present client certificates or participate in any gateway-layer auth** (no cookie/OAuth/TOTP), so per-device authentication is not available on Gen 1.

2. **LAN and trusted subnets are never blocked.** Every trusted network must be in `CROWDSEC_WHITELIST_IPS` — not just the primary `LAN_SUBNET`. If a trusted device can reach the gateway from a *second* VLAN (e.g. via inter-VLAN routing), that VLAN must be whitelisted too, or the device can be banned even though it's "internal." Conversely, **guest/IoT segments are intentionally left out** of the whitelist: they are untrusted and pass through the full security stack like any remote client.

3. **Harden on the hardware you have.** The goal is maximum security on the existing Gen 1 Miniserver *without buying new hardware*. Native TLS on the Miniserver, Remote Connect, Trusts, and per-user/per-device identity are Gen 2+ features and are **deferred to a future "v2" with new hardware** — explicitly out of scope here.

4. **The availability trade-off is accepted, not engineered away.** Because remote clients roam onto shared or rotating IPs (mobile carriers, iCloud Private Relay / Cloudflare WARP), the CAPI community blocklist can occasionally block a legitimate user for another tenant's behavior — and a rotating IP **cannot be pre-whitelisted**. We keep the community blocklist for its protection value and resolve such cases reactively (see "Legitimate User Blocked").

---

## Threat Model

### What We're Protecting Against

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| **Internet scanning / reconnaissance** | Certain | High | nftables DROP by default, CrowdSec CAPI |
| **Brute force on web UI** | High | Critical | nginx rate limits, CrowdSec scenarios |
| **Application-layer DDoS** | Medium | High | nginx conn limits, timeouts, CrowdSec |
| **Volumetric DDoS** | Low | Critical | *Cannot stop at gateway — ISP/cloud only* |
| **Credential stuffing** | High | Critical | Rate limits + CrowdSec http-cve |
| **Exploitation of Loxone CVEs** | Medium | Critical | AppSec WAF (virtual patching), WAF rules |
| **Lateral movement (LAN → Miniserver)** | Low | High | Proxmox firewall, VLAN isolation |
| **Lateral movement (LAN → Gateway via SSH)** | Low | Critical | `setup_ssh_hardening` — CIS §5.2 drop-in, key-only, `PermitRootLogin no`, `MaxAuthTries 4` |
| **Config file password extraction** | Medium | High | *Physical access control only* |
| **Cloud DNS hijacking (CVE-2020-27488)** | Low | High | Disable Cloud DNS, use static IP |

### SSH model — LAN-side only

The gateway exposes `:22` only to `SSH_ALLOWED_SUBNETS` via nftables. The internet never sees SSH on this host — there is **no** `endlessh`-style tarpit because there is no public attack surface on port 22 to absorb. The hardening matters for the inside-the-LAN attacker scenario only: a compromised laptop, smart-TV, or IoT toaster trying to pivot from the LAN to the gateway. `deploy.sh` ships a CIS Debian 12 §5.2 drop-in (key-only, no root, VERBOSE log) with a first-deploy bootstrap that prevents the lock-yourself-out chicken-and-egg (see `CONFIGURATION-GUIDE.md` → "SSH Key Bootstrap").

### What the Miniserver CANNOT Do (Gen 1 Limitations)

- No HTTPS/TLS (hardware can't handle SSL CPU load)
- No WebSocket over WSS
- Passwords in config XML are encrypted, not hashed — decryptable in memory
- No multi-factor authentication
- No session timeout controls
- No built-in rate limiting
- No IP-based access control
- No audit logging
- Firmware updates have slowed; the last known security patch was in 2020 (Cloud DNS vulnerability CVE-2020-27488). New security features (TLS, Remote Connect, Trusts) are Gen 2+ only.

### What the Gateway DOES

The gateway is the **entire security layer**. Every protection the Miniserver lacks is implemented here.

---

## Architecture

```
Internet ──► Router:1080 ──► Gateway VM:1080 ──► Loxone:80
                    │              │
                    │              ├── nginx (proxy, rate limits, headers)
                    │              ├── CrowdSec (IDS, CAPI blocks, AppSec WAF)
                    │              ├── nftables (input DROP, allow :1080 + SSH)
                    │              ├── AppArmor (nginx profile enforced)
                    │              ├── auditd (config change monitoring)
                    │              ├── Discord alerts (real-time notifications)
                    │              └── Network watchdog (self-healing monitor)
                    │
                    └── LAN:<LAN_SUBNET> ──► Loxone:80 (direct, bypass)
```

---

## Implemented Protections

### Layer 1: Network Firewall (nftables)

- Input policy: **DROP**
- Allowed inbound: SSH (LAN + site2site only), :1080 (any source)
- Forward policy: DROP
- CrowdSec bouncer manages dynamic `table ip crowdsec` for live blocks
- Static rules in `table inet filter` never wiped on reload

### Layer 2: Reverse Proxy (nginx)

- Rate limit: 10 req/s per IP, burst 100
- Connection limit: 20 concurrent per IP
- Slowloris protection: aggressive timeouts (10-15s)
- Security headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, **Content-Security-Policy**, **Permissions-Policy**
- `server_tokens off`; `proxy_hide_header Server` and `proxy_hide_header X-Powered-By` to prevent backend version leakage
- Buffer limits to prevent memory exhaustion
- AppSec subrequest: every request evaluated by CrowdSec WAF before proxying

### Layer 3: Intrusion Detection (CrowdSec)

- CAPI community feed: ~26k known malicious IPs auto-blocked
- Local scenarios: nginx bad requests, SSH brute force, HTTP CVEs
- AppSec WAF: virtual patching for known CVEs, SQLi, XSS, path traversal
- Whitelist: LAN, site2site, uptime monitor, Heroku prowl IPs
- SSH acquisition via `/var/log/auth.log`

### Layer 4: Application Security (AppSec WAF)

- Mode: **enforce** (blocks matched requests with 403)
- Collection: `crowdsecurity/appsec-virtual-patching` (200+ CVE-specific rules)
- Listens on `127.0.0.1:7422`
- Evaluates every request before it reaches Loxone
- **Authentication**: AppSec requires the CrowdSec firewall bouncer API key in the `X-Crowdsec-Appsec-Api-Key` header
- **Required headers**: `X-Crowdsec-Appsec-Ip`, `X-Crowdsec-Appsec-Uri`, `X-Crowdsec-Appsec-Verb`
- The nginx `auth_request` subrequest passes these headers automatically via `/etc/nginx/crowdsec-appsec.conf`
- **Risk note**: The AppSec API key is stored in `/etc/nginx/crowdsec-appsec.conf` (mode 640, root:www-data). If an attacker achieves local file read (e.g., via LFI in Loxone or a compromised nginx worker), they could extract this key and bypass the WAF. This is a known, accepted risk for this architecture. Mitigation: keep Loxone and nginx fully patched; consider systemd `LoadCredential=` for memory-only secret injection (requires njs/Lua in nginx).
- AppSec metrics: `cscli metrics | grep -A3 Appsec`

### Layer 5: System Hardening

- AppArmor: nginx profile enforced
- systemd: PrivateTmp, NoNewPrivileges, ProtectKernelTunables, etc.
- Kernel: syncookies, rp_filter, dmesg_restrict, kptr_restrict, ASLR
- auditd: monitors nginx/crowdsec/nftables config changes, auth files, sudo
- unattended-upgrades: auto-reboot at 03:00 for kernel patches

### Layer 6: Monitoring & Alerting

- **Discord webhook**: real-time alerts for blocks, anomalies, service failures
- **Security monitor** (60s cycle): CrowdSec decisions, nginx errors, auth attempts, AppSec detections, system resources
- **Network watchdog** (60s cycle): Detects network-layer failures (dhclient death-spiral, kernel routing corruption, interface desync) that process-level checks miss. Self-heals by restarting services; reboots as last resort with pre/post-reboot Discord reporting and anti-loop protection.
- **Log rotation**: 14-day retention for nginx logs
- **Config backup**: daily automated backup to `/root/loxprox-backups/`
- **Test suite**: `sudo ./test-gateway.sh` validates all components post-deploy

---

## What Could Be Added (Future Hardening)

### Geo-blocking
- Block high-risk countries via ipdeny.com + nftables set
- Status: Script created, not enabled by default (may break traveling users)
- Enable: `GEOIP_ENABLED=true /opt/loxprox/geoip-block.sh`

### Fail2ban (redundant but extra layer)
- SSH: max 3 failed logins in 10 min = 1 hour ban
- nginx: 404 scanning detection
- Status: Not installed — CrowdSec handles this natively

### TLS Termination on :1080 (shipped in v1.5.0, opt-in)

The Miniserver itself still cannot speak TLS (Gen 1 CPU constraint — unchanged), so the no-TLS device behind the gateway remains the architectural reality. What changed in v1.5.0: **the gateway can now terminate HTTPS on `:1080` toward the public side** via `acme.sh` + HTTP-01, with an automatic renewal cron that's verified after every deploy. The acme.sh installer is pinned by SHA256 (no `curl|bash`), the issued cert lives at `/etc/loxprox/tls/` (mode 0640), and the public surface widens by exactly one listener — `:80`, scoped to `/.well-known/acme-challenge/` plus a 301 redirect to HTTPS-on-1080. Off by default; toggled by a single `ENABLE_TLS` key in `/etc/loxprox/deploy.conf`. The disable path reverts the site and cancels the renewal cron but keeps the cert files, so flipping back is fast. Full runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).

### Volumetric DDoS Protection
- **Cannot be done at this gateway** — 512MB RAM / 1 vCPU
- Options: Cloudflare Spectrum, AWS Shield, ISP-level scrubbing
- Status: Documented limitation

### Network Segmentation
- Place Loxone in isolated VLAN
- Gateway in DMZ VLAN
- Firewall rules: only gateway IP → Loxone:80
- Status: Requires router/Proxmox changes

### Honeypot Endpoints
- Fake `/admin`, `/wp-login.php`, etc. on gateway
- CrowdSec detects scanners hitting honeypots → instant ban
- Status: Easy to add via nginx location blocks

---

## Operational Commands

```bash
# Verify all components
sudo bash /tmp/test-gateway.sh

# Check CrowdSec decisions
sudo cscli decisions list

# Check CrowdSec alerts
sudo cscli alerts list

# Check AppSec metrics
sudo cscli metrics | grep -A3 Appsec

# Check nftables rules
sudo nft list ruleset

# View real-time nginx access log
sudo tail -f /var/log/nginx/loxone-access.log

# View monitor log
sudo tail -f /var/log/loxprox-monitor.log

# Manually ban an IP
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual-ban"

# Unban an IP
sudo cscli decisions delete --ip 1.2.3.4

# Re-run full deployment
sudo bash /tmp/deploy.sh
```

---

## Incident Response Playbook

### Gateway Unresponsive

1. Check Proxmox console: `systemctl status nginx crowdsec`
2. If overwhelmed: revert router forwarding to Loxone IP directly
3. Investigate logs later, restore gateway, re-cutover

### Legitimate User Blocked

1. `cscli decisions list` → find their IP
2. `cscli decisions delete --ip <IP>`
3. Add to whitelist if recurring **and the IP is stable** (a fixed LAN/VLAN subnet, a static remote office, etc.)

**Roaming / shared-egress clients (mobile).** A remote user on a mobile carrier, iCloud Private Relay, or Cloudflare WARP egresses from a **shared, rotating** IP (e.g. `104.28.x.x` for Private Relay). The CAPI community blocklist can list such an IP because of *another* tenant's behavior, blocking your user through no fault of their own. You **cannot** pre-whitelist a rotating IP — there is no stable target. This is an accepted trade-off of keeping the community blocklist on a no-VPN public path (see "Scope & Design Invariants"). Handle it reactively with step 2; if a trusted user is hit repeatedly, advise them to disable Private Relay / WARP so they present a more stable carrier IP.

> **Not a ban — the `https://` migration trap.** If a Loxone app "can't connect" but `cscli decisions list` shows **no** decision for its IP, the cause is almost always the TLS scheme, not a block. See "The Loxone app can't connect after I enabled TLS" in `CONFIGURATION-GUIDE.md`.

### Loxone Unreachable Externally

1. Verify router forwarding: external 1080 → `<GATEWAY_IP>:1080`
2. Verify gateway health: `systemctl status nginx`
3. Verify gateway → Loxone reachability: `curl http://<LOXONE_IP>:80/jdev/cfg/api`
4. Check nginx error log for backend timeouts
5. Run test suite: `sudo bash /tmp/test-gateway.sh`

### Discord Webhook Rotation

If a webhook URL is compromised or you need to rotate credentials:
1. In Discord: Server Settings → Integrations → Webhooks → Delete the old webhook
2. Create a new webhook and copy the URL
3. Update `DISCORD_WEBHOOK_URL` in `deploy.sh` (or directly in `/etc/loxprox/config.env`)
4. Re-run `deploy.sh` or restart the monitor timer: `systemctl restart loxprox-monitor.timer`
5. Verify: trigger a test alert (e.g., `sudo /opt/loxprox/discord-alert.sh INFO "Test" "Rotation verified"`)

**Note**: The webhook URL is stored in `/etc/loxprox/config.env` with mode 640. Only root and the loxprox group can read it.

### AppSec Returning 401 Errors

If you see AppSec 401 errors in nginx logs, the bouncer API key may have changed:
1. Read current key: `awk '/^api_key:/ {print $2}' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local`
2. Update `/etc/nginx/crowdsec-appsec.conf` with the new key
3. `sudo nginx -s reload`
4. Or simply re-run `deploy.sh` which regenerates the include file automatically

---

## Compliance Notes

- **No GDPR/Privacy compliance** on the Miniserver itself — logs contain IP addresses
- Gateway logs include source IPs (required for security analysis)
- Discord alerts include IP addresses and request details
- Retention: 14 days for nginx, system logs managed by journald
