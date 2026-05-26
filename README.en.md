**Language:** [Deutsch](README.md) · English

# LoxProx — Hardened Gateway for Loxone Miniservers

[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-red.svg)](#license)
[![Validation: A-](https://img.shields.io/badge/Validation-A--_brightgreen)]()
[![Debian 12](https://img.shields.io/badge/Debian-12-A81D33?logo=debian)]()
[![CIS Hardened](https://img.shields.io/badge/CIS-Hardened-blue)]()
[![Shellcheck](https://img.shields.io/badge/Shellcheck-passing-brightgreen)]()

> **A drop-in security gateway for Loxone Miniserver Gen 1.** No TLS, no built-in auth, no rate limits — this gateway adds every protection the hardware lacks, transparently.

## About This Project

**Idea, hardware, and the final call:** [sgtsilver](https://github.com/sgtsilver) — IT systems administrator. Knows how attackers actually behave, knows how to defend infrastructure against them, doesn't write code. Brought the network, the Miniserver, the real-world constraints, and the operational instinct to tell apart a genuinely sound design from one that only sounds clever.

**Design and implementation: a rotating panel of AIs.** [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) did the original architecture and most of the code. [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviews, fact-checks, finds and fixes bugs, and contributes follow-on work (the v1.3.4 supply-chain and kernel-hardening release among others). Other models (GPT, Gemini, etc.) get pulled in to second-guess specific decisions when the stakes warrant it.

**The rule:** AIs propose. AIs cross-examine each other. Nothing lands in the codebase because one model said it should — it lands because the cross-examination didn't break it *and* a human sysadmin's gut said "yes, that's how you actually defend infrastructure." A clever-sounding suggestion that doesn't survive either filter gets dropped, no matter which model proposed it.

This is an experiment in **AI-assisted, human-curated infrastructure hardening**. Multiple AIs, none of them the sole architect; one human with the veto and the operational responsibility.

---

## The Problem

The Loxone Miniserver Gen 1 is **legacy first-generation hardware** with:
- ❌ No HTTPS/TLS support (CPU too weak for SSL)
- ❌ No native rate limiting
- ❌ No IP-based access control
- ❌ No audit logging
- ❌ No multi-factor authentication for web/API access
- ❌ Passwords in config XML are encrypted, not hashed
- ⚠️ Firmware updates have slowed significantly; the last known security patch was in 2020 (Cloud DNS vulnerability CVE-2020-27488). New security features (TLS, Remote Connect, Trusts) are Gen 2+ only.

It is the definition of a *legacy device that must be protected by the network layer*.

This gateway exists because the Miniserver cannot protect itself.

---

## Architecture

```
Internet ──► Router:1080 ──► Security Gateway:1080 ──► Loxone:80
                                    │
                                    ├── nginx (proxy, rate limits, headers)
                                    ├── CrowdSec (IDS, CAPI blocks, AppSec WAF)
                                    ├── nftables (input DROP, allow :1080 + SSH)
                                    ├── AppArmor (nginx profile enforced)
                                    ├── auditd (config change monitoring)
                                    └── Discord alerts (real-time notifications)

LAN (192.168.x.0/24) ──────► Loxone:80  (direct, bypasses gateway)
```

**Design principle:** LAN devices reach Loxone directly. Only internet traffic passes through the gateway. This means LAN users are unaffected, and the gateway can focus entirely on external threats.

> 🕵️ **What's next?** We've been exploring whether loxprox could one day bridge Gen 1 Miniservers to the outside world — without a VPN, without hardware upgrades. The research rabbit hole went deeper than expected. If you're curious, [#4](https://github.com/sgtsilver/loxprox/issues/4) has the full story (and the caveats).

---

## Project Structure

```
loxprox/
├── deploy.sh                          # ★ MAIN DEPLOY SCRIPT — run on target
├── detect-loxone.sh                   # ★ AUTO-DETECT your Miniserver IP
├── test-gateway.sh                    # ★ VALIDATION SUITE — 50+ automated checks
├── progressive-ban.py                 # CrowdSec progressive-ban escalator (cron, 15min)
├── set-static-ip.sh                   # VM network pre-configuration
├── CONFIGURATION-GUIDE.md             # ★ Explains every setting in deploy.sh
├── .env.example                       # Configuration template
├── README.md                          # German version (rendered on repo home)
├── README.en.md                       # This file (English)
├── SECURITY.md                        # Threat model, incident response, hardening
├── VALIDATION-REPORT.html             # Independent security audit (2026 frameworks)
├── LICENSE                            # Non-Commercial
├── CONTRIBUTING.md                    # Contribution guidelines
├── CHANGELOG.md                       # Version history
├── phase1-hardening.md                # Proxmox firewall + Loxone hardening
├── phase2-gateway/
│   ├── nginx-loxone.conf              # Nginx reverse proxy config (reference)
│   ├── crowdsec-acquis.yaml           # CrowdSec log source config (reference)
│   └── sysctls.conf                   # Kernel tuning (reference)
├── phase3-cutover.md                  # Router + firewall cutover steps
├── phase4-monitoring.md               # Monitoring, log rotation, tuning
├── security-monitoring/
│   ├── discord-alert.sh               # Discord webhook dispatcher
│   ├── gateway-monitor.sh             # Security monitor (60s cycle)
│   ├── network-watchdog.sh            # Network stack self-healing watchdog
│   ├── network-watchdog.service       # systemd system service (root)
│   ├── network-watchdog.timer         # systemd timer (60s)
│   ├── gateway-backup.sh              # Config backup script
│   ├── geoip-block.sh                 # GeoIP blocking (optional)
│   ├── loxprox-monitor.service        # systemd service
│   └── loxprox-monitor.timer          # systemd timer (60s)
└── assets/                            # Diagrams, screenshots
```

---

## Quick Start

1. **Create a Debian 12 VM** (1 vCPU, 512MB RAM, 5GB disk minimum).
   > ⚠️ **VM only — no LXC.** Several gateway defenses (kernel sysctls including the Fragnesia mitigation, auditd, AppArmor enforcement, nftables in unprivileged containers) cannot be applied from inside an LXC and are silently skipped by `deploy.sh`. The deployment looks green but does not deliver the documented security posture. See [Hardware Requirements](#hardware-requirements) and `CHANGELOG.md` for details. Operators who knowingly accept the reduced posture can deploy with `ALLOW_LXC=1 sudo ./deploy.sh`.
2. **Set static IP:** Copy and run `set-static-ip.sh` inside the target.
3. **Copy `deploy.sh`**, `detect-loxone.sh`, and `.env.example` into the target.
4. **Find your Loxone:** `chmod +x detect-loxone.sh && ./detect-loxone.sh`
   - This scans your network and prints the exact IP, MAC, firmware version, and suggested config values.
5. **Configure:** Create your per-host configuration file:
   ```bash
   sudo install -d -m 0750 /etc/loxprox
   sudo cp deploy.conf.example /etc/loxprox/deploy.conf
   sudo $EDITOR /etc/loxprox/deploy.conf      # fill in [REQUIRED] values
   ```
   `deploy.sh` sources this file at startup — no more editing the script itself (as of v1.5.0). Stuck on a value? Read `CONFIGURATION-GUIDE.md`.
6. **Deploy:** `chmod +x deploy.sh && sudo ./deploy.sh`
7. **Validate:** `sudo bash test-gateway.sh` (50+ automated checks)
8. **Cut over:** Follow `phase3-cutover.md` to switch router forwarding.
9. **Monitor:** Follow `phase4-monitoring.md` to tune and observe.

The deploy script is **idempotent and upgrade-safe**: `git pull && sudo bash deploy.sh` just works. Operator edits to `/etc/nginx/sites-available/loxone` (e.g. a WebSocket block) survive every redeploy.

> **Upgrading from v1.4.x?** Run `sudo bash deploy.sh --bootstrap-config` once — it reads back your current values from live nftables / nginx / CrowdSec and writes them to `/etc/loxprox/deploy.conf`. Full walkthrough in `docs/UPGRADE-v1.4-to-v1.5.md`.

> **SSH bootstrap:** On first run the script checks for an existing `authorized_keys`. If none exists it **won't lock you out** — instead it shows an interactive menu: paste your public key (with fingerprint confirmation), show help for creating one (`ssh-keygen` on macOS/Linux/Windows), keep password auth for now (loud warning banner on every login), or abort. Non-interactive deploys fall back to soft mode automatically. After `ssh-copy-id`, run `sudo bash deploy.sh --finalize-ssh` to swap to the hard profile. Full details in `CONFIGURATION-GUIDE.md` → "SSH Key Bootstrap".

> **Threat-model note:** Port 22 is LAN-side only (nftables drops anything outside `SSH_ALLOWED_SUBNETS`). The hardening doesn't shield against internet SSH scanners — it shields against a compromised LAN host trying to brute-force the gateway from inside the perimeter. Stock Debian ships `PasswordAuthentication yes`; that window is what the deploy closes.

---

## What's Deployed

| Layer | Component | Purpose |
|-------|-----------|---------|
| 1 | **nftables** | Input DROP by default; SSH restricted to LAN; :1080 open to internet |
| 2 | **nginx** | Reverse proxy, 10 req/s rate limit, connection caps, security headers, slowloris timeouts |
| 3 | **CrowdSec** | IDS parsing nginx + SSH logs; CAPI community feed (~26k known bad IPs) |
| 4 | **Firewall Bouncer** | Pulls CrowdSec decisions → enforces via nftables dynamically |
| 5 | **AppSec WAF** | Virtual patching (200+ CVE-specific rules); inspects every request before proxying |
| 6 | **AppArmor** | nginx profile enforced |
| 7 | **auditd** | Monitors config changes to nginx, crowdsec, nftables, ssh, sudoers |
| 8 | **unattended-upgrades** | Auto-reboot at 03:00 for kernel patches |
| 9 | **Security monitor** | 60s cycle: CrowdSec blocks, nginx errors, auth attempts, resource alerts → Discord |
| 10 | **Network watchdog** | Self-healing monitor: detects network-layer failures (dhclient death-spiral, routing corruption) and auto-recovers via service restart or reboot |
| 11 | **Log rotation** | 14-day nginx log retention |
| 12 | **Config backup** | Daily automated backups to `/root/loxprox-backups/` |

---

## Hardware Requirements

### Minimum (Tested Configuration)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 vCPU | **2 vCPU** |
| RAM | **1 GB** | **2 GB** |
| Disk | 5 GB | 10 GB |
| OS | Debian 12 (Bookworm) 64-bit | Debian 12 |

The reference deployment runs on a **Proxmox VM with 1 vCPU and 1 GB RAM**, sitting at **~850 MB RSS** under normal operation. The stack itself (nginx + CrowdSec + AppSec + bouncer) consumes 100–150 MB at idle; the rest is Debian base and page cache.

**Why 2 vCPU / 2 GB is recommended:** CrowdSec's leaky-bucket memory scales with the number of distinct active attacker IPs — 256 IPs ≈ 150 MB, 15,000 IPs ≈ 1.2–1.5 GB ([source](https://www.crowdsec.net/blog/how-to-process-billions-daily-events-with-crowdsec)). A wide-cardinality scan (many unique source IPs) blows up RAM accordingly. The AppSec WAF costs roughly **5 ms / 50 millicores of CPU per request** with the Virtual Patching ruleset enabled ([source](https://docs.crowdsec.net/docs/appsec/benchmark/)) — a second vCPU lets the kernel keep `nginx` responsive for legitimate users during the first 30–60 seconds of an attack, before the bouncer catches up and starts dropping attackers at the nftables layer. 1 vCPU / 1 GB is fine for steady-state home-automation traffic; the recommended sizing is the headroom that matters under attack.

> ⚠️ **Substrate: VM, not LXC.** LoxProx is a VM-only deployment. Inside an unprivileged Proxmox LXC, several hardening steps silently fail because they write to host-kernel state the container cannot reach:
>
> - `kernel.unprivileged_userns_clone = 0` — the **Fragnesia / CVE-2026-46300 mitigation** documented elsewhere in this project returns `EPERM` and does not take effect. This knob is global, not per-netns.
> - `kernel.dmesg_restrict`, `kernel.kptr_restrict`, `kernel.randomize_va_space`, `fs.protected_*` — all host-wide, not writable from a container namespace.
> - **auditd** — the kernel has **exactly one** audit consumer per netlink socket, owned by the host. `augenrules --load` fails; the config-tamper detection for `nftables`/`nginx`/`sshd`/`sudoers` is gone.
> - **AppArmor enforcement** — `aa-enforce` loads profiles into the host's AppArmor subsystem; the container cannot do this for itself.
> - **nftables** — the default capability set of an unprivileged LXC rejects creation of the `inet filter` table.
>
> `deploy.sh` detects an LXC substrate and **aborts by default**. Operators who knowingly accept the degraded posture can deploy with `ALLOW_LXC=1 sudo ./deploy.sh` — the documented CIS Debian 12 and OWASP IoT Top 10 posture no longer applies in that configuration.

### Raspberry Pi Viability

This stack is **designed to be lightweight enough for Raspberry Pi** home automation deployments.

| Model | Architecture | RAM | Compatibility | Notes |
|-------|-------------|-----|---------------|-------|
| **Pi 5** | ARMv8 (64-bit) | 2–8 GB | ✅ Full | Overkill. Will run effortlessly. |
| **Pi 4** | ARMv8 (64-bit) | 1–8 GB | ✅ Full | Ideal. Official CrowdSec ARM64 packages available. |
| **Pi 3** | ARMv8 (64-bit) | 1 GB | ✅ Full | Good fit. Use 64-bit Raspberry Pi OS. |
| **Pi 2** | ARMv7 (32-bit) | 1 GB | ⚠️ Partial | CrowdSec officially requires 64-bit. Community reports success with 64-bit kernel or manual ARMv7 compile. Not recommended for production without testing. |
| **Pi 1 / Zero (original)** | ARMv6 | 512 MB | ❌ No | CrowdSec does not provide ARMv6 binaries. |
| **Pi Zero 2 W** | ARMv8 (64-bit) | 512 MB | ⚠️ Tight | 64-bit OS supported, but 512MB RAM is tight. May need swap and scenario pruning. |

**Comparable projects running similar stacks on Pi:**

- [CrowdSec on Raspberry Pi 3 with DietPi](https://it-security.dnit.fr/en/crowdsec-installation-on-rpi3-with-dietpi-raspberry-os/) — running CrowdSec + nftables on Pi 3 since 2021
- [Home Assistant community](https://community.learnlinux.tv/t/reverse-proxy-for-home-automation/4325) — users running 18+ Docker containers (including nginx reverse proxy) on Pi 4 at ~18% CPU, 2.5GB RAM
- [CrowdSec + Nginx on Raspberry Pi](https://www.polimetro.com/en/How-to-protect-your-Raspberry-Pi-with-CrowdSec/) — comprehensive 2025 guide for Pi 3/4/5
- [CrowdSec Firewall Bouncer on low-end VPS](https://github.com/crowdsecurity/crowdsec/issues/3641) — 2-core, 2GB RAM OpenCloudOS deployment with nginx + ModSecurity + CrowdSec

**Resource estimates for this stack on Pi:**

| Service | RAM (typical) |
|---------|--------------|
| nginx (1 worker) | ~5–10 MB |
| CrowdSec agent | ~30–50 MB |
| CrowdSec firewall bouncer | ~10–20 MB |
| AppSec WAF | ~20–40 MB |
| OS overhead | ~100–200 MB |
| **Total** | **~165–320 MB** |

A Pi 3 or Pi 4 handles this with room to spare. A Pi 2 may work with a 64-bit kernel or source compile, but Pi 3+ is strongly recommended.

---

## Threats Mitigated

| Threat | Mitigation |
|--------|-----------|
| Internet scanning / reconnaissance | nftables DROP default + CrowdSec CAPI |
| Brute force on web UI | nginx rate limits + CrowdSec `http-generic-bf` |
| Application-layer DDoS | nginx conn limits, timeouts, CrowdSec |
| Credential stuffing | Rate limits + CrowdSec `http-cve` |
| Exploitation of Loxone CVEs | AppSec WAF (200+ virtual patches) |
| SSH brute force | CrowdSec `ssh-bf` + nftables source restriction |
| Slowloris / slow-read | nginx aggressive timeouts (10–15s) |
| Config tampering | auditd + AppArmor |

**Not mitigated:** Volumetric DDoS (link saturation). A 1–2 GB gateway cannot absorb a pipe-filling attack. For that, you need ISP-level scrubbing or a cloud service.

---

## Configuration

All tunables are at the top of `deploy.sh`:

```bash
LOXONE_IP="192.168.1.100"           # Your Miniserver IP
GATEWAY_IP="192.168.1.50"           # This gateway's static IP
LAN_SUBNET="192.168.1.0/24"         # LAN that can reach SSH
SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")
RATE_LIMIT_REQ_PER_SEC="10"
RATE_LIMIT_BURST="100"
ENABLE_APPSEC="true"
APPSEC_MODE="enforce"                # "monitor" or "enforce"
```

Discord alerting is optional. Set `DISCORD_WEBHOOK_URL` in the config section or leave empty to skip.

---

## Testing

After deployment, run the validation suite:

```bash
sudo bash test-gateway.sh
```

This performs **50+ automated checks** across services, firewall, proxy, CrowdSec, AppSec, monitoring, kernel hardening, and backups. It also adds and removes a test ban to verify the full blocking pipeline.

---

## Operational Commands

```bash
# Check all components
sudo bash test-gateway.sh

# View CrowdSec blocks
sudo cscli decisions list

# Check AppSec metrics
sudo cscli metrics | grep -A3 Appsec

# View live nginx access log
sudo tail -f /var/log/nginx/loxone-access.log

# Manually ban an IP
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual"

# Unban an IP
sudo cscli decisions delete --ip 1.2.3.4

# Check network watchdog status
sudo systemctl status network-watchdog.timer
sudo journalctl -u network-watchdog -f

# Disable/enable network watchdog
sudo systemctl stop network-watchdog.timer
sudo systemctl enable --now network-watchdog.timer

# Re-run deployment (idempotent)
sudo bash deploy.sh
```

See `SECURITY.md` for the full incident response playbook.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This is a specialized security appliance — contributions should stay focused on Loxone-gateway-specific hardening, Pi compatibility, and test coverage.

---

## License

**Non-Commercial Use Only** — see [LICENSE](LICENSE).

The Software may be used, modified, and distributed freely for personal,
educational, research, and non-commercial purposes. Commercial use — directly
or indirectly, in whole or in part — is strictly prohibited.

---

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) — the collaborative IDS/WAF engine that makes community-driven blocking possible
- [Loxone](https://www.loxone.com/) — the home automation platform this gateway protects (even if they stopped patching Gen 1)
- The home automation community — for documenting Loxone Gen 1 limitations so clearly that an AI could design around them
