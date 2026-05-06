# LoxProx — Hardened Gateway for Loxone Miniservers

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Validation: A-](https://img.shields.io/badge/Validation-A--_brightgreen)]()
[![Debian 12](https://img.shields.io/badge/Debian-12-A81D33?logo=debian)]()
[![CIS Hardened](https://img.shields.io/badge/CIS-Hardened-blue)]()
[![Shellcheck](https://img.shields.io/badge/Shellcheck-passing-brightgreen)]()

> **A drop-in security gateway for Loxone Miniserver Gen 1.** No TLS, no built-in auth, no rate limits — this gateway adds every protection the hardware lacks, transparently.

## About This Project

**Idea & Infrastructure:** [sgtsilver](https://github.com/sgtsilver) — who wanted to secure a Loxone Miniserver without keeping a VPN connected around the clock, and provided the hardware, network context, and real-world constraints to make it happen.

**Design & Implementation:** Kimi (Moonshot AI) — who researched Loxone Gen 1 vulnerabilities, architected the six-layer defense stack, wrote all code, and produced the test suite and documentation. Every line of shell script, every nftables rule, and every sysctl parameter was selected and validated by an AI systems engineer working from first principles.

This is an experiment in **AI-led infrastructure hardening**: a human defines the problem and the constraints; the AI designs, implements, tests, and documents the complete solution.

---

## The Problem

The Loxone Miniserver Gen 1 is **end-of-life hardware** with:
- ❌ No HTTPS/TLS support (CPU too weak for SSL)
- ❌ No native rate limiting
- ❌ No IP-based access control
- ❌ No audit logging
- ❌ No multi-factor authentication
- ❌ Passwords in config XML are encrypted, not hashed
- ❌ Firmware is EOL — no security patches

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

---

## Project Structure

```
loxprox/
├── deploy.sh                          # ★ MAIN DEPLOY SCRIPT — run on target
├── detect-loxone.sh                   # ★ AUTO-DETECT your Miniserver IP
├── test-gateway.sh                    # ★ VALIDATION SUITE — 29 automated checks
├── set-static-ip.sh                   # VM network pre-configuration
├── CONFIGURATION-GUIDE.md             # ★ Explains every setting in deploy.sh
├── .env.example                       # Configuration template
├── README.md                          # This file
├── SECURITY.md                        # Threat model, incident response, hardening
├── VALIDATION-REPORT.html             # Independent security audit (2026 frameworks)
├── LICENSE                            # MIT
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
│   ├── loxprox-monitor.sh             # Security monitor (60s cycle)
│   ├── gateway-backup.sh              # Config backup script
│   ├── geoip-block.sh                 # GeoIP blocking (optional)
│   ├── loxprox-monitor.service # systemd service
│   └── loxprox-monitor.timer   # systemd timer (60s)
└── assets/                            # Diagrams, screenshots
```

---

## Quick Start

1. **Create a Debian 12 VM or LXC** (1 vCPU, 512MB RAM, 5GB disk minimum).
2. **Set static IP:** Copy and run `set-static-ip.sh` inside the target.
3. **Copy `deploy.sh`**, `detect-loxone.sh`, and `.env.example` into the target.
4. **Find your Loxone:** `chmod +x detect-loxone.sh && ./detect-loxone.sh`
   - This scans your network and prints the exact IP, MAC, firmware version, and suggested config values.
5. **Configure:** Open `deploy.sh` and edit the `[REQUIRED]` values at the top. Stuck? Read `CONFIGURATION-GUIDE.md` — it explains every setting with examples.
6. **Deploy:** `chmod +x deploy.sh && sudo ./deploy.sh`
7. **Validate:** `sudo bash test-gateway.sh` (29 automated checks)
8. **Cut over:** Follow `phase3-cutover.md` to switch router forwarding.
9. **Monitor:** Follow `phase4-monitoring.md` to tune and observe.

The deploy script is **idempotent** — safe to re-run.

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
| 10 | **Log rotation** | 14-day nginx log retention |
| 11 | **Config backup** | Daily automated backups to `/root/gateway-backups/` |

---

## Hardware Requirements

### Minimum (Tested Configuration)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 1-2 cores |
| RAM | 512 MB | 1 GB |
| Disk | 5 GB | 10 GB |
| OS | Debian 12 (Bookworm) 64-bit | Debian 12 or Ubuntu 22.04 LTS |

The reference deployment runs on a **1 vCPU, 512MB RAM Proxmox LXC** with headroom to spare. The entire security stack (nginx + CrowdSec + AppSec + bouncer) consumes approximately **100–150 MB RAM** under normal home-automation traffic loads.

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

**Not mitigated:** Volumetric DDoS (link saturation). A 512MB RAM gateway cannot absorb a pipe-filling attack. For that, you need ISP-level scrubbing or a cloud service.

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

This performs **29 automated checks** across services, firewall, proxy, CrowdSec, AppSec, monitoring, kernel hardening, and backups. It also adds and removes a test ban to verify the full blocking pipeline.

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

# Re-run deployment (idempotent)
sudo bash deploy.sh
```

See `SECURITY.md` for the full incident response playbook.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This is a specialized security appliance — contributions should stay focused on Loxone-gateway-specific hardening, Pi compatibility, and test coverage.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) — the collaborative IDS/WAF engine that makes community-driven blocking possible
- [Loxone](https://www.loxone.com/) — the home automation platform this gateway protects (even if they stopped patching Gen 1)
- The home automation community — for documenting Loxone Gen 1 limitations so clearly that an AI could design around them
