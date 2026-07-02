**Language:** [Deutsch](README.md) · English

# LoxProx — Hardened Gateway for Loxone Miniservers

[![Release](https://img.shields.io/github/v/release/sgtsilver/loxprox?label=release&color=brightgreen)](https://github.com/sgtsilver/loxprox/releases)
[![CI](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml/badge.svg)](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml)
[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-red.svg)](#license)
[![Validation: A-](https://img.shields.io/badge/Validation-A--_brightgreen)](#)
[![Debian 12](https://img.shields.io/badge/Debian-12-A81D33?logo=debian)](#)
[![CIS Hardened](https://img.shields.io/badge/CIS-Hardened-blue)](#)

> **A drop-in security gateway for the Loxone Miniserver Gen 1.** No TLS, no built-in auth, no rate limits — LoxProx adds every protection the hardware lacks, transparently. Your app keeps working; the gateway takes the hits.

```
Internet ──► Router:1080 ──► LoxProx Gateway:1080 ──► Loxone:80
                                   │
                                   ├── nginx (proxy, rate limits, headers)
                                   ├── CrowdSec (IDS, CAPI blocks, AppSec WAF)
                                   ├── nftables (input DROP, allow :1080 + SSH)
                                   ├── AppArmor (nginx profile enforced)
                                   ├── auditd (config-change monitoring)
                                   └── Discord alerts (real-time)

LAN (192.168.x.0/24) ──────────► Loxone:80   (direct — bypasses the gateway)
```

---

## Contents

- [Why LoxProx?](#why-loxprox)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Security Layers](#security-layers)
- [Configuration](#configuration)
- [Hardware Requirements](#hardware-requirements)
- [Threats Mitigated](#threats-mitigated)
- [Operations & Testing](#operations--testing)
- [Documentation](#documentation)
- [How This Project Is Built](#how-this-project-is-built)
- [Contributing](#contributing) · [License](#license) · [Acknowledgments](#acknowledgments)

---

## Why LoxProx?

The Loxone Miniserver Gen 1 is **legacy first-generation hardware** that cannot protect itself — no HTTPS (the CPU is too weak for SSL), no rate limiting, no IP access control, no audit logging, no MFA, passwords in config XML are encrypted rather than hashed, and the last known security patch was in **2020** (Cloud-DNS vuln [CVE-2020-27488](https://nvd.nist.gov/vuln/detail/CVE-2020-27488)). New security features (TLS, Remote Connect, Trusts) are Gen 2+ only.

LoxProx sits in front of it and supplies the whole missing security layer.

**Highlights**

- **Drop-in & idempotent** — one script; `git pull && sudo bash deploy.sh` re-runs safely and survives upgrades (your nginx hand-edits included).
- **Defense in depth** — nginx reverse proxy + CrowdSec IDS + AppSec WAF + nftables + AppArmor + auditd, layered.
- **Transparent** — LAN traffic goes straight to the Miniserver; only internet traffic is inspected, so local users are never slowed down.
- **Optional HTTPS on `:1080`** — terminate TLS via `acme.sh` + Let's Encrypt (with ZeroSSL fallback), covering the no-TLS device behind it.
- **Optional zero-open-ports remote access (v2.0)** — frp tunnel via your own relay VPS for CGNAT/DS-Lite connections; self-hosted, no subscription, with its own watchdog. See [Tunnel Setup](docs/TUNNEL-SETUP.md).
- **Lightweight** — runs on a 1 GB VM or a Raspberry Pi 3+.
- **Self-healing** — a network watchdog detects and recovers stack failures automatically.
- **Real-time alerts** — optional Discord notifications for blocks, errors, and anomalies.
- **Independently validated** — A- against CIS Debian 12 + OWASP IoT Top 10.

---

## Quick Start

> **New to Linux?** Own a Loxone Miniserver but never touched a terminal? No problem — we won't judge or gatekeep. Follow the gentle, copy-paste walkthrough instead: **[Installation for Linux Newbies](docs/INSTALL-FOR-NEWBIES.md)**.

1. **Create a Debian 12 VM** — 1 vCPU, 1 GB RAM, 5 GB disk minimum (see [Hardware Requirements](#hardware-requirements)). **VM only — not LXC** (several defenses silently no-op in a container; `deploy.sh` aborts unless you set `ALLOW_LXC=1`).
2. **Set a static IP** — copy and run `set-static-ip.sh` inside the target.
3. **Copy the repo** to the target (`git clone` or scp).
4. **Find your Miniserver** — `chmod +x detect-loxone.sh && ./detect-loxone.sh` prints its IP, MAC, firmware, and suggested config values.
5. **Write your config:**
   ```bash
   sudo install -d -m 0750 /etc/loxprox
   sudo cp deploy.conf.example /etc/loxprox/deploy.conf
   sudo $EDITOR /etc/loxprox/deploy.conf      # fill in the [REQUIRED] values
   ```
6. **Deploy** — `chmod +x deploy.sh && sudo ./deploy.sh`
7. **Validate** — `sudo bash test-gateway.sh` (50+ automated checks)
8. **Cut over** — follow [`phase3-cutover.md`](phase3-cutover.md) to switch router forwarding to the gateway.
9. **Monitor** — follow [`phase4-monitoring.md`](phase4-monitoring.md) to tune and observe.

The deploy script is **idempotent and upgrade-safe** — `git pull && sudo bash deploy.sh` just works, and operator edits to `/etc/nginx/sites-available/loxone` (e.g. a WebSocket block) survive every redeploy.

**Good to know:**
- **Upgrading from v1.3.x?** Run `sudo bash deploy.sh --bootstrap-config` once — it reads your live values back into `/etc/loxprox/deploy.conf`. Walkthrough: [`docs/UPGRADE-to-v1.5.md`](docs/UPGRADE-to-v1.5.md).
- **Want HTTPS?** Enable `ENABLE_TLS="true"` (needs a public DNS name + a `WAN:80 → gateway:80` forward for ACME). Runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).
- **Behind CGNAT / DS-Lite (no port forwarding possible)?** Enable the v2.0 tunnel: a small relay VPS becomes your public entry point, the gateway dials out. Runbook: [`docs/TUNNEL-SETUP.md`](docs/TUNNEL-SETUP.md).
- **SSH won't lock you out.** On first run, if no `authorized_keys` exists, the installer shows an interactive menu (paste a key, get help making one, or keep password auth with a warning) and falls back to a safe mode for non-interactive deploys. Details: [`CONFIGURATION-GUIDE.md`](CONFIGURATION-GUIDE.md) → "SSH Key Bootstrap".

---

## How It Works

```
Internet ──► Router:1080 ──► LoxProx Gateway:1080 ──► Loxone:80
LAN ───────────────────────────────────────────────► Loxone:80   (direct)
```

**Design principle:** LAN devices reach the Miniserver directly; only internet traffic passes through the gateway. This means local users are unaffected, and the gateway can focus entirely on external threats. Every external request is rate-limited, run through the CrowdSec AppSec WAF, and checked against the community blocklist before nginx ever proxies it to the Miniserver.

**Can't forward a port (CGNAT / DS-Lite)?** Since v2.0 there is a second path to the outside — the research teased in [#4](https://github.com/sgtsilver/loxprox/issues/4) is now a feature:

```
App ──► https://your-domain (relay VPS:443) ──► frp tunnel ──► gateway:1080 ──► Loxone:80
                                                (dialed OUT from home)
```

The gateway dials out to a self-hosted relay VPS; not a single port needs to be opened on the router. TLS terminates at the relay, the gateway's full security stack stays on the path, and the relay adds its own CrowdSec perimeter. Two-step setup: [`tunnel-relay/install-relay.sh`](tunnel-relay/README.md) on the VPS, then `ENABLE_TUNNEL="true"` on the gateway. Full runbook: [Tunnel Setup](docs/TUNNEL-SETUP.md).

---

## Security Layers

| # | Layer | Purpose |
|---|-------|---------|
| 1 | **nftables** | Input DROP by default; SSH restricted to the LAN; `:1080` open to the internet |
| 2 | **nginx** | Reverse proxy, 10 req/s rate limit, connection caps, security headers, slowloris timeouts |
| 3 | **CrowdSec** | IDS parsing nginx + SSH logs; CAPI community feed (~26k known-bad IPs) |
| 4 | **Firewall Bouncer** | Pulls CrowdSec decisions → enforces them dynamically in nftables |
| 5 | **AppSec WAF** | Virtual patching (200+ CVE-specific rules); inspects every request before proxying |
| 6 | **AppArmor** | nginx profile enforced |
| 7 | **auditd** | Monitors config changes to nginx, crowdsec, nftables, ssh, sudoers |
| 8 | **unattended-upgrades** | Auto-reboot at 03:00 for kernel patches |
| 9 | **Security monitor** | 60 s cycle: CrowdSec blocks, nginx errors, auth attempts, resource alerts → Discord |
| 10 | **Network watchdog** | Self-healing: detects network-layer failures (dhclient death-spiral, routing corruption) and recovers via service restart or reboot |
| 11 | **Log rotation** | 14-day nginx log retention |
| 12 | **Config backup** | Daily automated backups to `/root/loxprox-backups/` |

---

## Configuration

Per-host settings live in **`/etc/loxprox/deploy.conf`** (mode 0640) — `deploy.sh` reads them at startup, so you never edit the script itself. Start from the tracked template `deploy.conf.example`; every value has an inline comment, and the full reference is [`CONFIGURATION-GUIDE.md`](CONFIGURATION-GUIDE.md).

The values you'll actually set:

```bash
LOXONE_IP="192.168.1.100"                 # your Miniserver
GATEWAY_IP="192.168.1.50"                  # this gateway's static IP
LAN_SUBNET="192.168.1.0/24"                # trusted LAN
SSH_ALLOWED_SUBNETS=("192.168.1.0/24")     # who may reach SSH
RATE_LIMIT_REQ_PER_SEC="10"
RATE_LIMIT_BURST="100"
ENABLE_APPSEC="true"
APPSEC_MODE="enforce"                      # "monitor" or "enforce"
ENABLE_TLS="false"                         # optional HTTPS on :1080 (see TLS-SETUP)
ENABLE_TUNNEL="false"                      # optional zero-open-ports remote access (see TUNNEL-SETUP)
DISCORD_WEBHOOK_URL=""                     # optional alerting — leave empty to skip
```

---

## Hardware Requirements

### Minimum (tested configuration)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 vCPU | **2 vCPU** |
| RAM | **1 GB** | **2 GB** |
| Disk | 5 GB | 10 GB |
| OS | Debian 12 (Bookworm) 64-bit | Debian 12 |

The reference deployment runs on a **Proxmox VM with 1 vCPU and 1 GB RAM**, sitting at **~850 MB RSS** under normal operation. The stack itself (nginx + CrowdSec + AppSec + bouncer) consumes 100–150 MB at idle; the rest is Debian base and page cache.

**Why 2 vCPU / 2 GB is recommended:** CrowdSec's leaky-bucket memory scales with the number of distinct active attacker IPs — 256 IPs ≈ 150 MB, 15,000 IPs ≈ 1.2–1.5 GB ([source](https://www.crowdsec.net/blog/how-to-process-billions-daily-events-with-crowdsec)). A wide-cardinality scan blows up RAM accordingly. The AppSec WAF costs roughly **5 ms / 50 millicores per request** with Virtual Patching enabled ([source](https://docs.crowdsec.net/docs/appsec/benchmark/)) — a second vCPU keeps `nginx` responsive for legitimate users during the first 30–60 seconds of an attack, before the bouncer catches up and drops attackers at the nftables layer. 1 vCPU / 1 GB is fine for steady-state home-automation traffic; the recommended sizing is the headroom that matters under attack.

> ⚠️ **Substrate: VM, not LXC.** Inside an unprivileged Proxmox LXC, several hardening steps silently fail because they write to host-kernel state the container cannot reach:
>
> - `kernel.unprivileged_userns_clone = 0` — the **Fragnesia / CVE-2026-46300 mitigation** returns `EPERM` and does not take effect (the knob is global, not per-netns).
> - `kernel.dmesg_restrict`, `kernel.kptr_restrict`, `kernel.randomize_va_space`, `fs.protected_*` — all host-wide, not writable from a container namespace.
> - **auditd** — the kernel has exactly one audit consumer per netlink socket, owned by the host; `augenrules --load` fails and config-tamper detection is gone.
> - **AppArmor enforcement** — `aa-enforce` loads profiles into the host's subsystem; the container cannot.
> - **nftables** — an unprivileged LXC's capability set rejects creating the `inet filter` table.
>
> `deploy.sh` detects LXC and **aborts by default**. `ALLOW_LXC=1 sudo ./deploy.sh` overrides it — but the documented CIS Debian 12 / OWASP IoT Top 10 posture no longer applies.

### Raspberry Pi viability

The stack is **lightweight enough for Raspberry Pi** home-automation deployments.

| Model | Architecture | RAM | Compatibility | Notes |
|-------|-------------|-----|---------------|-------|
| **Pi 5** | ARMv8 (64-bit) | 2–8 GB | ✅ Full | Overkill. Runs effortlessly. |
| **Pi 4** | ARMv8 (64-bit) | 1–8 GB | ✅ Full | Ideal. Official CrowdSec ARM64 packages. |
| **Pi 3** | ARMv8 (64-bit) | 1 GB | ✅ Full | Good fit. Use 64-bit Raspberry Pi OS. |
| **Pi 2** | ARMv7 (32-bit) | 1 GB | ⚠️ Partial | CrowdSec officially requires 64-bit. Community success with 64-bit kernel or manual build; not recommended for production untested. |
| **Pi 1 / Zero (original)** | ARMv6 | 512 MB | ❌ No | No ARMv6 binaries from CrowdSec. |
| **Pi Zero 2 W** | ARMv8 (64-bit) | 512 MB | ⚠️ Tight | 64-bit OS works, but 512 MB is tight — may need swap and scenario pruning. |

Typical footprint on a Pi: nginx ~5–10 MB · CrowdSec agent ~30–50 MB · firewall bouncer ~10–20 MB · AppSec ~20–40 MB · OS ~100–200 MB → **~165–320 MB total**. A Pi 3 or Pi 4 handles it with room to spare. Prior art: [CrowdSec on a Pi 3 (DietPi)](https://it-security.dnit.fr/en/crowdsec-installation-on-rpi3-with-dietpi-raspberry-os/), [CrowdSec + nginx on Raspberry Pi (2025)](https://www.polimetro.com/en/How-to-protect-your-Raspberry-Pi-with-CrowdSec/).

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
| Slowloris / slow-read | nginx aggressive timeouts (10–15 s) |
| Config tampering | auditd + AppArmor |

**Not mitigated:** volumetric DDoS (link saturation). A 1–2 GB gateway cannot absorb a pipe-filling attack — that needs ISP-level scrubbing or a cloud service.

---

## Operations & Testing

After deploying, run the validation suite — **50+ automated checks** across services, firewall, proxy, CrowdSec, AppSec, monitoring, kernel hardening, and backups (it even adds and removes a test ban to verify the full blocking pipeline):

```bash
sudo bash test-gateway.sh
```

Day-to-day commands:

```bash
sudo cscli decisions list                       # view active blocks
sudo cscli metrics | grep -A3 Appsec            # AppSec metrics
sudo tail -f /var/log/nginx/loxone-access.log   # live access log
sudo cscli decisions add --ip 1.2.3.4 --duration 4h --reason "manual"   # ban
sudo cscli decisions delete --ip 1.2.3.4        # unban
sudo systemctl status network-watchdog.timer    # watchdog status
sudo bash deploy.sh                              # re-run deploy (idempotent)
```

The full incident-response playbook is in [`SECURITY.md`](SECURITY.md).

---

## Documentation

| Doc | What's inside |
|-----|---------------|
| [Installation for Linux Newbies](docs/INSTALL-FOR-NEWBIES.md) · [DE](docs/INSTALL-FOR-NEWBIES.de.md) | Gentle, no-jargon, copy-paste install walkthrough |
| [Configuration Guide](CONFIGURATION-GUIDE.md) · [DE](CONFIGURATION-GUIDE.de.md) | Every `deploy.conf` setting explained |
| [TLS Setup](docs/TLS-SETUP.md) · [DE](docs/TLS-SETUP.de.md) | Enabling HTTPS on `:1080` via acme.sh |
| [Tunnel Setup](docs/TUNNEL-SETUP.md) · [DE](docs/TUNNEL-SETUP.de.md) | v2.0: zero-open-ports remote access (CGNAT/DS-Lite) via a relay VPS |
| [Family Onboarding](docs/FAMILY-ONBOARDING.md) · [DE](docs/FAMILY-ONBOARDING.de.md) | QR-code onboarding for family phones, split-horizon DNS notes |
| [Upgrade to v1.5](docs/UPGRADE-to-v1.5.md) · [DE](docs/UPGRADE-to-v1.5.de.md) | Migrating from v1.3.x (config bootstrap) |
| [Security](SECURITY.md) · [DE](SECURITY.de.md) | Threat model, incident response, hardening |
| [Phase guides](phase1-hardening.md) | [1: hardening](phase1-hardening.md) · [3: cutover](phase3-cutover.md) · [4: monitoring](phase4-monitoring.md) |
| [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) | Version history · how to contribute |

---

## How This Project Is Built

This is an experiment in **AI-assisted, human-curated infrastructure hardening** — multiple AIs, none of them the sole architect; one human with the veto and the operational responsibility.

- **Idea, hardware, and the final call:** [sgtsilver](https://github.com/sgtsilver) — IT systems administrator. Knows how attackers actually behave and how to defend infrastructure against them; doesn't write code. Brings the network, the Miniserver, the real-world constraints, and the operational instinct to tell a genuinely sound design apart from one that only sounds clever.
- **Design and implementation — a rotating panel of AIs:** [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) did the original architecture and most of the code. [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviews, fact-checks, finds and fixes bugs, and contributes follow-on work (the v1.3.4 supply-chain and kernel-hardening release among others). Other models (GPT, Gemini, …) get pulled in to second-guess specific decisions when the stakes warrant it.
- **The rule:** AIs propose, AIs cross-examine each other, and nothing lands because one model said so — it lands because the cross-examination didn't break it *and* a human sysadmin's gut said "yes, that's how you actually defend infrastructure." A clever-sounding suggestion that fails either filter gets dropped, no matter which model proposed it.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This is a specialized security appliance — contributions should stay focused on Loxone-gateway hardening, Raspberry Pi compatibility, and test coverage. Every tracked Markdown doc is bilingual (German + English); keep both in sync in the same PR.

---

## License

**Non-Commercial Use Only** — see [LICENSE](LICENSE). The Software may be used, modified, and distributed freely for personal, educational, research, and non-commercial purposes. Commercial use — directly or indirectly, in whole or in part — is strictly prohibited.

---

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) — the collaborative IDS/WAF engine that makes community-driven blocking possible.
- [Loxone](https://www.loxone.com/) — the home-automation platform this gateway protects (even if they stopped patching Gen 1).
- The home-automation community — for documenting the Gen-1 limitations clearly enough that an AI panel could build around them.
