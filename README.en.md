**Language:** [Deutsch](README.md) · English

# LoxProx — Hardened Gateway for Loxone Miniservers

[![Release](https://img.shields.io/github/v/release/sgtsilver/loxprox?label=release&color=brightgreen)](https://github.com/sgtsilver/loxprox/releases)
[![CI](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml/badge.svg)](https://github.com/sgtsilver/loxprox/actions/workflows/ci.yml)
[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-red.svg)](#license)
[![Debian 12](https://img.shields.io/badge/Debian-12-A81D33?logo=debian)](#)

> **A drop-in security gateway for the Loxone Miniserver Gen 1.** No TLS, no built-in auth, no rate limits — LoxProx adds every protection the hardware lacks, transparently. Your app keeps working; the gateway takes the hits.

```
Internet ──► Router:1080 ──► LoxProx Gateway:1080 ──► Loxone:80
                                   │
                                   ├── nginx (Host/SNI gate + scanner trap, proxy, rate limits, headers)
                                   ├── CrowdSec (IDS, CAPI blocks, AppSec WAF, HARD/SOFT ban ladders)
                                   ├── nftables (input DROP, GeoIP drop, allow :1080 + SSH; :80 with TLS)
                                   ├── AppArmor (nginx profile: complain → opt-in enforce)
                                   ├── auditd (config-change monitoring)
                                   ├── LoxProx Panel (:1081, LAN only)
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

- **Drop-in & idempotent** — one script; `git pull && sudo bash deploy.sh` re-runs safely. The nginx site `/etc/nginx/sites-available/loxone` is regenerated whenever it drifts from the template or from your `deploy.conf` (backed up first; a failing `nginx -t` reverts it), so hand-edits do **not** survive a redeploy — set `LOXPROX_KEEP_NGINX_SITE=1` to freeze a hand-maintained site ([details](CONFIGURATION-GUIDE.md#re-running-deploysh--nginx-site-regeneration--exit-codes)).
- **Defense in depth** — nginx reverse proxy + CrowdSec IDS + AppSec WAF + nftables + AppArmor + auditd, layered.
- **Scanner elimination (v3.0)** — with TLS, `:1080` and `:80` serve only your real host name (`TLS_DOMAIN` + `EXTRA_SERVER_NAMES`). A bare IP, a missing SNI, a foreign `Host` or a scanner path lands in a trap (444 + log) and gets a **HARD ban**: 7 days, then 90, then 365. Other offences ride a **SOFT ladder** (24 h → 7 → 30 → 90 days), and `progressive-ban.py` extends repeat offenders. Every app uses `https://<hostname>:1080`, never the IP; roll out with `TRAP_BAN_MODE="observe"` first, and list a known prober in `TRAP_EXEMPT_IPS` if needed.
- **Admin paths closed (v3.0)** — the plain Loxone admin webservices (`fsget`, `fsdel`, `sys/reboot`, …) answer `403` from the internet (`REMOTE_ADMIN_PATHS="allow"` reopens them); the LAN and `TRUSTED_SOURCES` are exempt. This filters plain HTTP paths only — the Miniserver's own credentials remain the real control.
- **Never banned is not trusted (v3.0)** — `CROWDSEC_WHITELIST_IPS` only stops bans; nginx trusts just loopback, `LAN_SUBNET` and the new `TRUSTED_SOURCES`.
- **GeoIP drop** — nftables drops CN, RU, KP and IR (IPv4 + IPv6). Travellers in those countries are blocked too.
- **Transparent** — LAN traffic goes straight to the Miniserver; only internet traffic is inspected, so local users are never slowed down.
- **Optional HTTPS on `:1080`** — terminate TLS via `acme.sh` + Let's Encrypt (with ZeroSSL fallback), covering the no-TLS device behind it.
- **Optional zero-open-ports remote access (v2.0)** — frp tunnel via your own relay VPS for CGNAT/DS-Lite connections; self-hosted, no subscription, with its own watchdog. See [Tunnel Setup](docs/TUNNEL-SETUP.md).
- **LAN-only web panel (v2.1, on by default)** — status tiles, log viewing, config editing, and one-click support actions (unban, restart, TLS renew) at `http://<gateway-ip>:1081`, reachable only from `LAN_SUBNET` and `SSH_ALLOWED_SUBNETS`. `GUI_PASSWORD` is empty by default — set one. See [GUI Panel](docs/GUI-PANEL.md).
- **Lightweight** — runs on a 1 vCPU / 1 GB VM (2 vCPU / 2 GB recommended); Raspberry Pi hardware is in scope but not a tested target (see [Hardware Requirements](#hardware-requirements)).
- **Self-healing** — a network watchdog detects and recovers stack failures automatically.
- **Real-time alerts** — optional Discord notifications for blocks, errors, and anomalies.
- **CIS-aligned hardening** — SSH, kernel sysctls, auditd and unattended-upgrades follow CIS Debian 12 guidance. This is not a certification; a 2026-05 AI-assisted, repo-only self-audit of v1.3.3 is kept in [`audits/`](audits/2026-05-23-skills-audit.md).

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
7. **Validate** — `sudo bash test-gateway.sh` (100+ automated checks)
8. **Cut over** — follow [`phase3-cutover.md`](phase3-cutover.md) to switch router forwarding to the gateway. (The phase guides predate the VM-only decision: the gateway is a VM, so run their commands inside the VM instead of `pct exec`.)
9. **Monitor** — follow [`phase4-monitoring.md`](phase4-monitoring.md) to tune and observe. (Same note: run the commands inside the VM instead of `pct exec`; use `qm` instead of `pct` on Proxmox.)

The deploy script is **idempotent** — `git pull && sudo bash deploy.sh` re-runs safely. It is not a hand-edit-preserving upgrade: since v2.3.0 it regenerates `/etc/nginx/sites-available/loxone` from the template whenever the file or your `deploy.conf` drifted (with a backup, and a revert if `nginx -t` fails). Set `LOXPROX_KEEP_NGINX_SITE=1` to freeze a hand-maintained site — template fixes and `deploy.conf` changes then no longer reach it. See the [Configuration Guide](CONFIGURATION-GUIDE.md#re-running-deploysh--nginx-site-regeneration--exit-codes).

### Upgrading to v3.0.0 (from v2.3.0)

Upgrade in place with `sudo bash deploy.sh` over SSH. Read the [upgrade notes](CHANGELOG.md#upgrade-notes--from-v230) and **Behaviour changes you must act on** at the top of the [changelog](CHANGELOG.md) first. The short version:

- **Start in observe mode.** Set `TRAP_BAN_MODE="observe"` (`ban` is the default) in `/etc/loxprox/deploy.conf` and deploy: the trap still answers 444 and logs, but nobody is banned. After a few days check `sudo cscli alerts list -s loxprox/scanner-trap --limit 0` and `/var/log/nginx/loxprox-trap-hosts.log` for your own devices, fix them, then set `"ban"` and redeploy.
- **Re-add every Loxone app and device with the host name** (`https://<your-host>:1080`). With TLS on, a bare IP, a missing SNI or a foreign `Host` is a trap hit: a 444 and a HARD ban (7 days on the first offence).
- **Admin webservice paths answer `403` from the internet.** `REMOTE_ADMIN_PATHS="allow"` proxies them again; the LAN and `TRUSTED_SOURCES` are exempt anyway.
- **Root SSH login is off in HARD mode** once a non-root account has a key, sudo rights and a login shell. Put your key on a sudo user first, then run `sudo bash deploy.sh --finalize-ssh`; otherwise root stays `prohibit-password` and the deploy warns.
- **`TRUSTED_SOURCES` vs `CROWDSEC_WHITELIST_IPS`.** A whitelist entry now means "never banned", no longer "trusted": it gets the admin-path `403` and the auth/WebSocket limits like any internet client. If a whitelisted network really administers the Miniserver through the gateway, add it to `TRUSTED_SOURCES` *before* you deploy.

Other changes (much longer bans, security updates installing again, how to probe `:1080` on the gateway itself) are in the upgrade notes.

**Good to know:**
- **Upgrading from v1.3.x or older?** Run `sudo bash deploy.sh --bootstrap-config` once — it reads your live values back into `/etc/loxprox/deploy.conf`. Walkthrough: [`docs/UPGRADE-to-v1.5.md`](docs/UPGRADE-to-v1.5.md). Then follow the v3.0.0 notes above.
- **Want HTTPS?** Enable `ENABLE_TLS="true"` (needs a public DNS name + a `WAN:80 → gateway:80` forward for ACME). With TLS on, every app and device must use `https://<hostname>:1080` — never the IP, which is a trap hit and a HARD ban. Runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).
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

### Family access & the LoxProx Panel

Want to hand your Miniserver connection to family members? The QR-code
onboarding flow in [`docs/FAMILY-ONBOARDING.md`](docs/FAMILY-ONBOARDING.md)
gets a phone connected in under a minute. Since v2.1, the same QR code,
connection status, and a one-click unban button are also available from
the gateway's own **LoxProx Panel** — a LAN-only web UI at
`http://<gateway-ip>:1081`. See [`docs/GUI-PANEL.md`](docs/GUI-PANEL.md).

---

## Security Layers

| # | Layer | Purpose |
|---|-------|---------|
| 1 | **nftables** | Input DROP by default; SSH restricted to the LAN; `:1080` open to the internet (plus `:80` for ACME when TLS is on); the LoxProx Panel `:1081` only from the LAN; GeoIP drop of CN, RU, KP and IR (IPv4 + IPv6) |
| 2 | **nginx** | Reverse proxy, 10 req/s rate limit, connection caps, security headers, slowloris timeouts; with TLS a Host/SNI gate with a scanner trap (444 + log); admin webservice paths answer `403` from the internet (`REMOTE_ADMIN_PATHS`); auth and WebSocket limits per untrusted address |
| 3 | **CrowdSec** | IDS parsing nginx + SSH logs; CAPI community blocklist; HARD (7 d → 90 d → 365 d) and SOFT (24 h → 7 → 30 → 90 d) ban ladders, extended for repeat offenders by `progressive-ban.py` |
| 4 | **Firewall Bouncer** | Pulls CrowdSec decisions → enforces them dynamically in nftables |
| 5 | **AppSec WAF** | Virtual patching for known CVEs in common software (CrowdSec hub rules); inspects every request before proxying |
| 6 | **AppArmor** | nginx profile — runs in complain mode (logs, does not block) until you opt into enforce with `APPARMOR_NGINX_MODE="enforce"` after the soak ([ADR 0006](docs/adr/0006-apparmor-nginx-profile-complain-first.md)) |
| 7 | **auditd** | Monitors config changes to nginx, crowdsec, nftables, ssh, sudoers, LoxProx's own config, the AppArmor policy and the scripts under `/opt/loxprox` |
| 8 | **unattended-upgrades** | Debian security updates; auto-reboot for kernel patches at `AUTOREBOOT_TIME` (default 03:00) |
| 9 | **Security monitor** | 60 s cycle: CrowdSec blocks, nginx errors, auth attempts, resource alerts → Discord |
| 10 | **Network watchdog** | Self-healing: detects network-layer failures (dhclient death-spiral, routing corruption) and recovers via service restart or reboot |
| 11 | **Log rotation** | nginx access, trap and unknown-path logs kept 90 days, error and AppSec logs 14 days; LoxProx's own logs weekly or at 10 MB (8 generations); journal capped at 300 MB |
| 12 | **Config backup** | Daily automated backups to `/root/loxprox-backups/` — includes `deploy.conf`, TLS cert+key, tunnel config, and the SSH drop-in; restore via `deploy.sh --restore <tarball>` |

---

## Configuration

Per-host settings live in **`/etc/loxprox/deploy.conf`** (mode 0640) — `deploy.sh` reads them at startup, so you never edit the script itself. Start from the tracked template `deploy.conf.example`; every value has an inline comment, and the full reference is [`CONFIGURATION-GUIDE.md`](CONFIGURATION-GUIDE.md).

The values you'll actually set:

```bash
LOXONE_IP="192.168.1.100"                 # your Miniserver
GATEWAY_IP="192.168.1.50"                  # this gateway's static IP
LAN_SUBNET="192.168.1.0/24"                # trusted LAN (nginx trusts it: no admin-path 403, no auth/WebSocket limits)
SSH_ALLOWED_SUBNETS=("192.168.1.0/24")     # who may reach SSH
CROWDSEC_WHITELIST_IPS=("192.168.1.0/24")  # never banned (not trusted by nginx); keep your LAN here, add your household WAN IP
RATE_LIMIT_REQ_PER_SEC="10"
RATE_LIMIT_BURST="100"
ENABLE_APPSEC="true"
APPSEC_MODE="enforce"                      # "monitor" or "enforce"
ENABLE_TLS="false"                         # optional HTTPS on :1080 (see TLS-SETUP)
TLS_DOMAIN=""                              # needed when ENABLE_TLS="true": the public host name every app must use
TLS_EMAIL=""                               # needed when ENABLE_TLS="true": ACME account e-mail
TRAP_BAN_MODE="ban"                        # "observe" for the first rollout: trap answers 444 + logs, bans nothing
ENABLE_GUI="true"                          # LoxProx Panel on :1081, LAN only
GUI_PASSWORD=""                            # empty = no password: set one
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

**Supported target: a Debian 12 (Bookworm) VM.** That is what the reference deployment and the project's tests run on. The CrowdSec package repository is pinned to `bookworm`, and `deploy.sh` only warns on any other OS ("continuing"). Debian 13 and current Raspberry Pi OS are untested.

**Miniserver:** Gen 1 (plain HTTP on port 80) is the tested target. `detect-loxone.sh` also recognises a Gen 2 or newer by its HTTPS answer and then only suggests enabling TLS on the gateway; a Gen 2 or newer setup has not been tested.

The reference deployment is a **Proxmox VM with 1 vCPU and 1 GB RAM**. Memory use was last measured on v1.x and has not been re-measured since the Panel, the log watchers and the extra CrowdSec scenarios arrived — check `free -m` on your own gateway before you shrink the VM below the recommendation.

**Why 2 vCPU / 2 GB is recommended:** CrowdSec's leaky-bucket memory scales with the number of distinct active attacker IPs — 256 IPs ≈ 150 MB, 15,000 IPs ≈ 1.2–1.5 GB ([source](https://www.crowdsec.net/blog/how-to-process-billions-daily-events-with-crowdsec)). A wide-cardinality scan blows up RAM accordingly. The AppSec WAF costs roughly **5 ms / 50 millicores per request** with Virtual Patching enabled ([source](https://docs.crowdsec.net/docs/appsec/benchmark/)) — a second vCPU keeps `nginx` responsive for legitimate users during the first 30–60 seconds of an attack, before the bouncer catches up and drops attackers at the nftables layer. 1 vCPU / 1 GB is fine for steady-state home-automation traffic; the recommended sizing is the headroom that matters under attack.

> ⚠️ **Substrate: VM, not LXC.** Inside an unprivileged Proxmox LXC, several hardening steps silently fail because they write to host-kernel state the container cannot reach:
>
> - `kernel.unprivileged_userns_clone = 0` — the **Fragnesia / CVE-2026-46300 mitigation** returns `EPERM` and does not take effect (the knob is global, not per-netns).
> - `kernel.dmesg_restrict`, `kernel.kptr_restrict`, `kernel.randomize_va_space`, `fs.protected_*` — all host-wide, not writable from a container namespace.
> - **auditd** — the kernel has exactly one audit consumer per netlink socket, owned by the host; `augenrules --load` fails and config-tamper detection is gone.
> - **AppArmor enforcement** — `aa-enforce` loads profiles into the host's subsystem; the container cannot.
> - **nftables** — an unprivileged LXC's capability set rejects creating the `inet filter` table.
>
> `deploy.sh` detects LXC and **aborts by default**. `ALLOW_LXC=1 sudo ./deploy.sh` overrides it — but the documented hardening posture no longer applies.

### Raspberry Pi viability

Raspberry Pi hardware is in scope, but it is **not a tested target**: the project's own tests and reference deployment run on an x86-64 Debian 12 VM. The table below follows CrowdSec's published architecture support, not LoxProx test runs. Use a 64-bit Debian 12 (Bookworm)-based OS; current Raspberry Pi OS (Debian 13-based) is untested. Run `sudo bash test-gateway.sh` after the deploy.

| Model | Architecture | RAM | Expected compatibility | Notes |
|-------|-------------|-----|---------------|-------|
| **Pi 5** | ARMv8 (64-bit) | 2–8 GB | ✅ Full | Overkill. Runs effortlessly. |
| **Pi 4** | ARMv8 (64-bit) | 1–8 GB | ✅ Full | Ideal. Official CrowdSec ARM64 packages. |
| **Pi 3** | ARMv8 (64-bit) | 1 GB | ✅ Full | Good fit. Use 64-bit Raspberry Pi OS. |
| **Pi 2** | ARMv7 (32-bit) | 1 GB | ⚠️ Partial | CrowdSec officially requires 64-bit. Community success with 64-bit kernel or manual build; not recommended for production untested. |
| **Pi 1 / Zero (original)** | ARMv6 | 512 MB | ❌ No | No ARMv6 binaries from CrowdSec. |
| **Pi Zero 2 W** | ARMv8 (64-bit) | 512 MB | ⚠️ Tight | 64-bit OS works, but 512 MB is tight — may need swap and scenario pruning. |

Per-process memory figures for a Pi are not given here: the numbers earlier versions of this README quoted were measured on v1.x and predate the Panel and the 2026-10 hardening. Measure on your own board. Prior art: [CrowdSec on a Pi 3 (DietPi)](https://it-security.dnit.fr/en/crowdsec-installation-on-rpi3-with-dietpi-raspberry-os/), [CrowdSec + nginx on Raspberry Pi (2025)](https://www.polimetro.com/en/How-to-protect-your-Raspberry-Pi-with-CrowdSec/).

---

## Threats Mitigated

| Threat | Mitigation |
|--------|-----------|
| Internet scanning / reconnaissance (Shodan/Censys-style crawlers) | nftables DROP default, Host/SNI gate + trap (444, no fingerprint), HARD ban ladder (7 d → 90 d → 365 d), GeoIP drop (CN/RU/KP/IR), CrowdSec community blocklist |
| Remote use of the Loxone admin webservices (file system, reboot) | `403` from the internet on the plain paths (`REMOTE_ADMIN_PATHS`); LAN and `TRUSTED_SOURCES` exempt |
| Brute force on web UI | nginx rate limits + CrowdSec `http-generic-bf` |
| Application-layer DDoS | nginx conn limits, timeouts, CrowdSec |
| Credential stuffing | Rate limits, auth-endpoint limits (3 req/s per untrusted address) + CrowdSec `http-cve` |
| Exploitation of known web CVEs | AppSec WAF virtual patching (CrowdSec hub rules — coverage is whatever the hub ships, not Loxone-specific) |
| SSH brute force | CrowdSec `ssh-bf` + nftables source restriction |
| Slowloris / slow-read | nginx aggressive timeouts (10–15 s) |
| Config tampering | auditd (+ AppArmor once enforced) |

**Not mitigated:** volumetric DDoS (link saturation). A 1–2 GB gateway cannot absorb a pipe-filling attack — that needs ISP-level scrubbing or a cloud service.

---

## Operations & Testing

After deploying, run the validation suite — **100+ automated checks** across services, firewall, proxy, CrowdSec, AppSec, monitoring, kernel hardening, and backups (it even adds and removes a test ban to verify the full blocking pipeline):

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
| [LoxProx Panel](docs/GUI-PANEL.md) · [DE](docs/GUI-PANEL.de.md) | v2.1: LAN-only web GUI — family QR, status, config, unban |
| [Upgrade to v1.5](docs/UPGRADE-to-v1.5.md) · [DE](docs/UPGRADE-to-v1.5.de.md) | Migrating from v1.3.x (config bootstrap) |
| [Security](SECURITY.md) · [DE](SECURITY.de.md) | Threat model, incident response, hardening |
| [Phase guides](phase1-hardening.md) | [1: hardening](phase1-hardening.md) · [3: cutover](phase3-cutover.md) · [4: monitoring](phase4-monitoring.md) |
| [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) | Version history (incl. the [upgrade notes from v2.3.0](CHANGELOG.md#upgrade-notes--from-v230)) · how to contribute |

---

## How This Project Is Built

This is an experiment in **AI-assisted, human-curated infrastructure hardening** — multiple AIs, none of them the sole architect; one human with the veto and the operational responsibility.

- **Idea, hardware, and the final call:** [sgtsilver](https://github.com/sgtsilver) — IT systems administrator. Knows how attackers actually behave and how to defend infrastructure against them; doesn't write code. Brings the network, the Miniserver, the real-world constraints, and the operational instinct to tell a genuinely sound design apart from one that only sounds clever.
- **Design and implementation — a rotating panel of AIs:** [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) did the original architecture and most of the code. [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviews, fact-checks, finds and fixes bugs, and contributes follow-on work (the v1.3.4 supply-chain and kernel-hardening release among others). Other models (GPT, Gemini, …) get pulled in to second-guess specific decisions when the stakes warrant it.
- **The rule:** AIs propose, AIs cross-examine each other, and nothing lands because one model said so — it lands because the cross-examination didn't break it *and* a human sysadmin's gut said "yes, that's how you actually defend infrastructure." A clever-sounding suggestion that fails either filter gets dropped, no matter which model proposed it.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This is a specialized security appliance — contributions should stay focused on Loxone-gateway hardening, Raspberry Pi compatibility, and test coverage. User-facing docs are bilingual (German + English); keep both in sync in the same PR. The changelog, the rundown, ADRs and audit records are English-only.

**Getting help:** open a [GitHub issue](https://github.com/sgtsilver/loxprox/issues) for questions and bugs; for security problems follow [SECURITY.md](SECURITY.md) (Responsible Disclosure).

---

## License

**Source-available, free for non-commercial use** — see [LICENSE](LICENSE). The Software may be used, modified, and distributed freely for personal, educational, research, and non-commercial purposes. Commercial use — directly or indirectly, in whole or in part — is strictly prohibited.

---

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) — the collaborative IDS/WAF engine that makes community-driven blocking possible.
- [Loxone](https://www.loxone.com/) — the home-automation platform this gateway protects (even if they stopped patching Gen 1).
- The home-automation community — for documenting the Gen-1 limitations clearly enough that an AI panel could build around them.
