# LoxProx — Project Rundown

**Status:** Published on GitHub  
**Repo:** https://github.com/sgtsilver/loxprox  
**Version:** 1.0.0  
**Last updated:** 2026-05-06

---

## What This Is

A drop-in security gateway for Loxone Miniserver Gen 1 (and Gen 2). It sits between the internet and your Miniserver, adding every protection the hardware lacks: TLS termination, rate limiting, WAF, IDS, firewall, audit logging, and real-time alerting.

LAN traffic bypasses the gateway entirely — only external traffic is inspected.

---

## Architecture at a Glance

```
Internet ──► Router:1080 ──► Gateway:1080 ──► Loxone:80
                                    │
                                    ├── nginx (proxy, rate limits, headers)
                                    ├── CrowdSec (IDS + CAPI blocks + AppSec WAF)
                                    ├── nftables (input DROP, allow :1080 + SSH)
                                    ├── AppArmor (nginx profile)
                                    ├── auditd (config change monitoring)
                                    └── Discord alerts (real-time)
```

---

## Key Files

| File | Purpose |
|------|---------|
| `deploy.sh` | One-shot Debian 12 hardening & installation (870 lines, idempotent) |
| `detect-loxone.sh` | Network autodetector — finds your Miniserver by MAC OUI and API fingerprint |
| `test-gateway.sh` | 29-check validation suite — run after deploy to verify every control |
| `set-static-ip.sh` | Pre-deploy VM network configuration |
| `security-monitoring/` | Discord alerts, health monitor, config backup, GeoIP block script |
| `VALIDATION-REPORT.html` | Self-contained HTML report — A- grade, 9 security frameworks |

---

## Known Quirks & Lessons Learned

### CrowdSec AppSec Authentication
CrowdSec AppSec requires the **firewall bouncer API key** (not the LAPI machine key) in the `X-Crowdsec-Appsec-Api-Key` header, plus `X-Crowdsec-Appsec-Ip`, `-Uri`, and `-Verb`. This was completely undocumented in standard CrowdSec guides and caused hours of 401 debugging. The bouncer `.local` file is the source of truth.

### CrowdSec Whitelist CIDR Syntax
CrowdSec's parser expects `cidr:` for ranges, not `ip:`. Using `ip:192.168.178.0/24` causes a FATAL parser error. `cidr:192.168.178.0/24` is correct.

### nftables Table Isolation
The `crowdsec-firewall-bouncer` manages its own `table ip crowdsec` with timeout-based sets. When reloading static rules, use `flush table inet filter` — never `flush ruleset` — or you wipe the bouncer's dynamic blocks.

### German Locale Breaks `free` Parsing
The monitor script parses `free -m` output. On German locales, `Mem:` becomes `Speicher:` and numbers use commas. Fix: `LC_ALL=C free -m`.

### Loxone Gen 1 Has No TLS
The Miniserver Gen 1 CPU cannot handle SSL. The gateway terminates TLS and speaks HTTP to the Miniserver. This is a hardware limitation, not a design choice.

---

## Hardware Tested

| Platform | Status | Notes |
|----------|--------|-------|
| Debian 12 VM (Proxmox) | ✅ Production | 1 vCPU, 512MB RAM, 4GB disk |
| Raspberry Pi 4/5 | ✅ Supported | Official ARM64 packages |
| Raspberry Pi 3 | ✅ Supported | Requires 64-bit Raspberry Pi OS |
| Raspberry Pi 2 | ⚠️ Partial | Needs 64-bit kernel or manual compile |
| Raspberry Pi 1 / Zero | ❌ Not supported | ARMv6, no 64-bit support |

---

## CI / GitHub Actions

Workflow in `.github/workflows/ci.yml`:
- **ShellCheck** on all `.sh` files (warning severity)
- **Syntax check** — `bash -n` on every script
- **Markdown link check** — validates all documentation links

---

## Roadmap / Ideas

- [ ] Ansible role for fleet deployment
- [ ] Docker/Podman container version
- [ ] Web dashboard for CrowdSec decisions + gateway metrics
- [ ] Automatic TLS certificate renewal monitoring
- [ ] Support for Loxone Miniserver Go (cloud-dependent)
- [ ] Tailscale/WireGuard integration for remote management
- [ ] Prometheus metrics export

---

## Citation

See `CITATION.cff` for academic citation metadata.
