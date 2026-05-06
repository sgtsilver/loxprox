# GitHub Metadata for LoxProx

Live repo: **https://github.com/sgtsilver/loxprox**

---

## Repository Description

> Hardened security gateway for Loxone Miniservers. Reverse proxy + WAF + IDS + firewall + monitoring — because your smart home deserves a deadbolt.

---

## Topics (Tags)

Copy all of these into the repo "Topics" field (max 20):

```
loxone, smart-home, home-automation, security-gateway, reverse-proxy, nginx, crowdsec, waf, ids, intrusion-detection, firewall, nftables, debian, homelab, selfhosted, iot-security, miniserver, proxy, hardening, cybersecurity
```

---

## Social Preview Image (Optional)

Recommended: 1280×640px. Text: "LoxProx — Hardened Gateway for Loxone Miniservers"
Colors: Dark background (#0d1117), green accent (#238636), white text.

---

## Releases — v1.0.0 Notes

Title: `LoxProx v1.0.0 — Production Ready`

Body:
```markdown
## LoxProx v1.0.0

A hardened security gateway for Loxone Miniservers. Deploys a Debian 12 VM as a protective reverse proxy with WAF, IDS, firewall, and automated monitoring.

### What's Included
- **nginx reverse proxy** with CrowdSec AppSec WAF
- **CrowdSec IDS** with community threat intelligence
- **nftables firewall** with rate limiting & GeoIP blocking
- **Automated monitoring** with Discord alerting
- **Network autodetector** — finds your Miniserver automatically
- **29-check validation suite** — verify every security control
- **Self-contained HTML report** — A- grade across 9 security frameworks

### Quick Start
```bash
curl -fsSL https://raw.githubusercontent.com/sgtsilver/loxprox/main/deploy.sh | sudo bash
```

See [CONFIGURATION-GUIDE.md](CONFIGURATION-GUIDE.md) for required variables.

### Validation
- **Grade:** A- (Production Ready)
- **Controls:** 29/34 pass, 5 are enhancements
- **Frameworks:** CIS Debian 12, OWASP Top 10 2026, OWASP IoT Top 10

### Hardware
- VM: 1 vCPU, 512MB RAM, 4GB disk
- Raspberry Pi 4/5: fully supported (ARM64)
- Raspberry Pi 3: supported with 64-bit OS

### Attribution
Built by Paul Dewald with [Kimi](https://kimi.moonshot.cn) ([Moonshot AI](https://www.moonshot.cn)). See [README.md](README.md#attribution) for details.
```

---

## README Badges

Already added to README.md:
- License: MIT
- Validation: A-
- Debian 12
- CIS Hardened
- Shellcheck: passing
