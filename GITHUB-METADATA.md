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

## Releases

Release notes live on the GitHub Releases page — they're sourced from `CHANGELOG.md` and authored at tag time, not here. Don't draft release bodies in this file (they go stale).

- Current shelf: https://github.com/sgtsilver/loxprox/releases
- For changes since the last release, see `CHANGELOG.md`.

> **Do not** publish a `curl … | sudo bash` install line. The CrowdSec install in `deploy.sh` was hardened in v1.1.0 (CRIT-001 fix) specifically to remove pipe-to-shell from the supply chain — publishing one for `deploy.sh` itself would reintroduce the same vector. Users should `git clone` (or download a tagged tarball), inspect, then run.

---

## README Badges

Already added to README.md:
- License: MIT
- Validation: A-
- Debian 12
- CIS Hardened
- Shellcheck: passing
