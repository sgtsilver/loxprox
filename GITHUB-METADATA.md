# GitHub Metadata for LoxProx

Live repo: **https://github.com/sgtsilver/loxprox**

---

## Repository Description

> Hardened security gateway for Loxone Miniserver Gen 1: nginx reverse proxy, CrowdSec IDS + AppSec WAF, nftables firewall, scanner trap and alerts, installed by one idempotent script on a Debian 12 VM. Your smart home deserves a deadbolt.

---

## Topics (Tags)

Copy all of these into the repo "Topics" field (max 20):

```
loxone, loxone-miniserver, reverse-proxy, security, waf, ids, crowdsec, nginx, nftables, smart-home, home-automation, hardening, debian, iot-security, homelab, self-hosted
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

Currently in `README.md` (German) and `README.en.md` (English):
- Release (latest GitHub release)
- CI (the workflow runs ShellCheck, the shell syntax check, the unit tests and the integration test)
- License: Non-Commercial (see LICENSE)
- Debian 12

Deliberately **not** shown: a "Validation: A-" and a "CIS Hardened" badge. Their only basis was an AI-assisted, repo-only self-audit of v1.3.3 (`audits/2026-05-23-skills-audit.md`), which is not an independent validation or a CIS certification.
