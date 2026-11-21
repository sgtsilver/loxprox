**Language:** [Deutsch](ABOUT.de.md) · English

# About LoxProx

Pick the length that fits your context.

---

## One-Liner (Tagline)

> Hardened security gateway for Loxone Miniserver Gen 1: nginx reverse proxy, CrowdSec IDS + AppSec WAF, nftables firewall, scanner trap and alerts, installed by one idempotent script on a Debian 12 VM. Your smart home deserves a deadbolt.

---

## GitHub Repo Description

> Hardened security gateway for Loxone Miniserver Gen 1: nginx reverse proxy, CrowdSec IDS + AppSec WAF, nftables firewall, scanner trap and alerts, installed by one idempotent script on a Debian 12 VM. Your smart home deserves a deadbolt.

---

## Elevator Pitch (2 sentences)

Loxone Miniserver Gen 1 has no TLS, no rate limiting, no native auth hardening, and firmware that hasn't seen a known security patch since 2020. LoxProx is a drop-in Debian 12 gateway that adds every protection the hardware lacks — transparently, without touching your LAN.

---

## README About Section (Paragraph)

**LoxProx** is a security gateway built specifically for Loxone Miniserver Gen 1 — legacy first-generation hardware that cannot protect itself. It sits between the internet and your Miniserver, adding optional TLS termination (off by default), rate limiting, a scanner trap that bans crawlers for long periods, a Web Application Firewall (CrowdSec AppSec), intrusion detection (CrowdSec IDS), nftables firewall rules, an AppArmor profile for nginx, audit logging, and real-time Discord alerting. LAN traffic bypasses the gateway entirely, so local users are unaffected. Only external traffic is inspected and hardened. Deployment is one script on a Debian 12 VM.

---

## Social Media / Blog Post (Medium Length)

**Your smart home has a back door. This is the deadbolt.**

The Loxone Miniserver Gen 1 is the brain of thousands of European smart homes — lights, heating, alarms, cameras, door locks. It's also legacy first-generation hardware with no TLS support, no rate limiting, no built-in IP filtering, and firmware that has not received a known security patch since 2020. While Loxone has not formally declared it EOL, new security features (TLS, Remote Connect, Trusts) are Gen 2+ only.

That bothered me.

So I built **LoxProx**: a hardened Debian 12 security gateway that sits between the internet and your Miniserver, adding every protection the hardware lacks. nginx reverse proxy with rate limiting. CrowdSec IDS + AppSec WAF with virtual patching for known CVEs. nftables firewall with GeoIP blocking. AppArmor. Audit logging. Discord alerts when someone probes your perimeter.

LAN traffic goes straight to the Miniserver — local users never notice it's there. Only external traffic gets inspected. One script deploys the whole stack. A 100+-check validation suite tells you if anything is misconfigured.

It's source-available and free for non-commercial use, and built for a Debian 12 VM (Raspberry Pi hardware is in scope but not a tested target).

---

## Hacker News / Reddit Post (Technical)

**Show HN: LoxProx — Security gateway for Loxone Miniserver Gen 1**

The Loxone Miniserver Gen 1 is legacy first-generation IoT hardware that powers a lot of European smart homes. No TLS (CPU can't handle it), no rate limiting, no native auth hardening, and no known security patch since 2020. The vendor's answer is "buy Gen 2." That means new hardware and a full config migration.

LoxProx is a self-hosted alternative: a Debian 12 VM that acts as a transparent security gateway.

Stack:
- nginx reverse proxy + rate limiting
- CrowdSec IDS (community threat intel) + AppSec WAF (virtual patching for known CVEs)
- Host/SNI gate with a scanner trap (444) and HARD/SOFT ban ladders (7 d → 90 d → 365 d for scanners)
- nftables firewall with GeoIP drop rules
- AppArmor profile for nginx
- auditd for config tampering detection
- Discord alerting on security events

Deploy: one script (`deploy.sh`, ~6200 lines, idempotent). Validate: 100+ automated checks. The hardening follows CIS Debian 12 guidance; there is no external audit or certification (a 2026-05 AI-assisted, repo-only self-audit of v1.3.3 is kept in `audits/`).

LAN bypasses the gateway entirely — only internet-facing traffic is hardened. Runs on a 1 vCPU / 1 GB VM (2 vCPU / 2 GB recommended for attack headroom); Raspberry Pi hardware is in scope but not a tested target. **VM-only — LXC unsupported**, because several kernel-level defenses (sysctls including the Fragnesia mitigation, auditd, AppArmor enforcement, nftables) cannot be applied from inside a container and would silently no-op.

Source-available, non-commercial licence. Would love feedback from anyone running CrowdSec on low-resource gateways.

---

## LinkedIn / Professional

Published **LoxProx**, a source-available security gateway for Loxone Miniserver Gen 1 smart home controllers. The project addresses a real gap: legacy first-generation hardware with no TLS, no rate limiting, and no native security hardening — leaving thousands of homes exposed.

LoxProx deploys a layered defense stack (nftables → nginx → CrowdSec IDS → AppSec WAF → firewall bouncer → AppArmor/auditd) on a Debian 12 VM, transparently protecting external access without affecting LAN users.

Technical highlights:
- Idempotent ~6200-line deployment script
- 100+-check automated validation suite
- Scanner trap with escalating HARD/SOFT ban ladders
- Raspberry Pi hardware in scope (not a tested target)
- Source-available, non-commercial licence

Built as an experiment in AI-assisted, human-curated infrastructure hardening: [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) did the original architecture and most of the code, [Claude](https://claude.com) ([Anthropic](https://www.anthropic.com)) reviews and contributes follow-on work, and a human sysadmin has the final say.

Repository: https://github.com/sgtsilver/loxprox

---

## One-Sentence Variants

- **For engineers:** LoxProx is a Debian 12 security gateway that adds optional TLS, a WAF, IDS, and firewall rules to Loxone Miniserver Gen 1 via a single idempotent deploy script.
- **For homeowners:** LoxProx puts a deadbolt on your Loxone smart home — blocking hackers without slowing down your lights.
- **For the cynical:** Your smart home runs on a first-generation box that hasn't seen a known security patch since 2020. LoxProx fixes that.
