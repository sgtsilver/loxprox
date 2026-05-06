# About LoxProx

Pick the length that fits your context.

---

## One-Liner (Tagline)

> A hardened security gateway for Loxone Miniservers. Reverse proxy + WAF + IDS + firewall + monitoring — because your smart home deserves a deadbolt.

---

## GitHub Repo Description

> Hardened security gateway for Loxone Miniservers. Reverse proxy + WAF + IDS + firewall + monitoring — because your smart home deserves a deadbolt.

---

## Elevator Pitch (2 sentences)

Loxone Miniserver Gen 1 has no TLS, no rate limiting, no native auth hardening, and end-of-life firmware. LoxProx is a drop-in Debian 12 gateway that adds every protection the hardware lacks — transparently, without touching your LAN.

---

## README About Section (Paragraph)

**LoxProx** is a security gateway built specifically for Loxone Miniserver Gen 1 — end-of-life hardware that cannot protect itself. It sits between the internet and your Miniserver, adding TLS termination, rate limiting, a Web Application Firewall (CrowdSec AppSec), intrusion detection (CrowdSec IDS), nftables firewall rules, AppArmor confinement, audit logging, and real-time Discord alerting. LAN traffic bypasses the gateway entirely, so local users are unaffected. Only external traffic is inspected and hardened. Deployment is one script on a Debian 12 VM.

---

## Social Media / Blog Post (Medium Length)

**Your smart home has a back door. This is the deadbolt.**

The Loxone Miniserver Gen 1 is the brain of thousands of European smart homes — lights, heating, alarms, cameras, door locks. It's also end-of-life hardware with no TLS support, no rate limiting, no built-in IP filtering, and firmware that will never see another security patch.

That bothered me.

So I built **LoxProx**: a hardened Debian 12 security gateway that sits between the internet and your Miniserver, adding every protection the hardware lacks. nginx reverse proxy with rate limiting. CrowdSec IDS + AppSec WAF with 200+ CVE virtual patches. nftables firewall with GeoIP blocking. AppArmor. Audit logging. Discord alerts when someone probes your perimeter.

LAN traffic goes straight to the Miniserver — local users never notice it's there. Only external traffic gets inspected. One script deploys the whole stack. A 29-check validation suite tells you if anything is misconfigured.

It's open source, MIT licensed, and runs on anything from a Proxmox VM to a Raspberry Pi 4.

---

## Hacker News / Reddit Post (Technical)

**Show HN: LoxProx — Security gateway for Loxone Miniserver Gen 1**

The Loxone Miniserver Gen 1 is end-of-life IoT hardware that powers a lot of European smart homes. No TLS (CPU can't handle it), no rate limiting, no native auth hardening, EOL firmware. The vendor's answer is "buy Gen 2." That's €500+ and a full config migration.

LoxProx is a self-hosted alternative: a Debian 12 VM that acts as a transparent security gateway.

Stack:
- nginx reverse proxy + rate limiting
- CrowdSec IDS (community threat intel) + AppSec WAF (200+ CVE virtual patches)
- nftables firewall with GeoIP drop rules
- AppArmor profile for nginx
- auditd for config tampering detection
- Discord alerting on security events

Deploy: one script (`deploy.sh`, 870 lines, idempotent). Validate: 29 automated checks. Grade: A- across CIS Debian 12, OWASP Top 10, and OWASP IoT Top 10.

LAN bypasses the gateway entirely — only internet-facing traffic is hardened. Runs on a 1 vCPU / 512MB VM or a Raspberry Pi 4.

MIT licensed. Would love feedback from anyone running CrowdSec on low-resource gateways.

---

## LinkedIn / Professional

Published **LoxProx**, an open-source security gateway for Loxone Miniserver Gen 1 smart home controllers. The project addresses a real gap: EOL hardware with no TLS, no rate limiting, and no native security hardening — leaving thousands of homes exposed.

LoxProx deploys a six-layer defense stack (nftables → nginx → CrowdSec IDS → AppSec WAF → firewall bouncer → AppArmor/auditd) on a Debian 12 VM, transparently protecting external access without affecting LAN users.

Technical highlights:
- Idempotent 870-line deployment script
- 29-check automated validation suite
- Self-contained HTML security report (A- grade)
- Raspberry Pi 4/5 compatible
- MIT licensed

Built in collaboration with [Kimi](https://www.kimi.com) ([Moonshot AI](https://www.moonshot.ai)) as an experiment in AI-led infrastructure hardening.

Repository: https://github.com/sgtsilver/loxprox

---

## One-Sentence Variants

- **For engineers:** LoxProx is a Debian 12 security gateway that adds TLS, WAF, IDS, and firewall rules to Loxone Miniserver Gen 1 via a single idempotent deploy script.
- **For homeowners:** LoxProx puts a deadbolt on your Loxone smart home — blocking hackers without slowing down your lights.
- **For the cynical:** Your €3,000 smart home runs on a €200 box from 2014 with no security patches. LoxProx fixes that.
