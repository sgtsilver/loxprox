# 0001. Layered defense-in-depth stack on a Debian VM (nginx + CrowdSec + nftables + AppArmor/auditd)

- **Status:** accepted
- **Date:** 2026-05-06

## Context

The Loxone Miniserver Gen 1 is legacy first-generation hardware that cannot
protect itself: no TLS (the CPU cannot sustain SSL without delaying event
responses), no rate limiting, no native authentication hardening, and firmware
that has received no known security patch since 2020. New protective features
(TLS, Remote Connect, Trusts) are Gen 2+ only. Exposing such a device to the
internet — directly or via a router port-forward — is unacceptable, yet many
households need remote access to it.

No single control closes this gap. A reverse proxy alone does not stop a
credential-stuffing campaign; an IDS alone does not terminate TLS or rate-limit;
a firewall alone does no application-layer inspection. The design therefore had
to compose several independent controls so that a bypass of one is caught by the
next, while still fitting a low-resource target (1 vCPU / 1 GB VM, ~165–320 MB
RAM for the whole stack). Independent validation against CIS Debian 12 v1.1.0,
OWASP Top 10 2026, and OWASP IoT Top 10 graded the result A- and noted that the
CrowdSec firewall-bouncer + nftables pairing is the 2026-recommended pattern for
low-resource environments.

Context source: `wiki/loxprox.md` (Architecture, Independent Security Validation
2026-05-06, Security Audit History v1.1.0), repo `ABOUT.md`.

## Decision

We will protect the Miniserver with a layered defense-in-depth stack deployed by
a single idempotent `deploy.sh` onto a Debian 12 host, composed of:

- **nftables** — default-drop input firewall; allows only `:1080` and LAN-side
  SSH; GeoIP drop set.
- **nginx** — reverse proxy terminating external traffic on `:1080`, with
  per-IP `limit_req` / `limit_conn` rate limiting and security headers.
- **CrowdSec IDS** — behavioural detection plus community CAPI blocklists.
- **CrowdSec AppSec WAF** — application-layer virtual patching via nginx
  `auth_request`, fail-closed on outage.
- **CrowdSec firewall bouncer** — enforces decisions in its own
  `table ip crowdsec`, kept isolated from the static `table inet filter`.
- **AppArmor + auditd** — nginx confinement and config-tampering / persistence-
  vector detection, with Discord alerting on security events.

LAN traffic bypasses the gateway entirely and reaches the Miniserver directly;
only external traffic is inspected. The system fails closed — if the gateway is
down, external access is down with it, and there is no bypass path.

## Consequences

- **Positive:** Each layer independently raises the cost of an attack; a bypass
  of one is caught by the next. The stack is the documented best-practice shape
  for low-resource gateways and validated A-. LAN users are unaffected. Fail-
  closed eliminates a silent bypass path.
- **Negative:** Operational complexity is high — six interacting components, each
  with its own footguns (CrowdSec AppSec auth-key semantics, nftables table
  isolation, whitelist CIDR syntax). The full stack requires a **VM, not an LXC**
  (see ADR 0004), because several kernel-level controls silently no-op in an
  unprivileged container. The gateway is a single point of failure for remote
  access by design.
- **Neutral:** The stack depends on CrowdSec's cloud CAPI for the community-
  intelligence layer; local detection and the WAF remain functional without it,
  but the community layer degrades when CAPI is unreachable. The terminology
  "the Stack" is used as a unit across docs; "six-layer defense" is deliberately
  avoided in user-facing copy.
