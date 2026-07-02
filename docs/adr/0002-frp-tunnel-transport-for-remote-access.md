# 0002. frp as the remote-access tunnel transport (v2.0)

- **Status:** accepted
- **Date:** 2026-05-08

## Context

In v1.x the gateway is reached from the internet via a router port-forward
(`WAN:1080 → gateway:1080`), which requires a public IPv4 and an open port. Many
German home connections are behind CGNAT / DS-Lite, where no inbound port can be
opened. Loxone Gen 2's "Remote Connect" solves this with a persistent outbound
TLS tunnel to `*.loxonecloud.com`, but it is **Gen 2 only**; Gen 1's official
Cloud-DNS path needs a public IP + port-forward and carries a documented UDP
spoofing vulnerability. For Gen 1 + CGNAT owners, building our own tunnel is the
only path to external access.

The goal for v2.0 is "zero open ports" parity with Remote Connect: an outbound
tunnel from the Gateway VM to an Operator-owned Relay (VPS) that becomes the
public entry point. A roughly-20-hour research effort evaluated the candidates
(`wiki/loxone-tunnel-research.md`, `wiki/loxprox-tunnel-sessions.md`,
`wiki/loxprox-v20-hardcore-plan.md`):

- **WireGuard / OpenVPN direct** — need an open port or both sides behind NAT;
  not zero-port. Rejected.
- **SSH reverse tunnel** — fragile, no robust auto-reconnect, hard to
  productionise. Rejected.
- **Cloudflare Tunnel** — best UX, free, full WebSocket support, but US-operated
  SaaS with no self-hosting; the Operator has data-sovereignty concerns. Kept
  only as an emergency/validation fallback.
- **Tailscale / Headscale / NetBird** — NetBird's all-in-one reverse proxy was
  attractive (EU-based) but beta, Traefik-bound (not nginx), with untested
  Loxone WebSocket passthrough. Deferred to a future re-evaluation.
- **frp** — most popular self-hosted OSS tunnel (100k+ stars), TCP passthrough
  mode, QUIC transport option (NAT-friendly, connection migration), runs frps on
  a cheap EU VPS (Hetzner, ~€4/mo) and frpc on the Gateway VM. A security review
  confirmed no known RCE in core tunnel logic, and that the `routeByHTTPUser`
  auth-bypass CVE-2026-40910 does **not** affect TCP passthrough.

frp keeps the nginx + CrowdSec stack intact (it tunnels TCP; the WAF/IDS stay on
the path), is fully self-hosted on EU infrastructure, and pairs with the proven
nginx + Authelia + acme.sh components already understood by the project.

## Decision

We will use **frp** (frpc on the Gateway VM dialling out to frps on an Operator-
owned Relay VPS) as the v2.0 remote-access tunnel transport, in TCP-passthrough
mode over QUIC, terminating HTTPS at the Relay's nginx. frpc will run in a
hardened systemd sandbox (`ProtectSystem=strict`, capability drop, syscall
filter, memory cap), with the frp auth token treated as a rotated secret.
Cloudflare Tunnel is retained only as a manual emergency fallback; NetBird is
deferred until it reaches v1.0 stability.

## Consequences

- **Positive:** Achieves zero-open-ports remote access for Gen 1 behind CGNAT —
  the single capability Loxone never shipped for this hardware. Fully self-hosted
  on EU infrastructure, satisfying the sovereignty constraint. The existing
  nginx + CrowdSec defenses remain on the traffic path; frp adds an outer
  Relay perimeter that can rate-limit before traffic reaches the gateway.
- **Negative:** Adds an Operator-owned VPS (recurring ~€4/mo) and more moving
  parts — four proxy hops, each of which must preserve the Loxone WebSocket
  headers (`Host`, `X-Forwarded-Proto`, `Upgrade`/`Connection`, long timeouts).
  CrowdSec must be reconfigured with `trusted_proxies` / `real_ip` so it sees
  real client IPs and not the tunnel endpoint. frp's upstream is China-based and
  must be kept patched for transitive dependency CVEs.
- **Neutral:** This is a v2.0 decision; v1.x continues to use the router port-
  forward. The harder problem identified in research is not the tunnel but the
  split-horizon DNS UX (the Loxone App stores exactly one URL) — tracked
  separately and not part of this transport choice.
