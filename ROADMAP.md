# Loxprox Roadmap

> Living document. Last updated: 2025-05-08

## Current State — v1.2.0

- Debian 12/13 gateway VM with static IP, nginx reverse proxy (`:1080` → Loxone Gen 1)
- CrowdSec + custom progressive-ban for bruteforce mitigation
- Self-healing network watchdog (dhclient death-spiral detection, auto-reboot)
- Gateway monitor with Discord alerting
- Gen 1 Miniserver behind gateway (HTTP only, no TLS, no native auth tokens)

---

## Long-Term Goal: Gen 2 Feature Parity for Gen 1 Gateways

Loxone Gen 2 Miniservers ship with capabilities that Gen 1 lacks entirely. The purpose of this roadmap is to bring equivalent security and access capabilities to Gen 1 installations via the Loxprox gateway — without requiring hardware replacement or vendor cloud dependencies.

### What Gen 2 Has That Gen 1 Lacks

| Feature | Gen 1 | Gen 2 | What It Means |
|---------|-------|-------|---------------|
| **Remote Connect** | ❌ No | ✅ Yes | Outbound TLS tunnel to Loxone cloud. No port forwarding. Works behind CGNAT. |
| **TLS / HTTPS** | ❌ No | ✅ Yes | All traffic encrypted. Certificates auto-provisioned via CloudDNS. |
| **WSS (secure WebSocket)** | ❌ No | ✅ Yes | Encrypted real-time status streams. |
| **Token-based auth** | ❌ No | ✅ Yes | Per-session tokens instead of plaintext passwords. |
| **Trust system** | ❌ No | ✅ Yes | Distributed user/auth across multiple Miniservers. |
| **Concurrent clients** | 48 HTTP | 256 HTTPS | Higher capacity for apps and integrations. |
| **CloudDNS + TLS** | HTTP redirect only | HTTPS redirect | Gen 1 leaks traffic in plaintext even via CloudDNS. |

### How Loxprox Can Close the Gap

| Gen 2 Feature | Loxprox Equivalent Strategy | Complexity | Priority |
|---------------|---------------------------|------------|----------|
| Remote Connect (no open ports) | Cloudflare Tunnel or self-hosted WireGuard/frp reverse tunnel | Medium | 🔴 High |
| TLS / HTTPS | Let's Encrypt on nginx gateway + HTTP→HTTPS redirect | Low | 🔴 High |
| Token-based auth | nginx `auth_request` subrequest + lightweight token service | Medium | 🟡 Medium |
| Trust / multi-user ACL | Cloudflare Access (if using CF Tunnel) or custom auth proxy | Medium | 🟡 Medium |
| Concurrent client scaling | Already 256+ via nginx (no hardware limit) | N/A | ✅ Done |

---

## Phase: Reverse Tunnel — No Open Ports

### Background Research (2025-05-08)

**Loxone Remote Connect (Gen 2) architecture:**
- Miniserver initiates an **outbound-only TLS tunnel** to `*.loxonecloud.com`
- The tunnel is persistent; Loxone cloud proxies inbound HTTPS→tunnel→Miniserver
- Works behind any NAT/CGNAT because only outbound :443 is needed
- Client access: `https://dns.loxonecloud.com/SERIALNUMBER`
- Requires device registration, serial number binding, vendor cloud dependency

**Implication for Gen 1:** We cannot use Loxone's Remote Connect (vendor-locked, Gen 2 only). We must build our own equivalent.

### Evaluated Options

| Solution | Type | Self-Hosted | Cost | CGNAT Works | Notes |
|----------|------|-------------|------|-------------|-------|
| **Cloudflare Tunnel** | Outbound TLS tunnel to Cloudflare edge | No (managed edge) | Free | ✅ Yes | Zero-trust access, no open ports, TLS at edge. Requires CF account. |
| **frp** | Reverse proxy over TCP | Yes (need VPS) | ~€3/mo VPS | ✅ Yes | Most popular open-source option. 100k+ GitHub stars. |
| **WireGuard + VPS** | VPN mesh / point-to-site | Partial (VPS needed) | ~€3/mo VPS | ✅ Yes | Direct p2p when possible, relay through VPS when not. |
| **Tailscale / Headscale** | Mesh VPN with NAT hole punching | Headscale yes | Free (headscale) | ✅ Yes | Best UX. Headscale = self-hosted control plane. |
| **SSH reverse tunnel** | SSH `-R` tunnel | Yes (need VPS) | ~€3/mo VPS | ✅ Yes | Simple but fragile. Not for production. |
| **Cloudflare Tunnel + Access** | Tunnel + IdP auth | No | Free | ✅ Yes | Adds SSO/MFA layer on top. Closest to "Trust" model. |

### Recommended: Cloudflare Tunnel (Phase 1)

**Why:**
- Zero open inbound ports — identical security posture to Loxone Remote Connect
- Free tier is generous and sufficient for a single Miniserver
- TLS termination at Cloudflare's edge (arguably stronger than self-managed certs)
- Optional Cloudflare Access adds SSO/MFA (equivalent to Gen 2 Trusts)
- No VPS required, no monthly cost
- Works behind Fritzbox/UniFi/CGNAT without any router config

**Trade-off:** Cloud dependency. Traffic flows through Cloudflare.
- Mitigation: TLS is end-to-end (cloudflared → Cloudflare edge → origin). Cloudflare sees encrypted SNI but not HTTP payloads.
- If unacceptable, fall back to **frp on a €3 VPS** or **Headscale**.

### Implementation Plan (Cloudflare Tunnel)

1. **Install `cloudflared`** on gateway VM (`192.168.178.252`)
2. **Authenticate** with Cloudflare account via one-time token
3. **Create tunnel** named `loxprox`
4. **Configure ingress rule**: `*.tunnel-domain → localhost:1080`
5. **Update nginx**: Add `proxy_set_header Host $host;` preserve if needed
6. **Test**: Access Miniserver via Cloudflare Tunnel URL
7. **(Optional) Enable Cloudflare Access**: Add Google/GitHub OAuth or OTP
8. **Update Discord alerts** to include tunnel health check
9. **Document**: Add to CONFIGURATION-GUIDE.md
10. **Update deploy.sh**: Include cloudflared install + tunnel setup

### Fallback Plan (Self-Hosted frp)

If Cloudflare dependency is rejected by user:
1. Rent smallest Hetzner/Contabo VPS (~€3/mo)
2. Run `frps` (server) on VPS
3. Run `frpc` (client) on gateway VM
4. Configure TCP reverse proxy: `vps:443 → frp → gateway:1080`
5. Use Let's Encrypt on VPS for TLS
6. Same zero-open-ports property, full self-hosting

---

## Phase: TLS Termination

Already partially done (nginx listens on `:1080` and can do TLS). The gap is:
- Currently no Let's Encrypt integration
- No automatic cert renewal
- No HTTP→HTTPS redirect (irrelevant if using Tunnel, since Tunnel origin is HTTP)

If using **frp fallback**, TLS must be handled at the VPS or gateway. If using **Cloudflare Tunnel**, TLS is handled at the edge.

### Quick-Win: Add Let's Encrypt to nginx

```nginx
server {
    listen 443 ssl;
    server_name loxprox.home.arpa;  # or real domain

    ssl_certificate /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;

    location / {
        proxy_pass http://192.168.178.20;
        proxy_set_header Host $host;
    }
}
```

Use `certbot --nginx` or acme.sh for auto-renewal.

---

## Phase: Token-Based Auth Proxy

Gen 2 uses per-session tokens via AES+RSA handshake. This is overkill for a gateway. Instead:

### Option A: nginx `auth_request` + small Python service
- Lightweight FastAPI/Flask auth endpoint
- Validates JWT or session token against SQLite user DB
- Falls back to HTTP Basic Auth for Loxone app compatibility

### Option B: Cloudflare Access (if using Tunnel)
- Zero code. Configure IdP (Google, GitHub, OTP) in Cloudflare dashboard.
- Users authenticate via Cloudflare before reaching Loxone.
- Closest equivalent to Gen 2 "Trust" model.

### Option C: Authelia / Authentik
- Full-featured SSO proxy
- Overkill for a single Miniserver, but robust

**Recommendation:** Start with Cloudflare Access (if using Tunnel) or Option A (custom JWT proxy) if going self-hosted.

---

## Decisions Log

| Date | Decision | Context |
|------|----------|---------|
| 2025-05-08 | Cloudflare Tunnel chosen as primary reverse tunnel | Zero cost, zero open ports, closest parity to Gen 2 Remote Connect. Fallback = frp on VPS. |
| 2025-05-08 | TLS handled at Cloudflare edge (Tunnel) or VPS (frp fallback) | No need for Let's Encrypt on gateway if using Tunnel. Simpler deployment. |
| 2025-05-08 | Token auth deferred to post-tunnel phase | Tunnel auth (Cloudflare Access) provides equivalent user-level access control. Custom token service is Phase 3. |

---

## Open Questions

1. **Domain**: Does the user have a domain, or should we use a `*.trycloudflare.com` free subdomain?
2. **Cloudflare account**: Does the user have one, or do we need to create it?
3. **Multi-user access**: How many users need remote access? Just the homeowner, or also family/contractors?
4. **Cloud dependency tolerance**: Is Cloudflare acceptable, or must this be 100% self-hosted?
5. **Loxone app compatibility**: Does the Loxone iOS/Android app work through Cloudflare Tunnel + Access, or does it break websocket/auth flows?

---

## References

- Loxone KB: [Remote Connect](https://www.loxone.com/enen/kb/remote-connect/)
- Loxone API Docs: [Communicating With Miniserver PDF](https://www.loxone.com/wp-content/uploads/datasheets/CommunicatingWithMiniserver.pdf)
- Cloudflare Tunnel docs: [developers.cloudflare.com/cloudflare-one/connections/connect-networks](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks)
- frp: [github.com/fatedier/frp](https://github.com/fatedier/frp)
- Headscale: [github.com/juanfont/headscale](https://github.com/juanfont/headscale)
