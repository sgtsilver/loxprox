# tunnel-relay/ — Relay VPS (v2.0 tunnel, server side)

This directory sets up the **relay VPS** for LoxProx's optional zero-open-ports
remote access (ADR-0002). The gateway's `frpc` dials out to `frps` here; the
Loxone app connects to `https://<your-domain>` and nginx forwards into the
tunnel. Nothing needs to be opened on the home router — this is the path for
CGNAT / DS-Lite connections where port forwarding is impossible.

| File | Purpose |
|---|---|
| `install-relay.sh` | One-shot Debian 12 VPS installer: nftables, frps (pinned + SHA256-verified), nginx TLS entry point (Let's Encrypt with ZeroSSL fallback), CrowdSec perimeter enforcement (with a `RELAY_WHITELIST_IPS` ban-exemption list), unattended upgrades. Idempotent — a re-run on a relay that already serves TLS keeps the live `:443` site instead of downgrading it. |
| `relay.conf.example` | Configuration template. Copy to `/etc/loxprox-relay/relay.conf` and fill in the `[REQUIRED]` values. |

## Quick start

```bash
# On a fresh Debian 12 VPS (as root):
install -d -m 0750 /etc/loxprox-relay
cp relay.conf.example /etc/loxprox-relay/relay.conf
$EDITOR /etc/loxprox-relay/relay.conf     # domain, email, token
bash install-relay.sh
```

Then enable the gateway side: set `ENABLE_TUNNEL="true"` (plus the matching
`TUNNEL_*` values) in `/etc/loxprox/deploy.conf` and re-run `deploy.sh`.

## Other entry points

```bash
bash install-relay.sh --finalize-ssh    # key-only SSH once a key is installed
bash install-relay.sh --health-check    # services + TLS certificate expiry, no changes
```

There is no `--rollback` on the relay. Every run's backups are written to
`/root/loxprox-relay-backup-<timestamp>/files/…` with a `manifest.txt` — restoring
one is a manual `cp` back into place.

**Full runbook, threat model and troubleshooting:**
[docs/TUNNEL-SETUP.md](../docs/TUNNEL-SETUP.md)
