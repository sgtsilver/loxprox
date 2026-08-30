# 0006. Ship an nginx AppArmor profile, complain-first with a gated enforce

- **Status:** accepted
- **Date:** 2026-08-30

## Context

The architecture has documented "AppArmor (nginx profile)" as a layer of the
Stack since inception, and `setup_apparmor()` enforced
`/etc/apparmor.d/usr.sbin.nginx` *if it existed* — but Debian 12 ships no
nginx profile (not even in `apparmor-profiles`), so the branch never fired. A
2026-08-30 live audit found AppArmor loaded and globally enforcing with only
the 7 generic Debian profiles: **0 processes confined**. The documented layer
did not exist. The production gateway now runs on a KVM VM (ADR 0004's LXC
enforcement blocker no longer applies), so the only missing piece was the
profile itself.

The dangerous failure mode of adding one is not day-one breakage — it is a
profile gap that surfaces **months later** on a rare path: acme.sh renews the
certificate (~every 60 days) and nginx is denied the reload read; logrotate's
USR1 log-reopen; a deploy-regenerated config. A denial there is silent until
the gateway breaks.

## Decision

Ship `apparmor/usr.sbin.nginx` in the repo, authored for exactly this
gateway's surface (proxy on :1080, ACME listener on :80, AppSec
`auth_request` to `127.0.0.1:7422`, USR1 log reopen, read-only
`/etc/loxprox/tls/`, `/var/lib/nginx` temp dirs, dynamic modules). The
containment goal: a compromised nginx cannot read `/etc/loxprox/` outside
`tls/` (webhook URL, panel password), cannot touch `/opt/loxprox/`, cannot
execute anything.

`setup_apparmor()` installs the profile and loads it in **complain mode on
every deploy**. Enforcement happens **only** when the operator sets
`APPARMOR_NGINX_MODE="enforce"` in `deploy.conf`, and only after a
**multi-week complain soak** that has covered at least:

1. one real acme.sh certificate renewal (~60-day cycle),
2. one logrotate cycle (nightly),
3. one full `deploy.sh` run,
4. normal + WebSocket client traffic,

with zero unexplained `ALLOWED` events in `journalctl -g apparmor` /
`aa-status` over that window. The previous unconditional
`aa-enforce`-if-present behavior is removed — a soaking profile can no longer
flip to enforce as a side effect of the next deploy.

## Consequences

- **Positive:** the sixth documented layer becomes real instead of
  aspirational; the highest-exposure process (the one parsing hostile
  internet input) gains mandatory access control; the soak discipline is
  encoded in the deploy script rather than in memory.
- **Negative:** until the soak completes, the layer detects but does not
  block (complain mode) — the stack is honestly "five enforcing + one
  observing". Profile maintenance is a new (small) obligation whenever
  nginx's file or network surface changes in `configure_nginx()`.
