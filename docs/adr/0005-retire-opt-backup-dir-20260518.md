# 0005. Retire `/opt/loxone-security.bak-20260518-225555/` after provenance verification

- **Status:** accepted
- **Date:** 2026-08-30

## Context

The v1.3.0 project rename (2026-05-18) left a safety-net backup at
`/opt/loxone-security.bak-20260518-225555/` on the production gateway, with the
note "remove after a week of clean operation". 104 days later it was still on
disk, and a 2026-08-30 read-only audit flagged that it held the only `deploy.sh`
present anywhere on the box — raising the fear that live-edited production
values (`SSH_ALLOWED_SUBNETS`, `LOXONE_IP`, `GATEWAY_IP`) existed nowhere else
and would be lost on deletion.

A file-by-file provenance check (2026-08-30) showed that fear to be outdated:

| File in backup dir | SHA-1 | Identical to |
|---|---|---|
| `deploy.sh` | `25ced0a9d411…` | `c1e0681:deploy.sh` (v1.2.x, 2026-05-10) |
| `progressive-ban.py` | `238df187…` | `c1e0681:progressive-ban.py` |
| `geoip-block.sh` | `eb1048a4…` | `22c67859:security-monitoring/geoip-block.sh` |
| `discord-alert.sh` | `68acfeae…` | `69d36dd8:security-monitoring/discord-alert.sh` |
| `gateway-backup.sh` | `6cece83e…` | `69d36dd8:security-monitoring/gateway-backup.sh` |
| `gateway-monitor.sh` | `012551ab…` | `69d36dd8:security-monitoring/gateway-monitor.sh` |
| `docs/RUNDOWN.md`, `docs/CHANGELOG.md` | — | `e0e720d6` versions |
| `docs/for-kimi.md` | `515b2c7d…` | maintainer's untracked working copy (byte-identical) |

Crucially, the backed-up `deploy.sh` carries only the **placeholder** values
(`LOXONE_IP="192.168.1.100"`, `GATEWAY_IP="192.168.1.50"`,
`SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")`, empty webhook) — it
never held the production values. Since v1.5.0 the per-host production values
live in `/etc/loxprox/deploy.conf` on the gateway (mirrored in the maintainer's
gitignored `local-deployment/deploy.conf`), and both were verified on
2026-08-30 to match the live nftables SSH rule, the nginx upstream, and the
interface address.

## Decision

Delete the backup directory. Do **not** re-commit the rescued v1.2.x `deploy.sh`
alongside the current one: its content is already in git history (`c1e0681`),
and a runnable monolith with placeholder subnets sitting in the tree is exactly
the LAN-lockout footgun the v1.5.0 config separation was built to remove. The
authoritative home for per-host values remains `/etc/loxprox/deploy.conf`
(template: `deploy.conf.example`); a bit-for-bit copy of the rescued file is
retained in the maintainer's gitignored `local-deployment/rescued/`.

## Consequences

- **Positive:** No stale root-owned copy of the codebase on the gateway; no
  second `deploy.sh` an operator could run with placeholder subnets; the
  provenance of every deleted file is recorded here and verifiable from git
  history.
- **Negative:** The on-box rollback anchor from the 2026-05-18 rename is gone —
  rollback now goes through git history plus `local-deployment/push-to-vm.sh`,
  which is the supported path anyway.
