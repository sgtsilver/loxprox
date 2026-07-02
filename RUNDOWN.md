# LoxProx — Project Rundown

**Status:** Published on GitHub  
**Repo:** https://github.com/sgtsilver/loxprox  
**Version:** 2.0.1 (released)  
**Last updated:** 2026-07-02 (v2.0.1 — fix: deploy.sh aborted on TLS hosts when the acme.sh cron line was written in acme.sh's quoted-home form; verified by a full clean deploy on the live production VM. v2.0.0 — zero-open-ports frp tunnel (opt-in, `ENABLE_TUNNEL`), `/ws/` WebSocket template fix, Tier-2 resilience: tunnel watchdog + ACME fallback CA; token configs locked 0640 before chown; layered on top of the v1.5.2 audit)

---

## What This Is

A drop-in security gateway for Loxone Miniserver Gen 1. It sits between the internet and your Miniserver, adding every protection the hardware lacks: TLS termination, rate limiting, WAF, IDS, firewall, audit logging, and real-time alerting.

LAN traffic bypasses the gateway entirely — only external traffic is inspected.

---

## Architecture at a Glance

```
Internet ──► Router:1080 ──► Gateway:1080 ──► Loxone:80
                                    │
                                    ├── nginx (proxy, rate limits, headers)
                                    ├── CrowdSec (IDS + CAPI blocks + AppSec WAF)
                                    ├── nftables (input DROP, allow :1080 + SSH)
                                    ├── AppArmor (nginx profile)
                                    ├── auditd (config change monitoring)
                                    └── Discord alerts (real-time)
```

---

## Key Files

| File | Purpose |
|------|---------|
| `deploy.sh` | One-shot Debian 12 hardening & installation (~3000 lines, idempotent) |
| `detect-loxone.sh` | Network autodetector — finds your Miniserver by MAC OUI and API fingerprint |
| `test-gateway.sh` | 50+ automated checks — run after deploy to verify every control |
| `set-static-ip.sh` | Pre-deploy VM network configuration |
| `security-monitoring/` | Discord alerts, health monitor, config backup, GeoIP block script, network watchdog |
| `security-monitoring/network-watchdog.sh` | Self-healing network stack monitor |
| `security-monitoring/tunnel-watchdog.sh` | v2.0: self-healing frp-tunnel monitor (restart + Discord alert, no reboots) |
| `tunnel-relay/install-relay.sh` | v2.0: one-shot relay-VPS installer (frps + nginx TLS + CrowdSec perimeter) |
| `security-monitoring/network-watchdog.service` | systemd system service (root) |
| `security-monitoring/network-watchdog.timer` | Runs watchdog every 60 seconds |

---

## Network Stack Watchdog (Self-Healing)

### What It Is
A **transparent, locally-operated** health monitor that detects when the VM's network stack becomes unreachable — e.g. the `dhclient` death-spiral that caused the 2026-05-07 outage, kernel routing corruption, or interface state desync. It attempts to heal by restarting services; if that fails, it reboots the VM and reports what happened.

### What It Is NOT
- **NOT a backdoor**, remote-access tool, or telemetry collector.
- **NOT affiliated with any third-party service**.
- **DOES NOT "phone home"**. The only external call is to **your** configured Discord webhook (the same one used by all other LoxProx alerts).
- **DOES NOT modify firewall rules, install packages, or change secrets**.

### How It Works
Every 60 seconds the watchdog (running as a systemd **system** service, i.e. root — same privilege model as `nginx.service` and `networking.service`) runs five local health checks:

1. **Gateway ping** — can the VM reach the router?
2. **DNS resolution** — can it resolve a hostname?
3. **nginx localhost** — does `curl http://127.0.0.1:1080/` respond?
4. **Interface IP** — does the primary interface have the expected static IP?
5. **dhclient anomaly** — if the interface is configured `static`, is a `dhclient` process still running? (Logged, but does **not** count as a failure.)

**Two consecutive failures** are required before any action is taken (prevents false positives from transient packet loss).

**Heal path:**
1. Restart `nginx` (cheapest fix if the proxy just hung).
2. If still failing, restart `networking.service` — this re-runs all `ifupdown` scripts from a clean state.
3. Wait 15 seconds and re-check.

**Reboot path:**
If healing fails, the watchdog:
1. Checks an anti-loop counter (max 2 reboots per hour). If exceeded, it **gives up** and sends a Discord alert asking for manual intervention.
2. Writes a persistent flag file to `/var/lib/loxprox/.watchdog-reboot-pending`.
3. Sends a Discord CRITICAL alert with the failure reason, collected diagnostics, and **actionable advice**.
4. Waits 30 seconds, then calls `/sbin/reboot`.
5. After reboot, the first watchdog cycle reads the flag file, sends a "system recovered" report, and deletes the flag.

### Privilege Model
The watchdog runs as a **systemd system service** — root by default. This is required because it must:
- Restart `networking.service`
- Call `reboot`

**No sudo configuration is needed.** No `/etc/sudoers` edits. No passwordless anything. It uses the exact same privilege model as every other system service (`nginx`, `crowdsec`, `networking`).

### Anti-Reboot-Loop Protection (Two Layers)
| Layer | Mechanism |
|-------|-----------|
| **Script-level** | Tracks reboots in `/var/lib/loxprox/watchdog-reboot-history.log`. Max 2 per hour. If exceeded, sends Discord alert and exits without rebooting. |
| **systemd-level** | `FailureAction=reboot` acts as a last-resort safety net if the script exits non-zero. `StartLimitBurst=0` (disabled) because a finite burst limit conflicts with the 60-second timer — the 4th start would be blocked as "start-limit-hit" and falsely trigger a reboot. The script already has its own anti-loop counter (max 2/hour). |

This means: even if your Fritzbox is physically unplugged, the VM reboots **at most twice** in an hour, then stops and waits for you.

### Logs & Forensics
```bash
# Live log
journalctl -u network-watchdog -f

# Persistent log
cat /var/log/loxprox-network-watchdog.log

# Reboot history
cat /var/lib/loxprox/watchdog-reboot-history.log

# Check if a post-reboot report is pending
ls -la /var/lib/loxprox/.watchdog-reboot-pending
```

### Disable / Re-enable
```bash
# Stop immediately
sudo systemctl stop network-watchdog.timer

# Disable permanently
sudo systemctl disable network-watchdog.timer

# Re-enable
sudo systemctl enable --now network-watchdog.timer
```

### Discord Alert Content
When the watchdog fires, the Discord message includes:
- **Which checks failed** (gateway, DNS, nginx, interface IP)
- **Current system state** (interface mode, IP, dhclient PIDs, service statuses)
- **Last syslog / dmesg lines**
- **Actionable advice:**
  1. Check if `dhclient` is running on a static interface → run `set-static-ip.sh`
  2. Check your Fritzbox / upstream router → may be the actual cause
  3. SSH in after reboot and check `journalctl -u network-watchdog --since '1 hour ago'`
  4. View logs: `cat /var/log/loxprox-network-watchdog.log`

---

## Known Quirks & Lessons Learned

### DHCP → Static Transition Kills Inbound Connections (Debian 12)
Switching `/etc/network/interfaces` from `inet dhcp` to `inet static` without rebooting leaves a stale `dhclient` running. ~24 hours later the lease renewal loop corrupts the interface state. nginx stays up but becomes unreachable. **Fix:** Kill dhclient, remove `isc-dhcp-client`, then `ifdown/ifup` — or just reboot. This is now automated in `set-static-ip.sh`.

### CrowdSec AppSec Authentication
CrowdSec AppSec requires the **firewall bouncer API key** (not the LAPI machine key) in the `X-Crowdsec-Appsec-Api-Key` header, plus `X-Crowdsec-Appsec-Ip`, `-Uri`, and `-Verb`. This was completely undocumented in standard CrowdSec guides and caused hours of 401 debugging. The bouncer `.local` file is the source of truth.

### CrowdSec Whitelist CIDR Syntax
CrowdSec's parser expects `cidr:` for ranges, not `ip:`. Using `ip:192.168.1.0/24` causes a FATAL parser error. `cidr:192.168.1.0/24` is correct.

### nftables Table Isolation
The `crowdsec-firewall-bouncer` manages its own `table ip crowdsec` with timeout-based sets. When reloading static rules, use `flush table inet filter` — never `flush ruleset` — or you wipe the bouncer's dynamic blocks.

### German Locale Breaks `free` Parsing
The monitor script parses `free -m` output. On German locales, `Mem:` becomes `Speicher:` and numbers use commas. Fix: `LC_ALL=C free -m`.

### Loxone Gen 1 Has No TLS
The Miniserver Gen 1 CPU cannot handle SSL. The gateway terminates TLS and speaks HTTP to the Miniserver. This is a hardware limitation, not a design choice.

---

## Hardware Tested

| Platform | Status | Notes |
|----------|--------|-------|
| Debian 12 VM (Proxmox) | ✅ Production | 1 vCPU, 1 GB RAM, 5 GB disk |
| Raspberry Pi 4/5 | ✅ Supported | Official ARM64 packages |
| Raspberry Pi 3 | ✅ Supported | Requires 64-bit Raspberry Pi OS |
| Raspberry Pi 2 | ⚠️ Partial | Needs 64-bit kernel or manual compile |
| Raspberry Pi 1 / Zero | ❌ Not supported | ARMv6, no 64-bit support |

---

## CI / GitHub Actions

Workflow in `.github/workflows/ci.yml`:
- **ShellCheck** on all `.sh` files (warning severity)
- **Syntax check** — `bash -n` on every script
- **Python unit tests** — pytest with mocked `subprocess.run()` for `progressive-ban.py`
- **Shell unit tests** — portable mock-based tests for `deploy.sh` and `detect-loxone.sh` functions
- **Integration test** — config generation validation inside a Debian 12 Docker container
- **Markdown link check** — validates all documentation links

## GitHub Repository Setup

These settings are configured on the repo and affect how code lands in `main`:

| Setting | Status | Notes |
|---------|--------|-------|
| Branch protection on `main` | ✅ Active | Requires PR + 1 approval + all CI checks pass |
| Dependabot (Actions) | ✅ Active | Weekly checks; auto-opens PRs for action updates |
| Secret scanning | ⏭️ Skipped | LAN-only project; no secrets committed |
| Releases | ✅ Published | `v1.1.0`, `v1.2.0`, `v1.2.1`, `v1.3.1`, `v1.3.2`, `v1.3.3`, `v1.3.4`, `v1.5.0`, `v1.5.1`, `v1.5.2`, `v2.0.0`, `v2.0.1` (latest). v1.3.0 was withdrawn — do not install. v1.4.0 and the v1.6.x same-day tags were retired and consolidated into v1.5.0 (see CHANGELOG). See [Releases](https://github.com/sgtsilver/loxprox/releases). |

### Developer workflow (after branch protection)

Direct push to `main` is blocked. Use feature branches:

```bash
# 1. Create a feature branch
git checkout -b feature-name

# 2. Commit your changes
git add -A
git commit -m "type: description"

# 3. Push the branch
git push origin feature-name

# 4. Open a Pull Request on GitHub
#    Click the yellow "Compare & pull request" banner

# 5. Wait for CI to pass (all green checks)
# 6. Merge via GitHub UI (requires 1 approval)
```

---

## Bug Fix Sweeps

### 2026-05-10 Handover Sweep (6 findings)
Post-code-review fixes found during handover documentation:

| Finding | File | Fix |
|---------|------|-----|
| HIGH-005 Empty backups | `gateway-backup.sh` | Deterministic `WORK_DIR` instead of `mktemp` |
| MED-007 Re-extending bans | `progressive-ban.py` | JSON state file tracks already-escalated decision IDs |
| MED-008 HTTP GeoIP + no reload | `geoip-block.sh` | HTTPS + `nft -f` reload |
| MED-009 Unsafe JSON interpolation | `discord-alert.sh` | `jq -n --arg` construction |
| LOW-010 Locale-dependent `free` | `gateway-monitor.sh` | `LC_ALL=C free` |
| LOW-011 `bc` dependency | `gateway-monitor.sh` | `awk` comparison |

### 2026-05-06 Ezio Audit (23 findings)
All 23 findings from the 2026-05-06 Ezio audit have been addressed:

| Finding | Fix |
|---------|-----|
| CRIT-001 `curl \| bash` | GPG-key-pinned apt repository setup — no pipe-to-shell |
| HIGH-001 AppSec key on disk | Documented threat model + mitigation guidance |
| HIGH-002 Missing CSP | Added CSP + Permissions-Policy; removed deprecated X-XSS-Protection |
| HIGH-003 No integration tests | Added Docker-based CI integration test + portable unit tests |
| HIGH-004 `curl \| bash` in install-gateway.sh | Same GPG-pinned fix applied |
| MED-001 Unpinned hub collections | Removed unconditional `hub upgrade`; install at hub-index version |
| MED-002 Rollback without validation | Added `nginx -t`, `nft -c`, pre-rollback snapshot |
| MED-003 Python subprocess timeouts | Added `timeout=30` to all `subprocess.run()` calls |
| MED-004 Silent subprocess failures | Return codes checked, stderr logged |
| MED-005 No Python unit tests | Full pytest suite with mocked `subprocess` |
| MED-006 No scanner tests | Portable bash unit tests for IP math, OUI, mktemp |
| LOW-001–LOW-012 | All fixed (mktemp, stricter IP regex, logrotate, circuit breaker, proxy_hide_header, test split, webhook rotation docs, AppSec tests, nftables comment, email delta, rollback glob) |

### Cumulative Stats
- **Total findings resolved:** 66 (23 audit + 10 handover + 12 second sweep + 13 full-project-audit v1.5.2 + 8 v2.0 tunnel pre-release)
- **Test assertions:** 213 (36 pytest + 166 deploy integration + 11 scanner) — all green as of v2.0.0

## Test Infrastructure

```
tests/
├── run-tests.sh              # unified test runner (runs all of tests/)
├── test_progressive_ban.py   # 22 pytest cases for ban script
├── test_repo_hygiene.py      # 14 repo-hygiene guards (OpSec, versions, hardware,
│                             #   config model, dead-file refs, links, bilingual,
│                             #   naming) — the automated audit; tracked files only
├── test_deploy_integration.sh # 166 assertions for deploy.sh logic (incl. v2.0 tunnel)
└── test_detect_loxone.sh     # 11 assertions for scanner logic
```

**`test_repo_hygiene.py` replaces the manual "deep clean" audits.** It scans only
git-tracked files (the public repo), so the gitignored `local-deployment/`
production config is never inspected. Run it before any docs/release PR:
`pytest tests/ -v`.

Run locally:
```bash
bash tests/run-tests.sh          # all portable tests
bash tests/run-tests.sh shell    # shell tests only
bash tests/run-tests.sh python   # Python tests only
```

VM integration tests (requires live gateway):
```bash
sudo ./test-gateway.sh
```

## Roadmap / Ideas

> ⚠️ Long-term planning docs kept local-only — not committed to GitHub.

### Quick Wins
- [ ] Ansible role for fleet deployment
- [ ] Docker/Podman container version
- [ ] Web dashboard for CrowdSec decisions + gateway metrics
- [ ] Automatic TLS certificate renewal monitoring
- [ ] Prometheus metrics export

---

## Citation

See `CITATION.cff` for academic citation metadata.
