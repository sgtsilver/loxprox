# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] — 2026-05-18

### Fixed (Second Bug Sweep — 12/12 findings resolved)
- **HIGH**: `progressive-ban.py` — `cscli decisions list -o json` emits `null` (Go nil-slice marshal), not `[]`. `json.loads("null") → None` then `sys.exit(1)` on every cron run on a gateway with no decisions. Normalised to `[]` in `run_cscli`. New regression test `test_run_cscli_null_response_returns_empty_list`.
- **HIGH**: `grafana-integration/loxprox-metrics.sh` — `... | grep -c PATTERN || echo 0` under `pipefail` emitted a two-line string `"0\n0"` that broke node_exporter textfile scraping. Replaced with `|| true` in 3 places.
- **MED**: `network-watchdog.sh` — `EXPECTED_IP` fallback chained to `GATEWAY_IP`, which by then has been reassigned to the upstream router IP. Configs without an explicit `WATCHDOG_EXPECTED_IP` would trip `check_interface_ip` forever and trigger reboot loops (capped at 2/hr by anti-loop). Default to `UNSET` and skip the check.
- **MED**: `deploy.sh` first-deploy ordering — `setup_firewall` restarted nftables while `/etc/nftables.conf` referenced `@geoip_blocklist`, which was only defined later when `geoip-block.sh` runs. Pre-seed an empty placeholder set so the include resolves and nftables loads on a clean VM.
- **MED**: `deploy.sh` was missing the install-monitoring step — `gateway-monitor.sh`, `gateway-backup.sh`, the monitor systemd timer, and the cron file. Added `setup_security_monitoring()` so a fresh deploy matches what operators had been installing by hand.
- **LOW**: `gateway-monitor.sh:86` fragile `[ "$count" -gt 0 ] 2>/dev/null` (which does NOT suppress `set -e` from `[`'s rc=2 on empty `$count`). Use `[[ "${count:-0}" -gt 0 ]]`.
- **LOW**: `network-watchdog.service` — `StartLimitIntervalSec` + `StartLimitBurst` were in `[Service]`; per `systemd.unit(5)` they belong in `[Unit]`. systemd was silently ignoring them with `Unknown key` warnings. Moved.

### Changed (polish / dedup)
- `detect-loxone.sh` — `scan_subnet_cidr` and `scan_range` were ~95% duplicated; factored into shared `scan_int_range` + `print_match` (−40 LOC, same behaviour).
- `detect-loxone.sh:probe_loxone` — `/jdev/cfg/api` was GET'd twice on OUI miss; one call now.
- `detect-loxone.sh` — throttle `wait` fired at iter 0 with only 1 background spawned (first 50-batch never actually parallel); counter-based now.
- `progressive-ban.py` — `save_state` moved out of the escalation loop.
- `test-gateway.sh` — dropped dead `bc`-as-monitor-dep check (LOW-011 removed the `bc` dependency in v1.2.1); updated paths/timer to `/opt/loxprox/` and `loxprox-monitor.timer`.

### Renamed (install footprint)
- `/opt/loxone-security/*` → `/opt/loxprox/*`
- `/var/lib/loxone-monitor/*` → `/var/lib/loxprox/*`
- `loxone-security-monitor.{service,timer}` → `loxprox-monitor.{service,timer}`
- `/etc/cron.d/loxone-security` → `/etc/cron.d/loxprox`

For operators on an earlier install, see PR #5 for a step-by-step migration.

### Docs
- `CONFIGURATION-GUIDE.md`, `RUNDOWN.md`, `deploy.sh`, `network-watchdog.sh` — replaced specific network examples with RFC-style documentation ranges (`192.168.1.x`, `203.0.113.x`, `198.51.100.x`). No behaviour change.

### Tests
- pytest: 21 (was 20). Scanner shell: 11. Deploy integration: 54. All green. `systemd-analyze verify` clean on all units.

## [1.2.1] — 2026-05-10

### Fixed (Handover Bug Sweep — 10/10 findings resolved)
- **HIGH-005**: `gateway-backup.sh` — `tar` archived a `mktemp`-generated path that never matched `$BACKUP_NAME`, producing empty backups. Replaced `mktemp -d` with deterministic `WORK_DIR="/tmp/${BACKUP_NAME}"`.
- **MED-007**: `progressive-ban.py` — Re-extended already-escalated bans on every cron run because `target in current_duration` checked remaining time (not original duration) and suffered false-positive substring matches. Replaced with JSON state file.
- **MED-008**: `geoip-block.sh` — Blocklists downloaded over plain HTTP (MITM risk). Upgraded to HTTPS. Added `nft -f /etc/nftables.conf` reload.
- **MED-009**: `discord-alert.sh` — JSON payload built via unsafe heredoc string interpolation. Replaced with `jq -n --arg` construction.
- **LOW-010**: `gateway-monitor.sh` — Missing `LC_ALL=C` before `free` caused empty `mem_pct` on German locales.
- **LOW-011**: `gateway-monitor.sh` — `bc` dependency silently disabled load alerts. Replaced with `awk`.
- **MED-012**: `progressive-ban.py` — State keyed by decision ID caused infinite re-extension loop. CrowdSec creates a new ID on every delete+add, so the old ID was pruned and the new ID re-processed. Fixed by keying state by **IP address**.
- **MED-013**: `geoip-block.sh` + `deploy.sh` — GeoIP blocking was a complete no-op. The set was never loaded into a table context, `/etc/nftables.conf` had no include, and no rule referenced the set. Fixed: `deploy.sh` now generates the include + `ip saddr @geoip_blocklist drop` rule, and runs `geoip-block.sh` at deploy time.
- **LOW-012**: `deploy.sh` — Email alert checked total nginx error log line count, not delta. After a few days of uptime the log always exceeded 100 lines, emailing every 15 minutes indefinitely. Fixed with stored baseline (`last-error-count`).
- **MED-014**: `deploy.sh` — Rollback glob `loxprox-backup-*` matched pre-rollback snapshot dirs (`loxprox-backup-pre-rollback-*`). On a second rollback the snapshot — containing the post-deploy state — was restored instead of the real backup. Fixed: glob restricted to `loxprox-backup-[0-9]*`.

### Changed
- `tests/test_progressive_ban.py` expanded from 17 to 20 cases: added 4 state-file tests (creation, re-run skip, new-ID-after-extend, stale pruning).

## [1.2.0] — 2026-05-07

### Added
- **Network Stack Self-Healing Watchdog** (`security-monitoring/network-watchdog.sh`):
  - Detects network-layer failures (dhclient death-spiral, kernel routing corruption, interface desync) that process-level health checks miss.
  - State-aware: reads `/etc/network/interfaces` to know whether DHCP or static is expected; never kills dhclient on DHCP-configured systems.
  - Heal path: restart nginx → restart `networking.service` → re-evaluate.
  - Reboot path: if healing fails, sends Discord alert with diagnostics, waits 30s, reboots. Post-reboot cycle sends recovery report.
  - Two-layer anti-reboot-loop protection: script-level (max 2/hour) + systemd-level (`StartLimitBurst=3` + `FailureAction=reboot`).
  - Runs as systemd **system** service (root by default) — no sudo, no passwordless access, same privilege model as nginx/networking services.
  - Fully documented in `RUNDOWN.md` with transparency statement, disable instructions, and forensics commands.
- `deploy.sh` now installs and enables the network watchdog automatically.

## [1.1.0] — 2026-05-06

### Security (Ezio Audit Fix Sweep — 23/23 findings resolved)
- **CRIT-001**: Eliminated `curl | bash` supply-chain vector. CrowdSec install now uses GPG-key-pinned apt repository (`gpgkey` downloaded to temp file, verified, then dearmored to `/etc/apt/keyrings/`).
- **HIGH-002**: Added `Content-Security-Policy` and `Permissions-Policy` headers; removed deprecated `X-XSS-Protection`.
- **HIGH-001**: Documented AppSec API key exposure risk in `SECURITY.md` with threat model and mitigation guidance.
- **MED-001**: Removed unconditional `cscli hub upgrade` — hub components are installed at hub-index version; upgrades are intentional operator actions, not automatic surprises.
- **MED-002**: Rollback now validates backup files with `nginx -t`, `nft -c`, and creates a pre-rollback snapshot.
- **MED-003 / MED-004**: `progressive-ban.py` — added `timeout=30` to all `subprocess.run()` calls; return codes checked and stderr logged.
- **LOW-001 / LOW-002**: Replaced predictable temp files with `mktemp` in `detect-loxone.sh` and `gateway-backup.sh`.
- **LOW-003**: `validate_ip()` now uses strict RFC-style regex (0–255 per octet) with `ipcalc` fallback.
- **LOW-005**: Added `/var/log/nginx/appsec-detections.log` to logrotate config.
- **LOW-006**: Discord alert circuit breaker — skips alerts for 15 min after 3 consecutive failures.
- **LOW-007**: Added `proxy_hide_header Server` and `proxy_hide_header X-Powered-By`.
- **LOW-009**: Documented Discord webhook rotation procedure in `SECURITY.md`.

### Added
- Full test infrastructure: `tests/test_progressive_ban.py` (17 pytest cases), `tests/test_deploy_integration.sh` (54 assertions), `tests/test_detect_loxone.sh` (11 assertions).
- Unified test runner: `tests/run-tests.sh`.
- CI integration test job: validates config generation inside a Debian 12 Docker container.
- CI Python test job: runs pytest on every PR.

### Fixed
- `deploy.sh` internal path variables (`SYSCTL_CONF`, `NFTABLES_CONF`, `NGINX_SITE`, etc.) now use `${VAR:-default}` syntax so CI integration tests can override them when sourcing the script.
- **DHCP → Static IP transition now fully safe**: `set-static-ip.sh` actively removes `isc-dhcp-client` and kills stale `dhclient` processes before applying static config. Prevents the 24-hour lease-renewal death-spiral that caused a full network outage.

### Changed
- `deploy.sh` and `detect-loxone.sh` now guard `main()` with `[[ "${BASH_SOURCE[0]}" == "${0}" ]]` to enable sourcing for unit tests.

## [1.0.0] — 2026-05-06

### Added
- Complete six-layer security stack: nftables → nginx → CrowdSec → Firewall Bouncer → AppSec WAF → AppArmor/auditd
- `deploy.sh` — idempotent Debian 12 hardening script (870 lines)
- `test-gateway.sh` — 29-check automated validation suite
- `set-static-ip.sh` — VM network pre-configuration
- `security-monitoring/` — Discord alerts, health monitor, config backup, GeoIP blocking
- CrowdSec AppSec WAF integration with nginx `auth_request` (200+ CVE virtual patches)
- Discord webhook alerting for security events
- Configurable via `.env` pattern
- Raspberry Pi compatibility research and documentation
- Full threat model and incident response playbook in `SECURITY.md`

### Fixed
- CrowdSec AppSec HTTP 401 "missing API key" — discovered required `X-Crowdsec-Appsec-*` headers and bouncer API key authentication flow
- Monitor script locale bug (`LC_ALL=C free` for non-English systems)
- deploy.sh `set -e` compatibility (fixed `check_root` and `backup_file` functions)
- CrowdSec whitelist CIDR parser (was using `ip:` for ranges, caused FATAL error)
- nginx rate limit 503s on Loxone UI assets (burst increased 20→100)

### Security
- AppSec WAF switched from `monitor` to `enforce` mode
- nftables input policy: DROP
- SSH restricted to LAN + site-to-site subnets
- Kernel hardening: syncookies, rp_filter, dmesg_restrict, ASLR
- AppArmor nginx profile enforced
- auditd monitoring for config changes and privilege escalation
- unattended-upgrades with auto-reboot for kernel patches

## [0.9.0] — 2026-05-05

### Added
- Initial gateway deployment with nginx reverse proxy
- CrowdSec IDS + firewall bouncer (nftables)
- Basic rate limiting and connection caps
- Security headers via nginx

### Fixed
- IP migration from DHCP to static `.252`
- Router cutover: external port 1080 forwarded to gateway
- SSH multiplexing with ControlMaster (`%C` hash format)
