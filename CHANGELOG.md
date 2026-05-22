# Changelog

All notable changes to this project will be documented in this file.

> **v1.3.0 was withdrawn on 2026-05-18 — do not use.** The systemd unit change in v1.3.0 (moving `StartLimit*` from `[Service]` to `[Unit]`) activated a previously-silent `StartLimitBurst=3` that, combined with the watchdog's 60-second timer and `FailureAction=reboot`, caused an unbounded reboot loop on the 4th start. **v1.3.1 supersedes v1.3.0** and contains the same fixes plus the burst-value correction. Install v1.3.1 or later.

## [1.3.4] — 2026-05-22

### Security

- **HIGH — supply chain**: `deploy.sh` and `phase2-gateway/install-gateway.sh` now cross-verify the CrowdSec packagecloud GPG key against three independent public keyservers (`keys.openpgp.org`, `keyserver.ubuntu.com`, `pgp.surf.nl`) before importing it. Previously the key was Trust-On-First-Use: an attacker with first-install MITM (rogue CA, hostile resolver, CDN compromise) could substitute the key and serve attacker-signed `crowdsec` packages. The verifier extracts the primary fingerprint from the freshly-downloaded primary key, queries each keyserver for the same fingerprint, and refuses to import if any keyserver returns a *different* fingerprint (positive attack signal — always fatal). Below the quorum threshold (`LOXPROX_GPG_QUORUM=2`), behaviour is controlled by `LOXPROX_GPG_VERIFY_MODE`: `soft` (default) warns and falls back to TOFU when keyservers are unreachable; `hard` aborts. No fingerprint is hardcoded — when CrowdSec rotates keys, the keyservers reflect the rotation automatically and no script update is required. Only affects fresh installs (existing deployments keep their already-imported keyring untouched, since the install block is gated by `command -v cscli`).

- **MED — kernel hardening (CVE-2026-46300 "Fragnesia")**: `apply_sysctls()` now sets `kernel.unprivileged_userns_clone = 0`. Fragnesia is an unpatched Linux XFRM ESP-in-TCP LPE (CVSS 7.8, public PoC) that requires unprivileged user namespaces to reach the vulnerable code path. The gateway VM has no legitimate use for unprivileged userns (no containers, no sandboxed browsers, no non-root processes that need them), so disabling them removes the exploit prerequisite at zero functional cost. Mitigation lands as a runtime change on `deploy.sh` re-run; on the production VM it was applied live via `/etc/sysctl.d/95-loxprox-userns.conf` prior to this release.

### Notes — upstream patches applied via apt (not part of this release, but related)

- **DSA-6278-1** (16 May 2026) — nginx `1.22.1-9+deb12u4 → +deb12u7`. Covers CVE-2026-40701, -42934, -42945, **-42946** (SCGI/uWSGI memory disclosure, only exploitable when `scgi_pass`/`uwsgi_pass` is configured — LoxProx does not configure either), -40460. Pulled in by `apt upgrade` on 2026-05-22.
- **DSA-6275-1** (15 May 2026) — linux kernel `6.1.170-1 → 6.1.172-1`. Fixes CVE-2026-46333 (kernel LPE). Reboot required to activate; auto-reboot at `AUTOREBOOT_TIME` (default 03:00) will pick it up.
- **CrowdSec** `1.7.7 → 1.7.8` — routine upstream maintenance release, no security-tracker advisory.

### Tests
- `tests/test_deploy_integration.sh` — added two regression cases:
  - `apply_sysctls()` emits `kernel.unprivileged_userns_clone = 0`
  - `verify_crowdsec_key` function is defined and references all three keyserver hosts
- Deploy integration suite: 68 assertions (was 64). Scanner shell: 11. All green.

### Operator action required

- **No action for existing installs.** The GPG fingerprint pin only fires on fresh installs (when `cscli` is absent). Existing deployments keep their already-trusted keyring.
- **Re-run `deploy.sh`** on existing installs to pick up the Fragnesia sysctl. Or apply manually:
  ```
  echo "kernel.unprivileged_userns_clone = 0" | sudo tee /etc/sysctl.d/95-loxprox-userns.conf
  sudo sysctl --system
  ```
- **Apply kernel + nginx DSAs** via `sudo apt update && sudo apt upgrade` if `unattended-upgrades` has not already done so. Kernel patch activates on reboot.

## [1.3.3] — 2026-05-21

### Fixed
- **HIGH**: `security-monitoring/geoip-block.sh` — the final `nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf` step failed with `netlink: Error: Could not process rule: No buffer space available` once the blocklist passed ~20 000 CIDRs. The error is a netlink message-size limit (independent of `net.core.rmem_max` / `wmem_max` socket buffer sysctls — confirmed live by bumping them to 8 MB with no effect). Symptom: `/etc/nftables.d/99-geoip.conf` updated daily, but kernel state silently stale after first boot. The boot path was not affected (kernel state empty at that point fits in a single transaction). Replaced the single atomic reload with an incremental loader: `nft flush set inet filter geoip_blocklist` followed by `nft add element inet filter geoip_blocklist { … }` in batches of `GEOIP_BATCH_SIZE` (default 1000) — each batch is its own small netlink message. First-deploy path (set not declared yet) still uses the full `nft -f /etc/nftables.conf` reload to declare the set. Fail closed: a failed flush or any failed batch exits non-zero and logs via `logger -p user.err`. (#11)

### Notes
- New optional env var: `GEOIP_BATCH_SIZE` (default `1000`). Lower it on extremely memory-constrained hosts; raise it if you want fewer netlink round-trips.
- Tests: shellcheck/syntax clean. End-to-end validated on the production VM (22 061 CIDRs → 11 031 interval-merged set entries, 23 batches, exit 0).

## [1.3.2] — 2026-05-21

### Fixed (Third-Party Audit Sweep — 5/5 findings resolved)
- **HIGH**: `deploy.sh:validate_network()` — regex was shape-only and accepted impossible CIDRs such as `999.999.1.0/24`. Bad `LAN_SUBNET` or `SSH_ALLOWED_SUBNETS` inputs could pass preflight and produce invalid or unintended firewall behaviour at nftables reload. Tightened to require each octet 0–255 (matching `validate_ip` strictness), with optional `ipcalc -c` fallback. Regression tests added for octet-overflow, 3-octet, and alpha-octet inputs.
- **MED**: `deploy.sh:preflight()` — `LAN_SUBNET` was validated but each entry of `SSH_ALLOWED_SUBNETS` was not. Malformed entries were accepted until nftables reload time, where deployment failed late or behaved unpredictably. Preflight now iterates the array and runs the same CIDR validator on every entry; empty array refuses to deploy.
- **MED**: `security-monitoring/geoip-block.sh` — every `curl` was `|| true`, so a complete (or partial) download outage at ipdeny.com silently shrank coverage while operators believed GeoIP blocking was fresh. Made the update path fail closed: each list downloads to `${cc}.zone.new`; only when `GEOIP_MIN_SUCCESS_RATIO` (default `1.0`) of fetches succeed are the staged files promoted. Otherwise active rules are left untouched, an error is logged via `logger -p user.err`, and the script exits non-zero so cron mail / monitoring picks it up.
- **MED**: `deploy.sh:setup_alerting()` — the 15-minute cron writes `/var/lib/loxprox/last-error-count`, but the directory was only created later by `setup_security_monitoring()`. On a pristine host with `ALERT_EMAIL` set, the first cron tick failed silently. `setup_alerting()` now `mkdir -p /var/lib/loxprox` (mode 0750) up front.
- **LOW**: `deploy.sh:configure_crowdsec()` — comment block claimed "pinned versions" while installs use rolling collection names (cscli does not support `@version` tags on `collections install`). Rewrote the comment to reflect reality: determinism is provided by skipping `cscli hub upgrade` on every deploy and by operator-driven upgrade after staging validation, not by version pins.

### Tests
- `tests/test_deploy_integration.sh` — added four `validate_network()` regression cases (octet >255, 256-edge, 3-octet CIDR, alpha-octet CIDR). Deploy integration suite: 64 assertions (was 60). Scanner shell suite: 11. All green.

## [1.3.1] — 2026-05-18 (supersedes withdrawn v1.3.0)

### Fixed (regression from v1.3.0)
- **CRIT**: `network-watchdog.service` — v1.3.0 moved `StartLimitIntervalSec=600` + `StartLimitBurst=3` from `[Service]` to `[Unit]` per `systemd.unit(5)`. The move was correct, but for the first time the values *activated* — and `3` is far too low when the watchdog timer fires every 60 s. The 4th start inside the 600 s window was blocked as `start-limit-hit`, then `FailureAction=reboot` interpreted that as failure and rebooted the host. Result: production VM rebooted ~10× in ~40 minutes. Set `StartLimitBurst=0` (disabled). The script already has its own anti-loop counter (`MAX_REBOOTS_PER_HOUR=2`); the systemd-level limit was redundant *and* lethal at that burst value. Updated comments in `network-watchdog.sh` (`handle_reboot` block) to match.

### Fixed (Second Bug Sweep — carried over from v1.3.0, 12/12 findings resolved)
- **HIGH**: `progressive-ban.py` — `cscli decisions list -o json` emits `null` (Go nil-slice marshal), not `[]`. `json.loads("null") → None` then `sys.exit(1)` on every cron run on a gateway with no decisions. Normalised to `[]` in `run_cscli`. New regression test `test_run_cscli_null_response_returns_empty_list`.
- **HIGH**: `grafana-integration/loxprox-metrics.sh` — `... | grep -c PATTERN || echo 0` under `pipefail` emitted a two-line string `"0\n0"` that broke node_exporter textfile scraping. Replaced with `|| true` in 3 places.
- **MED**: `network-watchdog.sh` — `EXPECTED_IP` fallback chained to `GATEWAY_IP`, which by then has been reassigned to the upstream router IP. Configs without an explicit `WATCHDOG_EXPECTED_IP` would trip `check_interface_ip` forever and trigger reboot loops (capped at 2/hr by anti-loop). Default to `UNSET` and skip the check.
- **MED**: `deploy.sh` first-deploy ordering — `setup_firewall` restarted nftables while `/etc/nftables.conf` referenced `@geoip_blocklist`, which was only defined later when `geoip-block.sh` runs. Pre-seed an empty placeholder set so the include resolves and nftables loads on a clean VM.
- **MED**: `deploy.sh` was missing the install-monitoring step — `gateway-monitor.sh`, `gateway-backup.sh`, the monitor systemd timer, and the cron file. Added `setup_security_monitoring()` so a fresh deploy matches what operators had been installing by hand.
- **LOW**: `gateway-monitor.sh:86` fragile `[ "$count" -gt 0 ] 2>/dev/null` (which does NOT suppress `set -e` from `[`'s rc=2 on empty `$count`). Use `[[ "${count:-0}" -gt 0 ]]`.
- **LOW**: `network-watchdog.service` — `StartLimitIntervalSec` + `StartLimitBurst` directives moved from `[Service]` to `[Unit]` per `systemd.unit(5)`. (See the **CRIT** entry above for the burst-value follow-up that this move forced.)

### Changed (polish / dedup, from v1.3.0)
- `detect-loxone.sh` — `scan_subnet_cidr` and `scan_range` were ~95% duplicated; factored into shared `scan_int_range` + `print_match` (−40 LOC, same behaviour).
- `detect-loxone.sh:probe_loxone` — `/jdev/cfg/api` was GET'd twice on OUI miss; one call now.
- `detect-loxone.sh` — throttle `wait` fired at iter 0 with only 1 background spawned (first 50-batch never actually parallel); counter-based now.
- `progressive-ban.py` — `save_state` moved out of the escalation loop.
- `test-gateway.sh` — dropped dead `bc`-as-monitor-dep check (LOW-011 removed the `bc` dependency in v1.2.1); updated paths/timer to `/opt/loxprox/` and `loxprox-monitor.timer`.

### Renamed (install footprint, from v1.3.0)
- `/opt/loxone-security/*` → `/opt/loxprox/*`
- `/var/lib/loxone-monitor/*` → `/var/lib/loxprox/*`
- `loxone-security-monitor.{service,timer}` → `loxprox-monitor.{service,timer}`
- `/etc/cron.d/loxone-security` → `/etc/cron.d/loxprox`

For operators on an earlier install, see PR #5 for a step-by-step migration.

### Docs (carried + extended)
- `CONFIGURATION-GUIDE.md`, `RUNDOWN.md`, `deploy.sh`, `network-watchdog.sh` — replaced specific network examples with RFC-style documentation ranges (`192.168.1.x`, `203.0.113.x`, `198.51.100.x`). No behaviour change.
- `README.md`, `ABOUT.md`, `RUNDOWN.md` — replaced stale "29 automated checks" with "50+ automated checks" (`test-gateway.sh` has grown to ~51 assertions). Fixed stale backup path `/root/gateway-backups/` → `/root/loxprox-backups/`. Added `progressive-ban.py` to the README file tree. Refreshed deploy.sh line count (~1240 lines) and the cumulative test-assertion stat (88 total).
- `GITHUB-METADATA.md` — dropped the stale v1.0.0 release-notes draft and the `curl ... | sudo bash` install line (would have reintroduced the supply-chain vector that v1.1.0's CRIT-001 fix removed from `deploy.sh`). Releases are sourced from `CHANGELOG.md` at tag time now.

### Tests
- pytest: 21 (was 20). Scanner shell: 11. Deploy integration: 54. All green. `systemd-analyze verify` clean on all units.

## [1.3.0] — 2026-05-18 — **WITHDRAWN**

This release was withdrawn ~3 hours after publication. The systemd-unit fix it contained activated a previously-silent `StartLimitBurst=3` that, combined with the 60-second watchdog timer and `FailureAction=reboot`, caused an unbounded reboot loop on the 4th start. See `[1.3.1]` for the corrected release; all v1.3.0 content is included there.

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
  - Two-layer anti-reboot-loop protection: script-level (max 2/hour) + systemd-level (`FailureAction=reboot` as last-resort safety net; `StartLimitBurst=0` because a finite burst limit conflicts with a 60-second timer).
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
