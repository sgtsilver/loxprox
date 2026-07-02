# Changelog

All notable changes to this project will be documented in this file.

> **v1.3.0 was withdrawn on 2026-05-18 — do not use.** The systemd unit change in v1.3.0 (moving `StartLimit*` from `[Service]` to `[Unit]`) activated a previously-silent `StartLimitBurst=3` that, combined with the watchdog's 60-second timer and `FailureAction=reboot`, caused an unbounded reboot loop on the 4th start. **v1.3.1 supersedes v1.3.0** and contains the same fixes plus the burst-value correction. Install v1.3.1 or later.

## [Unreleased] — v2.0.0 (tunnel hardening & WebSocket support)

The v2.0 theme: remote access for connections that cannot forward a port
(CGNAT / DS-Lite), plus Tier-2 resilience. Everything is opt-in; a v1.5.x
install upgrades with zero behavior change until `ENABLE_TUNNEL` is flipped.

### Added

- **Zero-open-ports remote access via frp (opt-in, `ENABLE_TUNNEL`)** — the
  gateway dials OUT to an operator-owned relay VPS (ADR-0002); the Loxone app
  connects to the relay's domain. New `deploy.sh` tunnel module: pinned +
  SHA256-verified frpc install (v0.69.1, amd64/arm64), `/etc/frp/frpc.toml`
  (0640, token-authenticated, QUIC or TCP transport), hardened `frpc.service`
  (dedicated unprivileged user, `ProtectSystem=strict`, empty capability set,
  syscall filter, `MemoryMax=256M`), toggle-off + `--remove-tunnel` re-entry
  point. Runbook: `docs/TUNNEL-SETUP.md`.
- **Relay-side installer (`tunnel-relay/install-relay.sh`)** — one-shot
  Debian 12 VPS setup: nftables input-drop, frps (pinned + verified,
  sandboxed, `proxyBindAddr=127.0.0.1` so only nginx is public), nginx TLS
  entry point with WS support and perimeter rate limits, scrubbed access-log
  format (v1.5.1 token-confidentiality carried over to the relay), CrowdSec +
  firewall bouncer (perimeter enforcement — where bans against tunneled
  attackers actually bite), unattended upgrades. Config template:
  `tunnel-relay/relay.conf.example`.
- **Tunnel watchdog (`security-monitoring/tunnel-watchdog.{sh,service,timer}`)**
  — 60s cycle: frpc service + full public-path probe, self-heal via frpc
  restart, Discord CRITICAL alert rate-limited to 1/hour, recovery report.
  Never reboots (a dead tunnel is a relay/ISP problem; LAN access is
  unaffected).
- **Real-IP restoration for tunneled traffic**
  (`/etc/nginx/conf.d/loxprox-tunnel-realip.conf`) — trusts `X-Forwarded-For`
  from loopback only, `real_ip_recursive off`; rate limits, access logs,
  CrowdSec and the AppSec header see true client IPs instead of 127.0.0.1.
- **Dedicated `/ws/` nginx location in the generated site** — the Loxone
  native WebSocket endpoint gets 24h read/send timeouts and
  `proxy_buffering off`; the server-wide ~15s slowloris timeouts previously
  killed idle event sockets on freshly generated configs (production had it
  hand-added; the template now matches). AppSec still inspects the upgrade
  handshake.
- **ACME fallback CA (`TLS_ACME_FALLBACK_SERVER`, default `zerossl`)** — a
  Let's Encrypt outage or rate limit no longer takes cert issuance down;
  applies to gateway (`setup_tls`) and relay alike.
- **Family onboarding guide (`docs/FAMILY-ONBOARDING.md`)** — QR-code deep
  link (`loxone://ms?host=…`), per-member credentials advice, one-URL app
  limitation + split-horizon DNS mitigations.
- **Docs (bilingual EN/DE):** `docs/TUNNEL-SETUP`, `docs/FAMILY-ONBOARDING`,
  `tunnel-relay/README`; new tunnel sections in README, CONFIGURATION-GUIDE
  and SECURITY (threat model: enforcement point moves to the relay for
  tunneled traffic).

### Changed

- `deploy.sh` gains config keys `ENABLE_TUNNEL`, `TUNNEL_SERVER_ADDR`,
  `TUNNEL_SERVER_PORT`, `TUNNEL_PROTOCOL`, `TUNNEL_TOKEN`,
  `TUNNEL_PROXY_NAME`, `TUNNEL_REMOTE_PORT`, `TUNNEL_PUBLIC_HOST`,
  `TLS_ACME_FALLBACK_SERVER` (all defaulted — existing deploy.conf files
  keep working unchanged), health-check/summary coverage for frpc + tunnel
  watchdog, and runtime-config passthrough for the watchdog.
- `ENABLE_TLS=true` + `ENABLE_TUNNEL=true` is refused with a clear error:
  with the tunnel, TLS terminates at the relay (split-horizon wildcard via
  DNS-01 is the tracked follow-up).

## [1.5.2] — 2026-06-14

Full-project audit (`audits/2026-06-09-full-project-audit.md`) remediation: all
HIGH findings plus the mechanical `set -euo pipefail` / `((var++))` error class
across the deploy, monitoring, and ban scripts. Every runtime change was applied
to the maintainer's production gateway and verified live (monitor completes,
watchdog "Cycle passed", ban script clean, nginx/CrowdSec healthy) before release.

### Fixed — HIGH
- **H1 — progressive ban never escalated real attackers.** Offense counting used
  `cscli decisions list -a` (only ever returns *active* decisions) and required
  `origin == "cscli"`, but scenario/AppSec bans are origin `crowdsec`. Now offenses
  come from `cscli alerts list --ip` (durable history) and `crowdsec`-origin bans
  are the ones extended; `-a` dropped. Regression tests rewritten to the new model.
- **H2 — security monitor aborted every clean cycle.** Under `set -euo pipefail` a
  no-match `grep` in the nginx/auth/appsec checks exited non-zero and killed the
  whole cycle (sticky — later checks never ran). `|| true` on each scan pipeline.
- **H3 — watchdog reboot loop.** The give-up path `exit 1` combined with the unit's
  `FailureAction=reboot` to reboot on every failed state; `((count++))` also aborted
  `reboots_in_window` under `set -e`. Give-up now `exit 0`, `FailureAction=reboot`
  removed (the script's own gated reboot remains), arithmetic made safe.
- **H4 — `((retries++))` / `((failures++))` aborted the deploy** on bash ≥ 4.1
  (the expression returns 1 when the var is 0). Switched to `$((var + 1))`.
- **H5 — SSH bootstrap could lock out a root-only box.** The HARD drop-in now uses
  `PermitRootLogin prohibit-password` (key login still works) instead of `no`.
- **H6 — rollback was broken end to end.** Backups now preserve full paths
  (mirror + manifest) and restore to their original locations (not flat into `/etc/`);
  the BACKUP is validated (not the live config); nginx is `-t`'d after restore; and
  every stopped service is restarted, not just nginx. Pre-format flat backups are refused.
- **H7 — `set-static-ip.sh` could strand the box.** Refuses to run with `<placeholder>`
  or invalid IPs, and runs `ifdown`/`ifup` detached (`setsid`+`nohup`) so it survives
  the SSH session dropping the moment the address goes away.

### Fixed — MEDIUM / LOW
- **M6** — new-ban Discord alert no longer swallowed (community-count pipeline
  `|| true`; counts IPs, not lines). **M8** — a cscli/LAPI outage no longer skips the
  rest of the monitor (`|| return 0`). **M9** — backticks stripped from
  attacker-controlled content before the Discord code fence (markdown injection).
  **M11** — Loxone reachability probe uses `:` not `cat` (no false "Cannot reach").
- **L3 + SIGPIPE** — the watchdog interface-IP check now anchors on the `/prefix`
  (so `.5` ≠ `.50/24`) AND is a pure-bash substring match: the old
  `ip addr … | grep -q` false-failed under `pipefail` (grep -q exits on the match →
  `ip` takes SIGPIPE), which could spuriously reboot the box whenever
  `WATCHDOG_EXPECTED_IP` is set. **L13** — sysctls header corrected LXC → VM.

## [1.5.1] — 2026-06-04

Token-confidentiality audit follow-up. A multi-agent session-stealing re-audit
on top of v1.5.0; the residual was confidentiality of the relayed Loxone token,
not the (already-fixed) shell bugs a stale review re-raised. Every change was
applied to the maintainer's production gateway and verified live before release.

### Security — session/token-confidentiality audit (2026-06-04)

A full multi-agent re-audit focused on the confidentiality of the relayed Loxone
token. The five candidate "shell bugs" a stale external review re-raised were
confirmed already fixed in v1.3.2; the real residual was at-rest/in-transit
confidentiality of Loxone auth material. All of the below were applied to the
maintainer's production gateway and verified live (`nginx -t`, real-app traffic
on 5G + WiFi, `cscli explain`) before landing here.

- **MED — access log scrubbed of Loxone auth material (F3).** The `access_log`
  carried no `log_format`, so nginx logged the full `combined` `$request`
  including the query string. Live traffic confirmed the app drives commands as
  `GET /jdev/sys/fenc/<encrypted-blob>?sk=<key>` — secret in **both** path and
  query. New `log_format loxone_scrubbed` reconstructs the request as
  `$request_method $loxone_log_uri $server_protocol` (drops `?query`) and a
  `map $uri $loxone_log_uri` redacts the secret suffix of
  `fenc|enc|gettoken|getjwt|keyexchange|getkey2` path forms → `<redacted>`. Same
  combined shape, so the CrowdSec `type:nginx` parser still parses 100% (verified
  with `cscli explain`). Operators with existing logs should sanitize the current
  log + rotated archives in place (the secrets are already at rest there).
- **MED — TLS forward-secrecy hardening (F6).** The injected TLS block had no
  `ssl_ciphers` and no `ssl_session_tickets off`, so a TLS-1.2 client could pick a
  non-PFS suite and the unrotated session-ticket STEK defeated forward secrecy.
  Added an ECDHE-only `ssl_ciphers` list and `ssl_session_tickets off`. TLS 1.3
  unaffected. Verified live: TLS 1.2 negotiates `ECDHE-…-GCM`, no ticket issued.
- **MED — cleartext backend hop documented in the threat model (F2).** The
  gateway→Miniserver hop is plaintext (Gen 1 has no TLS), carrying the relayed
  token. Added a threat-table row + "Backend hop" note (EN + DE) recommending
  VLAN/point-to-point isolation as the compensating control.
- **LOW — WebSocket transparency in the generated site (F7).** Added
  `map $http_upgrade $connection_upgrade` + `Upgrade`/`Connection` headers so a
  fresh install proxies native ws:// transparently; non-WebSocket requests keep
  the existing empty-Connection keepalive behaviour (no change to the HTTP-API
  path). Existing installs that hand-edited a `/ws/` block keep it (site is
  write-once).
- **LOW — audit tooling excluded from the public repo (F5).** The local audit
  machinery and scratch attack-analysis files were untracked but not gitignored —
  one `git add -A` would have published them. Added to `.gitignore`.

### Fixed

- **Watchdog no longer reboots a healthy VM on an upstream blip (F4).** The
  network watchdog counted router-ping and public-DNS failures toward the reboot
  decision, so an ISP/DNS outage rebooted a healthy VM (dropping every live
  session) for something a reboot can't fix. Reboot now triggers only on
  local-stack failure (`nginx_local`/`interface_ip`); upstream-only failures
  alert once and wait. The dhclient-spiral case this watchdog exists for still
  reboots.
- **Progressive ban is now fail-safe (F9).** `progressive-ban.py` deleted the
  existing decision before adding the extended one, so a failure between the two
  left the IP **unbanned**. Reordered to add-before-delete: a mid-operation
  failure now over-bans (harmless duplicate that expires) rather than un-bans.
  Three regression tests added.
- **CrowdSec collection install failures no longer silent (F8).** `cscli
  collections install … || true` swallowed hub-outage/renamed-item failures;
  `deploy.sh` now asserts each expected collection is present and warns on a gap.

### Changed

- **Preflight warns on cleartext public exposure (F1).** `deploy.sh` now warns
  when `ENABLE_TLS=false`, since a WAN-exposed `:1080` would serve Loxone
  credentials in cleartext (non-fatal — LAN-only gateways legitimately run
  without TLS).
- **Whitelist-breadth warning (F10).** A `CROWDSEC_WHITELIST_IPS` entry broader
  than /24 disables CrowdSec for every host in that range; `deploy.sh` now warns.
- **AppSec fail-closed documented as intentional (F11).** Added an inline note
  that the `auth_request` deny-on-AppSec-outage behaviour is deliberate; do not
  "fix" it into fail-open.

## [1.5.0] — 2026-05-26

Everything from a single intense day: the skills-audit response (SSH hardening, auditd persistence-vector coverage, AppSec audit log, `/tmp` TOCTOU, progressive-ban CAPI filter), the SSH bootstrap flow that solves the lock-yourself-out chicken-and-egg, per-host configuration separated from `deploy.sh` (closing the inline-edit footgun that bricked the maintainer's own VM mid-day), nginx site preservation across upgrades, and optional HTTPS on `:1080` via `acme.sh` + HTTP-01 — plus the three live-deploy fixes that surfaced when the maintainer dogfooded the TLS path on production.

> **Why one big release:** by 21:30 CEST the day had produced six tagged releases (v1.4.0 morning, v1.5.0+v1.5.1 afternoon, v1.6.0+v1.6.1+v1.6.2 evening). That's sloppy. Tags and GitHub releases for all of them were deleted in two consolidation passes; this single v1.5.0 entry is the record. The engineering history (multiple Ezio-style audit-driven fixes, the conf.d-split attempt + revert, the whitespace-regex bug found by the maintainer's own production-VM bootstrap, the firewall-blocking-own-listener footgun, the `if ! cmd; then rc=$?` bash trap, the Loxone-iOS-app self-ban loop from cleartext requests hitting `listen 1080 ssl`) is preserved below and in inline code comments. Future readers may want to know what was tried and why something is shaped the way it is.

The previously-released v1.4.0 (skills-audit response) was consolidated into this entry on the same day — the audit findings are in the **Security** section below.

### Security (skills audit — `audits/2026-05-23-skills-audit.md`)

- **HIGH — SSH daemon hardened by `deploy.sh`.** New `setup_ssh_hardening()` writes `/etc/ssh/sshd_config.d/99-loxprox.conf` with the CIS Debian 12 §5.2 settings: `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, `MaxAuthTries 4`, `LogLevel VERBOSE`, `ClientAliveInterval 300`, agent/X11/TCP-forward all off. nftables already drops `:22` from anything outside `SSH_ALLOWED_SUBNETS`, so this finding only ever mattered against a compromised LAN host trying to brute-force the gateway from inside the perimeter — but stock Debian shipped `PasswordAuthentication yes`, leaving that window open. Closed now.
- **MED — auditd persistence-vector coverage.** `setup_auditd()` now also watches `/etc/ld.so.preload` + `ld.so.conf{,.d/}` (T1574.006 LD_PRELOAD hijack), `/etc/systemd/system/` + `/lib/systemd/system/` + `/usr/lib/systemd/system/` (T1543.002 unit drops), `/etc/profile{,.d/}` + `/etc/bash.bashrc` + `/root/.bashrc` + `.bash_profile` + `.profile` (T1546.004 shell init), `/root/.ssh/` plus any `/home/<user>/.ssh/` for UID≥1000 (T1098.004 SSH backdoor keys), and the four periodic cron dirs + `/etc/anacrontab` (T1053.003).
- **MED — progressive-ban no longer inflates offense count from CAPI/AppSec.** `progressive-ban.py` was building the per-IP offense counter from every decision in `cscli decisions list -a` regardless of `origin`. An IP that appeared once on the CAPI community blocklist plus once on a local cscli ban was treated as a 2nd-offense local repeat → instant escalation to 24h, defeating the intended "punish proven-local repeats" policy. Counter is now filtered to `origin == "cscli"` only. Regression test `test_capi_history_does_not_inflate_local_offense_count` added.
- **MED — AppSec detections actually get written to disk.** `gateway-monitor.sh:check_appsec_detections()` had been tailing `/var/log/nginx/appsec-detections.log` since v1.x, but nothing ever wrote that file — CrowdSec AppSec returns decisions to nginx via `auth_request`, and nginx was not logging the body. `configure_nginx()` now emits a `map $appsec_action $appsec_blocked` + `log_format appsec_evt` + conditional `access_log` so blocked requests get a parseable per-IP audit trail.
- **LOW — `/tmp` TOCTOU surface closed in monitoring scripts.** `gateway-backup.sh` previously used a predictable `/tmp/${BACKUP_NAME}` work dir; replaced with `mktemp -d` + `trap rm -rf EXIT`. `discord-alert.sh` circuit-breaker state moved from `/tmp/loxprox-discord-cb` to `${LOXPROX_STATE_DIR:-/var/lib/loxprox}/discord-cb` (0750 root).
- **LOW — `/tmp` mounted nosuid,nodev,noexec (CIS §1.1.2).** New `setup_tmp_mount()` writes a `tmp.mount.d` drop-in with `mode=1777,strictatime,nosuid,nodev,noexec` and enables `tmp.mount`. Warns and continues on systems without a `tmp.mount` unit (manual `/etc/fstab` then required).

### Added — SSH bootstrap flow (chicken-and-egg solved)

`setup_ssh_hardening()` detects whether any `authorized_keys` is present (root + UID≥1000 users) **before** disabling password auth. Without this, the HIGH fix above would have bricked any first-time deploy run over a password-only SSH session.

- **Interactive deploy (tty):** four-option menu — `[P]` paste your public key (validated by prefix + `ssh-keygen -l -f` round-trip, echoed back with fingerprint, requires explicit `y` to install at `/root/.ssh/authorized_keys` mode 0600), `[H]` show help (exact `ssh-keygen -t ed25519` + `cat ~/.ssh/id_ed25519.pub` invocations for macOS/Linux/Windows + Google search terms), `[K]` keep password auth + loud login banner, `[A]` abort.
- **Non-interactive (no tty):** falls back automatically to `[K]` mode so Ansible/CI/unattended runs never brick the box.
- **Soft mode** (`[K]` or no-tty) ships a different sshd drop-in that keeps `PasswordAuthentication yes` but still sets `MaxAuthTries 4`, `LogLevel VERBOSE`, key-pref, no forwarding; and installs `/etc/update-motd.d/99-loxprox-ssh-warn` — a red banner on every login until `/var/lib/loxprox/ssh-keys-missing` is removed.
- **`sudo bash deploy.sh --finalize-ssh`** — new re-entry point; rechecks keys, swaps soft→hard drop-in, removes nag, reloads sshd. Run after `ssh-copy-id root@<gateway>`.
- **Private keys are never generated on the server.** The paste flow only accepts a pre-existing public key.

### Changed (breaking — requires one-time migration)

- **Per-host configuration moved to `/etc/loxprox/deploy.conf`** (mode 0640 root). `deploy.sh` no longer carries inline REQUIRED defaults. The tracked template `deploy.conf.example` lives at the repo root; `.gitignore` excludes the populated `deploy.conf` so an accidental copy into the repo never gets committed.
- **`deploy.sh` refuses to run if no config file is present and no live install is detected.** Fresh-VM operators who forget to copy the example get a clear error pointing to `deploy.conf.example` instead of a silently-broken deploy with upstream placeholders. The previous footgun — `LOXONE_IP="192.168.1.100"` shipped inline at line 47 of `deploy.sh`, requiring every operator to edit the script before running and keep that edited copy somewhere safe — bricked the maintainer's own production VM during the morning's skills-audit deploy. No longer reachable.
- **Idempotent upgrades.** `git pull && sudo bash deploy.sh` now actually works the way the README has always claimed — no more re-editing the script every release.
- **Supported substrate narrowed to VM-only.** `deploy.sh` refuses to run inside a container (LXC / systemd-nspawn) unless `ALLOW_LXC=1` is set explicitly. Several gateway defenses — the Fragnesia (CVE-2026-46300) mitigation, `kernel.dmesg_restrict` / `kptr_restrict` / `randomize_va_space`, auditd rule loading, AppArmor profile enforcement, nftables table creation — either no-op or return EPERM from inside an unprivileged container. The previous "warn and continue" behavior made the deploy look green while the actual posture was degraded. New behavior aborts with an explicit explanation. Operators who knowingly accept the reduced posture can opt in with `ALLOW_LXC=1`; the CIS Debian 12 / OWASP IoT Top 10 posture claims do not apply in that configuration.
- **Minimum hardware: 1 GB RAM / 1 vCPU minimum (was 512 MB / 1 core); 2 GB RAM / 2 vCPU recommended.** The previous 512 MB was fiction — reference VM sits at ~850 MB RSS idle. CrowdSec leaky-bucket memory scales linearly with active attacker IPs (256 IPs ≈ 150 MB, 15k IPs ≈ 1.2–1.5 GB). AppSec WAF + Virtual Patching adds ~5 ms / ~50 millicores per request. A second vCPU gives the scheduler room to keep nginx responsive while AppSec catches up during a wide-cardinality scan.

### Added — config bootstrap from existing installs

- **`sudo bash deploy.sh --bootstrap-config`** — for upgrading existing v1.4.0 (and earlier) installs that don't yet have `/etc/loxprox/deploy.conf`. Reads back the operator's current production values from live state:
    - `LOXONE_IP` / `LOXONE_PORT` from `/etc/nginx/sites-available/loxone` (`upstream` block)
    - `GATEWAY_IP` from `hostname -I` (primary interface)
    - `LAN_SUBNET` from `ip route` (first `proto kernel scope link` route)
    - `SSH_ALLOWED_SUBNETS` from `/etc/nftables.conf` (`tcp dport 22 ip saddr {…}` set)
    - `ENABLE_APPSEC` from the presence of `auth_request /crowdsec-appsec` in the nginx site (whitespace-tolerant regex — aligned-column nginx configs like `auth_request      /crowdsec-appsec;` parse correctly)
    - `APPSEC_MODE` from `/etc/crowdsec/acquis.d/appsec.yaml`
    - `CROWDSEC_WHITELIST_IPS` from `/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml`
    - `DISCORD_WEBHOOK_URL` from `/etc/loxprox/config.env`
  Writes the candidate to a temp file, prints it for review, asks for confirmation, then installs at `/etc/loxprox/deploy.conf` (with a `.bak-<timestamp>` of any prior file). Non-interactive mode (`LOXPROX_BOOTSTRAP_YES=1`) writes without prompting.
- **Auto-bootstrap fallback for non-interactive deploys.** If `deploy.sh` runs without a tty, no config exists, and a live install IS detected, it auto-runs `--bootstrap-config` (no prompt) and proceeds. Ansible / CI pipelines no longer need a two-step invocation.

### Changed — nginx config now resists hand-edits

- **`configure_nginx()` preserves `/etc/nginx/sites-available/loxone` if it already exists.** WebSocket location blocks, custom `proxy_set_header` lines, and other operator hand-edits no longer get nuked on every redeploy. Set `LOXPROX_FORCE_REGEN_NGINX=1` to override and regenerate from template.
- **AppSec map + log_format stay inline in the site file.** A `/etc/nginx/conf.d/loxprox-appsec.conf` split was attempted (and reverted in the same branch) because nginx rejects it: `auth_request_set $appsec_action $upstream_http_x_crowdsec_action` is what registers `$appsec_action` with nginx's variable subsystem, and that directive lives inside the location block. Any earlier reference to `$appsec_action` — including in an http-scope `if=` clause or another conf.d file — fails parse-time validation with `unknown "appsec_action" variable`. The map and `log_format appsec_evt` therefore stay where they were placed by the v1.4.0 surgical patch (same file as the `auth_request_set`). A leftover `/etc/nginx/conf.d/loxprox-appsec.conf` from any dev iteration is `rm -f`'d on every deploy.
- **nginx reloaded (`systemctl reload`) instead of restarted** when the config changes during a deploy. Restart burned established `keepalive` to the Miniserver; reload is graceful. Falls back to restart if reload fails.

### Added — optional HTTPS on :1080 via `acme.sh` + HTTP-01

Off by default. Toggle is a `deploy.conf` edit + `sudo bash deploy.sh` re-run; the on→off path is just as clean as off→on. Cert files survive a disable so flipping back doesn't pay re-issuance time.

- **New `deploy.conf` keys** (all optional, sane defaults):
    - `ENABLE_TLS="false"` — master toggle.
    - `TLS_DOMAIN=""` — fully-qualified public hostname (e.g. `loxprox.example.com`). Required when `ENABLE_TLS=true`; refused with a clear error if missing or non-FQDN.
    - `TLS_EMAIL=""` — registered with the ACME provider.
    - `TLS_ACME_SERVER="letsencrypt"` — also accepts `letsencrypt_test` (staging), `zerossl`, `buypass`, `buypass_test`, `sslcom`, or a full directory URL.
    - `TLS_ACME_EXTRA=""` — passthrough to `acme.sh --issue` (e.g. `--keylength ec-256`).
- **`setup_tls()` orchestrator** in `deploy.sh`:
    - Installs `acme.sh 3.1.3` from a **SHA256-pinned GitHub release tarball** — no `curl | bash`. The pin (`ACMESH_VER`, `ACMESH_SHA256`) lives at the top of the script; refresh procedure documented inline.
    - Writes `/etc/nginx/conf.d/loxprox-acme.conf` — a small `:80` `default_server` that serves only `/.well-known/acme-challenge/` from `/var/www/acme/` and 301s everything else to `https://$host:1080$request_uri`. The widened public surface is just the challenge directory.
    - **Opens `:80` in nftables** when `ENABLE_TLS=true` (a v1.6.1 follow-up — v1.6.0 wrote the listener but the default-drop firewall silently swallowed Let's Encrypt's external probe). When TLS is disabled, the rule is omitted and `:80` returns to closed.
    - Issues (or renews) the cert via `acme.sh --issue --webroot --server $TLS_ACME_SERVER`. The `--issue` exit code is captured **outside** the `if` (a v1.6.1 follow-up — the `if ! cmd; then rc=$?; fi` pattern always captured the negation result `0`, so operators saw `acme.sh --issue failed (rc=0)` on every real failure). `case "$rc"` now handles `0`, `2` (skipped — cert still valid), and other-as-error.
    - Installs the cert at `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (`0640 root`) with `--reloadcmd "systemctl reload nginx"` recorded for the renewal cron.
    - **Mutates the nginx site** between explicit markers (`# LOXPROX-TLS-BEGIN` / `# LOXPROX-TLS-END`) and swaps `listen 1080;` ↔ `listen 1080 ssl;`. This is the one deviation from the site-preservation rule above; operator hand-edits outside the marker block are untouched. Strict regex on the listen line: anything other than the canonical `listen 1080;` is refused with a warning, never silently mutated.
    - **Inside the marker block: `error_page 497` → named-location 301 redirect** (a v1.6.2 follow-up — without it, any plain-HTTP client hitting `:1080 ssl` got nginx's default `400 "The plain HTTP request was sent to HTTPS port"`, which CrowdSec's `http-probing` scenario interprets as scanning and bans the client IP. The Loxone iOS app trips this within seconds when its connection URL is still `http://`). The bare `error_page 497 https://…` form does NOT redirect on nginx 1.22.1 (Debian 12) — the working pattern is `error_page 497 = @loxprox_https_redirect;` plus a named location returning a 301. Clients that follow redirects are unaffected; ones that don't (the Loxone app, notably) still need their connection URL updated from `http://` to `https://`, but the gateway no longer triggers the ban loop while the operator is migrating.
    - **Auto-renewal cron is verified after every TLS-enabled deploy.** `acme.sh`'s `--install` creates the daily cron; `_loxprox_ensure_acme_cron` re-asserts it exists, restores it via `--install-cronjob` if missing, and logs the exact cron line + the manual-renewal recipe.
    - awk (not sed) for both the enable and disable mutations — BSD sed (macOS) and GNU sed (Linux) disagree on `\n` expansion and `\+` support; awk handles it uniformly.
- **`sudo bash deploy.sh --renew-tls`** — manual force-renew (`acme.sh --renew … --force`).
- **`sudo bash deploy.sh --remove-tls`** — full nuke: site revert, conf.d listener removed, `acme.sh --uninstall`, `/etc/loxprox/tls/` deleted, cron cancelled. Operator action remaining: remove the `WAN:80 → gateway:80` router forward.

### Disable path (`ENABLE_TLS=false`)

- Strips the marker block from the site, reverts the listen line to plain `listen 1080;`, removes the ACME `:80` listener, drops the `:80` nftables rule, cancels the per-domain renewal in `acme.sh`. Cert files at `/etc/loxprox/tls/` are kept — re-enable is fast.

### Tests

- 114 deploy-integration assertions (was 64 pre-v1.6). New cases cover:
    - `_loxprox_load_config`, `_loxprox_detect_live_install`, `_loxprox_extract_config_from_live_state` (positive + empty-fixture negative).
    - `configure_nginx` preservation — operator sentinel + WebSocket block survive a redeploy by default; `LOXPROX_FORCE_REGEN_NGINX=1` regenerates from template.
    - `_loxprox_tls_validate_config` — refuses empty `TLS_DOMAIN`, refuses non-FQDN, accepts FQDN.
    - `_loxprox_site_enable_tls` + `_loxprox_site_disable_tls` round-trip: enable → markers + ssl listen + cert directives + HSTS header → disable → marker block stripped + listen reverted → enable again → identical output. Re-enable and re-disable are byte-identical no-ops (hash compared).
    - Refusal path: `listen [::]:1080;` (operator hand-edit) is detected and rejected without touching the site.
    - `_loxprox_write_acme_listener` writes the conf.d block with the right contents.
- pytest progressive-ban suite unchanged: 22/22.
- shellcheck `-S warning` clean.

### Live verification on the maintainer's production VM (2026-05-26)

- Bootstrap: `--bootstrap-config` extracted the seven critical values from live state (after the whitespace-regex fix; aligned-column `auth_request      /crowdsec-appsec;` was the trigger that exposed the bug).
- Staging issuance: succeeded against `letsencrypt_test` once the `:80` nftables rule was in place.
- Production issuance: cert from Let's Encrypt E7 intermediate, valid 2026-05-26 → 2026-08-24, browser-trusted from an external Hetzner host (`TLS_verify 0`, no `-k`).
- Auto-renewal cron: `0 0 * * * "/root/.acme.sh"/acme.sh --cron ...` present.
- End-to-end: Loxone iOS app on cellular connecting through `https://<gateway-fqdn>:1080` after the operator added `:1080` to the URL in the app's connection settings.

### Operator action

**v1.3.4 → v1.5.0 upgrade (existing install):**

```bash
git pull
sudo bash deploy.sh --bootstrap-config        # writes /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf         # review (recommended)
sudo bash deploy.sh                           # normal deploy, sources the file
```

**Fresh VM install:**

```bash
sudo install -d -m 0750 /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf         # fill [REQUIRED] values
sudo bash deploy.sh
```

**Enable HTTPS:**

```bash
# 1. Add a router forward: WAN:80 → gateway:80
# 2. Point public DNS at your WAN IP for TLS_DOMAIN
# 3. Edit /etc/loxprox/deploy.conf:
#      ENABLE_TLS="true"
#      TLS_DOMAIN="loxprox.example.com"
#      TLS_EMAIL="you@example.com"
#      TLS_ACME_SERVER="letsencrypt_test"   # staging first; switch to "letsencrypt" once validated
sudo bash deploy.sh
```

**Toggle TLS off:** `ENABLE_TLS="false"` in `deploy.conf`, `sudo bash deploy.sh`. Cert kept, site reverted, `:80` nftables rule dropped.

**For clients still on `http://`:** the v1.6.2 redirect prevents the ban-loop while you migrate. Update each client's connection URL to `https://<hostname>:1080`. The Loxone iOS/Android apps preserve port in their UI separately from scheme — verify `:1080` is still present after switching to `https`.

Full upgrade walkthrough: [`docs/UPGRADE-to-v1.5.md`](docs/UPGRADE-to-v1.5.md). TLS runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).

### Retired tags (deleted, consolidated into v1.5.0)

Six tags + GitHub releases were created during today's iteration and then deleted in two consolidation passes:

| Tag (deleted) | Why it existed |
|---|---|
| `v1.4.0` | Skills-audit response (SSH §5.2, auditd persistence, AppSec log, /tmp, SSH bootstrap). Folded into v1.5.0's **Security** + **Added — SSH bootstrap flow** sections. |
| `v1.5.0` (first cut) | Config-separation + auto-bootstrap upgrade path. Folded in. |
| `v1.5.1` | Whitespace regex bug found by live `--bootstrap-config` on the maintainer's site. Fix folded in. |
| `v1.6.0` | Optional TLS via acme.sh + HTTP-01. Folded in. |
| `v1.6.1` | nftables `:80` open when ENABLE_TLS=true + `acme.sh` rc=0 reporting fix. Folded in. |
| `v1.6.2` | `error_page 497 → @named-location 301` to stop the Loxone-iOS-app ban loop. Folded in. |

All six tags' content is in this v1.5.0 entry. Inline code comments still reference the dev iterations by name (e.g. "v1.5.0-dev iteration") for engineering-history traceability — future readers benefit from knowing what was tried, not just what shipped.

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
- IP migration from DHCP to a static LAN IP
- Router cutover: external port 1080 forwarded to gateway
- SSH multiplexing with ControlMaster (`%C` hash format)
