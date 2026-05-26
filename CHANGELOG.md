# Changelog

All notable changes to this project will be documented in this file.

> **v1.3.0 was withdrawn on 2026-05-18 — do not use.** The systemd unit change in v1.3.0 (moving `StartLimit*` from `[Service]` to `[Unit]`) activated a previously-silent `StartLimitBurst=3` that, combined with the watchdog's 60-second timer and `FailureAction=reboot`, caused an unbounded reboot loop on the 4th start. **v1.3.1 supersedes v1.3.0** and contains the same fixes plus the burst-value correction. Install v1.3.1 or later.

## [Unreleased]

## [1.6.2] — 2026-05-26

### Fixed

- **`listen 1080 ssl` now answers plain-HTTP clients with a 301 redirect to HTTPS** instead of returning the default `400 "The plain HTTP request was sent to HTTPS port"`. Found within minutes of switching the maintainer's production VM to HTTPS: the Loxone iOS app was configured for `http://gateway:1080`, the gateway is now `listen 1080 ssl`, and every API call (`/jdev/cfg/api?cacheBstr=…`) got a 400. CrowdSec's `http-probing` scenario interprets a burst of 400s as scanning activity and bans the client IP — Loxone clients trip into a self-ban loop within seconds.

    nginx's internal status code for this case is `497`. Bare `error_page 497 https://…` does not actually redirect (verified on Debian 12 nginx 1.22.1). The reliable form is a named location:

    ```nginx
    error_page 497 = @loxprox_https_redirect;
    location @loxprox_https_redirect {
        return 301 https://$host:1080$request_uri;
    }
    ```

    Added inside the v1.6.0 TLS marker block in `configure_nginx()` → `_loxprox_site_enable_tls()`. Lands automatically on every TLS-enabled deploy from v1.6.2 onward. Sites mutated by v1.6.0/v1.6.1 don't get the redirect on re-deploy unless the marker block is regenerated; the simplest fix on those installs is `sudo bash deploy.sh --remove-tls && sudo bash deploy.sh` to recycle the marker block.

### Notes

- This is a transitional grace, not the final story. Loxone iOS/Android/Mac clients that follow HTTP 301 redirects will continue to work without configuration change. Clients that don't (some embedded Loxone Touch UIs, older firmware) will still need their connection URL updated from `http://` to `https://`.
- CrowdSec's `http-probing` scenario stays as-is — once cleartext clients are migrated to HTTPS, no 400 storm is generated and the scenario doesn't fire on legitimate Loxone traffic.

## [1.6.1] — 2026-05-26

Two fixes caught by the first live TLS deploy on the maintainer's production VM.

### Fixed

- **`setup_firewall()` now opens `:80` in nftables when `ENABLE_TLS=true`.** v1.6.0 wrote the nginx `:80` ACME challenge listener but left the nftables input chain at default-drop with no `:80` accept rule — Let's Encrypt's external probe always timed out with "Timeout during connect (likely firewall problem)" regardless of whether the router forward was in place. The listener answered correctly on `127.0.0.1:80` (loopback bypasses the input chain) but every WAN-arriving SYN to `:80` was silently dropped by the gateway itself. v1.6.1 adds:
    ```nftables
    # ACME HTTP-01 + HTTPS-on-1080 301 redirector (v1.6.1)
    tcp dport 80 accept
    ```
    inside `chain input`, gated on `ENABLE_TLS=true`. When TLS is disabled, the conf.d ACME listener is removed AND the firewall rule is omitted — `:80` returns to its v1.5/v1.6.0 closed state.

- **`_loxprox_acme_issue` now reports the correct exit code on failure.** v1.6.0's `if ! cmd; then rc=$?; ...; fi` pattern always captured `rc=0` because, inside the `then` branch, `$?` is the result of the `!` operator (0 or 1), not the original command. Operators saw `acme.sh --issue failed (rc=0)` no matter what acme.sh actually returned. v1.6.1 captures rc OUTSIDE the conditional:
    ```bash
    local rc=0
    "$ACME_HOME/acme.sh" --issue … || rc=$?
    case "$rc" in
        0) ok "Cert issued for $TLS_DOMAIN." ;;
        2) info "Cert already valid; acme.sh skipped re-issue." ;;
        *) error "acme.sh --issue failed (rc=$rc) …"; return 1 ;;
    esac
    ```
    The error message also got an ordered diagnostic checklist (nftables first, then router forward, then DNS, then rate limit) since the actual order of "most likely causes" on a fresh deploy is now nftables-first.

### Tests

- Unchanged from v1.6.0 (114 deploy-integration assertions, 22 pytest, 11 scanner). The new nftables rule is conditionally interpolated into the existing setup_firewall heredoc; no test rewrite needed.
- shellcheck `-S warning` clean.

### Operator action

**Existing v1.6.0 installs with TLS planned:** re-run `sudo bash deploy.sh` — `setup_firewall()` re-runs idempotently and the new `:80` rule lands in `/etc/nftables.conf`. The acme.sh state from any v1.6.0 attempt is preserved.

**Already running v1.6.0 with TLS enabled and working:** no action — v1.6.0 + manual `nft add` is functionally identical to v1.6.1. The deploy.sh fix matters next time you re-run `deploy.sh`.

## [1.6.0] — 2026-05-26

Three changes that landed together in one release window: per-host config separated from `deploy.sh` (closing the lock-yourself-out footgun that bit the maintainer's own production VM earlier in the same day), nginx site preservation across upgrades, and optional HTTPS via `acme.sh` HTTP-01.

> **Why one release for all three:** the config-separation work was originally cut as v1.5.0 / v1.5.1 — back-to-back releases hours apart, the second one fixing a regex bug found by the live deploy of the first. Two big-version releases on the same day was sloppier than warranted; consolidating into v1.6.0 + retiring those tags is the cleaner record. The engineering history of "we tried a conf.d split for AppSec http-scope plumbing and reverted it in the same branch" is preserved below because future readers may want to know why we *don't* have it.

### Changed (breaking — requires one-time migration)

- **Per-host configuration moved to `/etc/loxprox/deploy.conf`** (mode 0640 root). `deploy.sh` no longer carries inline REQUIRED defaults. The tracked template `deploy.conf.example` lives at the repo root; `.gitignore` excludes the populated `deploy.conf` so an accidental copy into the repo never gets committed.
- **`deploy.sh` refuses to run if no config file is present and no live install is detected.** Fresh-VM operators who forget to copy the example get a clear error pointing to `deploy.conf.example` instead of a silently-broken deploy with upstream placeholders. The previous footgun — `LOXONE_IP="192.168.1.100"` shipped inline at line 47 of `deploy.sh`, requiring every operator to edit the script before running and keep that edited copy somewhere safe — bricked the maintainer's own production VM during the v1.4.0 deploy. No more reachable in v1.6.0.
- **Idempotent upgrades.** `git pull && sudo bash deploy.sh` now actually works the way the README has always claimed — no more re-editing the script every release.

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
  Writes the candidate to a temp file, prints it for review, asks for confirmation, then installs at `/etc/loxprox/deploy.conf` (with a `.bak-<timestamp>` of any prior file). Non-interactive mode (`LOXPROX_BOOTSTRAP_YES=1`) writes without prompting — used by the auto-fallback path when `deploy.sh` is run without a tty.

- **Auto-bootstrap fallback for non-interactive deploys.** If `deploy.sh` runs without a tty, no config exists, and a live install IS detected, it auto-runs `--bootstrap-config` (no prompt) and proceeds. Ansible / CI pipelines no longer need a two-step invocation.

### Changed — nginx config now resists hand-edits

- **`configure_nginx()` preserves `/etc/nginx/sites-available/loxone` if it already exists.** WebSocket location blocks, custom `proxy_set_header` lines, and other operator hand-edits no longer get nuked on every redeploy. Set `LOXPROX_FORCE_REGEN_NGINX=1` to override and regenerate from template. (The maintainer's own production site has had a hand-edited WebSocket block since 2026-05-09 — preserving it is the actual point of the change.)
- **AppSec map + log_format stay inline in the site file.** A `/etc/nginx/conf.d/loxprox-appsec.conf` split was attempted (and reverted in the same branch) because nginx rejects it: `auth_request_set $appsec_action $upstream_http_x_crowdsec_action` is what registers `$appsec_action` with nginx's variable subsystem, and that directive lives inside the location block. Any earlier reference to `$appsec_action` — including in an http-scope `if=` clause or another conf.d file — fails parse-time validation with `unknown "appsec_action" variable`. The map and `log_format appsec_evt` therefore stay where they were placed by the v1.4.0 surgical patch (same file as the `auth_request_set`). A leftover `/etc/nginx/conf.d/loxprox-appsec.conf` from any dev iteration is removed on every deploy.
- **nginx reloaded (`systemctl reload`) instead of restarted** when the config changes during a deploy. Restart kept connections open via SO_REUSEPORT but burned established `keepalive` to the Miniserver; reload is graceful. Falls back to restart if reload fails.

### Added — optional HTTPS on :1080 via `acme.sh` + HTTP-01

Off by default. Toggle is a `deploy.conf` edit + `sudo bash deploy.sh` re-run; the on→off path is just as clean as off→on. Cert files survive a disable so flipping back doesn't pay re-issuance time.

- **New `deploy.conf` keys** (all optional, sane defaults):
    - `ENABLE_TLS="false"` — master toggle.
    - `TLS_DOMAIN=""` — fully-qualified public hostname (e.g. `loxprox.example.com`). Required when `ENABLE_TLS=true`; refused with a clear error if missing or non-FQDN.
    - `TLS_EMAIL=""` — registered with the ACME provider.
    - `TLS_ACME_SERVER="letsencrypt"` — also accepts `letsencrypt_test` (staging), `zerossl`, `buypass`, `buypass_test`, `sslcom`, or a full directory URL.
    - `TLS_ACME_EXTRA=""` — passthrough to `acme.sh --issue` (e.g. `--keylength ec-256`).
- **`setup_tls()` orchestrator** in `deploy.sh`:
    - Installs `acme.sh ${ACMESH_VER}` from a **SHA256-pinned GitHub release tarball** — no `curl | bash`. The pin (`ACMESH_VER="3.1.3"`, `ACMESH_SHA256="efd12b…"`) lives at the top of the script; refresh procedure documented inline.
    - Writes `/etc/nginx/conf.d/loxprox-acme.conf` — a small `:80` `default_server` that serves only `/.well-known/acme-challenge/` from `/var/www/acme/` and 301s everything else to `https://$host:1080$request_uri`. The widened public surface is just the challenge directory.
    - Issues (or renews) the cert via `acme.sh --issue --webroot --server $TLS_ACME_SERVER`. `acme.sh`'s "cert still valid, skipped" exit code 2 is treated as success.
    - Installs the cert at `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (`0640 root`) with `--reloadcmd "systemctl reload nginx"` recorded for the renewal cron.
    - **Mutates the nginx site** between explicit markers (`# LOXPROX-TLS-BEGIN` / `# LOXPROX-TLS-END`) and swaps `listen 1080;` ↔ `listen 1080 ssl;`. This is the one deviation from the site-preservation rule above; operator hand-edits outside the marker block (WebSocket location, custom headers, etc.) are untouched. Strict regex on the listen line: anything other than the canonical `listen 1080;` is refused with a warning, never silently mutated.
    - **Auto-renewal cron is verified after every TLS-enabled deploy.** `acme.sh`'s `--install` creates the daily cron; `_loxprox_ensure_acme_cron` re-asserts it exists, restores it via `--install-cronjob` if missing, and logs the exact cron line + the manual-renewal recipe. No silent assumption that auto-renewal "just works."
    - awk (not sed) for both the enable and disable mutations — BSD sed (macOS) and GNU sed (Linux) disagree on `\n` expansion and `\+` support; awk handles it uniformly.
- **`sudo bash deploy.sh --renew-tls`** — manual force-renew (`acme.sh --renew … --force`).
- **`sudo bash deploy.sh --remove-tls`** — full nuke: site revert, conf.d listener removed, `acme.sh --uninstall`, `/etc/loxprox/tls/` deleted, cron cancelled. Operator action remaining: remove the `WAN:80 → gateway:80` router forward.

### Disable path (`ENABLE_TLS=false`)

- Strips the marker block from the site, reverts the listen line to plain `listen 1080;`, removes the ACME `:80` listener, cancels the per-domain renewal in `acme.sh`. Cert files at `/etc/loxprox/tls/` are kept — re-enable is fast.

### Tests

- 114 deploy-integration assertions (was 64). New cases cover:
    - `_loxprox_load_config` — sources from a fixture `deploy.conf`, verifies LOXONE_IP / GATEWAY_IP / SSH_ALLOWED_SUBNETS / ENABLE_APPSEC, returns 1 when the file is absent.
    - `_loxprox_detect_live_install` — true on populated mock root (`NGINX_SITE` exists), false on empty.
    - `_loxprox_extract_config_from_live_state` — extracts the seven critical values from fixture nginx + nftables + crowdsec files (whitespace-tolerant on the AppSec detection regex), returns 1 on empty state.
    - `configure_nginx` preservation — operator sentinel + WebSocket block survive a redeploy by default; `LOXPROX_FORCE_REGEN_NGINX=1` regenerates from template with map + log_format + conditional access_log inline.
    - `_loxprox_tls_validate_config` — refuses empty `TLS_DOMAIN`, refuses non-FQDN, accepts FQDN.
    - `_loxprox_site_enable_tls` + `_loxprox_site_disable_tls` round-trip: enable → markers + ssl listen + cert directives + HSTS header → disable → marker block stripped + listen reverted → enable again → identical output. Re-enable and re-disable are byte-identical no-ops (hash compared).
    - Refusal path: `listen [::]:1080;` (operator hand-edit) is detected and rejected without touching the site.
    - `_loxprox_write_acme_listener` writes the conf.d block with the right contents.
- pytest progressive-ban suite unchanged: 22/22.
- shellcheck `-S warning` clean.

### Operator action

**v1.4.0 → v1.6.0 upgrade (existing install):**

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

**Enable HTTPS (after the upgrade settles):**

```bash
# 1. Add a router forward: WAN:80 → gateway:80
# 2. Point public DNS at your WAN IP for TLS_DOMAIN
# 3. Edit /etc/loxprox/deploy.conf:
#      ENABLE_TLS="true"
#      TLS_DOMAIN="loxprox.example.com"
#      TLS_EMAIL="you@example.com"
sudo bash deploy.sh
```

**Toggle TLS off:** `ENABLE_TLS="false"` in `deploy.conf`, `sudo bash deploy.sh`. Cert kept, site reverted.

Full upgrade walkthrough: [`docs/UPGRADE-v1.4-to-v1.6.md`](docs/UPGRADE-v1.4-to-v1.6.md). TLS runbook: [`docs/TLS-SETUP.md`](docs/TLS-SETUP.md).

## [1.4.0] — 2026-05-26

> **The maintainer's production VM was updated on 2026-05-26 at 18:22 CEST via surgical patches**, not a full `deploy.sh` re-run. Reason: the production VM's originally-deployed `deploy.sh` was edited inline with production-specific values (Miniserver IP, gateway IP, SSH-allowed subnets) and that edited copy was never persisted — running the repo's `deploy.sh` as-is would have rewritten nftables with the upstream placeholder subnets and locked out the LAN. Pre-deploy backup at `/root/loxprox-backups/v1.4.0-pre-20260526-182129/`. One LOW finding (`/tmp` mount hardening) was skipped because `tmp.mount` is not present on this Debian 12 VM — recorded in `phase4-monitoring.md` as deferred work. Specific IPs/hostname omitted from this entry by v1.6.0 retroactive scrub.

### Security (skills-audit follow-up — `audits/2026-05-23-skills-audit.md`)

- **HIGH — SSH daemon now hardened by `deploy.sh`.** New `setup_ssh_hardening()` writes `/etc/ssh/sshd_config.d/99-loxprox.conf` with the CIS Debian 12 §5.2 settings: `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, `MaxAuthTries 4`, `LogLevel VERBOSE`, `ClientAliveInterval 300`, agent/X11/TCP-forward all off. nftables already drops `:22` from anything outside `SSH_ALLOWED_SUBNETS`, so this finding only ever mattered against a compromised LAN host trying to brute-force the gateway from inside the perimeter — but stock Debian shipped `PasswordAuthentication yes`, leaving that window open. Closed now. Verify from a second terminal before logging out.

- **MED — auditd persistence-vector coverage.** `setup_auditd()` now also watches `/etc/ld.so.preload` + `ld.so.conf{,.d/}` (T1574.006 LD_PRELOAD hijack), `/etc/systemd/system/` + `/lib/systemd/system/` + `/usr/lib/systemd/system/` (T1543.002 unit drops), `/etc/profile{,.d/}` + `/etc/bash.bashrc` + `/root/.bashrc` + `.bash_profile` + `.profile` (T1546.004 shell init), `/root/.ssh/` plus any `/home/<user>/.ssh/` for UID≥1000 (T1098.004 SSH backdoor keys), and the four periodic cron dirs + `/etc/anacrontab` (T1053.003).

- **MED — progressive-ban no longer inflates offense count from CAPI/AppSec.** `progressive-ban.py` was building the per-IP offense counter from every decision in `cscli decisions list -a` regardless of `origin`. An IP that appeared once on the CAPI community blocklist plus once on a local cscli ban was treated as a 2nd-offense local repeat → instant escalation to 24h, defeating the intended "punish proven-local repeats" policy. Counter is now filtered to `origin == "cscli"` only. Regression test `test_capi_history_does_not_inflate_local_offense_count` added.

- **MED — AppSec detections actually get written to disk.** `gateway-monitor.sh:check_appsec_detections()` had been tailing `/var/log/nginx/appsec-detections.log` since v1.x, but nothing ever wrote that file — CrowdSec AppSec returns decisions to nginx via `auth_request`, and nginx was not logging the body. `configure_nginx()` now emits a `map $appsec_action $appsec_blocked` + `log_format appsec_evt` (http scope, gated on `ENABLE_APPSEC=true`) and a conditional `access_log /var/log/nginx/appsec-detections.log appsec_evt if=$appsec_blocked` so blocked requests get a parseable per-IP audit trail.

- **LOW — `/tmp` TOCTOU surface closed in monitoring scripts.** `gateway-backup.sh` previously used a predictable `/tmp/${BACKUP_NAME}` work dir; replaced with `mktemp -d` + `trap rm -rf EXIT`. `discord-alert.sh` circuit-breaker state moved from `/tmp/loxprox-discord-cb` to `${LOXPROX_STATE_DIR:-/var/lib/loxprox}/discord-cb` (0750 root). Closes symlink-race pre-staging from a hostile non-root LAN host.

- **LOW — `/tmp` mounted nosuid,nodev,noexec (CIS §1.1.2).** New `setup_tmp_mount()` writes a `tmp.mount.d` drop-in with `mode=1777,strictatime,nosuid,nodev,noexec` and enables `tmp.mount`. Warns and continues on systems without a `tmp.mount` unit (manual `/etc/fstab` then required).

### Added — SSH bootstrap flow (chicken-and-egg solved)

`setup_ssh_hardening()` now **detects whether any `authorized_keys` is present** (root + UID≥1000 users) before disabling password auth. The previous implementation would have bricked any first-time deploy run over a password-only SSH session.

- **Interactive deploy (tty):** prints a colored "no keys found — would lock you out" warning and shows a 4-option menu:
    - `[P]` paste your public key — round-trip echoed back with fingerprint, requires explicit `y` confirmation, written with `install -d -m 0700` / `chmod 0600`. Validated by prefix (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-*`, `sk-*`) and `ssh-keygen -l -f` round-trip. Private-key paste rejected.
    - `[H]` show help — exact `ssh-keygen -t ed25519` + `cat ~/.ssh/id_ed25519.pub` invocations for macOS/Linux/Windows, plus Google search terms.
    - `[K]` keep password auth, loud login banner until fixed.
    - `[A]` abort deploy entirely.
- **Non-interactive deploy (no tty):** falls back automatically to `[K]` mode so an Ansible / unattended run never bricks the box.
- **Soft mode (`[K]` or no-tty)** ships a different sshd drop-in that keeps `PasswordAuthentication yes` but still sets `MaxAuthTries 4`, `LogLevel VERBOSE`, `PubkeyAuthentication yes` first, no X11/agent/TCP forwarding, and installs `/etc/update-motd.d/99-loxprox-ssh-warn` — a red banner that fires on every login until `/var/lib/loxprox/ssh-keys-missing` is removed.
- **`sudo bash deploy.sh --finalize-ssh`** — new re-entry point that re-runs only `setup_ssh_hardening()`. Use after `ssh-copy-id root@<gateway>` to swap the soft drop-in for the hard one and remove the MOTD nag.
- **Private keys are never generated on the server.** The flow only accepts paste of an already-existing public key — the appliance-ships-with-default-key antipattern is explicitly avoided.

### Changed (carried over from previously-unreleased work)

- **Supported substrate narrowed to VM-only.** `deploy.sh` now refuses to run inside a container (LXC / systemd-nspawn) unless `ALLOW_LXC=1` is set explicitly. Background: several documented defenses silently fail or no-op when applied from inside an unprivileged Proxmox LXC because they touch host-kernel state the container cannot reach — most importantly the `kernel.unprivileged_userns_clone = 0` Fragnesia (CVE-2026-46300) mitigation added in v1.3.4, which returns `EPERM` from inside a container and does not take effect. Also affected: `kernel.dmesg_restrict` / `kptr_restrict` / `randomize_va_space`, `fs.protected_*`, auditd rule loading (one audit consumer per kernel, owned by the host), AppArmor profile enforcement (`aa-enforce` loads into the host's AppArmor subsystem), and nftables table creation in unprivileged LXC. Prior behaviour was a `warn` and continue — the script's `|| warn` swallow on the sysctl reload meant the deploy looked green while the actual posture was degraded. The new behaviour aborts with an explicit explanation of which defenses would no-op. Operators who knowingly accept the reduced posture can opt in with `ALLOW_LXC=1 sudo ./deploy.sh`; the CIS Debian 12 and OWASP IoT Top 10 posture claims do not apply in that configuration. Docs updated: `README.md`, `README.en.md`, `CONFIGURATION-GUIDE.md`, `phase3-cutover.md`, `phase4-monitoring.md`, `DOCUMENTATION.md`.

- **Minimum hardware requirements raised: 1 GB RAM / 1 vCPU minimum (was 512 MB / 1 core); 2 GB RAM / 2 vCPU recommended.** The previous 512 MB minimum was fiction — the reference VM sits at ~850 MB RSS under normal operation (Debian 12 base ~150 MB + stack idle 100–150 MB + page cache + slack). 512 MB invites OOM under any non-trivial probe. The 2 vCPU / 2 GB recommendation reflects measured behavior under attack: CrowdSec leaky-bucket memory scales linearly with distinct active attacker IPs (256 IPs ≈ 150 MB, 15,000 IPs ≈ 1.2–1.5 GB per upstream's [own benchmark](https://www.crowdsec.net/blog/how-to-process-billions-daily-events-with-crowdsec)), and the AppSec WAF with the Virtual Patching ruleset adds ~5 ms / ~50 millicores per request ([CrowdSec AppSec benchmark](https://docs.crowdsec.net/docs/appsec/benchmark/)). On a single vCPU the first 30–60 seconds of a wide-cardinality scan — before the bouncer propagates decisions to nftables — head-of-line-blocks legitimate users behind AppSec inspection of attacker requests. A second vCPU gives the kernel scheduler room to keep `nginx` responsive while AppSec catches up. 1 vCPU / 1 GB remains viable for steady-state home-automation traffic; the recommended sizing is attack-time headroom. Docs updated: `README.md`, `README.en.md`, `ABOUT.md`, `deploy.sh` header comment.

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
