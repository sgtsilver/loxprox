# LoxProx Skills-Based Audit — 2026-05-23 (post-v1.3.3)

## Scope

Baseline: v1.3.3 (2026-05-21, netlink batch GeoIP loader). Audit is repo-only;
no SSH to the production VM.

Skills applied (12, all loaded from `/Users/paul/Library/Mobile Documents/com~apple~CloudDocs/Projects/skills/Anthropic-Cybersecurity-Skills/skills/`):

1. `implementing-cloud-waf-rules`
2. `detecting-sql-injection-via-waf-logs`
3. `performing-web-application-firewall-bypass`
4. `hardening-linux-endpoint-with-cis-benchmark`
5. `performing-iot-security-assessment`
6. `configuring-tls-1-3-for-secure-communications`
7. `performing-ssl-tls-security-assessment`
8. `detecting-port-scanning-with-fail2ban`
9. `analyzing-tls-certificate-transparency-logs`
10. `auditing-tls-certificate-transparency-logs`
11. `implementing-file-integrity-monitoring-with-aide`
12. `analyzing-persistence-mechanisms-in-linux`
13. `performing-linux-log-forensics-investigation`

Files read:
- `/Users/paul/projects/loxone-security-gateway/deploy.sh` (1374 lines)
- `/Users/paul/projects/loxone-security-gateway/progressive-ban.py` (209 lines)
- `/Users/paul/projects/loxone-security-gateway/security-monitoring/geoip-block.sh`
- `/Users/paul/projects/loxone-security-gateway/security-monitoring/gateway-monitor.sh`
- `/Users/paul/projects/loxone-security-gateway/security-monitoring/gateway-backup.sh`
- `/Users/paul/projects/loxone-security-gateway/security-monitoring/discord-alert.sh`
- `/Users/paul/projects/loxone-security-gateway/README.md`, `CONTEXT.md`
- `/Users/paul/projects/knowledge-wiki/wiki/loxprox.md` (full version history)

Architecture note: README explicitly disclaims TLS termination ("Keine
HTTPS/TLS-Unterstützung"). nginx listens on plain HTTP `:1080`. TLS
termination is deferred to the v2.0+ Relay VPS (`CONTEXT.md` line 16). The
wiki summary calling the gateway a "TLS terminator" is **wrong for v1.x**.
See OUT-OF-SCOPE section.

## Findings

### [HIGH] No SSH daemon hardening in deploy.sh (skill: hardening-linux-endpoint-with-cis-benchmark)

- **Where:** `/Users/paul/projects/loxone-security-gateway/deploy.sh` — no `sshd_config` write block exists anywhere in the 1374-line script. Only `auditd` watches the file (line 933).
- **What:** `deploy.sh` ships Debian 12 stock `sshd_config`. Stock Debian 12 ships with `PermitRootLogin prohibit-password`, `PasswordAuthentication yes`, no `MaxAuthTries` override, no `ClientAliveInterval`, no `LogLevel VERBOSE`.
- **Gap:** CIS Debian 12 §5.2 (and the `hardening-linux-endpoint-with-cis-benchmark` SKILL Step 3) require `PermitRootLogin no`, `PasswordAuthentication no`, `MaxAuthTries 4`, `LoginGraceTime 60`, `ClientAliveInterval 300`, `ClientAliveCountMax 3`, `LogLevel VERBOSE`. None are set. nftables restricts SSH source IPs to `SSH_ALLOWED_SUBNETS`, but a compromised host inside the LAN can still password-brute-force root over SSH because nothing on the box prevents it.
- **Fix:** Add a `setup_ssh_hardening()` function called from `main()` between `setup_nginx_hardening` and `install_crowdsec`:

        setup_ssh_hardening() {
            banner "SSH Daemon Hardening (CIS §5.2)"
            backup_file /etc/ssh/sshd_config
            local drop=/etc/ssh/sshd_config.d/99-loxprox.conf
            cat > "$drop" <<'EOF'
        # LoxProx — CIS §5.2 SSH hardening
        Protocol 2
        LogLevel VERBOSE
        MaxAuthTries 4
        PermitRootLogin no
        PermitEmptyPasswords no
        PasswordAuthentication no
        PubkeyAuthentication yes
        X11Forwarding no
        AllowTcpForwarding no
        AllowAgentForwarding no
        MaxStartups 10:30:60
        LoginGraceTime 60
        ClientAliveInterval 300
        ClientAliveCountMax 3
        Banner none
        EOF
            chmod 0644 "$drop"
            if sshd -t; then
                systemctl reload ssh
                ok "SSH hardened — re-test from a SECOND session before logging out."
            else
                error "sshd -t failed; reverting"
                rm -f "$drop"; return 1
            fi
        }

- **Why it matters:** The single biggest CIS gap in an otherwise A- baseline. Trivial to add, and the `loxone` deploy user already authenticates with a key.

### [MED] auditd persistence-watch gaps (skill: analyzing-persistence-mechanisms-in-linux)

- **Where:** `/Users/paul/projects/loxone-security-gateway/deploy.sh:925-948` (audit rules file).
- **What:** Watches `/etc/nginx/`, `/etc/crowdsec/`, `/etc/nftables.conf`, `/etc/ssh/sshd_config`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`, `/usr/bin/sudo`, `/bin/su`, `/etc/cron.d/`, `/var/spool/cron/`.
- **Gap:** `analyzing-persistence-mechanisms-in-linux` covers six MITRE techniques (T1053.003, T1543.002, T1574.006, T1546.004). Coverage is missing for:
    - **T1574.006 LD_PRELOAD** — `/etc/ld.so.preload` not watched.
    - **T1543.002 systemd services** — `/etc/systemd/system/` not watched (the script itself writes here at lines 493, 696, 1042, 1054, but does not watch it). An attacker dropping a `.service` here gets reboot-persistence with zero audit trail.
    - **T1546.004 shell init** — `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `/root/.bashrc` not watched.
    - **T1098.004 SSH backdoor keys** — `/root/.ssh/authorized_keys` and `/home/*/.ssh/authorized_keys` not watched.
    - **T1053.003 cron** — `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/` not watched (only `/etc/cron.d/` and per-user spool are).
- **Fix:** Append to the heredoc at line 925:

        # Persistence: LD_PRELOAD hijacking (T1574.006)
        -w /etc/ld.so.preload    -p wa -k persistence_ld
        -w /etc/ld.so.conf       -p wa -k persistence_ld
        -w /etc/ld.so.conf.d/    -p wa -k persistence_ld

        # Persistence: systemd unit drops (T1543.002)
        -w /etc/systemd/system/  -p wa -k persistence_systemd
        -w /lib/systemd/system/  -p wa -k persistence_systemd
        -w /usr/lib/systemd/system/ -p wa -k persistence_systemd

        # Persistence: shell init (T1546.004)
        -w /etc/profile          -p wa -k persistence_shell
        -w /etc/profile.d/       -p wa -k persistence_shell
        -w /etc/bash.bashrc      -p wa -k persistence_shell
        -w /root/.bashrc         -p wa -k persistence_shell
        -w /root/.bash_profile   -p wa -k persistence_shell
        -w /root/.profile        -p wa -k persistence_shell

        # Persistence: SSH authorized_keys backdoor (T1098.004)
        -w /root/.ssh/           -p wa -k persistence_ssh
        # Add -w /home/loxone/.ssh/ -p wa -k persistence_ssh after first deploy

        # Persistence: scheduled task drops (T1053.003)
        -w /etc/cron.hourly/     -p wa -k persistence_cron
        -w /etc/cron.daily/      -p wa -k persistence_cron
        -w /etc/cron.weekly/     -p wa -k persistence_cron
        -w /etc/cron.monthly/    -p wa -k persistence_cron
        -w /etc/anacrontab       -p wa -k persistence_cron

- **Why it matters:** Without these watches, the most common Linux post-exploit persistence vectors leave zero forensic trail in the box's own audit log — the very log the wiki cites as a defense layer.

### [MED] progressive-ban.py inflates offense count with CAPI community decisions (skill: detecting-port-scanning-with-fail2ban / implementing-cloud-waf-rules)

- **Where:** `/Users/paul/projects/loxone-security-gateway/progressive-ban.py:123-133`.
- **What:**

        all_decisions = run_cscli(["decisions", "list", "-a"])
        ...
        for d in all_decisions:
            ip = d.get("value", "")
            if ip:
                ip_offenses[ip] += 1

  Counts every decision ever recorded for an IP, regardless of `origin`. CrowdSec stores CAPI community blocklist hits, AppSec triggers, and local `cscli` bans in the same decisions store.
- **Gap:** The escalation table (`24h → 7d → 30d`) is documented as "repeat offender" — meaning repeated local offenses against THIS gateway. As written, an IP listed once on the CAPI community blocklist plus three Crowdsec scenario triggers locally → `offenses=4` → instantly escalated to 30 days on its first local ban. Fail2ban's `recidive` jail, which is the closest standard analog, only counts the local ban log (`/var/log/fail2ban.log`).
- **Fix:** Filter by origin when building the counter:

        # Count only local (cscli) bans as "offenses" for escalation. CAPI/AppSec
        # decisions reflect global reputation, not repeated local misbehavior.
        for d in all_decisions:
            ip = d.get("value", "")
            origin = d.get("origin", "")
            if ip and origin == "cscli":
                ip_offenses[ip] += 1

  Add a regression test in `tests/test_progressive_ban.py` covering a fixture with mixed-origin history that should NOT escalate.
- **Why it matters:** The whole point of progressive bans is to punish proven-local repeat offenders. Community-reputation inflation defeats the policy AND makes the state file diverge from CrowdSec's own truth, which is what the v1.2.1 MED-007 fix was supposed to prevent.

### [MED] AppSec detections log is referenced but never written (skill: detecting-sql-injection-via-waf-logs)

- **Where:** Referenced at `deploy.sh:965` (logrotate target) and `gateway-monitor.sh:142` (parser source). The AppSec acquis at `deploy.sh:818-826` and nginx integration at `deploy.sh:661-679` configure no sink to that path.
- **What:** `check_appsec_detections()` in `gateway-monitor.sh` reads `/var/log/nginx/appsec-detections.log`, tracks file position in `/var/lib/loxprox/last_appsec_check`, and would alert on new entries. The file is never created by any component (CrowdSec AppSec writes to its own LAPI, not to a flat log file; nginx `auth_request` only sets `$appsec_action` and does not log the body).
- **Gap:** `detecting-sql-injection-via-waf-logs` SKILL is built on the assumption that the WAF emits a parseable audit log (ModSecurity audit log, AWS WAF JSON, Cloudflare events). Without that log, no offline SQLi analysis is possible after the fact, and the `check_appsec_detections` cooldown logic is effectively dead code. Currently the only post-hoc forensic for WAF events is `cscli alerts list | grep appsec`, which is ephemeral (rotates with CrowdSec internal DB).
- **Fix:** Either (a) emit a custom nginx log for blocked AppSec requests, or (b) tail CrowdSec's alert stream. Option (a) is the smaller change — add to the nginx site at `deploy.sh:570-572`:

        # AppSec-blocked requests get logged to a separate file for forensics
        map $appsec_action $appsec_blocked {
            default       0;
            "deny"        1;
            "ban"         1;
        }
        log_format appsec_evt '$time_iso8601 $remote_addr "$request" '
                              'appsec=$appsec_action ua="$http_user_agent" '
                              'xff="$http_x_forwarded_for"';
        access_log /var/log/nginx/appsec-detections.log appsec_evt if=$appsec_blocked;

  Then SQLi pattern hunting per the SKILL's regex set (`UNION SELECT`, `OR 1=1`, `SLEEP()`, `BENCHMARK()`) can run against that file. Validate by triggering `curl 'http://127.0.0.1:1080/?id=1%27%20OR%201=1--'` from outside `CROWDSEC_WHITELIST_IPS` and confirming an entry appears.
- **Why it matters:** A WAF that does not log its blocks is invisible to both incident response and tuning. The current setup blocks, but you cannot reconstruct what was blocked or build a per-attacker timeline.

### [LOW] gateway-backup.sh and discord-alert.sh use `/tmp` without TOCTOU protection (skill: hardening-linux-endpoint-with-cis-benchmark / performing-linux-log-forensics-investigation)

- **Where:**
    - `/Users/paul/projects/loxone-security-gateway/security-monitoring/gateway-backup.sh:15` — `WORK_DIR="/tmp/${BACKUP_NAME}"`
    - `/Users/paul/projects/loxone-security-gateway/security-monitoring/discord-alert.sh:73-78` — `CB_DIR="/tmp/loxprox-discord-cb"`
- **What:** Both scripts run as root, use predictable `/tmp` paths, and rely on `mkdir -p` (which silently uses an existing path).
- **Gap:** CIS §1.1.2 requires `/tmp` mounted `nodev,nosuid,noexec` (the deploy does not configure this — see also next finding) AND scripts running as root should not use shared, predictable `/tmp` paths. Today the gateway has no non-root interactive users so the attack surface is theoretical, but the `network-watchdog.sh` reboot path runs the same scripts after a partial network failure, exactly the window where a compromised LAN host could pre-stage symlinks at the predictable paths.
- **Fix:**

        # gateway-backup.sh line 15-16
        WORK_DIR=$(mktemp -d -t "loxprox-backup-XXXXXX")
        trap 'rm -rf "$WORK_DIR"' EXIT

  And for `discord-alert.sh`, move the circuit-breaker state under the existing root-owned dir:

        # discord-alert.sh — replace /tmp with /var/lib
        CB_DIR="${LOXPROX_STATE_DIR:-/var/lib/loxprox}/discord-cb"

  `deploy.sh:setup_alerting()` already creates `/var/lib/loxprox` with mode 0750.
- **Why it matters:** Future-proofing. The wiki repeatedly says LoxProx should remain hardened against a hostile LAN, not only a hostile WAN. Symlink races in `/tmp` are exactly the CIS hardening class that catches this.

### [LOW] /tmp not mounted with nodev,nosuid,noexec (skill: hardening-linux-endpoint-with-cis-benchmark)

- **Where:** `/Users/paul/projects/loxone-security-gateway/deploy.sh` — no `setup_filesystem_hardening` or fstab modification anywhere.
- **What:** Stock Debian 12 mounts `/tmp` as part of root filesystem with default options (or as a `tmpfs` via `systemd` with default mount options).
- **Gap:** CIS §1.1.2-1.1.5 (and the `hardening-linux-endpoint-with-cis-benchmark` SKILL Step 1) require `tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0`. The repo's independent A- validation called out `kernel.yama.ptrace_scope` and `fs.suid_dumpable` (fixed in v1.1.0) but missed the filesystem-level `noexec` hardening which is in the same CIS section.
- **Fix:** Add to `apply_sysctls` epilogue, or as a new short function:

        setup_tmp_mount() {
            banner "Filesystem hardening (CIS §1.1.2)"
            if systemctl cat tmp.mount >/dev/null 2>&1; then
                mkdir -p /etc/systemd/system/tmp.mount.d
                cat > /etc/systemd/system/tmp.mount.d/loxprox.conf <<'EOF'
        [Mount]
        Options=mode=1777,strictatime,nosuid,nodev,noexec
        EOF
                systemctl daemon-reload
                systemctl unmask tmp.mount
                systemctl enable --now tmp.mount
                ok "/tmp hardened: nosuid,nodev,noexec"
            else
                warn "tmp.mount unit not present — skipping (manual /etc/fstab needed)"
            fi
        }

- **Why it matters:** Together with the `/tmp` TOCTOU finding above this closes the cluster of CIS §1.1 residuals not covered by the v1.1.0 sweep.

### [LOW] CrowdSec firewall bouncer rate-limiting / scanning detection not explicitly tuned (skill: detecting-port-scanning-with-fail2ban)

- **Where:** `/Users/paul/projects/loxone-security-gateway/deploy.sh:837-841` (CrowdSec collections list).
- **What:** Installs `crowdsecurity/base-http-scenarios` and `crowdsecurity/http-cve`, plus AppSec. Has no equivalent of the `recidive` / `nmap-scan` / `portscan` jails from the `detecting-port-scanning-with-fail2ban` SKILL.
- **Gap:** Fail2ban-style port-scan detection (kernel `--recent --hitcount` rule streaming into a custom filter) is NOT covered by CrowdSec's stock nginx/sshd collections. CrowdSec only sees what nginx + auth.log surface; a slow TCP fan-scan against port 1080 itself never makes the access log because nginx never accepts beyond the listen socket. Port-scan visibility is therefore zero.
- **Fix:** Two-line addition to the nftables `input` chain at `deploy.sh:454-480` to feed a `recent`-style limit set into `meta nftrace` for CrowdSec — OR install the upstream collection that does this:

        cscli collections install crowdsecurity/iptables --error || true

  And/or add an nftables counter-based scan detector before the SSH rule:

        # Inside chain input, before `tcp dport 22 ip saddr ...`
        tcp flags syn tcp dport != { 22, 1080 } limit rate over 10/minute log prefix "portscan: " drop

  Then add a CrowdSec parser at `/etc/crowdsec/parsers/s00-raw/loxprox-portscan.yaml` matching `^.*portscan: ` on `/var/log/kern.log`. Lower priority than the AppSec gap; document in `phase4-monitoring.md` rather than the README.
- **Why it matters:** A scanner that probes `:22` from a non-whitelisted IP gets dropped by nftables silently. There is no offender count, no escalation. The CrowdSec model assumes attackers will rattle the application; LoxProx's threat model includes attackers who pre-fingerprint before touching it.

### [INFO] No CT-log monitoring — out-of-scope by design (skill: analyzing-tls-certificate-transparency-logs, auditing-tls-certificate-transparency-logs)

- **What:** No `crt.sh` polling, no `certspotter`, no CAA records.
- **Gap:** Both CT-log skills assume the system owns one or more public DNS names with public TLS certificates. LoxProx v1.x has no public DNS name and no TLS termination — port 1080 is reached via raw IP through a router port-forward. There is therefore no certificate to monitor in any CT log.
- **Status:** **Genuinely out of scope** for v1.x. Becomes in-scope the moment the v2.0+ Relay VPS is set up (the Relay does terminate TLS on a public name per `CONTEXT.md:16`). At that point: deploy a `certspotter` agent or a 15-min crt.sh poller for the chosen public name, with CAA pinned to the Relay's chosen CA.
- **Why it matters:** Avoid re-flagging in future audits. When Relay-v2.0 lands, the `auditing-tls-certificate-transparency-logs` checklist becomes mandatory for it.

### [INFO] No AIDE — defensible omission, but document the tradeoff (skill: implementing-file-integrity-monitoring-with-aide)

- **What:** No AIDE, no `aide.conf`, no baseline DB, no cron entry.
- **Gap:** The `implementing-file-integrity-monitoring-with-aide` SKILL recommends AIDE as the standard host-FIM for Linux endpoints. LoxProx relies entirely on auditd file watches for change visibility.
- **Status:** auditd watches detect changes in real time as they happen (better latency than AIDE's daily cron); AIDE detects offline tampering (rootkit, live-CD modification of disk while VM is off) — a class auditd CANNOT see. On a single-VM Proxmox guest with 512 MB RAM the cost-benefit is real: AIDE's nightly `aide --check` of `/etc + /bin + /sbin + /usr/bin + /boot` peaks around 200 MB RSS and 5-10 minutes wall time on this hardware class. Both numbers exceed the watchdog's tolerance window.
- **Recommendation (not a fix):** If added, pin AIDE to a low-RSS weekly schedule, exclude `/var` and `/proc`, and have the cron line emit only the diff via `discord-alert.sh`. Example one-shot for `setup_aide()`:

        apt-get install -y aide aide-common
        # Trim default config — Debian's ships ~150 rules; we need ~20.
        cat > /etc/aide/aide.conf.d/99-loxprox.conf <<'EOF'
        /etc           NORMAL
        /bin           NORMAL
        /sbin          NORMAL
        /usr/bin       NORMAL
        /usr/sbin      NORMAL
        /boot          NORMAL
        /opt/loxprox   NORMAL
        !/etc/mtab
        !/etc/adjtime
        !/etc/aide/aide.db
        !/var/lib/loxprox
        EOF
        aideinit -y -f
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        # Weekly Sunday 04:00 — pairs with daily backup at 02:00 and geoip at 03:00
        echo "0 4 * * 0 root /usr/bin/aide.wrapper --check 2>&1 | /opt/loxprox/aide-to-discord.sh" \
            > /etc/cron.d/loxprox-aide

  Whether to do this is a project-level decision, not a finding. Note it in the wiki gap log.
- **Why it matters:** Future audits will keep raising this. Settling the question once and writing the rationale into `wiki/loxprox.md` ends the loop.

### [INFO] IoT-assessment skill applies to the Miniserver itself, not the gateway (skill: performing-iot-security-assessment)

- **What:** Skill covers UART/JTAG/firmware extraction of embedded devices.
- **Status:** Loxone Gen 1 is the IoT device behind LoxProx, not LoxProx itself. The gateway is a hardened Debian VM (the recommended compensating control, per the SKILL's "Pitfalls" section: "Deploy on an isolated VLAN" — which is what LoxProx is). No findings against LoxProx code from this skill.
- **Why it matters:** Recording the disposition so future audits don't waste a cycle on it. If the user ever wants the Miniserver itself assessed (firmware dump, UART probing on the physical Gen 1 box), that is a separate engagement with physical access required, not a deploy.sh review.

### [INFO] WAF-bypass red-team skill — testable post-deploy, not pre-deploy (skill: performing-web-application-firewall-bypass)

- **What:** Skill is a red-team workflow against an already-running WAF (wafw00f, SQLmap tamper scripts, JSON/HPP bypass, encoding chains).
- **Status:** Cannot exercise it from the repo. Once the AppSec-detections log gap (MED above) is fixed and the VM is reachable, the natural next step is to run the SKILL's Step 2-5 payload set against `https://<gateway>:1080/` while monitoring `/var/log/nginx/appsec-detections.log` and `cscli alerts list`. The aim is to confirm AppSec's `crowdsecurity/virtual-patching` collection actually catches:
    1. URL-encoded SQLi (Step 2)
    2. JSON-wrapped SQLi (Step 4)
    3. `<svg/onload=alert(1)>` and event-handler XSS (Step 6)
    4. HTTP method overrides PUT/PATCH (Step 3)
- **Why it matters:** Without this validation, the "AppSec WAF active" status in the README is a configuration assertion, not a tested capability.

## Already-covered (no action)

- **`hardening-linux-endpoint-with-cis-benchmark` — sysctl block.** `deploy.sh:apply_sysctls()` (lines 372-423) covers the network and kernel sysctl set from the SKILL's Step 2 with one notable addition (`kernel.unprivileged_userns_clone=0` is stricter than CIS default). `ptrace_scope=1` and `suid_dumpable=0` already fixed in v1.1.0.
- **`hardening-linux-endpoint-with-cis-benchmark` — unattended upgrades.** `setup_unattended_upgrades()` (lines 885-914) covers CIS auto-patching and security updates with kernel-reboot scheduling.
- **`hardening-linux-endpoint-with-cis-benchmark` — auditd installed and enabled.** `setup_auditd()` lines 920-953 (note persistence gaps separately above).
- **`hardening-linux-endpoint-with-cis-benchmark` — host firewall.** nftables default-drop + LAN-restricted SSH at `deploy.sh:setup_firewall()` (lines 429-520) is stricter than the SKILL's UFW example.
- **`implementing-cloud-waf-rules` — managed rules.** `crowdsecurity/virtual-patching` + `http-cve` + `base-http-scenarios` correspond directly to the SKILL's Step 1 managed-rules pattern (AWS Managed Common/SQLi/KnownBad). Whitelisting at `deploy.sh:852-871` matches the SKILL's "ignore trusted IPs" advice.
- **`implementing-cloud-waf-rules` — rate limiting.** nginx `limit_req` + `limit_conn` at `deploy.sh:559-601` is the on-prem analog of the SKILL's `RateBasedStatement` example. AppSec `monitor` → `enforce` mode toggle (deploy.sh line 103) is exactly the SKILL's Count→Block migration pattern.
- **`detecting-port-scanning-with-fail2ban` — SSH brute-force.** Covered by CrowdSec `crowdsecurity/sshd` collection + the firewall bouncer. The fail2ban-specific syntax is irrelevant; CrowdSec provides the same maxretry→ban primitive with collaborative blocklists on top.
- **`detecting-port-scanning-with-fail2ban` — HTTP scanning.** `crowdsecurity/base-http-scenarios` catches the 404-storm pattern for `/wp-admin`, `/phpmyadmin`, `/.env` that the SKILL's `http-scan.conf` filter targets.
- **`detecting-port-scanning-with-fail2ban` — ignore-IP / whitelist.** `CROWDSEC_WHITELIST_IPS` (deploy.sh:113-118) matches `ignoreip`.
- **`performing-linux-log-forensics-investigation` — log sources present.** auth.log (sshd via syslog), syslog, kern.log, audit.log, /var/log/nginx/*, journalctl — all standard Debian 12 locations, all readable by the audit pipeline.
- **`performing-linux-log-forensics-investigation` — log retention.** `setup_logrotate()` covers nginx; auditd retention defaults to 8 × 8MB = 64MB which is reasonable for the 5 GB disk.
- **`analyzing-persistence-mechanisms-in-linux` — basic auth watches.** `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/cron.d/`, `/var/spool/cron/`, `/usr/bin/sudo`, `/bin/su` all already covered (gaps noted in MED above).
- **GPG supply-chain cross-verification** (`deploy.sh:verify_crowdsec_key`, lines 241-311). This is stronger than anything in the loaded skills; no skill in the audited set covers GPG quorum verification. Recorded here so it doesn't read like an omission.

## Out-of-scope / needs live access

- **`configuring-tls-1-3-for-secure-communications`, `performing-ssl-tls-security-assessment`** — LoxProx v1.x deliberately runs HTTP-only on `:1080` (README disclaims TLS support). These skills apply to the v2.0+ Relay VPS, not the Gateway. When the Relay lands, run `testssl.sh --severity HIGH <relay-host>:443` and validate: TLS 1.3 only, x25519 + secp256r1 key exchange, OCSP stapling, HSTS `max-age=63072000; includeSubDomains; preload`. The SKILL's cipher table (`TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`) is the exact target list.
- **`analyzing-tls-certificate-transparency-logs`, `auditing-tls-certificate-transparency-logs`** — Same. No public DNS name today. Becomes mandatory at Relay-v2.0 (see INFO finding above).
- **`performing-web-application-firewall-bypass`** — Needs the running VM and external network access. Test plan written into the INFO finding above.
- **`detecting-sql-injection-via-waf-logs` — runtime validation.** Once the appsec-detections.log gap (MED above) is fixed and one week of traffic has accumulated, run the SKILL's payload-pattern analyzer (`UNION SELECT`, `OR 1=1`, `SLEEP()`, `BENCHMARK()`) against `/var/log/nginx/appsec-detections.log` to baseline noise level and tune thresholds.
- **GeoIP set size verification** — `geoip-block.sh` claims 22 061 → 11 031 merged CIDRs on the live VM (v1.3.3 release note). Cannot verify locally; requires SSH access to the production VM and `nft list set inet filter geoip_blocklist | wc -l`.
- **AppSec actually firing** — Cannot verify the `auth_request` → 127.0.0.1:7422 chain returns 403 on a malicious payload without the running VM. Curl test plan: `curl -i 'http://<gateway>:1080/?id=%27%20OR%201=1--'` from an IP not in `CROWDSEC_WHITELIST_IPS`, expect HTTP/1.1 403.
- **nftables real input policy** — `health_check()` parses `nft list chain inet filter input | grep policy`. Cannot snapshot remotely.
- **CrowdSec hub component versions actually deployed** — `cscli hub list` would tell. Deferred.
