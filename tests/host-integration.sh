#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — host integration checks (CI only — MUTATES THE HOST)
# ═══════════════════════════════════════════════════════════════════════════════
# Exercises the 2026-10 health-audit fixes against the real services they
# configure — cron, logrotate, journald, auditd, nginx-extras and AppArmor —
# which the portable suite (tests/run-tests.sh) can only mock. It writes to
# /etc, restarts services and loads AppArmor policy, so it is deliberately NOT
# named test_*.sh (run-tests.sh never picks it up) and refuses to run unless
# CI=true. CI runs each section on a throwaway runner or container:
#
#   sudo CI=true bash tests/host-integration.sh cron journald auditd   # systemd host
#   CI=true bash tests/host-integration.sh logrotate                   # Debian 12 container
#   sudo CI=true bash tests/host-integration.sh nginx-apparmor         # host with docker
#   sudo CI=true bash tests/host-integration.sh nginx-appsec           # host with docker
#   sudo CI=true bash tests/host-integration.sh crowdsec crowdsec-rotation  # host with CrowdSec
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
PASSED=0
FAILED=0
pass()    { echo "  ✓ $1"; PASSED=$((PASSED + 1)); }
fail()    { echo "  ✗ $1"; FAILED=$((FAILED + 1)); }
note()    { echo "    $1"; }
section() { echo ""; echo "━━━ $1 ━━━"; }

if [[ "${CI:-}" != "true" ]]; then
    echo "Refusing to run: this script rewrites /etc and restarts services. CI only (CI=true)." >&2
    exit 2
fi
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 2; }

# deploy.sh's own functions, with its log and backups kept out of the way.
export LOG_FILE BACKUP_DIR
LOG_FILE=$(mktemp /var/tmp/loxprox-host-test.XXXXXX)
BACKUP_DIR=$(mktemp -d /var/tmp/loxprox-host-backup.XXXXXX)
# shellcheck source=../deploy.sh
source "$REPO/deploy.sh"
set +e

# ── cron: the real Debian-family cron, not a model of it ─────────────────────

t_cron() {
    section "cron — real cron rejects 'MAILTO=', accepts 'MAILTO=\"\"', health check agrees"
    systemctl is-active --quiet cron || systemctl start cron

    # 1. Two probe files, identical but for the MAILTO line. Only the fixed
    #    one may ever run its job.
    local good=/etc/cron.d/loxprox-ci-good bad=/etc/cron.d/loxprox-ci-bad
    rm -f /run/loxprox-ci-good /run/loxprox-ci-bad
    printf '%s\n' 'SHELL=/bin/bash' 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' 'MAILTO=""' '' \
        '* * * * * root touch /run/loxprox-ci-good' > "$good"
    printf '%s\n' 'SHELL=/bin/bash' 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' 'MAILTO=' '' \
        '* * * * * root touch /run/loxprox-ci-bad' > "$bad"
    chmod 0644 "$good" "$bad"
    systemctl restart cron
    sleep 3

    local out
    if out=$(_loxprox_cron_journal_errors "$bad"); then
        pass "cron itself rejected the bare 'MAILTO=' file:"
        note "${out//$'\n'/$'\n'    }"
    else
        fail "cron logged no rejection for the bare 'MAILTO=' file (journalctl -u cron below)"
        journalctl -u cron -n 20 --no-pager -o cat | sed 's/^/    /'
    fi
    if _loxprox_cron_journal_errors "$good" >/dev/null; then
        fail "cron rejected the 'MAILTO=\"\"' file"
    else
        pass "cron logged no rejection for the 'MAILTO=\"\"' file"
    fi

    local i
    for i in $(seq 1 15); do
        [[ -f /run/loxprox-ci-good ]] && break
        sleep 5
    done
    [[ -f /run/loxprox-ci-good ]] && pass "job from the 'MAILTO=\"\"' file actually ran (within ${i}x5 s)" \
                                   || fail "job from the 'MAILTO=\"\"' file never ran"
    [[ ! -f /run/loxprox-ci-bad ]] && pass "job from the 'MAILTO=' file never ran (whole file ignored)" \
                                    || fail "job from the 'MAILTO=' file ran — cron accepted it?"
    rm -f "$good" "$bad" /run/loxprox-ci-good /run/loxprox-ci-bad

    # 2. deploy.sh's guard on the real /etc/cron.d/loxprox: pre-fix content →
    #    health check FAILS; deploy.sh's writer + reload → health check passes.
    rm -f "$LOXPROX_ALERT_CRON_FILE"
    printf '%s\n' '# LoxProx security automation (pre-fix header)' 'SHELL=/bin/bash' \
        'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin' 'MAILTO=' '' \
        '*/15 * * * * root /opt/loxprox/progressive-ban.py >> /var/log/loxprox-cron.log 2>&1' > "$LOXPROX_CRON_FILE"
    _loxprox_cron_reload
    sleep 3
    _loxprox_cron_journal_errors "$LOXPROX_CRON_FILE" >/dev/null \
        && pass "pre-fix /etc/cron.d/loxprox: rejection found in cron's journal" \
        || fail "pre-fix /etc/cron.d/loxprox: no rejection found in cron's journal"
    _loxprox_check_cron_files >/dev/null 2>&1 \
        && fail "health check PASSED a cron file cron rejected" \
        || pass "health check FAILS on the pre-fix cron file"

    sleep 1   # next write gets a later mtime second than the rejection above
    _loxprox_write_security_cron
    _loxprox_cron_reload
    sleep 3
    _loxprox_cron_journal_errors "$LOXPROX_CRON_FILE" >/dev/null \
        && fail "cron rejected deploy.sh's fixed /etc/cron.d/loxprox" \
        || pass "cron accepted deploy.sh's fixed /etc/cron.d/loxprox (no error since its mtime)"
    _loxprox_check_cron_files >/dev/null 2>&1 \
        && pass "health check passes on the fixed file — the earlier rejection is not held against it" \
        || fail "health check fails on the fixed file"
    rm -f "$LOXPROX_CRON_FILE"
    systemctl restart cron
}

# ── journald: the drop-in is what the running journald uses ──────────────────

t_journald() {
    section "journald — SystemMaxUse cap applied by the real journald"
    local t0 inv_before inv_after
    rm -f "$JOURNALD_DROPIN"
    sleep 1
    t0=$(date +%s)
    setup_journald >/dev/null 2>&1 && pass "setup_journald returns 0" || fail "setup_journald failed"
    systemctl is-active --quiet systemd-journald && pass "systemd-journald active after the restart" \
                                                 || fail "systemd-journald NOT active after the restart"
    systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -qx "SystemMaxUse=${JOURNALD_SYSTEM_MAX_USE}" \
        && pass "effective journald config carries SystemMaxUse=${JOURNALD_SYSTEM_MAX_USE}" \
        || fail "SystemMaxUse not in the effective journald config"
    sleep 2
    local usage
    usage=$(journalctl --since "@$t0" -o cat --no-pager 2>/dev/null | grep -E '^System Journal .* max ' | tail -1)
    if grep -qE 'max 300(\.0)?M' <<<"$usage"; then
        pass "journald reports the new ceiling: $usage"
    else
        fail "journald did not report a 300M ceiling (got: '${usage:-nothing}')"
    fi
    logger -t loxprox-ci "journald-still-logging-$t0"
    sleep 1
    journalctl -t loxprox-ci --since "@$t0" -o cat --no-pager | grep -q "journald-still-logging-$t0" \
        && pass "logging works after the restart" || fail "message logged after the restart not found"

    inv_before=$(systemctl show -p InvocationID --value systemd-journald)
    setup_journald >/dev/null 2>&1
    inv_after=$(systemctl show -p InvocationID --value systemd-journald)
    [[ -n "$inv_before" && "$inv_before" == "$inv_after" ]] && pass "unchanged drop-in → journald not restarted again" \
                                                            || fail "journald restarted although the drop-in was unchanged"
    rm -f "$JOURNALD_DROPIN"
    systemctl restart systemd-journald
}

# ── auditd: rules load into the kernel and fire ───────────────────────────────

t_auditd() {
    section "auditd — LoxProx watches loaded and firing"
    mkdir -p /etc/loxprox /opt/loxprox
    systemctl is-active --quiet auditd || systemctl start auditd
    setup_auditd >/dev/null 2>&1 && pass "setup_auditd returns 0" || fail "setup_auditd failed"
    local rules key
    rules=$(auditctl -l 2>&1)
    for key in loxprox_config apparmor_config loxprox_scripts; do
        if grep -qE -- "(-k |key=)${key}\$" <<<"$rules"; then
            pass "kernel accepted the watch: $(grep -E -- "(-k |key=)${key}\$" <<<"$rules" | head -1)"
        else
            fail "watch $key not loaded (auditctl -l below)"
            note "${rules//$'\n'/$'\n'    }"
        fi
    done
    note "auditctl -s: $(auditctl -s 2>&1 | tr '\n' ' ')"
    local probe
    for probe in /etc/loxprox/ci-audit-probe /opt/loxprox/ci-audit-probe /etc/apparmor.d/ci-audit-probe; do
        touch "$probe"; rm -f "$probe"
    done
    sleep 3
    local pair dir events serials log=/var/log/audit/audit.log
    for pair in loxprox_config:/etc/loxprox/ apparmor_config:/etc/apparmor.d/ loxprox_scripts:/opt/loxprox/; do
        key="${pair%%:*}"; dir="${pair#*:}"
        events=$(ausearch -if "$log" -k "$key" 2>&1)
        if grep -q "name=\"${dir}ci-audit-probe\"" <<<"$events"; then
            pass "write under $dir produced an audit event with key $key (ausearch -k $key)"
            continue
        fi
        # ausearch on some hosts returns nothing although the records are
        # there — match them directly: a SYSCALL record carrying the key, and
        # a PATH record of the same event naming the probe file.
        serials=$(grep -F "key=\"$key\"" "$log" | grep -oE 'audit\([0-9.]+:[0-9]+\)' | sort -u)
        if [[ -n "$serials" ]] \
            && grep -F -f <(printf '%s\n' "$serials") "$log" | grep -q "name=\"${dir}ci-audit-probe\""; then
            pass "write under $dir produced an audit event with key $key (raw audit.log; ausearch returned: $(tail -1 <<<"$events"))"
        else
            fail "no audit event for ${dir}ci-audit-probe under key $key"
            grep -F 'ci-audit-probe' "$log" | head -3 | cut -c1-300 | sed 's/^/      /'
        fi
    done
}

# ── panel jobs: a deploy started by the panel outlives the panel's unit ──────

# A stand-in panel: a transient service (PrivateTmp, like loxprox-gui.service)
# that loads the real gui/loxprox-gui.py JobRunner, starts an "apply" and
# idles. The test then stops that unit — exactly what deploy.sh's
# `systemctl restart loxprox-gui.service` does to the real panel mid-apply.
t_panel_job() {
    section "panel jobs — apply survives a stop of the panel's own unit (systemd-run)"
    command -v systemd-run >/dev/null || { fail "systemd-run missing"; return; }
    local base=/var/lib/loxprox-ci-jobs deploy=/usr/local/sbin/loxprox-ci-fake-deploy.sh
    local panel_py=/usr/local/sbin/loxprox-ci-panel.py marker=/tmp/loxprox-ci-job-saw-host-tmp
    rm -rf "$base" "$marker"
    mkdir -p "$base"
    cat > "$deploy" <<'EOF'
#!/bin/bash
echo "deploy: started"
echo "deploy: HOME=${HOME:-<unset>} umask=$(umask)"
sleep 6
echo "deploy: still alive after the panel unit was stopped"
touch /tmp/loxprox-ci-job-saw-host-tmp
exit 3
EOF
    chmod 0755 "$deploy"
    cat > "$panel_py" <<EOF
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("panel", "$REPO/gui/loxprox-gui.py")
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)
mode = sys.argv[1]
runner = panel.JobRunner(job_dir="$base/" + mode, systemd_run=None if mode == "systemd" else "")
print(runner.start("apply", ["bash", "$deploy"]), flush=True)
time.sleep(600)
EOF
    local mode
    for mode in systemd child; do
        systemctl stop "loxprox-ci-panel-$mode" 2>/dev/null
        systemd-run --quiet --unit "loxprox-ci-panel-$mode" --property=PrivateTmp=yes \
            /usr/bin/python3 "$panel_py" "$mode"
    done
    sleep 2
    systemctl stop loxprox-ci-panel-systemd loxprox-ci-panel-child   # = the panel restart
    sleep 8

    local summary
    summary=$(python3 - "$REPO/gui/loxprox-gui.py" "$base" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("panel", sys.argv[1])
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)
out = {}
for mode in ("systemd", "child"):
    r = panel.JobRunner(job_dir=f"{sys.argv[2]}/{mode}", systemd_run=None if mode == "systemd" else "")
    s = r.current_summary()
    out[mode] = {"summary": s, "log": r.log_tail(s["id"]) if s else None}
print(json.dumps(out))
PY
)
    note "$summary"
    local st log
    st=$(jq -r '.systemd.summary | "\(.status) \(.rc) \(.running)"' <<<"$summary")
    log=$(jq -r '.systemd.log' <<<"$summary")
    [[ "$st" == "degraded 3 false" ]] \
        && pass "systemd-run job finished with its real result after the panel unit stopped (status degraded, rc 3)" \
        || fail "systemd-run job state after the panel stop: $st"
    grep -q 'still alive after the panel unit was stopped' <<<"$log" \
        && pass "the deploy kept running past the panel stop (full log)" || fail "deploy log incomplete: $log"
    # 2026-10: the transient unit has no HOME of its own — acme.sh then used
    # /.acme.sh. The runner passes --setenv=HOME=/root and UMask=0022.
    grep -q 'deploy: HOME=/root umask=0022' <<<"$log" \
        && pass "the job ran with HOME=/root and umask 0022 (panel unit itself has no HOME)" \
        || fail "job environment: $(grep 'deploy: HOME' <<<"$log")"
    [[ -e "$marker" ]] && pass "the job wrote to the host /tmp, not the panel's PrivateTmp" \
                       || fail "job did not see the host /tmp"
    # Control — the pre-fix launch (a child process of the panel): killed with
    # the panel's cgroup, never finishes, no exit code.
    st=$(jq -r '.child.summary | "\(.status) \(.rc) \(.running)"' <<<"$summary")
    log=$(jq -r '.child.log' <<<"$summary")
    if [[ "$st" == "failed null false" ]] && ! grep -q 'still alive' <<<"$log"; then
        pass "control: a job launched as the panel's child dies with the panel unit (the reported bug)"
    else
        fail "control did not reproduce the kill: $st"
    fi
    rm -rf "$base" "$deploy" "$panel_py" "$marker"
}

# ── install dir owned by the SSH user (production since May) ────────────────

t_install_dir() {
    section "install dir — pre-existing /opt/loxprox owned by a login user, symlinked unit"
    local user=loxprox-ci-login dir="$LOXPROX_INSTALL_DIR" unit=loxprox-ci-probe.service
    id "$user" >/dev/null 2>&1 || useradd -m "$user"
    rm -rf "${dir:?}" "${SYSTEMD_UNIT_DIR:?}/${unit:?}"
    install -d -m 0755 -o "$user" -g "$user" "$dir"
    printf '[Unit]\nDescription=hand-copied\n' > "$dir/$unit"
    printf '#!/bin/bash\n' > "$dir/network-watchdog.sh"
    chown "$user:$user" "$dir/$unit" "$dir/network-watchdog.sh"
    ln -s "$dir/$unit" "$SYSTEMD_UNIT_DIR/$unit"     # the `systemctl link` shape

    local saved_sh="$LOXPROX_DEPLOY_SH"
    install_deploy_source >/dev/null 2>&1 \
        && fail "control: install_deploy_source accepted a dir owned by $user" \
        || pass "control: install_deploy_source refuses a dir owned by $user (the live failure)"
    LOXPROX_DEPLOY_SH="$saved_sh"

    _loxprox_secure_install_dir >/dev/null 2>&1 && pass "secure_install_dir returns 0" || fail "secure_install_dir failed"
    [[ "$(stat -c '%U:%G %a' "$dir")" == "root:root 755" ]] && pass "$dir → root:root 755" \
        || fail "$dir is $(stat -c '%U:%G %a' "$dir")"
    local strays
    strays=$(find "$dir" -xdev \( ! -user 0 -o ! -group 0 -o ! -type l -perm /022 \) -printf '%u %m %p\n')
    [[ -z "$strays" ]] && pass "nothing under $dir owned by $user or writable by others" || fail "left: $strays"

    sudo -u "$user" sh -c "echo pwned >> '$dir/$unit'" 2>/dev/null \
        && fail "$user can still write the unit target" || pass "$user can no longer write into $dir"

    install_deploy_source >/dev/null 2>&1 && pass "install_deploy_source succeeds afterwards" || fail "install_deploy_source still refuses"
    [[ "$(stat -c '%U:%G %a' "$LOXPROX_DEPLOY_DIR")" == "root:root 750" ]] && pass "$LOXPROX_DEPLOY_DIR → root:root 750" \
        || fail "$LOXPROX_DEPLOY_DIR is $(stat -c '%U:%G %a' "$LOXPROX_DEPLOY_DIR" 2>&1)"
    LOXPROX_DEPLOY_SH="$saved_sh"

    _loxprox_install_unit_file "$REPO/security-monitoring/network-watchdog.timer" "$unit" >/dev/null 2>&1
    [[ -f "$SYSTEMD_UNIT_DIR/$unit" && ! -L "$SYSTEMD_UNIT_DIR/$unit" ]] \
        && pass "symlinked unit replaced by a regular file" || fail "unit is still a symlink"
    [[ "$(stat -c '%U %a' "$SYSTEMD_UNIT_DIR/$unit")" == "root 644" ]] && pass "unit root 0644" \
        || fail "unit is $(stat -c '%U %a' "$SYSTEMD_UNIT_DIR/$unit")"
    grep -q 'hand-copied' "$dir/$unit" && pass "old link target not written through" || fail "link target overwritten"

    rm -rf "${dir:?}" "${SYSTEMD_UNIT_DIR:?}/${unit:?}"
    systemctl daemon-reload
}

# ── launch environment: systemd-run without HOME, umask 077 ──────────────────

t_launch_env() {
    section "launch env — deploy.sh under systemd-run (no HOME, UMask=0077)"
    local out probe=/run/loxprox-ci-mode-probe
    rm -rf "$probe"
    out=$(systemd-run --quiet --wait --pipe --collect --property=UMask=0077 \
        /bin/bash -c "printf 'launcher umask=%s HOME=%s\n' \"\$(umask)\" \"\${HOME:-<unset>}\"
                      source '$REPO/deploy.sh' >/dev/null 2>&1
                      printf 'deploy umask=%s HOME=%s\n' \"\$(umask)\" \"\$HOME\"
                      umask 077; _loxprox_mkdir_mode 0755 '$probe'" 2>&1)
    note "${out//$'\n'/ | }"
    grep -q 'launcher umask=0077 HOME=<unset>' <<<"$out" && pass "reproduced the launch: umask 0077, no HOME" \
        || fail "launcher environment not as expected"
    grep -q 'deploy umask=0022 HOME=/root' <<<"$out" && pass "deploy.sh normalises to umask 0022, HOME=/root" \
        || fail "deploy.sh environment not normalised"
    [[ "$(stat -c %a "$probe" 2>/dev/null)" == "755" ]] && pass "owned dir created 0755 even under umask 077" \
        || fail "probe dir mode $(stat -c %a "$probe" 2>&1)"
    rm -rf "$probe"
}

# ── panel stop: the real panel under systemd exits on SIGTERM ────────────────

t_panel_stop() {
    section "panel stop — real loxprox-gui.py under systemd, systemctl stop"
    local d=/var/lib/loxprox-ci-panel unit=loxprox-ci-gui port=18181
    rm -rf "$d"; mkdir -p "$d"
    printf 'ENABLE_GUI="true"\nGUI_PORT="%s"\n' "$port" > "$d/deploy.conf"
    systemctl stop "$unit" 2>/dev/null
    systemd-run --quiet --unit "$unit" --property=TimeoutStopSec=60 \
        --setenv=LOXPROX_DEPLOY_CONF="$d/deploy.conf" --setenv=LOXPROX_RUNTIME_CONF="$d/config.env" \
        --setenv=LOXPROX_STATE_DIR="$d/state" /usr/bin/python3 "$REPO/gui/loxprox-gui.py"
    local i
    for i in $(seq 1 30); do
        curl -s -o /dev/null "http://127.0.0.1:$port/" && break
        sleep 0.5
    done
    curl -s -o /dev/null "http://127.0.0.1:$port/" && pass "panel up on :$port" || { fail "panel did not start"; return; }
    local t0 t1 result
    t0=$(date +%s.%N)
    systemctl stop "$unit"
    t1=$(date +%s.%N)
    result=$(journalctl -u "$unit" -o cat --no-pager -q | grep -cE 'State .stop-sigterm. timed out|Killing process|SIGKILL' || true)
    awk -v a="$t0" -v b="$t1" 'BEGIN {exit !((b - a) < 5)}' \
        && pass "systemctl stop took $(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.1f", b - a}') s (was ~90 s + SIGKILL)" \
        || fail "systemctl stop took $(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.1f", b - a}') s"
    [[ "$result" == "0" ]] && pass "no stop timeout / SIGKILL in the unit's journal" || fail "stop escalated to SIGKILL"
    journalctl -u "$unit" -o cat --no-pager -q | grep -q 'LoxProx Panel stopped.' \
        && pass "panel logged a clean exit" || fail "no clean-exit line in the journal"
    rm -rf "$d"
}

# ── Debian 12's cron unit: restarting cron must not kill running jobs ────────

t_cron_unit() {
    section "cron.service (Debian 12 package) — restart keeps running jobs"
    local unit=/lib/systemd/system/cron.service
    [[ -f "$unit" ]] || { fail "$unit missing — install cron first"; return; }
    if grep -qx 'KillMode=process' "$unit"; then
        pass "$unit has KillMode=process — deploy.sh's 'systemctl restart cron' leaves running jobs alone"
    else
        fail "$unit has no KillMode=process: $(grep -E '^KillMode' "$unit" || echo 'default control-group')"
    fi
}

# ── logrotate: Debian 12's logrotate with the stock nginx stanza present ─────

t_logrotate() {
    section "logrotate — stock nginx stanza + LoxProx stanzas, real logrotate"
    [[ -f /etc/logrotate.d/nginx ]] || { fail "stock /etc/logrotate.d/nginx missing — install nginx first"; return; }
    grep -q '^/var/log/nginx/\*\.log' /etc/logrotate.d/nginx \
        && pass "stock nginx stanza present: $(head -1 /etc/logrotate.d/nginx)" \
        || fail "stock nginx stanza not in its stock form"

    local f
    mkdir -p /var/log/nginx
    for f in access error loxone-access loxone-error appsec-detections; do echo seed > "/var/log/nginx/$f.log"; done
    for f in monitor network-watchdog tunnel-watchdog gui cron deploy; do echo seed > "/var/log/loxprox-$f.log"; done

    # 1. Reproduce the 2026-08-30 collision: LoxProx's nginx stanza next to
    #    the untouched stock one.
    NGINX_STOCK_LOGROTATE=/nonexistent setup_logrotate >/dev/null 2>&1
    local out rc
    out=$(logrotate -d /etc/logrotate.conf 2>&1)
    if grep -q 'duplicate log entry' <<<"$out"; then
        pass "reproduced: $(grep -m1 'duplicate log entry' <<<"$out")"
    else
        fail "stock glob + loxone-nginx did NOT report a duplicate — the control proves nothing"
    fi

    # 2. deploy.sh's yield.
    setup_logrotate >/dev/null 2>&1
    note "stock stanza now: $(head -1 /etc/logrotate.d/nginx)"
    out=$(logrotate -d /etc/logrotate.conf 2>&1); rc=$?
    if grep -qiE '^error:|duplicate log entry' <<<"$out"; then
        fail "logrotate still reports errors: $(grep -iE '^error:|duplicate log entry' <<<"$out" | head -3 | tr '\n' ';')"
    else
        pass "logrotate -d /etc/logrotate.conf: no errors, no duplicate entries"
    fi
    [[ $rc -eq 0 ]] && pass "logrotate -d exits 0" || fail "logrotate -d exits $rc"
    for f in /var/log/loxprox-monitor.log /var/log/loxprox-network-watchdog.log /var/log/loxprox-gui.log \
             /var/log/nginx/error.log /var/log/nginx/appsec-detections.log; do
        grep -q "considering log $f" <<<"$out" && pass "considered for rotation: $f" || fail "never considered: $f"
    done

    # 3. copytruncate vs a writer that holds its fd open with O_APPEND
    #    (systemd's StandardOutput=append: for loxprox-gui.service).
    exec 7>>/var/log/loxprox-gui.log
    echo "before-rotation" >&7
    logrotate -f "$LOXPROX_LOGROTATE_CONF" >/dev/null 2>&1
    zcat /var/log/loxprox-gui.log.1.gz 2>/dev/null | grep -q before-rotation \
        && pass "rotated copy (.1.gz) holds the pre-rotation line" || fail "pre-rotation line not in loxprox-gui.log.1.gz"
    echo "after-rotation" >&7
    exec 7>&-
    [[ "$(cat /var/log/loxprox-gui.log)" == "after-rotation" ]] \
        && pass "open writer keeps logging into the live file, from offset 0 (no hole)" \
        || fail "live file after rotation: $(od -c /var/log/loxprox-gui.log | head -3 | tr '\n' ' ')"

    # 4. maxsize: an oversized log rotates on an ordinary (unforced) run,
    #    before the weekly interval — the 41 MB monitor log on day one.
    rm -f /var/log/loxprox-monitor.log.*
    head -c $((11 * 1024 * 1024)) /dev/zero | tr '\0' 'x' > /var/log/loxprox-monitor.log
    logrotate -s /var/tmp/loxprox-ci-logrotate.state "$LOXPROX_LOGROTATE_CONF" >/dev/null 2>&1
    [[ -f /var/log/loxprox-monitor.log.1.gz && ! -s /var/log/loxprox-monitor.log ]] \
        && pass "11 MB log rotated by maxsize on an unforced run" \
        || fail "11 MB log not rotated on an unforced run ($(ls -la /var/log/loxprox-monitor.log* | tr '\n' ' '))"
}

# ── nginx-extras under the AppArmor profile + proxied security headers ──────

CTR=loxprox-ci-nginx

# Runs INSIDE the Debian 12 container: generate the gateway's own site with
# deploy.sh (TLS, self-signed) in front of a Miniserver emulator that sends
# its own X-Frame-Options / X-XSS-Protection, like the real one.
t_nginx_container_setup() {
    systemctl() { true; }
    # shellcheck disable=SC2034  # consumed by deploy.sh's configure_nginx
    LOXONE_IP=127.0.0.1 LOXONE_PORT=8081 ENABLE_APPSEC=false TLS_DOMAIN=loxprox.test
    mkdir -p /etc/loxprox/tls /var/log/nginx
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=loxprox.test \
        -keyout /etc/loxprox/tls/privkey.pem -out /etc/loxprox/tls/fullchain.pem >/dev/null 2>&1
    cat > /etc/nginx/conf.d/ci-miniserver-emulator.conf <<'EMU'
server {
    listen 127.0.0.1:8081;
    location / {
        add_header X-Frame-Options "deny" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        return 200 "miniserver\n";
    }
}
EMU
    configure_nginx >/dev/null 2>&1 || { echo "configure_nginx failed"; nginx -t; exit 1; }
    _loxprox_site_enable_tls >/dev/null 2>&1 || { echo "TLS mutation failed"; exit 1; }
    nginx -t || exit 1
    printf 'ENABLE_TLS="true"\nENABLE_APPSEC="false"\nTLS_DOMAIN="loxprox.test"\n' > /etc/loxprox/deploy.conf
    echo "container ready: $(grep -c . "$NGINX_SITE") site lines, $(ls /etc/nginx/modules-enabled | wc -l) dynamic modules enabled"
}

# Runs INSIDE the container: test-gateway.sh's own proxy section.
t_nginx_container_test_proxy() {
    # shellcheck source=../test-gateway.sh
    source "$REPO/test-gateway.sh"
    # shellcheck disable=SC2034  # counters of the sourced test-gateway.sh
    TESTS_PASSED=0; TESTS_FAILED=0
    test_proxy
    echo "test_proxy: $TESTS_PASSED passed, $TESTS_FAILED failed"
    [[ $TESTS_FAILED -eq 0 ]]
}

# One nginx lifecycle under whatever profile is loaded: start (module init),
# reload, USR1 reopen, USR2 binary upgrade + QUIT of the old master, a TLS
# request through the proxy, stop. Echoes the master's confinement label.
ngx_lifecycle() {
    # Full path: the USR2 upgrade execve()s the master's argv[0] as given.
    docker exec "$CTR" sh -c '
        pkill -x nginx 2>/dev/null; sleep 1
        /usr/sbin/nginx || exit 10
        sleep 1
        echo "label: $(cat /proc/$(cat /run/nginx.pid)/attr/current)"
        nginx -s reload || exit 11; sleep 1
        kill -USR1 "$(cat /run/nginx.pid)" || exit 12; sleep 1
        kill -USR2 "$(cat /run/nginx.pid)" || exit 13; sleep 2
        [ -f /run/nginx.pid.oldbin ] || exit 14
        kill -QUIT "$(cat /run/nginx.pid.oldbin)" || exit 15; sleep 2
        [ ! -e /run/nginx.pid.oldbin ] || exit 16
        curl -fsk --resolve loxprox.test:1080:127.0.0.1 -o /dev/null https://loxprox.test:1080/jdev/cfg/api || exit 17
        nginx -s quit; sleep 1
        exit 0'
}

aa_events() {  # kernel AppArmor lines for the nginx profile since the last dmesg -C
    { dmesg 2>/dev/null; [[ -f /var/log/audit/audit.log ]] && cat /var/log/audit/audit.log; } \
        | grep 'apparmor=' | grep 'profile="/usr/sbin/nginx"' || true
}

aa_summary() {  # one line per distinct event: verdict, operation, object, masks
    local f
    while IFS= read -r line; do
        for f in apparmor operation name peer requested_mask denied_mask signal info; do
            [[ "$line" =~ $f=\"?([^\" ]*)\"? ]] && printf '%s=%s ' "$f" "${BASH_REMATCH[1]}"
        done
        echo
    done | sort | uniq -c | sort -rn | sed 's/^/      /'
}

t_nginx_apparmor() {
    section "nginx-extras (Debian 12) — proxied headers + AppArmor profile, complain and enforce"
    command -v docker >/dev/null || { fail "docker missing"; return; }
    command -v apparmor_parser >/dev/null || { fail "apparmor_parser missing"; return; }
    [[ -e /sys/kernel/security/apparmor/profiles ]] || { fail "AppArmor not enabled on this kernel"; return; }

    docker rm -f "$CTR" >/dev/null 2>&1
    docker run -d --name "$CTR" --security-opt apparmor=unconfined -e CI=true \
        -v "$REPO:/workspace:ro" -w /workspace debian:12 sleep infinity >/dev/null
    docker exec "$CTR" sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx-extras curl procps openssl >/dev/null 2>&1' \
        || { fail "could not install nginx-extras in the container"; return; }
    docker exec "$CTR" sh -c 'nginx -s quit 2>/dev/null; sleep 1; pkill -x nginx; true'
    docker exec "$CTR" bash /workspace/tests/host-integration.sh nginx-container-setup \
        || { fail "container nginx setup failed"; return; }
    note "$(docker exec "$CTR" nginx -v 2>&1); modules: $(docker exec "$CTR" ls /etc/nginx/modules-enabled | tr '\n' ' ')"
    note "lua-resty-core in the container: $(docker exec "$CTR" sh -c 'ls /usr/share/lua/5.1/resty/core.lua 2>&1; dpkg -l lua-resty-core 2>/dev/null | tail -1')"

    # ── Fix 5: proxied response headers (unconfined; independent of AppArmor)
    docker exec "$CTR" nginx
    sleep 1
    local hdrs
    # 2026-10: under the gateway's name — 127.0.0.1 over TLS is the trap's.
    hdrs=$(docker exec "$CTR" curl -sk --resolve loxprox.test:1080:127.0.0.1 -D - -o /dev/null https://loxprox.test:1080/jdev/cfg/api | tr -d '\r')
    [[ "$(grep -ci '^x-frame-options:' <<<"$hdrs")" == "1" ]] && grep -qi '^x-frame-options: SAMEORIGIN' <<<"$hdrs" \
        && pass "HTTPS-proxied response: exactly one X-Frame-Options (SAMEORIGIN), Miniserver's 'deny' hidden" \
        || fail "HTTPS-proxied X-Frame-Options: $(grep -i '^x-frame-options' <<<"$hdrs" | tr '\n' ';')"
    grep -qi '^x-xss-protection:' <<<"$hdrs" && fail "Miniserver's X-XSS-Protection passed through" \
                                             || pass "Miniserver's X-XSS-Protection hidden"
    [[ "$(grep -ci '^x-content-type-options:' <<<"$hdrs")" == "1" ]] && pass "exactly one X-Content-Type-Options" \
                                                                     || fail "X-Content-Type-Options count != 1"
    [[ "$(grep -ci '^strict-transport-security:' <<<"$hdrs")" == "1" ]] && pass "exactly one Strict-Transport-Security" \
                                                                         || fail "HSTS count != 1"
    if docker exec "$CTR" bash /workspace/tests/host-integration.sh nginx-container-test-proxy > /var/tmp/tg-proxy.log 2>&1; then
        pass "test-gateway.sh test_proxy passes against the v4 site ($(tail -1 /var/tmp/tg-proxy.log))"
    else
        fail "test-gateway.sh test_proxy fails against the v4 site"; sed 's/^/    /' /var/tmp/tg-proxy.log
    fi
    # Negative control: strip the v4 hides → test-gateway.sh must catch the
    # duplicate the audit saw (SAMEORIGIN + deny).
    docker exec "$CTR" sh -c "cp $NGINX_SITE /var/tmp/site.v4 && sed -i '/proxy_hide_header \\(X-Frame-Options\\|X-XSS-Protection\\|X-Content-Type-Options\\);/d' $NGINX_SITE && nginx -s reload"
    sleep 1
    if docker exec "$CTR" bash /workspace/tests/host-integration.sh nginx-container-test-proxy > /var/tmp/tg-proxy-neg.log 2>&1; then
        fail "test-gateway.sh did NOT flag the duplicated headers of a v3-style site"
    else
        pass "test-gateway.sh flags the v3-style duplicates: $(grep -m1 'X-Frame-Options header(s)' /var/tmp/tg-proxy-neg.log | sed 's/^ *//')"
    fi
    docker exec "$CTR" sh -c "cp /var/tmp/site.v4 $NGINX_SITE && nginx -s quit"
    sleep 1

    # ── Fix 6: the profile under a real nginx-extras lifecycle
    sysctl -qw kernel.printk_ratelimit=0
    local new_profile="$REPO/apparmor/usr.sbin.nginx" old_profile
    old_profile=$(mktemp /var/tmp/usr.sbin.nginx.pre-fix.XXXXXX)
    # The pre-2026-10 profile = this one minus the added rules, exec back to mr.
    grep -vE '^[[:space:]]*(/usr/share/lua/\*\* r,|/usr/share/perl/\*\* r,|/sys/devices/system/node/|/run/nginx\.pid\.oldbin rw,)' "$new_profile" \
        | sed 's#^\([[:space:]]*\)/usr/sbin/nginx mrix,#\1/usr/sbin/nginx mr,#' > "$old_profile"

    # Compile against Debian 12's own tunables/abstractions — the production
    # gateway's — not the runner's (Ubuntu, newer AppArmor), which may grant
    # different paths and hide or add events.
    local deb_aa=/var/tmp/debian12-apparmor.d
    local -a aa_base=()
    rm -rf "$deb_aa"
    if docker exec "$CTR" sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor >/dev/null 2>&1' \
        && docker cp "$CTR:/etc/apparmor.d" "$deb_aa" \
        && apparmor_parser -QTK --base "$deb_aa" "$new_profile"; then
        aa_base=(--base "$deb_aa")
        note "runtime profiles compiled against Debian 12's abstractions ($deb_aa)"
    else
        note "could not use Debian 12's abstractions — falling back to the runner's own"
    fi

    local label rc events
    # (a) control: pre-fix profile, complain mode → the audit's ALLOWED events
    apparmor_parser -r -T "${aa_base[@]}" -C "$old_profile" || { fail "could not load the pre-fix profile"; return; }
    dmesg -C
    label=$(ngx_lifecycle); rc=$?
    events=$(aa_events)
    note "pre-fix profile, complain: $label (lifecycle rc=$rc)"
    if grep -q 'complain' <<<"$label"; then
        pass "nginx inside the container is attached to /usr/sbin/nginx (complain)"
    else
        fail "nginx not attached to the profile ('$label') — runtime results below are meaningless"
    fi
    if grep -q 'apparmor="ALLOWED"' <<<"$events"; then
        pass "control reproduces ALLOWED events with the pre-fix profile ($(grep -c 'apparmor="ALLOWED"' <<<"$events") lines):"
        aa_summary <<<"$events"
    else
        fail "pre-fix profile produced no ALLOWED events — the control cannot show the fix"
    fi

    # (a2) control: pre-fix profile ENFORCED — what opting into enforce would
    #      have done to a nginx-extras gateway before this fix.
    apparmor_parser -r -T "${aa_base[@]}" "$old_profile" || { fail "could not enforce the pre-fix profile"; return; }
    dmesg -C
    label=$(ngx_lifecycle 2>&1); rc=$?
    events=$(aa_events)
    note "pre-fix profile, enforce: ${label//$'\n'/ } (lifecycle rc=$rc)"
    if grep -q 'apparmor="DENIED"' <<<"$events" || (( rc != 0 )); then
        pass "control: the pre-fix profile in enforce mode denies nginx-extras (lifecycle rc=$rc):"
        aa_summary <<<"$events"
    else
        fail "control: the pre-fix profile in enforce mode denied nothing"
    fi
    docker exec "$CTR" sh -c 'pkill -x nginx; true'

    # (b) fixed profile, complain mode → zero ALLOWED
    apparmor_parser -r -T "${aa_base[@]}" -C "$new_profile" || { fail "could not load the fixed profile"; return; }
    dmesg -C
    label=$(ngx_lifecycle); rc=$?
    events=$(aa_events)
    note "fixed profile, complain: $label (lifecycle rc=$rc)"
    if [[ -z "$(grep 'apparmor="ALLOWED"' <<<"$events")" ]]; then
        pass "fixed profile, complain mode: zero ALLOWED events over start/reload/USR1/USR2-upgrade/TLS request/stop"
    else
        fail "fixed profile still logs ALLOWED events:"
        aa_summary <<<"$events"
    fi

    # (c) fixed profile, ENFORCE → nothing denied, every lifecycle step works
    apparmor_parser -r -T "${aa_base[@]}" "$new_profile" || { fail "could not load the fixed profile in enforce mode"; return; }
    dmesg -C
    label=$(ngx_lifecycle); rc=$?
    events=$(aa_events)
    note "fixed profile, enforce: $label (lifecycle rc=$rc)"
    grep -q 'enforce' <<<"$label" && pass "nginx runs under the profile in enforce mode" || fail "not enforced: '$label'"
    [[ $rc -eq 0 ]] && pass "enforce: start, reload, USR1, USR2 upgrade + old-master QUIT, HTTPS proxy request all succeed" \
                    || fail "enforce: nginx lifecycle broke (step rc=$rc)"
    if [[ -z "$(grep 'apparmor="DENIED"' <<<"$events")" ]]; then
        pass "enforce: zero DENIED events"
    else
        fail "enforce: DENIED events:"
        aa_summary <<<"$events"
    fi

    apparmor_parser -R "$new_profile" >/dev/null 2>&1
    docker rm -f "$CTR" >/dev/null 2>&1
    rm -f "$old_profile"
}

# ── AppSec detection log: a blocked request reaches appsec-detections.log ────

APPSEC_CTR=loxprox-ci-appsec
APPSEC_LOG=/var/log/nginx/appsec-detections.log

# Runs INSIDE the Debian 12 container: the gateway's own site (deploy.sh,
# ENABLE_APPSEC=true, the real AppSec include) in front of a Miniserver
# stand-in, plus an AppSec stand-in on 127.0.0.1:7422 that answers the way
# CrowdSec's AppSec component does — 403 + JSON body for a blocked request,
# 200 + JSON otherwise, and no X-Crowdsec-Action response header.
t_nginx_appsec_setup() {
    systemctl() { true; }
    # shellcheck disable=SC2034  # consumed by deploy.sh's configure_nginx
    LOXONE_IP=127.0.0.1 LOXONE_PORT=8081 ENABLE_APPSEC=true APPSEC_MODE=enforce
    mkdir -p /etc/crowdsec/bouncers /var/log/nginx
    printf 'api_key: ci-test-key\n' > /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local
    cat > /etc/nginx/conf.d/ci-appsec-backends.conf <<'EMU'
server {
    listen 127.0.0.1:8081;
    location / { return 200 "miniserver\n"; }
}
server {
    listen 127.0.0.1:7422;
    location / {
        default_type application/json;
        if ($http_x_crowdsec_appsec_uri ~ "^/(\.git/|ci-blocked/|jdev/sys/enc/)") {
            return 403 '{"action":"ban","http_status":403}';
        }
        return 200 '{"action":"allow","http_status":200}';
    }
}
EMU
    configure_nginx >/dev/null 2>&1 || { echo "configure_nginx failed"; nginx -t; exit 1; }
    configure_appsec_nginx >/dev/null 2>&1 || { echo "configure_appsec_nginx failed"; nginx -t; exit 1; }
    grep -q 'X-Crowdsec-Appsec-Api-Key' "$NGINX_APPSEC_INCLUDE" || { echo "real AppSec include not written"; exit 1; }
    nginx -t || exit 1
    echo "container ready: template v$(_loxprox_site_marker_value "$_LOXPROX_SITE_VERSION_MARKER"), $(grep -c 'auth_request ' "$NGINX_SITE") auth_request locations"
}

# Runs INSIDE the container: turn the live site back into the pre-fix (v4)
# verdict source — the X-Crowdsec-Action response header and v4's map keys.
t_nginx_appsec_v4() {
    sed -i -e 's/auth_request_set  \$appsec_status \$upstream_status;/auth_request_set  $appsec_status $upstream_http_x_crowdsec_action;/' \
           -e 's/^    "401"         1;$/    "deny"        1;/' \
           -e 's/^    "403"         1;$/    "ban"         1;\n    "captcha"     1;/' "$NGINX_SITE"
    if ! grep -q 'upstream_http_x_crowdsec_action' "$NGINX_SITE" || ! grep -q '"ban"' "$NGINX_SITE" \
        || grep -q '"403"' "$NGINX_SITE"; then
        echo "v4 rewrite did not apply"; exit 1
    fi
    nginx -t && nginx -s reload
}

appsec_get() {  # appsec_get PATH → HTTP status of a request through the gateway
    docker exec "$APPSEC_CTR" curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:1080$1"
}

t_nginx_appsec() {
    section "nginx-extras (Debian 12) — AppSec blocks reach appsec-detections.log"
    command -v docker >/dev/null || { fail "docker missing"; return; }
    local code lines panel
    docker rm -f "$APPSEC_CTR" >/dev/null 2>&1
    docker run -d --name "$APPSEC_CTR" -e CI=true -v "$REPO:/workspace:ro" -w /workspace debian:12 sleep infinity >/dev/null
    docker exec "$APPSEC_CTR" sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx-extras curl procps >/dev/null 2>&1' \
        || { fail "could not install nginx-extras in the container"; return; }
    docker exec "$APPSEC_CTR" sh -c 'nginx -s quit 2>/dev/null; sleep 1; pkill -x nginx; true'
    docker exec "$APPSEC_CTR" bash /workspace/tests/host-integration.sh nginx-appsec-setup \
        || { fail "container AppSec setup failed"; return; }
    docker exec "$APPSEC_CTR" /usr/sbin/nginx || { fail "nginx did not start"; return; }
    sleep 1

    code=$(appsec_get '/jdev/cfg/api')
    [[ "$code" == "200" ]] && pass "allowed request proxied to the Miniserver (HTTP 200)" || fail "allowed request: HTTP $code"
    # 2026-10: /.git is a trap path — answered (444) in the rewrite phase,
    # before the AppSec subrequest that would have 403'd it, so it leaves no
    # detection line (the count of two below proves it).
    code=$(appsec_get '/.git/config')
    [[ "$code" == "000" ]] && pass "trap path /.git/config closed (444) before AppSec is asked" || fail "trap path: HTTP $code"
    code=$(appsec_get '/ci-blocked/config?sk=CI-SECRET-QUERY')
    [[ "$code" == "403" ]] && pass "AppSec 403 → nginx refuses the request (HTTP 403)" || fail "blocked request: HTTP $code"
    code=$(appsec_get '/jdev/sys/enc/CI-SECRET-BLOB')
    [[ "$code" == "403" ]] && pass "second blocked request (HTTP 403)" || fail "second blocked request: HTTP $code"
    sleep 1
    lines=$(docker exec "$APPSEC_CTR" cat "$APPSEC_LOG" 2>/dev/null)
    note "appsec-detections.log:"
    sed 's/^/      /' <<<"${lines:-<empty>}"
    [[ "$(grep -c . <<<"$lines")" == "2" ]] && pass "exactly the two blocked requests were logged, the allowed one was not" \
                                            || fail "expected 2 detection lines, got $(grep -c . <<<"$lines")"
    grep -q '127.0.0.1 "GET /ci-blocked/config HTTP/1.1" appsec=403 status=403' <<<"$lines" \
        && pass "line carries client address, method, path, appsec=403, status=403" \
        || fail "no well-formed line for /ci-blocked/config"
    docker exec "$APPSEC_CTR" grep -q '"GET /.git/config HTTP/1.1" 444' /var/log/nginx/loxprox-trap.log \
        && pass "the trap path is in the trap log (444)" || fail "trap path missing from loxprox-trap.log"
    grep -q '"GET /jdev/sys/enc/<redacted> HTTP/1.1"' <<<"$lines" \
        && pass "Loxone credential path redacted (F3 scrub) in the detection log" \
        || fail "Loxone credential path not redacted"
    grep -q 'CI-SECRET' <<<"$lines" && fail "query string or credential blob written to the detection log" \
                                    || pass "no query string, no credential blob on disk"

    # The panel's own readers on that very file: "Abgewehrte Angriffe heute"
    # (appsec_today) and the per-minute AppSec series of the 24 h chart.
    rm -f /var/tmp/appsec-ci.log
    docker cp "$APPSEC_CTR:$APPSEC_LOG" /var/tmp/appsec-ci.log >/dev/null
    panel=$(python3 - "$REPO/gui/loxprox-gui.py" /var/tmp/appsec-ci.log <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("panel", sys.argv[1])
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)
panel.LOG_FILES["appsec"] = sys.argv[2]
counter = panel.LogGrowthCounter(sys.argv[2])
counter.pos = 0          # as if sampled just before the requests
print(json.dumps({"today": panel.appsec_today(), "sec": counter.delta()}))
PY
)
    [[ "$panel" == '{"today": {"hits": 2, "ips": 1}, "sec": 2}' ]] \
        && pass "panel reads it: today 2 blocks from 1 address, 2 in the chart's AppSec series" \
        || fail "panel readers: $panel"
    rm -f /var/tmp/appsec-ci.log

    # Control: the pre-fix (v4) verdict source, a response header CrowdSec
    # never sends. Same 403 to the client, nothing logged — the empty file
    # seen on the gateway since 2026-05-26.
    docker exec "$APPSEC_CTR" bash /workspace/tests/host-integration.sh nginx-appsec-v4 \
        || { fail "control: could not switch the site to the v4 header source"; docker rm -f "$APPSEC_CTR" >/dev/null 2>&1; return; }
    sleep 1
    code=$(appsec_get '/ci-blocked/config')
    sleep 1
    lines=$(docker exec "$APPSEC_CTR" cat "$APPSEC_LOG" 2>/dev/null)
    if [[ "$code" == "403" && "$(grep -c . <<<"$lines")" == "2" ]]; then
        pass "control: with the v4 header-based map the same 403 is NOT logged (reproduces the empty file)"
    else
        fail "control: HTTP $code, $(grep -c . <<<"$lines") line(s) — expected 403 and no new line"
    fi
    docker rm -f "$APPSEC_CTR" >/dev/null 2>&1
}

# ── 2026-10 breach hardening ────────────────────────────────────────────────

# Lines of a container's output → this run's counters: "  ✓ x" passes,
# "  ✗ x" fails, anything else is context.
relay_results() {
    local line
    while IFS= read -r line; do
        case "$line" in
            "  ✓ "*) pass "${line#  ✓ }" ;;
            "  ✗ "*) fail "${line#  ✗ }" ;;
            *)       note "$line" ;;
        esac
    done
}

EDGE_CTR=loxprox-ci-edge

# Runs INSIDE the Debian 12 container: the gateway's own site (deploy.sh) in
# mode $1 — tls (UNKNOWN_PATH_MODE=log), tls-deny (=deny) or plain — in front
# of a Miniserver stand-in. LAN_SUBNET is 192.168.1.0/24, so requests to the
# container's own eth0 address are "internet" (untrusted), loopback trusted.
# 198.51.100.7 (added to lo by t_nginx_edge) is untrusted too, but in
# TRAP_EXEMPT_IPS.
t_nginx_edge_setup() {
    local mode="${1:-tls}"
    systemctl() { true; }
    # shellcheck disable=SC2034  # consumed by deploy.sh's configure_nginx / TLS block
    LOXONE_IP=127.0.0.1 LOXONE_PORT=8081 ENABLE_APPSEC=false TLS_DOMAIN=loxprox.test \
        EXTRA_SERVER_NAMES=alt.loxprox.test LAN_SUBNET=192.168.1.0/24 REMOTE_ADMIN_PATHS=deny UNKNOWN_PATH_MODE=log
    # shellcheck disable=SC2034
    CROWDSEC_WHITELIST_IPS=("192.168.1.0/24")
    # shellcheck disable=SC2034
    TRAP_EXEMPT_IPS=("198.51.100.7" "2001:db8:5::/48")
    [[ "$mode" == "tls-deny" ]] && UNKNOWN_PATH_MODE=deny
    mkdir -p /etc/loxprox/tls /var/log/nginx "$ACME_WEBROOT/.well-known/acme-challenge"
    [[ -s /etc/loxprox/tls/fullchain.pem ]] || openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=loxprox.test \
        -keyout /etc/loxprox/tls/privkey.pem -out /etc/loxprox/tls/fullchain.pem >/dev/null 2>&1
    printf 'ci-token-content\n' > "$ACME_WEBROOT/.well-known/acme-challenge/ci-token"
    cat > /etc/nginx/conf.d/ci-miniserver-emulator.conf <<'EMU'
server {
    listen 127.0.0.1:8081;
    # A slow body keeps a proxied /ws/ connection open for the limit_conn check.
    location /ws/ { limit_rate 1; return 200 "0123456789012345678901234567890123456789\n"; }
    location / { return 200 "miniserver\n"; }
}
EMU
    configure_nginx >/dev/null 2>&1 || { echo "configure_nginx failed"; nginx -t; exit 1; }
    if [[ "$mode" == "plain" ]]; then
        _loxprox_site_disable_tls >/dev/null 2>&1
        rm -f "$NGINX_ACME_CONF"
    else
        _loxprox_site_enable_tls >/dev/null 2>&1 || { echo "TLS block failed"; exit 1; }
    fi
    nginx -t || exit 1
    echo "edge container ready ($mode): $(grep -c . "$NGINX_SITE") site lines"
}

edge_code() {   # edge_code CURL_ARGS… → HTTP status; 000 = closed without a response (444)
    docker exec "$EDGE_CTR" curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null || true
}

edge_lines() {  # edge_lines FILE → line count inside the container
    docker exec "$EDGE_CTR" sh -c "[ -f '$1' ] && wc -l < '$1' || echo 0"
}

edge_mode() {
    docker exec "$EDGE_CTR" bash /workspace/tests/host-integration.sh nginx-edge-setup "$1" \
        && docker exec "$EDGE_CTR" nginx -s reload && sleep 1
}

t_nginx_edge() {
    section "nginx-extras (Debian 12) — Host/SNI gate, path classes, limits, scrub, server_tokens (2026-10)"
    command -v docker >/dev/null || { fail "docker missing"; return; }
    local trap=/var/log/nginx/loxprox-trap.log unknown=/var/log/nginx/loxprox-unknown.log access=/var/log/nginx/loxone-access.log
    local ip code before after hdrs p n
    docker rm -f "$EDGE_CTR" >/dev/null 2>&1
    # NET_ADMIN: a second untrusted source address (TRAP_EXEMPT_IPS) on lo.
    docker run -d --name "$EDGE_CTR" --cap-add NET_ADMIN -e CI=true -v "$REPO:/workspace:ro" -w /workspace debian:12 sleep infinity >/dev/null
    docker exec "$EDGE_CTR" sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx-extras curl procps openssl iproute2 >/dev/null 2>&1' \
        || { fail "could not install nginx-extras in the container"; docker rm -f "$EDGE_CTR" >/dev/null 2>&1; return; }
    docker exec "$EDGE_CTR" sh -c 'nginx -s quit 2>/dev/null; sleep 1; pkill -x nginx; true'
    if docker exec "$EDGE_CTR" bash /workspace/tests/host-integration.sh nginx-edge-setup tls; then
        pass "nginx -t accepts the v8 site with the TLS block, both trap servers and the exempt geo"
    else
        fail "edge setup (tls) failed"; docker rm -f "$EDGE_CTR" >/dev/null 2>&1; return
    fi
    # Template v7: the maps' variables fit the hash — production's nginx -t
    # warned "could not build optimal variables_hash" at the 1024 default.
    local nt
    nt=$(docker exec "$EDGE_CTR" nginx -t 2>&1)
    docker exec "$EDGE_CTR" grep -qx 'variables_hash_max_size 2048;' "$NGINX_SITE" \
        && pass "site sets variables_hash_max_size 2048 at http level" || fail "site lacks variables_hash_max_size 2048"
    grep -q 'variables_hash' <<<"$nt" && fail "nginx -t still warns: $(grep 'variables_hash' <<<"$nt")" \
                                       || pass "nginx -t: no variables_hash warning"
    docker exec "$EDGE_CTR" /usr/sbin/nginx || { fail "nginx did not start"; docker rm -f "$EDGE_CTR" >/dev/null 2>&1; return; }
    sleep 1
    ip=$(docker exec "$EDGE_CTR" hostname -i | awk '{print $1}')
    note "untrusted source = the container's own address $ip (LAN_SUBNET 192.168.1.0/24)"
    local R=(--resolve loxprox.test:1080:127.0.0.1) X=(--resolve "loxprox.test:1080:$ip")

    # ── Host/SNI gate
    code=$(edge_code "${R[@]}" https://loxprox.test:1080/jdev/cfg/api)
    [[ "$code" == "200" ]] && pass "real name (TLS_DOMAIN) proxied (HTTP 200)" || fail "real name: HTTP $code"
    code=$(edge_code --resolve alt.loxprox.test:1080:127.0.0.1 https://alt.loxprox.test:1080/jdev/cfg/api)
    [[ "$code" == "200" ]] && pass "EXTRA_SERVER_NAMES name proxied" || fail "extra name: HTTP $code"
    before=$(edge_lines "$trap")
    code=$(edge_code https://127.0.0.1:1080/)
    [[ "$code" == "000" ]] && pass "bare IP, no SNI: 444 (closed, no bytes)" || fail "bare IP over TLS: HTTP $code"
    code=$(edge_code "${R[@]}" -H 'Host: evil.example' https://loxprox.test:1080/)
    [[ "$code" == "000" ]] && pass "real SNI but foreign Host: 444" || fail "foreign Host: HTTP $code"
    code=$(edge_code http://127.0.0.1:1080/)
    [[ "$code" == "000" ]] && pass "cleartext to :1080 with a foreign Host (497): 444" || fail "cleartext foreign Host: HTTP $code"
    hdrs=$(docker exec "$EDGE_CTR" curl -s -D - -o /dev/null --max-time 10 -H 'Host: loxprox.test' http://127.0.0.1:1080/jdev/cfg/api | tr -d '\r')
    grep -q '^HTTP/1.1 301' <<<"$hdrs" && grep -qi '^Location: https://loxprox.test:1080/jdev/cfg/api' <<<"$hdrs" \
        && pass "cleartext for the real name keeps the 301 to https (the family device)" || fail "real-name cleartext: $(head -1 <<<"$hdrs")"
    grep -qx 'Server: nginx' <<<"$hdrs" && pass "server_tokens off: 'Server: nginx' without a version" || fail "Server header: $(grep -i '^Server' <<<"$hdrs")"
    code=$(edge_code http://127.0.0.1:80/)
    [[ "$code" == "000" ]] && pass ":80 with a foreign Host: 444" || fail ":80 foreign Host: HTTP $code"
    code=$(docker exec "$EDGE_CTR" curl -s --max-time 10 -H 'Host: loxprox.test' http://127.0.0.1/.well-known/acme-challenge/ci-token)
    [[ "$code" == "ci-token-content" ]] && pass ":80 real name: ACME challenge served" || fail "ACME challenge: '$code'"
    code=$(edge_code -H 'Host: loxprox.test' http://127.0.0.1/anything)
    [[ "$code" == "301" ]] && pass ":80 real name: 301 to https" || fail ":80 real name: HTTP $code"
    sleep 1
    after=$(edge_lines "$trap")
    (( after - before == 4 )) && pass "the 4 foreign-host requests are in the trap log" || fail "trap log grew by $((after - before)), expected 4"
    docker exec "$EDGE_CTR" grep -q '" 301 ' "$trap" && fail "a 301 (real name) was logged as a trap hit" || pass "the real name's 301 is never a trap hit"
    # R5: the host diagnostics log saw the same four, with Host and SNI.
    docker exec "$EDGE_CTR" grep -q 'host="evil.example" sni="loxprox.test" "GET /" 444' /var/log/nginx/loxprox-trap-hosts.log \
        && pass "trap-hosts log names Host and SNI (host=\"evil.example\" sni=\"loxprox.test\")" || fail "trap-hosts log lacks the foreign-Host hit"
    docker exec "$EDGE_CTR" grep -q 'host="127.0.0.1" sni="-" "GET /" 444' /var/log/nginx/loxprox-trap-hosts.log \
        && pass "trap-hosts log: a cleartext hit carries sni=\"-\"" || fail "trap-hosts log: no cleartext line with sni=\"-\""
    [[ "$(edge_lines /var/log/nginx/loxprox-trap-hosts.log)" -ge 4 ]] && pass "trap-hosts log has the :1080 and :80 trap hits" \
                                                                    || fail "trap-hosts log: $(docker exec "$EDGE_CTR" cat /var/log/nginx/loxprox-trap-hosts.log)"

    # R1: the SHIPPED network watchdog's probe against this gated nginx. With
    # a config.env that carries TLS_DOMAIN it sees a healthy listener; with a
    # pre-2026-10 config.env (no TLS_DOMAIN) it asks 127.0.0.1, gets the
    # trap's 444 and reads 000 — the reason deploy.sh disables the old
    # watchdog before the gate goes live.
    local wd
    wd=$(docker exec "$EDGE_CTR" bash -c '
        printf "ENABLE_TLS=\"true\"\nTLS_DOMAIN=\"loxprox.test\"\n" > /var/tmp/wd-new.env
        printf "ENABLE_TLS=\"true\"\n" > /var/tmp/wd-old.env
        for cfg in new old; do
            ( export LOXPROX_CONFIG=/var/tmp/wd-$cfg.env WATCHDOG_IFACE=lo WATCHDOG_GATEWAY=127.0.0.1 DISCORD_ALERT_PATH=/bin/true
              source /workspace/security-monitoring/network-watchdog.sh
              printf "%s=%s " "$cfg" "$(nginx_local_status)" )
        done' 2>&1)
    [[ "$wd" == *"new=200"* ]] && pass "shipped watchdog with TLS_DOMAIN: healthy (${wd%% *})" || fail "watchdog with TLS_DOMAIN: '$wd'"
    [[ "$wd" == *"old=000"* ]] && pass "shipped watchdog without TLS_DOMAIN: 000 from the trap — why the pause exists" \
                               || fail "watchdog without TLS_DOMAIN: '$wd'"

    # ── trap paths and methods on the real name
    before=$(edge_lines "$trap")
    n=0
    for p in /.env /api/.env /.git/config /wp-login.php /index.php /cgi-bin/luci \
             /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php /HNAP1/ /boaform/admin/formLogin /actuator/health; do
        code=$(edge_code "${R[@]}" "https://loxprox.test:1080$p")
        if [[ "$code" == "000" ]]; then n=$((n + 1)); else fail "trap path $p: HTTP $code"; fi
    done
    (( n == 10 )) && pass "10 scanner paths: 444"
    n=0
    for p in TRACK PROPFIND TRACE; do
        code=$(edge_code "${R[@]}" -X "$p" https://loxprox.test:1080/)
        if [[ "$code" == "000" ]]; then n=$((n + 1)); else fail "method $p: HTTP $code"; fi
    done
    (( n == 3 )) && pass "TRACK / PROPFIND / TRACE: 444 (TRACE via nginx's own 405 → error_page)"
    sleep 1
    after=$(edge_lines "$trap")
    (( after - before == 13 )) && pass "all 13 in the trap log" || fail "trap log grew by $((after - before)), expected 13"
    # CONNECT with an origin-form target may already fail nginx's request-line
    # parser (400) before the method's 405; either way it is never proxied.
    code=$(edge_code "${R[@]}" -X CONNECT https://loxprox.test:1080/)
    [[ "$code" == "000" || "$code" == "400" ]] && pass "CONNECT refused, never proxied (HTTP $code)" || fail "CONNECT: HTTP $code"
    local bad_lines
    bad_lines=$(docker exec "$EDGE_CTR" grep -cvE '^[0-9a-f.:]+ - [^ ]+ \[[^]]+\] "[A-Z]+ [^ ]* HTTP/1\.[01]" [0-9]{3} [0-9]+ "[^"]*" "[^"]*"$' "$trap" || true)
    [[ "$bad_lines" == "0" ]] && pass "every trap-log line has the combined shape crowdsecurity/nginx-logs parses" \
                              || fail "$bad_lines trap-log line(s) not in the loxone_scrubbed shape"

    # ── admin / app / unknown, trusted vs untrusted
    code=$(edge_code "${X[@]}" https://loxprox.test:1080/dev/fsget/log/def.log)
    [[ "$code" == "403" ]] && pass "admin path from the internet: 403" || fail "admin from untrusted: HTTP $code"
    code=$(edge_code "${R[@]}" https://loxprox.test:1080/dev/fsget/log/def.log)
    [[ "$code" == "200" ]] && pass "admin path from a trusted source: proxied" || fail "admin from loopback: HTTP $code"
    before=$(edge_lines "$unknown")
    n=0
    for p in /jdev/cfg/api /jdev/cfg/apiKey /jdev/sys/getcertificate /dev/sys/getcertificate /favicon.ico \
             /resources/favicon/x.png /get /data/LoxAPP3.json /jdev/sps/LoxAPPversion3 /stats/statistics.json; do
        code=$(edge_code "${X[@]}" "https://loxprox.test:1080$p")
        if [[ "$code" == "200" ]]; then n=$((n + 1)); else fail "app path $p from untrusted: HTTP $code"; fi
    done
    (( n == 10 )) && pass "10 app paths from the internet: proxied"
    after=$(edge_lines "$unknown")
    (( after == before )) && pass "app paths never reach the unknown log" || fail "app paths written to the unknown log"
    code=$(edge_code "${X[@]}" https://loxprox.test:1080/ci/unknown/path)
    sleep 1
    [[ "$code" == "200" ]] && pass "UNKNOWN_PATH_MODE=log: unknown path proxied" || fail "unknown (log mode): HTTP $code"
    docker exec "$EDGE_CTR" sh -c "tail -1 $unknown" | grep -q '"GET /ci/unknown/path HTTP/1.1" 200' \
        && pass "…and written to the unknown log" || fail "unknown path not in the unknown log"

    # ── scrub: a token command never reaches a log in clear
    edge_code "${R[@]}" https://loxprox.test:1080/jdev/sys/authwithtoken/CI-SECRET-TOKEN/ciuser >/dev/null
    sleep 1
    if docker exec "$EDGE_CTR" grep -q 'CI-SECRET-TOKEN' "$access"; then
        fail "authwithtoken token hash written to the access log"
    else
        docker exec "$EDGE_CTR" grep -q '"GET /jdev/sys/authwithtoken/<redacted> HTTP/1.1"' "$access" \
            && pass "authwithtoken logged as /jdev/sys/authwithtoken/<redacted>" || fail "authwithtoken request not found in the access log"
    fi

    # ── limits: untrusted auth requests 3/s burst 30; trusted never limited
    local burst
    burst=$(docker exec "$EDGE_CTR" sh -c "for i in \$(seq 45); do curl -sk -o /dev/null -w '%{http_code}\n' --resolve loxprox.test:1080:$ip https://loxprox.test:1080/jdev/sys/getkey2/ciuser; done" | grep -c '^503$' || true)
    (( burst >= 1 )) && pass "45 rapid auth requests from the internet: $burst rejected (loxone_auth 3r/s, burst 30)" || fail "auth burst never limited"
    burst=$(docker exec "$EDGE_CTR" sh -c "for i in \$(seq 45); do curl -sk -o /dev/null -w '%{http_code}\n' --resolve loxprox.test:1080:127.0.0.1 https://loxprox.test:1080/jdev/sys/getkey2/ciuser; done" | grep -c '^503$' || true)
    [[ "$burst" == "0" ]] && pass "the same burst from a trusted source: none rejected" || fail "trusted source rate-limited ($burst × 503)"
    sleep 2
    code=$(docker exec "$EDGE_CTR" sh -c "for i in 1 2 3 4 5 6; do curl -sk -o /dev/null --max-time 8 --resolve loxprox.test:1080:$ip https://loxprox.test:1080/ws/rfc6455 & done; sleep 2; curl -sk -o /dev/null -w '%{http_code}' --max-time 3 --resolve loxprox.test:1080:$ip https://loxprox.test:1080/ws/rfc6455; wait" || true)
    [[ "$code" == "503" ]] && pass "7th concurrent /ws/ socket from one internet address: 503 (limit 6)" || fail "7th /ws/ socket: HTTP $code"
    code=$(docker exec "$EDGE_CTR" sh -c "for i in 1 2 3 4 5 6; do curl -sk -o /dev/null --max-time 8 --resolve loxprox.test:1080:127.0.0.1 https://loxprox.test:1080/ws/rfc6455 & done; sleep 2; curl -sk -o /dev/null -w '%{http_code}' --max-time 3 --resolve loxprox.test:1080:127.0.0.1 https://loxprox.test:1080/ws/rfc6455; wait" || true)
    [[ "$code" != "503" ]] && pass "7 concurrent /ws/ sockets from a trusted source: not limited" || fail "trusted /ws/ sockets limited"

    # ── TRAP_EXEMPT_IPS (2026-10-21): exempt from the trap logs, NOT trusted.
    # The probe it is for: plain HTTP to the TLS port, bare IP as Host, no
    # SNI, no user agent. The same probe from the non-exempt $ip is the control.
    local E=198.51.100.7 hosts=/var/log/nginx/loxprox-trap-hosts.log tb hb ta ha
    if docker exec "$EDGE_CTR" ip addr add "$E/32" dev lo; then
        note "trap-exempt source = $E (on lo, in TRAP_EXEMPT_IPS); non-exempt control = $ip"
        tb=$(edge_lines "$trap"); hb=$(edge_lines "$hosts")
        hdrs=$(docker exec "$EDGE_CTR" curl -s -D - -o /dev/null --max-time 10 -H 'User-Agent:' "http://$E:1080/dev/sys/getcertificate" | tr -d '\r')
        if grep -q '^HTTP/1.1 301' <<<"$hdrs" && grep -qx 'Location: https://loxprox.test:1080/dev/sys/getcertificate' <<<"$hdrs"; then
            pass "exempt $E: cleartext to :1080, bare IP as Host → 301 to https://loxprox.test:1080/dev/sys/getcertificate"
        else
            fail "exempt cleartext probe: '$(head -1 <<<"$hdrs")' $(grep -i '^Location' <<<"$hdrs")"
        fi
        code=$(edge_code "https://$E:1080/dev/sys/getcertificate")
        [[ "$code" == "000" ]] && pass "exempt $E: TLS without SNI (bare IP) → 444" || fail "exempt, TLS bare IP: HTTP $code"
        code=$(edge_code --resolve "evil.example:1080:$E" https://evil.example:1080/)
        [[ "$code" == "000" ]] && pass "exempt $E: TLS with a wrong SNI → 444" || fail "exempt, wrong SNI: HTTP $code"
        code=$(edge_code -X TRACE "http://$E:1080/")
        [[ "$code" == "000" ]] && pass "exempt $E: cleartext TRACE (405, not 497) → 444, no redirect" || fail "exempt, cleartext TRACE: HTTP $code"
        code=$(edge_code "http://$E:80/")
        [[ "$code" == "000" ]] && pass "exempt $E: :80 with a foreign Host → 444" || fail "exempt, :80: HTTP $code"
        code=$(edge_code --resolve "loxprox.test:1080:$E" https://loxprox.test:1080/.env)
        [[ "$code" == "000" ]] && pass "exempt $E: scanner path on the real name → 444" || fail "exempt, /.env: HTTP $code"
        sleep 1
        ta=$(edge_lines "$trap"); ha=$(edge_lines "$hosts")
        (( ta == tb && ha == hb )) && pass "exempt $E: none of its 6 requests is in loxprox-trap.log or loxprox-trap-hosts.log" \
                                   || fail "exempt requests logged: trap +$((ta - tb)), trap-hosts +$((ha - hb))"
        code=$(edge_code --resolve "loxprox.test:1080:$E" https://loxprox.test:1080/dev/fsget/log/def.log)
        [[ "$code" == "403" ]] && pass "exempt $E is not trusted: admin path → 403" || fail "exempt, admin path: HTTP $code"
        burst=$(docker exec "$EDGE_CTR" sh -c "for i in \$(seq 45); do curl -sk -o /dev/null -w '%{http_code}\n' --resolve loxprox.test:1080:$E https://loxprox.test:1080/jdev/sys/getkey2/ciuser; done" | grep -c '^503$' || true)
        (( burst >= 1 )) && pass "exempt $E is not trusted: 45 rapid auth requests, $burst rejected (rate limit)" || fail "exempt source never rate-limited"
        tb=$(edge_lines "$trap"); hb=$(edge_lines "$hosts")
        code=$(edge_code -H 'User-Agent:' "http://$ip:1080/dev/sys/getcertificate")
        [[ "$code" == "000" ]] && pass "non-exempt $ip: the same cleartext probe → 444" || fail "non-exempt cleartext probe: HTTP $code"
        sleep 1
        ta=$(edge_lines "$trap"); ha=$(edge_lines "$hosts")
        if (( ta - tb == 1 && ha - hb == 1 )) \
                && docker exec "$EDGE_CTR" grep -q "^$ip - - .*\"GET /dev/sys/getcertificate HTTP/1.1\" 444 " "$trap" \
                && docker exec "$EDGE_CTR" grep -qF "$ip host=\"$ip\" sni=\"-\" \"GET /dev/sys/getcertificate\" 444" "$hosts"; then
            pass "non-exempt $ip: logged to loxprox-trap.log and loxprox-trap-hosts.log (host=\"$ip\" sni=\"-\")"
        else
            fail "non-exempt probe: trap +$((ta - tb)), trap-hosts +$((ha - hb)); last: $(docker exec "$EDGE_CTR" tail -n 1 "$hosts")"
        fi
    else
        fail "could not add $E to the container's lo (needs --cap-add NET_ADMIN and iproute2)"
    fi

    # ── UNKNOWN_PATH_MODE=deny
    if edge_mode tls-deny; then
        before=$(edge_lines "$unknown")
        code=$(edge_code "${X[@]}" https://loxprox.test:1080/ci/unknown/deny)
        [[ "$code" == "404" ]] && pass "UNKNOWN_PATH_MODE=deny: unknown path from the internet → 404" || fail "deny mode, untrusted: HTTP $code"
        code=$(edge_code "${R[@]}" https://loxprox.test:1080/ci/unknown/deny)
        [[ "$code" == "200" ]] && pass "deny mode, trusted source: still proxied" || fail "deny mode, trusted: HTTP $code"
        code=$(edge_code "${X[@]}" https://loxprox.test:1080/jdev/cfg/api)
        [[ "$code" == "200" ]] && pass "deny mode: app paths unaffected" || fail "deny mode app path: HTTP $code"
        sleep 1
        after=$(edge_lines "$unknown")
        (( after - before == 2 )) && pass "deny mode still writes the unknown log" || fail "unknown log grew by $((after - before)), expected 2"
    else
        fail "switching the container to tls-deny failed"
    fi

    # ── plain mode (ENABLE_TLS=false): no gate, classes still apply
    if edge_mode plain; then
        code=$(edge_code http://127.0.0.1:1080/jdev/cfg/api)
        [[ "$code" == "200" ]] && pass "plain mode: any Host served (server_name _)" || fail "plain mode: HTTP $code"
        code=$(edge_code http://127.0.0.1:1080/.env)
        [[ "$code" == "000" ]] && pass "plain mode: trap paths still 444" || fail "plain mode trap path: HTTP $code"
        before=$(edge_lines "$trap")
        code=$(edge_code "http://$E:1080/.env")
        sleep 1
        after=$(edge_lines "$trap")
        [[ "$code" == "000" ]] && (( after == before )) && pass "plain mode: exempt $E gets 444 for /.env, not logged as a trap hit" \
                                                       || fail "plain mode, exempt /.env: HTTP $code, trap log +$((after - before))"
        code=$(edge_code "http://$ip:1080/.env")
        sleep 1
        before=$(edge_lines "$trap")
        [[ "$code" == "000" ]] && (( before == after + 1 )) && pass "plain mode: non-exempt $ip's /.env is logged" \
                                                         || fail "plain mode, non-exempt /.env: HTTP $code, trap log +$((before - after))"
        docker exec "$EDGE_CTR" grep -q 'LOXPROX-TRAP' "$NGINX_SITE" && fail "trap servers left in plain mode" || pass "plain mode: no trap servers, no default_server"
    else
        fail "switching the container to plain mode failed"
    fi
    docker rm -f "$EDGE_CTR" >/dev/null 2>&1
}

# Runs INSIDE a Debian 12 container with CAP_NET_ADMIN (its own network
# namespace): deploy.sh's ruleset checked — and loaded — by Debian 12's nft.
t_nft_check_inner() {
    systemctl() { true; }
    local d
    d=$(mktemp -d)
    # shellcheck disable=SC2034  # consumed by deploy.sh's setup_firewall
    NFTABLES_CONF="$d/nftables.conf" NFTABLES_D_DIR="$d/nftables.d" LOXONE_IP=192.168.1.100 LOXONE_PORT=80 \
        LAN_SUBNET=192.168.1.0/24 ENABLE_GUI=true GUI_PORT=1081 ENABLE_TLS=true
    # shellcheck disable=SC2034
    SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")
    setup_firewall >/dev/null 2>&1
    nft -c -f "$NFTABLES_CONF" && pass "nft -c accepts the generated ruleset (placeholder sets)" || fail "nft -c rejects the ruleset: $(nft -c -f "$NFTABLES_CONF" 2>&1 | head -3)"
    printf '%s\n' '# Generated: ci' 'set geoip_blocklist {' '    type ipv4_addr' '    flags interval' '    elements = { 198.51.100.0/24 }' '}' \
        'set geoip_blocklist6 {' '    type ipv6_addr' '    flags interval' '    elements = { 2001:db8::/32 }' '}' > "$NFTABLES_D_DIR/99-geoip.conf"
    nft -c -f "$NFTABLES_CONF" && pass "nft -c accepts it with geoip-block.sh's two-set include" || fail "two-set include rejected"
    printf '%s\n' 'set geoip_blocklist {' '    type ipv4_addr' '    flags interval' '}' > "$NFTABLES_D_DIR/99-geoip.conf"
    nft -c -f "$NFTABLES_CONF" >/dev/null 2>&1 && fail "control: a v4-only include was accepted (the check cannot fail)" \
                                               || pass "control: a v4-only include is rejected — the IPv6 set must be declared"
    setup_firewall >/dev/null 2>&1
    nft -c -f "$NFTABLES_CONF" && pass "setup_firewall repairs an old v4-only include (v6 placeholder appended)" || fail "old include not repaired"
    if nft -f "$NFTABLES_CONF"; then
        local out
        out=$(nft list chain inet filter output)
        [[ "$(grep -c 'loxprox-egress' <<<"$out")" == "5" ]] && pass "loaded: 5 loxprox-egress rules in the output chain" || fail "output chain after load: $out"
        grep -q 'skuid' <<<"$out" && pass "loaded: www-data resolved for meta skuid ($(grep -m1 -o 'skuid [^ ]*' <<<"$out"))" || fail "skuid rule missing after load"
        grep -q 'ip6 saddr @geoip_blocklist6 drop' <<<"$(nft list chain inet filter input)" && pass "loaded: ip6 GeoIP drop rule active" || fail "ip6 drop rule not loaded"
    else
        fail "nft -f could not load the ruleset in the container's namespace"
    fi
}

t_nft_check() {
    section "nftables (Debian 12 nft 1.0.6) — generated ruleset (2026-10)"
    command -v docker >/dev/null || { fail "docker missing"; return; }
    relay_results < <(docker run --rm --cap-add NET_ADMIN -e CI=true -v "$REPO:/workspace:ro" -w /workspace debian:12 bash -c '
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null 2>&1 || { echo "  ✗ nftables install failed"; exit 0; }
        nft --version
        bash /workspace/tests/host-integration.sh nft-check-inner' 2>&1)
}

# Runs INSIDE a Debian 12 container: unattended-upgrades' own matcher against
# the generated config and the container's real apt sources, and sshd -t / -T
# against the generated drop-in.
t_debian12_host_inner() {
    systemctl() { true; }
    setup_unattended_upgrades >/dev/null 2>&1
    local out
    # shellcheck source=../test-gateway.sh
    out=$( (source "$REPO/test-gateway.sh"; _uu_origin_check) | tail -n 1)
    case "$out" in
        ok*live-security-files=0) fail "u-u matcher ran, but apt knows no Debian-Security file: $out" ;;
        ok*) pass "unattended-upgrades' matcher: main + security accepted, CrowdSec repo rejected, live security files matched ($out)" ;;
        *)   fail "unattended-upgrades origin check: $out" ;;
    esac
    out=$(unattended-upgrade --dry-run -d 2>&1 | grep -m1 'Allowed origins are' || true)
    grep -q 'codename=bookworm-security,label=Debian-Security' <<<"$out" \
        && pass "unattended-upgrade --dry-run reads the patterns: ${out#*: }" || fail "dry run: '${out:-no Allowed origins line}'"

    ssh-keygen -A >/dev/null 2>&1
    mkdir -p /run/sshd
    id loxci >/dev/null 2>&1 || useradd -m -s /bin/bash loxci
    install -d -m 0700 -o loxci -g loxci /home/loxci/.ssh
    ssh-keygen -q -t ed25519 -N '' -f /var/tmp/loxci_key <<<y >/dev/null 2>&1
    install -m 0600 -o loxci -g loxci /var/tmp/loxci_key.pub /home/loxci/.ssh/authorized_keys
    # Control first: a keyed account that cannot become root keeps root's key login.
    SSH_ALLOW_USERS="loxci" _loxprox_write_hard_ssh_drop_in >/dev/null 2>&1
    grep -qx 'PermitRootLogin prohibit-password' "$SSHD_DROPIN" \
        && pass "keyed account outside sudo → PermitRootLogin prohibit-password (no root lockout)" || fail "root login off without a sudo-capable account"
    usermod -aG sudo loxci
    SSH_ALLOW_USERS="loxci" _loxprox_write_hard_ssh_drop_in >/dev/null 2>&1
    sshd -t && pass "sshd -t accepts the HARD drop-in" || fail "sshd -t rejects the drop-in: $(sshd -t 2>&1 | head -2)"
    out=$(sshd -T 2>/dev/null)
    grep -qx 'permitrootlogin no' <<<"$out" && pass "effective: permitrootlogin no" || fail "effective permitrootlogin: $(grep permitrootlogin <<<"$out")"
    grep -qx 'allowusers loxci' <<<"$out" && pass "effective: allowusers loxci" || fail "effective allowusers: $(grep allowusers <<<"$out")"
    grep -qx 'passwordauthentication no' <<<"$out" && pass "effective: passwordauthentication no" || fail "password auth not off"
    SSH_ALLOW_USERS="ghost" _loxprox_write_hard_ssh_drop_in >/dev/null 2>&1
    grep -q '^AllowUsers' "$SSHD_DROPIN" && fail "AllowUsers for an account that does not exist (lockout)" || pass "AllowUsers refused for a non-existent account"
    echo 'PermitRootLogin maybe' >> "$SSHD_DROPIN"
    sshd -t >/dev/null 2>&1 && fail "control: sshd -t accepted a broken drop-in" || pass "control: sshd -t rejects a broken drop-in (the guard can fire)"
}

t_debian12_host() {
    section "Debian 12 — unattended-upgrades origins + sshd drop-in (2026-10)"
    command -v docker >/dev/null || { fail "docker missing"; return; }
    relay_results < <(docker run --rm -e CI=true -v "$REPO:/workspace:ro" -w /workspace debian:12 bash -c '
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades python3-apt lsb-release openssh-server >/dev/null 2>&1 \
            || { echo "  ✗ package install failed"; exit 0; }
        bash /workspace/tests/host-integration.sh debian12-host-inner' 2>&1)
}

# deploy.sh's configure_crowdsec as CI runs it: no AppSec, UNKNOWN_PATH_MODE=log,
# the LAN 192.168.1.0/24 whitelisted, TRAP_BAN_MODE=$1. The firewall bouncer is
# not under test (and would program the runner's firewall).
cs_configure() {
    # shellcheck disable=SC2034  # consumed by deploy.sh's configure_crowdsec
    ( ENABLE_APPSEC=false UNKNOWN_PATH_MODE=log TRAP_BAN_MODE="$1"
      CROWDSEC_WHITELIST_IPS=("192.168.1.0/24")
      systemctl() { case " $* " in *" crowdsec-firewall-bouncer"*) return 0 ;; esac; command systemctl "$@"; }
      configure_crowdsec ) >>"$LOG_FILE" 2>&1
}

# The real CrowdSec (packagecloud, installed by the CI step) driven by
# deploy.sh's configure_crowdsec: the daemon must start with the managed
# files, and the scenarios must route by log file. Synthetic events use
# TEST-NET addresses (RFC 5737) only; their decisions are deleted again.
t_crowdsec() {
    section "CrowdSec — LoxProx scenarios, profiles, retention, simulation, explain, replay (2026-10)"
    command -v cscli >/dev/null || { fail "cscli missing — install crowdsec first"; return; }
    mkdir -p /var/log/nginx
    local f out dir dec
    for f in loxone-access loxone-error loxprox-trap loxprox-unknown; do touch "/var/log/nginx/$f.log"; done
    # 2026-10-21: trap-exempt sources (an address and an IPv4 + IPv6 network),
    # read by cs_configure's configure_crowdsec. The hand-made stopgap of the
    # same path and parser name is taken over.
    local xwl="$CROWDSEC_TRAP_EXEMPT_WHITELIST"
    # shellcheck disable=SC2034
    TRAP_EXEMPT_IPS=("203.0.113.50" "203.0.113.128/25" "2001:db8:5::/48")
    mkdir -p "$(dirname "$xwl")"
    printf '%s\n' '# stopgap' 'name: loxprox/trap-exempt' 'whitelist:' '  reason: "stopgap"' '  ip:' '    - "203.0.113.99"' > "$xwl"
    if cs_configure ban; then
        pass "configure_crowdsec returns 0 against the real CrowdSec ($(cscli version 2>&1 | awk '/version:/ {print $2; exit}'))"
    else
        fail "configure_crowdsec failed — deploy log and crowdsec journal below"
        tail -25 "$LOG_FILE" | sed 's/^/    /'
        journalctl -u crowdsec -n 25 --no-pager -o cat | sed 's/^/    /'
    fi
    systemctl is-active --quiet crowdsec && pass "crowdsec active with the managed profiles.yaml, config.yaml.local, scenarios and acquisition" \
                                         || fail "crowdsec NOT active"
    grep -q 'LOXPROX-MANAGED' "$CROWDSEC_PROFILES" && pass "managed profiles.yaml in place (not rolled back)" || fail "profiles.yaml rolled back — CrowdSec rejected it"
    out=$(cscli config show-yaml 2>/dev/null)
    grep -qE '^ +max_age: +400d$' <<<"$out" && grep -qE '^ +max_items: +100000$' <<<"$out" \
        && pass "config.yaml.local merged: flush max_age 400d, max_items 100000" || fail "merged config lacks the flush settings: $(grep -A3 'flush:' <<<"$out" | tr '\n' ' ')"
    out=$(cscli scenarios list 2>&1)
    for f in loxprox/scanner-trap loxprox/unknown-path loxprox/auth-bf; do
        grep -qF "$f" <<<"$out" && pass "scenario loaded: $f" || fail "scenario not listed: $f"
    done
    out=$(cscli simulation status 2>&1)
    grep -qF loxprox/auth-bf <<<"$out" && grep -qF loxprox/unknown-path <<<"$out" && ! grep -qF loxprox/scanner-trap <<<"$out" \
        && pass "simulation: auth-bf + unknown-path alert only, scanner-trap bans" || fail "simulation status: $out"
    grep -q 'LOXPROX-MANAGED' "$xwl" && grep -qx 'name: loxprox/trap-exempt' "$xwl" && grep -qx '    - "203.0.113.50"' "$xwl" \
        && grep -qx '    - "2001:db8:5::/48"' "$xwl" && ! grep -q '203.0.113.99' "$xwl" \
        && pass "trap-exempt whitelist: the hand-made stopgap replaced by the managed file ($xwl)" || fail "trap-exempt file: $(tr '\n' '|' < "$xwl")"
    out=$(cscli parsers list 2>&1)
    grep -qF 'loxprox/trap-exempt' <<<"$out" && pass "cscli parsers list: loxprox/trap-exempt loaded (local)" || fail "loxprox/trap-exempt not listed: $out"

    # Log routing, proven both ways with cscli explain (read-only, -no-api).
    explain() { (source "$REPO/test-gateway.sh"; _cs_explain "$@"); }
    out=$(explain loxprox-trap.log 198.51.100.7 "GET /.env" 444)
    grep -qF 'crowdsecurity/nginx-logs' <<<"$out" && pass "explain: crowdsecurity/nginx-logs parses a trap-log line" || fail "trap-log line not parsed"
    grep -qF 'loxprox/scanner-trap' <<<"$out" && pass "explain: a trap-log line fires loxprox/scanner-trap" || { fail "trap-log line did not reach loxprox/scanner-trap"; note "$out"; }
    grep -qF '[whitelisted]' <<<"$out" && fail "explain: the non-exempt 198.51.100.7 was whitelisted" \
                                       || pass "explain: non-exempt 198.51.100.7 is not whitelisted (reaches loxprox/scanner-trap)"
    # TRAP_EXEMPT_IPS: the same trap-log line from an exempt address / network.
    for f in 203.0.113.50 203.0.113.200; do
        out=$(explain loxprox-trap.log "$f" "GET /dev/sys/getcertificate" 444)
        if grep -qE 'loxprox/trap-exempt .*\[whitelisted\]' <<<"$out" && grep -qF 'ignored by whitelist' <<<"$out" \
                && ! grep -qF 'loxprox/scanner-trap' <<<"$out"; then
            pass "explain: a trap-log line from exempt $f is whitelisted by loxprox/trap-exempt, never reaches loxprox/scanner-trap"
            note "$(grep -E 'loxprox/trap-exempt|ignored by whitelist' <<<"$out" | tr -s '\t ' ' ' | tr '\n' ';')"
        else
            fail "explain: exempt $f not whitelisted"; note "$out"
        fi
    done
    out=$(explain loxone-access.log 198.51.100.7 "GET /.env" 444)
    grep -qF 'loxprox/scanner-trap' <<<"$out" && fail "explain: the same line in the access log fired scanner-trap" || pass "explain: the same line in loxone-access.log does not (routing by evt.Line.Src)"
    out=$(explain loxone-access.log 198.51.100.7 "GET /jdev/cfg/api" 200)
    grep -qF 'loxprox/' <<<"$out" && fail "explain: a normal app line reached a loxprox scenario" || pass "explain: a normal app line reaches no loxprox scenario"
    out=$(explain loxprox-unknown.log 198.51.100.7 "GET /ci/unknown" 200)
    grep -qF 'loxprox/unknown-path' <<<"$out" && pass "explain: an unknown-log line pours into loxprox/unknown-path" || fail "unknown-log line not routed"
    out=$(explain loxone-access.log 198.51.100.7 "GET /jdev/sys/getkey2/<redacted>" 200)
    grep -qF 'loxprox/auth-bf' <<<"$out" && pass "explain: a scrubbed getkey2 line pours into loxprox/auth-bf" || fail "auth line not routed to auth-bf"
    out=$(explain loxprox-unknown.log 198.51.100.7 "GET /jdev/sys/getkey2/<redacted>" 200)
    grep -qF 'loxprox/auth-bf' <<<"$out" && fail "auth-bf counted a line from the unknown log" || pass "auth-bf reads the main access log only"

    # End to end through the running LAPI and the managed profiles: an agent
    # (-no-api) replays the lines and pushes the alerts.
    local now
    now=$(LC_ALL=C date '+%d/%b/%Y:%H:%M:%S %z')

    # TRAP_BAN_MODE=observe (deploy.conf switch): the trap hit becomes an
    # alert whose decision is only simulated — nothing enforces it.
    if cs_configure observe; then
        out=$(cscli simulation status 2>&1)
        grep -qF loxprox/scanner-trap <<<"$out" && pass "TRAP_BAN_MODE=observe: deploy put scanner-trap in simulation before the restart" \
                                               || fail "observe mode: scanner-trap not simulated: $out"
        dir=$(mktemp -d /var/tmp/loxprox-replay.XXXXXX)
        printf '198.51.100.9 - - [%s] "GET /.env HTTP/1.1" 444 0 "-" "ci"\n' "$now" > "$dir/loxprox-trap.log"
        timeout 180 crowdsec -c /etc/crowdsec/config.yaml -dsn "file://$dir/loxprox-trap.log" -type nginx -no-api >>"$LOG_FILE" 2>&1 \
            || note "observe replay exited $? (see $LOG_FILE)"
        sleep 5
        local alerts enforced
        alerts=$(cscli alerts list --ip 198.51.100.9 --limit 0 -o json 2>/dev/null \
                 | jq -r '[.[]? | select(.scenario == "loxprox/scanner-trap")] | length' 2>/dev/null)
        dec=$(cscli decisions list --limit 0 -o json 2>/dev/null)
        enforced=$(jq -r '[.[]?.decisions[]? | select(.value == "198.51.100.9" and (.simulated | not))] | length' <<<"$dec" 2>/dev/null)
        out="alerts=${alerts:-?} enforced=${enforced:-?}"
        [[ "$out" =~ ^alerts=[1-9][0-9]*\ enforced=0$ ]] \
            && pass "observe mode: the replayed trap hit is an alert, its decision simulated only — no ban ($out)" \
            || fail "observe replay: '${out:-none}'"
        cscli decisions delete --ip 198.51.100.9 >/dev/null 2>&1 || true
        cscli alerts delete --ip 198.51.100.9 >/dev/null 2>&1 || true
        rm -rf "$dir"
    else
        fail "configure_crowdsec with TRAP_BAN_MODE=observe failed"
    fi
    # Back to ban: the next deploy takes the trap out of simulation again.
    cs_configure ban || fail "configure_crowdsec with TRAP_BAN_MODE=ban failed"
    out=$(cscli simulation status 2>&1)
    grep -qF loxprox/scanner-trap <<<"$out" && fail "TRAP_BAN_MODE=ban: scanner-trap still simulated: $out" \
                                           || pass "TRAP_BAN_MODE=ban: deploy took scanner-trap out of simulation"

    dir=$(mktemp -d /var/tmp/loxprox-replay.XXXXXX)
    printf '198.51.100.7 - - [%s] "GET /.env HTTP/1.1" 444 0 "-" "ci"\n' "$now" > "$dir/loxprox-trap.log"
    printf '203.0.113.50 - - [%s] "GET /.env HTTP/1.1" 444 0 "-" "ci"\n' "$now" >> "$dir/loxprox-trap.log"
    for f in $(seq 1 12); do
        printf '198.51.100.8 - - [%s] "GET /ci-probe-%s HTTP/1.1" 404 0 "-" "ci"\n' "$now" "$f"
    done > "$dir/loxone-access.log"
    for f in loxprox-trap.log loxone-access.log; do
        timeout 180 crowdsec -c /etc/crowdsec/config.yaml -dsn "file://$dir/$f" -type nginx -no-api >>"$LOG_FILE" 2>&1 \
            || note "replay of $f exited $? (see $LOG_FILE)"
    done
    sleep 5
    dec=$(cscli decisions list --limit 0 -o json 2>/dev/null)
    out=$(jq -r '[.[]?.decisions[]? | select(.value == "198.51.100.7")][0] | "\(.scenario) \(.duration)"' <<<"$dec" 2>/dev/null)
    [[ "$out" =~ ^loxprox/scanner-trap\ 16[78]h ]] && pass "trap hit → loxprox_hard_ip profile → first HARD ban ($out)" || fail "trap replay decision: '${out:-none}'"
    out=$(jq -r '[.[]?.decisions[]? | select(.value == "198.51.100.8")][0] | "\(.scenario) \(.duration)"' <<<"$dec" 2>/dev/null)
    [[ "$out" =~ ^crowdsecurity/http-probing\ 2[34]h ]] && pass "an ambiguous scenario → default profile → first SOFT ban ($out)" || fail "SOFT replay decision: '${out:-none}'"
    out=$(jq -r '[.[]?.decisions[]? | select(.value == "203.0.113.50")] | length' <<<"$dec" 2>/dev/null)
    f=$(cscli alerts list --ip 203.0.113.50 --limit 0 -o json 2>/dev/null | jq -r 'length' 2>/dev/null)
    [[ "$out" == "0" && "${f:-0}" =~ ^(0|null)$ ]] && pass "the same trap hit from exempt 203.0.113.50: no alert, no decision" \
                                                || fail "exempt replay: decisions=${out:-?} alerts=${f:-?}"
    cscli decisions delete --ip 198.51.100.7 >/dev/null 2>&1 || true
    cscli decisions delete --ip 198.51.100.8 >/dev/null 2>&1 || true
    rm -rf "$dir"

    # An empty TRAP_EXEMPT_IPS removes the whitelist; the trap bans that source again.
    # shellcheck disable=SC2034
    TRAP_EXEMPT_IPS=()
    cs_configure ban || fail "configure_crowdsec with an empty TRAP_EXEMPT_IPS failed"
    systemctl is-active --quiet crowdsec && [[ ! -e "$xwl" ]] && ! grep -qF 'loxprox/trap-exempt' <<<"$(cscli parsers list 2>&1)" \
        && pass "empty TRAP_EXEMPT_IPS: whitelist file removed, parser gone, crowdsec active" || fail "removal: file $(ls "$xwl" 2>&1), crowdsec $(systemctl is-active crowdsec)"
    out=$(explain loxprox-trap.log 203.0.113.50 "GET /dev/sys/getcertificate" 444)
    grep -qF 'loxprox/scanner-trap' <<<"$out" && ! grep -qF '[whitelisted]' <<<"$out" \
        && pass "explain: without the exemption, 203.0.113.50's trap-log line reaches loxprox/scanner-trap" || { fail "post-removal explain"; note "$out"; }
}

# The package's crowdsec-hubupdate.timer runs `cscli hub upgrade` on EVERY
# installed item nightly, with no snapshot and no rollback. deploy.sh's
# _loxprox_mask_package_hubupdate against the real unit and the real systemd:
# masked, stopped, idempotent, and still masked after what the package itself
# does — its postinst's `systemctl enable --now` and a package reinstall.
t_crowdsec_hubupdate() {
    section "CrowdSec — the package's crowdsec-hubupdate.timer is masked (2026-10)"
    local unit=crowdsec-hubupdate.timer inst out rc ver
    if [[ -z "$(systemctl list-unit-files --no-legend "$unit" 2>/dev/null)" ]]; then
        fail "$unit is not shipped by this CrowdSec package — the real-unit checks cannot run"
        return
    fi
    out=$(systemctl is-enabled "$unit" 2>/dev/null)
    [[ "$out" == enabled ]] && pass "the package enabled $unit (the blanket nightly upgrade)" || note "$unit was '$out' before the mask step"

    # The first mask must hit an ACTIVE timer: that is where `mask --now`
    # left the unit failed ("Unit to trigger vanished").
    systemctl start "$unit" >>"$LOG_FILE" 2>&1 || true
    systemctl is-active --quiet "$unit" \
        && pass "$unit is active before the first mask (the case that used to fail)" \
        || fail "$unit is not active before the first mask — the failed-state check below would be vacuous"

    inst=$(mktemp -d /var/tmp/loxprox-hubupdate.XXXXXX)
    install -m 0755 "$REPO/security-monitoring/hub-refresh.sh" "$inst/hub-refresh.sh"
    if (LOXPROX_INSTALL_DIR="$inst"; _loxprox_mask_package_hubupdate) >>"$LOG_FILE" 2>&1; then
        pass "_loxprox_mask_package_hubupdate returns 0"
    else
        fail "_loxprox_mask_package_hubupdate returned non-zero"
    fi
    out=$(systemctl is-enabled "$unit" 2>/dev/null)
    [[ "$out" == masked ]] && pass "$unit is masked" || fail "$unit is '$out' after the mask step"
    [[ "$(readlink "/etc/systemd/system/$unit")" == /dev/null ]] \
        && pass "persistent mask: /etc/systemd/system/$unit → /dev/null" || fail "no persistent mask link: $(ls -l "/etc/systemd/system/$unit" 2>&1)"
    systemctl is-active --quiet "$unit" && fail "$unit is still active (scheduled)" || pass "$unit stopped — no longer scheduled"
    if systemctl is-failed --quiet "$unit" || systemctl --failed --no-legend --plain 2>/dev/null | grep -q "^$unit"; then
        fail "$unit is in failed state after the first mask of an active timer: $(systemctl is-failed "$unit" 2>&1)"
    else
        pass "$unit not failed after first mask of an active timer"
    fi
    if (LOXPROX_INSTALL_DIR="$inst"; _loxprox_mask_package_hubupdate) >>"$LOG_FILE" 2>&1 \
            && [[ "$(systemctl is-enabled "$unit" 2>/dev/null)" == masked ]]; then
        pass "a second deploy run: still masked, returns 0"
        systemctl is-failed --quiet "$unit" && fail "$unit failed after the second run" || pass "$unit not failed after the second run"
    else
        fail "second run: $(systemctl is-enabled "$unit" 2>&1)"
    fi

    # The line the package's postinst runs on every configure (with || true).
    systemctl enable --now "$unit" >/dev/null 2>&1 \
        && fail "systemctl enable --now succeeded on the masked timer" \
        || pass "the postinst's 'systemctl enable --now $unit' is refused while masked"
    [[ "$(systemctl is-enabled "$unit" 2>/dev/null)" == masked ]] && ! systemctl is-active --quiet "$unit" \
        && pass "…and it stays masked and inactive" || fail "after enable --now: $(systemctl is-enabled "$unit" 2>&1)"
    # The whole maintainer-script path of a package upgrade, same version.
    ver=$(dpkg-query -W -f='${Version}' crowdsec 2>/dev/null)
    DEBIAN_FRONTEND=noninteractive timeout 600 apt-get install -y -qq --reinstall "crowdsec=$ver" >>"$LOG_FILE" 2>&1; rc=$?
    if (( rc == 0 )); then
        pass "package reinstall (crowdsec $ver) ran its maintainer scripts"
    else
        fail "apt-get install --reinstall crowdsec=$ver exited $rc — log below"
        tail -15 "$LOG_FILE" | sed 's/^/    /'
    fi
    out=$(systemctl is-enabled "$unit" 2>/dev/null)
    [[ "$out" == masked ]] && ! systemctl is-active --quiet "$unit" \
        && pass "…and $unit is still masked and inactive afterwards" || fail "after the package reinstall $unit is '$out'"

    # A unit this systemd does not know: nothing to mask, nothing created.
    note "systemd's is-enabled for an unknown unit prints: '$(systemctl is-enabled loxprox-ci-absent.timer 2>/dev/null)'"
    # shellcheck disable=SC2034  # read by deploy.sh's _loxprox_mask_package_hubupdate
    out=$( (LOXPROX_INSTALL_DIR="$inst" CROWDSEC_HUBUPDATE_TIMER=loxprox-ci-absent.timer; _loxprox_mask_package_hubupdate) 2>&1 ); rc=$?
    if [[ $rc -eq 0 ]] && grep -q 'not present' <<<"$out" \
            && [[ ! -e /etc/systemd/system/loxprox-ci-absent.timer && ! -L /etc/systemd/system/loxprox-ci-absent.timer ]]; then
        pass "an absent unit → 'not present', returns 0, no mask link created"
    else
        fail "absent unit: rc=$rc out: $out"
    fi
    rm -rf "$inst"
}

# hub-refresh.sh against the real CrowdSec (installed by the CI step, after
# t_crowdsec): where this install keeps its hub, a full daily run with Discord
# stubbed, what the snapshot holds, a tamper → restore round trip, and the
# fail-safe for a hub_dir that does not exist (the first version assumed
# /var/lib/crowdsec/hub). cscli is wrapped to record its calls.
t_crowdsec_hub_refresh() {
    section "CrowdSec — hub-refresh.sh on the real hub: layout, full run, snapshot, restore (2026-10)"
    command -v cscli >/dev/null || { fail "cscli missing — install crowdsec first"; return; }
    local hr="$REPO/security-monitoring/hub-refresh.sh" real w hub index link item snap x rc line
    real=$(command -v cscli)
    hub=$(cscli config show --key Config.ConfigPaths.HubDir 2>/dev/null)
    index=$(cscli config show --key Config.ConfigPaths.HubIndexFile 2>/dev/null)
    note "cscli config show: HubDir='$hub' HubIndexFile='$index' ConfigDir='$(cscli config show --key Config.ConfigPaths.ConfigDir 2>/dev/null)'"
    note "config.yaml: $(grep -E '^[[:space:]]+(config_dir|hub_dir|index_path):' /etc/crowdsec/config.yaml 2>/dev/null | tr -s ' ' | tr '\n' ';')"
    if [[ -d /var/lib/crowdsec/hub ]]; then note "/var/lib/crowdsec/hub exists"; else note "/var/lib/crowdsec/hub does not exist"; fi
    hub="${hub%/}"
    if [[ -d "$hub" && -s "$index" ]]; then
        pass "this install's hub: $hub, index $index"
    else
        fail "hub_dir '$hub' / index '$index' not found"
        return
    fi

    # Production runs AppSec; t_crowdsec configured CrowdSec without it.
    cscli collections install crowdsecurity/appsec-virtual-patching --error >>"$LOG_FILE" 2>&1 \
        || note "installing crowdsecurity/appsec-virtual-patching returned non-zero"
    link=/etc/crowdsec/collections/http-cve.yaml
    item=$(readlink -f "$link" 2>/dev/null)
    if [[ -L "$link" && -f "$item" && "$item" == "$hub"/* ]]; then
        pass "installed item $link → $item (a link into hub_dir)"
    else
        fail "http-cve is not a link into hub_dir: $(ls -l "$link" 2>&1)"
        return
    fi
    note "hub item states: $(cscli hub list -o json 2>/dev/null | jq -r '[.. | objects | select(has("status")) | .status] | group_by(.) | map("\(.[0]) ×\(length)") | join(", ")' 2>/dev/null)"

    w=$(mktemp -d /var/tmp/loxprox-hubrefresh.XXXXXX)
    mkdir -p "$w/bin"
    cat > "$w/discord.sh" <<EOF
#!/bin/bash
printf '%s|%s|%s\n' "\$1" "\$2" "\$3" >> "$w/discord.log"
EOF
    cat > "$w/bin/cscli" <<EOF
#!/bin/bash
echo "\$*" >> "$w/cscli.calls"
exec "$real" "\$@"
EOF
    chmod +x "$w/discord.sh" "$w/bin/cscli"
    : > "$w/discord.log"; : > "$w/cscli.calls"
    # hub-refresh.sh with Discord stubbed and its state under $w; "$@" = extra VAR=value.
    hr_run() {
        env LOXPROX_CONFIG=/nonexistent DISCORD_ALERT_PATH="$w/discord.sh" LOXPROX_HUB_LOG="$w/hub.log" \
            LOXPROX_HUB_LOCK="$w/lock" LOXPROX_HUB_SNAPSHOT_DIR="$w/snapshots" LOXPROX_HUB_OUTDATED_STATE="$w/outdated" \
            PATH="$w/bin:$PATH" "$@" timeout 900 bash "$hr" >>"$LOG_FILE" 2>&1
    }

    # 1. The full daily run.
    hr_run; rc=$?
    note "hub-refresh.sh log:"
    grep -E 'layout|snapshot|Upgraded|eload|not upgraded|unreadable|failed|FAILED|active|finished' "$w/hub.log" | sed 's/^/      /'
    if [[ $rc -eq 0 ]] && systemctl is-active --quiet crowdsec; then
        pass "full run of hub-refresh.sh against CrowdSec $(cscli version 2>&1 | awk '/version:/ {print $2; exit}'): exit 0, crowdsec active"
    else
        fail "full run: rc=$rc, crowdsec $(systemctl is-active crowdsec); Discord: $(tr '\n' ';' < "$w/discord.log")"
    fi
    grep -qF "CrowdSec layout: hub_dir=$hub index=$index" "$w/hub.log" \
        && pass "it used the hub_dir CrowdSec reports" || fail "layout: $(grep layout "$w/hub.log")"
    line=$(grep -o 'index + [0-9]* installed hub items verified' "$w/hub.log" || true)
    [[ -n "$line" ]] && pass "snapshot checked before the upgrade: $line" || fail "no verified snapshot in the log"
    grep -qx 'hub upgrade' "$w/cscli.calls" && ! grep -q -- '--force' "$w/cscli.calls" \
        && pass "it ran 'cscli hub upgrade', without --force" || fail "cscli calls: $(tr '\n' ';' < "$w/cscli.calls")"
    grep -qE '^(WARNING|CRITICAL)\|' "$w/discord.log" && fail "WARNING/CRITICAL alert: $(cat "$w/discord.log")" || pass "no WARNING or CRITICAL alert"
    note "Discord stub got: $(cut -d'|' -f1,2 "$w/discord.log" | tr '\n' ';')"

    # 2. What the snapshot holds.
    snap=$(find "$w/snapshots" -name 'hub-*.tar.gz' 2>/dev/null | sort | tail -n 1)
    x="$w/x"; mkdir -p "$x"
    if [[ -n "$snap" ]] && tar -xzf "$snap" -C "$x" 2>/dev/null; then
        [[ -f "$x$index" && ! -L "$x$index" ]] \
            && pass "the tarball holds the hub index $index (regular file, $(stat -c %s "$x$index") bytes)" || fail "index not in the tarball"
        [[ -s "$x$item" && ! -L "$x$item" ]] \
            && pass "…the real item file $item (not a link)" || fail "item file not in the tarball: $(ls -l "$x$item" 2>&1)"
        [[ -L "$x$link" ]] && pass "…and the installed-item link $link" || fail "link not in the tarball"
        note "tar -tv: $(tar -tvzf "$snap" 2>/dev/null | grep -E 'http-cve|\.index\.json' | tr -s ' ' | tr '\n' ';')"
    else
        fail "no snapshot tarball under $w/snapshots"
    fi

    # 3. Tamper with an installed item and add a file, then the rollback's restore.
    printf '\n# loxprox-ci-tamper\n' >> "$item"
    echo stray > "$hub/loxprox-ci-stray.yaml"
    cmp -s "$item" "$x$item" && fail "the tamper did not change $item"
    env LOXPROX_CONFIG=/nonexistent PATH="$w/bin:$PATH" LOXPROX_HUB_LOG="$w/hub.log" LOXPROX_HUB_SNAPSHOT_DIR="$w/snapshots" \
        bash -c 'source "$1" && set +e && resolve_layout && restore_snapshot "$2"' _ "$hr" "$snap" >>"$LOG_FILE" 2>&1; rc=$?
    [[ $rc -eq 0 ]] && pass "restore_snapshot (the rollback's restore) returns 0" || fail "restore_snapshot returned $rc"
    cmp -s "$item" "$x$item" && pass "the tampered $item has the snapshot's content back" || fail "item content not restored"
    [[ ! -e "$hub/loxprox-ci-stray.yaml" ]] && pass "a file added to hub_dir after the snapshot is gone" || fail "stray file survived the restore"
    [[ "$(readlink -f "$link")" == "$item" ]] && pass "$link still resolves to it" || fail "$link → $(readlink -f "$link")"
    systemctl restart crowdsec >/dev/null 2>&1
    for _ in $(seq 1 30); do systemctl is-active --quiet crowdsec && break; sleep 1; done
    if systemctl is-active --quiet crowdsec; then
        pass "crowdsec active after the restore and a restart"
    else
        fail "crowdsec not active after the restore — journal below"
        journalctl -u crowdsec -n 25 --no-pager -o cat | sed 's/^/    /'
    fi

    # 4. Fail-safe: the first version's hub_dir.
    : > "$w/discord.log"; : > "$w/cscli.calls"
    hr_run LOXPROX_CROWDSEC_HUB_DIR=/var/lib/crowdsec/hub; rc=$?
    line=$(grep '^WARNING|CrowdSec Hub Snapshot Failed|' "$w/discord.log" || true)
    if [[ $rc -eq 1 && -n "$line" ]] && ! grep -qE '^hub (update|upgrade)' "$w/cscli.calls"; then
        line="${line#*|*|}"
        pass "hub_dir /var/lib/crowdsec/hub → no hub update, no upgrade, WARNING: ${line:0:160}"
    else
        fail "fail-safe: rc=$rc Discord: $(cat "$w/discord.log") cscli: $(tr '\n' ';' < "$w/cscli.calls")"
    fi
    rm -rf "$w"
}

# ── CrowdSec file acquisition across logrotate (2026-10-21) ──────────────────
# Production lost its log-based detection at the nightly logrotate: crowdsec.log
# showed "file reader died : Failed to detect creation of /var/log/nginx/<log>:
# inotify watcher has been closed", and CrowdSec's read counters for the nginx
# logs stopped until the next restart. acquis.d held cscli setup's
# setup.nginx.yaml (/var/log/nginx/*.log) beside deploy.sh's nginx.yaml and
# loxprox.yaml, so every LoxProx log was tailed twice. CrowdSec 1.8.1's tail
# library (nxadm/tail 1.4.11) runs ONE inotify tracker per process and keys its
# event channel by file name: two tailers of one file share that channel, and
# each closes it for the other when logrotate renames the file.
#
# The real CrowdSec, the real logrotate and deploy.sh's own logrotate config.
# Every cycle writes RT_M lines to each log, rotates, writes RT_M more, and
# compares what CrowdSec read of each file (cs_filesource_hits_total) with
# what a reader per tailer should have read; CrowdSec's own "Starting tail"
# lines say how many tailers a file has, its "file reader died" lines are kept.
#   A   production's acquisition, crowdsec restarted before every rotation
#       (the first rotation after a start is the one that splits a pair) —
#       evidence, never a failure: the race need not lose on every runner;
#   B   the same host after deploy.sh's configure_crowdsec: every check gates;
#   B2  B's acquisition through consecutive rotations without a restart —
#       what production does night after night;
#   C   B with poll_without_inotify: true — information only.
# The lines come from 192.168.1.77 (CROWDSEC_WHITELIST_IPS): nothing is banned.

RT_NGINX=/var/log/nginx
RT_CSLOG=/var/log/crowdsec.log
RT_M=5
RT_LOGS=(loxone-access loxone-error loxprox-trap loxprox-unknown loxprox-trap-hosts appsec-detections access error)
RT_W=""
RT_RESTART_OFF=0

# What CrowdSec has read so far, "path count" per file it tails (the counter
# sums every datasource that reads the path).
rt_reads() {
    curl -s --max-time 5 http://127.0.0.1:6060/metrics 2>/dev/null | awk '
        /^cs_filesource_hits_total\{/ && match($0, /source="[^"]*"/) { n[substr($0, RSTART + 8, RLENGTH - 9)] += $NF }
        END { for (s in n) printf "%s %.0f\n", s, n[s] }'
}

# rt_load NAME — rt_reads into the associative array NAME.
rt_load() {
    local -n _rt_a="$1"
    local p c
    # shellcheck disable=SC2034  # written through the nameref
    _rt_a=()
    while read -r p c; do
        # shellcheck disable=SC2034
        _rt_a[$p]=$c
    done < <(rt_reads)
}

# RT_M nginx access-log lines, tagged $1, appended to every log.
rt_write() {
    local f i ts
    ts=$(LC_ALL=C date '+%d/%b/%Y:%H:%M:%S %z')
    for f in "${RT_LOGS[@]}"; do
        for (( i = 1; i <= RT_M; i++ )); do
            printf '192.168.1.77 - - [%s] "GET /ci-rotation/%s/%s HTTP/1.1" 200 0 "-" "loxprox-ci"\n' "$ts" "$1" "$i"
        done >> "$RT_NGINX/$f.log"
    done
}

# One nightly rotation, as production's cron.daily logrotate run does it:
# deploy.sh's loxone-nginx config, then the stock nginx stanza for access.log
# and error.log. 0 when the access log was really rotated (new inode).
rt_rotate() {
    local before
    before=$(stat -c %i "$RT_NGINX/loxone-access.log" 2>/dev/null)
    logrotate -f -s "$RT_W/logrotate.state" "$RT_W/loxone-nginx" "$RT_W/nginx-stock" >>"$RT_W/logrotate.out" 2>&1
    [[ "$(stat -c %i "$RT_NGINX/loxone-access.log" 2>/dev/null)" != "$before" ]]
}

# Restarts crowdsec and waits until it has started at least $1 tailers under
# /var/log/nginx; RT_RESTART_OFF is crowdsec.log's size before the restart.
rt_restart() {
    local n=0
    RT_RESTART_OFF=$(stat -c %s "$RT_CSLOG" 2>/dev/null || echo 0)
    systemctl restart crowdsec >>"$LOG_FILE" 2>&1 || return 1
    for _ in $(seq 1 120); do
        n=$(tail -c +$((RT_RESTART_OFF + 1)) "$RT_CSLOG" 2>/dev/null | grep -F 'msg="Starting tail' | grep -cF "file=$RT_NGINX/")
        (( n >= $1 )) && break
        sleep 0.25
    done
    sleep 2   # each tailer opens its file and seeks to the end in its own goroutine
    (( n >= $1 ))
}

# rt_tails NAME — tailers per file since the last rt_restart, from CrowdSec's
# own "Starting tail … file=<path>" lines, into the associative array NAME.
rt_tails() {
    local -n _rt_t="$1"
    local f
    # shellcheck disable=SC2034  # written through the nameref
    _rt_t=()
    while read -r f; do
        # shellcheck disable=SC2034
        _rt_t[$f]=$(( ${_rt_t[$f]:-0} + 1 ))
    done < <(tail -c +$((RT_RESTART_OFF + 1)) "$RT_CSLOG" 2>/dev/null | grep -F 'msg="Starting tail' \
             | sed -nE "s#.* file=($RT_NGINX/[^ ]+).*#\1#p")
}

# rt_arm NAME CYCLES PER_RESTART MIN_TAILERS — CYCLES rotations; crowdsec is
# restarted before every cycle (PER_RESTART=1) or only before the first.
# One note line per cycle: "<log> <read before>→<read after the rotation>".
# Afterwards:
#   RT_TAILS    " file:n" — tailers per file
#   RT_PRE      files whose reads BEFORE a rotation were not n × RT_M
#   RT_LOST     " file:k/CYCLES" — rotations after which a file had fewer readers
#   RT_STOPPED  " file:k/CYCLES" — rotations after which CrowdSec read nothing of it
#   RT_DEATHS   CrowdSec's "file reader died" lines during the arm
#   RT_REOPEN   CrowdSec's "Re-opening moved/deleted file" lines during the arm
#   RT_ROTATED  rotations that really happened
rt_arm() {
    local name="$1" cycles="$2" per_restart="$3" min="$4" k f b d1 d2 want off line
    local -A pre=() mid=() post=() tails=() lost=() stopped=()
    RT_PRE="" RT_TAILS="" RT_LOST="" RT_STOPPED="" RT_DEATHS="" RT_REOPEN=0 RT_ROTATED=0
    off=$(stat -c %s "$RT_CSLOG" 2>/dev/null || echo 0)
    for (( k = 1; k <= cycles; k++ )); do
        if (( per_restart || k == 1 )); then
            if ! rt_restart "$min"; then
                fail "$name: crowdsec did not come back with at least $min nginx tailers (cycle $k)"
                journalctl -u crowdsec -n 20 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
                return 1
            fi
            rt_tails tails
        fi
        rt_load pre; rt_write "$name-$k-a"; sleep 3; rt_load mid
        rt_rotate && RT_ROTATED=$((RT_ROTATED + 1))
        sleep 1; rt_write "$name-$k-b"; sleep 3; rt_load post
        line=""
        for f in $(printf '%s\n' "${!tails[@]}" | LC_ALL=C sort); do
            b=$(basename "$f")
            want=$(( ${tails[$f]} * RT_M ))
            d1=$(( ${mid[$f]:-0} - ${pre[$f]:-0} ))
            d2=$(( ${post[$f]:-0} - ${mid[$f]:-0} ))
            (( d1 == want )) || RT_PRE+=" $b(#$k: $d1 of $want)"
            if (( d2 == 0 )); then
                stopped[$b]=$(( ${stopped[$b]:-0} + 1 ))
            elif (( d2 < want )); then
                lost[$b]=$(( ${lost[$b]:-0} + 1 ))
            fi
            line+=" ${b%.log} ${d1}→${d2}"
        done
        note "$name #$k:$line"
    done
    for f in $(printf '%s\n' "${!tails[@]}" | LC_ALL=C sort); do RT_TAILS+=" $(basename "$f"):${tails[$f]}"; done
    for b in $(printf '%s\n' "${!lost[@]}" | LC_ALL=C sort); do RT_LOST+=" $b:${lost[$b]}/$cycles"; done
    for b in $(printf '%s\n' "${!stopped[@]}" | LC_ALL=C sort); do RT_STOPPED+=" $b:${stopped[$b]}/$cycles"; done
    RT_DEATHS=$(tail -c +$((off + 1)) "$RT_CSLOG" 2>/dev/null | grep -F 'file reader died')
    RT_REOPEN=$(tail -c +$((off + 1)) "$RT_CSLOG" 2>/dev/null | grep -cF 'Re-opening moved/deleted file')
    return 0
}

# The death lines, shortened to time + message + file.
rt_show_deaths() {
    [[ -n "$RT_DEATHS" ]] || return 0
    sed -E 's/^time="([^"]+)".*msg="([^"]+)".* tail=([^ ]+).*/\1 \2 [\3]/' <<<"$RT_DEATHS" | head -n "${1:-8}" | sed 's/^/      /'
}

# test-gateway.sh's reading of the acquisition files (what it checks on a
# gateway) next to CrowdSec's own tailers: same " file:n" form as RT_TAILS.
rt_static_tails() {
    (source "$REPO/test-gateway.sh"; _cs_acquired_paths "$CROWDSEC_DIR") 2>/dev/null \
        | awk -F'\t' -v d="$RT_NGINX/" 'index($1, d) == 1 {n[$1]++} END {for (f in n) print f, n[f]}' | LC_ALL=C sort \
        | while read -r f n; do printf ' %s:%s' "${f##*/}" "$n"; done
}

# The gates for an arm whose acquisition must be deploy.sh's (B, B2).
rt_gates() {
    local name="$1" cycles="$2" want=" access.log:1 error.log:1 loxone-access.log:1 loxone-error.log:1 loxprox-trap.log:1 loxprox-unknown.log:1"
    [[ "$RT_TAILS" == "$want" ]] \
        && pass "$name: one tailer per acquired log, trap-hosts and AppSec logs not tailed:$RT_TAILS" \
        || fail "$name: tailers per log:$RT_TAILS (want:$want)"
    [[ "$RT_ROTATED" == "$cycles" ]] && pass "$name: $cycles rotations by the deployed logrotate config" \
                                     || fail "$name: only $RT_ROTATED of $cycles rotations happened: $(tail -n 5 "$RT_W/logrotate.out" | tr '\n' ' ')"
    [[ -z "$RT_PRE" ]] && pass "$name: before every rotation each line read exactly once" || fail "$name: reads before a rotation:$RT_PRE"
    if [[ -z "$RT_LOST$RT_STOPPED" ]]; then
        pass "$name: after every rotation CrowdSec read every new line of every log"
    else
        fail "$name: after a rotation — fewer readers:${RT_LOST:- none}; nothing read:${RT_STOPPED:- none}"
    fi
    if [[ -z "$RT_DEATHS" ]]; then
        pass "$name: no 'file reader died' in crowdsec.log ($RT_REOPEN reopens)"
    else
        fail "$name: $(grep -c . <<<"$RT_DEATHS") 'file reader died' in crowdsec.log:"
        rt_show_deaths
    fi
}

t_crowdsec_rotation() {
    section "CrowdSec — file acquisition across logrotate: production's layout vs deploy.sh's (2026-10-21)"
    command -v cscli >/dev/null || { fail "cscli missing — install crowdsec first"; return; }
    command -v logrotate >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate >>"$LOG_FILE" 2>&1
    command -v logrotate >/dev/null || { fail "logrotate missing"; return; }
    if ! id www-data >/dev/null 2>&1 || ! getent group adm >/dev/null 2>&1; then
        fail "user www-data / group adm missing (the logrotate configs create files as www-data:adm)"; return
    fi
    [[ -f "$RT_CSLOG" ]] || { fail "$RT_CSLOG missing — CrowdSec logs elsewhere ($(cscli config show --key Config.Common.LogDir 2>&1))"; return; }
    local acq f out fake_pid="" cycles logoff
    acq=$(dirname "$CROWDSEC_NGINX_ACQUIS")
    RT_W=$(mktemp -d /var/tmp/loxprox-rotation.XXXXXX)
    note "CrowdSec $(cscli version 2>&1 | awk '/version:/ {print $2; exit}'), $(logrotate --version 2>&1 | head -n 1), $(nproc) CPUs"
    note "acquis.d before this section: $(cd "$acq" && ls | tr '\n' ' ')"

    mkdir -p "$RT_NGINX"
    for f in "${RT_LOGS[@]}"; do
        [[ -e "$RT_NGINX/$f.log" ]] || install -m 0640 -o www-data -g adm /dev/null "$RT_NGINX/$f.log"
    done
    # deploy.sh's logrotate config, and Debian 12's stock nginx stanza as
    # deploy.sh narrows it (its postrotate is `invoke-rc.d nginx rotate`, the
    # same USR1 as below).
    # shellcheck disable=SC2034  # consumed by deploy.sh's setup_logrotate
    ( LOGROTATE_CONF="$RT_W/loxone-nginx" LOXPROX_LOGROTATE_CONF="$RT_W/loxprox-logs" NGINX_STOCK_LOGROTATE="$RT_W/absent"
      setup_logrotate ) >>"$LOG_FILE" 2>&1
    if ! grep -qF "$RT_NGINX/loxprox-trap.log" "$RT_W/loxone-nginx" 2>/dev/null; then
        fail "setup_logrotate wrote no loxone-nginx config"; return
    fi
    cat > "$RT_W/nginx-stock" <<'EOF'
/var/log/nginx/access.log /var/log/nginx/error.log {
	daily
	missingok
	rotate 14
	compress
	delaycompress
	notifempty
	create 0640 www-data adm
	sharedscripts
	postrotate
		[ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
	endscript
}
EOF
    chmod 0644 "$RT_W/nginx-stock"
    # nginx itself is not under test: a stand-in that ignores USR1 lets the
    # deployed postrotate (kill -USR1 $(cat /var/run/nginx.pid)) succeed.
    if [[ ! -e /var/run/nginx.pid ]]; then
        bash -c 'trap "" USR1; exec sleep 7200' &
        fake_pid=$!
        echo "$fake_pid" > /var/run/nginx.pid
    fi

    # ── A: production's acquisition (read from the gateway 2026-10-21) ──
    # cscli setup's three files byte for byte (their checksums verify), and
    # deploy.sh's nginx.yaml / ssh.yaml as releases before 2026-10-21 wrote them.
    cat > "$acq/setup.nginx.yaml" <<'EOF'
#
# Configuration generated by "cscli setup".
# Please check your non-generated configuration files to make sure
# the log sources are not acquired twice. This includes
# the file acquis.yaml created by crowdsec <= 1.7.0.
#
# cscli-checksum: 9131e66b247aac7984402f0d16ff3a67

filenames:
  - /var/log/nginx/*.log
labels:
  type: nginx
source: file
EOF
    cat > "$acq/setup.sshd.yaml" <<'EOF'
#
# Configuration generated by "cscli setup".
# Please check your non-generated configuration files to make sure
# the log sources are not acquired twice. This includes
# the file acquis.yaml created by crowdsec <= 1.7.0.
#
# cscli-checksum: 2536c85258d4efc265e4627ced7e2903

journalctl_filter:
  - _SYSTEMD_UNIT=ssh.service
labels:
  type: syslog
source: journalctl
EOF
    cat > "$acq/setup.linux.yaml" <<'EOF'
#
# Configuration generated by "cscli setup".
# Please check your non-generated configuration files to make sure
# the log sources are not acquired twice. This includes
# the file acquis.yaml created by crowdsec <= 1.7.0.
#
# cscli-checksum: a380e4b3fc5e43e510e8287a3fcbe374

filenames:
  - /var/log/messages
  - /var/log/syslog
  - /var/log/kern.log
labels:
  type: syslog
source: file
EOF
    cp -a "$acq/setup.linux.yaml" "$RT_W/setup.linux.yaml"
    printf '%s\n' '# Nginx log acquisition' 'filenames:' '  - /var/log/nginx/loxone-access.log' \
        '  - /var/log/nginx/loxone-error.log' 'labels:' '  type: nginx' > "$CROWDSEC_NGINX_ACQUIS"
    printf '%s\n' '# SSH acquisition (Debian 12 — no sshd-session unit split)' 'filenames:' \
        '  - /var/log/auth.log' 'labels:' '  type: syslog' > "$CROWDSEC_SSH_ACQUIS"
    cmp -s "$REPO/crowdsec/acquis.d/loxprox.yaml" "$CROWDSEC_LOXPROX_ACQUIS" \
        || { fail "acquis.d/loxprox.yaml is not the repository's (run the crowdsec section first)"; return; }

    cycles="${RT_CYCLES_A:-15}"
    if rt_arm A "$cycles" 1 12; then
        [[ "$RT_TAILS" == " access.log:1 appsec-detections.log:1 error.log:1 loxone-access.log:2 loxone-error.log:2 loxprox-trap-hosts.log:1 loxprox-trap.log:2 loxprox-unknown.log:2" ]] \
            && pass "A: production's acquisition tails the four LoxProx logs twice, the other nginx logs (trap-hosts too) once" \
            || fail "A: not production's layout — tailers per log:$RT_TAILS"
        [[ -z "$RT_PRE" ]] && pass "A: before a rotation every line is read once per tailer (twice for the four LoxProx logs)" \
                           || note "A: reads before a rotation:$RT_PRE"
        note "A: $RT_ROTATED rotations, $RT_REOPEN reopens, $(grep -c . <<<"$RT_DEATHS") 'file reader died'"
        if [[ -n "$RT_DEATHS$RT_LOST$RT_STOPPED" ]]; then
            pass "A: REPRODUCED in $cycles rotations — fewer readers after the rotation:${RT_LOST:- none}; nothing read after it:${RT_STOPPED:- none}"
            rt_show_deaths
        else
            note "A: NOT reproduced in $cycles rotations — every tailer kept reading on this runner"
        fi
    fi
    out=$(rt_static_tails)
    [[ "$out" == "$RT_TAILS" ]] && pass "test-gateway.sh reads production's acquisition as CrowdSec tails it:$out" \
                                || fail "test-gateway.sh reads:$out — CrowdSec tailed:$RT_TAILS"

    # ── B: deploy.sh's configure_crowdsec on that host ──
    if cs_configure ban; then
        pass "configure_crowdsec on production's layout returns 0"
    else
        fail "configure_crowdsec failed — deploy log below"
        tail -25 "$LOG_FILE" | sed 's/^/    /'
    fi
    note "acquis.d after deploy.sh: $(cd "$acq" && ls | tr '\n' ' ')"
    for f in setup.nginx.yaml setup.sshd.yaml; do
        if [[ ! -e "$acq/$f" && -f "$acq/$f.loxprox-disabled" && -f "$BACKUP_DIR/files$acq/$f" ]]; then
            pass "$f disabled (kept as $f.loxprox-disabled, backed up in the deploy backup)"
        else
            fail "$f: $(ls -l "$acq/$f"* 2>&1 | tr '\n' ' ')"
        fi
    done
    cmp -s "$RT_W/setup.linux.yaml" "$acq/setup.linux.yaml" && pass "setup.linux.yaml (syslog files, no overlap) left as it is" \
                                                              || fail "setup.linux.yaml changed or removed"
    out=$(cat "$CROWDSEC_SSH_ACQUIS" 2>/dev/null)
    grep -qx 'source: journalctl' <<<"$out" && grep -qF -- '- _SYSTEMD_UNIT=ssh.service' <<<"$out" && ! grep -qF auth.log <<<"$out" \
        && pass "ssh.yaml reads sshd's journal (ssh.service) — the one SSH source" || fail "ssh.yaml: $out"

    cycles="${RT_CYCLES_B:-10}"
    rt_arm B "$cycles" 1 6 && rt_gates B "$cycles"
    out=$(rt_static_tails)
    [[ "$out" == "$RT_TAILS" ]] && pass "test-gateway.sh reads deploy.sh's acquisition as CrowdSec tails it:$out" \
                                || fail "test-gateway.sh reads:$out — CrowdSec tailed:$RT_TAILS"
    out=$( (source "$REPO/test-gateway.sh"; _cs_acquisition_problems "$CROWDSEC_DIR" "$RT_NGINX") 2>&1)
    [[ -z "$out" ]] && pass "test-gateway.sh: no log read twice, trap-hosts not read, sshd read once" \
                    || fail "test-gateway.sh acquisition problems: $(tr '\n' ';' <<<"$out")"
    cycles="${RT_CYCLES_B2:-20}"
    rt_arm B2 "$cycles" 0 6 && rt_gates B2 "$cycles"

    # The package's postinst runs `cscli setup unattended` on every upgrade.
    out=$(cscli setup unattended 2>&1)
    if [[ ! -e "$acq/setup.nginx.yaml" && ! -e "$acq/setup.sshd.yaml" ]] && grep -qF 'will not proceed' <<<"$out"; then
        pass "cscli setup unattended (the package's postinst) leaves them disabled: $(grep -F 'will not proceed' <<<"$out" | head -n 1 | cut -c1-90)…"
    else
        fail "cscli setup unattended: $(tr '\n' ' ' <<<"$out" | cut -c1-300); acquis.d: $(cd "$acq" && ls | tr '\n' ' ')"
    fi
    logoff=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
    cp -a "$acq/setup.nginx.yaml.loxprox-disabled" "$RT_W/disabled.copy" 2>/dev/null
    if cs_configure ban && [[ ! -e "$acq/setup.nginx.yaml" && ! -e "$acq/setup.sshd.yaml" ]] \
            && cmp -s "$RT_W/disabled.copy" "$acq/setup.nginx.yaml.loxprox-disabled" \
            && ! tail -c +$((logoff + 1)) "$LOG_FILE" | grep -qE 'Disabled .*setup\.|left in place'; then
        pass "a second deploy run changes nothing (idempotent)"
    else
        fail "second deploy run: acquis.d: $(cd "$acq" && ls | tr '\n' ' '); log: $(tail -c +$((logoff + 1)) "$LOG_FILE" | grep -E 'setup\.' | tr '\n' ' ' | cut -c1-300)"
    fi

    # ── C: B with poll_without_inotify: true (information only) ──
    for f in "$CROWDSEC_NGINX_ACQUIS" "$CROWDSEC_LOXPROX_ACQUIS"; do printf 'poll_without_inotify: true\n' >> "$f"; done
    cycles="${RT_CYCLES_C:-8}"
    if rt_arm C "$cycles" 0 6; then
        note "C (poll_without_inotify): tailers:$RT_TAILS; $RT_ROTATED rotations; fewer readers:${RT_LOST:- none}; nothing read:${RT_STOPPED:- none}; $(grep -c . <<<"$RT_DEATHS") deaths"
        rt_show_deaths
    fi
    cs_configure ban || fail "configure_crowdsec after C failed"
    systemctl is-active --quiet crowdsec && pass "crowdsec active on deploy.sh's acquisition at the end" || fail "crowdsec not active at the end"

    if [[ -n "$fake_pid" ]]; then kill "$fake_pid" 2>/dev/null; rm -f /var/run/nginx.pid; fi
    rm -rf "$RT_W"
}

# ── main ──────────────────────────────────────────────────────────────────────

(( $# > 0 )) || { echo "usage: $0 <cron|journald|auditd|logrotate|nginx-apparmor|nginx-appsec|nginx-edge|nft-check|debian12-host|crowdsec|crowdsec-hubupdate|crowdsec-hub-refresh|crowdsec-rotation> ..." >&2; exit 2; }
for s in "$@"; do
    case "$s" in
        cron)                      t_cron ;;
        journald)                  t_journald ;;
        auditd)                    t_auditd ;;
        panel-job)                 t_panel_job ;;
        install-dir)               t_install_dir ;;
        launch-env)                t_launch_env ;;
        panel-stop)                t_panel_stop ;;
        logrotate)                 t_logrotate ;;
        cron-unit)                 t_cron_unit ;;
        nginx-apparmor)            t_nginx_apparmor ;;
        nginx-container-setup)     t_nginx_container_setup; exit $? ;;
        nginx-container-test-proxy) t_nginx_container_test_proxy; exit $? ;;
        nginx-appsec)              t_nginx_appsec ;;
        nginx-appsec-setup)        t_nginx_appsec_setup; exit $? ;;
        nginx-appsec-v4)           t_nginx_appsec_v4; exit $? ;;
        nginx-edge)                t_nginx_edge ;;
        nginx-edge-setup)          t_nginx_edge_setup "${2:-tls}"; exit $? ;;
        nft-check)                 t_nft_check ;;
        nft-check-inner)           t_nft_check_inner; exit $(( FAILED > 0 )) ;;
        debian12-host)             t_debian12_host ;;
        debian12-host-inner)       t_debian12_host_inner; exit $(( FAILED > 0 )) ;;
        crowdsec)                  t_crowdsec ;;
        crowdsec-hubupdate)        t_crowdsec_hubupdate ;;
        crowdsec-hub-refresh)      t_crowdsec_hub_refresh ;;
        crowdsec-rotation)         t_crowdsec_rotation ;;
        *) echo "unknown section: $s" >&2; exit 2 ;;
    esac
done

echo ""
echo "host integration: $PASSED passed, $FAILED failed"
[[ $FAILED -eq 0 ]]
