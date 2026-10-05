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
    LOXONE_IP=127.0.0.1 LOXONE_PORT=8081 ENABLE_APPSEC=false
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
    printf 'ENABLE_TLS="true"\nENABLE_APPSEC="false"\n' > /etc/loxprox/deploy.conf
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
        curl -fsk -o /dev/null https://127.0.0.1:1080/jdev/cfg/api || exit 17
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
    hdrs=$(docker exec "$CTR" curl -sk -D - -o /dev/null https://127.0.0.1:1080/jdev/cfg/api | tr -d '\r')
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

# ── main ──────────────────────────────────────────────────────────────────────

(( $# > 0 )) || { echo "usage: $0 <cron|journald|auditd|logrotate|nginx-apparmor> ..." >&2; exit 2; }
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
        *) echo "unknown section: $s" >&2; exit 2 ;;
    esac
done

echo ""
echo "host integration: $PASSED passed, $FAILED failed"
[[ $FAILED -eq 0 ]]
