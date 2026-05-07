#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Network Stack Self-Healing Watchdog
# ═══════════════════════════════════════════════════════════════════════════════
# WHAT THIS IS:
#   A transparent, locally-operated health monitor that detects when the VM's
#   network stack becomes unreachable (e.g. dhclient death-spiral, kernel
#   routing corruption, interface state desync) and attempts to heal it.
#
# WHAT THIS IS NOT:
#   - NOT a backdoor, remote-access tool, or telemetry collector.
#   - NOT affiliated with any third-party service.
#   - DOES NOT phone home. The ONLY external call is to YOUR configured
#     Discord webhook (same one used by all other LoxProx alerts).
#   - DOES NOT modify firewall rules, install packages, or change secrets.
#
# HOW IT WORKS:
#   Every 60 seconds it runs five local health checks (gateway ping, DNS,
#   nginx localhost, interface IP, dhclient anomaly). If checks fail for
#   two consecutive cycles it:
#     1. Attempts to heal by restarting nginx, then networking.service
#     2. If healing fails, writes a flag file, sends a Discord alert,
#        waits 30 s, and reboots the VM.
#     3. After reboot, the first cycle reads the flag file and sends a
#        "system recovered" report.
#
# HOW TO DISABLE:
#   sudo systemctl stop network-watchdog.timer
#   sudo systemctl disable network-watchdog.timer
#
# LOGS:
#   /var/log/loxprox-network-watchdog.log
#   /var/lib/loxprox/watchdog-reboot-history.log
#   journalctl -u network-watchdog
#
# SOURCE: https://github.com/sgtsilver/loxprox
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
CONFIG_FILE="${LOXPROX_CONFIG:-/etc/loxprox/config.env}"
if [[ -f "$CONFIG_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    set +a
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISCORD="${DISCORD_ALERT_PATH:-$SCRIPT_DIR/discord-alert.sh}"

# Auto-detect network topology; allow env/config override
IFACE="${WATCHDOG_IFACE:-$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)}"
IFACE="${IFACE:-$(ip -o link show | awk -F': ' '/^[0-9]+: e/{print $2}' | head -1)}"
GATEWAY_IP="${WATCHDOG_GATEWAY:-$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1)}"
GATEWAY_IP="${GATEWAY_IP:-192.168.178.1}"
NGINX_LOCAL="${WATCHDOG_NGINX_URL:-http://127.0.0.1:1080/}"
EXPECTED_IP="${WATCHDOG_EXPECTED_IP:-${GATEWAY_IP:-}}"

# If EXPECTED_IP is still empty, we can't validate the interface IP.
# This only happens in pathological cases; skip the IP check rather than fail.
[[ -z "$EXPECTED_IP" ]] && EXPECTED_IP="UNSET"

# ── State / Logging ───────────────────────────────────────────────────────────
STATE_DIR="/var/lib/loxprox"
LOG_FILE="/var/log/loxprox-network-watchdog.log"
REBOOT_FLAG="$STATE_DIR/.watchdog-reboot-pending"
REBOOT_LOG="$STATE_DIR/watchdog-reboot-history.log"
FAILURE_COUNT_FILE="$STATE_DIR/watchdog-failure-count"

# Anti-reboot-loop protection
MAX_REBOOTS_PER_HOUR=2
REBOOT_WINDOW=3600

# Heal timing
HEAL_WAIT_SECONDS=15
REBOOT_DELAY_SECONDS=30

mkdir -p "$STATE_DIR"

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" | tee -a "$LOG_FILE"
    logger -t loxprox-watchdog "$1"
}

# ── Helpers ───────────────────────────────────────────────────────────────────

send_discord() {
    local severity="$1" title="$2" message="$3"
    if [[ -x "$DISCORD" ]]; then
        "$DISCORD" "$severity" "$title" "$message" || true
    fi
}

detect_expected_mode() {
    local iface="$1"
    local mode
    mode=$(awk -v iface="$iface" '
        /^iface / && $2 == iface && $3 == "inet" {print $4; exit}
    ' /etc/network/interfaces 2>/dev/null || true)
    echo "${mode:-unknown}"
}

increment_failure_count() {
    local count=0
    [[ -f "$FAILURE_COUNT_FILE" ]] && count=$(cat "$FAILURE_COUNT_FILE")
    echo "$((count + 1))" > "$FAILURE_COUNT_FILE"
}

clear_failure_count() {
    rm -f "$FAILURE_COUNT_FILE"
}

get_failure_count() {
    [[ -f "$FAILURE_COUNT_FILE" ]] && cat "$FAILURE_COUNT_FILE" || echo 0
}

# Count how many watchdog reboots happened in the last REBOOT_WINDOW seconds
reboots_in_window() {
    [[ -f "$REBOOT_LOG" ]] || { echo 0; return; }
    local now cutoff
    now=$(date +%s)
    cutoff=$((now - REBOOT_WINDOW))
    local count=0
    while read -r ts _rest; do
        # ts is epoch seconds written by handle_reboot
        [[ "$ts" =~ ^[0-9]+$ ]] || continue
        [[ "$ts" -gt "$cutoff" ]] && ((count++))
    done < "$REBOOT_LOG"
    echo "$count"
}

# ── Health Checks (return 0 = healthy, 1 = failed) ────────────────────────────

check_gateway() {
    ping -c 2 -W 4 "$GATEWAY_IP" > /dev/null 2>&1
}

check_dns() {
    # Test DNS resolution. Prefer dig (tests external path), fall back to
    # getent (tests local resolver — good enough if dig is not installed).
    if command -v dig &>/dev/null; then
        dig +short +time=3 +tries=1 github.com @8.8.8.8 > /dev/null 2>&1 || \
            dig +short +time=3 +tries=1 github.com > /dev/null 2>&1
    else
        getent hosts github.com > /dev/null 2>&1
    fi
}

check_nginx_local() {
    curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$NGINX_LOCAL" 2>/dev/null | grep -qE "^(200|301|302|401|403)$"
}

check_interface_ip() {
    [[ "$EXPECTED_IP" == "UNSET" ]] && return 0
    ip addr show "$IFACE" 2>/dev/null | grep -q "inet ${EXPECTED_IP}"
}

check_dhclient_anomaly() {
    local expected_mode
    expected_mode=$(detect_expected_mode "$IFACE")
    if [[ "$expected_mode" == "static" ]] && pgrep -x dhclient > /dev/null 2>&1; then
        log "ANOMALY: dhclient is running but interface $IFACE is configured static"
        return 1
    fi
    return 0
}

# ── Diagnostics Collector ─────────────────────────────────────────────────────

collect_diagnostics() {
    local failed="$1"
    local diag=""
    diag+="Failed checks: ${failed}\n"
    diag+="Interface: ${IFACE}\n"
    diag+="Expected mode: $(detect_expected_mode "$IFACE")\n"
    diag+="Gateway: ${GATEWAY_IP}\n"
    diag+="Current IP: $(ip addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | head -1)\n"
    diag+="Default route: $(ip route show default 2>/dev/null | head -1)\n"
    diag+="dhclient PIDs: $(pgrep -x dhclient 2>/dev/null | tr '\n' ' ' || echo 'none')\n"
    diag+="nginx status: $(systemctl is-active nginx 2>/dev/null || echo 'unknown')\n"
    diag+="networking status: $(systemctl is-active networking 2>/dev/null || echo 'unknown')\n"
    diag+="--- Last 10 syslog lines ---\n"
    diag+="$(tail -n 10 /var/log/syslog 2>/dev/null || echo 'syslog unavailable')\n"
    diag+="--- Last 5 dmesg lines ---\n"
    diag+="$(dmesg | tail -n 5 2>/dev/null || echo 'dmesg unavailable')\n"
    printf '%s' "$diag"
}

# ── Healer ────────────────────────────────────────────────────────────────────

attempt_heal() {
    log "HEAL: Attempting recovery..."

    # Step 1: nginx might just be hung; it's the cheapest fix
    if ! check_nginx_local; then
        log "HEAL: nginx local check failed — restarting nginx"
        systemctl restart nginx 2>/dev/null || true
        sleep 3
        if check_nginx_local; then
            log "HEAL: nginx restart resolved the issue"
            return 0
        fi
    fi

    # Step 2: Full networking restart (ifupdown re-runs all interface scripts)
    log "HEAL: Restarting networking.service..."
    systemctl restart networking 2>/dev/null || true
    sleep "$HEAL_WAIT_SECONDS"

    # Re-evaluate
    local still_failed=""
    if ! check_gateway; then still_failed+="gateway "; fi
    if ! check_dns;     then still_failed+="dns "; fi
    if ! check_nginx_local; then still_failed+="nginx "; fi
    if ! check_interface_ip; then still_failed+="ip "; fi

    if [[ -z "$still_failed" ]]; then
        log "HEAL: networking restart resolved the issue"
        return 0
    fi

    log "HEAL: Still failing after networking restart: $still_failed"
    return 1
}

# ── Reboot Handler ────────────────────────────────────────────────────────────

handle_reboot() {
    local failed_checks="$1"
    local diagnostics="$2"

    log "REBOOT: Network unrecoverable. Checks: $failed_checks"

    # Anti-loop: how many watchdog reboots recently?
    local recent_reboots
    recent_reboots=$(reboots_in_window)
    if [[ "$recent_reboots" -ge "$MAX_REBOOTS_PER_HOUR" ]]; then
        local msg="WATCHDOG GIVING UP: $MAX_REBOOTS_PER_HOUR reboots in the last hour."
        log "$msg"
        log "The upstream network (router/Fritzbox) may actually be down."
        send_discord "CRITICAL" "Watchdog Gave Up — Manual Intervention Required" \
            "$msg\n\nFailed checks: ${failed_checks}\n\n${diagnostics}\n\nAction: Check your upstream router/Fritzbox. If the router is up, SSH in and run:\njournalctl -u network-watchdog --since '1 hour ago'\ncat $LOG_FILE"
        # Exit non-zero so systemd knows we failed, but FailureAction won't
        # trigger because StartLimitBurst protects against loops.
        exit 1
    fi

    # Write persistent flag so post-reboot cycle can report recovery
    local now_epoch
    now_epoch=$(date +%s)
    cat > "$REBOOT_FLAG" <<EOF
timestamp_epoch=$now_epoch
timestamp_iso=$(date -Iseconds)
failed_checks=$failed_checks
gateway=$GATEWAY_IP
iface=$IFACE
diagnostics<<DIAG_EOF
$diagnostics
DIAG_EOF
EOF

    # Record in reboot history log (epoch + human-readable)
    echo "$now_epoch $(date -Iseconds) $failed_checks" >> "$REBOOT_LOG"

    # Pre-reboot Discord alert (network might still barely work)
    local pre_msg="Auto-rebooting in ${REBOOT_DELAY_SECONDS}s.\n\n"
    pre_msg+="Failed checks: ${failed_checks}\n\n"
    pre_msg+="${diagnostics}\n\n"
    pre_msg+="If this keeps happening:\n"
    pre_msg+="1. Check if dhclient is running on a static interface → run set-static-ip.sh\n"
    pre_msg+="2. Check your Fritzbox / upstream router → may be the actual cause\n"
    pre_msg+="3. SSH in after reboot and check: journalctl -u network-watchdog --since '1 hour ago'\n"
    pre_msg+="4. View logs: cat $LOG_FILE"

    send_discord "CRITICAL" "Network Failure — Auto-Reboot Triggered" "$pre_msg"

    log "REBOOT: Waiting ${REBOOT_DELAY_SECONDS}s before reboot..."
    sleep "$REBOOT_DELAY_SECONDS"

    # Ensure flag file is flushed to disk before the kernel takes over
    sync

    # Final local log entry before the kernel takes over
    log "REBOOT: Executing /sbin/reboot now."
    /sbin/reboot
}

# ── Post-Reboot Reporter ──────────────────────────────────────────────────────

check_post_reboot() {
    [[ -f "$REBOOT_FLAG" ]] || return 0

    local ts_iso failed_checks diag
    ts_iso=$(awk -F= '/^timestamp_iso=/{print $2}' "$REBOOT_FLAG")
    failed_checks=$(awk -F= '/^failed_checks=/{print $2}' "$REBOOT_FLAG")
    diag=$(awk '/^diagnostics<<DIAG_EOF$/{found=1; next} /^DIAG_EOF$/{found=0} found' "$REBOOT_FLAG")

    local msg="The system has recovered after a watchdog-initiated reboot.\n\n"
    msg+="Previous failure (${ts_iso}):\n"
    msg+="Failed checks: ${failed_checks}\n\n"
    msg+="Current state:\n"
    msg+="Gateway ping: $(check_gateway && echo OK || echo FAIL)\n"
    msg+="DNS resolve: $(check_dns && echo OK || echo FAIL)\n"
    msg+="Nginx local: $(check_nginx_local && echo OK || echo FAIL)\n"
    msg+="Interface IP: $(check_interface_ip && echo OK || echo FAIL)\n\n"
    msg+="If this was caused by a dhclient conflict, ensure set-static-ip.sh was run.\n"
    msg+="If it keeps recurring, check your Fritzbox and network cables."

    send_discord "WARNING" "System Recovered After Watchdog Reboot" "$msg"
    log "POST-REBOOT: Recovery reported. Previous failure: $failed_checks at $ts_iso"

    rm -f "$REBOOT_FLAG"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    # Log start (but keep it concise to avoid log spam)
    log "Cycle started"

    # 1. Post-reboot reporting (only runs if flag file exists)
    check_post_reboot

    # 2. Determine what network mode we expect
    local expected_mode
    expected_mode=$(detect_expected_mode "$IFACE")
    log "Expected mode for $IFACE: $expected_mode"

    # 3. Run health checks
    local failed=()

    if ! check_gateway; then
        failed+=("gateway_ping")
        log "FAIL: gateway $GATEWAY_IP unreachable"
    fi

    if ! check_dns; then
        failed+=("dns_resolve")
        log "FAIL: DNS resolution broken"
    fi

    if ! check_nginx_local; then
        failed+=("nginx_local")
        log "FAIL: nginx localhost check failed"
    fi

    if ! check_interface_ip; then
        failed+=("interface_ip")
        log "FAIL: interface $IFACE does not have expected IP $EXPECTED_IP"
    fi

    # 4. Anomaly detection (non-fatal, just logged)
    if ! check_dhclient_anomaly; then
        # Already logged inside function
        : # anomaly noted but does not count as a health-check failure
    fi

    # 5. All healthy?
    if [[ ${#failed[@]} -eq 0 ]]; then
        clear_failure_count
        log "Cycle passed"
        exit 0
    fi

    # 6. Something failed — increment counter
    increment_failure_count
    local fcount
    fcount=$(get_failure_count)
    log "FAILURE COUNT: $fcount (checks: ${failed[*]})"

    # 7. Require 2 consecutive failures before acting (avoid false positives)
    if [[ "$fcount" -lt 2 ]]; then
        log "Waiting for confirmation (need 2 consecutive failures)"
        exit 0
    fi

    # 8. Collect diagnostics before we try to heal
    local diag
    diag=$(collect_diagnostics "${failed[*]}")

    # 9. Attempt heal
    if attempt_heal; then
        clear_failure_count
        send_discord "WARNING" "Network Recovered After Restart" \
            "Watchdog detected failure (${failed[*]}) but recovered after restarting networking/nginx.\n\n${diag}"
        log "Recovered after heal"
        exit 0
    fi

    # 10. Unrecoverable — reboot
    handle_reboot "${failed[*]}" "$diag"
}

main "$@"
