#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Tunnel Self-Healing Watchdog (v2.0)
# ═══════════════════════════════════════════════════════════════════════════════
# WHAT THIS IS:
#   A transparent, locally-operated health monitor for the optional frp tunnel
#   (ENABLE_TUNNEL=true). It detects when the tunnel to the relay VPS is down
#   and attempts to heal it by restarting frpc. It NEVER reboots the VM — a
#   dead tunnel is usually a relay/ISP problem that a gateway reboot cannot
#   fix, and the network watchdog already covers local stack failures.
#
# WHAT THIS IS NOT:
#   - NOT a backdoor, remote-access tool, or telemetry collector.
#   - NOT affiliated with any third-party service.
#   - DOES NOT phone home. The ONLY external calls are (a) the public-path
#     probe against YOUR OWN relay domain and (b) YOUR configured Discord
#     webhook (same one used by all other LoxProx alerts).
#   - DOES NOT modify firewall rules, install packages, or change secrets.
#
# HOW IT WORKS:
#   Every 60 seconds it runs two checks:
#     1. frpc service active?
#     2. Public path answering? (curl https://TUNNEL_PUBLIC_HOST/ — any HTTP
#        status except 000/502/503/504 counts as up, because a 401/403/404
#        still proves relay + tunnel + gateway nginx are all alive.)
#   Two consecutive failed cycles → restart frpc, wait, re-check. If still
#   down → one CRITICAL Discord alert (rate-limited to 1/hour), then keep
#   retrying every cycle. Recovery is reported once when checks pass again.
#
# HOW TO DISABLE:
#   sudo systemctl stop tunnel-watchdog.timer
#   sudo systemctl disable tunnel-watchdog.timer
#
# LOGS:
#   /var/log/loxprox-tunnel-watchdog.log
#   journalctl -u tunnel-watchdog
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

ENABLE_TUNNEL="${ENABLE_TUNNEL:-false}"
TUNNEL_PUBLIC_HOST="${TUNNEL_PUBLIC_HOST:-}"
PROBE_TIMEOUT="${TUNNEL_PROBE_TIMEOUT:-10}"

# ── State / Logging ───────────────────────────────────────────────────────────
STATE_DIR="/var/lib/loxprox"
LOG_FILE="/var/log/loxprox-tunnel-watchdog.log"
FAILURE_COUNT_FILE="$STATE_DIR/tunnel-failure-count"
# Written when we alert so (a) alerts are rate-limited and (b) recovery is
# reported exactly once. Contains the epoch of the last CRITICAL alert.
DOWN_FLAG="$STATE_DIR/.tunnel-down-alerted"

ALERT_COOLDOWN=3600      # max one CRITICAL alert per hour
HEAL_WAIT_SECONDS=20

mkdir -p "$STATE_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    logger -t loxprox-tunnel-watchdog "$1"
}

send_discord() {
    local severity="$1" title="$2" message="$3"
    if [[ -x "$DISCORD" ]]; then
        "$DISCORD" "$severity" "$title" "$message" || true
    fi
}

# ── Health Checks (return 0 = healthy, 1 = failed) ────────────────────────────

check_frpc_service() {
    systemctl is-active --quiet frpc 2>/dev/null
}

check_public_path() {
    # No public host configured → nothing to probe, treat as healthy.
    [[ -z "$TUNNEL_PUBLIC_HOST" ]] && return 0
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$PROBE_TIMEOUT" \
        "https://${TUNNEL_PUBLIC_HOST}/" 2>/dev/null || echo "000")
    case "$code" in
        000|502|503|504) return 1 ;;   # no answer / relay up but tunnel dead
        *)               return 0 ;;   # any real answer proves the full path
    esac
}

# ── Failure counter ───────────────────────────────────────────────────────────

increment_failure_count() {
    local count=0
    [[ -f "$FAILURE_COUNT_FILE" ]] && count=$(cat "$FAILURE_COUNT_FILE")
    echo "$((count + 1))" > "$FAILURE_COUNT_FILE"
}

clear_failure_count() { rm -f "$FAILURE_COUNT_FILE"; }

get_failure_count() {
    [[ -f "$FAILURE_COUNT_FILE" ]] && cat "$FAILURE_COUNT_FILE" || echo 0
}

alert_allowed() {
    [[ -f "$DOWN_FLAG" ]] || return 0
    local last now
    last=$(cat "$DOWN_FLAG" 2>/dev/null || echo 0)
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
    now=$(date +%s)
    (( now - last >= ALERT_COOLDOWN ))
}

# ── Diagnostics ───────────────────────────────────────────────────────────────

collect_diagnostics() {
    local failed="$1"
    local diag=""
    diag+="Failed checks: ${failed}\n"
    diag+="frpc service: $(systemctl is-active frpc 2>/dev/null || echo 'unknown')\n"
    diag+="Public host: ${TUNNEL_PUBLIC_HOST:-<not configured>}\n"
    diag+="Local log: ${LOG_FILE}\n"
    diag+="--- Last 10 frpc journal lines ---\n"
    diag+="$(journalctl -u frpc -n 10 --no-pager 2>/dev/null || echo 'journal unavailable')\n"
    printf '%s' "$diag"
}

# ── Healer ────────────────────────────────────────────────────────────────────

attempt_heal() {
    log "HEAL: restarting frpc..."
    systemctl restart frpc 2>/dev/null || true
    sleep "$HEAL_WAIT_SECONDS"

    local still_failed=""
    check_frpc_service   || still_failed+="frpc_service "
    check_public_path    || still_failed+="public_path "

    if [[ -z "$still_failed" ]]; then
        log "HEAL: frpc restart resolved the issue"
        return 0
    fi
    log "HEAL: still failing after frpc restart: $still_failed"
    return 1
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    # Defensive: if the operator disabled the tunnel but the timer is still
    # armed (e.g. mid-upgrade), do nothing rather than alert on a dead frpc.
    if [[ "${ENABLE_TUNNEL,,}" != "true" ]]; then
        exit 0
    fi

    local failed=()
    check_frpc_service || { failed+=("frpc_service"); log "FAIL: frpc service not active"; }
    check_public_path  || { failed+=("public_path");  log "FAIL: public path https://${TUNNEL_PUBLIC_HOST}/ unreachable"; }

    # All healthy?
    if [[ ${#failed[@]} -eq 0 ]]; then
        if [[ -f "$DOWN_FLAG" ]]; then
            send_discord "WARNING" "Tunnel Recovered" \
                "The frp tunnel is healthy again (frpc active$( [[ -n "$TUNNEL_PUBLIC_HOST" ]] && echo ", public path answering" )). No action needed."
            rm -f "$DOWN_FLAG"
            log "RECOVERED: tunnel healthy again, recovery reported"
        fi
        clear_failure_count
        exit 0
    fi

    increment_failure_count
    local fcount
    fcount=$(get_failure_count)
    log "FAILURE COUNT: $fcount (checks: ${failed[*]})"

    # Require 2 consecutive failures before acting (avoid false positives
    # from a single dropped probe or a relay nginx reload).
    if [[ "$fcount" -lt 2 ]]; then
        log "Waiting for confirmation (need 2 consecutive failures)"
        exit 0
    fi

    local diag
    diag=$(collect_diagnostics "${failed[*]}")

    if attempt_heal; then
        clear_failure_count
        rm -f "$DOWN_FLAG"
        send_discord "WARNING" "Tunnel Recovered After frpc Restart" \
            "Watchdog detected a tunnel failure (${failed[*]}) and recovered it by restarting frpc.\n\n${diag}"
        log "Recovered after heal"
        exit 0
    fi

    # Heal failed. Alert once per cooldown window, keep retrying every cycle.
    if alert_allowed; then
        date +%s > "$DOWN_FLAG"
        send_discord "CRITICAL" "Tunnel Down — Remote Access Unavailable" \
            "The frp tunnel is down and an frpc restart did not fix it. Remote access via the relay is unavailable until this is resolved. LAN access is unaffected.\n\n${diag}\nMost likely causes:\n1. Relay VPS down or unreachable → check your VPS provider console\n2. frps not running on the relay → ssh relay, then: systemctl status frps\n3. Token mismatch after a rotation → compare TUNNEL_TOKEN on both sides\n4. Relay firewall/DNS changes → verify port and domain\n\nThis alert fires at most once per hour; the watchdog keeps retrying every 60s and will report recovery."
        log "CRITICAL alert sent (cooldown ${ALERT_COOLDOWN}s)"
    else
        log "Still down; alert suppressed by cooldown"
    fi
    exit 0
}

main "$@"
