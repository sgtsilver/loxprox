#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Real-Time Security Monitor
# ═══════════════════════════════════════════════════════════════════════════════
# Watches nginx access logs, CrowdSec decisions, auth attempts, and system
# anomalies. Sends Discord alerts on detection.
#
# Run manually or via systemd timer every 60s.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Configuration
CONFIG_FILE="${LOXPROX_CONFIG:-/etc/loxprox/config.env}"
if [[ -f "$CONFIG_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    set +a
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISCORD="${DISCORD_ALERT_PATH:-$SCRIPT_DIR/discord-alert.sh}"
LOG_FILE="/var/log/loxprox-monitor.log"
STATE_DIR="/var/lib/loxprox"
ALERT_COOLDOWN=300  # 5 min between identical alert types

mkdir -p "$STATE_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

# ── Helpers ──────────────────────────────────────────────────────────────────
last_alert_time() {
    local key="$1"
    local file="$STATE_DIR/alert_$key"
    [ -f "$file" ] && cat "$file" || echo 0
}

record_alert_time() {
    local key="$1"
    date +%s > "$STATE_DIR/alert_$key"
}

can_alert() {
    local key="$1"
    local last
    last=$(last_alert_time "$key")
    local now
    now=$(date +%s)
    [ $((now - last)) -gt $ALERT_COOLDOWN ]
}

send_alert() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local key="$4"
    
    if can_alert "$key"; then
        record_alert_time "$key"
        "$DISCORD" "$severity" "$title" "$message" || true
        log "ALERT [$severity]: $title"
    fi
}

# ── Checks ───────────────────────────────────────────────────────────────────

check_crowdsec_blocks() {
    local decisions_json
    decisions_json=$(cscli decisions list -o json 2>/dev/null)
    [[ -z "$decisions_json" ]] && return 0

    # cscli's JSON shape varies across CrowdSec versions: a flat array of
    # decisions (older), a {"decisions":[...]} wrapper, and (current) an array of
    # *alert* objects each carrying a `.decisions[]`. Recursively pull out every
    # decision object — uniquely identified by having both `value` and `duration`
    # — so parsing is robust to all three shapes.
    local decisions_filter='[ .. | objects | select(has("value") and has("duration")) ]'
    local new_decisions
    new_decisions=$(echo "$decisions_json" | jq -r "$decisions_filter"' | .[] |
        "\(.value) (\(.type // "ban")) - \(.scenario // "unknown")"' 2>/dev/null | sort -u | head -10)

    local count
    count=$(echo "$decisions_json" | jq "$decisions_filter"' | length' 2>/dev/null)

    if [[ -n "$new_decisions" && "${count:-0}" -gt 0 ]]; then
        send_alert "WARNING" "CrowdSec Active Blocks" "$count IPs currently blocked by CrowdSec:\n$new_decisions" "crowdsec_blocks"
    fi
}

check_nginx_errors() {
    local log="/var/log/nginx/loxone-error.log"
    [ -f "$log" ] || return 0
    
    local last_check_file="$STATE_DIR/last_nginx_check"
    local last_pos=0
    [ -f "$last_check_file" ] && last_pos=$(cat "$last_check_file")
    
    local current_pos
    current_pos=$(wc -c < "$log")
    [ "$current_pos" -le "$last_pos" ] && { echo "$current_pos" > "$last_check_file"; return 0; }
    
    local new_errors
    new_errors=$(tail -c +$((last_pos + 1)) "$log" 2>/dev/null | grep -E "limiting requests|upstream prematurely|502|503|504" | head -20)
    
    echo "$current_pos" > "$last_check_file"
    
    if [ -n "$new_errors" ]; then
        local count
        count=$(echo "$new_errors" | wc -l)
        send_alert "WARNING" "Nginx Anomalies Detected" "$count new anomalies in nginx error log:\n$new_errors" "nginx_errors"
    fi
}

check_auth_attempts() {
    local log="/var/log/auth.log"
    [ -f "$log" ] || return 0
    
    local last_check_file="$STATE_DIR/last_auth_check"
    local last_pos=0
    [ -f "$last_check_file" ] && last_pos=$(cat "$last_check_file")
    
    local current_pos
    current_pos=$(wc -c < "$log")
    [ "$current_pos" -le "$last_pos" ] && { echo "$current_pos" > "$last_check_file"; return 0; }
    
    local failed_logins
    failed_logins=$(tail -c +$((last_pos + 1)) "$log" 2>/dev/null | grep -E "Failed password|Invalid user|Connection closed by authenticating user" | head -20)
    
    echo "$current_pos" > "$last_check_file"
    
    if [ -n "$failed_logins" ]; then
        local count
        count=$(echo "$failed_logins" | wc -l)
        if [ "$count" -ge 5 ]; then
            send_alert "HIGH" "SSH Brute Force Activity" "$count failed SSH login attempts:\n$failed_logins" "ssh_brute"
        fi
    fi
}

check_appsec_detections() {
    local log="/var/log/nginx/appsec-detections.log"
    [ -f "$log" ] || return 0
    
    local last_check_file="$STATE_DIR/last_appsec_check"
    local last_pos=0
    [ -f "$last_check_file" ] && last_pos=$(cat "$last_check_file")
    
    local current_pos
    current_pos=$(wc -c < "$log")
    [ "$current_pos" -le "$last_pos" ] && { echo "$current_pos" > "$last_check_file"; return 0; }
    
    local detections
    detections=$(tail -c +$((last_pos + 1)) "$log" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10)
    
    echo "$current_pos" > "$last_check_file"
    
    if [ -n "$detections" ]; then
        send_alert "WARNING" "AppSec Detections" "New AppSec WAF detections:\n$detections" "appsec_detections"
    fi
}

check_system_resources() {
    local load avg_load mem_pct disk_pct
    load=$(cat /proc/loadavg)
    avg_load=$(echo "$load" | awk '{print $1}')
    mem_pct=$(LC_ALL=C free | awk '/Mem:/ {printf "%.0f", $3/$2 * 100}')
    disk_pct=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
    
    # High load alert
    if awk "BEGIN {exit !($avg_load > 2.0)}"; then
        send_alert "WARNING" "High System Load" "Load average: $avg_load\nMemory: ${mem_pct}%\nDisk: ${disk_pct}%" "high_load"
    fi
    
    # High memory alert
    if [ "$mem_pct" -gt 90 ]; then
        send_alert "CRITICAL" "Critical Memory Usage" "Memory usage: ${mem_pct}%\nLoad: $avg_load\nDisk: ${disk_pct}%" "critical_memory"
    fi
    
    # High disk alert
    if [ "$disk_pct" -gt 85 ]; then
        send_alert "HIGH" "High Disk Usage" "Disk usage: ${disk_pct}%\nMemory: ${mem_pct}%\nLoad: $avg_load" "high_disk"
    fi
}

check_gateway_health() {
    if ! systemctl is-active --quiet nginx; then
        send_alert "CRITICAL" "NGINX DOWN" "nginx service is not running on the gateway." "nginx_down"
    fi
    if ! systemctl is-active --quiet crowdsec; then
        send_alert "CRITICAL" "CrowdSec DOWN" "crowdsec service is not running on the gateway." "crowdsec_down"
    fi
    if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
        send_alert "HIGH" "CrowdSec Bouncer DOWN" "crowdsec-firewall-bouncer is not running." "bouncer_down"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    log "Security monitor cycle started"
    
    check_gateway_health
    check_crowdsec_blocks
    check_nginx_errors
    check_auth_attempts
    check_appsec_detections
    check_system_resources
    
    log "Security monitor cycle completed"
}

main "$@"
