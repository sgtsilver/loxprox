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
    # Alert on each NEW local scenario ban (this gateway's own detections) — not a
    # repeating snapshot of the current set. `cscli decisions list` (no -a) returns
    # only local decisions; the large community blocklist (CAPI, tens of thousands
    # of IPs) is enforced by the bouncer separately and is reported here as a
    # background count, never per-IP (that would be thousands of alerts).
    local decisions_json seen_file="$STATE_DIR/seen_local_bans"
    decisions_json=$(cscli decisions list -o json 2>/dev/null) || return 0  # M8: LAPI outage must not abort the whole cycle
    [[ -z "$decisions_json" ]] && return 0

    # Robust to all cscli JSON shapes (flat array / {decisions:[]} / array of
    # alerts): pull out decision objects, identified by having value + duration.
    local current
    current=$(echo "$decisions_json" | jq -r '
        [ .. | objects | select(has("value") and has("duration")) ]
        | .[] | "\(.id)|\(.value)|\(.scenario // "?")|\(.origin // "?")"' 2>/dev/null | sort -u) || true  # M8

    if [[ -z "$current" ]]; then
        : > "$seen_file" 2>/dev/null   # nothing active — forget previous IDs
        return 0
    fi

    touch "$seen_file" 2>/dev/null
    local new_msg="" id value scenario origin
    while IFS='|' read -r id value scenario origin; do
        [[ -z "$id" ]] && continue
        grep -qxF "$id" "$seen_file" 2>/dev/null || new_msg+="${value} — ${scenario} [${origin}]\n"
    done <<< "$current"

    # Remember exactly the currently-active local bans; expired ones drop out, so a
    # later re-ban (new decision id) alerts again.
    echo "$current" | cut -d'|' -f1 > "$seen_file" 2>/dev/null

    if [[ -n "$new_msg" ]]; then
        local community
        community=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d ' ') || true  # M6: count IPs not lines; never abort the send
        log "ALERT [WARNING]: New CrowdSec local ban(s)"
        "$DISCORD" "WARNING" "New CrowdSec Ban" \
            "Newly banned by a local scenario:\n${new_msg}\nBackground: ${community:-?} IPs currently enforced via the CrowdSec community blocklist." 2>/dev/null || true
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
    new_errors=$(tail -c +$((last_pos + 1)) "$log" 2>/dev/null | grep -E "limiting requests|upstream prematurely|502|503|504" | head -20) || true  # H2: no-match grep is normal
    
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
    failed_logins=$(tail -c +$((last_pos + 1)) "$log" 2>/dev/null | grep -E "Failed password|Invalid user|Connection closed by authenticating user" | head -20) || true  # H2: no-match grep is normal
    
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
    detections=$(tail -c +$((last_pos + 1)) "$log" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10) || true  # H2-class: SIGPIPE/no-match must not abort
    
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
