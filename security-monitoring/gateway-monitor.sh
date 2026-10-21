#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Real-Time Security Monitor
# ═══════════════════════════════════════════════════════════════════════════════
# Watches nginx access logs, CrowdSec decisions, auth attempts, system
# anomalies, and TLS certificate expiry. Sends Discord alerts on detection.
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
LOG_FILE="${LOXPROX_MONITOR_LOG:-/var/log/loxprox-monitor.log}"
STATE_DIR="${LOXPROX_STATE_DIR:-/var/lib/loxprox}"
ALERT_COOLDOWN=300  # 5 min between identical alert types
CERT_ALERT_COOLDOWN=86400  # H13: cert expiry is a slow-moving fact — 1 alert/day/level

# H13: paths deploy.sh writes for TLS mode. The cert files are deliberately KEPT
# when ENABLE_TLS is toggled off, so the marker deploy.sh brackets the
# ssl_certificate directives with — not the file's existence — is what says TLS
# is actually live.
TLS_CERT="${LOXPROX_TLS_CERT:-/etc/loxprox/tls/fullchain.pem}"
NGINX_SITE="${LOXPROX_NGINX_SITE:-/etc/nginx/sites-available/loxone}"

# 2026-10: GeoIP blocklist freshness (stamps written by geoip-block.sh).
GEOIP_DIR="${LOXPROX_GEOIP_DIR:-/var/lib/loxone-geoip}"
GEOIP_NFT_FILE="${LOXPROX_GEOIP_NFT:-/etc/nftables.d/99-geoip.conf}"
GEOIP_SCRIPT="${LOXPROX_GEOIP_SCRIPT:-/opt/loxprox/geoip-block.sh}"
GEOIP_STALE_DAYS="${GEOIP_STALE_DAYS:-3}"
# 2026-10: false = no IPv6 GeoIP blocking (geoip-block.sh empties the v6 set);
# then neither a missing v6 refresh nor an empty v6 set is an alert.
GEOIP_IPV6_ENABLED="${GEOIP_IPV6_ENABLED:-true}"

# 2026-10 breach hardening: remote-session, firewall, pending-update and auth-rate checks.
SESSION_ALERT_ENABLED="${SESSION_ALERT_ENABLED:-true}"
AUTH_RATE_ALERT_PER_CYCLE="${AUTH_RATE_ALERT_PER_CYCLE:-20}"
ASN_DB="${LOXPROX_ASN_DB:-/var/lib/crowdsec/data/GeoLite2-ASN.mmdb}"
CITY_DB="${LOXPROX_CITY_DB:-/var/lib/crowdsec/data/GeoLite2-City.mmdb}"
KNOWN_ASNS_FILE="${LOXPROX_KNOWN_ASNS:-$STATE_DIR/known-asns.json}"
ASN_LEARNING_DAYS="${ASN_LEARNING_DAYS:-7}"
MMDBLOOKUP="${LOXPROX_MMDBLOOKUP:-mmdblookup}"
# Same trusted-address list progressive-ban.py honours (deploy-managed YAML).
SESSION_WHITELIST_FILE="${PROGRESSIVE_BAN_WHITELIST_FILE:-/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml}"
SEC_UPDATES_FILE="${LOXPROX_SEC_UPDATES_FILE:-$STATE_DIR/security-updates-seen.json}"
SEC_UPDATE_MAX_AGE_DAYS="${SEC_UPDATE_MAX_AGE_DAYS:-2}"
SEC_UPDATE_CHECK_INTERVAL="${SEC_UPDATE_CHECK_INTERVAL:-3600}"  # apt simulation is not free: hourly, not per cycle
ACCESS_LOG="${LOXPROX_ACCESS_LOG:-/var/log/nginx/loxone-access.log}"
# Listing the GeoIP sets prints every range (tens of thousands): hourly, not per cycle.
FW_SET_CHECK_INTERVAL="${FW_SET_CHECK_INTERVAL:-3600}"

# 2026-10 breach hardening: bans of unambiguous scanners (HARD, ~150 a day with
# the scanner trap) go into one daily INFO digest, not a per-ban alert each.
# Same regex and default as progressive-ban.py and deploy.sh (config.env).
_LOXPROX_HARD_SCENARIOS_DEFAULT='^(loxprox/scanner-trap|crowdsecurity/(appsec-vpatch|vpatch-.+|http-cve-.+|CVE-.+|[A-Za-z0-9_]+-cve-.+|http-sensitive-files|http-backdoors-attempts|http-path-traversal-probing|http-admin-interface-probing|http-open-proxy))$'
BAN_HARD_SCENARIOS="${BAN_HARD_SCENARIOS:-$_LOXPROX_HARD_SCENARIOS_DEFAULT}"
TRAP_BAN_MODE="${TRAP_BAN_MODE:-ban}"
BAN_DIGEST_HOUR="${BAN_DIGEST_HOUR:-8}"     # local hour; the digest goes out on the first cycle at or after it
BAN_ALERT_MAX_ENTRIES=15                    # per-ban message cap (Discord message size)
HARD_BANS_PENDING="$STATE_DIR/hard-bans-pending"   # "epoch|hard|scenario" lines since the last digest
HARD_DIGEST_STAMP="$STATE_DIR/hard_digest_day"
TRAP_HOSTS_LOG="${LOXPROX_TRAP_HOSTS_LOG:-/var/log/nginx/loxprox-trap-hosts.log}"

# 2026-10-21: CrowdSec log-reading watchdog (check_crowdsec_acquisition).
CROWDSEC_LOG="${LOXPROX_CROWDSEC_LOG:-/var/log/crowdsec.log}"
CROWDSEC_METRICS_URL="${LOXPROX_CROWDSEC_METRICS_URL:-http://127.0.0.1:6060/metrics}"
# The logs with steady traffic; a stalled reader shows on them first.
ACQ_WATCH_LOGS="${LOXPROX_ACQ_WATCH_LOGS:-/var/log/nginx/loxone-access.log /var/log/nginx/loxprox-trap.log /var/log/nginx/loxprox-unknown.log}"
ACQ_STALL_CYCLES="${ACQ_STALL_CYCLES:-3}"           # growths seen with nothing read before it counts
ACQ_RESTART_INTERVAL="${ACQ_RESTART_INTERVAL:-3600}" # at most one restart per hour
ACQ_RESTART_WAIT="${ACQ_RESTART_WAIT:-30}"           # seconds to wait for crowdsec to be active again
HUB_REFRESH_LOCK="${LOXPROX_HUB_LOCK:-/run/loxprox-hub-refresh.lock}"

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
    local cooldown="${2:-$ALERT_COOLDOWN}"
    local last
    last=$(last_alert_time "$key")
    local now
    now=$(date +%s)
    [ $((now - last)) -gt "$cooldown" ]
}

send_alert() {
    local severity="$1"
    local title="$2"
    local message="$3"
    local key="$4"
    local cooldown="${5:-$ALERT_COOLDOWN}"

    if can_alert "$key" "$cooldown"; then
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
    # 2026-10: only ambiguous (SOFT) bans alert here, at most
    # BAN_ALERT_MAX_ENTRIES per message. A ban whose scenario matches
    # BAN_HARD_SCENARIOS, or progressive-ban's extension of one (reason
    # repeat-offender-hard-<n>), is queued for check_hard_ban_digest instead.
    # --no-simu: a simulation-mode decision bans nothing. --limit 0: cscli
    # returns 100 alerts by default, and far more bans are active at once.
    local decisions_json seen_file="$STATE_DIR/seen_local_bans" hard_re="$BAN_HARD_SCENARIOS"
    decisions_json=$(cscli decisions list --no-simu --limit 0 -o json 2>/dev/null) || return 0  # M8: LAPI outage must not abort the whole cycle
    [[ -z "$decisions_json" ]] && return 0

    # jq (Oniguruma) is the closest match here to progressive-ban's Python re
    # and CrowdSec's RE2. A value it cannot compile falls back to the default.
    if jq -n --arg re "$hard_re" '"" | test($re)' >/dev/null 2>&1; then
        rm -f "$STATE_DIR/logged_hard_re"
    else
        log_once hard_re "BAN_HARD_SCENARIOS does not compile in jq — classifying bans with the default regex"
        hard_re="$_LOXPROX_HARD_SCENARIOS_DEFAULT"
    fi

    # Robust to all cscli JSON shapes (flat array / {decisions:[]} / array of
    # alerts): pull out decision objects, identified by having value + duration.
    # A jq failure skips the cycle: it must not look like "nothing active" and
    # wipe the seen list, or the next cycle re-alerts every active ban (M8).
    local current
    if ! current=$(echo "$decisions_json" | jq -r '
            [ .. | objects | select(has("value") and has("duration")) | select(.simulated != true) ]
            | .[] | "\(.id)|\(.value | tostring | gsub("[|\n\r]"; " "))|\(.scenario // "?" | tostring | gsub("[|\n\r]"; " "))|\(.origin // "?")"' 2>/dev/null); then
        log_once crowdsec_json "New-ban check skipped: cscli decisions output is not parseable JSON"
        return 0
    fi
    rm -f "$STATE_DIR/logged_crowdsec_json"
    current=$(sort -u <<< "$current")

    if [[ -z "$current" ]]; then
        : > "$seen_file" 2>/dev/null || true   # nothing active — forget previous IDs
        return 0
    fi

    # New = id not in the seen list. One awk pass: thousands of bans are active.
    touch "$seen_file" 2>/dev/null || true
    local new_lines
    new_lines=$(awk -F'|' -v seen="$seen_file" \
        'BEGIN { while ((getline id < seen) > 0) known[id] = 1 } !($1 in known)' <<< "$current") || return 0

    # Remember exactly the currently-active local bans; expired ones drop out, so a
    # later re-ban (new decision id) alerts again.
    cut -d'|' -f1 <<< "$current" > "$seen_file" 2>/dev/null || true
    [[ -n "$new_lines" ]] || return 0

    # Class of each new ban: hard (scenario matches BAN_HARD_SCENARIOS),
    # hard-ext (progressive-ban extending a HARD ban), or soft. Should jq fail
    # here, every new ban is treated as soft — alerted, never silently dropped.
    local classified
    classified=$(jq -Rr --arg re "$hard_re" '
            (split("|") | .[2] // "") as $s
            | "\(.)|\(if ($s | test($re)) then "hard" elif ($s | startswith("repeat-offender-hard-")) then "hard-ext" else "soft" end)"' \
            <<< "$new_lines" 2>/dev/null) || classified=$(sed 's/$/|soft/' <<< "$new_lines")

    local now soft_msg="" shown=0 more=0 id value scenario origin class
    now=$(date +%s)
    while IFS='|' read -r id value scenario origin class; do
        [[ -n "$id" ]] || continue
        if [[ "$class" == "hard" || "$class" == "hard-ext" ]]; then
            printf '%s|%s|%s\n' "$now" "$class" "$scenario" >> "$HARD_BANS_PENDING" 2>/dev/null || true
        elif (( shown < BAN_ALERT_MAX_ENTRIES )); then
            # Capped fields keep 15 entries well inside Discord's 2000 characters.
            soft_msg+="${value:0:39} — ${scenario:0:48} [${origin:0:12}]\n"
            shown=$((shown + 1))
        else
            more=$((more + 1))
        fi
    done <<< "$classified"
    [[ -n "$soft_msg" ]] || return 0
    if (( more > 0 )); then soft_msg+="… and ${more} more\n"; fi

    local community
    community=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d ' ') || true  # M6: count IPs not lines; never abort the send
    log "ALERT [WARNING]: New CrowdSec local ban(s)"
    "$DISCORD" "WARNING" "New CrowdSec Ban" \
        "Newly banned by a local scenario:\n${soft_msg}\nBackground: ${community:-?} IPs currently enforced via the CrowdSec community blocklist. Scanner (HARD) bans are counted in the daily digest." 2>/dev/null || true
}

check_hard_ban_digest() {
    # Once a day, on the first cycle at or after BAN_DIGEST_HOUR (local time):
    # one INFO message counting the HARD bans check_crowdsec_blocks queued since
    # the previous digest (at most the last 24 h), by scenario. While
    # TRAP_BAN_MODE=observe it also counts the trap alerts that did not ban.
    local now day="" hour="" digest_hour="$BAN_DIGEST_HOUR"
    [[ "$digest_hour" =~ ^[0-9]{1,2}$ ]] && (( 10#$digest_hour <= 23 )) || digest_hour=8
    now=$(date +%s)
    read -r day hour < <(date -d "@$now" '+%F %H' 2>/dev/null) || return 0
    [[ "$hour" =~ ^[0-9]{2}$ ]] || return 0
    (( 10#$hour >= 10#$digest_hour )) || return 0
    [ "$(cat "$HARD_DIGEST_STAMP" 2>/dev/null)" = "$day" ] && return 0
    # Stamp first: a failing send costs one digest, never a resend every cycle.
    echo "$day" > "$HARD_DIGEST_STAMP" 2>/dev/null || return 0

    local since=$((now - 86400)) bans=0 exts=0 by=""
    if [ -s "$HARD_BANS_PENDING" ]; then
        bans=$(awk -F'|' -v s="$since" '$1 >= s && $2 == "hard"' "$HARD_BANS_PENDING" | wc -l | tr -d ' ') || bans=0
        exts=$(awk -F'|' -v s="$since" '$1 >= s && $2 == "hard-ext"' "$HARD_BANS_PENDING" | wc -l | tr -d ' ') || exts=0
        by=$(awk -F'|' -v s="$since" '$1 >= s && $2 == "hard" { n[$3]++ } END { for (k in n) printf "%d %s\n", n[k], k }' \
                "$HARD_BANS_PENDING" | sort -k1,1nr -k2,2) || by=""
    fi
    : > "$HARD_BANS_PENDING" 2>/dev/null || true

    local body="New HARD bans (unambiguous scanners) in the last 24 h: ${bans}\n"
    if [[ -n "$by" ]]; then
        body+=$(awk 'NR <= 5 { printf "  %5d  %s\\n", $1, $2 }
                     NR > 5  { other += $1; kinds++ }
                     END     { if (kinds) printf "  %5d  other (%d scenarios)\\n", other, kinds }' <<< "$by")
    fi
    if (( exts > 0 )); then body+="Returning scanners whose ban progressive-ban extended: ${exts}\n"; fi

    if [[ "${TRAP_BAN_MODE,,}" == "observe" ]]; then
        local trap_json observed=""
        if trap_json=$(cscli alerts list -s loxprox/scanner-trap --since 24h -o json --limit 0 2>/dev/null); then
            observed=$(jq -r 'if type == "array" then [.[] | select(type == "object" and .simulated == true)] | length else 0 end' \
                <<< "$trap_json" 2>/dev/null) || observed=""
        fi
        if [[ "$observed" =~ ^[0-9]+$ ]]; then
            body+="\nTRAP_BAN_MODE=observe: ${observed} trap alert(s) in the last 24 h were observed (simulated, not banned).\n"
        else
            body+="\nTRAP_BAN_MODE=observe: the trap alert count is unavailable (cscli alerts list failed).\n"
        fi
        body+="review ${TRAP_HOSTS_LOG}, then set TRAP_BAN_MODE=ban\n"
    fi

    log "ALERT [INFO]: Daily HARD Ban Digest"
    "$DISCORD" "INFO" "Daily HARD Ban Digest" "$body" 2>/dev/null || true
    return 0
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
    # M7: the appsec_evt log_format is `$time_iso8601 $remote_addr "<method> <path> <proto>" ...`
    # — field 1 is the timestamp, so aggregating it produced one line per second
    # instead of a top-offender list. Field 2 is the client IP.
    detections=$(tail -c +$((last_pos + 1)) "$log" 2>/dev/null | awk '{print $2}' | sort | uniq -c | sort -rn | head -10) || true  # H2-class: SIGPIPE/no-match must not abort

    echo "$current_pos" > "$last_check_file"

    if [ -n "$detections" ]; then
        send_alert "WARNING" "AppSec Detections" "New AppSec WAF detections (hits IP):\n$detections" "appsec_detections"
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

check_cert_expiry() {
    # H13: acme.sh renews via cron and reports failures to a mailbox that does not
    # exist on this box (no MTA), so a broken renewal is otherwise silent until the
    # cert expires and every family phone stops connecting. Quiet no-op unless the
    # live site is actually in TLS mode.
    grep -q '^[[:space:]]*# LOXPROX-TLS-BEGIN[[:space:]]*$' "$NGINX_SITE" 2>/dev/null || return 0
    [ -f "$TLS_CERT" ] || return 0

    local end_date
    end_date=$(openssl x509 -enddate -noout -in "$TLS_CERT" 2>/dev/null | cut -d= -f2) || true
    [ -n "$end_date" ] || return 0

    local expiry_epoch
    expiry_epoch=$(date -d "$end_date" +%s 2>/dev/null) || true
    [ -n "$expiry_epoch" ] || return 0

    local now days
    now=$(date +%s)
    days=$(( (expiry_epoch - now) / 86400 ))

    local detail
    detail="Certificate: $TLS_CERT\nExpires: $end_date\n\n"
    detail+="acme.sh renews at 30 days left and has no way to tell you when it fails.\nCheck the renewal cron and force a renewal:\n"
    detail+="  crontab -l | grep acme\n"
    detail+="  sudo bash deploy.sh --renew-tls\n"
    detail+="Common causes: the WAN:80 → gateway:80 forward was removed, DNS no longer\npoints at your WAN IP, or the ACME challenge listener was overwritten."

    if [ "$days" -lt 0 ]; then
        send_alert "CRITICAL" "TLS Certificate EXPIRED" \
            "The gateway's TLS certificate expired $(( -days )) day(s) ago. Clients get a certificate error and the Loxone apps will refuse to connect.\n\n$detail" \
            "cert_expired" "$CERT_ALERT_COOLDOWN"
    elif [ "$days" -lt 7 ]; then
        send_alert "CRITICAL" "TLS Certificate Expires in ${days}d" \
            "The gateway's TLS certificate expires in $days day(s) and has not been renewed.\n\n$detail" \
            "cert_expiry_critical" "$CERT_ALERT_COOLDOWN"
    elif [ "$days" -lt 21 ]; then
        send_alert "WARNING" "TLS Certificate Expires in ${days}d" \
            "The gateway's TLS certificate expires in $days day(s). Automatic renewal should have happened at 30 days — it did not.\n\n$detail" \
            "cert_expiry_warning" "$CERT_ALERT_COOLDOWN"
    fi
}

check_geoip_staleness() {
    _geoip_stale_check "" "GeoIP Blocklist Stale" "The GeoIP blocklist"
    # IPv6 list (2026-10): its own stamps, its own alert. Only once a v6 refresh
    # has run at all, so an install that predates IPv6 stays quiet — and never
    # with GEOIP_IPV6_ENABLED=false, whatever stamps an earlier run left.
    if [ "$GEOIP_IPV6_ENABLED" = "true" ] \
            && { [ -f "$GEOIP_DIR/last-success6" ] || [ -f "$GEOIP_DIR/last-failure6" ]; }; then
        _geoip_stale_check "6" "GeoIP IPv6 Blocklist Stale" "The GeoIP IPv6 blocklist"
    fi
    return 0
}

_geoip_stale_check() {
    local fam="$1" title="$2" what="$3"
    # 2026-10: a failed nightly refresh keeps the last known-good list — safe,
    # but it failed silently night after night. One WARNING per stale episode:
    # the alert is keyed to the last success it reports, so it is re-armed only
    # after the list has refreshed again.
    [ -f "$GEOIP_SCRIPT" ] || return 0
    [ -e "$GEOIP_DIR/disabled" ] && return 0

    local last_ok="" ranges="" now
    if [ -f "$GEOIP_DIR/last-success${fam}" ]; then
        read -r last_ok ranges < "$GEOIP_DIR/last-success${fam}" || true
    fi
    # Installs that predate the stamp: the nftables include is rewritten only
    # after a successful refresh (deploy.sh's placeholder has no "Generated:").
    if [ -z "$fam" ] && [[ ! "$last_ok" =~ ^[0-9]+$ ]] && grep -qs 'Generated:' "$GEOIP_NFT_FILE"; then
        last_ok=$(stat -c %Y "$GEOIP_NFT_FILE" 2>/dev/null) || last_ok=""
    fi
    [[ "$last_ok" =~ ^[0-9]+$ ]] || last_ok=0

    now=$(date +%s)
    if (( now - last_ok < GEOIP_STALE_DAYS * 86400 )); then
        rm -f "$STATE_DIR/geoip${fam}_stale_alerted"
        return 0
    fi
    [ "$(cat "$STATE_DIR/geoip${fam}_stale_alerted" 2>/dev/null)" = "$last_ok" ] && return 0

    local since reason="" fail_ts="" fail_reason=""
    if (( last_ok > 0 )); then
        since="has not refreshed for $(( (now - last_ok) / 86400 )) day(s) — last success $(date -d "@$last_ok" '+%Y-%m-%d %H:%M')"
    else
        since="has never refreshed successfully"
    fi
    # The last failure's reason, if it is newer than the last success.
    if [ -f "$GEOIP_DIR/last-failure${fam}" ]; then
        read -r fail_ts fail_reason < "$GEOIP_DIR/last-failure${fam}" || true
        if [[ "$fail_ts" =~ ^[0-9]+$ ]] && (( fail_ts > last_ok )); then
            reason="${fail_reason:0:300}"
        fi
    fi
    "$DISCORD" "WARNING" "$title" \
        "${what} ${since}.\nThe last known-good list${ranges:+ (${ranges} ranges)} stays active, but new ranges are not picked up.\n${reason:+Last error: ${reason}\n}\nCheck: sudo bash ${GEOIP_SCRIPT}; tail /var/log/loxprox-cron.log" \
        2>/dev/null || true
    echo "$last_ok" > "$STATE_DIR/geoip${fam}_stale_alerted"
    log "ALERT [WARNING]: ${title}"
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

# ── 2026-10 breach hardening checks ──────────────────────────────────────────

log_once() {
    # Log a degraded condition once per distinct message, not every cycle.
    local key="$1" msg="$2" marker="$STATE_DIR/logged_$1"
    [ "$(cat "$marker" 2>/dev/null)" = "$msg" ] && return 0
    printf '%s' "$msg" > "$marker" 2>/dev/null || true
    log "$msg"
}

is_private_peer() {
    # LAN / loopback / link-local / ULA / CGNAT-or-tailnet: not a remote session.
    local ip="${1,,}"
    case "$ip" in
        10.*|127.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
        ::1|::|fe80:*|fc*:*|fd*:*) return 0 ;;
    esac
    return 1
}

ipv4_in_cidr() {
    local ip="$1" cidr="$2" net bits mask a b
    net="${cidr%/*}"; bits=32
    [[ "$cidr" == */* ]] && bits="${cidr#*/}"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$net" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$bits" =~ ^[0-9]+$ ]] || return 1
    (( bits >= 0 && bits <= 32 )) || return 1
    mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    local IFS=.
    local -a o1 o2
    read -ra o1 <<< "$ip"; read -ra o2 <<< "$net"
    a=$(( (o1[0] << 24) + (o1[1] << 16) + (o1[2] << 8) + o1[3] ))
    b=$(( (o2[0] << 24) + (o2[1] << 16) + (o2[2] << 8) + o2[3] ))
    (( (a & mask) == (b & mask) ))
}

is_whitelisted_peer() {
    local ip="$1" entry
    [ -f "$SESSION_WHITELIST_FILE" ] || return 1
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        if [[ "$ip" == *:* ]]; then
            [ "$ip" = "$entry" ] && return 0
        else
            ipv4_in_cidr "$ip" "$entry" && return 0
        fi
    done < <(sed -nE 's/^[[:space:]]*-[[:space:]]*"?([0-9A-Fa-f:.]+(\/[0-9]{1,3})?)"?[[:space:]]*$/\1/p' "$SESSION_WHITELIST_FILE" 2>/dev/null)
    return 1
}

mask_ip() {
    # Alerts never carry a full client address.
    local ip="$1"
    if [[ "$ip" == *:* ]]; then
        echo "$(echo "$ip" | cut -d: -f1-3):…/48"
    else
        echo "${ip%.*}.x"
    fi
}

mmdb_value() {
    # mmdblookup prints `  13335 <uint32>` or `  "DE" <utf8_string>`; return the bare value.
    local db="$1" ip="$2"; shift 2
    "$MMDBLOOKUP" --file "$db" --ip "$ip" "$@" 2>/dev/null \
        | sed -nE -e 's/^[[:space:]]*"(.*)"[[:space:]]+<[a-z0-9_]+>.*$/\1/p' \
                  -e 's/^[[:space:]]*([0-9]+)[[:space:]]+<[a-z0-9_]+>.*$/\1/p' \
        | head -n 1 | tr -cd '[:print:]' | cut -c1-80 || true
}

check_new_asn_session() {
    # A remote session = a public peer with an established TCP connection to the
    # Loxone port in two consecutive cycles. The first time an ASN is seen it is
    # recorded and (after the learning period) alerted once, so the family's own
    # mobile carriers become baseline and a login from a hosting provider stands out.
    [[ "${SESSION_ALERT_ENABLED,,}" == "true" ]] || return 0
    command -v ss >/dev/null 2>&1 || return 0
    if ! command -v "$MMDBLOOKUP" >/dev/null 2>&1; then
        log_once session_degraded "Session alert disabled: mmdblookup is not installed (apt install mmdb-bin)"; return 0
    fi
    if [ ! -r "$ASN_DB" ] || [ ! -r "$CITY_DB" ]; then
        log_once session_degraded "Session alert disabled: GeoLite2 database missing ($ASN_DB / $CITY_DB)"; return 0
    fi
    rm -f "$STATE_DIR/logged_session_degraded"

    local now; now=$(date +%s)
    if [ ! -f "$KNOWN_ASNS_FILE" ]; then
        printf '{"learning_started": %s, "asns": {}}\n' "$now" > "$KNOWN_ASNS_FILE.tmp" \
            && mv -f "$KNOWN_ASNS_FILE.tmp" "$KNOWN_ASNS_FILE" || return 0
        log "Session alert: learning ASNs silently for ${ASN_LEARNING_DAYS} day(s)"
    fi
    jq -e . "$KNOWN_ASNS_FILE" >/dev/null 2>&1 || { log_once session_state "Session alert skipped: $KNOWN_ASNS_FILE is not valid JSON"; return 0; }

    local prev_file="$STATE_DIR/session_peers_prev" cur="" peer
    while IFS= read -r peer; do
        [ -n "$peer" ] || continue
        is_private_peer "$peer" && continue
        is_whitelisted_peer "$peer" && continue
        cur+="$peer"$'\n'
    done < <(ss -Htn state established '( sport = :1080 )' 2>/dev/null \
                | awk '{print $NF}' | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff://I' | sort -u)

    local sessions=""
    [ -f "$prev_file" ] && sessions=$(printf '%s' "$cur" | grep -Fxf "$prev_file" || true)
    printf '%s' "$cur" > "$prev_file"
    [ -n "$sessions" ] || return 0

    local learning_started learning=0
    learning_started=$(jq -r '.learning_started // 0' "$KNOWN_ASNS_FILE")
    (( now - learning_started < ASN_LEARNING_DAYS * 86400 )) && learning=1

    local asn org cc masked
    while IFS= read -r peer; do
        [ -n "$peer" ] || continue
        asn=$(mmdb_value "$ASN_DB" "$peer" autonomous_system_number)
        [[ "$asn" =~ ^[0-9]+$ ]] || continue
        jq -e --arg a "$asn" '.asns[$a] != null' "$KNOWN_ASNS_FILE" >/dev/null 2>&1 && continue
        org=$(mmdb_value "$ASN_DB" "$peer" autonomous_system_organization)
        cc=$(mmdb_value "$CITY_DB" "$peer" country iso_code)
        jq --arg a "$asn" --arg o "${org:-?}" --arg c "${cc:-??}" --argjson t "$now" \
            '.asns[$a] = {org: $o, country: $c, first_seen: $t}' "$KNOWN_ASNS_FILE" > "$KNOWN_ASNS_FILE.tmp" \
            && mv -f "$KNOWN_ASNS_FILE.tmp" "$KNOWN_ASNS_FILE" || continue
        (( learning )) && continue
        masked=$(mask_ip "$peer")
        send_alert "WARNING" "Remote Session From a New ASN" \
            "A remote client held a session on the Loxone port from a network never seen before.\nASN: AS${asn} (${org:-unknown})\nCountry: ${cc:-??}\nClient: ${masked}\nIf this is a family member on a new carrier or VPN, ignore it; the ASN is now known and will not alert again." \
            "new_asn_${asn}" 0
    done <<< "$sessions"
    return 0
}

check_firewall_integrity() {
    # The inet filter ruleset is the last line of defence; a flushed or
    # half-loaded ruleset must not go unnoticed. Absent NEW elements (v6 drop
    # rule, egress rule) on a box that has neither is an old deploy: WARNING only.
    # Every cycle: the chains — policy, GeoIP drop rules, egress rules. Cheap:
    # `nft list chain` prints a named set as @name, not its elements. The set
    # listings (every range, tens of thousands) at most once per
    # FW_SET_CHECK_INTERVAL, stamped before the call like check_security_updates.
    command -v nft >/dev/null 2>&1 || return 0
    local crit="" warn="" input_chain output_chain v4 v6 v6_rule=0 egress=0 geoip=1
    [ -e "${GEOIP_DIR}/disabled" ] && geoip=0

    input_chain=$(nft list chain inet filter input 2>&1) || input_chain=""
    if ! grep -qE 'policy drop' <<< "$input_chain"; then
        crit+="inet filter input policy is not drop\n"
    fi
    # deploy.sh always writes both drop rules (the sets are merely empty while
    # GeoIP is disabled); the v6 one is new in 2026-10, so it marks a new deploy.
    grep -qE '(^|[[:space:]])ip6 saddr @geoip_blocklist6[[:space:]](.*[[:space:]])?drop' <<< "$input_chain" && v6_rule=1
    if (( geoip )) && ! grep -qE '(^|[[:space:]])ip saddr @geoip_blocklist[[:space:]](.*[[:space:]])?drop' <<< "$input_chain"; then
        crit+="input rule 'ip saddr @geoip_blocklist drop' is missing\n"
    fi

    output_chain=$(nft list chain inet filter output 2>&1) || output_chain=""
    grep -q 'loxprox-egress' <<< "$output_chain" && egress=1

    if (( geoip && ! v6_rule )); then
        if (( egress )); then crit+="input rule 'ip6 saddr @geoip_blocklist6 drop' is missing\n"; else warn+="IPv6 GeoIP rule not deployed yet (old deploy)\n"; fi
    fi
    if (( ! egress )); then
        if (( v6_rule )); then crit+="no output rule commented loxprox-egress\n"; else warn+="egress rules not deployed yet (old deploy)\n"; fi
    fi

    local now last_run=0 sets_stamp="$STATE_DIR/fw_sets_last_run"
    now=$(date +%s)
    [ -f "$sets_stamp" ] && last_run=$(cat "$sets_stamp" 2>/dev/null || echo 0)
    [[ "$last_run" =~ ^[0-9]+$ ]] || last_run=0
    if (( geoip )) && (( now - last_run >= FW_SET_CHECK_INTERVAL )); then
        echo "$now" > "$sets_stamp" 2>/dev/null || true
        v4=$(nft list set inet filter geoip_blocklist 2>&1) || v4=""
        if ! grep -q 'elements = {' <<< "$v4"; then
            crit+="set geoip_blocklist is missing or empty\n"
        fi
        # Empty by design with GEOIP_IPV6_ENABLED=false (still declared); an
        # old deploy without the v6 rule has nothing to list.
        if (( v6_rule )) && [ "$GEOIP_IPV6_ENABLED" = "true" ]; then
            if ! v6=$(nft list set inet filter geoip_blocklist6 2>&1); then
                crit+="set geoip_blocklist6 is missing\n"
            elif ! grep -q 'elements = {' <<< "$v6"; then
                crit+="set geoip_blocklist6 is empty\n"
            fi
        fi
    fi

    if [ -n "$crit" ]; then
        send_alert "CRITICAL" "Firewall Integrity Failure" \
            "The nftables ruleset no longer matches what deploy.sh installs:\n${crit}${warn:+\nAlso:\n${warn}}\nRe-apply: sudo bash deploy.sh (or nft -f /etc/nftables.conf), then check who changed it." \
            "fw_integrity_critical" 3600
    elif [ -n "$warn" ]; then
        send_alert "WARNING" "Firewall Hardening Not Deployed" \
            "${warn}Re-run deploy.sh to install the current ruleset." \
            "fw_integrity_warning" 86400
    fi
    return 0
}

check_security_updates() {
    # unattended-upgrades fails silently when its origin patterns stop matching
    # (Bookworm's security archive was renamed). A security update that sits
    # pending for days is the symptom, whatever the cause.
    command -v apt-get >/dev/null 2>&1 || return 0
    local now last_run_file="$STATE_DIR/sec_updates_last_run" last_run=0
    now=$(date +%s)
    [ -f "$last_run_file" ] && last_run=$(cat "$last_run_file" 2>/dev/null || echo 0)
    [[ "$last_run" =~ ^[0-9]+$ ]] || last_run=0
    (( now - last_run < SEC_UPDATE_CHECK_INTERVAL )) && return 0

    # Stamp BEFORE the call: a hung or failing apt then costs one capped run per
    # interval, not one per 60 s cycle. 45 s keeps a slow run inside one cycle.
    echo "$now" > "$last_run_file"
    local sim
    sim=$(LC_ALL=C timeout 45 apt-get -s upgrade 2>/dev/null) || { log "apt-get -s upgrade failed; skipping pending-update check"; return 0; }

    local sec info
    # `Inst pkg [old] (new Debian-Security:12/oldstable-security [arch])`
    sec=$(sed -nE 's/^Inst ([^ ]+) (\[[^]]*\] )?\(([^ ]+) .*Debian-Security.*/\1=\3/p' <<< "$sim" | sort -u)
    info=$(sed -nE 's/^Inst (crowdsec|crowdsec-firewall-bouncer[^ ]*) (\[[^]]*\] )?\(([^ ]+) .*/\1=\3/p' <<< "$sim" | sort -u)

    [ -f "$SEC_UPDATES_FILE" ] && jq -e . "$SEC_UPDATES_FILE" >/dev/null 2>&1 || echo '{"pending": {}, "notified": {}}' > "$SEC_UPDATES_FILE"

    # Keep first-seen for what is still pending, drop what got installed.
    local pending_json='{}' item first
    while IFS= read -r item; do
        [ -n "$item" ] || continue
        first=$(jq -r --arg k "$item" '.pending[$k] // empty' "$SEC_UPDATES_FILE")
        pending_json=$(jq --arg k "$item" --argjson t "${first:-$now}" '.[$k] = $t' <<< "$pending_json")
    done <<< "$sec"

    local notified_json
    notified_json=$(jq '.notified // {}' "$SEC_UPDATES_FILE")
    local new_info=""
    while IFS= read -r item; do
        [ -n "$item" ] || continue
        if [ "$(jq -r --arg k "$item" '.[$k] // empty' <<< "$notified_json")" = "" ]; then
            new_info+="${item}\n"
            notified_json=$(jq --arg k "$item" --argjson t "$now" '.[$k] = $t' <<< "$notified_json")
        fi
    done <<< "$info"

    jq -n --argjson p "$pending_json" --argjson n "$notified_json" '{pending: $p, notified: $n}' \
        > "$SEC_UPDATES_FILE.tmp" && mv -f "$SEC_UPDATES_FILE.tmp" "$SEC_UPDATES_FILE"

    local overdue
    overdue=$(jq -r --argjson now "$now" --argjson max "$((SEC_UPDATE_MAX_AGE_DAYS * 86400))" \
        '.pending | to_entries[] | select($now - .value > $max) | "\(.key) (pending \(($now - .value) / 86400 | floor)d)"' "$SEC_UPDATES_FILE")
    if [ -n "$overdue" ]; then
        send_alert "WARNING" "Security Updates Not Installing" \
            "Debian-Security updates have been pending for more than ${SEC_UPDATE_MAX_AGE_DAYS} days. unattended-upgrades is probably not matching the security archive.\n${overdue//$'\n'/\\n}\n\nCheck: sudo unattended-upgrade --dry-run -d | tail; /etc/apt/apt.conf.d/50unattended-upgrades" \
            "security_updates_pending" 86400
    fi
    if [ -n "$new_info" ]; then
        log "ALERT [INFO]: CrowdSec package update available"
        "$DISCORD" "INFO" "CrowdSec Update Available" \
            "A newer CrowdSec package is available (not installed automatically):\n${new_info}" 2>/dev/null || true
    fi
    return 0
}

check_auth_rate() {
    # Global rate of Loxone auth-path requests (all clients together). A single
    # family's usage is a trickle; a credential-stuffing run is not. The access
    # log is the scrubbed form: query dropped, token endpoints end in /<redacted>.
    # A cycle is one monitor run (the timer fires every 60 s).
    [ -f "$ACCESS_LOG" ] || return 0
    local pos_file="$STATE_DIR/last_auth_rate_pos" last_pos current_pos count=0
    current_pos=$(wc -c < "$ACCESS_LOG" | tr -d ' ')
    if [ ! -f "$pos_file" ]; then echo "$current_pos" > "$pos_file"; return 0; fi
    last_pos=$(cat "$pos_file" 2>/dev/null || echo 0)
    [[ "$last_pos" =~ ^[0-9]+$ ]] || last_pos=0
    echo "$current_pos" > "$pos_file"
    (( current_pos == last_pos )) && return 0
    (( current_pos < last_pos )) && last_pos=0   # rotated: count the new file from the top

    # 301/497 answers are the cleartext-to-TLS redirect, not authentication.
    # The auth paths are those of deploy.sh's $loxprox_auth_path map and the
    # loxprox/auth-bf scenario — both spellings (jdev/ and the deprecated dev/),
    # any method — as the scrubbed log writes them: /jdev/sys/<cmd>/<redacted>,
    # or the bare command (getkey) followed by the protocol.
    count=$(tail -c +$((last_pos + 1)) "$ACCESS_LOG" 2>/dev/null \
        | grep -E '"[A-Z]+ /j?dev/sys/(getkey2?|getjwt|gettoken|authwithtoken|refreshjwt)[/ ]' \
        | grep -cvE '" (301|497) ') || true
    [[ "$count" =~ ^[0-9]+$ ]] || count=0

    if (( count > AUTH_RATE_ALERT_PER_CYCLE )); then
        send_alert "WARNING" "High Loxone Auth Request Rate" \
            "${count} authentication requests reached the Loxone port since the last cycle (threshold ${AUTH_RATE_ALERT_PER_CYCLE}, all clients together).\nThis can be a credential-stuffing run, or a misconfigured app retrying in a loop. See: cscli alerts list; tail /var/log/nginx/loxone-access.log" \
            "auth_rate"
    fi
    return 0
}

# ── CrowdSec log reading (2026-10-21) ────────────────────────────────────────
# CrowdSec's file acquisition can stop for good at a logrotate: with a log
# acquired twice, the two tailers of the file close each other's inotify watch
# — one stops without a word, the other logs "file reader died" — and a file
# listed by name is not picked up again until CrowdSec restarts. Log-based
# detection (trap, unknown-path, auth-bf, the http and CVE scenarios) is then
# blind while AppSec and the community blocklist keep working, so nothing else
# notices. deploy.sh acquires every log once since 2026-10-21; this is the
# safety net. It acts on positive evidence only — AppSec fails closed, so every
# request gets a 500 for the seconds of a restart:
#   1. a "file reader died" line CrowdSec wrote after its current start;
#   2. a watched log that grew ACQ_STALL_CYCLES times while CrowdSec read none
#      of it (cs_filesource_hits_total). A log without a counter yet, a cycle
#      with a rotation (new inode) or a CrowdSec restart gives no verdict.
# Then crowdsec is restarted, at most once per ACQ_RESTART_INTERVAL, with a
# Discord WARNING naming what stopped and when (CRITICAL if it does not come
# back). Evidence that cannot be acted on yet (the hour is not over, or the
# hub refresh holds its lock) is kept for the next cycle.

# Epoch of crowdsec's current start, or nothing.
_crowdsec_start_epoch() {
    local ts
    ts=$(systemctl show crowdsec -p ExecMainStartTimestamp --value 2>/dev/null) || ts=""
    if [ -z "$ts" ] || [ "$ts" = "n/a" ]; then return 0; fi
    date -d "$ts" +%s 2>/dev/null || true
}

# ACQ_DEATHS ← "epoch|time|file|message" per reader death CrowdSec logged after
# its start ($1): the lines crowdsec.log gained since the last cycle (the whole
# file on the first cycle, or after it was replaced), plus deaths kept from
# earlier cycles that were not acted on.
_acq_reader_deaths() {
    local start="$1" pos_file="$STATE_DIR/crowdsec_log_pos" pending="$STATE_DIR/acq_deaths_pending"
    local inode="" size=0 last_inode="" last_pos=0 from=0 line all="" e t f m
    ACQ_DEATHS=""
    if [ -z "$start" ]; then
        log_once acq_start "crowdsec's start time is unreadable (systemctl show) — reader-death check skipped"
        return 0
    fi
    rm -f "$STATE_DIR/logged_acq_start"
    if [ -f "$pending" ]; then all=$(cat "$pending" 2>/dev/null || true); fi
    if [ -f "$CROWDSEC_LOG" ] && read -r inode size < <(stat -c '%i %s' "$CROWDSEC_LOG" 2>/dev/null); then
        if [ -f "$pos_file" ]; then read -r last_inode last_pos < "$pos_file" || true; fi
        [[ "$last_pos" =~ ^[0-9]+$ ]] || last_pos=0
        if [ "$inode" = "$last_inode" ] && [ "$size" -ge "$last_pos" ]; then from=$last_pos; fi
        printf '%s %s\n' "$inode" "$size" > "$pos_file"
        if [ "$size" -gt "$from" ]; then
            while IFS= read -r line; do
                t=$(sed -nE 's/^time="([^"]+)".*/\1/p' <<<"$line")
                e=$(date -d "$t" +%s 2>/dev/null) || continue
                f=$(sed -nE 's/.* tail=([^ ]+).*/\1/p' <<<"$line")
                m=$(sed -nE 's/.*msg="([^"]*)".*/\1/p' <<<"$line")
                all+=$'\n'"$e|$t|${f:-?}|${m//|//}"
            # Only the text is used (the bytes up to the size recorded above).
            done < <(tail -c +$((from + 1)) "$CROWDSEC_LOG" 2>/dev/null | head -c $((size - from)) \
                     | grep -F 'file reader died' | tail -n 20 || true)
        fi
    fi
    while IFS='|' read -r e t f m; do
        if [[ "$e" =~ ^[0-9]+$ ]] && [ "$e" -ge "$start" ]; then ACQ_DEATHS+="$e|$t|$f|$m"$'\n'; fi
    done <<<"$all"
    ACQ_DEATHS=$(printf '%s' "$ACQ_DEATHS" | sort -u | tail -n 20)
    if [ -n "$ACQ_DEATHS" ]; then printf '%s\n' "$ACQ_DEATHS" > "$pending"; else rm -f "$pending"; fi
}

# ACQ_STALLS ← "file|times|bytes" per watched log that grew ACQ_STALL_CYCLES
# times while CrowdSec read none of it. State: crowdsec's PID, then one
# "file inode size reads times bytes" line per log.
_acq_stalled_logs() {
    local pid="$1" state="$STATE_DIR/acq_reads" metrics f inode size reads streak grown new="" p_pid=""
    local pf pi ps pr pk pg
    local -A cur=() prev_i=() prev_s=() prev_r=() prev_k=() prev_g=()
    ACQ_STALLS=""
    metrics=$(curl -s --max-time 5 "$CROWDSEC_METRICS_URL" 2>/dev/null) || metrics=""
    if ! grep -q '^cs_' <<<"$metrics"; then
        log_once acq_metrics "CrowdSec metrics unreadable at $CROWDSEC_METRICS_URL — log-reading stall check skipped"
        return 0
    fi
    rm -f "$STATE_DIR/logged_acq_metrics"
    while read -r f reads; do
        if [ -n "$f" ]; then cur[$f]=$reads; fi
    done < <(awk '/^cs_filesource_hits_total\{/ && match($0, /source="[^"]*"/) { n[substr($0, RSTART + 8, RLENGTH - 9)] += $NF }
                  END { for (s in n) printf "%s %.0f\n", s, n[s] }' <<<"$metrics")
    if [ -f "$state" ]; then
        { read -r p_pid || true
          while read -r pf pi ps pr pk pg; do
              [ -n "$pf" ] || continue
              prev_i[$pf]=$pi prev_s[$pf]=$ps prev_r[$pf]=$pr prev_k[$pf]=$pk prev_g[$pf]=$pg
          done; } < "$state"
    fi
    for f in $ACQ_WATCH_LOGS; do
        [ -f "$f" ] || continue
        read -r inode size < <(stat -c '%i %s' "$f" 2>/dev/null) || continue
        reads="${cur[$f]:--}"
        streak=0 grown=0
        if [ -n "$pid" ] && [ "$pid" = "$p_pid" ] && [ "$inode" = "${prev_i[$f]:-}" ] \
                && [ "$reads" != "-" ] && [ "${prev_r[$f]:--}" != "-" ] \
                && [[ "${prev_s[$f]:-}" =~ ^[0-9]+$ && "${prev_k[$f]:-}" =~ ^[0-9]+$ && "${prev_g[$f]:-}" =~ ^[0-9]+$ ]]; then
            streak=${prev_k[$f]} grown=${prev_g[$f]}
            if [ "$reads" != "${prev_r[$f]}" ]; then
                streak=0 grown=0
            elif [ "$size" -gt "${prev_s[$f]}" ]; then
                streak=$((streak + 1)) grown=$((grown + size - ${prev_s[$f]}))
            fi
        fi
        new+="$f $inode $size $reads $streak $grown"$'\n'
        if [ "$streak" -ge "$ACQ_STALL_CYCLES" ]; then ACQ_STALLS+="$f|$streak|$grown"$'\n'; fi
    done
    printf '%s\n%s' "$pid" "$new" > "$state.tmp" && mv -f "$state.tmp" "$state"
}

check_crowdsec_acquisition() {
    systemctl is-active --quiet crowdsec || return 0   # check_gateway_health alerts on that
    local pid start now last=0 what="" e t f m n g rc=0 i active=0 at
    pid=$(systemctl show crowdsec -p MainPID --value 2>/dev/null) || pid=""
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || pid=""
    start=$(_crowdsec_start_epoch)
    now=$(date +%s)
    _acq_reader_deaths "$start"
    _acq_stalled_logs "$pid"
    [ -n "$ACQ_DEATHS$ACQ_STALLS" ] || return 0

    while IFS='|' read -r e t f m; do
        [ -n "$e" ] || continue
        what+="- ${f##*/}: reader died at ${t} (${m})\n"
    done <<<"$ACQ_DEATHS"
    while IFS='|' read -r f n g; do
        [ -n "$f" ] || continue
        what+="- ${f##*/}: grew by ${g} bytes in ${n} checks, CrowdSec read none of it\n"
    done <<<"$ACQ_STALLS"

    if [ -f "$STATE_DIR/acq_restart_last" ]; then last=$(cat "$STATE_DIR/acq_restart_last" 2>/dev/null || echo 0); fi
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
    if [ $((now - last)) -lt "$ACQ_RESTART_INTERVAL" ]; then
        send_alert "HIGH" "CrowdSec Log Reading Still Stopped" \
            "CrowdSec stopped reading these logs again, $(( (now - last) / 60 )) min after the monitor restarted it for that:\n${what}At most one restart per hour, so not now: log-based detection stays blind until the next one.\nCheck: sudo cscli metrics show acquisition; sudo grep 'file reader died' ${CROWDSEC_LOG}" \
            "acq_restart_skipped" "$ACQ_RESTART_INTERVAL"
        return 0
    fi
    if command -v flock >/dev/null 2>&1 && [ -e "$HUB_REFRESH_LOCK" ] && ! flock -n "$HUB_REFRESH_LOCK" true 2>/dev/null; then
        log "CrowdSec log reading stopped, but the hub refresh holds its lock — restart deferred to the next cycle"
        return 0
    fi

    echo "$now" > "$STATE_DIR/acq_restart_last"
    log "CrowdSec log reading stopped — restarting crowdsec: ${what}"
    systemctl restart crowdsec >/dev/null 2>&1 || rc=$?
    for (( i = 0; i < ACQ_RESTART_WAIT; i++ )); do
        if systemctl is-active --quiet crowdsec; then active=1; break; fi
        sleep 1
    done
    rm -f "$STATE_DIR/acq_deaths_pending" "$STATE_DIR/acq_reads"
    at=$(date '+%Y-%m-%d %H:%M:%S')
    if (( active )); then
        send_alert "WARNING" "CrowdSec Log Reading Stopped — Restarted" \
            "CrowdSec had stopped reading these logs, so log-based detection (trap, unknown-path, auth, http and CVE scenarios) was blind; AppSec and the community blocklist kept working:\n${what}Restarted crowdsec at ${at}; it is active again. AppSec answers 500 for the seconds of a restart. At most one such restart per hour.\nUsual cause: a log acquired twice (test-gateway.sh checks it). Lines read per log: sudo cscli metrics show acquisition" \
            "acq_restarted" 60
    else
        send_alert "CRITICAL" "CrowdSec Down After a Log-Reading Restart" \
            "CrowdSec had stopped reading these logs:\n${what}The monitor restarted it at ${at} (systemctl exit ${rc}) and it is not active after ${ACQ_RESTART_WAIT}s. AppSec fails closed: nginx answers 500 to every request and the Loxone apps cannot connect.\nRecover:\n  sudo journalctl -u crowdsec -n 80 --no-pager\n  sudo systemctl restart crowdsec" \
            "acq_restart_failed" 60
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    log "Security monitor cycle started"
    
    check_gateway_health
    check_crowdsec_acquisition
    check_crowdsec_blocks
    check_hard_ban_digest
    check_nginx_errors
    check_auth_attempts
    check_appsec_detections
    check_system_resources
    check_cert_expiry
    check_geoip_staleness
    check_new_asn_session
    check_firewall_integrity
    check_security_updates
    check_auth_rate
    
    log "Security monitor cycle completed"
}

# Only run when executed, not when sourced (tests source it for single checks).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
