#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Discord Alert Dispatcher
# ═══════════════════════════════════════════════════════════════════════════════
# Sends security events to Discord webhook. Called by monitoring scripts
# and systemd path units when log files change.
#
# Usage: discord-alert.sh "Severity" "Title" "Message" [optional_fields_json]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Configuration: read from env or fallback to /etc/loxprox/config.env
CONFIG_FILE="${LOXPROX_CONFIG:-/etc/loxprox/config.env}"
if [[ -f "$CONFIG_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    set +a
fi

WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
LOXONE_IP="${LOXONE_IP:-192.168.1.100}"
GATEWAY_IP="${GATEWAY_IP:-192.168.1.50}"

if [[ -z "$WEBHOOK_URL" ]]; then
    echo "ERROR: DISCORD_WEBHOOK_URL not set. Configure it in $CONFIG_FILE or set the environment variable." >&2
    exit 1
fi

SEVERITY="${1:-INFO}"
TITLE="${2:-Security Alert}"
MESSAGE="${3:-No details provided}"
# Color mapping
case "${SEVERITY^^}" in
    CRITICAL) COLOR=15158332 ;;  # red
    HIGH)     COLOR=16711680 ;;  # bright red
    WARNING)  COLOR=16776960 ;;  # yellow
    INFO)     COLOR=3447003  ;;  # blue
    LOW)      COLOR=3066993  ;;  # green
    *)        COLOR=9807270  ;;  # grey
esac

# Truncate message if too long for Discord embed (max 4096 for description)
if [ ${#MESSAGE} -gt 4000 ]; then
    MESSAGE="${MESSAGE:0:4000}... [truncated]"
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname -s 2>/dev/null || echo "gateway")

PAYLOAD=$(cat <<EOF
{
    "embeds": [{
        "title": "$TITLE",
        "description": "\`\`\`\n$MESSAGE\n\`\`\`",
        "color": $COLOR,
        "timestamp": "$TIMESTAMP",
        "footer": {
            "text": "$HOSTNAME | LoxProx"
        },
        "fields": [
            {
                "name": "Severity",
                "value": "$SEVERITY",
                "inline": true
            },
            {
                "name": "Gateway",
                "value": "$GATEWAY_IP",
                "inline": true
            },
            {
                "name": "Loxone",
                "value": "$LOXONE_IP",
                "inline": true
            }
        ]
    }]
}
EOF
)

# Send to Discord with retry logic
for attempt in 1 2 3; do
    if curl -s -o /dev/null -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        --connect-timeout 10 \
        --max-time 15 \
        "$WEBHOOK_URL" | grep -q "^20[0-9]$"; then
        exit 0
    fi
    sleep "$((attempt * 2))"
done

logger -t loxprox-discord "FAILED to send Discord alert: $TITLE"
exit 1
