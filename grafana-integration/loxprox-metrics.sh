#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Prometheus Textfile Collector
# ═══════════════════════════════════════════════════════════════════════════════
# Writes LoxProx-specific metrics in Prometheus format for node_exporter's
# textfile collector to expose. Run every 60s via systemd timer.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

OUTDIR="/var/lib/node_exporter/textfile_collector"
OUTFILE="$OUTDIR/loxprox.prom"
TMPFILE="$OUTFILE.$$"

mkdir -p "$OUTDIR"

# ── CrowdSec metrics ───────────────────────────────────────────────────────────

CROWDSEC_BLOCKS=0
if command -v cscli >/dev/null 2>&1; then
    CROWDSEC_BLOCKS=$(cscli decisions list -o json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
fi

CROWDSEC_ALERTS=0
if command -v cscli >/dev/null 2>&1; then
    CROWDSEC_ALERTS=$(cscli alerts list -o json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
fi

# ── nginx metrics ──────────────────────────────────────────────────────────────

NGINX_ERROR_COUNT=0
if [[ -f /var/log/nginx/loxone-error.log ]]; then
    # grep -c already prints "0" on no matches; `|| true` masks the rc=1 only.
    # Using `|| echo 0` here would emit two lines under `pipefail` and break
    # the Prometheus textfile collector.
    NGINX_ERROR_COUNT=$(tail -n 1000 /var/log/nginx/loxone-error.log 2>/dev/null | \
        grep -cE "limiting requests|upstream prematurely|502|503|504" || true)
fi

NGINX_RATE_LIMITED=0
if [[ -f /var/log/nginx/loxone-error.log ]]; then
    NGINX_RATE_LIMITED=$(tail -n 1000 /var/log/nginx/loxone-error.log 2>/dev/null | \
        grep -c "limiting requests" || true)
fi

# ── AppSec metrics ─────────────────────────────────────────────────────────────

APPSEC_DETECTIONS=0
if [[ -f /var/log/nginx/appsec-detections.log ]]; then
    APPSEC_DETECTIONS=$(wc -l < /var/log/nginx/appsec-detections.log 2>/dev/null || echo 0)
fi

# ── SSH metrics ────────────────────────────────────────────────────────────────

SSH_FAILED=0
if [[ -f /var/log/auth.log ]]; then
    SSH_FAILED=$(grep -cE "Failed password|Invalid user" /var/log/auth.log 2>/dev/null || true)
fi

# ── Service health ─────────────────────────────────────────────────────────────

nginx_up=0
systemctl is-active --quiet nginx 2>/dev/null && nginx_up=1

crowdsec_up=0
systemctl is-active --quiet crowdsec 2>/dev/null && crowdsec_up=1

bouncer_up=0
systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null && bouncer_up=1

watchdog_up=0
systemctl is-active --quiet network-watchdog.timer 2>/dev/null && watchdog_up=1

monitor_up=0
systemctl is-active --quiet loxprox-monitor.timer 2>/dev/null && monitor_up=1

# ── Network watchdog ───────────────────────────────────────────────────────────

WATCHDOG_REBOOTS=0
if [[ -f /var/lib/loxprox/watchdog-reboot-history.log ]]; then
    WATCHDOG_REBOOTS=$(wc -l < /var/lib/loxprox/watchdog-reboot-history.log 2>/dev/null || echo 0)
fi

# ── Monitor health ─────────────────────────────────────────────────────────────

monitor_last_run=0
if [[ -f /var/log/loxprox-monitor.log ]]; then
    monitor_last_run=$(stat -c %Y /var/log/loxprox-monitor.log 2>/dev/null || echo 0)
fi

# ── Write Prometheus format ────────────────────────────────────────────────────

cat > "$TMPFILE" <<EOF
# HELP loxprox_crowdsec_blocks Number of active CrowdSec block decisions
# TYPE loxprox_crowdsec_blocks gauge
loxprox_crowdsec_blocks $CROWDSEC_BLOCKS

# HELP loxprox_crowdsec_alerts Number of active CrowdSec alerts
# TYPE loxprox_crowdsec_alerts gauge
loxprox_crowdsec_alerts $CROWDSEC_ALERTS

# HELP loxprox_nginx_errors_recent Recent nginx error log entries (last 1000 lines)
# TYPE loxprox_nginx_errors_recent gauge
loxprox_nginx_errors_recent $NGINX_ERROR_COUNT

# HELP loxprox_nginx_rate_limited_recent Recent rate limit hits (last 1000 lines)
# TYPE loxprox_nginx_rate_limited_recent gauge
loxprox_nginx_rate_limited_recent $NGINX_RATE_LIMITED

# HELP loxprox_appsec_detections_total Total AppSec WAF detections
# TYPE loxprox_appsec_detections_total counter
loxprox_appsec_detections_total $APPSEC_DETECTIONS

# HELP loxprox_ssh_failed_total Total failed SSH login attempts in auth.log
# TYPE loxprox_ssh_failed_total counter
loxprox_ssh_failed_total $SSH_FAILED

# HELP loxprox_service_up Service health status (1 = up, 0 = down)
# TYPE loxprox_service_up gauge
loxprox_service_up{service="nginx"} $nginx_up
loxprox_service_up{service="crowdsec"} $crowdsec_up
loxprox_service_up{service="crowdsec-firewall-bouncer"} $bouncer_up
loxprox_service_up{service="network-watchdog"} $watchdog_up
loxprox_service_up{service="loxprox-monitor"} $monitor_up

# HELP loxprox_watchdog_reboots_total Watchdog-initiated reboots (lifetime count)
# TYPE loxprox_watchdog_reboots_total counter
loxprox_watchdog_reboots_total $WATCHDOG_REBOOTS

# HELP loxprox_monitor_last_run_unixtime Last monitor run timestamp
# TYPE loxprox_monitor_last_run_unixtime gauge
loxprox_monitor_last_run_unixtime $monitor_last_run
EOF

# Atomic write
mv "$TMPFILE" "$OUTFILE"
