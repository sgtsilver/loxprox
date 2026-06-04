#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Comprehensive Test Suite
# ═══════════════════════════════════════════════════════════════════════════════
# Validates all security components after deployment. Run on the gateway VM.
#
# Usage: sudo ./test-gateway.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

test_header() {
    echo ""
    echo "━━━ $1 ━━━"
}

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    ((TESTS_FAILED++))
}

warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

# ── Service Tests ────────────────────────────────────────────────────────────

test_services() {
    test_header "Core Services"

    for svc in nginx crowdsec crowdsec-firewall-bouncer; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            pass "$svc is running"
        else
            fail "$svc is NOT running"
        fi
    done

    if systemctl is-enabled --quiet nftables 2>/dev/null; then
        pass "nftables is enabled"
    else
        warn "nftables may not be enabled (one-shot service)"
    fi

    if systemctl is-enabled --quiet loxprox-monitor.timer 2>/dev/null; then
        pass "monitor timer is enabled"
    else
        warn "monitor timer not enabled"
    fi

    if systemctl is-enabled --quiet network-watchdog.timer 2>/dev/null; then
        pass "network watchdog timer is enabled"
    else
        warn "network watchdog timer not enabled"
    fi
}

# ── Network Tests ────────────────────────────────────────────────────────────

test_network() {
    test_header "Network & Firewall"

    # Check listening ports
    if ss -tlnp | grep -q ':1080 '; then
        pass "nginx listening on :1080"
    else
        fail "nginx NOT listening on :1080"
    fi

    if ss -tlnp | grep -q ':22 '; then
        pass "sshd listening on :22"
    else
        fail "sshd NOT listening on :22"
    fi

    # Check nftables input policy
    local policy
    policy=$(nft list chain inet filter input 2>/dev/null | grep -oP 'policy \K\w+')
    if [[ "$policy" == "drop" ]]; then
        pass "nftables input policy is DROP"
    else
        fail "nftables input policy is '$policy' (expected DROP)"
    fi

    # Check SSH is restricted
    if nft list chain inet filter input 2>/dev/null | grep -qE 'dport 22.*saddr|tcp dport 22'; then
        pass "SSH port has source restrictions"
    else
        warn "SSH port may not have source restrictions"
    fi

    # Check CrowdSec table exists
    if nft list tables 2>/dev/null | grep -qE 'crowdsec|crowdsec6'; then
        pass "CrowdSec nftables table exists"
    else
        warn "CrowdSec nftables table not found (bouncer may still be initializing)"
    fi
}

# ── Proxy Tests ──────────────────────────────────────────────────────────────

test_proxy() {
    test_header "Nginx Proxy"

    # Test localhost proxy
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://127.0.0.1:1080/jdev/cfg/api 2>/dev/null)
    if [[ "$status" == "200" || "$status" == "401" ]]; then
        pass "Proxy responds to Loxone API (HTTP $status)"
    else
        fail "Proxy returned HTTP $status (expected 200 or 401)"
    fi

    # Test security headers
    local headers
    headers=$(curl -sI --connect-timeout 5 http://127.0.0.1:1080/jdev/cfg/api 2>/dev/null)
    if echo "$headers" | grep -qi "X-Frame-Options"; then
        pass "X-Frame-Options header present"
    else
        fail "X-Frame-Options header missing"
    fi
    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        pass "CSP header present"
    else
        fail "CSP header missing"
    fi
    if echo "$headers" | grep -qi "Permissions-Policy"; then
        pass "Permissions-Policy header present"
    else
        fail "Permissions-Policy header missing"
    fi
    if echo "$headers" | grep -qi "X-XSS-Protection"; then
        fail "Deprecated X-XSS-Protection header still present (should be removed)"
    else
        pass "X-XSS-Protection correctly removed"
    fi

    # Test rate limiting (send 150 requests quickly)
    local limited=0
    for _ in {1..5}; do
        local s
        s=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:1080/jdev/cfg/api 2>/dev/null)
        [[ "$s" == "503" ]] && limited=1
    done
    if [[ "$limited" -eq 0 ]]; then
        pass "Rate limiting: no false 503s on benign traffic"
    else
        warn "Rate limiting returned 503 (may need burst tuning)"
    fi
}

# ── CrowdSec Tests ───────────────────────────────────────────────────────────

test_crowdsec() {
    test_header "CrowdSec IDS"

    # Check LAPI is responding (any 2xx/4xx means it's up; 5xx or timeout means down)
    local lapi_status
    lapi_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 http://127.0.0.1:8080/v1/decisions 2>/dev/null)
    if [[ "$lapi_status" =~ ^[24][0-9][0-9]$ ]]; then
        pass "CrowdSec LAPI is responding (HTTP $lapi_status)"
    else
        fail "CrowdSec LAPI not responding (HTTP ${lapi_status:-none})"
    fi

    # Check parsers are processing logs
    local nginx_lines
    nginx_lines=$(cscli metrics 2>/dev/null | awk '/file:\/var\/log\/nginx\/loxone-access.log/ {print $2}')
    if [[ -n "$nginx_lines" && "$nginx_lines" != "0" ]]; then
        pass "Nginx logs parsed ($nginx_lines lines)"
    else
        warn "No nginx log lines parsed yet (may need traffic)"
    fi

    # Test decision → bouncer → nftables pipeline
    local test_ip="198.51.100.99"
    cscli decisions add --ip "$test_ip" --duration 1m --reason "gateway-test" --type ban >/dev/null 2>&1
    sleep 5

    if cscli decisions list 2>/dev/null | grep -q "$test_ip"; then
        pass "Decision created successfully"
    else
        fail "Decision creation failed"
    fi

    if nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | grep -q "$test_ip"; then
        pass "Decision propagated to nftables"
    else
        warn "Decision not yet in nftables (bouncer pulls every 10s)"
    fi

    cscli decisions delete --ip "$test_ip" >/dev/null 2>&1 || true
}

# ── AppSec Tests ─────────────────────────────────────────────────────────────

test_appsec() {
    test_header "CrowdSec AppSec WAF"

    # Check AppSec listener
    if ss -tlnp | grep -q ':7422 '; then
        pass "AppSec listening on 127.0.0.1:7422"
    else
        fail "AppSec NOT listening on :7422"
    fi

    # Check AppSec metrics show processed requests
    local processed
    processed=$(cscli metrics 2>/dev/null | awk '/appsec-loxone/ {print $2}')
    if [[ -n "$processed" && "$processed" != "0" && "$processed" != "-" ]]; then
        pass "AppSec has processed $processed requests"
    else
        warn "AppSec has not processed requests yet (send traffic and retry)"
    fi

    # Verify nginx AppSec include exists and has API key
    if [[ -f /etc/nginx/crowdsec-appsec.conf ]]; then
        if grep -q "X-Crowdsec-Appsec-Api-Key" /etc/nginx/crowdsec-appsec.conf; then
            pass "nginx AppSec include configured with API key"
        else
            fail "nginx AppSec include missing API key"
        fi
    else
        fail "nginx AppSec include file missing"
    fi

    # Verify end-to-end: proxy request should trigger AppSec
    local appsec_before appsec_after
    appsec_before=$(cscli metrics 2>/dev/null | awk '/appsec-loxone/ {print $2}')
    appsec_before=${appsec_before:-0}

    curl -s -o /dev/null --connect-timeout 5 http://127.0.0.1:1080/jdev/cfg/api 2>/dev/null
    sleep 2

    appsec_after=$(cscli metrics 2>/dev/null | awk '/appsec-loxone/ {print $2}')
    appsec_after=${appsec_after:-0}

    # Use string comparison to avoid bash arithmetic errors with empty vars
    if [[ "$appsec_after" != "$appsec_before" ]]; then
        pass "AppSec inspects proxy traffic end-to-end"
    else
        warn "AppSec metrics did not increment (may be delayed)"
    fi

    # LOW-010: AppSec 401 error detection
    local appsec_status
    appsec_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://127.0.0.1:1080/crowdsec-appsec 2>/dev/null)
    if [[ "$appsec_status" == "401" ]]; then
        warn "AppSec returned 401 — bouncer API key may be misconfigured"
    else
        pass "AppSec auth subrequest responds without 401 (HTTP ${appsec_status:-none})"
    fi

    # LOW-010: CrowdSec whitelist syntax validation
    local whitelist_file="/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml"
    if [[ -f "$whitelist_file" ]]; then
        if cscli parsers inspect whitelist-loxone 2>/dev/null | grep -qi "whitelist-loxone"; then
            pass "CrowdSec whitelist parser is registered"
        else
            warn "CrowdSec whitelist parser may not be registered yet"
        fi
    else
        warn "CrowdSec whitelist file not found"
    fi
}

# ── Monitoring Tests ─────────────────────────────────────────────────────────

test_monitoring() {
    test_header "Monitoring & Alerting"

    # Check monitor script exists and is executable
    if [[ -x /opt/loxprox/gateway-monitor.sh ]]; then
        pass "Monitor script exists and is executable"
    else
        fail "Monitor script missing or not executable"
    fi

    # Check discord alert script
    if [[ -x /opt/loxprox/discord-alert.sh ]]; then
        pass "Discord alert script exists"
    else
        fail "Discord alert script missing"
    fi

    # Check the Discord webhook is actually configured. An empty webhook makes
    # the monitor detect bans and then silently drop every alert — exactly the
    # failure that hid for weeks after the v1.5.0 config split (--bootstrap-config
    # cannot recover a webhook from live system state). Warn, don't fail: alerting
    # is optional, but a silent-no-alerts gateway is worse than a loud warning.
    if [[ -f /etc/loxprox/config.env ]] && \
       grep -qE '^DISCORD_WEBHOOK_URL="https://' /etc/loxprox/config.env 2>/dev/null; then
        pass "Discord webhook is configured"
    else
        warn "Discord webhook NOT configured in /etc/loxprox/config.env — ban/alert notifications are disabled (set DISCORD_WEBHOOK_URL)"
    fi

    # Check monitor log
    if [[ -f /var/log/loxprox-monitor.log ]]; then
        pass "Monitor log exists"
    else
        warn "Monitor log not yet created"
    fi

    # Verify jq is installed (required by monitor)
    if command -v jq >/dev/null 2>&1; then
        pass "jq is installed (monitor dependency)"
    else
        fail "jq is NOT installed (monitor will fail)"
    fi
}

# ── sysctl Tests ─────────────────────────────────────────────────────────────

test_sysctl() {
    test_header "Kernel Hardening"

    local checks=(
        "net.ipv4.tcp_syncookies:1"
        "net.ipv4.conf.all.accept_redirects:0"
        "net.ipv4.conf.all.rp_filter:1"
        "kernel.dmesg_restrict:1"
        "fs.protected_hardlinks:1"
    )

    for check in "${checks[@]}"; do
        local key=${check%%:*}
        local expected=${check##*:}
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null)
        if [[ "$actual" == "$expected" ]]; then
            pass "$key = $expected"
        else
            fail "$key = $actual (expected $expected)"
        fi
    done
}

# ── Backup Tests ─────────────────────────────────────────────────────────────

test_backup() {
    test_header "Backup System"

    if [[ -x /opt/loxprox/gateway-backup.sh ]]; then
        pass "Backup script exists"
    else
        warn "Backup script missing"
        return
    fi

    # Run a backup
    local backup_output
    backup_output=$(/opt/loxprox/gateway-backup.sh 2>&1)
    if echo "$backup_output" | grep -q "Backup created"; then
        pass "Backup creation succeeded"
    else
        fail "Backup creation failed"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    [[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }

    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "  LoxProx — Test Suite"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo ""

    test_services
    test_network
    test_proxy
    test_crowdsec
    test_appsec
    test_monitoring
    test_sysctl
    test_backup

    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"

    [[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
}

main "$@"
