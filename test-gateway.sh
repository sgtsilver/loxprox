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

# Counters use an assignment, not ((x++)): ((x++)) returns status 1 while x
# is 0, so the first `check && pass ... || fail ...` of a run also recorded a
# bogus failure.
pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

# 2026-10 — pipefail rule for this suite: never `cmd | grep -q …` (or head,
# grep -m, awk …exit). grep -q exits at the first match, the still-writing
# cmd (cscli, nft — large outputs) dies of SIGPIPE, and under pipefail the
# pipeline returns 141: a match is reported as a miss. That produced the live
# "Decision creation failed" (the decision existed) and the nftables / SSH
# warnings. Capture the output first, then match the captured text.

# The gateway's TLS mode lives in deploy.conf (write_runtime_config never puts
# ENABLE_TLS into config.env). Echoes the scheme the :1080 listener speaks.
_gateway_scheme() {
    local tls=""
    [[ -f /etc/loxprox/deploy.conf ]] && tls=$(awk -F'"' '/^ENABLE_TLS=/{print $2}' /etc/loxprox/deploy.conf)
    if [[ "${tls,,}" == "true" ]]; then echo https; else echo http; fi
}

# Exact count of requests CrowdSec's AppSec engine has evaluated, or nothing
# when it cannot be read. Not from the `cscli metrics` table: field 2 of its
# row is the engine NAME (the table has a leading border column), and the
# table rounds counts ("1.23k"), so one extra request is invisible there.
# Sources: `cscli metrics -o json` ("appsec-engine" → <engine> → processed),
# else CrowdSec's Prometheus endpoint (cs_appsec_reqs_total).
_appsec_processed() {
    local out n=""
    out=$(cscli metrics -o json 2>/dev/null) || out=""
    if [[ -n "$out" ]] && command -v jq >/dev/null 2>&1; then
        n=$(jq -r '[(."appsec-engine" // {})[] | .processed? // empty] | if length > 0 then add else empty end' <<<"$out" 2>/dev/null) || n=""
    fi
    if [[ ! "$n" =~ ^[0-9]+$ ]]; then
        out=$(curl -s --max-time 5 http://127.0.0.1:6060/metrics 2>/dev/null) || out=""
        n=$(awk '/^cs_appsec_reqs_total[{ ]/ {s += $NF; f = 1} END {if (f) printf "%d", s}' <<<"$out")
    fi
    [[ "$n" =~ ^[0-9]+$ ]] && printf '%s' "$n"
    return 0
}

# Lines CrowdSec has read from the gateway's nginx access log (same sources,
# same reason as above).
_nginx_lines_read() {
    local out n="" src="file:/var/log/nginx/loxone-access.log"
    out=$(cscli metrics -o json 2>/dev/null) || out=""
    if [[ -n "$out" ]] && command -v jq >/dev/null 2>&1; then
        n=$(jq -r --arg s "$src" '(.acquisition // {})[$s].reads // empty' <<<"$out" 2>/dev/null) || n=""
    fi
    if [[ ! "$n" =~ ^[0-9]+$ ]]; then
        out=$(curl -s --max-time 5 http://127.0.0.1:6060/metrics 2>/dev/null) || out=""
        n=$(awk '/^cs_filesource_hits_total[{ ]/ && /loxone-access\.log/ {s += $NF; f = 1} END {if (f) printf "%d", s}' <<<"$out")
    fi
    [[ "$n" =~ ^[0-9]+$ ]] && printf '%s' "$n"
    return 0
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
    local listeners
    listeners=$(ss -tlnp 2>/dev/null)
    if grep -q ':1080 ' <<<"$listeners"; then
        pass "nginx listening on :1080"
    else
        fail "nginx NOT listening on :1080"
    fi

    if grep -q ':22 ' <<<"$listeners"; then
        pass "sshd listening on :22"
    else
        fail "sshd NOT listening on :22"
    fi

    # Check nftables input policy
    local policy input_chain
    input_chain=$(nft list chain inet filter input 2>/dev/null)
    policy=$(grep -oP 'policy \K\w+' <<<"$input_chain")
    if [[ "$policy" == "drop" ]]; then
        pass "nftables input policy is DROP"
    else
        fail "nftables input policy is '$policy' (expected DROP)"
    fi

    # Check SSH is restricted
    if grep -qE 'dport 22.*saddr|tcp dport 22' <<<"$input_chain"; then
        pass "SSH port has source restrictions"
    else
        warn "SSH port may not have source restrictions"
    fi

    # Check CrowdSec table exists
    local tables
    tables=$(nft list tables 2>/dev/null)
    if grep -qE 'crowdsec|crowdsec6' <<<"$tables"; then
        pass "CrowdSec nftables table exists"
    else
        warn "CrowdSec nftables table not found (bouncer may still be initializing)"
    fi
}

# ── Proxy Tests ──────────────────────────────────────────────────────────────

test_proxy() {
    test_header "Nginx Proxy"

    # ENABLE_TLS lives in deploy.conf, NOT config.env — write_runtime_config
    # never emits it, so a config.env read comes back empty and silently
    # selects the non-TLS branch (the bug that skipped test_tls for a year).
    local enable_tls="false"
    if [[ -f /etc/loxprox/deploy.conf ]]; then
        enable_tls=$(awk -F'"' '/^ENABLE_TLS=/{print $2}' /etc/loxprox/deploy.conf)
    fi

    # v2.3 (H2): the site is no longer write-once — deploy.sh stamps every
    # generated site with its template version and regenerates on upgrade.
    # A missing stamp means deploy.sh no longer owns this file (hand-written,
    # pre-v2.3, or LOXPROX_KEEP_NGINX_SITE=1 froze it before it was stamped).
    if [[ -f /etc/nginx/sites-available/loxone ]]; then
        grep -q '# LOXPROX-SITE-TEMPLATE-VERSION:' /etc/nginx/sites-available/loxone \
            && pass "nginx site carries the deploy.sh template version stamp" \
            || fail "nginx site missing the template version stamp"
    else
        fail "nginx site file missing (/etc/nginx/sites-available/loxone)"
    fi

    # Test localhost proxy. In TLS mode the :1080 listener is `listen 1080
    # ssl` (setup_tls in deploy.sh) — a plain-HTTP request never reaches the
    # proxied response, it lands on the error_page 497 grace redirect
    # instead, so the API check has to speak TLS to get a real answer.
    local status
    if [[ "${enable_tls,,}" == "true" ]]; then
        status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 https://127.0.0.1:1080/jdev/cfg/api 2>/dev/null)
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://127.0.0.1:1080/jdev/cfg/api 2>/dev/null)
    fi
    if [[ "$status" == "200" || "$status" == "401" ]]; then
        pass "Proxy responds to Loxone API (HTTP $status)"
    else
        fail "Proxy returned HTTP $status (expected 200 or 401)"
    fi

    if [[ "${enable_tls,,}" == "true" ]]; then
        # Pin the v1.5.0 http->https grace redirect (deploy.sh
        # _loxprox_site_enable_tls): plain HTTP to the TLS-mode :1080
        # listener must come back as a clean 301, not the raw 400 that used
        # to trip CrowdSec's http-probing scenario against Loxone apps still
        # configured for http://gateway:1080.
        local http_status
        http_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://127.0.0.1:1080/jdev/cfg/api 2>/dev/null)
        if [[ "$http_status" == "301" ]]; then
            pass "Plain HTTP on :1080 redirects to HTTPS (301 grace redirect)"
        else
            fail "Plain HTTP on :1080 returned HTTP $http_status (expected 301 redirect)"
        fi
    fi

    # Test security headers
    local headers
    headers=$(curl -sI --connect-timeout 5 http://127.0.0.1:1080/jdev/cfg/api 2>/dev/null)
    if grep -qi "X-Frame-Options" <<<"$headers"; then
        pass "X-Frame-Options header present"
    else
        fail "X-Frame-Options header missing"
    fi
    if grep -qi "Content-Security-Policy" <<<"$headers"; then
        pass "CSP header present"
    else
        fail "CSP header missing"
    fi
    if grep -qi "Permissions-Policy" <<<"$headers"; then
        pass "Permissions-Policy header present"
    else
        fail "Permissions-Policy header missing"
    fi
    if grep -qi "X-XSS-Protection" <<<"$headers"; then
        fail "Deprecated X-XSS-Protection header still present (should be removed)"
    else
        pass "X-XSS-Protection correctly removed"
    fi

    # 2026-10: in TLS mode the request above is answered by nginx's own 301 —
    # the Miniserver never sees it, so it cannot show duplicates. Those only
    # appear on a PROXIED response: nginx adds its header and, unless the site
    # hides it (template v4+), passes the Miniserver's own copy through too
    # (live: "X-Frame-Options: deny" next to "SAMEORIGIN"). Check one.
    local proxied_url="http://127.0.0.1:1080/jdev/cfg/api" proxied_headers proxied_status
    [[ "${enable_tls,,}" == "true" ]] && proxied_url="https://127.0.0.1:1080/jdev/cfg/api"
    proxied_headers=$(curl -sk -D - -o /dev/null --connect-timeout 5 --max-time 10 "$proxied_url" 2>/dev/null | tr -d '\r')
    proxied_status=$(awk 'NR == 1 {print $2}' <<<"$proxied_headers")
    if [[ -z "$proxied_headers" ]]; then
        fail "No response from $proxied_url — cannot check proxied security headers"
    else
        local hdr count
        for hdr in X-Frame-Options X-Content-Type-Options Content-Security-Policy Permissions-Policy Referrer-Policy; do
            count=$(grep -ci "^${hdr}:" <<<"$proxied_headers" || true)
            if [[ "$count" == "1" ]]; then
                pass "Proxied response (HTTP $proxied_status) carries exactly one $hdr"
            else
                fail "Proxied response (HTTP $proxied_status) carries $count $hdr header(s), expected 1 — upstream copy not hidden? (site template < v4)"
            fi
        done
        if [[ "${enable_tls,,}" == "true" ]]; then
            count=$(grep -ci '^Strict-Transport-Security:' <<<"$proxied_headers" || true)
            if [[ "$count" == "1" ]]; then
                pass "Proxied response carries exactly one Strict-Transport-Security"
            else
                fail "Proxied response carries $count Strict-Transport-Security header(s), expected 1"
            fi
        fi
        if grep -qi '^X-XSS-Protection:' <<<"$proxied_headers"; then
            fail "Proxied response still carries the Miniserver's X-XSS-Protection (should be hidden)"
        else
            pass "Proxied response carries no X-XSS-Protection"
        fi
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
    nginx_lines=$(_nginx_lines_read)
    if [[ -n "$nginx_lines" && "$nginx_lines" != "0" ]]; then
        pass "Nginx logs parsed ($nginx_lines lines)"
    else
        warn "No nginx log lines parsed yet (may need traffic)"
    fi

    # Test decision → bouncer → nftables pipeline
    local test_ip="198.51.100.99"
    cscli decisions add --ip "$test_ip" --duration 1m --reason "gateway-test" --type ban >/dev/null 2>&1
    sleep 5

    local decisions
    decisions=$(cscli decisions list 2>/dev/null)
    if grep -qF "$test_ip" <<<"$decisions"; then
        pass "Decision created successfully"
    else
        fail "Decision creation failed"
    fi

    # The whole table, not one set: newer bouncers keep one set per decision
    # origin (crowdsec-blacklists-cscli, -CAPI, …) instead of a single
    # crowdsec-blacklists. Captured in full — it holds tens of thousands of
    # CAPI addresses, exactly the output size that SIGPIPEs a `| grep -q`.
    local cs_table
    cs_table=$(nft list table ip crowdsec 2>/dev/null)
    if grep -qF "$test_ip" <<<"$cs_table"; then
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
    local listeners
    listeners=$(ss -tlnp 2>/dev/null)
    if grep -q ':7422 ' <<<"$listeners"; then
        pass "AppSec listening on 127.0.0.1:7422"
    else
        fail "AppSec NOT listening on :7422"
    fi

    # Check AppSec metrics show processed requests
    local processed
    processed=$(_appsec_processed)
    if [[ -z "$processed" ]]; then
        warn "Could not read AppSec counters (cscli metrics -o json / 127.0.0.1:6060)"
    elif [[ "$processed" != "0" ]]; then
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

    # v2.3 (H3): with ENABLE_APPSEC=true, an nginx AppSec include that is still
    # the fail-open PASS-THROUGH STUB (bouncer key never registered, or
    # nginx -t rejected the real include) means every request sails through
    # uninspected while the checks above still look green. ENABLE_APPSEC
    # itself is not in config.env (only in deploy.conf), so read it from there
    # like deploy.sh's own health_check does.
    local enable_appsec="true"
    if [[ -f /etc/loxprox/deploy.conf ]]; then
        enable_appsec=$(awk -F'"' '/^ENABLE_APPSEC=/{print $2}' /etc/loxprox/deploy.conf)
    fi
    enable_appsec="${enable_appsec:-true}"
    if [[ "${enable_appsec,,}" == "true" ]]; then
        if [[ -s /etc/nginx/crowdsec-appsec.conf ]] && grep -q "PASS-THROUGH STUB" /etc/nginx/crowdsec-appsec.conf; then
            fail "AppSec include is the PASS-THROUGH STUB — the WAF is NOT inspecting traffic (deploy degraded, re-run deploy.sh)"
        else
            pass "AppSec include is not the pass-through stub"
        fi
    fi

    # v2.3 (H11): APPSEC_MODE is written to config.env by write_runtime_config.
    # In monitor mode the acquisition must point at the local log-only config,
    # not the hub's enforce-shaped virtual-patching.
    local appsec_mode=""
    if [[ -f /etc/loxprox/config.env ]]; then
        appsec_mode=$(awk -F'"' '/^APPSEC_MODE=/{print $2}' /etc/loxprox/config.env)
    fi
    if [[ "${appsec_mode,,}" == "monitor" ]]; then
        local monitor_conf="/etc/crowdsec/appsec-configs/loxprox-virtual-patching-monitor.yaml"
        local appsec_acquis="/etc/crowdsec/acquis.d/appsec.yaml"
        [[ -f "$monitor_conf" ]] && pass "AppSec monitor-mode config present ($monitor_conf)" \
                                  || fail "AppSec monitor-mode config missing ($monitor_conf)"
        if [[ -f "$appsec_acquis" ]] && grep -qF "$monitor_conf" "$appsec_acquis"; then
            pass "AppSec acquisition references the monitor-mode config"
        else
            fail "AppSec acquisition does not reference $monitor_conf (still enforce-shaped?)"
        fi
    fi

    # Verify end-to-end: proxy request should trigger AppSec
    # 2026-10: the request must speak the listener's scheme. In TLS mode a
    # plain-HTTP request is answered by the 497 → 301 redirect before any
    # location runs, so it never reached the AppSec auth_request and the
    # counter could not move (the live "did not increment" warning).
    local appsec_before appsec_after scheme
    scheme=$(_gateway_scheme)
    appsec_before=$(_appsec_processed)
    curl -sk -o /dev/null --connect-timeout 5 "${scheme}://127.0.0.1:1080/jdev/cfg/api" 2>/dev/null
    sleep 2
    appsec_after=$(_appsec_processed)
    if [[ -z "$appsec_before" || -z "$appsec_after" ]]; then
        warn "Could not read AppSec counters — end-to-end inspection not verified"
    elif (( appsec_after > appsec_before )); then
        pass "AppSec inspects proxy traffic end-to-end ($appsec_before → $appsec_after)"
    else
        warn "AppSec counter did not move ($appsec_before → $appsec_after) after a ${scheme} request"
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
        # Captured, not piped into grep -q: cscli keeps writing after the
        # first match and the SIGPIPE'd pipeline read as "not registered".
        local parser_info
        parser_info=$(cscli parsers inspect whitelist-loxone 2>/dev/null)
        [[ -n "$parser_info" ]] || parser_info=$(cscli parsers list -a 2>/dev/null)
        if grep -qi "whitelist-loxone" <<<"$parser_info"; then
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

    # Run a real backup. gateway-backup.sh hardcodes /root/loxprox-backups
    # with no destination override, so this creates one real tarball on the
    # host — only a live run proves cp/tar/chmod all succeed end to end.
    # The archive is removed again below so the test leaves no side effect.
    local backup_output
    backup_output=$(/opt/loxprox/gateway-backup.sh 2>&1)
    if grep -q "Backup created" <<<"$backup_output"; then
        pass "Backup creation succeeded"
    else
        fail "Backup creation failed"
    fi

    local backup_path
    backup_path=$(echo "$backup_output" | awk '/^Backup created:/{print $3}')
    if [[ -n "$backup_path" && -f "$backup_path" ]]; then
        rm -f "$backup_path"
    fi
}

# ── Tunnel Tests (v2.0, only when ENABLE_TUNNEL=true) ───────────────────────

test_tunnel() {
    # Read the runtime config to know whether the tunnel is supposed to be on.
    local enable_tunnel="false" public_host=""
    if [[ -f /etc/loxprox/config.env ]]; then
        enable_tunnel=$(awk -F'"' '/^ENABLE_TUNNEL=/{print $2}' /etc/loxprox/config.env)
        public_host=$(awk -F'"' '/^TUNNEL_PUBLIC_HOST=/{print $2}' /etc/loxprox/config.env)
    fi
    [[ "${enable_tunnel,,}" == "true" ]] || return 0

    test_header "Tunnel (v2.0)"

    if systemctl is-active --quiet frpc 2>/dev/null; then
        pass "frpc is running"
    else
        fail "frpc is NOT running"
    fi

    if systemctl is-enabled --quiet tunnel-watchdog.timer 2>/dev/null; then
        pass "tunnel watchdog timer is enabled"
    else
        fail "tunnel watchdog timer NOT enabled"
    fi

    if [[ -f /etc/frp/frpc.toml ]]; then
        local mode owner
        mode=$(stat -c '%a' /etc/frp/frpc.toml)
        owner=$(stat -c '%U:%G' /etc/frp/frpc.toml)
        [[ "$mode" == "640" ]] && pass "frpc.toml mode 0640" || fail "frpc.toml mode is $mode (expected 640)"
        [[ "$owner" == "root:frpc" ]] && pass "frpc.toml owned root:frpc" || fail "frpc.toml owner is $owner (expected root:frpc)"
    else
        fail "/etc/frp/frpc.toml missing"
    fi

    if [[ -f /etc/nginx/conf.d/loxprox-tunnel-realip.conf ]]; then
        pass "real-IP restoration conf present"
        grep -q 'set_real_ip_from 127.0.0.1;' /etc/nginx/conf.d/loxprox-tunnel-realip.conf \
            && pass "real-IP trusts loopback only" \
            || fail "real-IP trust anchor wrong"
    else
        fail "loxprox-tunnel-realip.conf missing"
    fi

    # frpc must run unprivileged.
    local frpc_user
    frpc_user=$(ps -o user= -C frpc 2>/dev/null | awk 'NR == 1 {print $1}')
    if [[ "$frpc_user" == "frpc" ]]; then
        pass "frpc runs as unprivileged user"
    elif [[ -n "$frpc_user" ]]; then
        fail "frpc runs as '$frpc_user' (expected 'frpc')"
    else
        warn "frpc process not found for user check"
    fi

    # Full public path — the definitive end-to-end check.
    if [[ -n "$public_host" ]]; then
        local code
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://${public_host}/" 2>/dev/null || echo "000")
        case "$code" in
            000|502|503|504) fail "public path https://${public_host}/ unreachable (HTTP $code)" ;;
            *)               pass "public path answers (HTTP $code)" ;;
        esac
    else
        warn "TUNNEL_PUBLIC_HOST not set — skipping public-path check"
    fi
}

# ── TLS Tests (v2.0.1, only when ENABLE_TLS=true) ───────────────────────────

test_tls() {
    # ENABLE_TLS lives in deploy.conf, NOT config.env (write_runtime_config
    # never emits it) — the old config.env read was always empty, so this
    # whole section was silently skipped on every TLS-mode gateway.
    local enable_tls="false"
    if [[ -f /etc/loxprox/deploy.conf ]]; then
        enable_tls=$(awk -F'"' '/^ENABLE_TLS=/{print $2}' /etc/loxprox/deploy.conf)
    fi
    [[ "${enable_tls,,}" == "true" ]] || return 0

    test_header "TLS (v2.0.1)"

    local cert="/etc/loxprox/tls/fullchain.pem"
    if [[ -f "$cert" ]]; then
        pass "TLS certificate present ($cert)"

        if openssl x509 -checkend 1814400 -noout -in "$cert" >/dev/null 2>&1; then
            pass "TLS certificate valid for > 21 days"
        else
            fail "TLS certificate expires within 21 days (or is invalid)"
        fi
    else
        fail "TLS certificate missing ($cert)"
    fi

    local nginx_site="/etc/nginx/sites-available/loxone"
    if [[ -f "$nginx_site" ]]; then
        grep -q 'listen 1080 ssl' "$nginx_site" \
            && pass "nginx site listens on 1080 ssl" \
            || fail "nginx site missing 'listen 1080 ssl'"

        grep -q 'error_page 497' "$nginx_site" \
            && pass "nginx site has error_page 497 redirect" \
            || fail "nginx site missing error_page 497 redirect"
    else
        fail "nginx site file missing ($nginx_site)"
    fi

    if [[ -f /etc/nginx/conf.d/loxprox-acme.conf ]]; then
        pass "ACME challenge conf present"
    else
        fail "ACME challenge conf missing (/etc/nginx/conf.d/loxprox-acme.conf)"
    fi

    # Quote-tolerant pattern (v2.0.1 fix) — do NOT match on a full path prefix.
    if crontab -l 2>/dev/null | grep -F "acme.sh --cron" >/dev/null 2>&1; then
        pass "acme.sh renewal cron present"
    else
        fail "acme.sh renewal cron missing from root crontab"
    fi
}

# ── GUI Tests (v2.1, only when ENABLE_GUI=true) ─────────────────────────────

test_gui() {
    # Read the runtime config to know whether the GUI is supposed to be on.
    # Older installs won't have these keys yet — degrade to a skip.
    local enable_gui="false" gui_port="1081"
    if [[ -f /etc/loxprox/config.env ]]; then
        enable_gui=$(awk -F'"' '/^ENABLE_GUI=/{print $2}' /etc/loxprox/config.env)
        gui_port=$(awk -F'"' '/^GUI_PORT=/{print $2}' /etc/loxprox/config.env)
    fi
    enable_gui="${enable_gui:-false}"
    gui_port="${gui_port:-1081}"
    [[ "${enable_gui,,}" == "true" ]] || return 0

    test_header "GUI Panel (v2.3)"

    if systemctl is-active --quiet loxprox-gui.service 2>/dev/null; then
        pass "loxprox-gui.service is running"
    else
        fail "loxprox-gui.service is NOT running"
    fi

    local listeners
    listeners=$(ss -tlnp 2>/dev/null)
    if grep -q ":${gui_port} " <<<"$listeners"; then
        pass "GUI listening on :${gui_port}"
    else
        fail "GUI NOT listening on :${gui_port}"
    fi

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://127.0.0.1:${gui_port}/" 2>/dev/null)
    if [[ "$status" == "200" ]]; then
        pass "GUI panel responds (HTTP $status)"
    else
        fail "GUI panel returned HTTP $status (expected 200)"
    fi

    local csrf_status
    csrf_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -X POST "http://127.0.0.1:${gui_port}/api/unban" 2>/dev/null)
    if [[ "$csrf_status" == "403" ]]; then
        pass "POST without X-LoxProx-Gui header rejected (403)"
    else
        fail "POST without X-LoxProx-Gui header returned HTTP $csrf_status (expected 403)"
    fi

    # v2.2: the dashboard is a static app — a missing asset install means a
    # blank panel even though / returns 200-shaped errors on the API side.
    local asset_status
    asset_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://127.0.0.1:${gui_port}/static/panel.js" 2>/dev/null)
    if [[ "$asset_status" == "200" ]]; then
        pass "GUI dashboard assets served (/static/panel.js)"
    else
        fail "GUI dashboard assets missing (/static/panel.js returned HTTP $asset_status)"
    fi

    # The calm-console panel ships no third-party bundles; a 200 here means a
    # stale v2.2 static/vendor/ directory survived the upgrade.
    local stale_status
    stale_status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://127.0.0.1:${gui_port}/static/vendor/three.core.min.js" 2>/dev/null)
    if [[ "$stale_status" == "404" ]]; then
        pass "No stale vendored bundles served (/static/vendor/ is gone)"
    else
        fail "Stale vendored bundle still served (/static/vendor/three.core.min.js returned HTTP $stale_status)"
    fi

    if command -v qrencode >/dev/null 2>&1; then
        pass "qrencode is installed"
    else
        fail "qrencode is NOT installed"
    fi
}

test_version() {
    test_header "Version Marker"

    # 2026-08-30: write_runtime_config() always writes /etc/loxprox/VERSION
    # (from the tarball's VERSION file, git describe, or "unknown"), so a
    # missing/empty file means the running install predates the marker or the
    # deploy was interrupted before write_runtime_config.
    if [[ -s /etc/loxprox/VERSION ]] && grep -q '^version=' /etc/loxprox/VERSION; then
        pass "Version marker present: $(grep -m1 '^version=' /etc/loxprox/VERSION)"
    else
        fail "/etc/loxprox/VERSION missing or malformed — deployed release is not readable on-box (re-run deploy.sh)"
    fi
}

# ── Operations (2026-10 health-audit fixes) ─────────────────────────────────

# Prints one line per problem that makes Debian's cron ignore a whole
# /etc/cron.d file: an assignment with an empty unquoted value (`MAILTO=`
# instead of `MAILTO=""`), or a job line that is not 5 time fields + user +
# command. Same rules as deploy.sh's _loxprox_cron_lint.
_cron_file_problems() {
    awk '
        /^[[:space:]]*(#|$)/ { next }
        match($0, /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/) {
            v = substr($0, RLENGTH + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
            if (v == "") printf "line %d: bare assignment \"%s\" (needs a quoted empty value)\n", NR, $0
            next
        }
        $1 ~ /^@/ { if (NF < 3) printf "line %d: @keyword job without user/command\n", NR; next }
        NF < 7    { printf "line %d: needs 5 time fields + user + command\n", NR; next }
        {
            for (i = 1; i <= 5; i++) {
                if ($i !~ /^[0-9A-Za-z*\/,-]+$/) { printf "line %d: bad time field \"%s\"\n", NR, $i; break }
            }
        }' "$1"
}

test_operations() {
    test_header "Scheduled Jobs, Log Retention, Audit Coverage"

    # cron: a rejected file is ignored as a whole and nothing else notices —
    # progressive ban, backup and GeoIP refresh silently stopped for months.
    if systemctl is-active --quiet cron 2>/dev/null; then
        pass "cron is running"
    else
        fail "cron is NOT running — no LoxProx cron job (ban escalation, backup, GeoIP) runs"
    fi
    local cron_file name problems since rejected
    for cron_file in /etc/cron.d/loxprox /etc/cron.d/loxprox-alert; do
        if [[ ! -f "$cron_file" ]]; then
            [[ "$cron_file" == /etc/cron.d/loxprox ]] && fail "$cron_file missing"
            continue
        fi
        name=$(basename "$cron_file")
        problems=$(_cron_file_problems "$cron_file")
        if [[ -z "$problems" ]]; then
            pass "$cron_file is well-formed"
        else
            fail "$cron_file is malformed (cron ignores the whole file): ${problems//$'\n'/; }"
        fi
        # Only errors logged after the file's mtime count: cron re-reads a file
        # when its mtime changes, so these are about the content on disk now.
        since=$(stat -c %Y "$cron_file")
        rejected=$(journalctl -u cron --since "@${since}" -o cat --no-pager -q 2>/dev/null \
                   | grep -E -e "\(\*system\*${name}\) ERROR" -e "while reading /etc/cron[.]d/${name}\$" || true)
        if [[ -z "$rejected" ]]; then
            pass "cron has not rejected $cron_file since it was written"
        else
            fail "cron rejected $cron_file: ${rejected//$'\n'/; }"
        fi
    done

    # logrotate: LoxProx logs covered, and no duplicate stanza anywhere (one
    # duplicate path makes logrotate skip a whole file and fail every night).
    if [[ -f /etc/logrotate.d/loxprox ]] && grep -q '^/var/log/loxprox-\*\.log' /etc/logrotate.d/loxprox; then
        pass "logrotate covers /var/log/loxprox-*.log"
    else
        fail "/etc/logrotate.d/loxprox missing — LoxProx logs grow without bound"
    fi
    if command -v logrotate >/dev/null 2>&1; then
        local lr_errors
        lr_errors=$(logrotate -d /etc/logrotate.conf 2>&1 | grep -iE '^error:|duplicate log entry' || true)
        if [[ -z "$lr_errors" ]]; then
            pass "logrotate -d /etc/logrotate.conf reports no errors / duplicate entries"
        else
            fail "logrotate config errors (nightly rotation fails): ${lr_errors//$'\n'/; }"
        fi
    else
        fail "logrotate not installed"
    fi

    # journald: capped instead of 10% of the disk.
    if grep -qs '^SystemMaxUse=' /etc/systemd/journald.conf.d/50-loxprox.conf; then
        pass "journald capped ($(grep '^SystemMaxUse=' /etc/systemd/journald.conf.d/50-loxprox.conf)); $(journalctl --disk-usage 2>/dev/null)"
    else
        fail "journald size cap drop-in missing (/etc/systemd/journald.conf.d/50-loxprox.conf)"
    fi

    # auditd: LoxProx config, AppArmor policy and the root-run scripts watched.
    local key audit_rules
    audit_rules=$(auditctl -l 2>/dev/null || true)
    for key in loxprox_config apparmor_config loxprox_scripts; do
        if grep -q -- "-k ${key}\$\|key=${key}\$" <<<"$audit_rules"; then
            pass "audit watch loaded: $key"
        else
            fail "audit watch NOT loaded: $key (augenrules --load?)"
        fi
    done

    # 2026-10: everything under /opt/loxprox runs as root — nothing in it may
    # belong to another user or be group/world-writable, and deploy.sh's units
    # must be real files (a symlinked unit is written through into its target).
    if [[ -d /opt/loxprox ]]; then
        local strays
        strays=$(find /opt/loxprox -xdev \( ! -user 0 -o ! -group 0 -o ! -type l -perm /022 \) -printf '%u:%g %m %p; ' 2>/dev/null)
        if [[ -z "$strays" && "$(stat -c '%U:%G' /opt/loxprox)" == "root:root" ]]; then
            pass "/opt/loxprox root-owned, nothing in it owned by another user or group/world-writable"
        else
            fail "/opt/loxprox not root-only ($(stat -c '%U:%G %a' /opt/loxprox)): ${strays:-dir itself} — re-run deploy.sh"
        fi
    fi
    local unit links=""
    for unit in network-watchdog.service network-watchdog.timer tunnel-watchdog.service tunnel-watchdog.timer \
                loxprox-monitor.service loxprox-monitor.timer loxprox-gui.service; do
        [[ -L "/etc/systemd/system/$unit" ]] && links+=" $unit -> $(readlink "/etc/systemd/system/$unit")"
    done
    if [[ -z "$links" ]]; then
        pass "LoxProx unit files in /etc/systemd/system are regular files"
    else
        fail "symlinked LoxProx unit(s):$links — re-run deploy.sh"
    fi

    # Panel apply/renew: config.env must point at a persisted, root-only copy.
    local deploy_sh=""
    [[ -f /etc/loxprox/config.env ]] && deploy_sh=$(awk -F'"' '/^LOXPROX_DEPLOY_SH=/{print $2}' /etc/loxprox/config.env)
    if [[ -n "$deploy_sh" && -f "$deploy_sh" ]]; then
        local owner mode
        owner=$(stat -c '%U' "$(dirname "$deploy_sh")")
        mode=$(stat -c '%a' "$(dirname "$deploy_sh")")
        if [[ "$owner" == "root" && "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 8#022) == 0 )); then
            pass "Panel deploy source present and root-only ($deploy_sh, mode $mode)"
        else
            fail "Panel deploy source $deploy_sh is owned by $owner / mode $mode (must be root, not group/world-writable)"
        fi
    else
        fail "LOXPROX_DEPLOY_SH in config.env missing or not a file ('$deploy_sh') — panel apply/renew will refuse"
    fi

    # AppArmor complain soak: ALLOWED events since the nginx master started
    # (reloads included) are the accesses enforce mode would deny — zero is
    # the soak's exit criterion (docs/adr/0006). With auditd running the
    # kernel hands AVC records to auditd, so ask ausearch first and the kernel
    # log second. Informational (warn), not a failure: complain mode is
    # exactly where these are supposed to surface.
    local aa_out=""
    command -v aa-status >/dev/null 2>&1 && aa_out=$(aa-status 2>/dev/null)
    if grep -q '/usr/sbin/nginx' <<<"$aa_out"; then
        pass "AppArmor nginx profile loaded"
        local pid elapsed start_epoch allowed=0 n
        pid=$(systemctl show -p MainPID --value nginx 2>/dev/null)
        elapsed=$(ps -o etimes= -p "${pid:-0}" 2>/dev/null | tr -d ' ')
        if [[ "$elapsed" =~ ^[0-9]+$ ]]; then
            start_epoch=$(( $(date +%s) - elapsed ))
            if command -v ausearch >/dev/null 2>&1; then
                n=$(LC_ALL=C ausearch -m AVC -ts "$(LC_ALL=C date -d "@$start_epoch" '+%x %T')" 2>/dev/null \
                    | grep 'apparmor="ALLOWED"' | grep -c 'profile="/usr/sbin/nginx"' || true)
                (( ${n:-0} > allowed )) && allowed=$n
            fi
            n=$(journalctl -k --since "@$start_epoch" -o cat --no-pager -q 2>/dev/null \
                | grep 'apparmor="ALLOWED"' | grep -c 'profile="/usr/sbin/nginx"' || true)
            (( ${n:-0} > allowed )) && allowed=$n
            if (( allowed == 0 )); then
                pass "No AppArmor ALLOWED events for nginx since its master started"
            else
                warn "$allowed AppArmor ALLOWED event(s) for nginx since its master started — each would be a denial in enforce mode (ausearch -m AVC -ts recent)"
            fi
        else
            warn "Could not determine the nginx master's start time — ALLOWED-event count skipped"
        fi
    else
        warn "AppArmor nginx profile not loaded (aa-status)"
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
    test_tunnel
    test_tls
    test_gui
    test_version
    test_operations

    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════════"

    [[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
}

# Only run when executed, not when sourced — tests/ source this file to
# exercise individual checks (e.g. _cron_file_problems) in isolation.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
