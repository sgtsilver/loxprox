#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Portable Unit Tests for deploy.sh Functions
# ═══════════════════════════════════════════════════════════════════════════════
# These tests validate deploy.sh logic WITHOUT requiring a live VM.
# They mock system commands and verify generated configuration files.
#
# Run: bash tests/test_deploy_integration.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
TESTS_PASSED=0
TESTS_FAILED=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

# ── Setup ────────────────────────────────────────────────────────────────────

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
MOCK_ROOT="$(mktemp -d /tmp/loxprox-test-deploy.XXXXXXXXXX)"

export LOXONE_IP="192.168.1.100"
export LOXONE_PORT="80"
export GATEWAY_IP="192.168.1.50"
export LAN_SUBNET="192.168.1.0/24"
export SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")
export RATE_LIMIT_REQ_PER_SEC="10"
export RATE_LIMIT_BURST="100"
export RATE_LIMIT_CONN_PER_IP="20"
export PROXY_CONNECT_TIMEOUT="10"
export PROXY_SEND_TIMEOUT="15"
export PROXY_READ_TIMEOUT="15"
export CLIENT_BODY_TIMEOUT="10"
export CLIENT_HEADER_TIMEOUT="10"
export ENABLE_APPSEC="true"
export APPSEC_MODE="enforce"
export CROWDSEC_WHITELIST_IPS=("192.168.1.0/24" "10.0.0.0/24")
export DISCORD_WEBHOOK_URL=""
export ALERT_EMAIL=""
export AUTOREBOOT_TIME="03:00"
export ENABLE_GUI="true"
export GUI_PORT="1081"
export GUI_PASSWORD=""

# Override paths to use mock root
export LOG_FILE="$MOCK_ROOT/var/log/loxprox-deploy.log"
export BACKUP_DIR="$MOCK_ROOT/root/loxprox-backup-test"
export NGINX_SITE="$MOCK_ROOT/etc/nginx/sites-available/loxone"
export NGINX_ENABLED="$MOCK_ROOT/etc/nginx/sites-enabled/loxone"
export CROWDSEC_NGINX_ACQUIS="$MOCK_ROOT/etc/crowdsec/acquis.d/nginx.yaml"
export CROWDSEC_SSH_ACQUIS="$MOCK_ROOT/etc/crowdsec/acquis.d/ssh.yaml"
export CROWDSEC_APPSEC_ACQUIS="$MOCK_ROOT/etc/crowdsec/acquis.d/appsec.yaml"
export SYSCTL_CONF="$MOCK_ROOT/etc/sysctl.d/99-security-gateway.conf"
export NGINX_APPSEC_INCLUDE="$MOCK_ROOT/etc/nginx/crowdsec-appsec.conf"
export NGINX_APPSEC_AUDIT_CONF="$MOCK_ROOT/etc/nginx/conf.d/loxprox-appsec.conf"
export NGINX_ACME_CONF="$MOCK_ROOT/etc/nginx/conf.d/loxprox-acme.conf"
export NFTABLES_CONF="$MOCK_ROOT/etc/nftables.conf"
export LOGROTATE_CONF="$MOCK_ROOT/etc/logrotate.d/loxone-nginx"
export GATEWAY_CONFIG_DIR="$MOCK_ROOT/etc/loxprox"
export GATEWAY_CONFIG_FILE="$GATEWAY_CONFIG_DIR/config.env"
export LOXPROX_DEPLOY_CONF="$MOCK_ROOT/etc/loxprox/deploy.conf"
export GUI_UNIT="$MOCK_ROOT/etc/systemd/system/loxprox-gui.service"
export GUI_APP="$MOCK_ROOT/opt/loxprox/loxprox-gui.py"
# 2026-10 health-audit fixes
export LOXPROX_LOGROTATE_CONF="$MOCK_ROOT/etc/logrotate.d/loxprox"
export NGINX_STOCK_LOGROTATE="$MOCK_ROOT/etc/logrotate.d/nginx"
export JOURNALD_DROPIN="$MOCK_ROOT/etc/systemd/journald.conf.d/50-loxprox.conf"
export AUDIT_RULES_FILE="$MOCK_ROOT/etc/audit/rules.d/99-gateway.rules"
export LOXPROX_CRON_FILE="$MOCK_ROOT/etc/cron.d/loxprox"
export LOXPROX_ALERT_CRON_FILE="$MOCK_ROOT/etc/cron.d/loxprox-alert"
export LOXPROX_DEPLOY_DIR="$MOCK_ROOT/opt/loxprox/deploy"

mkdir -p "$MOCK_ROOT"/{etc/nginx/sites-available,etc/nginx/sites-enabled,etc/nginx/conf.d,etc/crowdsec/acquis.d,etc/crowdsec/parsers/s02-enrich,etc/sysctl.d,etc/logrotate.d,etc/loxprox,etc/systemd/system,etc/cron.d,opt/loxprox,var/log,root}

# Mock system commands
systemctl() { true; }
apt-get() { true; }
dpkg() { true; }
# v2.3: configure_nginx now ACTS on a failing `nginx -t` (restores the backup
# and returns 1) instead of ignoring it, so an unmocked/absent nginx binary
# would silently revert every regeneration under test.
nginx() { true; }
# `hostname -I` is Linux-only; macOS rejects it. Provide a deterministic mock
# so _loxprox_extract_config_from_live_state can test cleanly on either OS.
hostname() {
    case "$1" in
        -I) echo "192.168.42.99 fe80::1" ;;
        *) command hostname "$@" ;;
    esac
}
# `ip route` is also Linux-only — return a representative kernel-proto route.
ip() {
    case "$1" in
        route) echo "192.168.42.0/24 dev eth0 proto kernel scope link src 192.168.42.99" ;;
        *) command ip "$@" 2>/dev/null || true ;;
    esac
}
export -f systemctl apt-get dpkg nginx hostname ip

# Source deploy.sh functions (skip main via BASH_SOURCE guard)
# shellcheck source=../deploy.sh
source "$PROJECT_DIR/deploy.sh"

# deploy.sh sets 'set -e' which breaks ((0++)) in pass/fail — disable it here
set +e

# Override paths AFTER sourcing so deploy.sh defaults don't clobber us
LOG_FILE="$MOCK_ROOT/var/log/loxprox-deploy.log"
BACKUP_DIR="$MOCK_ROOT/root/loxprox-backup-test"
NGINX_SITE="$MOCK_ROOT/etc/nginx/sites-available/loxone"
NGINX_ENABLED="$MOCK_ROOT/etc/nginx/sites-enabled/loxone"
CROWDSEC_NGINX_ACQUIS="$MOCK_ROOT/etc/crowdsec/acquis.d/nginx.yaml"
CROWDSEC_SSH_ACQUIS="$MOCK_ROOT/etc/crowdsec/acquis.d/ssh.yaml"
CROWDSEC_APPSEC_ACQUIS="$MOCK_ROOT/etc/crowdsec/acquis.d/appsec.yaml"
SYSCTL_CONF="$MOCK_ROOT/etc/sysctl.d/99-security-gateway.conf"
NGINX_APPSEC_INCLUDE="$MOCK_ROOT/etc/nginx/crowdsec-appsec.conf"
NGINX_APPSEC_AUDIT_CONF="$MOCK_ROOT/etc/nginx/conf.d/loxprox-appsec.conf"
NGINX_ACME_CONF="$MOCK_ROOT/etc/nginx/conf.d/loxprox-acme.conf"
NFTABLES_CONF="$MOCK_ROOT/etc/nftables.conf"
LOGROTATE_CONF="$MOCK_ROOT/etc/logrotate.d/loxone-nginx"
GATEWAY_CONFIG_DIR="$MOCK_ROOT/etc/loxprox"
GATEWAY_CONFIG_FILE="$GATEWAY_CONFIG_DIR/config.env"
LOXPROX_DEPLOY_CONF="$MOCK_ROOT/etc/loxprox/deploy.conf"
GUI_UNIT="$MOCK_ROOT/etc/systemd/system/loxprox-gui.service"
GUI_APP="$MOCK_ROOT/opt/loxprox/loxprox-gui.py"
LOXPROX_LOGROTATE_CONF="$MOCK_ROOT/etc/logrotate.d/loxprox"
NGINX_STOCK_LOGROTATE="$MOCK_ROOT/etc/logrotate.d/nginx"
JOURNALD_DROPIN="$MOCK_ROOT/etc/systemd/journald.conf.d/50-loxprox.conf"
AUDIT_RULES_FILE="$MOCK_ROOT/etc/audit/rules.d/99-gateway.rules"
LOXPROX_CRON_FILE="$MOCK_ROOT/etc/cron.d/loxprox"
LOXPROX_ALERT_CRON_FILE="$MOCK_ROOT/etc/cron.d/loxprox-alert"
LOXPROX_DEPLOY_DIR="$MOCK_ROOT/opt/loxprox/deploy"

# ── Tests ────────────────────────────────────────────────────────────────────

test_validate_ip() {
    echo ""
    echo "━━━ validate_ip() ━━━"

    if validate_ip "192.168.1.1"; then pass "valid IP accepted"; else fail "valid IP rejected"; fi
    if validate_ip "10.0.0.1"; then pass "10.x IP accepted"; else fail "10.x IP rejected"; fi
    if validate_ip "255.255.255.255"; then pass "max octet accepted"; else fail "max octet rejected"; fi
    if validate_ip "0.0.0.0"; then pass "zero IP accepted"; else fail "zero IP rejected"; fi

    if ! validate_ip "999.999.999.999" 2>/dev/null; then pass "invalid IP rejected"; else fail "invalid IP accepted"; fi
    if ! validate_ip "192.168.1" 2>/dev/null; then pass "short IP rejected"; else fail "short IP accepted"; fi
    if ! validate_ip "abc.def.ghi.jkl" 2>/dev/null; then pass "alpha IP rejected"; else fail "alpha IP accepted"; fi
    if ! validate_ip "192.168.1.1.1" 2>/dev/null; then pass "5-octet IP rejected"; else fail "5-octet IP accepted"; fi
}

test_validate_network() {
    echo ""
    echo "━━━ validate_network() ━━━"

    if validate_network "192.168.1.0/24"; then pass "valid CIDR accepted"; else fail "valid CIDR rejected"; fi
    if validate_network "10.0.0.0/8"; then pass "10/8 accepted"; else fail "10/8 rejected"; fi
    if validate_network "0.0.0.0/0"; then pass "0/0 accepted"; else fail "0/0 rejected"; fi
    if ! validate_network "192.168.1.0" 2>/dev/null; then pass "missing prefix rejected"; else fail "missing prefix accepted"; fi
    if ! validate_network "192.168.1.0/33" 2>/dev/null; then pass "prefix >32 rejected"; else fail "prefix >32 accepted"; fi

    # Octet validation (audit HIGH): impossible networks must be rejected.
    if ! validate_network "999.999.1.0/24" 2>/dev/null; then pass "999.999.1.0/24 rejected (octet >255)"; else fail "999.999.1.0/24 accepted (octet >255)"; fi
    if ! validate_network "192.168.256.0/24" 2>/dev/null; then pass "256 octet rejected"; else fail "256 octet accepted"; fi
    if ! validate_network "192.168.1/24" 2>/dev/null; then pass "3-octet CIDR rejected"; else fail "3-octet CIDR accepted"; fi
    if ! validate_network "abc.def.ghi.jkl/24" 2>/dev/null; then pass "alpha CIDR rejected"; else fail "alpha CIDR accepted"; fi
}

test_apply_sysctls() {
    echo ""
    echo "━━━ apply_sysctls() ━━━"

    apply_sysctls

    if [[ -f "$SYSCTL_CONF" ]]; then pass "sysctl.conf created"; else fail "sysctl.conf missing"; fi
    if grep -q "tcp_syncookies = 1" "$SYSCTL_CONF"; then pass "syncookies present"; else fail "syncookies missing"; fi
    if grep -q "rp_filter = 1" "$SYSCTL_CONF"; then pass "rp_filter present"; else fail "rp_filter missing"; fi
    if grep -q "dmesg_restrict = 1" "$SYSCTL_CONF"; then pass "dmesg_restrict present"; else fail "dmesg_restrict missing"; fi
    if grep -q "protected_hardlinks = 1" "$SYSCTL_CONF"; then pass "protected_hardlinks present"; else fail "protected_hardlinks missing"; fi
    # v1.3.4: Fragnesia (CVE-2026-46300) mitigation
    if grep -q "unprivileged_userns_clone = 0" "$SYSCTL_CONF"; then pass "unprivileged_userns_clone=0 present (Fragnesia mitigation)"; else fail "unprivileged_userns_clone setting missing"; fi
}

test_gpg_verifier() {
    echo ""
    echo "━━━ verify_crowdsec_key() ━━━"

    # Function must be defined after sourcing deploy.sh
    if declare -F verify_crowdsec_key &>/dev/null; then pass "verify_crowdsec_key function defined"; else fail "verify_crowdsec_key function missing"; fi

    # Must reference all three independent keyserver hosts (string match in script)
    if grep -q "keys.openpgp.org" "$PROJECT_DIR/deploy.sh"; then pass "keys.openpgp.org source listed"; else fail "keys.openpgp.org source missing"; fi
    if grep -q "keyserver.ubuntu.com" "$PROJECT_DIR/deploy.sh"; then pass "keyserver.ubuntu.com source listed"; else fail "keyserver.ubuntu.com source missing"; fi
    if grep -q "pgp.surf.nl" "$PROJECT_DIR/deploy.sh"; then pass "pgp.surf.nl source listed"; else fail "pgp.surf.nl source missing"; fi

    # CONFLICT must always abort (positive attack signal)
    if grep -q "conflict > 0" "$PROJECT_DIR/deploy.sh"; then pass "conflict path is hard-fail"; else fail "conflict path not hard-fail"; fi

    # Soft-fail mode env var documented
    if grep -q "LOXPROX_GPG_VERIFY_MODE" "$PROJECT_DIR/deploy.sh"; then pass "LOXPROX_GPG_VERIFY_MODE env var honoured"; else fail "LOXPROX_GPG_VERIFY_MODE env var missing"; fi

    # No hardcoded fingerprint — verifier must extract dynamically (audit guard
    # against future regressions where someone pastes in a 40-char hex literal).
    if grep -E "^[[:space:]]*[A-Fa-f0-9]{40}[[:space:]]*$" "$PROJECT_DIR/deploy.sh" >/dev/null; then
        fail "hardcoded 40-char hex fingerprint found in deploy.sh — verifier should be dynamic"
    else
        pass "no hardcoded fingerprint in deploy.sh"
    fi
}

test_setup_firewall() {
    echo ""
    echo "━━━ setup_firewall() ━━━"

    setup_firewall

    if [[ -f "$NFTABLES_CONF" ]]; then pass "nftables.conf created"; else fail "nftables.conf missing"; fi
    if grep -q "policy drop" "$NFTABLES_CONF"; then pass "input policy is DROP"; else fail "input policy not DROP"; fi
    if grep -q "tcp dport 1080 accept" "$NFTABLES_CONF"; then pass "port 1080 allowed"; else fail "port 1080 not allowed"; fi
    if grep -q "tcp dport 22" "$NFTABLES_CONF"; then pass "SSH restricted"; else fail "SSH not restricted"; fi
    if grep -q "192.168.1.0/24" "$NFTABLES_CONF"; then pass "LAN subnet in SSH rule"; else fail "LAN subnet missing from SSH rule"; fi
    if grep -q "10.0.0.0/24" "$NFTABLES_CONF"; then pass "site-to-site subnet in SSH rule"; else fail "site-to-site subnet missing"; fi
    # INFO-001: verify comment about CIDR in anonymous sets
    if grep -q "nftables >= 1.0.6" "$NFTABLES_CONF"; then pass "CIDR compatibility comment present"; else fail "CIDR compatibility comment missing"; fi
}

test_configure_nginx() {
    echo ""
    echo "━━━ configure_nginx() ━━━"

    configure_nginx

    if [[ -f "$NGINX_SITE" ]]; then pass "nginx site created"; else fail "nginx site missing"; fi
    if grep -q "listen 1080" "$NGINX_SITE"; then pass "listen 1080 present"; else fail "listen 1080 missing"; fi
    if grep -q "proxy_pass http://loxone_backend" "$NGINX_SITE"; then pass "proxy_pass present"; else fail "proxy_pass missing"; fi
    if grep -q "limit_req_zone" "$NGINX_SITE"; then pass "rate limit zone present"; else fail "rate limit zone missing"; fi
    if grep -q "limit_conn_zone" "$NGINX_SITE"; then pass "conn limit zone present"; else fail "conn limit zone missing"; fi

    # HIGH-002: CSP and Permissions-Policy
    if grep -q "Content-Security-Policy" "$NGINX_SITE"; then pass "CSP header present"; else fail "CSP header missing"; fi
    if grep -q "Permissions-Policy" "$NGINX_SITE"; then pass "Permissions-Policy header present"; else fail "Permissions-Policy header missing"; fi
    # The gateway must not SEND X-XSS-Protection; since template v4 the name
    # legitimately appears once more, in proxy_hide_header (dropping the
    # Miniserver's own copy).
    if grep -qE '^[[:space:]]*add_header[[:space:]]+X-XSS-Protection' "$NGINX_SITE"; then fail "X-XSS-Protection still added (should be removed)"; else pass "X-XSS-Protection correctly not added"; fi

    # LOW-007: proxy_hide_header
    if grep -q "proxy_hide_header Server" "$NGINX_SITE"; then pass "proxy_hide_header Server present"; else fail "proxy_hide_header Server missing"; fi
    if grep -q "proxy_hide_header X-Powered-By" "$NGINX_SITE"; then pass "proxy_hide_header X-Powered-By present"; else fail "proxy_hide_header X-Powered-By missing"; fi

    # 2026-10 (template v4): every security header nginx adds itself — and the
    # TLS block's HSTS, and the deprecated X-XSS-Protection — is hidden from
    # the upstream response, so the Miniserver's copy is never sent alongside.
    local hdr added
    for hdr in X-Frame-Options X-Content-Type-Options Referrer-Policy Content-Security-Policy Permissions-Policy Strict-Transport-Security X-XSS-Protection; do
        if grep -qE "^[[:space:]]*proxy_hide_header[[:space:]]+${hdr};" "$NGINX_SITE"; then
            pass "proxy_hide_header $hdr present"
        else
            fail "proxy_hide_header $hdr missing (upstream copy would be duplicated)"
        fi
    done
    # Derived check: no add_header in the template without a matching hide.
    while read -r added; do
        grep -qE "^[[:space:]]*proxy_hide_header[[:space:]]+${added};" "$NGINX_SITE" \
            || fail "add_header $added has no proxy_hide_header counterpart"
    done < <(awk '$1 == "add_header" {print $2}' "$NGINX_SITE")
    # proxy_hide_header is only inherited by locations that define none of
    # their own — the template's locations must not declare any.
    if awk '/^[[:space:]]*location /{inloc=1} inloc && /proxy_hide_header/{found=1} /^[[:space:]]*}/{inloc=0} END{exit !found}' "$NGINX_SITE"; then
        fail "a location block declares proxy_hide_header — it would drop the server-level hides"
    else
        pass "server-level proxy_hide_header is inherited (no location overrides it)"
    fi
    grep -q "^# LOXPROX-SITE-TEMPLATE-VERSION: 4$" "$NGINX_SITE" && pass "site template stamped v4" || fail "site template not stamped v4"

    # AppSec placeholder
    if [[ -f "$MOCK_ROOT/etc/nginx/crowdsec-appsec.conf" ]]; then pass "AppSec placeholder created"; else fail "AppSec placeholder missing"; fi
}

test_configure_crowdsec() {
    echo ""
    echo "━━━ configure_crowdsec() ━━━"

    configure_crowdsec

    if [[ -f "$CROWDSEC_NGINX_ACQUIS" ]]; then pass "nginx acquis created"; else fail "nginx acquis missing"; fi
    if [[ -f "$CROWDSEC_SSH_ACQUIS" ]]; then pass "ssh acquis created"; else fail "ssh acquis missing"; fi
    if [[ -f "$CROWDSEC_APPSEC_ACQUIS" ]]; then pass "appsec acquis created"; else fail "appsec acquis missing"; fi
    if grep -q "loxone-access.log" "$CROWDSEC_NGINX_ACQUIS"; then pass "access log in acquis"; else fail "access log missing from acquis"; fi
}

test_setup_logrotate() {
    echo ""
    echo "━━━ setup_logrotate() ━━━"

    setup_logrotate

    if [[ -f "$LOGROTATE_CONF" ]]; then pass "logrotate config created"; else fail "logrotate config missing"; fi
    if grep -q "loxone-\*.log" "$LOGROTATE_CONF"; then pass "logrotate pattern present"; else fail "logrotate pattern missing"; fi
    # LOW-005: appsec-detections.log in logrotate
    if grep -q "appsec-detections.log" "$LOGROTATE_CONF"; then pass "appsec log in logrotate"; else fail "appsec log missing from logrotate"; fi
}

test_write_runtime_config() {
    echo ""
    echo "━━━ write_runtime_config() ━━━"

    write_runtime_config

    if [[ -f "$GATEWAY_CONFIG_FILE" ]]; then pass "runtime config created"; else fail "runtime config missing"; fi
    if grep -q "LOXONE_IP=" "$GATEWAY_CONFIG_FILE"; then pass "LOXONE_IP in config"; else fail "LOXONE_IP missing"; fi
    if grep -q "GATEWAY_IP=" "$GATEWAY_CONFIG_FILE"; then pass "GATEWAY_IP in config"; else fail "GATEWAY_IP missing"; fi
    if grep -q "LAN_SUBNET=" "$GATEWAY_CONFIG_FILE"; then pass "LAN_SUBNET in config"; else fail "LAN_SUBNET missing"; fi
    # v2.1 — panel inputs: test-gateway.sh gates on ENABLE_GUI/GUI_PORT, the
    # panel itself runs LOXPROX_DEPLOY_SH for its apply/renew jobs.
    if grep -q '^ENABLE_GUI=' "$GATEWAY_CONFIG_FILE"; then pass "ENABLE_GUI in config"; else fail "ENABLE_GUI missing"; fi
    if grep -q '^GUI_PORT="1081"' "$GATEWAY_CONFIG_FILE"; then pass "GUI_PORT in config"; else fail "GUI_PORT missing"; fi
    if grep -qE '^LOXPROX_DEPLOY_SH="/.*deploy\.sh"$' "$GATEWAY_CONFIG_FILE"; then
        pass "LOXPROX_DEPLOY_SH is an absolute deploy.sh path"
    else
        fail "LOXPROX_DEPLOY_SH missing or not absolute"
    fi
}

test_rollback_validation() {
    echo ""
    echo "━━━ rollback validation ━━━"

    # H6: rollback must restore each file to its ORIGINAL path (manifest-based),
    # validate the BACKED-UP config (not the live one), and restart everything it
    # stopped. We verify the path-preserving restore + service restart are present.
    if grep -q "manifest.txt" "$PROJECT_DIR/deploy.sh"; then
        pass "rollback path-preserving restore (manifest) present in deploy.sh"
    else
        fail "rollback path-preserving restore missing from deploy.sh"
    fi
    if grep -q "systemctl start crowdsec crowdsec-firewall-bouncer" "$PROJECT_DIR/deploy.sh"; then
        pass "rollback restarts all stopped services (H6.3)"
    else
        fail "rollback does not restart all stopped services"
    fi
    if grep -q "pre-rollback snapshot" "$PROJECT_DIR/deploy.sh"; then
        pass "pre-rollback snapshot code present"
    else
        fail "pre-rollback snapshot code missing"
    fi
    if grep -q "nft -c" "$PROJECT_DIR/deploy.sh"; then
        pass "nft -c validation present in rollback"
    else
        fail "nft -c validation missing from rollback"
    fi
}

test_crowdsec_install_no_curl_pipe() {
    echo ""
    echo "━━━ CrowdSec install (CRIT-001) ━━━"

    # Look for actual pipe-to-shell pattern, not just mentions in comments
    if grep -E 'curl .*\|.*bash' "$PROJECT_DIR/deploy.sh" >/dev/null 2>&1; then
        fail "deploy.sh still contains curl|bash"
    else
        pass "deploy.sh is free of curl|bash"
    fi
    if grep -q "gpgkey" "$PROJECT_DIR/deploy.sh"; then
        pass "GPG key pinning present in deploy.sh"
    else
        fail "GPG key pinning missing from deploy.sh"
    fi
    if grep -q "signed-by=" "$PROJECT_DIR/deploy.sh"; then
        pass "apt signed-by present in deploy.sh"
    else
        fail "apt signed-by missing from deploy.sh"
    fi
    if grep -q "/etc/apt/keyrings" "$PROJECT_DIR/deploy.sh"; then
        pass "GPG key in /etc/apt/keyrings (Debian 12 standard)"
    else
        fail "GPG key not in /etc/apt/keyrings"
    fi
    # cscli does not support @version tags in collections install — verify we didn't add them
    if grep -E 'cscli collections install.*@v' "$PROJECT_DIR/deploy.sh" >/dev/null 2>&1; then
        fail "cscli collections install uses unsupported @version syntax"
    else
        pass "cscli collections install uses plain names (no unsupported @version tags)"
    fi

    if grep -E 'curl .*\|.*bash' "$PROJECT_DIR/phase2-gateway/install-gateway.sh" >/dev/null 2>&1; then
        fail "install-gateway.sh still contains curl|bash"
    else
        pass "install-gateway.sh is free of curl|bash"
    fi
}

# ── v1.5.0 — config file separation + bootstrap ──────────────────────────────

test_load_config_sources_values() {
    echo ""
    echo "━━━ _loxprox_load_config() ━━━"

    local conf="$MOCK_ROOT/etc/loxprox/deploy.conf.unit-test"
    cat > "$conf" <<'EOF'
LOXONE_IP="192.168.42.99"
LOXONE_PORT="80"
GATEWAY_IP="192.168.42.10"
LAN_SUBNET="192.168.42.0/24"
SSH_ALLOWED_SUBNETS=("192.168.42.0/24" "10.99.0.0/24")
ENABLE_APPSEC="false"
EOF

    LOXPROX_DEPLOY_CONF="$conf" _loxprox_load_config && pass "load_config returns 0 when file exists" || fail "load_config returned non-zero"

    # Source it for assertions
    # shellcheck disable=SC1090
    source "$conf"
    [[ "$LOXONE_IP" == "192.168.42.99" ]]            && pass "LOXONE_IP sourced"           || fail "LOXONE_IP wrong: $LOXONE_IP"
    [[ "$GATEWAY_IP" == "192.168.42.10" ]]           && pass "GATEWAY_IP sourced"          || fail "GATEWAY_IP wrong: $GATEWAY_IP"
    [[ "${SSH_ALLOWED_SUBNETS[1]}" == "10.99.0.0/24" ]] && pass "SSH_ALLOWED_SUBNETS array sourced" || fail "SSH array wrong"
    [[ "$ENABLE_APPSEC" == "false" ]]                && pass "ENABLE_APPSEC sourced"       || fail "ENABLE_APPSEC wrong"

    # Reset for downstream tests
    LOXONE_IP="192.168.1.100"; LOXONE_PORT="80"
    GATEWAY_IP="192.168.1.50"; LAN_SUBNET="192.168.1.0/24"
    SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")
    ENABLE_APPSEC="true"

    # Negative — file missing
    LOXPROX_DEPLOY_CONF="$MOCK_ROOT/etc/loxprox/does-not-exist.conf" _loxprox_load_config
    [[ $? -eq 1 ]] && pass "load_config returns 1 when file absent" || fail "load_config should return 1 when file missing"
}

test_detect_live_install() {
    echo ""
    echo "━━━ _loxprox_detect_live_install() ━━━"

    # Fresh mock — no install artifacts
    rm -f "$NGINX_SITE"
    _loxprox_detect_live_install && fail "detect should return 1 on empty mock root" || pass "detect returns 1 on fresh state"

    # With nginx site present
    mkdir -p "$(dirname "$NGINX_SITE")"
    touch "$NGINX_SITE"
    _loxprox_detect_live_install && pass "detect returns 0 when nginx site exists" || fail "detect should return 0 when NGINX_SITE exists"
    rm -f "$NGINX_SITE"
}

test_extract_config_from_live_state() {
    echo ""
    echo "━━━ _loxprox_extract_config_from_live_state() ━━━"

    # Fixture: representative live state.
    mkdir -p "$(dirname "$NGINX_SITE")" "$(dirname "$NFTABLES_CONF")" \
             "$MOCK_ROOT/etc/crowdsec/acquis.d" "$MOCK_ROOT/etc/crowdsec/parsers/s02-enrich"

    # Note the aligned-column whitespace in `auth_request      /crowdsec-appsec;`
    # — that's how real hand-edited nginx configs look. v1.5.0 shipped a
    # literal-single-space match here and the maintainer's own upgrade
    # from v1.4.0 misread the site as ENABLE_APPSEC=false. v1.5.1 makes the
    # extractor whitespace-tolerant; this fixture pins the behaviour.
    cat > "$NGINX_SITE" <<'NGINX_FIXTURE'
upstream loxone_backend {
    server 192.168.42.20:80;
    keepalive 32;
}
server {
    listen 1080;
    location /crowdsec-appsec { internal; }
    location / {
        auth_request      /crowdsec-appsec;
        proxy_pass http://loxone_backend;
    }
}
NGINX_FIXTURE

    cat > "$NFTABLES_CONF" <<'NFT_FIXTURE'
table inet filter {
    chain input {
        tcp dport 22 ip saddr { 192.168.42.0/24, 10.99.0.0/24 } accept
        tcp dport 1080 accept
    }
}
NFT_FIXTURE

    cat > "$MOCK_ROOT/etc/crowdsec/acquis.d/appsec.yaml" <<'APPSEC_FIXTURE'
appsec_config: crowdsecurity/appsec-default
mode: enforce
APPSEC_FIXTURE

    cat > "$MOCK_ROOT/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml" <<'WL_FIXTURE'
name: whitelist-loxone
whitelist:
  ip:
    - "192.168.42.99"
  cidr:
    - "192.168.42.0/24"
    - "10.99.0.0/24"
WL_FIXTURE

    # Override the hardcoded paths the extractor reads.
    local out
    out=$(mktemp -t loxprox-extract.XXXXXX)
    _loxprox_extract_config_from_live_state "$out" >/dev/null 2>&1
    local rc=$?

    [[ $rc -eq 0 ]] && pass "extract returns 0 on complete fixture" || fail "extract returned $rc (expected 0)"
    grep -q 'LOXONE_IP="192.168.42.20"' "$out"      && pass "extracted LOXONE_IP"      || fail "LOXONE_IP not extracted"
    grep -q 'LOXONE_PORT="80"' "$out"                && pass "extracted LOXONE_PORT"    || fail "LOXONE_PORT not extracted"
    grep -q '"192.168.42.0/24"' "$out"              && pass "extracted SSH subnet 1"   || fail "SSH subnet 1 missing"
    grep -q '"10.99.0.0/24"' "$out"                  && pass "extracted SSH subnet 2"   || fail "SSH subnet 2 missing"
    grep -q 'ENABLE_APPSEC="true"' "$out"            && pass "detected ENABLE_APPSEC"   || fail "ENABLE_APPSEC not detected"
    grep -q 'APPSEC_MODE="enforce"' "$out"           && pass "extracted APPSEC_MODE"    || fail "APPSEC_MODE not extracted"
    rm -f "$out"

    # Negative — empty fixture
    rm -f "$NGINX_SITE" "$NFTABLES_CONF"
    out=$(mktemp -t loxprox-extract.XXXXXX)
    _loxprox_extract_config_from_live_state "$out" >/dev/null 2>&1
    [[ $? -eq 1 ]] && pass "extract returns 1 on empty fixture" || fail "extract should return 1 when nothing readable"
    rm -f "$out"
}

test_configure_nginx_preserves_existing_site() {
    echo ""
    echo "━━━ configure_nginx() — versioned regeneration (v2.3/H2) ━━━"

    mkdir -p "$(dirname "$NGINX_SITE")"
    local sentinel='# OPERATOR-EDITED-SENTINEL-DO-NOT-REMOVE'
    local backup_path="$BACKUP_DIR/files$NGINX_SITE"
    rm -f "$NGINX_SITE" "$backup_path"

    # ── (a) unstamped site (pre-v2.3, or hand-written) → regenerated ─────────
    # The site is no longer write-once: a file with no template-version stamp
    # is treated as stale and rewritten from the current template, with the
    # pre-regen content backed up first.
    cat > "$NGINX_SITE" <<EOF
$sentinel
server {
    listen 1080;
    location /ws/ {
        # custom WebSocket block — hand-edited, pre-v2.3
        proxy_pass http://loxone_backend;
    }
}
EOF

    configure_nginx >/dev/null 2>&1

    grep -q "$sentinel" "$NGINX_SITE" && fail "unstamped (pre-v2.3) site was NOT regenerated" \
                                       || pass "unstamped (pre-v2.3) site is regenerated"
    [[ -f "$backup_path" ]] && grep -q "$sentinel" "$backup_path" \
        && pass "pre-regen file backed up under BACKUP_DIR/files<path>, sentinel intact there" \
        || fail "backup of the pre-regen site missing, or does not carry the sentinel"
    grep -q "${_LOXPROX_SITE_VERSION_MARKER} ${_LOXPROX_SITE_TEMPLATE_VERSION}" "$NGINX_SITE" \
        && pass "regenerated site carries the current template version marker" \
        || fail "regenerated site missing the template version marker"
    # v1.5.0 final shape: NO conf.d split — map + log_format stay inline in
    # the site config (nginx -t rejects the split because `auth_request_set`
    # registers $appsec_action at parse time, and the variable must be
    # registered before any `if=$var` access_log reference). The conf.d file
    # must be cleaned up if it lingered from an earlier dev iteration.
    [[ ! -f "$NGINX_APPSEC_AUDIT_CONF" ]] && pass "conf.d/loxprox-appsec.conf is NOT written" \
                                          || fail "conf.d/loxprox-appsec.conf should not exist"
    grep -q 'log_format appsec_evt' "$NGINX_SITE"     && pass "log_format appsec_evt in regenerated site"    || fail "log_format missing from regenerated site"
    grep -q 'map \$appsec_action' "$NGINX_SITE"       && pass "map \$appsec_action in regenerated site"     || fail "map missing from regenerated site"
    grep -q 'if=\$appsec_blocked' "$NGINX_SITE"       && pass "conditional access_log in regenerated site" || fail "conditional access_log missing"
    # F3 — access log scrubbed of query string (combined-shaped for CrowdSec)
    grep -q 'log_format loxone_scrubbed' "$NGINX_SITE" && pass "F3: scrubbed log_format defined"          || fail "F3: scrubbed log_format missing"
    grep -qE 'access_log /var/log/nginx/loxone-access\.log +loxone_scrubbed;' "$NGINX_SITE" && pass "F3: main access_log uses scrubbed format" || fail "F3: main access_log not scrubbed (query string still logged)"
    grep -q '\$request_method \$loxone_log_uri \$server_protocol' "$NGINX_SITE" && pass "F3: request line uses redacted \$loxone_log_uri (not raw \$request)" || fail "F3: scrubbed format does not use \$loxone_log_uri"
    grep -q 'map \$uri \$loxone_log_uri' "$NGINX_SITE" && pass "F3: path-redaction map present"        || fail "F3: redaction map missing"
    grep -qE 'fenc\|enc\|gettoken\|getjwt\|keyexchange\|getkey2' "$NGINX_SITE" && pass "F3: redaction covers fenc/enc/gettoken/keyexchange path forms" || fail "F3: redaction map does not cover the sensitive Loxone endpoints"
    # F7 — WebSocket transparency (additive; non-WS behaviour unchanged)
    grep -q 'map \$http_upgrade \$connection_upgrade' "$NGINX_SITE" && pass "F7: WebSocket upgrade map present"        || fail "F7: WebSocket map missing"
    grep -qE 'proxy_set_header Upgrade +\$http_upgrade' "$NGINX_SITE" && pass "F7: Upgrade header forwarded"          || fail "F7: Upgrade header missing"
    grep -qE 'proxy_set_header Connection +\$connection_upgrade' "$NGINX_SITE" && pass "F7: Connection is WS-aware"   || fail "F7: Connection header not WS-aware"

    # ── (b) LOXPROX_KEEP_NGINX_SITE=1 → hand-maintained site is frozen ───────
    cat > "$NGINX_SITE" <<EOF
$sentinel
server {
    listen 1080;
}
EOF
    LOXPROX_KEEP_NGINX_SITE=1 configure_nginx >/dev/null 2>&1
    grep -q "$sentinel" "$NGINX_SITE" && pass "LOXPROX_KEEP_NGINX_SITE=1 freezes the site (sentinel survives)" \
                                       || fail "LOXPROX_KEEP_NGINX_SITE=1 did not freeze the site"

    # ── (c) unchanged re-run does not rewrite; a changed deploy.conf value does ─
    rm -f "$NGINX_SITE" "$backup_path"
    configure_nginx >/dev/null 2>&1   # fresh, current-version, current-fingerprint site
    local before_hash after_hash
    before_hash=$(sha256sum "$NGINX_SITE" | awk '{print $1}')
    configure_nginx >/dev/null 2>&1
    after_hash=$(sha256sum "$NGINX_SITE" | awk '{print $1}')
    [[ "$before_hash" == "$after_hash" ]] && pass "unchanged re-run does not rewrite the site (version+fingerprint match)" \
                                            || fail "unchanged re-run rewrote the site"

    local saved_rate="$RATE_LIMIT_REQ_PER_SEC"
    RATE_LIMIT_REQ_PER_SEC="42"
    configure_nginx >/dev/null 2>&1
    after_hash=$(sha256sum "$NGINX_SITE" | awk '{print $1}')
    [[ "$before_hash" != "$after_hash" ]] && pass "changed RATE_LIMIT_REQ_PER_SEC regenerates the site (fingerprint mismatch)" \
                                            || fail "changed RATE_LIMIT_REQ_PER_SEC did not regenerate the site"
    grep -q 'rate=42r/s' "$NGINX_SITE" && pass "regenerated site carries the new rate limit" || fail "new rate limit not applied"
    RATE_LIMIT_REQ_PER_SEC="$saved_rate"

    rm -f "$NGINX_SITE" "$backup_path"
}

# ── v1.5.0 — optional TLS via acme.sh ────────────────────────────────────────

test_tls_validate_config() {
    echo ""
    echo "━━━ _loxprox_tls_validate_config() ━━━"

    local saved_domain="$TLS_DOMAIN"

    TLS_DOMAIN="" _loxprox_tls_validate_config 2>/dev/null
    [[ $? -eq 1 ]] && pass "refuses empty TLS_DOMAIN" || fail "should refuse empty TLS_DOMAIN"

    TLS_DOMAIN="bare-hostname" _loxprox_tls_validate_config 2>/dev/null
    [[ $? -eq 1 ]] && pass "refuses non-FQDN (no dots)" || fail "should refuse non-FQDN"

    TLS_DOMAIN="loxprox.example.com" _loxprox_tls_validate_config 2>/dev/null
    [[ $? -eq 0 ]] && pass "accepts valid FQDN" || fail "should accept FQDN"

    TLS_DOMAIN="$saved_domain"
}

test_tls_site_mutation_round_trip() {
    echo ""
    echo "━━━ TLS site mutation — enable/disable/idempotency ━━━"

    mkdir -p "$(dirname "$NGINX_SITE")"
    # Fresh "v1.5.0-shaped" site config — what configure_nginx writes.
    cat > "$NGINX_SITE" <<'EOF'
upstream loxone_backend {
    server 192.168.42.20:80;
}
server {
    listen 1080;
    server_name _;
    location / {
        proxy_pass http://loxone_backend;
    }
}
EOF

    # State 0: not in TLS mode
    _loxprox_site_in_tls_mode && fail "fresh site should NOT report in_tls_mode" || pass "fresh site is plain HTTP"

    # Enable → markers + ssl listen
    _loxprox_site_enable_tls >/dev/null 2>&1
    [[ $? -eq 0 ]] && pass "enable returns 0 on canonical site" || fail "enable failed on canonical site"
    grep -q '^[[:space:]]*listen 1080 ssl;' "$NGINX_SITE" && pass "listen line swapped to 'listen 1080 ssl;'" || fail "listen line not swapped"
    grep -q '# LOXPROX-TLS-BEGIN' "$NGINX_SITE" && pass "TLS-BEGIN marker present" || fail "TLS-BEGIN marker missing"
    grep -q '# LOXPROX-TLS-END' "$NGINX_SITE" && pass "TLS-END marker present" || fail "TLS-END marker missing"
    grep -q 'ssl_certificate     /etc/loxprox/tls/fullchain.pem;' "$NGINX_SITE" && pass "ssl_certificate path present" || fail "ssl_certificate missing"
    grep -q 'Strict-Transport-Security' "$NGINX_SITE" && pass "HSTS header present" || fail "HSTS header missing"
    # F6 — TLS forward-secrecy hardening
    grep -q 'ssl_session_tickets off;' "$NGINX_SITE" && pass "F6: ssl_session_tickets off present" || fail "F6: ssl_session_tickets off missing (PFS regression)"
    grep -qE 'ssl_ciphers .*ECDHE' "$NGINX_SITE" && pass "F6: PFS ssl_ciphers (ECDHE-only) present" || fail "F6: PFS ssl_ciphers missing (non-PFS suite negotiable)"
    _loxprox_site_in_tls_mode && pass "in_tls_mode true after enable" || fail "in_tls_mode should be true"

    # Re-enable should be a no-op
    local before_hash after_hash
    before_hash=$(sha256sum "$NGINX_SITE" | awk '{print $1}')
    _loxprox_site_enable_tls >/dev/null 2>&1
    after_hash=$(sha256sum "$NGINX_SITE" | awk '{print $1}')
    [[ "$before_hash" == "$after_hash" ]] && pass "re-enable is idempotent (no mutation)" || fail "re-enable mutated the file"

    # Disable → marker block stripped, listen reverted
    _loxprox_site_disable_tls >/dev/null 2>&1
    grep -q '^[[:space:]]*listen 1080;' "$NGINX_SITE" && pass "listen line reverted to plain" || fail "listen revert failed"
    grep -q '# LOXPROX-TLS-' "$NGINX_SITE" && fail "TLS markers should be gone after disable" || pass "marker block stripped"
    _loxprox_site_in_tls_mode && fail "in_tls_mode should be false after disable" || pass "in_tls_mode false after disable"

    # Re-disable is a no-op (site already plain)
    before_hash=$(sha256sum "$NGINX_SITE" | awk '{print $1}')
    _loxprox_site_disable_tls >/dev/null 2>&1
    after_hash=$(sha256sum "$NGINX_SITE" | awk '{print $1}')
    [[ "$before_hash" == "$after_hash" ]] && pass "re-disable is idempotent (no mutation)" || fail "re-disable mutated the file"

    # Enable again — should produce identical content to the first enable
    _loxprox_site_enable_tls >/dev/null 2>&1
    grep -q '^[[:space:]]*listen 1080 ssl;' "$NGINX_SITE" && pass "second enable swaps listen again" || fail "second enable failed"

    rm -f "$NGINX_SITE"
}

test_tls_enable_refuses_noncanonical_listen() {
    echo ""
    echo "━━━ TLS site mutation refuses non-canonical 'listen' ━━━"

    mkdir -p "$(dirname "$NGINX_SITE")"
    # Operator hand-edited the listen line into IPv6-explicit form.
    cat > "$NGINX_SITE" <<'EOF'
server {
    listen [::]:1080;
    server_name _;
}
EOF
    _loxprox_site_enable_tls >/dev/null 2>&1
    [[ $? -eq 1 ]] && pass "refuses non-canonical listen line" || fail "should refuse non-canonical listen"
    grep -q 'TLS-BEGIN' "$NGINX_SITE" && fail "must NOT mutate when refusing" || pass "site untouched when refused"

    rm -f "$NGINX_SITE"
}

test_tls_acme_listener_written() {
    echo ""
    echo "━━━ _loxprox_write_acme_listener() ━━━"

    local saved_webroot="$ACME_WEBROOT"
    # Re-target the webroot into MOCK_ROOT so non-root tests can create dirs.
    ACME_WEBROOT="$MOCK_ROOT/var/www/acme"
    rm -f "$NGINX_ACME_CONF"
    GATEWAY_IP="192.168.42.252" _loxprox_write_acme_listener
    [[ -f "$NGINX_ACME_CONF" ]] && pass "ACME conf.d file written" || fail "ACME conf.d not written"
    grep -q 'listen      80 default_server;' "$NGINX_ACME_CONF" && pass ":80 listener present" || fail ":80 listen missing"
    grep -q '/.well-known/acme-challenge/' "$NGINX_ACME_CONF" && pass "challenge location present" || fail "challenge location missing"
    grep -q 'return 301 https://\$host:1080' "$NGINX_ACME_CONF" && pass "301-to-HTTPS catch-all present" || fail "301 catch-all missing"
    rm -f "$NGINX_ACME_CONF"
    rm -rf "$ACME_WEBROOT"
    ACME_WEBROOT="$saved_webroot"
}

# ── v2.0 — tunnel module ─────────────────────────────────────────────────────

# The config globals set below are consumed by the deploy.sh functions under
# test (sourced above), not read within this file — silence SC2034.
# shellcheck disable=SC2034
test_tunnel_validate_config() {
    echo ""
    echo "━━━ _loxprox_tunnel_validate_config() ━━━"

    # Baseline: everything valid.
    ENABLE_TLS="false"
    TUNNEL_SERVER_ADDR="203.0.113.10"
    TUNNEL_SERVER_PORT="7000"
    TUNNEL_PROTOCOL="quic"
    TUNNEL_TOKEN="deadbeefdeadbeefdeadbeefdeadbeef"
    TUNNEL_PROXY_NAME="loxone"
    TUNNEL_REMOTE_PORT="8443"
    if _loxprox_tunnel_validate_config 2>/dev/null; then pass "valid config accepted"; else fail "valid config rejected"; fi

    TUNNEL_SERVER_ADDR=""
    if ! _loxprox_tunnel_validate_config 2>/dev/null; then pass "empty server addr rejected"; else fail "empty server addr accepted"; fi
    TUNNEL_SERVER_ADDR="203.0.113.10"

    TUNNEL_TOKEN=""
    if ! _loxprox_tunnel_validate_config 2>/dev/null; then pass "empty token rejected"; else fail "empty token accepted"; fi
    TUNNEL_TOKEN="deadbeefdeadbeefdeadbeefdeadbeef"

    TUNNEL_SERVER_PORT="99999"
    if ! _loxprox_tunnel_validate_config 2>/dev/null; then pass "port >65535 rejected"; else fail "port >65535 accepted"; fi
    TUNNEL_SERVER_PORT="abc"
    if ! _loxprox_tunnel_validate_config 2>/dev/null; then pass "non-numeric port rejected"; else fail "non-numeric port accepted"; fi
    TUNNEL_SERVER_PORT="7000"

    TUNNEL_PROTOCOL="carrier-pigeon"
    if ! _loxprox_tunnel_validate_config 2>/dev/null; then pass "unknown protocol rejected"; else fail "unknown protocol accepted"; fi
    TUNNEL_PROTOCOL="tcp"
    if _loxprox_tunnel_validate_config 2>/dev/null; then pass "tcp protocol accepted"; else fail "tcp protocol rejected"; fi
    TUNNEL_PROTOCOL="quic"

    TUNNEL_PROXY_NAME="bad name;rm -rf"
    if ! _loxprox_tunnel_validate_config 2>/dev/null; then pass "shell-metachar proxy name rejected"; else fail "shell-metachar proxy name accepted"; fi
    TUNNEL_PROXY_NAME="loxone"

    # v2.0 hard limitation: gateway TLS + tunnel are mutually exclusive.
    ENABLE_TLS="true"
    if ! _loxprox_tunnel_validate_config 2>/dev/null; then pass "ENABLE_TLS+ENABLE_TUNNEL combination refused"; else fail "ENABLE_TLS+ENABLE_TUNNEL combination accepted"; fi
    ENABLE_TLS="false"
}

# shellcheck disable=SC2034  # globals consumed by sourced deploy.sh helpers
test_tunnel_frpc_config_generation() {
    echo ""
    echo "━━━ _loxprox_write_frpc_config() ━━━"

    FRP_DIR="$MOCK_ROOT/etc/frp"
    FRPC_CONF="$FRP_DIR/frpc.toml"
    TUNNEL_SERVER_ADDR="203.0.113.10"
    TUNNEL_SERVER_PORT="7000"
    TUNNEL_PROTOCOL="quic"
    TUNNEL_TOKEN="deadbeefdeadbeefdeadbeefdeadbeef"
    TUNNEL_PROXY_NAME="loxone"
    TUNNEL_REMOTE_PORT="8443"

    _loxprox_write_frpc_config

    if [[ -f "$FRPC_CONF" ]]; then pass "frpc.toml written"; else fail "frpc.toml missing"; fi
    grep -q 'serverAddr = "203.0.113.10"' "$FRPC_CONF" && pass "serverAddr rendered" || fail "serverAddr missing"
    grep -q 'serverPort = 7000' "$FRPC_CONF" && pass "serverPort rendered" || fail "serverPort missing"
    grep -q 'auth.token = "deadbeefdeadbeefdeadbeefdeadbeef"' "$FRPC_CONF" && pass "token rendered" || fail "token missing"
    grep -q 'transport.protocol = "quic"' "$FRPC_CONF" && pass "quic transport rendered" || fail "transport missing"
    grep -q 'transport.tls.enable = true' "$FRPC_CONF" && pass "transport TLS enabled" || fail "transport TLS missing"
    grep -q 'localIP = "127.0.0.1"' "$FRPC_CONF" && pass "localIP loopback" || fail "localIP wrong"
    grep -q 'localPort = 1080' "$FRPC_CONF" && pass "localPort 1080" || fail "localPort wrong"
    grep -q 'remotePort = 8443' "$FRPC_CONF" && pass "remotePort rendered" || fail "remotePort missing"

    # Token file must be group-readable at most (0640).
    local mode
    mode=$(stat -c '%a' "$FRPC_CONF" 2>/dev/null || stat -f '%OLp' "$FRPC_CONF" 2>/dev/null)
    [[ "$mode" == "640" ]] && pass "frpc.toml mode 0640" || fail "frpc.toml mode is $mode (expected 640)"
}

test_tunnel_frpc_unit_hardening() {
    echo ""
    echo "━━━ _loxprox_write_frpc_unit() ━━━"

    FRPC_UNIT="$MOCK_ROOT/etc/systemd/system/frpc.service"
    mkdir -p "$(dirname "$FRPC_UNIT")"
    _loxprox_write_frpc_unit

    if [[ -f "$FRPC_UNIT" ]]; then pass "frpc.service written"; else fail "frpc.service missing"; fi
    grep -q '^User=frpc' "$FRPC_UNIT" && pass "runs as unprivileged user" || fail "User=frpc missing"
    grep -q '^ProtectSystem=strict' "$FRPC_UNIT" && pass "ProtectSystem=strict" || fail "ProtectSystem missing"
    grep -q '^CapabilityBoundingSet=$' "$FRPC_UNIT" && pass "empty capability set" || fail "CapabilityBoundingSet not empty"
    grep -q '^SystemCallFilter=@system-service' "$FRPC_UNIT" && pass "syscall filter present" || fail "syscall filter missing"
    grep -q '^MemoryMax=256M' "$FRPC_UNIT" && pass "memory cap present" || fail "memory cap missing"
    grep -q '^Restart=always' "$FRPC_UNIT" && pass "Restart=always" || fail "Restart=always missing"
    grep -q '^StartLimitIntervalSec=0' "$FRPC_UNIT" && pass "no start-limit lockout (keeps retrying)" || fail "StartLimitIntervalSec=0 missing"
    grep -q '^NoNewPrivileges=true' "$FRPC_UNIT" && pass "NoNewPrivileges" || fail "NoNewPrivileges missing"
}

test_tunnel_realip_conf() {
    echo ""
    echo "━━━ _loxprox_write_tunnel_realip_conf() ━━━"

    NGINX_TUNNEL_CONF="$MOCK_ROOT/etc/nginx/conf.d/loxprox-tunnel-realip.conf"
    _loxprox_write_tunnel_realip_conf

    if [[ -f "$NGINX_TUNNEL_CONF" ]]; then pass "realip conf written"; else fail "realip conf missing"; fi
    grep -q 'set_real_ip_from 127.0.0.1;' "$NGINX_TUNNEL_CONF" && pass "trusts loopback only" || fail "set_real_ip_from wrong"
    grep -q 'real_ip_header X-Forwarded-For;' "$NGINX_TUNNEL_CONF" && pass "XFF header source" || fail "real_ip_header wrong"
    grep -q 'real_ip_recursive off;' "$NGINX_TUNNEL_CONF" && pass "recursive off (spoof-proof)" || fail "real_ip_recursive wrong"
    # Must NOT trust any non-loopback source.
    if grep 'set_real_ip_from' "$NGINX_TUNNEL_CONF" | grep -vq '127\.0\.0\.1'; then
        fail "unexpected extra trusted proxy"
    else
        pass "no extra trusted proxies"
    fi
}

test_nginx_ws_location() {
    echo ""
    echo "━━━ configure_nginx() — /ws/ WebSocket location (v2.0) ━━━"

    # Force a FRESH generation — the preserve-operator-edits guard would
    # otherwise keep the site file from the earlier test.
    rm -f "$NGINX_SITE"
    configure_nginx

    grep -q 'location /ws/ {' "$NGINX_SITE" && pass "/ws/ location present" || fail "/ws/ location missing"
    grep -q 'proxy_read_timeout  86400s;' "$NGINX_SITE" && pass "24h read timeout on /ws/" || fail "24h read timeout missing"
    grep -q 'proxy_send_timeout  86400s;' "$NGINX_SITE" && pass "24h send timeout on /ws/" || fail "24h send timeout missing"
    grep -q 'proxy_buffering     off;' "$NGINX_SITE" && pass "buffering off on /ws/" || fail "buffering off missing"
    # AppSec must still guard the WS handshake (two auth_request lines: / and /ws/).
    local auth_count
    auth_count=$(grep -c 'auth_request      /crowdsec-appsec;' "$NGINX_SITE")
    [[ "$auth_count" -eq 2 ]] && pass "AppSec guards both / and /ws/" || fail "expected 2 auth_request lines, got $auth_count"
}

# shellcheck disable=SC2034  # globals consumed by sourced deploy.sh helpers
test_acme_fallback_ca() {
    echo ""
    echo "━━━ _loxprox_acme_issue() — fallback CA (v2.0) ━━━"

    # Mock acme.sh: fails for letsencrypt, succeeds for zerossl.
    local saved_home="$ACME_HOME"
    ACME_HOME="$MOCK_ROOT/acme-home"
    mkdir -p "$ACME_HOME"
    cat > "$ACME_HOME/acme.sh" <<'MOCK'
#!/bin/bash
server=""
prev=""
for a in "$@"; do
    [[ "$prev" == "--server" ]] && server="$a"
    prev="$a"
done
[[ "$server" == "zerossl" ]] && exit 0
exit 1
MOCK
    chmod +x "$ACME_HOME/acme.sh"

    TLS_DOMAIN="loxprox.example.com"
    TLS_ACME_SERVER="letsencrypt"
    TLS_ACME_FALLBACK_SERVER="zerossl"
    ACME_WEBROOT="$MOCK_ROOT/var/www/acme"
    mkdir -p "$ACME_WEBROOT"

    if _loxprox_acme_issue >/dev/null 2>&1; then
        pass "primary CA failure falls back to zerossl"
    else
        fail "fallback CA not used on primary failure"
    fi

    TLS_ACME_FALLBACK_SERVER=""
    if ! _loxprox_acme_issue >/dev/null 2>&1; then
        pass "no fallback configured → failure propagates"
    else
        fail "issue succeeded despite failing primary and no fallback"
    fi

    # Primary success path (mock returns 0 for zerossl as primary).
    TLS_ACME_FALLBACK_SERVER="zerossl"
    TLS_ACME_SERVER="zerossl"
    if _loxprox_acme_issue >/dev/null 2>&1; then
        pass "primary success path intact"
    else
        fail "primary success path broken"
    fi
    TLS_ACME_SERVER="letsencrypt"
    ACME_HOME="$saved_home"
}

# ── v2.1 — LoxProx Panel (GUI) ───────────────────────────────────────────────

test_gui_setup() {
    echo ""
    echo "━━━ setup_gui() ━━━"

    rm -f "$GUI_UNIT" "$GUI_APP"

    # Simulate an upgrade from a v2.2 install that still has the vendored
    # three.js/anime.js bundles next to the panel.
    local gui_static
    gui_static="$(dirname "$GUI_APP")/static"
    mkdir -p "$gui_static/vendor"
    echo "stale" > "$gui_static/vendor/three.core.min.js"
    echo "stale" > "$gui_static/vendor/anime.esm.min.js"

    ENABLE_GUI="true" setup_gui >/dev/null 2>&1
    if [[ -f "$GUI_UNIT" ]]; then pass "unit written"; else fail "unit missing"; fi
    if [[ -f "$GUI_APP" ]]; then pass "panel script installed"; else fail "panel script not installed"; fi
    if [[ ! -e "$gui_static/vendor" ]]; then pass "upgrade removes stale static/vendor/ bundles"; else fail "stale static/vendor/ survived the upgrade"; fi
    if [[ -f "$gui_static/panel.html" && -f "$gui_static/panel.js" && -f "$gui_static/i18n.js" && -f "$gui_static/charts.js" ]]; then
        pass "panel assets installed next to the script"
    else
        fail "panel assets missing after install"
    fi
    grep -q '^Description=LoxProx Panel (LAN-only GUI)$' "$GUI_UNIT" && pass "Description present" || fail "Description wrong"
    grep -qE "^ExecStart=/usr/bin/python3 .*/loxprox-gui\.py$" "$GUI_UNIT" && pass "ExecStart runs python3 + panel" || fail "ExecStart wrong"
    grep -q '^Restart=always$' "$GUI_UNIT" && pass "Restart=always" || fail "Restart=always missing"
    grep -q '^RestartSec=5$' "$GUI_UNIT" && pass "RestartSec=5" || fail "RestartSec missing"
    grep -q '^PrivateTmp=true$' "$GUI_UNIT" && pass "PrivateTmp=true" || fail "PrivateTmp missing"
    grep -q '^StandardOutput=append:/var/log/loxprox-gui.log$' "$GUI_UNIT" && pass "log to loxprox-gui.log" || fail "StandardOutput wrong"
    grep -q '^WantedBy=multi-user.target$' "$GUI_UNIT" && pass "install target present" || fail "WantedBy missing"
    # Root + no ProtectSystem is deliberate — the unit must say why.
    grep -q 'ProtectSystem' "$GUI_UNIT" && pass "unit documents the missing sandbox" || fail "no rationale for absent ProtectSystem"

    # Idempotency: a second run must produce a byte-identical unit.
    local before_hash after_hash
    before_hash=$(sha256sum "$GUI_UNIT" | awk '{print $1}')
    ENABLE_GUI="true" setup_gui >/dev/null 2>&1
    after_hash=$(sha256sum "$GUI_UNIT" | awk '{print $1}')
    [[ "$before_hash" == "$after_hash" ]] && pass "re-run is idempotent (unit unchanged)" || fail "re-run mutated the unit"

    # Disable → unit and installed script removed.
    ENABLE_GUI="false" setup_gui >/dev/null 2>&1
    [[ ! -f "$GUI_UNIT" ]] && pass "ENABLE_GUI=false removes the unit" || fail "unit survived disable"
    [[ ! -f "$GUI_APP" ]] && pass "ENABLE_GUI=false removes the panel script" || fail "panel script survived disable"
    [[ ! -d "$gui_static" ]] && pass "ENABLE_GUI=false removes the panel assets" || fail "panel assets survived disable"

    # Disabling twice must stay quiet and succeed.
    ENABLE_GUI="false" setup_gui >/dev/null 2>&1
    [[ $? -eq 0 ]] && pass "second disable is a no-op" || fail "second disable returned non-zero"

    # Typo → hard error, never a silent skip.
    ENABLE_GUI="ture" setup_gui >/dev/null 2>&1
    [[ $? -eq 1 ]] && pass "invalid ENABLE_GUI value rejected" || fail "invalid ENABLE_GUI accepted"
    [[ ! -f "$GUI_UNIT" ]] && pass "invalid value writes nothing" || fail "invalid value still wrote the unit"
}

test_gui_firewall_rule() {
    echo ""
    echo "━━━ setup_firewall() — LoxProx Panel rule (v2.1) ━━━"

    local saved_ssh=("${SSH_ALLOWED_SUBNETS[@]}")

    ENABLE_GUI="true"
    setup_firewall >/dev/null 2>&1

    grep -q "tcp dport 1081 ip saddr" "$NFTABLES_CONF" && pass "panel rule emitted" || fail "panel rule missing"
    grep -q "LoxProx Panel — LAN only (v2.1)" "$NFTABLES_CONF" && pass "rule is commented" || fail "rule comment missing"

    local gui_line
    gui_line=$(grep 'tcp dport 1081' "$NFTABLES_CONF")
    grep -q '192.168.1.0/24' <<<"$gui_line" && pass "LAN_SUBNET in the source set" || fail "LAN_SUBNET missing from source set"
    grep -q '10.0.0.0/24' <<<"$gui_line" && pass "SSH subnet in the source set" || fail "SSH subnet missing from source set"

    # Dedup: LAN_SUBNET is also an SSH_ALLOWED_SUBNETS entry here. nft refuses
    # an anonymous set that lists the same element twice.
    local dupes
    dupes=$(grep -o '192.168.1.0/24' <<<"$gui_line" | wc -l | tr -d ' ')
    [[ "$dupes" -eq 1 ]] && pass "duplicate subnet collapsed (nft-safe set)" || fail "LAN_SUBNET appears $dupes times in the set"

    # Explicit duplicate in the array must not survive either.
    SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24" "192.168.1.0/24")
    setup_firewall >/dev/null 2>&1
    gui_line=$(grep 'tcp dport 1081' "$NFTABLES_CONF")
    dupes=$(grep -o '192.168.1.0/24' <<<"$gui_line" | wc -l | tr -d ' ')
    [[ "$dupes" -eq 1 ]] && pass "repeated SSH_ALLOWED_SUBNETS entry deduplicated" || fail "repeated entry appears $dupes times"
    SSH_ALLOWED_SUBNETS=("${saved_ssh[@]}")

    # Disabled → no rule at all.
    ENABLE_GUI="false"
    setup_firewall >/dev/null 2>&1
    grep -q "tcp dport 1081" "$NFTABLES_CONF" && fail "panel rule present with ENABLE_GUI=false" || pass "no panel rule when disabled"
    grep -q "tcp dport 1080 accept" "$NFTABLES_CONF" && pass "proxy rule unaffected" || fail "proxy rule damaged"

    ENABLE_GUI="true"
}

# ── v2.1 — CLI surface ───────────────────────────────────────────────────────
#
# These run deploy.sh as a subprocess, so the mocked systemctl/apt-get are NOT
# in effect. Only paths that exit before touching the system are exercised:
# --help and the unknown-flag guard both return before the root check.

test_cli_help_and_unknown_flag() {
    echo ""
    echo "━━━ deploy.sh --help / unknown flag ━━━"

    local out rc
    out=$(bash "$PROJECT_DIR/deploy.sh" --help 2>&1); rc=$?
    [[ $rc -eq 0 ]] && pass "--help exits 0 unprivileged" || fail "--help exited $rc"
    grep -q -- "--restore" <<<"$out"       && pass "--help documents --restore"       || fail "--restore missing from --help"
    grep -q -- "--remove-tunnel" <<<"$out" && pass "--help documents --remove-tunnel" || fail "--remove-tunnel missing from --help"
    grep -q -- "--bootstrap-config" <<<"$out" && pass "--help documents --bootstrap-config" || fail "--bootstrap-config missing"
    grep -q "ALLOW_LXC" <<<"$out"          && pass "--help documents env toggles"     || fail "env toggles missing from --help"

    out=$(bash "$PROJECT_DIR/deploy.sh" -h 2>&1); rc=$?
    [[ $rc -eq 0 ]] && pass "-h alias exits 0" || fail "-h exited $rc"

    out=$(bash "$PROJECT_DIR/deploy.sh" --not-a-real-flag 2>&1); rc=$?
    [[ $rc -eq 2 ]] && pass "unknown flag exits 2 (no deploy)" || fail "unknown flag exited $rc (expected 2)"
    grep -q "Unknown option" <<<"$out" && pass "unknown flag names the offender" || fail "no error message for unknown flag"
}

test_restore_refuses_missing_archive() {
    echo ""
    echo "━━━ --restore <tarball> — missing archive ━━━"

    # Subshell: the function calls check_root, which exits on failure.
    ( _loxprox_restore_backup "$MOCK_ROOT/does-not-exist.tar.gz" ) >/dev/null 2>&1
    [[ $? -eq 1 ]] && pass "refuses a missing archive (exit 1)" || fail "missing archive not refused"

    ( _loxprox_restore_backup "" ) >/dev/null 2>&1
    [[ $? -eq 1 ]] && pass "refuses an empty argument" || fail "empty argument not refused"

    # The bare-filename form must resolve inside /root/loxprox-backups.
    local out
    out=$( ( _loxprox_restore_backup "nope.tar.gz" ) 2>&1 )
    grep -q "/root/loxprox-backups/nope.tar.gz" <<<"$out" && pass "bare filename resolved in /root/loxprox-backups" || fail "bare filename not resolved"

    # Restore must extract to /var/tmp — /tmp is mounted noexec,nodev,nosuid.
    grep -q 'mktemp -d /var/tmp/loxprox-restore' "$PROJECT_DIR/deploy.sh" && pass "extracts to /var/tmp (not /tmp)" || fail "restore does not use /var/tmp"
    grep -q 'nginx -t fails with the restored site' "$PROJECT_DIR/deploy.sh" && pass "nginx revert-on-failure path present" || fail "nginx revert path missing"
}

# ── 2026-10 health-audit fixes ───────────────────────────────────────────────

# Fix 1 (HIGH): the generated cron file must be one cron accepts.
test_cron_file_generation() {
    echo ""
    echo "━━━ /etc/cron.d/loxprox — generation + lint (2026-10, HIGH) ━━━"

    rm -f "$LOXPROX_CRON_FILE"
    _loxprox_write_security_cron
    [[ -f "$LOXPROX_CRON_FILE" ]] && pass "cron file written" || fail "cron file missing"
    grep -qx 'MAILTO=""' "$LOXPROX_CRON_FILE" && pass 'MAILTO="" (quoted empty value)' || fail 'MAILTO="" missing'
    if grep -qE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=[[:space:]]*$' "$LOXPROX_CRON_FILE"; then
        fail "generated cron file still has a bare NAME= line"
    else
        pass "no bare NAME= assignment"
    fi
    local out
    if out=$(_loxprox_cron_lint "$LOXPROX_CRON_FILE"); then
        pass "generated cron file passes _loxprox_cron_lint"
    else
        fail "generated cron file fails lint: $out"
    fi
    local jobs
    jobs=$(grep -cE '^[0-9*]' "$LOXPROX_CRON_FILE" || true)
    [[ "$jobs" -eq 3 ]] && pass "3 job lines (ban / backup / GeoIP)" || fail "expected 3 job lines, got $jobs"

    # Regression: the shipped v1.3.0–2026-09 content must be rejected.
    local bad="$MOCK_ROOT/cron-fixture-bad"
    printf '%s\n' '# old' 'SHELL=/bin/bash' 'MAILTO=' '' \
        '*/15 * * * * root /opt/loxprox/progressive-ban.py' > "$bad"
    if out=$(_loxprox_cron_lint "$bad"); then
        fail "lint accepted the pre-fix file with a bare MAILTO="
    else
        grep -q ':3: bare MAILTO=' <<<"$out" && pass "lint rejects the pre-fix 'MAILTO=' and names line 3" \
                                            || fail "lint output does not name the bare MAILTO= line: $out"
    fi
    printf '%s\n' 'MAILTO=   ' > "$bad"
    _loxprox_cron_lint "$bad" >/dev/null && fail "whitespace-only value accepted" || pass "whitespace-only value rejected"
    printf '%s\n' '0 2 * * root /opt/x.sh' > "$bad"
    _loxprox_cron_lint "$bad" >/dev/null && fail "4-time-field job accepted" || pass "job line with 4 time fields rejected"
    printf '%s\n' 'x 2 * * * root /opt/x.sh' > "$bad"
    _loxprox_cron_lint "$bad" >/dev/null && fail "non-numeric minute accepted" || pass "non-numeric minute rejected"

    local good="$MOCK_ROOT/cron-fixture-good"
    printf '%s\n' 'MAILTO=""' "MAILTO=''" 'PATH = /usr/bin:/bin' '@daily root /opt/x.sh' \
        '0 3 1 jan mon root /opt/y.sh >> /var/log/y.log 2>&1' '*/5 0-6 * * 1,3,5 root /opt/z.sh' > "$good"
    if out=$(_loxprox_cron_lint "$good"); then
        pass 'lint accepts quoted-empty values, "NAME = v", @keywords and month/day names'
    else
        fail "lint rejects valid cron syntax: $out"
    fi

    # test-gateway.sh carries its own (awk) copy of the rules — same verdicts.
    local tg_bad tg_good
    tg_bad=$( (source "$PROJECT_DIR/test-gateway.sh"; printf '%s\n' 'MAILTO=' '0 2 * * * root /x' > "$bad"; _cron_file_problems "$bad") 2>&1)
    tg_good=$( (source "$PROJECT_DIR/test-gateway.sh"; _cron_file_problems "$good") 2>&1)
    grep -q 'line 1: bare assignment' <<<"$tg_bad" && pass "test-gateway.sh lint flags a bare MAILTO=" || fail "test-gateway.sh lint missed bare MAILTO=: $tg_bad"
    [[ -z "$tg_good" ]] && pass "test-gateway.sh lint accepts the valid fixture" || fail "test-gateway.sh lint rejects valid syntax: $tg_good"
    tg_good=$( (source "$PROJECT_DIR/test-gateway.sh"; _cron_file_problems "$LOXPROX_CRON_FILE") 2>&1)
    [[ -z "$tg_good" ]] && pass "test-gateway.sh lint accepts the generated cron file" || fail "test-gateway.sh lint rejects the generated file: $tg_good"
}

# Fix 1: the health check consults cron's own journal, scoped to the file's
# mtime. journalctl is mocked with a timestamped fixture journal that honours
# --since @EPOCH the way the real one does.
test_cron_health_check() {
    echo ""
    echo "━━━ _loxprox_check_cron_files() — journal guard (2026-10) ━━━"

    local journal="$MOCK_ROOT/journal.fixture" args="$MOCK_ROOT/journalctl.args"
    : > "$journal"; : > "$args"
    journalctl() {
        local a prev="" since="" unit=""
        for a in "$@"; do
            [[ "$prev" == "--since" ]] && since="${a#@}"
            [[ "$prev" == "-u" ]] && unit="$a"
            prev="$a"
        done
        printf '%s\n' "$*" >> "$MOCK_ROOT/journalctl.args"
        [[ "$unit" == "cron" ]] || return 0
        local ts msg
        while IFS='|' read -r ts msg; do
            [[ -n "$ts" ]] || continue
            if [[ -z "$since" ]] || (( ts >= since )); then printf '%s\n' "$msg"; fi
        done < "$MOCK_ROOT/journal.fixture"
    }

    rm -f "$LOXPROX_ALERT_CRON_FILE"
    _loxprox_write_security_cron
    local mtime=1790000000
    touch -d "@$mtime" "$LOXPROX_CRON_FILE"

    # (a) clean journal → pass
    _loxprox_check_cron_files >/dev/null 2>&1 && pass "clean file + clean journal → check passes" || fail "clean state reported as failing"
    grep -q -- "--since @$mtime" "$args" && pass "journal queried with --since @<file mtime>" || fail "journal not scoped to the file mtime: $(cat "$args")"

    # (b) an error about the PREVIOUS content (before the rewrite) is ignored
    printf '%s\n' \
        "$((mtime - 120))|Error: bad minute; while reading /etc/cron.d/loxprox" \
        "$((mtime - 120))|(*system*loxprox) ERROR (Syntax error, this crontab file will be ignored)" > "$journal"
    _loxprox_check_cron_files >/dev/null 2>&1 && pass "error logged before the file was rewritten is ignored" || fail "stale pre-mtime error fails a fixed file"

    # (c) an error AFTER the rewrite fails the check, and is reported
    printf '%s\n' "$((mtime + 30))|(*system*loxprox) ERROR (Syntax error, this crontab file will be ignored)" >> "$journal"
    local out
    if out=$(_loxprox_check_cron_files 2>&1); then
        fail "cron rejection after the rewrite NOT detected"
    else
        pass "cron rejection logged after the rewrite fails the check"
        grep -q 'Syntax error' <<<"$out" && pass "the failure quotes cron's own message" || fail "failure message does not quote cron"
    fi
    printf '%s\n' "$((mtime + 30))|Error: bad minute; while reading /etc/cron.d/loxprox" > "$journal"
    _loxprox_check_cron_files >/dev/null 2>&1 && fail "'while reading' form not detected" || pass "'Error: bad minute; while reading …' form detected"

    # (d) another file's rejection must not be attributed to loxprox
    printf '%s\n' \
        "$((mtime + 30))|(*system*loxprox-alert) ERROR (Syntax error, this crontab file will be ignored)" \
        "$((mtime + 30))|Error: bad minute; while reading /etc/cron.d/loxprox-alert" > "$journal"
    _loxprox_check_cron_files >/dev/null 2>&1 && pass "loxprox-alert's errors are not attributed to loxprox (alert file absent)" || fail "name match is not exact"

    # (e) …but they count once that file exists (mtime before the error)
    printf '%s\n' '*/15 * * * * root true' > "$LOXPROX_ALERT_CRON_FILE"
    touch -d "@$mtime" "$LOXPROX_ALERT_CRON_FILE"
    _loxprox_check_cron_files >/dev/null 2>&1 && fail "loxprox-alert rejection not detected" || pass "loxprox-alert rejection detected for its own file"
    rm -f "$LOXPROX_ALERT_CRON_FILE"

    # (f) a malformed file fails even before cron got to it (static lint)
    : > "$journal"
    printf '%s\n' 'MAILTO=' '*/15 * * * * root true' > "$LOXPROX_CRON_FILE"
    _loxprox_check_cron_files >/dev/null 2>&1 && fail "bare MAILTO= passed the health check" || pass "bare MAILTO= fails the health check before cron re-reads"

    # (g) missing file fails
    rm -f "$LOXPROX_CRON_FILE"
    _loxprox_check_cron_files >/dev/null 2>&1 && fail "missing cron file passed" || pass "missing cron file fails the health check"

    # health_check wires it in
    grep -qE '^[[:space:]]*_loxprox_check_cron_files \|\| failures=' "$PROJECT_DIR/deploy.sh" \
        && pass "health_check counts a cron failure" || fail "health_check does not call _loxprox_check_cron_files"

    unset -f journalctl
    _loxprox_write_security_cron
}

# Fix 3: LoxProx logs rotated; the stock nginx catch-all yields.
test_logrotate_loxprox() {
    echo ""
    echo "━━━ setup_logrotate() — /var/log/loxprox-*.log + stock nginx yield (2026-10) ━━━"

    local stock="$NGINX_STOCK_LOGROTATE"
    # Debian 12 nginx-common's /etc/logrotate.d/nginx, verbatim shape.
    cat > "$stock" <<'EOF'
/var/log/nginx/*.log {
	daily
	missingok
	rotate 14
	compress
	delaycompress
	notifempty
	create 0640 www-data adm
	sharedscripts
	prerotate
		if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
			run-parts /etc/logrotate.d/httpd-prerotate; \
		fi \
	endscript
	postrotate
		invoke-rc.d nginx rotate >/dev/null 2>&1
	endscript
}
EOF
    local inode_before inode_after
    inode_before=$(stat -c %i "$stock")
    rm -rf "$BACKUP_DIR/files$stock"

    setup_logrotate >/dev/null 2>&1

    local lr="$LOXPROX_LOGROTATE_CONF"
    [[ -f "$lr" ]] && pass "LoxProx logrotate file written" || fail "LoxProx logrotate file missing"
    grep -qx '/var/log/loxprox-\*\.log {' "$lr" && pass "covers /var/log/loxprox-*.log" || fail "glob /var/log/loxprox-*.log missing"
    local d
    for d in copytruncate missingok notifempty compress weekly 'maxsize 10M' 'rotate 8'; do
        grep -qE "^[[:space:]]+${d}\$" "$lr" && pass "directive: $d" || fail "directive missing: $d"
    done
    grep -qE '^[[:space:]]+create' "$lr" && fail "create used together with copytruncate" || pass "no create (copytruncate keeps the writer's fd valid)"

    head -1 "$stock" | grep -qx '/var/log/nginx/access.log /var/log/nginx/error.log {' \
        && pass "stock nginx stanza narrowed to access.log + error.log" || fail "stock nginx glob not narrowed: $(head -1 "$stock")"
    grep -q 'invoke-rc.d nginx rotate' "$stock" && pass "rest of the stock stanza untouched" || fail "stock stanza body damaged"
    inode_after=$(stat -c %i "$stock")
    [[ "$inode_before" == "$inode_after" ]] && pass "stock conffile rewritten in place (inode kept)" || fail "stock conffile replaced (inode changed)"
    [[ -f "$BACKUP_DIR/files$stock" ]] && grep -q '^/var/log/nginx/\*\.log' "$BACKUP_DIR/files$stock" \
        && pass "original stock file backed up under BACKUP_DIR" || fail "original stock file not backed up"
    local extra
    extra=$(find "$(dirname "$stock")" -type f ! -name nginx ! -name loxprox ! -name loxone-nginx)
    [[ -z "$extra" ]] && pass "no scratch/backup files left in the logrotate.d dir" || fail "stray files in logrotate.d (logrotate parses them all): $extra"

    local before after
    before=$(sha256sum "$stock" "$lr" | awk '{print $1}')
    setup_logrotate >/dev/null 2>&1
    after=$(sha256sum "$stock" "$lr" | awk '{print $1}')
    [[ "$before" == "$after" ]] && pass "re-run is idempotent" || fail "re-run changed the logrotate files"

    # An operator-edited stock file (no catch-all glob) is left alone.
    printf '%s\n' '/var/log/nginx/access.log {' '    weekly' '}' > "$stock"
    before=$(sha256sum "$stock" | awk '{print $1}')
    setup_logrotate >/dev/null 2>&1
    after=$(sha256sum "$stock" | awk '{print $1}')
    [[ "$before" == "$after" ]] && pass "non-stock nginx stanza left untouched" || fail "non-stock nginx stanza was rewritten"

    rm -f "$stock"
    setup_logrotate >/dev/null 2>&1 && pass "absent stock nginx file is fine" || fail "setup_logrotate failed without a stock nginx file"
}

# Fix 4: journald drop-in, restart only on change, failure surfaces.
test_setup_journald() {
    echo ""
    echo "━━━ setup_journald() (2026-10) ━━━"

    local calls="$MOCK_ROOT/systemctl.calls"
    : > "$calls"
    systemctl() { printf '%s\n' "$*" >> "$MOCK_ROOT/systemctl.calls"; return "${MOCK_SYSTEMCTL_RC:-0}"; }

    rm -f "$JOURNALD_DROPIN"
    setup_journald >/dev/null 2>&1 && pass "first run returns 0" || fail "first run failed"
    [[ -f "$JOURNALD_DROPIN" ]] && pass "drop-in written" || fail "drop-in missing"
    grep -qx '\[Journal\]' "$JOURNALD_DROPIN" && pass "[Journal] section" || fail "[Journal] section missing"
    grep -qx 'SystemMaxUse=300M' "$JOURNALD_DROPIN" && pass "SystemMaxUse=300M" || fail "SystemMaxUse=300M missing"
    [[ "$(grep -c 'restart systemd-journald' "$calls")" -eq 1 ]] && pass "journald restarted once" || fail "journald restart count: $(cat "$calls")"

    : > "$calls"
    setup_journald >/dev/null 2>&1
    grep -q 'restart' "$calls" && fail "unchanged drop-in restarted journald again" || pass "unchanged drop-in → no restart"

    printf '[Journal]\nSystemMaxUse=2G\n' > "$JOURNALD_DROPIN"
    : > "$calls"
    setup_journald >/dev/null 2>&1
    grep -qx 'SystemMaxUse=300M' "$JOURNALD_DROPIN" && grep -q 'restart systemd-journald' "$calls" \
        && pass "drifted drop-in rewritten + journald restarted" || fail "drifted drop-in not corrected"

    rm -f "$JOURNALD_DROPIN"
    MOCK_SYSTEMCTL_RC=1 setup_journald >/dev/null 2>&1 && fail "failed journald restart reported success" || pass "failed journald restart returns non-zero (degraded step)"

    systemctl() { true; }
}

# Fix 7: audit watches for /etc/loxprox, /etc/apparmor.d, /opt/loxprox.
test_setup_auditd() {
    echo ""
    echo "━━━ setup_auditd() — LoxProx watches (2026-10) ━━━"

    augenrules() { true; }
    service() { true; }
    setup_auditd >/dev/null 2>&1

    local rf="$AUDIT_RULES_FILE"
    [[ -f "$rf" ]] && pass "rules file written" || fail "rules file missing"
    grep -qE '^-w /etc/loxprox/ +-p wa -k loxprox_config$' "$rf"   && pass "watch /etc/loxprox (loxprox_config)"    || fail "/etc/loxprox watch missing"
    grep -qE '^-w /etc/apparmor.d/ +-p wa -k apparmor_config$' "$rf" && pass "watch /etc/apparmor.d (apparmor_config)" || fail "/etc/apparmor.d watch missing"
    grep -qE '^-w /opt/loxprox/ +-p wa -k loxprox_scripts$' "$rf"   && pass "watch /opt/loxprox (loxprox_scripts)"   || fail "/opt/loxprox watch missing"
    grep -qE '^-w /etc/nginx/ +-p wa -k nginx_config$' "$rf" && pass "existing watches kept" || fail "existing nginx watch lost"
    local bad
    bad=$(grep -vE '^(#|$)' "$rf" | grep -vE '^-w /[^ ]+ +-p [rwxa]+ +-k [a-z_]+$' || true)
    [[ -z "$bad" ]] && pass "every rule is a well-formed '-w PATH -p PERMS -k key' line" || fail "malformed audit rule(s): $bad"
    local dupes
    dupes=$(grep -E '^-w ' "$rf" | awk '{print $2}' | sort | uniq -d)
    [[ -z "$dupes" ]] && pass "no path watched twice" || fail "duplicate watches: $dupes"

    unset -f augenrules service
}

# Fix 2: persisted deploy source under LOXPROX_DEPLOY_DIR.
test_install_deploy_source() {
    echo ""
    echo "━━━ install_deploy_source() — panel apply/renew path (2026-10) ━━━"

    local dest="$LOXPROX_DEPLOY_DIR" parent
    parent=$(dirname "$dest")
    rm -rf "$dest"
    mkdir -p "$parent"; chmod 0755 "$parent"   # independent of the runner's umask
    local saved_sh="$LOXPROX_DEPLOY_SH" saved_dir="$SCRIPT_DIR"

    install_deploy_source >/dev/null 2>&1 && pass "install returns 0 from the repo tree" || fail "install failed from the repo tree"
    [[ "$LOXPROX_DEPLOY_SH" == "$dest/deploy.sh" ]] && pass "LOXPROX_DEPLOY_SH now points at the persisted copy" || fail "LOXPROX_DEPLOY_SH not repointed: $LOXPROX_DEPLOY_SH"

    local rel missing=""
    for rel in "${_LOXPROX_DEPLOY_SOURCE_FILES[@]}"; do
        cmp -s "$PROJECT_DIR/$rel" "$dest/$rel" || missing+=" $rel"
    done
    for rel in "${_LOXPROX_DEPLOY_SOURCE_DIRS[@]}"; do
        diff -r "$PROJECT_DIR/$rel" "$dest/$rel" >/dev/null 2>&1 || missing+=" $rel/"
    done
    [[ -z "$missing" ]] && pass "manifest copied byte-identical" || fail "missing/different in copy:$missing"
    grep -q '^version=' "$dest/VERSION" && pass "VERSION written into the copy ($(head -1 "$dest/VERSION"))" || fail "VERSION missing from the copy"
    [[ "$(stat -c %a "$dest")" == "750" ]] && pass "copy root dir is 0750" || fail "copy root dir mode $(stat -c %a "$dest")"
    local loose
    loose=$(find "$dest" -perm /o=rwx -print -quit)
    [[ -z "$loose" ]] && pass "nothing in the copy is accessible to 'other'" || fail "world-accessible path in copy: $loose"
    [[ -z "$(find "$parent" -maxdepth 1 -name ".$(basename "$dest").*")" ]] && pass "no staging/old dirs left behind" || fail "staging leftovers in $parent"

    write_runtime_config >/dev/null 2>&1
    grep -qx "LOXPROX_DEPLOY_SH=\"$dest/deploy.sh\"" "$GATEWAY_CONFIG_FILE" \
        && pass "config.env records the persisted deploy.sh" || fail "config.env: $(grep LOXPROX_DEPLOY_SH "$GATEWAY_CONFIG_FILE")"

    # The copy is self-contained: SCRIPT_DIR resolves to it and every path
    # deploy.sh reads relative to SCRIPT_DIR exists there.
    local out rc
    out=$(bash "$dest/deploy.sh" --help 2>&1); rc=$?
    [[ $rc -eq 0 ]] && pass "persisted deploy.sh runs (--help exits 0)" || fail "persisted deploy.sh --help exited $rc"
    local copy_script_dir
    copy_script_dir=$( (source "$dest/deploy.sh" >/dev/null 2>&1; printf '%s' "$SCRIPT_DIR") )
    [[ "$copy_script_dir" -ef "$dest" ]] && pass "SCRIPT_DIR resolves to the copy when run from it" || fail "SCRIPT_DIR from copy: $copy_script_dir"
    local ref absent=""
    while read -r ref; do
        [[ "$ref" == VERSION ]] && continue
        [[ -e "$dest/$ref" ]] || absent+=" $ref"
    done < <(grep -oE '(\$\{SCRIPT_DIR:-\.\}|\$src_dir)/[A-Za-z0-9_./-]+' "$PROJECT_DIR/deploy.sh" | sed -E 's#^[^/]+/##' | sort -u)
    [[ -z "$absent" ]] && pass "every SCRIPT_DIR-relative path deploy.sh reads exists in the copy" || fail "absent from copy:$absent"

    # Re-run FROM the copy (the panel's apply): no rewrite of the running tree.
    local inode_before inode_after
    inode_before=$(stat -c %i "$dest")
    out=$( (source "$dest/deploy.sh" >/dev/null 2>&1; set +e
            LOXPROX_DEPLOY_DIR="$dest"; LOG_FILE="$MOCK_ROOT/var/log/loxprox-deploy.log"
            install_deploy_source >/dev/null 2>&1; printf '%s|%s' "$?" "$LOXPROX_DEPLOY_SH") )
    inode_after=$(stat -c %i "$dest")
    [[ "$out" == "0|$dest/deploy.sh" ]] && pass "re-run from the copy returns 0 and keeps the path" || fail "re-run from copy: $out"
    [[ "$inode_before" == "$inode_after" ]] && pass "re-run from the copy leaves the tree in place" || fail "re-run from the copy swapped the tree it runs from"

    # A fresh deploy replaces a stale copy by rename: stale files vanish, and a
    # reader holding the old deploy.sh open keeps reading the complete old file.
    echo "stale" > "$dest/stale-from-old-version.txt"
    printf '\n# old-copy-marker\n' >> "$dest/deploy.sh"
    local old_sum
    old_sum=$(sha256sum "$dest/deploy.sh" | awk '{print $1}')
    exec 9<"$dest/deploy.sh"
    install_deploy_source >/dev/null 2>&1 && pass "re-install over an existing copy returns 0" || fail "re-install failed"
    [[ ! -e "$dest/stale-from-old-version.txt" ]] && pass "stale file from the previous copy is gone" || fail "stale file survived"
    cmp -s "$PROJECT_DIR/deploy.sh" "$dest/deploy.sh" && pass "deploy.sh replaced with the current source" || fail "deploy.sh not refreshed"
    [[ "$(sha256sum <&9 | awk '{print $1}')" == "$old_sum" ]] && pass "an fd open on the old deploy.sh still reads it intact (swap, not overwrite)" || fail "old deploy.sh was modified in place"
    exec 9<&-

    # Failure paths: an incomplete tree, an unsafe parent, an unreadable file —
    # each must leave the previous copy and config.env's path untouched.
    local tree_sum tree_sum_after
    tree_sum=$(cd "$dest" && find . -type f -exec sha256sum {} + | sort | sha256sum)
    local src="$MOCK_ROOT/src-incomplete"
    rm -rf "$src"; mkdir -p "$src"
    cp -R "$PROJECT_DIR/." "$src/" 2>/dev/null
    rm -f "$src/apparmor/usr.sbin.nginx"
    SCRIPT_DIR="$src"; LOXPROX_DEPLOY_SH="$src/deploy.sh"
    install_deploy_source >/dev/null 2>&1 && fail "incomplete source tree accepted" || pass "incomplete source tree refused"
    [[ "$LOXPROX_DEPLOY_SH" == "$src/deploy.sh" ]] && pass "refusal keeps the fallback LOXPROX_DEPLOY_SH" || fail "refusal changed LOXPROX_DEPLOY_SH"
    tree_sum_after=$(cd "$dest" && find . -type f -exec sha256sum {} + | sort | sha256sum)
    [[ "$tree_sum" == "$tree_sum_after" ]] && pass "previous copy untouched after the refusal" || fail "previous copy modified by a refused install"

    cp "$PROJECT_DIR/apparmor/usr.sbin.nginx" "$src/apparmor/usr.sbin.nginx"
    chmod 0777 "$parent"
    install_deploy_source >/dev/null 2>&1 && fail "group/world-writable parent accepted" || pass "group/world-writable parent refused"
    chmod 0755 "$parent"

    if [[ $EUID -ne 0 ]]; then
        chmod 000 "$src/progressive-ban.py"
        install_deploy_source >/dev/null 2>&1 && fail "unreadable source file accepted" || pass "copy failure mid-way refused"
        chmod 0644 "$src/progressive-ban.py"
        tree_sum_after=$(cd "$dest" && find . -type f -exec sha256sum {} + | sort | sha256sum)
        [[ "$tree_sum" == "$tree_sum_after" ]] && pass "previous copy untouched after a failed copy" || fail "failed copy damaged the previous copy"
        [[ -z "$(find "$parent" -maxdepth 1 -name ".$(basename "$dest").*")" ]] && pass "failed copy cleaned its staging dir" || fail "staging dir left after a failed copy"
    else
        pass "(running as root — unreadable-file case not reproducible, skipped)"
    fi

    SCRIPT_DIR="$saved_dir"; LOXPROX_DEPLOY_SH="$saved_sh"
    rm -rf "$src"

    # The SOFT-SSH login nag points at the persisted copy, not a path that
    # never existed (/opt/loxprox/deploy.sh).
    grep -q 'sudo bash /opt/loxprox/deploy/deploy.sh --finalize-ssh' "$PROJECT_DIR/deploy.sh" \
        && pass "SSH MOTD nag names /opt/loxprox/deploy/deploy.sh" || fail "SSH MOTD nag path stale"
    grep -qE '^[[:space:]]*run_optional_step "persistent deploy source"[[:space:]]+install_deploy_source$' "$PROJECT_DIR/deploy.sh" \
        && pass "main() runs install_deploy_source" || fail "install_deploy_source not wired into main()"
}

# Fix 5: an existing v3 site — including a TLS one, as in production — is
# regenerated to v4 and keeps its TLS block.
test_site_template_v3_upgrade() {
    echo ""
    echo "━━━ configure_nginx() — v3 → v4 regeneration keeps TLS (2026-10) ━━━"

    local backup_path="$BACKUP_DIR/files$NGINX_SITE"
    rm -f "$NGINX_SITE" "$backup_path"
    configure_nginx >/dev/null 2>&1
    _loxprox_site_enable_tls >/dev/null 2>&1
    # Turn it into what a v3 install has on disk: same params, older stamp, no hides.
    sed -i -e 's/^# LOXPROX-SITE-TEMPLATE-VERSION: 4$/# LOXPROX-SITE-TEMPLATE-VERSION: 3/' \
           -e '/proxy_hide_header \(X-Frame-Options\|X-Content-Type-Options\|Referrer-Policy\|Content-Security-Policy\|Permissions-Policy\|Strict-Transport-Security\|X-XSS-Protection\);/d' "$NGINX_SITE"
    rm -f "$backup_path"
    grep -q 'proxy_hide_header X-Frame-Options' "$NGINX_SITE" && fail "fixture still has the v4 hides" || pass "fixture is a v3 TLS site"

    configure_nginx >/dev/null 2>&1
    grep -q '^# LOXPROX-SITE-TEMPLATE-VERSION: 4$' "$NGINX_SITE" && pass "v3 site regenerated to v4" || fail "v3 site not regenerated"
    grep -q 'proxy_hide_header X-Frame-Options;' "$NGINX_SITE" && pass "regenerated site hides the upstream X-Frame-Options" || fail "hides missing after regeneration"
    grep -q '^[[:space:]]*listen 1080 ssl;' "$NGINX_SITE" && grep -q '# LOXPROX-TLS-BEGIN' "$NGINX_SITE" \
        && pass "TLS block re-applied after regeneration" || fail "regeneration dropped the TLS listener"
    [[ -f "$backup_path" ]] && grep -q 'TEMPLATE-VERSION: 3' "$backup_path" && pass "v3 site backed up first" || fail "v3 site not backed up"
    rm -f "$NGINX_SITE" "$backup_path"
}

# ── Cleanup ──────────────────────────────────────────────────────────────────

cleanup() {
    rm -rf "$MOCK_ROOT"
}

trap cleanup EXIT

# ── Main ─────────────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  LoxProx — deploy.sh Portable Unit Tests"
echo "═══════════════════════════════════════════════════════════════════════════════"

test_validate_ip
test_validate_network
test_apply_sysctls
test_gpg_verifier
test_setup_firewall
test_configure_nginx
test_configure_crowdsec
test_setup_logrotate
test_write_runtime_config
test_rollback_validation
test_crowdsec_install_no_curl_pipe

# v1.5.0 — config separation
test_load_config_sources_values
test_detect_live_install
test_extract_config_from_live_state
test_configure_nginx_preserves_existing_site

# v1.5.0 — optional TLS
test_tls_validate_config
test_tls_site_mutation_round_trip
test_tls_enable_refuses_noncanonical_listen
test_tls_acme_listener_written

# v2.0 — optional tunnel + resilience
test_tunnel_validate_config
test_tunnel_frpc_config_generation
test_tunnel_frpc_unit_hardening
test_tunnel_realip_conf
test_nginx_ws_location
test_acme_fallback_ca

# v2.1 — LoxProx Panel + CLI surface
test_gui_setup
test_gui_firewall_rule
test_cli_help_and_unknown_flag
test_restore_refuses_missing_archive

# 2026-10 health-audit fixes
test_cron_file_generation
test_cron_health_check
test_logrotate_loxprox
test_setup_journald
test_setup_auditd
test_install_deploy_source
test_site_template_v3_upgrade

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

[[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
