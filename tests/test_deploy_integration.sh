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

mkdir -p "$MOCK_ROOT"/{etc/nginx/sites-available,etc/nginx/sites-enabled,etc/nginx/conf.d,etc/crowdsec/acquis.d,etc/crowdsec/parsers/s02-enrich,etc/sysctl.d,etc/logrotate.d,etc/loxprox,var/log,root}

# Mock system commands
systemctl() { true; }
apt-get() { true; }
dpkg() { true; }
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
export -f systemctl apt-get dpkg hostname ip

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
    if grep -q "X-XSS-Protection" "$NGINX_SITE"; then fail "X-XSS-Protection still present (should be removed)"; else pass "X-XSS-Protection correctly removed"; fi

    # LOW-007: proxy_hide_header
    if grep -q "proxy_hide_header Server" "$NGINX_SITE"; then pass "proxy_hide_header Server present"; else fail "proxy_hide_header Server missing"; fi
    if grep -q "proxy_hide_header X-Powered-By" "$NGINX_SITE"; then pass "proxy_hide_header X-Powered-By present"; else fail "proxy_hide_header X-Powered-By missing"; fi

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
    echo "━━━ configure_nginx() preserves existing site ━━━"

    mkdir -p "$(dirname "$NGINX_SITE")"
    local sentinel='# OPERATOR-EDITED-SENTINEL-DO-NOT-REMOVE'
    cat > "$NGINX_SITE" <<EOF
$sentinel
server {
    listen 1080;
    location /ws/ {
        # custom WebSocket block — hand-edited, must survive deploy
        proxy_pass http://loxone_backend;
    }
}
EOF

    configure_nginx >/dev/null 2>&1

    grep -q "$sentinel" "$NGINX_SITE"             && pass "operator sentinel preserved"        || fail "operator sentinel was nuked"
    grep -q "custom WebSocket block" "$NGINX_SITE" && pass "WebSocket block preserved"          || fail "WebSocket block was nuked"
    # v1.5.0 final shape: NO conf.d split — map + log_format stay inline in
    # the site config (nginx -t rejects the split because `auth_request_set`
    # registers $appsec_action at parse time, and the variable must be
    # registered before any `if=$var` access_log reference). The conf.d file
    # must be cleaned up if it lingered from an earlier dev iteration.
    [[ ! -f "$NGINX_APPSEC_AUDIT_CONF" ]] && pass "conf.d/loxprox-appsec.conf is NOT written" \
                                          || fail "conf.d/loxprox-appsec.conf should not exist"

    # Force regen: should now overwrite (sentinel disappears, fresh template
    # carries map + log_format + access_log inline)
    LOXPROX_FORCE_REGEN_NGINX=1 configure_nginx >/dev/null 2>&1
    grep -q "$sentinel" "$NGINX_SITE" && fail "sentinel survived FORCE_REGEN (should have been overwritten)" \
                                      || pass "FORCE_REGEN regenerates from template"
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

    rm -f "$NGINX_SITE"
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

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

[[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
