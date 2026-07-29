#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Portable Unit Tests for install-relay.sh SSH hardening + firewall
# ═══════════════════════════════════════════════════════════════════════════════
# Covers CRIT C1 (relay SSH was world-open + unhardened) and the optional
# RELAY_SSH_ALLOWED_SUBNETS source narrowing. Mock-based, no root, no network.
# Run: bash tests/test_relay_ssh.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
TESTS_PASSED=0
TESTS_FAILED=0
# NB: $((x+1)), not ((x++)) — the post-increment returns exit 1 when x is 0
# under `set -e`-adjacent contexts, exactly the footgun this suite guards against.
pass() { echo -e "  ${GREEN}✓${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
MOCK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/loxprox-relay-test.XXXXXXXX")"
trap 'rm -rf "$MOCK_ROOT"' EXIT

# Redirect every file the SSH/firewall code touches into the mock root, before
# sourcing (the script reads these via ${VAR:-default} at load time).
export LOG_FILE="$MOCK_ROOT/relay-install.log"
export BACKUP_DIR="$MOCK_ROOT/backup"
export NFTABLES_CONF="$MOCK_ROOT/etc/nftables.conf"
export RELAY_SSHD_DROP="$MOCK_ROOT/etc/ssh/sshd_config.d/99-loxprox-relay.conf"
export RELAY_STATE_DIR="$MOCK_ROOT/var/lib/loxprox-relay"
export RELAY_SSH_MOTD="$MOCK_ROOT/etc/update-motd.d/99-loxprox-relay-ssh-warn"
export FRP_BIND_PORT="7000"
export TUNNEL_REMOTE_PORT="8443"
mkdir -p "$MOCK_ROOT/etc"

# Mock system-mutating commands so nothing touches the host.
systemctl() { return 0; }
sshd()      { return 0; }   # `sshd -t` always validates in tests
export -f systemctl sshd

# shellcheck source=../tunnel-relay/install-relay.sh
source "$PROJECT_DIR/tunnel-relay/install-relay.sh"
set +e                       # the script enables `set -e`; assertions must not abort
log() { :; }                 # silence banner/info/warn/ok/error (all route through log)

# ── SSH drop-in writers ──────────────────────────────────────────────────────

test_hard_drop_in() {
    echo ""; echo "━━━ HARD drop-in (key-only) ━━━"
    rm -f "$RELAY_SSHD_DROP"
    _relay_write_hard_ssh_drop_in
    [[ -f "$RELAY_SSHD_DROP" ]] && pass "hard drop-in written" || fail "hard drop-in missing"
    grep -q '^PasswordAuthentication no' "$RELAY_SSHD_DROP" && pass "password auth disabled" || fail "password auth not disabled"
    grep -q '^PermitRootLogin prohibit-password' "$RELAY_SSHD_DROP" && pass "root login key-only" || fail "root login not restricted"
    grep -q '^MaxAuthTries 4' "$RELAY_SSHD_DROP" && pass "MaxAuthTries 4" || fail "MaxAuthTries missing"
}

test_soft_drop_in() {
    echo ""; echo "━━━ SOFT drop-in (no-lockout fallback) ━━━"
    rm -f "$RELAY_SSHD_DROP"; rm -f "$RELAY_STATE_DIR/ssh-keys-missing"
    _relay_write_soft_ssh_drop_in
    grep -q '^PasswordAuthentication yes' "$RELAY_SSHD_DROP" && pass "password auth kept (no lockout)" || fail "password auth not kept"
    grep -q '^MaxAuthTries 4' "$RELAY_SSHD_DROP" && pass "still sets MaxAuthTries 4" || fail "MaxAuthTries missing"
    [[ -f "$RELAY_STATE_DIR/ssh-keys-missing" ]] && pass "keys-missing marker created" || fail "keys-missing marker not created"
}

# ── setup_ssh_hardening mode selection (key-detection mocked) ─────────────────

test_hardening_picks_soft_without_key() {
    echo ""; echo "━━━ setup_ssh_hardening → SOFT when no key ━━━"
    _relay_has_authorized_key() { return 1; }
    rm -f "$RELAY_SSHD_DROP" "$RELAY_STATE_DIR/ssh-keys-missing" "$RELAY_SSH_MOTD"
    setup_ssh_hardening >/dev/null 2>&1
    grep -q '^PasswordAuthentication yes' "$RELAY_SSHD_DROP" && pass "keyless host → SOFT profile" || fail "keyless host did not get SOFT"
    [[ -f "$RELAY_SSH_MOTD" ]] && pass "login nag installed" || fail "login nag missing"
}

test_hardening_picks_hard_with_key() {
    echo ""; echo "━━━ setup_ssh_hardening → HARD when key present ━━━"
    _relay_has_authorized_key() { return 0; }
    rm -f "$RELAY_SSHD_DROP"; touch "$RELAY_SSH_MOTD"
    setup_ssh_hardening >/dev/null 2>&1
    grep -q '^PasswordAuthentication no' "$RELAY_SSHD_DROP" && pass "keyed host → HARD profile" || fail "keyed host did not get HARD"
    [[ ! -f "$RELAY_SSH_MOTD" ]] && pass "login nag removed" || fail "login nag not removed"
}

# ── firewall SSH source rule ─────────────────────────────────────────────────

test_firewall_open_by_default() {
    echo ""; echo "━━━ firewall SSH rule — open when list empty ━━━"
    # shellcheck disable=SC2034  # consumed by setup_firewall in the sourced script
    RELAY_SSH_ALLOWED_SUBNETS=()
    setup_firewall >/dev/null 2>&1
    grep -qE '^\s*tcp dport 22 accept' "$NFTABLES_CONF" && pass "empty list → open :22 (sshd still key-only)" || fail "expected open :22 rule"
    grep -q 'ip saddr {' "$NFTABLES_CONF" && fail "unexpected source set with empty list" || pass "no source set when list empty"
}

test_firewall_narrowed_when_set() {
    echo ""; echo "━━━ firewall SSH rule — narrowed to allow-list ━━━"
    # shellcheck disable=SC2034  # consumed by setup_firewall in the sourced script
    RELAY_SSH_ALLOWED_SUBNETS=("203.0.113.5/32" "198.51.100.0/24")
    setup_firewall >/dev/null 2>&1
    grep -q 'tcp dport 22 ip saddr {' "$NFTABLES_CONF" && pass "source-restricted :22 rule emitted" || fail "no source-restricted :22 rule"
    grep -q '203.0.113.5/32' "$NFTABLES_CONF" && pass "first admin range present" || fail "first admin range missing"
    grep -q '198.51.100.0/24' "$NFTABLES_CONF" && pass "second admin range present" || fail "second admin range missing"
    grep -qE '^\s*tcp dport 22 accept\s*$' "$NFTABLES_CONF" && fail "open rule leaked alongside allow-list" || pass "no open rule when narrowed"
}

echo "═══ install-relay.sh SSH hardening + firewall ═══"
test_hard_drop_in
test_soft_drop_in
test_hardening_picks_soft_without_key
test_hardening_picks_hard_with_key
test_firewall_open_by_default
test_firewall_narrowed_when_set

echo ""
echo "─────────────────────────────────────────────"
echo -e "  Passed: ${GREEN}${TESTS_PASSED}${NC}   Failed: ${RED}${TESTS_FAILED}${NC}"
[[ "$TESTS_FAILED" -eq 0 ]]
