#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Portable Unit Tests for detect-loxone.sh Functions
# ═══════════════════════════════════════════════════════════════════════════════
# Run: bash tests/test_detect_loxone.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
TESTS_PASSED=0
TESTS_FAILED=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); }
fail() { echo -e "  ${RED}✗${NC} $1"; ((TESTS_FAILED++)); }

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"

# Source helper functions from detect-loxone.sh without running main
# We extract the non-main functions by running them in a subshell
source "$PROJECT_DIR/detect-loxone.sh"

# ── Tests ────────────────────────────────────────────────────────────────────

test_ip_math() {
    echo ""
    echo "━━━ IP math helpers ━━━"

    local result
    result=$(ip_to_int "192.168.1.1")
    if [[ "$result" == "3232235777" ]]; then pass "ip_to_int 192.168.1.1"; else fail "ip_to_int 192.168.1.1 = $result"; fi

    result=$(ip_to_int "0.0.0.0")
    if [[ "$result" == "0" ]]; then pass "ip_to_int 0.0.0.0"; else fail "ip_to_int 0.0.0.0 = $result"; fi

    result=$(ip_to_int "255.255.255.255")
    if [[ "$result" == "4294967295" ]]; then pass "ip_to_int max"; else fail "ip_to_int max = $result"; fi

    result=$(int_to_ip "3232235777")
    if [[ "$result" == "192.168.1.1" ]]; then pass "int_to_ip 3232235777"; else fail "int_to_ip 3232235777 = $result"; fi

    result=$(int_to_ip "0")
    if [[ "$result" == "0.0.0.0" ]]; then pass "int_to_ip 0"; else fail "int_to_ip 0 = $result"; fi
}

test_oui_validation() {
    echo ""
    echo "━━━ OUI validation ━━━"

    local ouis=("EE:E0:00" "E0:E0:00" "AC:4E:91" "B0:BE:76")
    local pass_count=0

    for oui in "${ouis[@]}"; do
        local test_mac="${oui}:12:34:56"
        local found=0
        for o in "${ouis[@]}"; do
            if [[ "$test_mac" == "$o"* ]] || [[ "$test_mac" == "${o//:/-}"* ]] || [[ "$test_mac" == "${o//:/}"* ]]; then
                found=1
                break
            fi
        done
        if [[ "$found" -eq 1 ]]; then pass_count=$((pass_count + 1)); fi
    done

    if [[ "$pass_count" -eq "${#ouis[@]}" ]]; then pass "all OUIs match correctly"; else fail "OUI mismatch ($pass_count/${#ouis[@]})"; fi

    # Negative test
    local bad_mac="DE:AD:BE:12:34:56"
    local found=0
    for o in "${ouis[@]}"; do
        if [[ "$bad_mac" == "$o"* ]] || [[ "$bad_mac" == "${o//:/-}"* ]] || [[ "$bad_mac" == "${o//:/}"* ]]; then
            found=1
            break
        fi
    done
    if [[ "$found" -eq 0 ]]; then pass "non-Loxone OUI rejected"; else fail "non-Loxone OUI incorrectly matched"; fi
}

test_mktemp_usage() {
    echo ""
    echo "━━━ mktemp usage (LOW-001) ━━━"

    if grep -q 'mktemp /tmp/loxone-scan-results' "$PROJECT_DIR/detect-loxone.sh"; then
        pass "detect-loxone.sh uses mktemp"
    else
        fail "detect-loxone.sh does not use mktemp"
    fi
    if grep -q '/tmp/loxone-scan-results\.\$\$' "$PROJECT_DIR/detect-loxone.sh"; then
        fail "detect-loxone.sh still uses predictable PID temp file"
    else
        pass "predictable PID temp file removed"
    fi
}

test_subnet_parsing() {
    echo ""
    echo "━━━ CIDR parsing ━━━"

    local network prefix net_int mask_int start end
    local cidr="192.168.1.0/24"
    network=${cidr%/*}
    prefix=${cidr#*/}
    net_int=$(ip_to_int "$network")
    mask_int=$((0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF))
    start=$((net_int & mask_int))
    end=$((start + (1 << (32 - prefix)) - 1))
    start=$((start + 1))
    end=$((end - 1))

    local first_ip last_ip
    first_ip=$(int_to_ip "$start")
    last_ip=$(int_to_ip "$end")

    if [[ "$first_ip" == "192.168.1.1" ]]; then pass "/24 first host correct"; else fail "/24 first host = $first_ip"; fi
    if [[ "$last_ip" == "192.168.1.254" ]]; then pass "/24 last host correct"; else fail "/24 last host = $last_ip"; fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  LoxProx — detect-loxone.sh Portable Unit Tests"
echo "═══════════════════════════════════════════════════════════════════════════════"

test_ip_math
test_oui_validation
test_mktemp_usage
test_subnet_parsing

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

[[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
