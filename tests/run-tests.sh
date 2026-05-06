#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Unified Test Runner
# ═══════════════════════════════════════════════════════════════════════════════
# Runs all portable unit tests. VM integration tests are in test-gateway.sh.
#
# Usage:
#   bash tests/run-tests.sh          # all tests
#   bash tests/run-tests.sh shell    # shell tests only
#   bash tests/run-tests.sh python   # Python tests only
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TOTAL_PASSED=0
TOTAL_FAILED=0

run_shell_tests() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Shell Unit Tests"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for t in "$SCRIPT_DIR"/test_*.sh; do
        if [[ "$(basename "$t")" == "run-tests.sh" ]]; then continue; fi
        echo ""
        echo "→ $(basename "$t")"
        if bash "$t"; then
            TOTAL_PASSED=$((TOTAL_PASSED + 1))
        else
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    done
}

run_python_tests() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Python Unit Tests"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local pytest_cmd=""
    if [[ -f "$SCRIPT_DIR/../.venv/bin/pytest" ]]; then
        pytest_cmd="$SCRIPT_DIR/../.venv/bin/pytest"
    elif command -v pytest &>/dev/null; then
        pytest_cmd="pytest"
    elif [[ -f "$SCRIPT_DIR/../.venv/bin/python" ]]; then
        pytest_cmd="$SCRIPT_DIR/../.venv/bin/python -m pytest"
    elif command -v python3 &>/dev/null; then
        pytest_cmd="python3 -m pytest"
    fi

    if [[ -n "$pytest_cmd" ]]; then
        if $pytest_cmd "$SCRIPT_DIR/test_progressive_ban.py" -v --tb=short; then
            TOTAL_PASSED=$((TOTAL_PASSED + 1))
        else
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    else
        echo -e "${YELLOW}!${NC} pytest/python3 not found — skipping Python tests"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

case "${1:-all}" in
    shell)
        run_shell_tests
        ;;
    python)
        run_python_tests
        ;;
    all|*)
        run_shell_tests
        run_python_tests
        ;;
esac

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $TOTAL_FAILED -eq 0 ]]; then
    echo -e "  ${GREEN}ALL TEST SUITES PASSED${NC} ($TOTAL_PASSED suite(s))"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 0
else
    echo -e "  ${RED}SOME TEST SUITES FAILED${NC} ($TOTAL_PASSED passed, $TOTAL_FAILED failed)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi
