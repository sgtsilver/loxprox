#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — GeoIP refresh + staleness alert (2026-10)
# ═══════════════════════════════════════════════════════════════════════════════
# geoip-block.sh runs end to end against a fake `curl` (serves synthetic zone
# lists, or fails the way ipdeny did) and a fake `nft` on PATH; nothing touches
# the host. gateway-monitor.sh's check_geoip_staleness runs with a fake
# Discord sender that records what it would have sent.
#
# Run: bash tests/test_geoip_monitor.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
TESTS_PASSED=0
TESTS_FAILED=0
pass() { echo -e "  ${GREEN}✓${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
GEOIP="$PROJECT_DIR/security-monitoring/geoip-block.sh"
MONITOR="$PROJECT_DIR/security-monitoring/gateway-monitor.sh"
WORK="$(mktemp -d /tmp/loxprox-test-geoip.XXXXXXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# ── fakes ────────────────────────────────────────────────────────────────────

FAKEBIN="$WORK/bin"
ZONES="$WORK/zones"
mkdir -p "$FAKEBIN" "$ZONES"

# Synthetic zone lists (CGNAT space — content is irrelevant, the shape is not).
gen_zone() { local n="$1" i; for ((i = 0; i < n; i++)); do printf '100.%d.%d.0/24\n' $((64 + i / 256)) $((i % 256)); done; }
gen_zone 300 > "$ZONES/cn.zone"
gen_zone 200 > "$ZONES/ru.zone"
gen_zone 3   > "$ZONES/kp.zone"
gen_zone 50  > "$ZONES/ir.zone"

cat > "$FAKEBIN/curl" <<'EOF'
#!/bin/bash
# Fake curl: serves $FAKE_ZONES/<cc>.zone; FAKE_MODE_<cc> picks a failure.
out="" url=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -w|--connect-timeout|--max-time) shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
cc=$(basename "$url" .zone)
echo "$cc" >> "$FAKE_CURL_LOG"
n=$(grep -cx "$cc" "$FAKE_CURL_LOG")
mode_var="FAKE_MODE_${cc}"
case "${!mode_var:-ok}" in
    ok)      cp "$FAKE_ZONES/$cc.zone" "$out"; printf 200 ;;
    timeout) echo "curl: (28) Operation timed out after 120001 milliseconds with 65536 bytes received" >&2; printf 000; exit 28 ;;
    flaky)   if (( n < 3 )); then echo "curl: (28) Operation timed out" >&2; printf 000; exit 28; fi
             cp "$FAKE_ZONES/$cc.zone" "$out"; printf 200 ;;
    http503) echo "curl: (22) The requested URL returned error: 503" >&2; printf 503; exit 22 ;;
    html)    printf '<html><body>Too many requests</body></html>\n' > "$out"; printf 200 ;;
    shrunk)  head -n 2 "$FAKE_ZONES/$cc.zone" > "$out"; printf 200 ;;
esac
EOF
cat > "$FAKEBIN/nft" <<'EOF'
#!/bin/bash
echo "$*" | cut -c1-80 >> "$FAKE_NFT_LOG"
exit 0
EOF
printf '#!/bin/bash\nexit 0\n' > "$FAKEBIN/logger"
chmod +x "$FAKEBIN"/*

# Runs geoip-block.sh in a fresh state dir (optionally pre-seeded with the
# active lists from a previous good run). Extra args are VAR=value overrides.
run_geoip() {
    local case_dir="$1"; shift
    mkdir -p "$case_dir/state"
    : > "$case_dir/curl.log"; : > "$case_dir/nft.log"
    env PATH="$FAKEBIN:$PATH" FAKE_ZONES="$ZONES" FAKE_CURL_LOG="$case_dir/curl.log" FAKE_NFT_LOG="$case_dir/nft.log" \
        GEOIP_BLOCKLIST_DIR="$case_dir/state" GEOIP_NFT_FILE="$case_dir/99-geoip.conf" \
        GEOIP_RETRY_DELAYS="0 0 0" "$@" bash "$GEOIP" > "$case_dir/out.log" 2>&1
}

seed_last_known_good() {   # a previous successful run's state
    local case_dir="$1"
    mkdir -p "$case_dir/state"
    cp "$ZONES"/*.zone "$case_dir/state/"
    printf '# LoxProx — GeoIP blocklist\n# Generated: earlier\nset geoip_blocklist { }\n' > "$case_dir/99-geoip.conf"
    printf '1790000000 553\n' > "$case_dir/state/last-success"
}

# The active state only: lists, success stamp, nftables include (not the logs).
tree_sum() { (cd "$1" && find state 99-geoip.conf -type f ! -name 'last-failure' -exec sha256sum {} + | sort | sha256sum); }

# ── geoip-block.sh ───────────────────────────────────────────────────────────

test_geoip_success() {
    echo ""; echo "━━━ geoip-block.sh — all lists fetched ━━━"
    local c="$WORK/ok"
    run_geoip "$c"; local rc=$?
    [[ $rc -eq 0 ]] && pass "exit 0" || fail "exit $rc: $(tail -3 "$c/out.log")"
    read -r stamp ranges < "$c/state/last-success" 2>/dev/null
    [[ "$ranges" == "553" && "$stamp" =~ ^[0-9]+$ ]] && pass "last-success stamped: 553 ranges" || fail "last-success: $(cat "$c/state/last-success" 2>&1)"
    grep -q '# Generated:' "$c/99-geoip.conf" && [[ $(grep -c '/24' "$c/99-geoip.conf") -eq 553 ]] \
        && pass "nftables include rebuilt with 553 ranges" || fail "nft include wrong"
    grep -q 'add element inet filter geoip_blocklist' "$c/nft.log" && pass "live set updated in batches" || fail "no live-set update"
    [[ ! -e "$c/state/last-failure" ]] && pass "no failure stamp" || fail "unexpected failure stamp"
}

test_geoip_retries_then_succeeds() {
    echo ""; echo "━━━ geoip-block.sh — transient failure is retried ━━━"
    local c="$WORK/flaky"
    run_geoip "$c" FAKE_MODE_cn=flaky; local rc=$?
    [[ $rc -eq 0 ]] && pass "exit 0 after retries" || fail "exit $rc"
    [[ $(grep -cx cn "$c/curl.log") -eq 3 ]] && pass "cn fetched 3 times (2 timeouts + success)" || fail "cn attempts: $(grep -cx cn "$c/curl.log")"
    grep -q 'cn attempt 1/4 failed — curl exit 28' "$c/out.log" && pass "each failed attempt logs its reason" || fail "attempt reason not logged"
    grep -q 'cn fetched on attempt 3/4' "$c/out.log" && pass "success after retry is logged" || fail "retry success not logged"
}

test_geoip_live_failure_keeps_last_known_good() {
    echo ""; echo "━━━ geoip-block.sh — the 2026-10-06 case: cn + ru fail ━━━"
    local c="$WORK/fail"
    seed_last_known_good "$c"
    local before; before=$(tree_sum "$c")
    run_geoip "$c" FAKE_MODE_cn=timeout FAKE_MODE_ru=http503; local rc=$?
    [[ $rc -eq 1 ]] && pass "exit 1" || fail "exit $rc"
    grep -q 'failed countries: cn ru' "$c/out.log" && pass "same summary line as before" || fail "summary line missing"
    grep -q 'cn: curl exit 28, HTTP 000: curl: (28) Operation timed out' "$c/out.log" \
        && grep -q 'ru: curl exit 22, HTTP 503' "$c/out.log" && pass "each failure now carries its reason (was discarded)" || fail "reasons missing: $(grep FAILED "$c/out.log")"
    [[ $(grep -cx cn "$c/curl.log") -eq 4 ]] && pass "cn tried 4 times (backoff schedule)" || fail "cn attempts: $(grep -cx cn "$c/curl.log")"
    [[ "$(tree_sum "$c")" == "$before" ]] && pass "last known-good lists, include and success stamp untouched" || fail "active state changed"
    [[ -z "$(find "$c/state" -name '*.new')" ]] && pass "no staged .new files left" || fail "staged files left"
    grep -q 'cn: curl exit 28' "$c/state/last-failure" && pass "last-failure stamped with the reason" || fail "last-failure: $(cat "$c/state/last-failure" 2>&1)"
    grep -q 'add element' "$c/nft.log" && fail "live set touched on failure" || pass "live set not touched"
}

test_geoip_rejects_bad_lists() {
    echo ""; echo "━━━ geoip-block.sh — validation (error page, shrink, syntax) ━━━"
    local c="$WORK/html"
    seed_last_known_good "$c"
    local before; before=$(tree_sum "$c")
    run_geoip "$c" FAKE_MODE_cn=html; local rc=$?
    [[ $rc -eq 1 ]] && grep -q 'cn: 1 line(s) are not IPv4 CIDRs' "$c/out.log" \
        && pass "an HTML page served with 200 is rejected" || fail "html accepted (rc=$rc)"
    [[ "$(tree_sum "$c")" == "$before" ]] && pass "…and the last known-good list stays" || fail "state changed after html"

    c="$WORK/shrunk"
    seed_last_known_good "$c"
    run_geoip "$c" FAKE_MODE_cn=shrunk; rc=$?
    [[ $rc -eq 1 ]] && grep -q 'cn: shrank from 300 to 2 ranges' "$c/out.log" \
        && pass "a list that lost >50% against last known-good is rejected" || fail "shrink accepted (rc=$rc): $(grep cn: "$c/out.log")"

    local out
    out=$( export GEOIP_BLOCKLIST_DIR="$WORK/unit"; mkdir -p "$WORK/unit"
           # shellcheck source=../security-monitoring/geoip-block.sh
           source "$GEOIP"
           set +e
           printf '10.0.0.0/8\n300.1.1.0/24\n' > "$WORK/unit/a"; validate_zone "$WORK/unit/a" xx; echo "rc=$?"
           printf '10.0.0.0/33\n' > "$WORK/unit/b"; validate_zone "$WORK/unit/b" xx; echo "rc=$?"
           printf '10.0.0.0/8\n\n192.0.2.0/24  \n' > "$WORK/unit/c"; validate_zone "$WORK/unit/c" xx; echo "rc=$?" )
    grep -q '1 line(s) are not IPv4 CIDRs' <<<"$out" && pass "octet > 255 rejected" || fail "bad octet accepted: $out"
    [[ $(grep -c 'rc=1' <<<"$out") -eq 2 && $(grep -c 'rc=0' <<<"$out") -eq 1 ]] \
        && pass "prefix > 32 rejected; blank lines / trailing spaces tolerated" || fail "validation verdicts: $out"
}

test_geoip_disabled_marker() {
    echo ""; echo "━━━ geoip-block.sh — GEOIP_ENABLED=false ━━━"
    local c="$WORK/disabled"
    run_geoip "$c" GEOIP_ENABLED=false; local rc=$?
    [[ $rc -eq 0 && -e "$c/state/disabled" ]] && pass "disabled run marks the state dir" || fail "no disabled marker (rc=$rc)"
    [[ ! -s "$c/curl.log" ]] && pass "nothing downloaded" || fail "downloaded while disabled"
    run_geoip "$c"
    [[ ! -e "$c/state/disabled" ]] && pass "an enabled run clears the marker" || fail "marker survived an enabled run"
}

# ── gateway-monitor.sh: staleness alert ──────────────────────────────────────

MON="$WORK/mon"
mkdir -p "$MON/state" "$MON/geoip"
printf '#!/bin/bash\nprintf "%%s|%%s|%%s\\n" "$1" "$2" "$3" >> "%s"\n' "$MON/discord.log" > "$MON/discord.sh"
chmod +x "$MON/discord.sh"
touch "$MON/geoip-block.sh"

run_check() {
    ( export LOXPROX_CONFIG="$MON/none.env" LOXPROX_STATE_DIR="$MON/state" LOXPROX_MONITOR_LOG="$MON/monitor.log" \
             DISCORD_ALERT_PATH="$MON/discord.sh" LOXPROX_GEOIP_DIR="$MON/geoip" \
             LOXPROX_GEOIP_NFT="$MON/99-geoip.conf" LOXPROX_GEOIP_SCRIPT="$MON/geoip-block.sh"
      # shellcheck source=../security-monitoring/gateway-monitor.sh
      source "$MONITOR"
      set +e
      check_geoip_staleness ) >/dev/null 2>&1
}
alerts() { grep -c 'GeoIP Blocklist Stale' "$MON/discord.log" 2>/dev/null || true; }

test_monitor_staleness() {
    echo ""; echo "━━━ gateway-monitor.sh — check_geoip_staleness ━━━"
    : > "$MON/discord.log"
    local now; now=$(date +%s)
    printf '%s 22249\n' $((now - 3600)) > "$MON/geoip/last-success"
    run_check
    [[ "$(alerts)" == "0" ]] && pass "fresh list → no alert" || fail "alerted on a fresh list"

    printf '%s 22249\n' $((now - 4 * 86400)) > "$MON/geoip/last-success"
    printf '%s cn: curl exit 28, HTTP 000: timed out\n' $((now - 600)) > "$MON/geoip/last-failure"
    run_check
    [[ "$(alerts)" == "1" ]] && pass "stale for 4 days → one WARNING" || fail "alerts after stale: $(alerts)"
    local msg; msg=$(grep 'GeoIP Blocklist Stale' "$MON/discord.log")
    [[ "$msg" == WARNING\|* ]] && grep -q 'has not refreshed for 4 day(s)' <<<"$msg" && grep -q '(22249 ranges)' <<<"$msg" \
        && grep -q 'Last error: cn: curl exit 28' <<<"$msg" && pass "message: age, kept ranges, last error" || fail "message: $msg"
    run_check; run_check
    [[ "$(alerts)" == "1" ]] && pass "deduplicated: no repeat while the same episode lasts" || fail "repeated: $(alerts)"

    printf '%s 22300\n' $((now - 60)) > "$MON/geoip/last-success"
    run_check
    [[ ! -e "$MON/state/geoip_stale_alerted" ]] && pass "a successful refresh re-arms the alert" || fail "not re-armed"
    printf '%s 22300\n' $((now - 5 * 86400)) > "$MON/geoip/last-success"
    run_check
    [[ "$(alerts)" == "2" ]] && pass "a new stale episode alerts again" || fail "alerts: $(alerts)"
    printf '%s old reason\n' $((now - 6 * 86400)) > "$MON/geoip/last-failure"
    printf '%s 22300\n' $((now - 4 * 86400)) > "$MON/geoip/last-success"
    run_check
    msg=$(grep 'GeoIP Blocklist Stale' "$MON/discord.log" | tail -n 1)
    [[ "$(alerts)" == "3" ]] && ! grep -q 'Last error' <<<"$msg" \
        && pass "a failure older than the last success is not reported as the cause" || fail "older failure: $(alerts) / $msg"

    : > "$MON/discord.log"; rm -f "$MON/state/geoip_stale_alerted"
    touch "$MON/geoip/disabled"; run_check
    [[ "$(alerts)" == "0" ]] && pass "GeoIP disabled → no alert" || fail "alerted while disabled"
    rm -f "$MON/geoip/disabled"

    rm -f "$MON/geoip/last-success" "$MON/geoip/last-failure"
    printf '# Generated: 2026-10-01\n' > "$MON/99-geoip.conf"; touch -d '@'$((now - 2 * 86400)) "$MON/99-geoip.conf"
    run_check
    [[ "$(alerts)" == "0" ]] && pass "pre-stamp install: nftables include mtime (2 days) counts as fresh" || fail "pre-stamp fresh alerted"
    touch -d '@'$((now - 6 * 86400)) "$MON/99-geoip.conf"; run_check
    [[ "$(alerts)" == "1" ]] && pass "pre-stamp install: 6-day-old include → alert" || fail "pre-stamp stale: $(alerts)"

    : > "$MON/discord.log"; rm -f "$MON/state/geoip_stale_alerted"
    printf '# Placeholder — overwritten by geoip-block.sh on first run\n' > "$MON/99-geoip.conf"; run_check
    grep -q 'has never refreshed successfully' "$MON/discord.log" && pass "never loaded → says so" || fail "never-loaded message missing"

    : > "$MON/discord.log"; rm -f "$MON/state/geoip_stale_alerted" "$MON/geoip-block.sh"; run_check
    [[ "$(alerts)" == "0" ]] && pass "geoip-block.sh not installed → no alert" || fail "alerted without the script"
    touch "$MON/geoip-block.sh"

    grep -qE '^[[:space:]]+check_geoip_staleness$' "$MONITOR" && pass "main() runs check_geoip_staleness" || fail "not wired into main()"
}

echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  LoxProx — GeoIP refresh + staleness tests"
echo "═══════════════════════════════════════════════════════════════════════════════"
test_geoip_success
test_geoip_retries_then_succeeds
test_geoip_live_failure_keeps_last_known_good
test_geoip_rejects_bad_lists
test_geoip_disabled_marker
test_monitor_staleness

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"
[[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
