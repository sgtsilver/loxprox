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
# geoip-block.sh loads $LOXPROX_CONFIG (default /etc/loxprox/config.env) —
# never the host's own file in a test; a case that wants one passes its own.
export LOXPROX_CONFIG="$WORK/no-config.env"

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
# IPv6 (documentation space 2001:db8::/32). kp has no IPv6 list: ipdeny answers 404.
gen_zone6() { local n="$1" i; for ((i = 0; i < n; i++)); do printf '2001:db8:%x::/48\n' $((i + 1)); done; }
gen_zone6 120 > "$ZONES/cn.zone6"
gen_zone6 80  > "$ZONES/ru.zone6"
gen_zone6 10  > "$ZONES/ir.zone6"

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
src="$FAKE_ZONES/$cc.zone"; mode_var="FAKE_MODE_${cc}"; logname="$cc"
if [[ "$url" == */ipv6/* ]]; then
    src="$FAKE_ZONES/$cc.zone6"; mode_var="FAKE6_MODE_${cc}"; logname="${cc}6"
    [[ -f "$src" ]] || FAKE_DEFAULT=http404
fi
echo "$logname" >> "$FAKE_CURL_LOG"
n=$(grep -cx "$logname" "$FAKE_CURL_LOG")
case "${!mode_var:-${FAKE_DEFAULT:-ok}}" in
    http404) echo "curl: (22) The requested URL returned error: 404" >&2; printf 404; exit 22 ;;
    ok)      cp "$src" "$out"; printf 200 ;;
    timeout) echo "curl: (28) Operation timed out after 120001 milliseconds with 65536 bytes received" >&2; printf 000; exit 28 ;;
    flaky)   if (( n < 3 )); then echo "curl: (28) Operation timed out" >&2; printf 000; exit 28; fi
             cp "$src" "$out"; printf 200 ;;
    http503) echo "curl: (22) The requested URL returned error: 503" >&2; printf 503; exit 22 ;;
    html)    printf '<html><body>Too many requests</body></html>\n' > "$out"; printf 200 ;;
    shrunk)  head -n 2 "$src" > "$out"; printf 200 ;;
esac
EOF
cat > "$FAKEBIN/nft" <<'EOF'
#!/bin/bash
echo "$*" | cut -c1-80 >> "$FAKE_NFT_LOG"
if [[ "${1:-}" == -f ]]; then
    cat "$2" >> "$FAKE_NFT_LOG.files"
    if [[ -n "${FAKE_NFT_REJECT6:-}" ]] && grep -q geoip_blocklist6 "$2"; then exit 1; fi
fi
exit 0
EOF
printf '#!/bin/bash\nexit 0\n' > "$FAKEBIN/logger"
chmod +x "$FAKEBIN"/*

# Runs geoip-block.sh in a fresh state dir (optionally pre-seeded with the
# active lists from a previous good run). Extra args are VAR=value overrides.
run_geoip() {
    local case_dir="$1"; shift
    mkdir -p "$case_dir/state"
    : > "$case_dir/curl.log"; : > "$case_dir/nft.log"; : > "$case_dir/nft.log.files"
    env PATH="$FAKEBIN:$PATH" FAKE_ZONES="$ZONES" FAKE_CURL_LOG="$case_dir/curl.log" FAKE_NFT_LOG="$case_dir/nft.log" \
        GEOIP_BLOCKLIST_DIR="$case_dir/state" GEOIP_NFT_FILE="$case_dir/99-geoip.conf" \
        GEOIP_RETRY_DELAYS="0 0 0" "$@" bash "$GEOIP" > "$case_dir/out.log" 2>&1
}

seed_v6() { mkdir -p "$1/state"; cp "$ZONES"/*.zone6 "$1/state/"; printf '1790000000 210\n' > "$1/state/last-success6"; }

seed_last_known_good() {   # a previous successful run's state
    local case_dir="$1"
    mkdir -p "$case_dir/state"
    cp "$ZONES"/*.zone "$case_dir/state/"
    printf '# LoxProx — GeoIP blocklist\n# Generated: earlier\nset geoip_blocklist { }\n' > "$case_dir/99-geoip.conf"
    printf '1790000000 553\n' > "$case_dir/state/last-success"
}

# The active state only: lists, success stamp, nftables include (not the logs).
tree_sum() { (cd "$1" && find state 99-geoip.conf -type f ! -name 'last-failure' ! -name '*6' -exec sha256sum {} + | sort | sha256sum); }

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
    run_geoip "$c" GEOIP_IPV6_ENABLED=false FAKE_MODE_cn=timeout FAKE_MODE_ru=http503; local rc=$?
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
    run_geoip "$c" GEOIP_IPV6_ENABLED=false FAKE_MODE_cn=html; local rc=$?
    [[ $rc -eq 1 ]] && grep -q 'cn: 1 line(s) are not IPv4 CIDRs' "$c/out.log" \
        && pass "an HTML page served with 200 is rejected" || fail "html accepted (rc=$rc)"
    [[ "$(tree_sum "$c")" == "$before" ]] && pass "…and the last known-good list stays" || fail "state changed after html"

    c="$WORK/shrunk"
    seed_last_known_good "$c"
    run_geoip "$c" GEOIP_IPV6_ENABLED=false FAKE_MODE_cn=shrunk; rc=$?
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

test_geoip_ipv6() {
    echo ""; echo "━━━ geoip-block.sh — IPv6 ━━━"
    local c="$WORK/v6ok" rc
    run_geoip "$c"; rc=$?
    [[ $rc -eq 0 ]] && pass "exit 0 with both families" || fail "exit $rc: $(tail -3 "$c/out.log")"
    read -r _ ranges6 < "$c/state/last-success6" 2>/dev/null
    read -r _ ranges4 < "$c/state/last-success" 2>/dev/null
    [[ "$ranges6" == "210" && "$ranges4" == "553" ]] && pass "separate stamps: 553 v4 ranges, 210 v6 ranges" || fail "stamps: v4=$ranges4 v6=$ranges6"
    grep -q 'no IPv6 list published for kp (HTTP 404)' "$c/out.log" && pass "a country without an IPv6 list (kp, 404) is skipped, not a failure" || fail "kp 404 not handled: $(cat "$c/out.log")"
    grep -q '^set geoip_blocklist6 {' "$c/99-geoip.conf" && grep -q 'type ipv6_addr' "$c/99-geoip.conf" \
        && [[ $(grep -c '/48' "$c/99-geoip.conf") -eq 210 ]] && pass "nftables include declares geoip_blocklist6 with 210 ranges" || fail "v6 include wrong"
    grep -q '^set geoip_blocklist {' "$c/99-geoip.conf" && [[ $(grep -c '/24' "$c/99-geoip.conf") -eq 553 ]] \
        && pass "…next to the unchanged IPv4 set" || fail "v4 set wrong"
    grep -q 'flush set inet filter geoip_blocklist6' "$c/nft.log.files" && grep -q 'add element inet filter geoip_blocklist6 { 2001:db8:' "$c/nft.log.files" \
        && [[ $(grep -c 'geoip_blocklist6' "$c/nft.log.files") -eq 2 ]] && pass "live v6 set loaded as one nft transaction (flush + add in one file)" || fail "v6 load: $(cat "$c/nft.log.files" | cut -c1-120)"
    [[ $(grep -cx cn6 "$c/curl.log") -eq 1 && $(grep -cx kp6 "$c/curl.log") -eq 1 ]] && pass "404 is not retried" || fail "attempts: $(grep 6 "$c/curl.log" | sort | uniq -c | tr '\n' ' ')"

    c="$WORK/v6fail"
    run_geoip "$c" FAKE6_MODE_cn=timeout; rc=$?
    [[ $rc -eq 1 ]] && pass "a v6 failure exits 1…" || fail "exit $rc"
    [[ -s "$c/state/last-success" && ! -e "$c/state/last-failure" ]] && [[ $(grep -c '/24' "$c/99-geoip.conf") -eq 553 ]] \
        && pass "…but the v4 refresh still completed" || fail "v4 lost to a v6 failure"
    grep -q 'cn: curl exit 28' "$c/state/last-failure6" && [[ ! -e "$c/state/last-success6" ]] && pass "v6 failure stamped separately, with its reason" || fail "last-failure6: $(cat "$c/state/last-failure6" 2>&1)"
    grep -q 'add element inet filter geoip_blocklist ' "$c/nft.log" && ! grep -q 'geoip_blocklist6' "$c/nft.log.files" && pass "v4 set loaded, v6 set untouched" || fail "live set handling wrong"

    c="$WORK/v4fail"
    run_geoip "$c" FAKE_MODE_cn=timeout; rc=$?
    [[ $rc -eq 1 && -s "$c/state/last-success6" && ! -e "$c/state/last-success" ]] && grep -q 'cn: curl exit 28' "$c/state/last-failure" \
        && pass "a v4 failure does not stop the v6 refresh" || fail "v4 failure blocked v6 (rc=$rc)"

    c="$WORK/v6bad"
    seed_last_known_good "$c"; seed_v6 "$c"
    local before; before=$(cd "$c/state" && sha256sum ./*.zone6 | sha256sum)
    run_geoip "$c" FAKE6_MODE_cn=html; rc=$?
    grep -q 'cn: 1 line(s) are not IPv6 CIDRs' "$c/out.log" && pass "v6: an HTML page served with 200 is rejected" || fail "v6 html accepted (rc=$rc)"
    run_geoip "$c" FAKE6_MODE_cn=shrunk; rc=$?
    grep -q 'cn: shrank from 120 to 2 ranges' "$c/out.log" && pass "v6: shrink guard applies" || fail "v6 shrink: $(grep cn: "$c/out.log")"
    [[ "$(cd "$c/state" && sha256sum ./*.zone6 | sha256sum)" == "$before" ]] && pass "v6: last known-good lists untouched after rejection" || fail "v6 lists changed"

    c="$WORK/v6none"
    run_geoip "$c" FAKE6_MODE_cn=http404 FAKE6_MODE_ru=http404 FAKE6_MODE_ir=http404; rc=$?
    grep -q 'no country list is published' "$c/out.log" && [[ $rc -eq 1 && -s "$c/state/last-success" ]] \
        && pass "no v6 list published at all counts as a v6 failure; v4 unaffected" || fail "all-404 handling (rc=$rc)"

    c="$WORK/v6reject"
    run_geoip "$c" FAKE_NFT_REJECT6=1; rc=$?
    grep -q 'transaction rejected' "$c/state/last-failure6" && [[ $rc -eq 1 && -s "$c/state/last-success" && ! -e "$c/state/last-success6" ]] \
        && pass "nft rejecting the v6 transaction: failure stamped, v4 stamp kept" || fail "nft reject (rc=$rc): $(cat "$c/state/last-failure6" 2>&1)"

    c="$WORK/v6off"
    run_geoip "$c" GEOIP_IPV6_ENABLED=false; rc=$?
    [[ $rc -eq 0 && $(grep -c 6 "$c/curl.log") -eq 0 && ! -e "$c/state/last-success6" ]] && pass "GEOIP_IPV6_ENABLED=false skips the v6 refresh" || fail "v6 ran while disabled"

    # 2026-10: the setting reaches the script through config.env (the cron
    # run has no environment) — written the way deploy.sh's
    # write_runtime_config writes it.
    c="$WORK/v6off-config"
    mkdir -p "$c"
    printf '%s\n' '# LoxProx — Runtime Configuration' 'GEOIP_IPV6_ENABLED="false"' 'GEOIP_URL_BASE6=""' > "$c/config.env"
    run_geoip "$c" LOXPROX_CONFIG="$c/config.env"; rc=$?
    [[ $rc -eq 0 && $(grep -c 6 "$c/curl.log") -eq 0 && ! -e "$c/state/last-success6" && -s "$c/state/last-success" ]] \
        && pass "GEOIP_IPV6_ENABLED=\"false\" in LOXPROX_CONFIG is honoured (v4 refreshed, v6 skipped)" \
        || fail "config.env setting ignored (rc=$rc, v6 fetches: $(grep -c 6 "$c/curl.log"))"
    c="$WORK/v6on-config"
    mkdir -p "$c"
    printf '%s\n' 'GEOIP_IPV6_ENABLED="true"' 'GEOIP_URL_BASE6=""' > "$c/config.env"
    run_geoip "$c" LOXPROX_CONFIG="$c/config.env"; rc=$?
    [[ $rc -eq 0 && $(grep -cx cn6 "$c/curl.log") -eq 1 && -s "$c/state/last-success6" ]] \
        && pass "control: GEOIP_IPV6_ENABLED=\"true\" (and an empty GEOIP_URL_BASE6 = the default) refreshes v6" \
        || fail "control: v6 not refreshed with the config enabling it (rc=$rc)"

    # 2026-10: switching IPv6 off means no v6 blocking — the set is emptied,
    # never rebuilt from the *.zone6 lists an enabled run left behind.
    local v6block
    c="$WORK/v6switchoff"
    run_geoip "$c"; rc=$?
    [[ $rc -eq 0 && $(grep -c '/48' "$c/99-geoip.conf") -eq 210 ]] && pass "v6 loaded first (210 ranges, enabled)" || fail "setup: v6 not loaded (rc=$rc)"
    run_geoip "$c" GEOIP_IPV6_ENABLED=false; rc=$?
    v6block=$(awk '/^set geoip_blocklist6 \{/ {on = 1} on {print} on && /^\}/ {exit}' "$c/99-geoip.conf")
    if [[ $rc -eq 0 && -n "$v6block" ]] && ! grep -q 'elements' <<<"$v6block" && ! grep -q '2001:db8' "$c/99-geoip.conf"; then
        pass "then GEOIP_IPV6_ENABLED=false: geoip_blocklist6 still declared, without elements"
    else
        fail "v6 set after switching off (rc=$rc): $v6block"
    fi
    grep -q '^set geoip_blocklist {' "$c/99-geoip.conf" && [[ $(grep -c '/24' "$c/99-geoip.conf") -eq 553 ]] \
        && pass "…the IPv4 set intact (553 ranges)" || fail "v4 set damaged by switching v6 off"
    compgen -G "$c/state/*.zone6" >/dev/null || [[ -e "$c/state/last-success6" || -e "$c/state/last-failure6" ]] \
        && fail "v6 lists or stamps left behind: $(ls "$c/state")" || pass "…v6 lists and stamps removed (nothing to rebuild from, nothing to call stale)"
    grep -q 'flush set inet filter geoip_blocklist6' "$c/nft.log" && ! grep -q 'add element inet filter geoip_blocklist6' "$c/nft.log.files" \
        && pass "…and the live v6 set flushed, nothing re-added" || fail "live v6 set not emptied: $(cat "$c/nft.log")"

    # Same switch on a night the v4 download fails: the include is still
    # rewritten (v4 from its last known-good lists, v6 empty).
    c="$WORK/v6switchoff-v4fail"
    run_geoip "$c"
    run_geoip "$c" GEOIP_IPV6_ENABLED=false FAKE_MODE_cn=timeout; rc=$?
    v6block=$(awk '/^set geoip_blocklist6 \{/ {on = 1} on {print} on && /^\}/ {exit}' "$c/99-geoip.conf")
    [[ $rc -eq 1 ]] && ! grep -q 'elements' <<<"$v6block" && [[ $(grep -c '/24' "$c/99-geoip.conf") -eq 553 ]] \
        && pass "switching v6 off empties the set even when the v4 refresh fails (v4 last known-good kept)" \
        || fail "v6 off + v4 failure (rc=$rc): $v6block"

    local out
    out=$( export GEOIP_BLOCKLIST_DIR="$WORK/unit6"; mkdir -p "$WORK/unit6"
           # shellcheck source=../security-monitoring/geoip-block.sh
           source "$GEOIP"
           set +e
           printf '2001:db8::/32\n\n2a00::/12  \n' > "$WORK/unit6/a"; validate_zone "$WORK/unit6/a" xx 6; echo "rc=$?"
           printf '2001:db8::/129\n' > "$WORK/unit6/b"; validate_zone "$WORK/unit6/b" xx 6; echo "rc=$?"
           printf '10.0.0.0/8\n' > "$WORK/unit6/c"; validate_zone "$WORK/unit6/c" xx 6; echo "rc=$?"
           printf 'deadbeef/32\n' > "$WORK/unit6/d"; validate_zone "$WORK/unit6/d" xx 6; echo "rc=$?" )
    [[ $(grep -c 'rc=0' <<<"$out") -eq 1 && $(grep -c 'rc=1' <<<"$out") -eq 3 ]] \
        && pass "v6 validation: /129, an IPv4 CIDR and a colon-less string rejected; blanks tolerated" || fail "v6 verdicts: $out"
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

test_monitor_staleness_v6() {
    echo ""; echo "━━━ gateway-monitor.sh — IPv6 staleness ━━━"
    : > "$MON/discord.log"; rm -f "$MON/state/"*stale_alerted "$MON/geoip/"* "$MON/99-geoip.conf"
    local now; now=$(date +%s)
    printf '%s 553\n' $((now - 3600)) > "$MON/geoip/last-success"
    run_check
    [[ "$(grep -c 'IPv6' "$MON/discord.log")" == "0" ]] && pass "no IPv6 stamps (pre-IPv6 install) → no IPv6 alert" || fail "alerted without v6 stamps"
    printf '%s 210\n' $((now - 4 * 86400)) > "$MON/geoip/last-success6"
    printf '%s cn: curl exit 28\n' $((now - 600)) > "$MON/geoip/last-failure6"
    run_check; run_check
    local msg; msg=$(grep 'GeoIP IPv6 Blocklist Stale' "$MON/discord.log")
    [[ $(grep -c 'GeoIP IPv6 Blocklist Stale' "$MON/discord.log") -eq 1 ]] && grep -q 'The GeoIP IPv6 blocklist has not refreshed for 4 day(s)' <<<"$msg" \
        && grep -q 'Last error: cn: curl exit 28' <<<"$msg" && pass "stale v6 list → one IPv6 WARNING, deduplicated, with the v6 reason" || fail "v6 stale: $msg"
    [[ "$(grep -c 'GeoIP Blocklist Stale' "$MON/discord.log")" == "0" ]] && pass "…while the fresh v4 list stays quiet" || fail "v4 alerted"

    # 2026-10: GEOIP_IPV6_ENABLED=false — the same stale v6 stamps alert nothing.
    : > "$MON/discord.log"; rm -f "$MON/state/"*stale_alerted
    ( export GEOIP_IPV6_ENABLED=false; run_check )
    [[ "$(grep -c 'IPv6' "$MON/discord.log")" == "0" ]] && pass "GEOIP_IPV6_ENABLED=false: stale v6 stamps raise no IPv6 alert" \
                                                       || fail "alerted on v6 while it is disabled: $(cat "$MON/discord.log")"
    rm -f "$MON/geoip/"*

    # check_firewall_integrity: a declared but empty geoip_blocklist6 is
    # CRITICAL while IPv6 blocking is on, and by design while it is off.
    local fwbin="$WORK/fwbin"
    mkdir -p "$fwbin"
    cat > "$fwbin/nft" <<'EOF'
#!/bin/bash
case "$*" in
    "list chain inet filter input")          echo 'chain input { type filter hook input priority filter; policy drop; ip saddr @geoip_blocklist drop; ip6 saddr @geoip_blocklist6 drop; }' ;;
    "list chain inet filter output")         echo 'chain output { type filter hook output priority filter; policy accept; oifname "lo" accept comment "loxprox-egress" }' ;;
    "list set inet filter geoip_blocklist")  echo 'set geoip_blocklist { type ipv4_addr; flags interval; elements = { 100.64.0.0/24 } }' ;;
    "list set inet filter geoip_blocklist6") echo 'set geoip_blocklist6 { type ipv6_addr; flags interval; }' ;;
esac
exit 0
EOF
    chmod +x "$fwbin/nft"
    local v6flag
    for v6flag in false true; do
        : > "$MON/discord.log"; rm -f "$MON/state/alert_"*
        ( export PATH="$fwbin:$PATH" LOXPROX_CONFIG="$MON/none.env" LOXPROX_STATE_DIR="$MON/state" LOXPROX_MONITOR_LOG="$MON/monitor.log" \
                 DISCORD_ALERT_PATH="$MON/discord.sh" LOXPROX_GEOIP_DIR="$MON/geoip" GEOIP_IPV6_ENABLED="$v6flag" \
                 FW_SET_CHECK_INTERVAL=0
          # shellcheck source=../security-monitoring/gateway-monitor.sh
          source "$MONITOR"
          set +e
          check_firewall_integrity ) >/dev/null 2>&1
        if [[ "$v6flag" == "false" ]]; then
            grep -q 'geoip_blocklist6 is empty' "$MON/discord.log" && fail "empty v6 set alerted although GEOIP_IPV6_ENABLED=false" \
                                                                   || pass "GEOIP_IPV6_ENABLED=false: the empty v6 set is no firewall alert"
        else
            grep -q '^CRITICAL|.*geoip_blocklist6 is empty' "$MON/discord.log" && pass "control: the same empty v6 set with IPv6 on → CRITICAL" \
                                                                              || fail "control: empty v6 set not reported with IPv6 on"
        fi
    done
}

echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  LoxProx — GeoIP refresh + staleness tests"
echo "═══════════════════════════════════════════════════════════════════════════════"
test_geoip_success
test_geoip_retries_then_succeeds
test_geoip_live_failure_keeps_last_known_good
test_geoip_rejects_bad_lists
test_geoip_disabled_marker
test_geoip_ipv6
test_monitor_staleness
test_monitor_staleness_v6

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"
[[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
