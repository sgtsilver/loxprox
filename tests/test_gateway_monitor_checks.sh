#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — gateway-monitor.sh breach-hardening checks (2026-10)
# ═══════════════════════════════════════════════════════════════════════════════
# check_crowdsec_blocks, check_hard_ban_digest, check_new_asn_session,
# check_firewall_integrity, check_security_updates and check_auth_rate run
# against fake cscli / ss / mmdblookup / nft / apt-get / date on PATH and a
# fake Discord sender that records what it would have sent. Nothing touches the
# host. Needs jq (the monitor itself needs it).
#
# Run: bash tests/test_gateway_monitor_checks.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
TESTS_PASSED=0
TESTS_FAILED=0
pass() { echo -e "  ${GREEN}✓${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not installed"
    exit 0
fi

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
MONITOR="$PROJECT_DIR/security-monitoring/gateway-monitor.sh"
WORK="$(mktemp -d /tmp/loxprox-test-monchecks.XXXXXXXXXX)"
trap 'rm -rf "${WORK:?}"' EXIT

FAKEBIN="$WORK/bin"; STATE="$WORK/state"; FW="$WORK/fw"
mkdir -p "$FAKEBIN" "$STATE" "$FW"
: > "$WORK/ss.txt"; : > "$WORK/mmdb.txt"; : > "$WORK/apt.txt"; : > "$WORK/whitelist.yaml"
touch "$WORK/asn.mmdb" "$WORK/city.mmdb"

# Fake Discord sender: "severity|title|message" per line.
cat > "$WORK/discord.sh" <<'EOF'
#!/bin/bash
printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$FAKE_DISCORD_LOG"
EOF
# ss: prints the prepared peer lines whatever the arguments are.
cat > "$FAKEBIN/ss" <<'EOF'
#!/bin/bash
cat "$FAKE_SS"
EOF
# mmdblookup: table lines "ip asn org country"; prints the real tool's value format.
cat > "$FAKEBIN/mmdblookup" <<'EOF'
#!/bin/bash
ip="" ; keys=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --file) shift 2 ;;
        --ip) ip="$2"; shift 2 ;;
        *) keys+=("$1"); shift ;;
    esac
done
row=$(grep -F "${ip} " "$FAKE_MMDB" | head -n 1)
if [[ -z "$row" ]]; then
    printf '\n  Could not find an entry for this IP address (%s)\n' "$ip"
    exit 0
fi
read -r _ asn org cc <<< "$row"
case "${keys[*]}" in
    "autonomous_system_number")       printf '\n  %s <uint32>\n\n' "$asn" ;;
    "autonomous_system_organization") printf '\n  "%s" <utf8_string>\n\n' "${org//_/ }" ;;
    "country iso_code")               printf '\n  "%s" <utf8_string>\n\n' "$cc" ;;
esac
EOF
# nft: serves prepared output per object; a missing file means "No such file".
# Every call is recorded in FAKE_NFT_LOG.
cat > "$FAKEBIN/nft" <<'EOF'
#!/bin/bash
echo "$*" >> "$FAKE_NFT_LOG"
case "$*" in
    "list chain inet filter input")          f="$FAKE_FW/input" ;;
    "list chain inet filter output")         f="$FAKE_FW/output" ;;
    "list set inet filter geoip_blocklist")  f="$FAKE_FW/set4" ;;
    "list set inet filter geoip_blocklist6") f="$FAKE_FW/set6" ;;
    *) exit 1 ;;
esac
[[ -f "$f" ]] || { echo "Error: No such file or directory" >&2; exit 1; }
cat "$f"
EOF
cat > "$FAKEBIN/apt-get" <<'EOF'
#!/bin/bash
cat "$FAKE_APT"
EOF
# cscli: serves FAKE_DECISIONS / FAKE_ALERTS with the CrowdSec 1.8.1 defaults
# the monitor has to override — without --limit 0, `decisions list` returns
# 100 alerts and `alerts list` 50; without --no-simu, simulated decisions are
# included. -s filters alerts by scenario. FAKE_RAW serves the file verbatim.
cat > "$FAKEBIN/cscli" <<'EOF'
#!/bin/bash
echo "$*" >> "$FAKE_CSCLI_LOG"
args=" $* "
case "$1 $2" in
    "decisions list")
        [[ "${FAKE_CSCLI_RC:-0}" == 0 ]] || exit "$FAKE_CSCLI_RC"
        [[ -z "${FAKE_RAW:-}" ]] || { cat "$FAKE_DECISIONS"; exit 0; }
        data=$(cat "$FAKE_DECISIONS")
        if [[ "$args" == *" --no-simu "* ]]; then
            data=$(jq '[.[]? | .decisions = [(.decisions // [])[] | select(.simulated != true)] | select(.decisions | length > 0)]' <<< "$data")
        fi
        [[ "$args" == *" --limit 0 "* ]] || data=$(jq '.[0:100]' <<< "$data")
        echo "$data" ;;
    "alerts list")
        [[ "${FAKE_ALERTS_RC:-0}" == 0 ]] || exit "$FAKE_ALERTS_RC"
        data=$(cat "$FAKE_ALERTS")
        scen=$(sed -nE 's/.* (-s|--scenario) ([^ ]+) .*/\2/p' <<< "$args")
        [[ -z "$scen" ]] || data=$(jq --arg s "$scen" '[.[]? | select(.scenario == $s)]' <<< "$data")
        [[ "$args" == *" --limit 0 "* ]] || data=$(jq '.[0:50]' <<< "$data")
        echo "$data" ;;
    *) exit 0 ;;
esac
EOF
# date: FAKE_NOW pins "now" (`date +%s`); every other call is the real date.
REAL_DATE="$(command -v date)"
cat > "$FAKEBIN/date" <<EOF
#!/bin/bash
if [[ -n "\${FAKE_NOW:-}" && "\$*" == "+%s" ]]; then echo "\$FAKE_NOW"; exit 0; fi
exec "$REAL_DATE" "\$@"
EOF
chmod +x "$WORK/discord.sh" "$FAKEBIN"/*
: > "$WORK/cscli.log"; : > "$WORK/nft.log"; echo '[]' > "$WORK/decisions.json"; echo '[]' > "$WORK/alerts.json"

# Runs one function of gateway-monitor.sh in a subshell with the fakes wired in.
# Extra args are VAR=value overrides.
run_fn() {
    local fn="$1"; shift
    ( export PATH="$FAKEBIN:$PATH" LOXPROX_CONFIG="$WORK/none.env" LOXPROX_STATE_DIR="$STATE" \
             LOXPROX_MONITOR_LOG="$WORK/monitor.log" DISCORD_ALERT_PATH="$WORK/discord.sh" \
             FAKE_DISCORD_LOG="$WORK/discord.log" FAKE_SS="$WORK/ss.txt" FAKE_MMDB="$WORK/mmdb.txt" \
             FAKE_FW="$FW" FAKE_APT="$WORK/apt.txt" FAKE_NFT_LOG="$WORK/nft.log" \
             FAKE_CSCLI_LOG="$WORK/cscli.log" FAKE_DECISIONS="$WORK/decisions.json" FAKE_ALERTS="$WORK/alerts.json" \
             LOXPROX_ASN_DB="$WORK/asn.mmdb" LOXPROX_CITY_DB="$WORK/city.mmdb" \
             PROGRESSIVE_BAN_WHITELIST_FILE="$WORK/whitelist.yaml" LOXPROX_ACCESS_LOG="$WORK/access.log" \
             LOXPROX_GEOIP_DIR="$WORK/geoip" SEC_UPDATE_CHECK_INTERVAL=0 FW_SET_CHECK_INTERVAL=0
      for kv in "$@"; do export "${kv?}"; done
      # shellcheck source=../security-monitoring/gateway-monitor.sh
      source "$MONITOR"
      set +e
      "$fn" ) >/dev/null 2>&1
}
fresh_alerts() { : > "$WORK/discord.log"; rm -f "${STATE:?}"/alert_*; }
count_alerts() { grep -c "$1" "$WORK/discord.log" 2>/dev/null || true; }
clear_fw() { rm -f "${FW:?}"/*; }

# ── new-ASN remote session ───────────────────────────────────────────────────

ss_line() { printf '0 0 192.168.1.50:1080 %s\n' "$1"; }

test_asn_session() {
    echo ""; echo "━━━ check_new_asn_session ━━━"
    local known="$STATE/known-asns.json"
    printf '198.51.100.7 64500 Example_Mobile_GmbH DE\n198.51.100.8 64501 Hosting_Corp NL\n2001:db8::5 64502 V6_Carrier AT\n' > "$WORK/mmdb.txt"

    fresh_alerts; rm -f "$known" "$STATE"/session_peers_prev
    ss_line "198.51.100.7:51234" > "$WORK/ss.txt"
    run_fn check_new_asn_session
    if [[ -f "$known" ]] && jq -e '.learning_started > 0 and (.asns | length) == 0' "$known" >/dev/null; then
        pass "first run creates the state file and starts the learning clock"
    else
        fail "state file: $(cat "$known" 2>&1)"
    fi
    run_fn check_new_asn_session
    if jq -e '.asns["64500"].org == "Example Mobile GmbH" and .asns["64500"].country == "DE"' "$known" >/dev/null; then
        pass "a peer seen in two consecutive cycles is a session: ASN, org and country recorded"
    else
        fail "asn not recorded: $(cat "$known")"
    fi
    [[ "$(count_alerts '')" == "0" ]] && pass "learning period: recorded silently, no alert" || fail "alerted while learning"

    # End the learning period.
    jq '.learning_started = 1' "$known" > "$known.t" && mv "$known.t" "$known"
    : > "$WORK/discord.log"
    ss_line "198.51.100.8:40000" > "$WORK/ss.txt"
    run_fn check_new_asn_session
    [[ "$(count_alerts '')" == "0" ]] && pass "one cycle is not a session" || fail "alerted after a single cycle"
    run_fn check_new_asn_session
    local line; line=$(grep 'New ASN' "$WORK/discord.log" || true)
    if [[ "$line" == WARNING\|* ]] && grep -q 'AS64501' <<<"$line" && grep -q 'Hosting Corp' <<<"$line" && grep -q 'Country: NL' <<<"$line"; then
        pass "new ASN after learning → one WARNING naming ASN, organisation, country"
    else
        fail "alert: $line"
    fi
    if grep -q '198.51.100.8' <<<"$line"; then fail "full client IP leaked into the alert"; else pass "client address is masked, not in the alert"; fi
    grep -q '198.51.100.x' <<<"$line" && pass "last octet masked as .x" || fail "masked address missing: $line"
    run_fn check_new_asn_session; run_fn check_new_asn_session
    [[ "$(count_alerts 'New ASN')" == "1" ]] && pass "the ASN is now known: no repeat alert" || fail "repeated: $(count_alerts 'New ASN')"

    : > "$WORK/discord.log"
    ss_line "198.51.100.7:1111" > "$WORK/ss.txt"
    run_fn check_new_asn_session; run_fn check_new_asn_session
    [[ "$(count_alerts '')" == "0" ]] && pass "a known ASN never alerts" || fail "known ASN alerted"

    : > "$WORK/discord.log"; rm -f "$STATE"/session_peers_prev
    printf '0 0 [::1]:1080 [2001:db8::5]:4000\n' > "$WORK/ss.txt"
    run_fn check_new_asn_session; run_fn check_new_asn_session
    if grep -q 'AS64502' "$WORK/discord.log" && grep -q '2001:db8:' "$WORK/discord.log" && ! grep -q '2001:db8::5' "$WORK/discord.log"; then
        pass "IPv6 peer: bracketed ss form parsed, address masked to the /48"
    else
        fail "ipv6: $(cat "$WORK/discord.log")"
    fi

    : > "$WORK/discord.log"; rm -f "$STATE"/session_peers_prev; jq '.asns = {}' "$known" > "$known.t" && mv "$known.t" "$known"
    printf '0 0 192.168.1.50:1080 192.168.1.20:5000\n0 0 192.168.1.50:1080 10.1.2.3:5000\n0 0 192.168.1.50:1080 127.0.0.1:5000\n0 0 192.168.1.50:1080 203.0.113.9:5000\n' > "$WORK/ss.txt"
    printf '192.168.1.20 64510 Lan_X DE\n10.1.2.3 64511 Lan_Y DE\n127.0.0.1 64512 Lo_Z DE\n203.0.113.9 64513 Whitelisted_W DE\n' > "$WORK/mmdb.txt"
    printf 'name: whitelist-loxone\nwhitelist:\n  ip:\n    - "203.0.113.9"\n  cidr:\n    - "198.51.100.0/24"\n' > "$WORK/whitelist.yaml"
    run_fn check_new_asn_session; run_fn check_new_asn_session
    if [[ "$(count_alerts '')" == "0" && "$(jq '.asns | length' "$known")" == "0" ]]; then
        pass "private/LAN/loopback peers and CrowdSec-whitelisted addresses are not sessions"
    else
        fail "excluded peers counted: $(cat "$WORK/discord.log") $(cat "$known")"
    fi
    ss_line "198.51.100.8:40000" > "$WORK/ss.txt"; rm -f "$STATE"/session_peers_prev
    printf '198.51.100.8 64501 Hosting_Corp NL\n' > "$WORK/mmdb.txt"
    run_fn check_new_asn_session; run_fn check_new_asn_session
    [[ "$(count_alerts '')" == "0" ]] && pass "whitelisted CIDR (198.51.100.0/24) is excluded" || fail "CIDR whitelist ignored"
    : > "$WORK/whitelist.yaml"

    # Degradation
    fresh_alerts; rm -f "$known" "$STATE"/session_peers_prev
    run_fn check_new_asn_session LOXPROX_MMDBLOOKUP=no-such-mmdblookup-binary
    if [[ ! -e "$known" && "$(count_alerts '')" == "0" ]] && grep -q 'mmdblookup is not installed' "$WORK/monitor.log"; then
        pass "no mmdblookup: logged, no alert, no state"
    else
        fail "missing mmdblookup mishandled"
    fi
    run_fn check_new_asn_session LOXPROX_ASN_DB="$WORK/missing.mmdb"
    if [[ ! -e "$known" ]] && grep -q 'GeoLite2 database missing' "$WORK/monitor.log"; then
        pass "no mmdb file: logged, no alert, no state"
    else
        fail "missing mmdb mishandled"
    fi
    run_fn check_new_asn_session SESSION_ALERT_ENABLED=false
    [[ ! -e "$known" ]] && pass "SESSION_ALERT_ENABLED=false does nothing" || fail "ran while disabled"
    grep -qE '^[[:space:]]+check_new_asn_session$' "$MONITOR" && pass "main() runs check_new_asn_session" || fail "not in main()"
}

# ── firewall integrity ───────────────────────────────────────────────────────

fw_healthy() {
    clear_fw
    printf 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t\tip saddr @geoip_blocklist drop\n\t\tip6 saddr @geoip_blocklist6 drop\n\t\ttcp dport 1080 accept\n\t}\n}\n' > "$FW/input"
    printf 'table inet filter { chain output { type filter hook output priority filter; policy accept;\n ip daddr 192.0.2.1 tcp dport 53 accept comment "loxprox-egress"\n } }\n' > "$FW/output"
    printf 'table inet filter { set geoip_blocklist { type ipv4_addr; flags interval; elements = { 100.64.0.0/24 } } }\n' > "$FW/set4"
    printf 'table inet filter { set geoip_blocklist6 { type ipv6_addr; flags interval; elements = { 2001:db8::/32 } } }\n' > "$FW/set6"
}

test_firewall_integrity() {
    echo ""; echo "━━━ check_firewall_integrity ━━━"
    mkdir -p "$WORK/geoip"
    fw_healthy; fresh_alerts; run_fn check_firewall_integrity
    [[ "$(count_alerts '')" == "0" ]] && pass "healthy ruleset → silent" || fail "alerted: $(cat "$WORK/discord.log")"

    fw_healthy; fresh_alerts; sed -i 's/policy drop/policy accept/' "$FW/input"; run_fn check_firewall_integrity
    grep -q '^CRITICAL|Firewall Integrity Failure|.*input policy is not drop' "$WORK/discord.log" && pass "input policy accept → CRITICAL" || fail "policy: $(cat "$WORK/discord.log")"

    fw_healthy; fresh_alerts; echo 'table inet filter { set geoip_blocklist { type ipv4_addr; flags interval; } }' > "$FW/set4"; run_fn check_firewall_integrity
    grep -q '^CRITICAL|.*geoip_blocklist is missing or empty' "$WORK/discord.log" && pass "empty v4 GeoIP set → CRITICAL" || fail "empty v4: $(cat "$WORK/discord.log")"

    fw_healthy; fresh_alerts; rm "$FW/set4"; run_fn check_firewall_integrity
    grep -q '^CRITICAL|.*geoip_blocklist is missing or empty' "$WORK/discord.log" && pass "missing v4 GeoIP set → CRITICAL" || fail "missing v4"

    fw_healthy; fresh_alerts; echo 'table inet filter { set geoip_blocklist6 { type ipv6_addr; flags interval; } }' > "$FW/set6"; run_fn check_firewall_integrity
    grep -q '^CRITICAL|.*geoip_blocklist6 is empty' "$WORK/discord.log" && pass "present but empty v6 set → CRITICAL" || fail "empty v6"

    fw_healthy; fresh_alerts; echo 'table inet filter { chain output { policy accept; } }' > "$FW/output"; run_fn check_firewall_integrity
    grep -q '^CRITICAL|.*no output rule commented loxprox-egress' "$WORK/discord.log" && pass "v6 drop rule deployed but egress rule gone → CRITICAL" || fail "egress gone: $(cat "$WORK/discord.log")"

    fw_healthy; fresh_alerts; sed -i '/geoip_blocklist6/d' "$FW/input"; run_fn check_firewall_integrity
    grep -q "^CRITICAL|.*input rule 'ip6 saddr @geoip_blocklist6 drop' is missing" "$WORK/discord.log" && pass "egress deployed but v6 drop rule gone → CRITICAL" || fail "v6 rule gone: $(cat "$WORK/discord.log")"

    fw_healthy; fresh_alerts; sed -i '/ip saddr @geoip_blocklist drop/d' "$FW/input"; run_fn check_firewall_integrity
    if grep -q "^CRITICAL|.*input rule 'ip saddr @geoip_blocklist drop' is missing" "$WORK/discord.log" \
            && ! grep -q "geoip_blocklist6 drop' is missing" "$WORK/discord.log"; then
        pass "v4 GeoIP drop rule gone (v6 rule still there) → CRITICAL naming the v4 rule only"
    else
        fail "v4 rule gone: $(cat "$WORK/discord.log")"
    fi

    fw_healthy; fresh_alerts; rm "$FW/set6"; sed -i '/geoip_blocklist6/d' "$FW/input"; echo 'table inet filter { chain output { policy accept; } }' > "$FW/output"; run_fn check_firewall_integrity
    if grep -q '^WARNING|Firewall Hardening Not Deployed' "$WORK/discord.log" && [[ "$(count_alerts CRITICAL)" == "0" ]]; then
        pass "old deploy (neither v6 drop rule nor egress rule yet) → WARNING, not CRITICAL"
    else
        fail "old deploy: $(cat "$WORK/discord.log")"
    fi

    # F6: the chains every cycle, the (large) set listings at most hourly.
    fw_healthy; fresh_alerts; rm -f "$STATE/fw_sets_last_run"; : > "$WORK/nft.log"
    run_fn check_firewall_integrity FW_SET_CHECK_INTERVAL=3600
    local sets_first; sets_first=$(grep -c '^list set inet filter' "$WORK/nft.log")
    : > "$WORK/nft.log"
    echo 'table inet filter { set geoip_blocklist { type ipv4_addr; flags interval; } }' > "$FW/set4"
    sed -i 's/policy drop/policy accept/' "$FW/input"
    run_fn check_firewall_integrity FW_SET_CHECK_INTERVAL=3600
    if [[ "$sets_first" == "2" ]] && ! grep -q '^list set' "$WORK/nft.log" && grep -q '^list chain inet filter input' "$WORK/nft.log"; then
        pass "within the hour: chains listed again, the GeoIP sets not (first run listed both)"
    else
        fail "nft calls: first run $sets_first set listings; second run: $(tr '\n' ';' < "$WORK/nft.log")"
    fi
    if grep -q 'input policy is not drop' "$WORK/discord.log" && ! grep -q 'geoip_blocklist is missing or empty' "$WORK/discord.log"; then
        pass "…so a policy change is caught on the next cycle, an emptied set only at the hourly check"
    else
        fail "second-run alert: $(cat "$WORK/discord.log")"
    fi
    fresh_alerts; echo $(( $(date +%s) - 3601 )) > "$STATE/fw_sets_last_run"; : > "$WORK/nft.log"
    run_fn check_firewall_integrity FW_SET_CHECK_INTERVAL=3600
    if [[ "$(grep -c '^list set inet filter' "$WORK/nft.log")" == "2" ]] && grep -q 'geoip_blocklist is missing or empty' "$WORK/discord.log"; then
        pass "after the hour: sets listed again and the empty v4 set reported"
    else
        fail "hourly re-check: $(tr '\n' ';' < "$WORK/nft.log") / $(cat "$WORK/discord.log")"
    fi
    rm -f "$STATE/fw_sets_last_run"

    fresh_alerts; clear_fw; run_fn check_firewall_integrity
    grep -q '^CRITICAL|' "$WORK/discord.log" && pass "unreadable ruleset (nft errors) → CRITICAL" || fail "unreadable ruleset silent"

    fw_healthy; fresh_alerts; sed -i 's/policy drop/policy accept/' "$FW/input"; run_fn check_firewall_integrity; run_fn check_firewall_integrity
    [[ "$(count_alerts CRITICAL)" == "1" ]] && pass "cooldown: one alert while the fault persists" || fail "spam: $(count_alerts CRITICAL)"

    fw_healthy; fresh_alerts; rm "$FW/set4" "$FW/set6"; touch "$WORK/geoip/disabled"; run_fn check_firewall_integrity
    [[ "$(count_alerts 'geoip_blocklist')" == "0" ]] && pass "GeoIP disabled → set checks skipped" || fail "set checks ran while disabled"
    rm -f "$WORK/geoip/disabled"
    grep -qE '^[[:space:]]+check_firewall_integrity$' "$MONITOR" && pass "main() runs check_firewall_integrity" || fail "not in main()"
}

# ── pending security updates ─────────────────────────────────────────────────

test_security_updates() {
    echo ""; echo "━━━ check_security_updates ━━━"
    local seen="$STATE/security-updates-seen.json" now; now=$(date +%s)
    cat > "$WORK/apt.txt" <<'EOF'
Reading package lists...
Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/oldstable-security [amd64])
Inst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.8/stable [all])
Inst crowdsec [1.6.2] (1.6.4 crowdsec:bookworm [amd64])
Conf libssl3 (3.0.11-1~deb12u2 Debian-Security:12/oldstable-security [amd64])
EOF
    fresh_alerts; rm -f "$seen" "$STATE/sec_updates_last_run"
    run_fn check_security_updates
    if jq -e '.pending["libssl3=3.0.11-1~deb12u2"] > 0 and (.pending | length) == 1' "$seen" >/dev/null; then
        pass "first-seen recorded per package=version; only Debian-Security lines count"
    else
        fail "state: $(cat "$seen" 2>&1)"
    fi
    [[ "$(count_alerts WARNING)" == "0" ]] && pass "fresh pending update → no alert yet" || fail "alerted on a fresh update"
    grep -q '^INFO|CrowdSec Update Available|.*crowdsec=1.6.4' "$WORK/discord.log" && pass "crowdsec package update → INFO" || fail "no INFO: $(cat "$WORK/discord.log")"
    rm -f "$STATE/sec_updates_last_run"; run_fn check_security_updates
    [[ "$(count_alerts INFO)" == "1" ]] && pass "…at most once per version" || fail "INFO repeated: $(count_alerts INFO)"

    jq --argjson t $((now - 3 * 86400)) '.pending["libssl3=3.0.11-1~deb12u2"] = $t' "$seen" > "$seen.t" && mv "$seen.t" "$seen"
    rm -f "$STATE/sec_updates_last_run"; run_fn check_security_updates
    if grep -q '^WARNING|Security Updates Not Installing|.*libssl3=3.0.11-1~deb12u2 (pending 3d)' "$WORK/discord.log"; then
        pass "pending for 3 days (> 2) → WARNING naming package, version and age"
    else
        fail "no overdue alert: $(cat "$WORK/discord.log")"
    fi
    rm -f "$STATE/sec_updates_last_run"; run_fn check_security_updates
    [[ "$(count_alerts 'Security Updates Not Installing')" == "1" ]] && pass "overdue alert has a daily cooldown" || fail "overdue repeated"

    printf 'Reading package lists...\n' > "$WORK/apt.txt"
    rm -f "$STATE/sec_updates_last_run"; run_fn check_security_updates
    jq -e '(.pending | length) == 0' "$seen" >/dev/null && pass "an installed update drops out of the pending list" || fail "stale pending: $(cat "$seen")"

    : > "$WORK/discord.log"; rm -f "${STATE:?}"/alert_*; echo "$now" > "$STATE/sec_updates_last_run"
    jq --argjson t 1 '.pending["x=1"] = $t' "$seen" > "$seen.t" && mv "$seen.t" "$seen"
    run_fn check_security_updates SEC_UPDATE_CHECK_INTERVAL=3600
    [[ "$(count_alerts '')" == "0" ]] && pass "apt is simulated at most once per interval" || fail "ignored the interval"
    grep -qE '^[[:space:]]+check_security_updates$' "$MONITOR" && pass "main() runs check_security_updates" || fail "not in main()"
}

# ── global auth rate ─────────────────────────────────────────────────────────

alog() {   # alog <path> <status> [n]
    local i
    for ((i = 0; i < ${3:-1}; i++)); do
        printf '203.0.113.9 - - [19/Oct/2026:10:00:00 +0000] "GET %s HTTP/1.1" %s 120 "-" "Loxone"\n' "$1" "$2" >> "$WORK/access.log"
    done
}

test_auth_rate() {
    echo ""; echo "━━━ check_auth_rate ━━━"
    grep -q 'AUTH_RATE_ALERT_PER_CYCLE:-20}' "$MONITOR" && pass "default threshold is 20 per cycle (60 s timer; live baseline 0-5 per day)" || fail "default threshold is not 20"
    fresh_alerts; rm -f "$STATE/last_auth_rate_pos" "$WORK/access.log"
    alog "/jdev/sys/gettoken/<redacted>" 200 100
    run_fn check_auth_rate AUTH_RATE_ALERT_PER_CYCLE=5
    [[ "$(count_alerts '')" == "0" ]] && pass "first run only sets the baseline (history is not a burst)" || fail "alerted on history"

    alog "/jdev/sys/gettoken/<redacted>" 200 3
    alog "/jdev/sys/getkey2/<redacted>" 200 1
    alog "/jdev/sps/LoxAPPversion3" 200 50
    run_fn check_auth_rate AUTH_RATE_ALERT_PER_CYCLE=5
    [[ "$(count_alerts '')" == "0" ]] && pass "4 auth requests (+50 non-auth) at or below threshold 5 → quiet" || fail "alerted below threshold"

    alog "/jdev/sys/getjwt/<redacted>" 200 3
    alog "/jdev/sys/authwithtoken/<redacted>" 401 1
    alog "/jdev/sys/refreshjwt/<redacted>" 200 1
    alog "/jdev/sys/getkey" 200 1
    alog "/jdev/sys/keyexchange/<redacted>" 200 4    # not an auth path in the nginx map / auth-bf
    alog "/jdev/sys/gettoken/<redacted>" 301 20
    run_fn check_auth_rate AUTH_RATE_ALERT_PER_CYCLE=5
    local line; line=$(grep 'Auth Request Rate' "$WORK/discord.log" || true)
    if [[ "$line" == WARNING\|* ]] && grep -q '6 authentication requests' <<<"$line" && grep -q 'threshold 5' <<<"$line"; then
        pass "6 auth requests in the cycle (getjwt, authwithtoken, refreshjwt, bare getkey; keyexchange and the 20 cleartext 301s excluded) → WARNING with count"
    else
        fail "alert: $line"
    fi

    # F7: the deprecated dev/ spelling is the same command (nginx map, auth-bf).
    : > "$WORK/discord.log"; rm -f "${STATE:?}"/alert_*
    alog "/dev/sys/getkey2/<redacted>" 200 4
    alog "/dev/sys/gettoken/<redacted>" 200 2
    alog "/dev/sps/io/x/on" 200 30
    run_fn check_auth_rate AUTH_RATE_ALERT_PER_CYCLE=5
    line=$(grep 'Auth Request Rate' "$WORK/discord.log" || true)
    if grep -q '6 authentication requests' <<<"$line"; then
        pass "/dev/sys/<cmd>/<redacted> (no j) counts like /jdev/: 6 → WARNING; /dev/sps/ is not auth"
    else
        fail "dev/ spelling not counted: $line"
    fi

    : > "$WORK/discord.log"; rm -f "${STATE:?}"/alert_*
    run_fn check_auth_rate AUTH_RATE_ALERT_PER_CYCLE=5
    [[ "$(count_alerts '')" == "0" ]] && pass "nothing new since the last cycle → quiet" || fail "re-counted old lines"

    : > "$WORK/access.log"
    alog "/jdev/sys/gettoken/<redacted>" 200 7
    run_fn check_auth_rate AUTH_RATE_ALERT_PER_CYCLE=5
    [[ "$(count_alerts 'Auth Request Rate')" == "1" ]] && pass "log rotation (file shrank): the new file is counted from the top" || fail "rotation: $(cat "$WORK/discord.log")"
    grep -qE '^[[:space:]]+check_auth_rate$' "$MONITOR" && pass "main() runs check_auth_rate" || fail "not in main()"
}

# ── new local bans: SOFT per ban, HARD into the daily digest ─────────────────

# Contract fixtures: scenario names seen live, and the class each must get.
HARD_FIXTURES=(crowdsecurity/vpatch-CVE-2025-29927 crowdsecurity/vpatch-env-access crowdsecurity/appsec-vpatch
    crowdsecurity/http-cve-2021-41773 crowdsecurity/CVE-2022-26134 crowdsecurity/grafana-cve-2021-43798
    crowdsecurity/http-sensitive-files crowdsecurity/http-backdoors-attempts crowdsecurity/http-path-traversal-probing
    crowdsecurity/http-admin-interface-probing crowdsecurity/http-open-proxy loxprox/scanner-trap)
SOFT_FIXTURES=(crowdsecurity/http-probing crowdsecurity/http-bad-user-agent crowdsecurity/http-crawl-non_statics
    crowdsecurity/nginx-req-limit-exceeded crowdsecurity/http-technology-probing LePresidente/http-generic-401-bf
    loxprox/unknown-path loxprox/auth-bf repeat-offender-2)

# stdin "id|ip|scenario|origin[|simulated]" → `cscli decisions list -o json` in
# the 1.8.1 shape: alerts, each with its decisions nested (the alert's source
# object has a value too, but no duration).
mkdecisions() {
    jq -Rn '[inputs | select(length > 0) | split("|") as $f | (($f[4] // "false") == "true") as $sim
             | {id: ($f[0] | tonumber), scenario: $f[2], simulated: $sim, created_at: "2026-10-19T07:00:00Z",
                source: {ip: $f[1], scope: "Ip", value: $f[1]},
                decisions: [{id: ($f[0] | tonumber), value: $f[1], origin: $f[3], scenario: $f[2],
                             duration: "167h59m", simulated: $sim, type: "ban", scope: "Ip"}]}]' > "$WORK/decisions.json"
}
# stdin "scenario|simulated" → `cscli alerts list -o json`
mkalerts() {
    jq -Rn '[inputs | select(length > 0) | split("|") | {scenario: .[0], simulated: (.[1] == "true"), events_count: 1, decisions: []}]' > "$WORK/alerts.json"
}
epoch() { "$REAL_DATE" -u -d "$1" +%s; }
bans_reset() {
    fresh_alerts; : > "$WORK/cscli.log"
    rm -f "$STATE/seen_local_bans" "$STATE/hard-bans-pending" "$STATE/hard_digest_day" "$STATE"/logged_*
}
ban_msg() { grep '^WARNING|New CrowdSec Ban|' "$WORK/discord.log" | tail -n 1; }
digest_msg() { grep '^INFO|Daily HARD Ban Digest|' "$WORK/discord.log" | tail -n 1; }
ips_in() { grep -oE '198\.51\.100\.[0-9]+' <<<"$1" | sort -t. -k4,4n | tr '\n' ' '; }

test_crowdsec_blocks() {
    echo ""; echo "━━━ check_crowdsec_blocks ━━━"
    local i=0 s lines="" line expected=""
    for s in "${HARD_FIXTURES[@]}"; do i=$((i + 1)); lines+="$i|198.51.100.$i|$s|crowdsec"$'\n'; done
    for s in "${SOFT_FIXTURES[@]}"; do i=$((i + 1)); lines+="$i|198.51.100.$i|$s|crowdsec"$'\n'; done
    lines+="22|198.51.100.22|repeat-offender-hard-2|cscli"$'\n'           # progressive-ban extending a HARD ban
    lines+="23|198.51.100.23|crowdsecurity/http-probing|crowdsec|true"$'\n' # simulation mode: bans nothing
    lines+="24|198.51.100.24|loxprox/scanner-trap|crowdsec|true"$'\n'
    printf '%s' "$lines" | mkdecisions
    for i in $(seq 13 21); do expected+="198.51.100.$i "; done

    bans_reset; run_fn check_crowdsec_blocks; local rc=$?
    line=$(ban_msg)
    [[ $rc -eq 0 && "$(count_alerts 'New CrowdSec Ban')" == "1" ]] && pass "one WARNING for the batch of new bans" || fail "rc=$rc alerts: $(cat "$WORK/discord.log")"
    [[ "$(ips_in "$line")" == "$expected" ]] && pass "it lists exactly the 9 SOFT bans (contract fixtures), no HARD and no simulated one" \
        || fail "listed: $(ips_in "$line") expected: $expected"
    local leaked=""
    for s in "${HARD_FIXTURES[@]}"; do grep -qF "$s" <<<"$line" && leaked+="$s "; done
    [[ -z "$leaked" ]] && pass "no HARD scenario name in the per-ban alert" || fail "HARD in per-ban alert: $leaked"

    run_fn check_hard_ban_digest TZ=UTC BAN_DIGEST_HOUR=0
    line=$(digest_msg)
    if grep -qF 'New HARD bans (unambiguous scanners) in the last 24 h: 12\n' <<<"$line" \
            && grep -qF '      7  other (7 scenarios)\n' <<<"$line" \
            && grep -qF 'Returning scanners whose ban progressive-ban extended: 1\n' <<<"$line"; then
        pass "the 12 HARD bans (not the simulated trap hit) reach the digest: top 5 + other (7), 1 extension"
    else
        fail "digest: $line"
    fi

    : > "$WORK/discord.log"; run_fn check_crowdsec_blocks
    [[ "$(count_alerts '')" == "0" ]] && pass "same bans next cycle → no alert" || fail "re-alerted: $(cat "$WORK/discord.log")"
    printf '%s99|198.51.100.99|crowdsecurity/http-bad-user-agent|crowdsec\n' "$lines" | mkdecisions
    run_fn check_crowdsec_blocks
    [[ "$(ips_in "$(ban_msg)")" == "198.51.100.99 " ]] && pass "one new SOFT ban → an alert for that one only" || fail "alert: $(ban_msg)"

    # Cap: 20 new SOFT bans, worst-case field lengths.
    bans_reset
    lines=""
    for i in $(seq 1 20); do lines+="$i|2001:db8:ffff:ffff:ffff:ffff:ffff:ff$(printf '%02d' "$i")|crowdsecurity/an-unusually-long-scenario-name-for-the-size-test|crowdsec"$'\n'; done
    printf '%s' "$lines" | mkdecisions
    run_fn check_crowdsec_blocks
    line=$(ban_msg); local msg="${line#WARNING|New CrowdSec Ban|}"
    if [[ "$(grep -o ' — ' <<<"$line" | wc -l)" == "15" ]] && grep -qF '… and 5 more\n' <<<"$line"; then
        pass "20 new bans → 15 entries, then '… and 5 more'"
    else
        fail "cap: $line"
    fi
    (( ${#msg} < 2000 )) && pass "worst-case message is ${#msg} characters (< 2000)" || fail "message is ${#msg} characters"

    # --limit 0: 150 active bans; the fake cscli returns 100 without it.
    bans_reset; lines=""
    for i in $(seq 1 150); do lines+="$i|198.51.$((i / 100)).$((i % 100))|crowdsecurity/http-probing|crowdsec"$'\n'; done
    printf '%s' "$lines" | mkdecisions
    run_fn check_crowdsec_blocks
    if [[ "$(grep -c '' "$STATE/seen_local_bans")" == "150" ]] && grep -qF '… and 135 more' "$WORK/discord.log"; then
        pass "all 150 active bans are listed and remembered (--limit 0)"
    else
        fail "seen $(grep -c '' "$STATE/seen_local_bans") bans: $(ban_msg | tail -c 120)"
    fi

    # Failures never abort the cycle and never wipe the seen list.
    local before; before=$(cat "$STATE/seen_local_bans")
    : > "$WORK/discord.log"
    run_fn check_crowdsec_blocks FAKE_CSCLI_RC=1; rc=$?
    [[ $rc -eq 0 && "$(cat "$STATE/seen_local_bans")" == "$before" && "$(count_alerts '')" == "0" ]] \
        && pass "cscli failing → return 0, no alert, seen list kept" || fail "cscli failure: rc=$rc"
    echo 'not json' > "$WORK/decisions.json"
    run_fn check_crowdsec_blocks FAKE_RAW=1; rc=$?
    if [[ $rc -eq 0 && "$(cat "$STATE/seen_local_bans")" == "$before" && "$(count_alerts '')" == "0" ]] \
            && grep -q 'not parseable JSON' "$WORK/monitor.log"; then
        pass "unparseable output → return 0, logged, seen list kept (no re-alert storm next cycle)"
    else
        fail "jq failure: rc=$rc"
    fi

    # The class comes from BAN_HARD_SCENARIOS in config.env, as deploy.sh writes it.
    printf '1|198.51.100.1|crowdsecurity/http-probing|crowdsec\n2|198.51.100.2|loxprox/scanner-trap|crowdsec\n' | mkdecisions
    printf '%s\n' '# LoxProx — Runtime Configuration' 'BAN_HARD_SCENARIOS="^crowdsecurity/http-probing$"' > "$WORK/custom.env"
    bans_reset; run_fn check_crowdsec_blocks LOXPROX_CONFIG="$WORK/custom.env"
    [[ "$(ips_in "$(ban_msg)")" == "198.51.100.2 " ]] && pass "a custom BAN_HARD_SCENARIOS from config.env is honoured" || fail "custom regex: $(ban_msg)"
    local deploy_default
    deploy_default=$(sed -nE "s/^_LOXPROX_HARD_SCENARIOS_DEFAULT='(.*)'$/\1/p" "$PROJECT_DIR/deploy.sh")
    printf 'BAN_HARD_SCENARIOS="%s"\n' "$deploy_default" > "$WORK/default.env"
    bans_reset; run_fn check_crowdsec_blocks LOXPROX_CONFIG="$WORK/default.env"
    [[ -n "$deploy_default" && "$(ips_in "$(ban_msg)")" == "198.51.100.1 " ]] \
        && pass "deploy.sh's default regex, double-quoted in config.env, sources and classifies (trap → digest)" || fail "default via config.env: $(ban_msg)"
    bans_reset; run_fn check_crowdsec_blocks 'BAN_HARD_SCENARIOS=(unclosed'
    if [[ "$(ips_in "$(ban_msg)")" == "198.51.100.1 " ]] && grep -q 'BAN_HARD_SCENARIOS does not compile' "$WORK/monitor.log"; then
        pass "a regex that does not compile → logged, the default is used"
    else
        fail "bad regex: $(ban_msg)"
    fi

    local mon_default pb_default
    mon_default=$( LOXPROX_CONFIG="$WORK/none.env" LOXPROX_STATE_DIR="$STATE" LOXPROX_MONITOR_LOG="$WORK/monitor.log"
                   # shellcheck source=../security-monitoring/gateway-monitor.sh
                   source "$MONITOR"; printf '%s' "$_LOXPROX_HARD_SCENARIOS_DEFAULT" )
    [[ "$mon_default" == "$deploy_default" ]] && pass "the monitor's default regex is deploy.sh's" || fail "monitor default differs from deploy.sh"
    if command -v python3 >/dev/null 2>&1; then
        pb_default=$(LOXPROX_CONFIG="$WORK/none.env" python3 -c 'import importlib.util, sys
s = importlib.util.spec_from_file_location("pb", sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(m.DEFAULT_HARD_SCENARIOS, end="")' "$PROJECT_DIR/progressive-ban.py" 2>/dev/null)
        [[ "$mon_default" == "$pb_default" ]] && pass "…and progressive-ban.py's" || fail "monitor default differs from progressive-ban.py: $pb_default"
    fi
    grep -qE '^[[:space:]]+check_crowdsec_blocks$' "$MONITOR" && pass "main() runs check_crowdsec_blocks" || fail "not in main()"
}

test_hard_digest() {
    echo ""; echo "━━━ check_hard_ban_digest ━━━"
    local line t_old t_queue t_before t_at t_after t_noon t_next
    t_old=$(epoch '2026-10-18 06:00'); t_queue=$(epoch '2026-10-19 07:00')
    t_before=$(epoch '2026-10-19 07:59'); t_at=$(epoch '2026-10-19 08:00'); t_after=$(epoch '2026-10-19 08:01')
    t_noon=$(epoch '2026-10-19 12:00'); t_next=$(epoch '2026-10-20 09:15')

    bans_reset
    printf '900|198.51.100.200|crowdsecurity/http-open-proxy|crowdsec\n' | mkdecisions
    run_fn check_crowdsec_blocks FAKE_NOW="$t_old"                     # queued 26 h before the digest
    local lines="900|198.51.100.200|crowdsecurity/http-open-proxy|crowdsec"$'\n' n=0 s k
    for s in loxprox/scanner-trap:6 crowdsecurity/http-sensitive-files:5 crowdsecurity/vpatch-env-access:4 \
             crowdsecurity/http-backdoors-attempts:3 crowdsecurity/CVE-2022-26134:2 crowdsecurity/appsec-vpatch:1 \
             crowdsecurity/http-cve-2021-41773:1; do
        for ((k = 0; k < ${s##*:}; k++)); do n=$((n + 1)); lines+="$n|198.51.100.$n|${s%:*}|crowdsec"$'\n'; done
    done
    printf '%s' "$lines" | mkdecisions
    run_fn check_crowdsec_blocks FAKE_NOW="$t_queue"
    [[ "$(count_alerts '')" == "0" ]] && pass "HARD bans raise no per-ban alert" || fail "alerted: $(cat "$WORK/discord.log")"

    run_fn check_hard_ban_digest TZ=UTC FAKE_NOW="$t_before"
    [[ "$(count_alerts '')" == "0" ]] && pass "07:59 → no digest yet (BAN_DIGEST_HOUR default 8)" || fail "digest before 08:00"
    run_fn check_hard_ban_digest TZ=UTC FAKE_NOW="$t_at"
    line=$(digest_msg)
    [[ "$(count_alerts 'Daily HARD Ban Digest')" == "1" && "$line" == INFO\|* ]] && pass "08:00 → one INFO digest" || fail "no digest at 08:00: $(cat "$WORK/discord.log")"
    if grep -qF 'in the last 24 h: 22\n      6  loxprox/scanner-trap\n      5  crowdsecurity/http-sensitive-files\n      4  crowdsecurity/vpatch-env-access\n      3  crowdsecurity/http-backdoors-attempts\n      2  crowdsecurity/CVE-2022-26134\n      2  other (2 scenarios)\n' <<<"$line"; then
        pass "22 bans in the last 24 h (the 26-h-old one not), top 5 by count, then 'other (2 scenarios)'"
    else
        fail "digest body: $line"
    fi
    ! grep -q 'TRAP_BAN_MODE' <<<"$line" && ! grep -q 'alerts list' "$WORK/cscli.log" && pass "TRAP_BAN_MODE=ban: no trap section, no alerts query" || fail "trap section in ban mode"
    run_fn check_hard_ban_digest TZ=UTC FAKE_NOW="$t_after"
    [[ "$(count_alerts 'Daily HARD Ban Digest')" == "1" ]] && pass "08:01 → not again the same day" || fail "digest repeated"

    printf '%s950|198.51.100.250|loxprox/scanner-trap|crowdsec\n951|198.51.100.251|loxprox/scanner-trap|crowdsec\n' "$lines" | mkdecisions
    run_fn check_crowdsec_blocks FAKE_NOW="$t_noon"
    run_fn check_hard_ban_digest TZ=UTC FAKE_NOW="$t_next"
    line=$(digest_msg)
    if [[ "$(count_alerts 'Daily HARD Ban Digest')" == "2" ]] && grep -qF 'in the last 24 h: 2\n      2  loxprox/scanner-trap\n' <<<"$line"; then
        pass "next day 09:15 → the next digest counts only the bans since the previous one"
    else
        fail "second digest: $line"
    fi

    # Observe mode: the trap alerts that did not ban, from config.env.
    bans_reset
    { for k in $(seq 60); do echo 'loxprox/scanner-trap|true'; done
      for k in $(seq 3); do echo 'loxprox/scanner-trap|false'; done
      for k in $(seq 5); do echo 'crowdsecurity/http-probing|true'; done; } | mkalerts
    printf '%s\n' 'TRAP_BAN_MODE="observe"' > "$WORK/observe.env"
    run_fn check_hard_ban_digest TZ=UTC BAN_DIGEST_HOUR=0 LOXPROX_CONFIG="$WORK/observe.env"
    line=$(digest_msg)
    if grep -qF 'TRAP_BAN_MODE=observe: 60 trap alert(s) in the last 24 h were observed (simulated, not banned).' <<<"$line" \
            && grep -qF 'review /var/log/nginx/loxprox-trap-hosts.log, then set TRAP_BAN_MODE=ban' <<<"$line"; then
        pass "observe mode: 60 simulated trap alerts counted (all of them: --limit 0, -s, simulated only) + the review line"
    else
        fail "observe digest: $line"
    fi
    grep -q -- '-s loxprox/scanner-trap --since 24h -o json --limit 0' "$WORK/cscli.log" && pass "…queried for the last 24 h" || fail "alerts query: $(cat "$WORK/cscli.log")"
    bans_reset
    run_fn check_hard_ban_digest TZ=UTC BAN_DIGEST_HOUR=0 TRAP_BAN_MODE=observe FAKE_ALERTS_RC=1; local rc=$?
    line=$(digest_msg)
    if [[ $rc -eq 0 ]] && grep -qF 'trap alert count is unavailable' <<<"$line" && grep -qF 'then set TRAP_BAN_MODE=ban' <<<"$line" \
            && grep -qF 'in the last 24 h: 0' <<<"$line"; then
        pass "cscli failing in observe mode → the digest still goes out, saying the count is unavailable"
    else
        fail "rc=$rc digest: $line"
    fi
    bans_reset
    run_fn check_hard_ban_digest TZ=UTC BAN_DIGEST_HOUR=25 FAKE_NOW="$t_before"
    run_fn check_hard_ban_digest TZ=UTC BAN_DIGEST_HOUR=25 FAKE_NOW="$t_at"
    [[ "$(count_alerts 'Daily HARD Ban Digest')" == "1" ]] && pass "an invalid BAN_DIGEST_HOUR falls back to 08:00" || fail "invalid hour: $(count_alerts 'Daily HARD Ban Digest') digests"
    grep -qE '^[[:space:]]+check_hard_ban_digest$' "$MONITOR" && pass "main() runs check_hard_ban_digest" || fail "not in main()"
}

echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  LoxProx — gateway-monitor breach-hardening checks"
echo "═══════════════════════════════════════════════════════════════════════════════"
test_crowdsec_blocks
test_hard_digest
test_asn_session
test_firewall_integrity
test_security_updates
test_auth_rate

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"
[[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
