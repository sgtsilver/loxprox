#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — GeoIP Blocking
# ═══════════════════════════════════════════════════════════════════════════════
# Downloads country IP blocklists from ipdeny.com and adds them to nftables.
# Conservative default: blocks high-risk scanning countries only.
# Can be disabled by setting GEOIP_ENABLED="false".
#
# 2026-10: a refresh that fails keeps the last known-good list (unchanged), but
# it now (a) retries each list with backoff instead of giving up on the first
# slow or failed transfer, (b) logs WHY a list failed (the old `curl -s` with
# stderr discarded left only "failed countries: cn ru"), (c) validates every
# list before it can replace the active one, and (d) stamps success and
# failure so gateway-monitor.sh and the panel can flag a list that has not
# refreshed for days.
#
# 2026-10 breach hardening: IPv6 too. ipdeny publishes the same countries as
# IPv6 lists under /ipv6/ipaddresses/blocks/<cc>.zone (a country with no IPv6
# allocation, e.g. kp, answers 404 and is skipped). The two families refresh
# independently with the same sanity checks and shrink guard: a v6 failure
# never costs the v4 refresh and vice versa, each has its own stamps
# (last-success / last-success6, last-failure / last-failure6) and its own
# staleness alert. The v6 set is loaded in ONE nft transaction (flush + add).
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# 2026-10: deploy.conf values (GEOIP_IPV6_ENABLED, GEOIP_URL_BASE6, …) reach
# this script through config.env, like every other LoxProx script — cron
# gives it no environment. Loaded before the defaults below.
CONFIG_FILE="${LOXPROX_CONFIG:-/etc/loxprox/config.env}"
if [[ -f "$CONFIG_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    set +a
fi

GEOIP_ENABLED="${GEOIP_ENABLED:-true}"
BLOCKLIST_DIR="${GEOIP_BLOCKLIST_DIR:-/var/lib/loxone-geoip}"
NFTABLES_GEOIP="${GEOIP_NFT_FILE:-/etc/nftables.d/99-geoip.conf}"
GEOIP_URL_BASE="${GEOIP_URL_BASE:-https://www.ipdeny.com/ipblocks/data/countries}"
GEOIP_URL_BASE6="${GEOIP_URL_BASE6:-https://www.ipdeny.com/ipv6/ipaddresses/blocks}"
GEOIP_IPV6_ENABLED="${GEOIP_IPV6_ENABLED:-true}"

# Retries: seconds to wait before attempt 2, 3, 4 (backoff). The two failing
# lists on 2026-10-06 (cn, ru) are the largest (~140-180 KB); a slow transfer
# hit the old 30 s cap. deploy.sh passes a shorter schedule for its own run.
GEOIP_RETRY_DELAYS="${GEOIP_RETRY_DELAYS:-30 120 300}"
GEOIP_CONNECT_TIMEOUT="${GEOIP_CONNECT_TIMEOUT:-15}"
GEOIP_MAX_TIME="${GEOIP_MAX_TIME:-120}"

# Sanity bounds a downloaded list must meet before it may replace the active
# one: at least GEOIP_MIN_RANGES valid CIDRs, no line that is not a CIDR of its family
# (an HTML error page answered with 200 must never reach nftables), and no
# shrink by more than GEOIP_MAX_SHRINK_PCT against the last known-good list.
GEOIP_MIN_RANGES="${GEOIP_MIN_RANGES:-1}"
GEOIP_MAX_SHRINK_PCT="${GEOIP_MAX_SHRINK_PCT:-50}"

# Minimum fraction of country lists that must download successfully before we
# replace the active blocklist. Below this threshold we keep the last known-good
# rules so a partial outage at ipdeny.com cannot silently shrink coverage.
: "${GEOIP_MIN_SUCCESS_RATIO:=1.0}"

# Countries to block (ISO 3166-1 alpha-2 codes)
# Default: known high-volume scanning / botnet sources
BLOCK_COUNTRIES=(
    "cn"  # China
    "ru"  # Russia
    "kp"  # North Korea
    "ir"  # Iran
)

# Freshness stamps, read by gateway-monitor.sh (staleness alert) and the panel.
STAMP_OK="${BLOCKLIST_DIR}/last-success"        # "<epoch> <ranges>"
STAMP_FAIL="${BLOCKLIST_DIR}/last-failure"      # "<epoch> <reason>"
STAMP_OK6="${BLOCKLIST_DIR}/last-success6"
STAMP_FAIL6="${BLOCKLIST_DIR}/last-failure6"
MARK_DISABLED="${BLOCKLIST_DIR}/disabled"

OCTET='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
CIDR_RE="${OCTET}\.${OCTET}\.${OCTET}\.${OCTET}/(3[0-2]|[12]?[0-9])"
# IPv6: hex groups with at least one colon, prefix 0-128. Shape check only; the
# atomic nft load is the real parser and keeps the old set if it rejects a line.
CIDR6_RE='[0-9A-Fa-f:]*:[0-9A-Fa-f:]*/(12[0-8]|1[01][0-9]|[1-9]?[0-9])'

FETCH_REASONS=()

write_stamp() {
    local file="$1"; shift
    printf '%s %s\n' "$(date +%s)" "$*" > "${file}.tmp" && mv -f "${file}.tmp" "$file"
}

cidr_re() { if [[ "${1:-4}" == 6 ]]; then echo "$CIDR6_RE"; else echo "$CIDR_RE"; fi; }
zone_file() {   # <cc> [family] -> active list path
    if [[ "${2:-4}" == 6 ]]; then echo "${BLOCKLIST_DIR}/${1}.zone6"; else echo "${BLOCKLIST_DIR}/${1}.zone"; fi
}

count_ranges() {   # valid CIDR lines of family $2 (default 4) in $1 (0 if the file is missing)
    [[ -f "$1" ]] || { echo 0; return 0; }
    grep -cE "^$(cidr_re "${2:-4}")[[:space:]]*$" "$1" || true
}

# Prints the reason and returns 1 when $1 must not replace the active list of ${cc}.
validate_zone() {
    local file="$1" cc="$2" fam="${3:-4}" valid invalid prev re
    re=$(cidr_re "$fam")
    valid=$(count_ranges "$file" "$fam")
    invalid=$(grep -cvE "^(${re})?[[:space:]]*$" "$file" || true)
    if (( invalid > 0 )); then
        echo "${invalid} line(s) are not IPv${fam} CIDRs (error page instead of a list?)"
        return 1
    fi
    if (( valid < GEOIP_MIN_RANGES )); then
        echo "only ${valid} valid range(s), need at least ${GEOIP_MIN_RANGES}"
        return 1
    fi
    prev=$(count_ranges "$(zone_file "$cc" "$fam")" "$fam")
    if (( prev > 0 && valid * 100 < prev * (100 - GEOIP_MAX_SHRINK_PCT) )); then
        echo "shrank from ${prev} to ${valid} ranges (more than ${GEOIP_MAX_SHRINK_PCT}%)"
        return 1
    fi
    return 0
}

# Downloads the list of ${cc} to <active>.new with retries + backoff; on final
# failure records the reason in FETCH_REASONS and returns 1. Returns 2 when the
# provider publishes no IPv6 list for the country (HTTP 404): not a failure.
fetch_country() {
    local cc="$1" fam="${2:-4}"
    local url out
    if [[ "$fam" == 6 ]]; then url="${GEOIP_URL_BASE6}/${cc}.zone"; else url="${GEOIP_URL_BASE}/${cc}.zone"; fi
    out="$(zone_file "$cc" "$fam").new"
    local -a delays
    read -r -a delays <<<"0 ${GEOIP_RETRY_DELAYS}"
    local errf attempt=0 delay code rc reason=""
    errf=$(mktemp)
    for delay in "${delays[@]}"; do
        attempt=$((attempt + 1))
        if (( delay > 0 )); then sleep "$delay"; fi
        rc=0
        code=$(curl -sS -f --connect-timeout "$GEOIP_CONNECT_TIMEOUT" --max-time "$GEOIP_MAX_TIME" \
                    -o "$out" -w '%{http_code}' "$url" 2>"$errf") || rc=$?
        if (( rc == 0 )); then
            if reason=$(validate_zone "$out" "$cc" "$fam"); then
                (( attempt == 1 )) || echo "GeoIP: ${cc}${fam/4/} fetched on attempt ${attempt}/${#delays[@]}."
                rm -f "$errf"
                return 0
            fi
        else
            reason="curl exit ${rc}, HTTP ${code:-000}: $(head -c 160 "$errf" | tr '\n' ' ')"
            if [[ "$fam" == 6 && "$code" == 404 ]]; then
                echo "GeoIP: no IPv6 list published for ${cc} (HTTP 404) — skipped"
                rm -f "$errf" "$out"
                return 2
            fi
        fi
        echo "GeoIP: ${cc}${fam/4/} attempt ${attempt}/${#delays[@]} failed — ${reason}" >&2
        rm -f "$out"
    done
    rm -f "$errf"
    FETCH_REASONS+=("${cc}: ${reason}")
    return 1
}

# Fetches + validates every country list of one family and promotes them only
# when enough succeeded. Sets PROMOTED<fam>=1 on success; returns 1 on failure
# (stamping the failure, active lists and rules untouched).
refresh_family() {
    local fam="$1" label stamp_fail cc rc total=0 succeeded=0 required r
    local -a failed_countries=()
    if [[ "$fam" == 6 ]]; then label="GeoIP IPv6"; stamp_fail="$STAMP_FAIL6"; else label="GeoIP"; stamp_fail="$STAMP_FAIL"; fi
    FETCH_REASONS=()

    for cc in "${BLOCK_COUNTRIES[@]}"; do
        rc=0
        fetch_country "$cc" "$fam" || rc=$?
        case "$rc" in
            0) total=$((total + 1)); succeeded=$((succeeded + 1)) ;;
            2) ;;   # no IPv6 list for this country
            *) total=$((total + 1)); failed_countries+=("$cc") ;;
        esac
    done

    required=$(awk -v t="$total" -v r="$GEOIP_MIN_SUCCESS_RATIO" 'BEGIN { v = t * r; printf "%d", (v == int(v) ? v : int(v) + 1) }')
    if [[ "$fam" == 6 && "$total" -eq 0 ]]; then
        FETCH_REASONS+=("no country list is published at ${GEOIP_URL_BASE6}")
        failed_countries=("all")
        required=1
    fi
    if [ "$succeeded" -lt "$required" ]; then
        # Fail closed: drop staged downloads, keep current active rules untouched.
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            rm -f "$(zone_file "$cc" "$fam").new"
        done
        echo "${label} update FAILED: only $succeeded/$total country lists fetched (need $required)." >&2
        echo "${label} update FAILED: failed countries: ${failed_countries[*]:-none}" >&2
        for r in "${FETCH_REASONS[@]}"; do echo "${label} update FAILED:   $r" >&2; done
        echo "${label} update FAILED: keeping last known-good blocklist; active nftables rules unchanged." >&2
        logger -t loxprox-geoip -p user.err "${label} update failed: ${succeeded}/${total} lists, failed=[${failed_countries[*]:-none}]; kept last known-good" || true
        write_stamp "$stamp_fail" "${FETCH_REASONS[*]:-${failed_countries[*]:-unknown}}"
        return 1
    fi

    # Promote staged files atomically (per file) into the active blocklist.
    for cc in "${BLOCK_COUNTRIES[@]}"; do
        [ -f "$(zone_file "$cc" "$fam").new" ] || continue
        mv -f "$(zone_file "$cc" "$fam").new" "$(zone_file "$cc" "$fam")"
    done
    if [[ "$fam" == 6 ]]; then PROMOTED6=1; else PROMOTED4=1; fi
    return 0
}

# The persistent include: both sets from the active lists (a family whose
# refresh failed contributes its last known-good list), repopulated at boot.
# An empty set is written without an `elements` block (nft rejects
# `elements = { }`); geoip_blocklist6 is always declared, because
# nftables.conf's drop rule references it.
write_nft_include() {
    local cc cidr first
    {
        echo "# LoxProx — GeoIP blocklist"
        echo "# Generated: $(date -Iseconds)"
        echo "set geoip_blocklist {"
        echo "    type ipv4_addr"
        echo "    flags interval"

        first=true
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            [ -f "$(zone_file "$cc" 4)" ] || continue
            while read -r cidr; do
                [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
                if [ "$first" = true ]; then
                    first=false
                    echo "    elements = {"
                    echo "        $cidr"
                else
                    echo "        , $cidr"
                fi
            done < "$(zone_file "$cc" 4)"
        done

        [ "$first" = true ] || echo "    }"
        echo "}"
        echo "set geoip_blocklist6 {"
        echo "    type ipv6_addr"
        echo "    flags interval"
        first=true
        # 2026-10: GEOIP_IPV6_ENABLED=false → declared, but empty. Never
        # rebuilt from *.zone6 files a previous enabled run left behind.
        [ "$GEOIP_IPV6_ENABLED" = "true" ] || echo "    # empty: GEOIP_IPV6_ENABLED=false"
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            [ "$GEOIP_IPV6_ENABLED" = "true" ] || break
            [ -f "$(zone_file "$cc" 6)" ] || continue
            while read -r cidr; do
                [[ "$cidr" =~ ^[0-9A-Fa-f:]+/[0-9]+$ && "$cidr" == *:* ]] || continue
                if [ "$first" = true ]; then
                    first=false
                    echo "    elements = {"
                    echo "        $cidr"
                else
                    echo "        , $cidr"
                fi
            done < "$(zone_file "$cc" 6)"
        done
        [ "$first" = true ] || echo "    }"
        echo "}"
    } > "$NFTABLES_GEOIP"
}

RULESET_RELOADED=0
reload_full_ruleset() {   # first-deploy path; at most once per run
    (( RULESET_RELOADED )) && return 0
    # Smaller-set case, single shot is fine here.
    if nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf; then
        echo "nftables reloaded (first-deploy path)."
        RULESET_RELOADED=1
        return 0
    fi
    return 1
}

# Update the live IPv4 kernel set incrementally. A single atomic `nft -f` of the
# full ruleset fails with "No buffer space available" once the set passes
# ~20 000 CIDRs — the netlink message representing the transaction exceeds
# what the kernel will accept in one shot (independent of socket buffer
# sysctls; see issue #11). We instead flush the existing set and add elements
# in small batches, each as its own netlink message.
#
# Persistent file `/etc/nftables.d/99-geoip.conf` is still updated above so
# that the set is repopulated at boot via the normal nftables.service reload
# (the boot-time path starts from empty kernel state and currently fits in
# a single transaction; see issue #11 for the long-term plan).
# Prints the number of CIDRs loaded on stdout's last line via ADDED4.
ADDED4=0
load_live_v4() {
    GEOIP_BATCH_SIZE="${GEOIP_BATCH_SIZE:-1000}"
    local added=0 cc cidr batch_file batch_count=0

    if nft list set inet filter geoip_blocklist >/dev/null 2>&1; then
        echo "Updating live geoip_blocklist set in batches of ${GEOIP_BATCH_SIZE}..."
        if ! nft flush set inet filter geoip_blocklist 2>/dev/null; then
            echo "FAILED: could not flush live geoip_blocklist set." >&2
            logger -t loxprox-geoip -p user.err "Live set flush failed; on-disk file is updated but kernel state is stale" || true
            write_stamp "$STAMP_FAIL" "live set flush failed (on-disk list updated, kernel set stale)"
            return 1
        fi

        batch_file=$(mktemp)
        : > "$batch_file"

        flush_batch() {
            [ -s "$batch_file" ] || return 0
            if ! nft add element inet filter geoip_blocklist "{ $(cat "$batch_file") }" 2>/dev/null; then
                echo "FAILED: nft add element rejected batch #${batch_count} (size ~${GEOIP_BATCH_SIZE})." >&2
                logger -t loxprox-geoip -p user.err "Live set partial update — batch ${batch_count} failed at ${added} elements" || true
                write_stamp "$STAMP_FAIL" "live set partial update (batch ${batch_count} rejected at ${added} elements)"
                return 1
            fi
            batch_count=$((batch_count + 1))
            : > "$batch_file"
        }

        # Stream every CIDR from every promoted country file; build comma-separated batches.
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            [ -f "$(zone_file "$cc" 4)" ] || continue
            while read -r cidr; do
                [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
                if [ -s "$batch_file" ]; then
                    echo -n "," >> "$batch_file"
                fi
                echo -n "$cidr" >> "$batch_file"
                added=$((added + 1))
                if [ $((added % GEOIP_BATCH_SIZE)) -eq 0 ]; then
                    flush_batch || { rm -f "$batch_file"; return 1; }
                fi
            done < "$(zone_file "$cc" 4)"
        done
        flush_batch || { rm -f "$batch_file"; return 1; }

        rm -f "$batch_file"
        echo "Live set updated: ${added} CIDRs in ${batch_count} batches."
    else
        # First-deploy path: the set doesn't exist yet, so we need the full ruleset
        # load via /etc/nftables.conf to declare it.
        if reload_full_ruleset; then
            for cc in "${BLOCK_COUNTRIES[@]}"; do
                added=$((added + $(count_ranges "$(zone_file "$cc" 4)" 4)))
            done
        else
            echo "FAILED: nft -f /etc/nftables.conf rejected the ruleset." >&2
            logger -t loxprox-geoip -p user.err "First-deploy reload failed; geoip_blocklist set not declared" || true
            write_stamp "$STAMP_FAIL" "nft -f /etc/nftables.conf rejected the ruleset"
            return 1
        fi
    fi
    ADDED4=$added
    return 0
}

# Update the live IPv6 set in ONE nft transaction (flush + add in a single
# `nft -f`): the kernel applies all of it or none, so a rejected line leaves the
# previous set in place instead of an empty one.
ADDED6=0
load_live_v6() {
    local cc cidr added=0 script
    if ! nft list set inet filter geoip_blocklist6 >/dev/null 2>&1; then
        # Old deploy: the running ruleset does not declare the set yet.
        if reload_full_ruleset; then
            for cc in "${BLOCK_COUNTRIES[@]}"; do
                added=$((added + $(count_ranges "$(zone_file "$cc" 6)" 6)))
            done
            ADDED6=$added
            return 0
        fi
        echo "FAILED: geoip_blocklist6 is not declared and nft -f /etc/nftables.conf rejected the ruleset." >&2
        logger -t loxprox-geoip -p user.err "IPv6 set not declared; ruleset reload failed" || true
        write_stamp "$STAMP_FAIL6" "geoip_blocklist6 not declared and ruleset reload failed"
        return 1
    fi

    script=$(mktemp)
    {
        echo "flush set inet filter geoip_blocklist6"
        local elems=""
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            [ -f "$(zone_file "$cc" 6)" ] || continue
            while read -r cidr; do
                [[ "$cidr" =~ ^[0-9A-Fa-f:]+/[0-9]+$ && "$cidr" == *:* ]] || continue
                elems+="${elems:+, }${cidr}"
            done < "$(zone_file "$cc" 6)"
        done
        [ -z "$elems" ] || echo "add element inet filter geoip_blocklist6 { ${elems} }"
    } > "$script"
    if ! nft -f "$script" 2>/dev/null; then
        rm -f "$script"
        echo "FAILED: nft rejected the IPv6 transaction; live geoip_blocklist6 unchanged." >&2
        logger -t loxprox-geoip -p user.err "Live IPv6 set transaction rejected; kernel set unchanged" || true
        write_stamp "$STAMP_FAIL6" "live IPv6 set transaction rejected (kernel set unchanged)"
        return 1
    fi
    rm -f "$script"
    for cc in "${BLOCK_COUNTRIES[@]}"; do
        added=$((added + $(count_ranges "$(zone_file "$cc" 6)" 6)))
    done
    ADDED6=$added
    echo "Live IPv6 set updated: ${added} CIDRs in one transaction."
    return 0
}

# True when the current include's geoip_blocklist6 still carries elements.
include_has_v6_elements() {
    awk '/^set geoip_blocklist6 \{/ {in6 = 1; next} in6 && /^\}/ {in6 = 0} in6 && /elements/ {found = 1} END {exit !found}' \
        "$NFTABLES_GEOIP" 2>/dev/null
}

# 2026-10: GEOIP_IPV6_ENABLED=false means no IPv6 GeoIP blocking at all, not
# "keep the last list". The active v6 lists go (nothing can rebuild the set
# from them), so do the v6 stamps (the monitor has no v6 list left to call
# stale), the include is rewritten with an empty geoip_blocklist6 when it
# still has elements, and the live set is flushed.
V6_CLEARED=0
disable_v6() {
    local cc
    for cc in "${BLOCK_COUNTRIES[@]}"; do
        rm -f "$(zone_file "$cc" 6)" "$(zone_file "$cc" 6).new"
    done
    rm -f "$STAMP_OK6" "$STAMP_FAIL6"
    if include_has_v6_elements; then V6_CLEARED=1; fi
    if nft list set inet filter geoip_blocklist6 >/dev/null 2>&1 \
            && ! nft flush set inet filter geoip_blocklist6 2>/dev/null; then
        echo "FAILED: GEOIP_IPV6_ENABLED=false, but the live geoip_blocklist6 set could not be flushed." >&2
        logger -t loxprox-geoip -p user.err "IPv6 disabled but live set flush failed" || true
        return 1
    fi
    echo "GeoIP IPv6 disabled: geoip_blocklist6 empty."
    return 0
}

PROMOTED4=0
PROMOTED6=0

main() {
    mkdir -p "$BLOCKLIST_DIR"
    if [ "$GEOIP_ENABLED" != "true" ]; then
        touch "$MARK_DISABLED"   # tells the monitor/panel not to expect refreshes
        echo "GeoIP blocking disabled"
        exit 0
    fi
    rm -f "$MARK_DISABLED"

    # Each family downloads to .new files first and only promotes on success, so
    # an incomplete update keeps its last known-good list (fail closed). One
    # family failing never blocks the other.
    local rc4=0 rc6=0
    refresh_family 4 || rc4=1
    if [ "$GEOIP_IPV6_ENABLED" = "true" ]; then
        refresh_family 6 || rc6=1
    else
        disable_v6 || rc6=1
    fi

    if (( PROMOTED4 || PROMOTED6 || V6_CLEARED )); then
        write_nft_include
        echo "GeoIP blocklist updated: $(wc -l < "$NFTABLES_GEOIP") lines"
    fi

    if (( PROMOTED4 )); then
        if load_live_v4; then write_stamp "$STAMP_OK" "$ADDED4"; else rc4=1; fi
    fi
    if (( PROMOTED6 )); then
        if load_live_v6; then write_stamp "$STAMP_OK6" "$ADDED6"; else rc6=1; fi
    fi

    (( rc4 == 0 && rc6 == 0 )) || exit 1
}

# Only run when executed, not when sourced (tests source it for the helpers).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
