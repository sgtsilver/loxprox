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
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

GEOIP_ENABLED="${GEOIP_ENABLED:-true}"
BLOCKLIST_DIR="${GEOIP_BLOCKLIST_DIR:-/var/lib/loxone-geoip}"
NFTABLES_GEOIP="${GEOIP_NFT_FILE:-/etc/nftables.d/99-geoip.conf}"
GEOIP_URL_BASE="${GEOIP_URL_BASE:-https://www.ipdeny.com/ipblocks/data/countries}"

# Retries: seconds to wait before attempt 2, 3, 4 (backoff). The two failing
# lists on 2026-10-06 (cn, ru) are the largest (~140-180 KB); a slow transfer
# hit the old 30 s cap. deploy.sh passes a shorter schedule for its own run.
GEOIP_RETRY_DELAYS="${GEOIP_RETRY_DELAYS:-30 120 300}"
GEOIP_CONNECT_TIMEOUT="${GEOIP_CONNECT_TIMEOUT:-15}"
GEOIP_MAX_TIME="${GEOIP_MAX_TIME:-120}"

# Sanity bounds a downloaded list must meet before it may replace the active
# one: at least GEOIP_MIN_RANGES valid CIDRs, no line that is not an IPv4 CIDR
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
MARK_DISABLED="${BLOCKLIST_DIR}/disabled"

OCTET='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
CIDR_RE="${OCTET}\.${OCTET}\.${OCTET}\.${OCTET}/(3[0-2]|[12]?[0-9])"

FETCH_REASONS=()

write_stamp() {
    local file="$1"; shift
    printf '%s %s\n' "$(date +%s)" "$*" > "${file}.tmp" && mv -f "${file}.tmp" "$file"
}

count_ranges() {   # valid IPv4 CIDR lines in $1 (0 if the file is missing)
    [[ -f "$1" ]] || { echo 0; return 0; }
    grep -cE "^${CIDR_RE}[[:space:]]*$" "$1" || true
}

# Prints the reason and returns 1 when $1 must not replace ${cc}.zone.
validate_zone() {
    local file="$1" cc="$2" valid invalid prev
    valid=$(count_ranges "$file")
    invalid=$(grep -cvE "^(${CIDR_RE})?[[:space:]]*$" "$file" || true)
    if (( invalid > 0 )); then
        echo "${invalid} line(s) are not IPv4 CIDRs (error page instead of a list?)"
        return 1
    fi
    if (( valid < GEOIP_MIN_RANGES )); then
        echo "only ${valid} valid range(s), need at least ${GEOIP_MIN_RANGES}"
        return 1
    fi
    prev=$(count_ranges "${BLOCKLIST_DIR}/${cc}.zone")
    if (( prev > 0 && valid * 100 < prev * (100 - GEOIP_MAX_SHRINK_PCT) )); then
        echo "shrank from ${prev} to ${valid} ranges (more than ${GEOIP_MAX_SHRINK_PCT}%)"
        return 1
    fi
    return 0
}

# Downloads ${cc}.zone to ${cc}.zone.new with retries + backoff; on final
# failure records the reason in FETCH_REASONS and returns 1.
fetch_country() {
    local cc="$1"
    local url="${GEOIP_URL_BASE}/${cc}.zone" out="${BLOCKLIST_DIR}/${cc}.zone.new"
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
            if reason=$(validate_zone "$out" "$cc"); then
                (( attempt == 1 )) || echo "GeoIP: ${cc} fetched on attempt ${attempt}/${#delays[@]}."
                rm -f "$errf"
                return 0
            fi
        else
            reason="curl exit ${rc}, HTTP ${code:-000}: $(head -c 160 "$errf" | tr '\n' ' ')"
        fi
        echo "GeoIP: ${cc} attempt ${attempt}/${#delays[@]} failed — ${reason}" >&2
        rm -f "$out"
    done
    rm -f "$errf"
    FETCH_REASONS+=("${cc}: ${reason}")
    return 1
}

main() {
    mkdir -p "$BLOCKLIST_DIR"
    if [ "$GEOIP_ENABLED" != "true" ]; then
        touch "$MARK_DISABLED"   # tells the monitor/panel not to expect refreshes
        echo "GeoIP blocking disabled"
        exit 0
    fi
    rm -f "$MARK_DISABLED"

    # Download to .new files first; only promote on success. Track failures so we
    # can fail closed (keep last known-good) when the update is incomplete.
    local total=${#BLOCK_COUNTRIES[@]} succeeded=0 cc
    local -a failed_countries=()
    for cc in "${BLOCK_COUNTRIES[@]}"; do
        if fetch_country "$cc"; then
            succeeded=$((succeeded + 1))
        else
            failed_countries+=("$cc")
        fi
    done

    local required
    required=$(awk -v t="$total" -v r="$GEOIP_MIN_SUCCESS_RATIO" 'BEGIN { v = t * r; printf "%d", (v == int(v) ? v : int(v) + 1) }')
    if [ "$succeeded" -lt "$required" ]; then
        # Fail closed: drop staged downloads, keep current active rules untouched.
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            rm -f "${BLOCKLIST_DIR}/${cc}.zone.new"
        done
        echo "GeoIP update FAILED: only $succeeded/$total country lists fetched (need $required)." >&2
        echo "GeoIP update FAILED: failed countries: ${failed_countries[*]:-none}" >&2
        local r
        for r in "${FETCH_REASONS[@]}"; do echo "GeoIP update FAILED:   $r" >&2; done
        echo "GeoIP update FAILED: keeping last known-good blocklist; active nftables rules unchanged." >&2
        logger -t loxprox-geoip -p user.err "GeoIP update failed: ${succeeded}/${total} lists, failed=[${failed_countries[*]:-none}]; kept last known-good" || true
        write_stamp "$STAMP_FAIL" "${FETCH_REASONS[*]:-${failed_countries[*]:-unknown}}"
        exit 1
    fi

    # Promote staged files atomically (per file) into the active blocklist.
    for cc in "${BLOCK_COUNTRIES[@]}"; do
        [ -f "${BLOCKLIST_DIR}/${cc}.zone.new" ] || continue
        mv -f "${BLOCKLIST_DIR}/${cc}.zone.new" "${BLOCKLIST_DIR}/${cc}.zone"
    done

    # Build nftables set
    {
        echo "# LoxProx — GeoIP blocklist"
        echo "# Generated: $(date -Iseconds)"
        echo "set geoip_blocklist {"
        echo "    type ipv4_addr"
        echo "    flags interval"
        echo "    elements = {"

        local first=true cidr
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            [ -f "${BLOCKLIST_DIR}/${cc}.zone" ] || continue
            while read -r cidr; do
                [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
                if [ "$first" = true ]; then
                    first=false
                    echo "        $cidr"
                else
                    echo "        , $cidr"
                fi
            done < "${BLOCKLIST_DIR}/${cc}.zone"
        done

        echo "    }"
        echo "}"
    } > "$NFTABLES_GEOIP"

    echo "GeoIP blocklist updated: $(wc -l < "$NFTABLES_GEOIP") lines"

    # Update the live kernel set incrementally. A single atomic `nft -f` of the
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

    GEOIP_BATCH_SIZE="${GEOIP_BATCH_SIZE:-1000}"
    local added=0

    if nft list set inet filter geoip_blocklist >/dev/null 2>&1; then
        echo "Updating live geoip_blocklist set in batches of ${GEOIP_BATCH_SIZE}..."
        if ! nft flush set inet filter geoip_blocklist 2>/dev/null; then
            echo "FAILED: could not flush live geoip_blocklist set." >&2
            logger -t loxprox-geoip -p user.err "Live set flush failed; on-disk file is updated but kernel state is stale" || true
            write_stamp "$STAMP_FAIL" "live set flush failed (on-disk list updated, kernel set stale)"
            exit 1
        fi

        batch_file=$(mktemp)
        trap 'rm -f "$batch_file"' EXIT
        batch_count=0
        : > "$batch_file"

        flush_batch() {
            [ -s "$batch_file" ] || return 0
            if ! nft add element inet filter geoip_blocklist "{ $(cat "$batch_file") }" 2>/dev/null; then
                echo "FAILED: nft add element rejected batch #${batch_count} (size ~${GEOIP_BATCH_SIZE})." >&2
                logger -t loxprox-geoip -p user.err "Live set partial update — batch ${batch_count} failed at ${added} elements" || true
                write_stamp "$STAMP_FAIL" "live set partial update (batch ${batch_count} rejected at ${added} elements)"
                exit 1
            fi
            batch_count=$((batch_count + 1))
            : > "$batch_file"
        }

        # Stream every CIDR from every promoted country file; build comma-separated batches.
        local cidr
        for cc in "${BLOCK_COUNTRIES[@]}"; do
            [ -f "${BLOCKLIST_DIR}/${cc}.zone" ] || continue
            while read -r cidr; do
                [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
                if [ -s "$batch_file" ]; then
                    echo -n "," >> "$batch_file"
                fi
                echo -n "$cidr" >> "$batch_file"
                added=$((added + 1))
                if [ $((added % GEOIP_BATCH_SIZE)) -eq 0 ]; then
                    flush_batch
                fi
            done < "${BLOCKLIST_DIR}/${cc}.zone"
        done
        flush_batch

        rm -f "$batch_file"
        trap - EXIT
        echo "Live set updated: ${added} CIDRs in ${batch_count} batches."
    else
        # First-deploy path: the set doesn't exist yet, so we need the full ruleset
        # load via /etc/nftables.conf to declare it. Smaller-set case, single shot
        # is fine here.
        if nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf; then
            echo "nftables reloaded (first-deploy path)."
            for cc in "${BLOCK_COUNTRIES[@]}"; do
                added=$((added + $(count_ranges "${BLOCKLIST_DIR}/${cc}.zone")))
            done
        else
            echo "FAILED: nft -f /etc/nftables.conf rejected the ruleset." >&2
            logger -t loxprox-geoip -p user.err "First-deploy reload failed; geoip_blocklist set not declared" || true
            write_stamp "$STAMP_FAIL" "nft -f /etc/nftables.conf rejected the ruleset"
            exit 1
        fi
    fi

    write_stamp "$STAMP_OK" "$added"
}

# Only run when executed, not when sourced (tests source it for the helpers).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
