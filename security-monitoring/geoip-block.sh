#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — GeoIP Blocking
# ═══════════════════════════════════════════════════════════════════════════════
# Downloads country IP blocklists from ipdeny.com and adds them to nftables.
# Conservative default: blocks high-risk scanning countries only.
# Can be disabled by setting GEOIP_ENABLED="false".
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

GEOIP_ENABLED="${GEOIP_ENABLED:-true}"
BLOCKLIST_DIR="/var/lib/loxone-geoip"
NFTABLES_GEOIP="/etc/nftables.d/99-geoip.conf"

# Countries to block (ISO 3166-1 alpha-2 codes)
# Default: known high-volume scanning / botnet sources
BLOCK_COUNTRIES=(
    "cn"  # China
    "ru"  # Russia
    "kp"  # North Korea
    "ir"  # Iran
)

[ "$GEOIP_ENABLED" = "true" ] || { echo "GeoIP blocking disabled"; exit 0; }

mkdir -p "$BLOCKLIST_DIR"

# Minimum fraction of country lists that must download successfully before we
# replace the active blocklist. Below this threshold we keep the last known-good
# rules so a partial outage at ipdeny.com cannot silently shrink coverage.
: "${GEOIP_MIN_SUCCESS_RATIO:=1.0}"

# Download to .new files first; only promote on success. Track failures so we
# can fail closed (keep last known-good) when the update is incomplete.
total=${#BLOCK_COUNTRIES[@]}
succeeded=0
failed_countries=()
for cc in "${BLOCK_COUNTRIES[@]}"; do
    if curl -s -f --max-time 30 "https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone" \
            -o "${BLOCKLIST_DIR}/${cc}.zone.new" 2>/dev/null \
        && [ -s "${BLOCKLIST_DIR}/${cc}.zone.new" ]; then
        succeeded=$((succeeded + 1))
    else
        rm -f "${BLOCKLIST_DIR}/${cc}.zone.new"
        failed_countries+=("$cc")
    fi
done

required=$(awk -v t="$total" -v r="$GEOIP_MIN_SUCCESS_RATIO" 'BEGIN { v = t * r; printf "%d", (v == int(v) ? v : int(v) + 1) }')
if [ "$succeeded" -lt "$required" ]; then
    # Fail closed: drop staged downloads, keep current active rules untouched.
    for cc in "${BLOCK_COUNTRIES[@]}"; do
        rm -f "${BLOCKLIST_DIR}/${cc}.zone.new"
    done
    echo "GeoIP update FAILED: only $succeeded/$total country lists fetched (need $required)." >&2
    echo "GeoIP update FAILED: failed countries: ${failed_countries[*]:-none}" >&2
    echo "GeoIP update FAILED: keeping last known-good blocklist; active nftables rules unchanged." >&2
    logger -t loxprox-geoip -p user.err "GeoIP update failed: ${succeeded}/${total} lists, failed=[${failed_countries[*]:-none}]; kept last known-good"
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

    first=true
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

if nft list set inet filter geoip_blocklist >/dev/null 2>&1; then
    echo "Updating live geoip_blocklist set in batches of ${GEOIP_BATCH_SIZE}..."
    if ! nft flush set inet filter geoip_blocklist 2>/dev/null; then
        echo "FAILED: could not flush live geoip_blocklist set." >&2
        logger -t loxprox-geoip -p user.err "Live set flush failed; on-disk file is updated but kernel state is stale"
        exit 1
    fi

    batch_file=$(mktemp)
    trap 'rm -f "$batch_file"' EXIT
    added=0
    batch_count=0
    : > "$batch_file"

    flush_batch() {
        [ -s "$batch_file" ] || return 0
        if ! nft add element inet filter geoip_blocklist "{ $(cat "$batch_file") }" 2>/dev/null; then
            echo "FAILED: nft add element rejected batch #${batch_count} (size ~${GEOIP_BATCH_SIZE})." >&2
            logger -t loxprox-geoip -p user.err "Live set partial update — batch ${batch_count} failed at ${added} elements"
            exit 1
        fi
        batch_count=$((batch_count + 1))
        : > "$batch_file"
    }

    # Stream every CIDR from every promoted country file; build comma-separated batches.
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
    else
        echo "FAILED: nft -f /etc/nftables.conf rejected the ruleset." >&2
        logger -t loxprox-geoip -p user.err "First-deploy reload failed; geoip_blocklist set not declared"
        exit 1
    fi
fi
