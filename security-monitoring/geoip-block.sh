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

# Reload via /etc/nftables.conf so the set is loaded inside table inet filter
nft -c -f /etc/nftables.conf \
    && nft -f /etc/nftables.conf \
    && echo "nftables reloaded" \
    || echo "nftables syntax check failed — rules not applied"
