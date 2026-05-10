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

# Download and process each country blocklist
for cc in "${BLOCK_COUNTRIES[@]}"; do
    curl -s -f "https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone" \
        -o "${BLOCKLIST_DIR}/${cc}.zone" 2>/dev/null || true
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
