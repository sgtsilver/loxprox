#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx Autodetector
# ═══════════════════════════════════════════════════════════════════════════════
# Scans the local network for Loxone Miniservers and suggests configuration
# values for deploy.sh. Safe to run — uses small timeouts and is read-only.
#
# Usage:
#   ./detect-loxone.sh                    # Auto-detect subnet
#   ./detect-loxone.sh 192.168.1.0/24     # Scan specific subnet
#   ./detect-loxone.sh 192.168.1.1 192.168.1.254  # Scan IP range
#
# Detection method:
#   1. Scans port 80 responders
#   2. Queries /jdev/cfg/mac (Loxone-specific endpoint)
#   3. Validates response format and MAC OUI
#   4. Queries /jdev/cfg/api for version & firmware info
#   5. Determines Gen 1 vs Gen 2 (Gen 1 = HTTP only, no redirect)
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Loxone OUIs (MAC address prefixes) ───────────────────────────────────────
# Loxone MAC addresses typically start with these prefixes.
# EE:E0:00 is the most common for Miniserver Gen 1.
LOXONE_OUIS=("EE:E0:00" "E0:E0:00" "AC:4E:91" "B0:BE:76")

# ── Network helpers ──────────────────────────────────────────────────────────

detect_subnet() {
    local iface
    iface=$(ip route | awk '/default/ {print $5}' | head -1)
    [[ -z "$iface" ]] && iface=$(route -n 2>/dev/null | awk '/^0\.0\.0\.0/ {print $8}' | head -1)
    [[ -z "$iface" ]] && return 1

    local subnet
    subnet=$(ip -o -f inet addr show "$iface" 2>/dev/null | awk '/scope global/ {print $4}')
    [[ -n "$subnet" ]] && echo "$subnet" && return 0

    # Fallback: try ifconfig-style
    subnet=$(ifconfig "$iface" 2>/dev/null | awk '/inet / {print $2}' | head -1)
    [[ -n "$subnet" ]] && echo "${subnet}/24" && return 0

    return 1
}

ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo "$((a * 256**3 + b * 256**2 + c * 256 + d))"
}

int_to_ip() {
    local ip=$1
    echo "$((ip >> 24 & 255)).$((ip >> 16 & 255)).$((ip >> 8 & 255)).$((ip & 255))"
}

# ── Loxone detection probe ───────────────────────────────────────────────────

probe_loxone() {
    local ip="$1"
    local mac_json version_json mac version snr

    # Try the Loxone-specific endpoint
    mac_json=$(curl -s --connect-timeout 1 --max-time 2 "http://${ip}/jdev/cfg/mac" 2>/dev/null)
    [[ -z "$mac_json" ]] && return 1

    # Check for Loxone response format: {"LL": { "control": "dev/cfg/mac", ... }}
    if ! echo "$mac_json" | grep -q '"LL".*"control".*"dev/cfg/mac"'; then
        return 1
    fi

    # Extract MAC address
    mac=$(echo "$mac_json" | grep -oP '"value":\s*"\K[^"]+' | head -1 | tr '[:lower:]' '[:upper:]')
    [[ -z "$mac" ]] && return 1

    # Validate OUI
    local oui_found=0
    for oui in "${LOXONE_OUIS[@]}"; do
        if [[ "$mac" == "$oui"* ]] || [[ "$mac" == "${oui//:/-}"* ]] || [[ "$mac" == "${oui//:/}"* ]]; then
            oui_found=1
            break
        fi
    done

    # Fetch /jdev/cfg/api once — both for OUI-fallback verification and to
    # pull version + serial. Avoids a duplicate request per probe.
    version_json=$(curl -s --connect-timeout 1 --max-time 2 "http://${ip}/jdev/cfg/api" 2>/dev/null)

    # If the OUI doesn't match, demand a matching /api response shape before
    # accepting this host as a Loxone Miniserver.
    if [[ "$oui_found" -eq 0 ]]; then
        if ! echo "$version_json" | grep -q '"LL".*"control".*"dev/cfg/api"'; then
            return 1
        fi
    fi

    version=$(echo "$version_json" | grep -oP "'version':\s*'\K[^']+" | head -1)
    snr=$(echo "$version_json" | grep -oP "'snr':\s*'\K[^']+" | head -1)

    # Determine generation
    local gen="unknown"
    # Gen 1: HTTP only on port 80, no HTTPS redirect, version typically < 12.x for very old,
    # but Gen 1 firmware goes up to 14.x. Better heuristic: check if HTTPS works.
    if curl -s --connect-timeout 1 --max-time 2 "https://${ip}/jdev/cfg/mac" 2>/dev/null | grep -q '"LL"'; then
        gen="Gen 2 (or newer — HTTPS detected)"
    else
        # Also check for redirect to HTTPS
        local redirect
        redirect=$(curl -sI --connect-timeout 1 --max-time 2 "http://${ip}/" 2>/dev/null | grep -i "location:" | grep -i "https")
        if [[ -n "$redirect" ]]; then
            gen="Gen 2 (or newer — HTTPS redirect detected)"
        else
            gen="Gen 1 (HTTP only — no HTTPS)"
        fi
    fi

    echo "LOXONE_FOUND|$ip|$mac|$version|$snr|$gen"
    return 0
}

# ── Scan execution ───────────────────────────────────────────────────────────

# Print a result block for a single matched host. Args:
#   1: ip, 2: mac, 3: version, 4: snr, 5: gen
#   6: include_warnings ("1" → emit Gen 1/Gen 2 advice and curl hint)
print_match() {
    local ip="$1" mac="$2" version="$3" snr="$4" gen="$5" verbose="$6"

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}✓ LOXONE MINISERVER DETECTED${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  IP Address:      ${CYAN}$ip${NC}"
    echo -e "  MAC Address:     ${CYAN}$mac${NC}"
    echo -e "  Serial:          ${CYAN}$snr${NC}"
    echo -e "  Firmware:        ${CYAN}$version${NC}"
    echo -e "  Generation:      ${CYAN}$gen${NC}"
    echo ""
    echo -e "  ${YELLOW}Suggested deploy.sh configuration:${NC}"
    echo ""
    echo -e "    LOXONE_IP=\"${ip}\""
    echo -e "    LOXONE_PORT=\"80\""
    echo ""

    if [[ "$verbose" == "1" ]]; then
        echo -e "  ${YELLOW}To test connectivity:${NC}"
        echo -e "    curl http://${ip}/jdev/cfg/api"
        echo ""
        if [[ "$gen" == *"Gen 2"* ]]; then
            warn "This appears to be a Loxone Miniserver Gen 2 or newer."
            warn "Gen 2 supports HTTPS — consider enabling TLS termination on the gateway."
        else
            ok "This is a Loxone Miniserver Gen 1 (HTTP only)."
            info "The gateway will proxy HTTP traffic transparently."
        fi
    fi
}

# Probe a contiguous integer IP range in batches of 50 concurrent curls.
# Returns 0 on at least one match, 1 otherwise. Args:
#   1: start_int, 2: end_int, 3: verbose ("1" to print Gen 1/Gen 2 advice)
scan_int_range() {
    local start="$1" end="$2" verbose="$3"
    local found=0 ip_int batch=0
    local tmpfile
    tmpfile=$(mktemp /tmp/loxone-scan-results.XXXXXXXXXX)

    for ((ip_int = start; ip_int <= end; ip_int++)); do
        local ip
        ip=$(int_to_ip "$ip_int")

        (
            result=$(probe_loxone "$ip")
            [[ -n "$result" ]] && echo "$result" >> "$tmpfile"
        ) &

        # Throttle to ~50 in-flight probes. Counting completed iterations
        # (batch++) avoids the iter-0 modulo-zero false trigger that used to
        # call `wait` after only one background was spawned.
        ((batch++))
        if (( batch % 50 == 0 )); then
            wait
        fi
    done
    wait

    if [[ -f "$tmpfile" && -s "$tmpfile" ]]; then
        while IFS='|' read -r _ ip mac version snr gen; do
            found=1
            print_match "$ip" "$mac" "$version" "$snr" "$gen" "$verbose"
        done < "$tmpfile"
    fi
    rm -f "$tmpfile"

    [[ "$found" -eq 1 ]]
}

scan_subnet_cidr() {
    local cidr="$1"
    local network prefix
    network=${cidr%/*}
    prefix=${cidr#*/}

    local net_int mask_int start end
    net_int=$(ip_to_int "$network")
    mask_int=$((0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF))
    start=$((net_int & mask_int))
    end=$((start + (1 << (32 - prefix)) - 1))

    # Skip network and broadcast addresses
    start=$((start + 1))
    end=$((end - 1))

    info "Scanning $cidr ($((end - start + 1)) hosts)..."
    info "This will take approximately $(((end - start + 1) / 50 + 1)) seconds."

    if ! scan_int_range "$start" "$end" "1"; then
        echo ""
        error "No Loxone Miniserver found on $cidr"
        echo ""
        echo "Possible reasons:"
        echo "  • The Miniserver is on a different subnet"
        echo "  • The Miniserver is powered off or unreachable"
        echo "  • The Miniserver is on a non-standard port"
        echo "  • Firewall blocking access from this host"
        echo ""
        echo "Try specifying a different subnet:"
        echo "  ./detect-loxone.sh 192.168.1.0/24"
        return 1
    fi
}

scan_range() {
    local start_ip="$1"
    local end_ip="$2"
    local start_int end_int

    start_int=$(ip_to_int "$start_ip")
    end_int=$(ip_to_int "$end_ip")

    info "Scanning range $start_ip → $end_ip ($((end_int - start_int + 1)) hosts)..."

    if ! scan_int_range "$start_int" "$end_int" "0"; then
        echo ""
        error "No Loxone Miniserver found in range $start_ip → $end_ip"
        return 1
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "  LoxProx Autodetector"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo ""

    # Check dependencies
    if ! command -v curl >/dev/null 2>&1; then
        error "curl is required but not installed."
        exit 1
    fi

    if [[ $# -eq 0 ]]; then
        # Auto-detect subnet
        local subnet
        subnet=$(detect_subnet)
        if [[ -z "$subnet" ]]; then
            error "Could not auto-detect network subnet."
            echo ""
            echo "Please specify a subnet manually:"
            echo "  ./detect-loxone.sh 192.168.1.0/24"
            echo "  ./detect-loxone.sh 192.168.1.1 192.168.1.254"
            exit 1
        fi
        ok "Auto-detected subnet: $subnet"
        scan_subnet_cidr "$subnet"

    elif [[ $# -eq 1 ]]; then
        # CIDR notation
        if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            scan_subnet_cidr "$1"
        else
            error "Invalid CIDR format: $1"
            echo "Expected: 192.168.1.0/24"
            exit 1
        fi

    elif [[ $# -eq 2 ]]; then
        # IP range
        scan_range "$1" "$2"

    else
        echo "Usage:"
        echo "  $0                              # Auto-detect subnet"
        echo "  $0 192.168.1.0/24               # Scan CIDR subnet"
        echo "  $0 192.168.1.1 192.168.1.254    # Scan IP range"
        exit 1
    fi
}

# Only run main if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
