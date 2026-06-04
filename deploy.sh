#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Loxone Miniserver Gen 1 — Security Gateway Deployment Script
# ═══════════════════════════════════════════════════════════════════════════════
# Target: fresh Debian 12 (Bookworm) VM on Proxmox — 1 vCPU / 1 GB RAM minimum,
#         2 vCPU / 2 GB recommended, 5 GB disk. VM only — LXC is refused at runtime
#         (kernel sysctls, auditd, AppArmor enforce, nftables silently no-op in
#         unprivileged containers). Override with ALLOW_LXC=1 at your own risk.
#
# Usage:
#   1. Run set-static-ip.sh first if the VM has no static IP yet.
#   2. Edit the CONFIGURATION section below.
#   3. chmod +x deploy.sh && ./deploy.sh
#
# The script is idempotent — safe to re-run.
# Rollback: ./deploy.sh --rollback
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Per-host configuration lives in /etc/loxprox/deploy.conf — NOT in this script.
# Upgrading no longer requires re-editing deploy.sh every time.
#
# First install:
#     sudo install -d -m 0750 /etc/loxprox
#     sudo cp deploy.conf.example /etc/loxprox/deploy.conf
#     sudo $EDITOR /etc/loxprox/deploy.conf      # fill in the [REQUIRED] values
#     sudo ./deploy.sh
#
# Upgrading from v1.3.x or earlier (no /etc/loxprox/deploy.conf yet):
#     sudo ./deploy.sh --bootstrap-config        # extracts your live values
#     sudo ./deploy.sh                           # normal run, sources the file
#
# Running deploy.sh without a deploy.conf and without an existing install is
# refused on purpose — that situation used to silently use placeholder values
# (192.168.1.100 etc.) and brick fresh-VM operators who forgot to edit the
# script. The error message points to deploy.conf.example.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Default initializations — sourcing deploy.conf overrides these. The
# `${VAR-default}` form expands to VAR if set (any value including empty),
# otherwise default. Lets the integration test suite pre-set values via
# `export`/assignment before sourcing the script. Portable across bash 3.2+
# (the `[[ -v VAR ]]` test would be cleaner but requires bash 4.2).
LOXONE_IP="${LOXONE_IP-}"
LOXONE_PORT="${LOXONE_PORT-80}"
GATEWAY_IP="${GATEWAY_IP-}"
LAN_SUBNET="${LAN_SUBNET-}"
declare -p SSH_ALLOWED_SUBNETS &>/dev/null || SSH_ALLOWED_SUBNETS=()
RATE_LIMIT_REQ_PER_SEC="${RATE_LIMIT_REQ_PER_SEC-10}"
RATE_LIMIT_BURST="${RATE_LIMIT_BURST-100}"
RATE_LIMIT_CONN_PER_IP="${RATE_LIMIT_CONN_PER_IP-20}"
PROXY_CONNECT_TIMEOUT="${PROXY_CONNECT_TIMEOUT-10}"
PROXY_SEND_TIMEOUT="${PROXY_SEND_TIMEOUT-15}"
PROXY_READ_TIMEOUT="${PROXY_READ_TIMEOUT-15}"
CLIENT_BODY_TIMEOUT="${CLIENT_BODY_TIMEOUT-10}"
CLIENT_HEADER_TIMEOUT="${CLIENT_HEADER_TIMEOUT-10}"
ENABLE_APPSEC="${ENABLE_APPSEC-true}"
APPSEC_MODE="${APPSEC_MODE-enforce}"
declare -p CROWDSEC_WHITELIST_IPS &>/dev/null || CROWDSEC_WHITELIST_IPS=()
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL-}"
ALERT_EMAIL="${ALERT_EMAIL-}"
AUTOREBOOT_TIME="${AUTOREBOOT_TIME-03:00}"
ENABLE_TLS="${ENABLE_TLS-false}"
TLS_DOMAIN="${TLS_DOMAIN-}"
TLS_EMAIL="${TLS_EMAIL-}"
TLS_ACME_SERVER="${TLS_ACME_SERVER-letsencrypt}"
TLS_ACME_EXTRA="${TLS_ACME_EXTRA-}"

# Operator config file path. Override via env (LOXPROX_DEPLOY_CONF=/path) for
# testing only — production callers should use the default.
LOXPROX_DEPLOY_CONF="${LOXPROX_DEPLOY_CONF:-/etc/loxprox/deploy.conf}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INTERNALS — Do not edit below
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LOG_FILE="${LOG_FILE:-/var/log/loxprox-deploy.log}"
BACKUP_DIR="${BACKUP_DIR:-/root/loxprox-backup-$(date +%Y%m%d-%H%M%S)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/loxone}"
NGINX_ENABLED="${NGINX_ENABLED:-/etc/nginx/sites-enabled/loxone}"
CROWDSEC_NGINX_ACQUIS="${CROWDSEC_NGINX_ACQUIS:-/etc/crowdsec/acquis.d/nginx.yaml}"
CROWDSEC_SSH_ACQUIS="${CROWDSEC_SSH_ACQUIS:-/etc/crowdsec/acquis.d/ssh.yaml}"
CROWDSEC_APPSEC_ACQUIS="${CROWDSEC_APPSEC_ACQUIS:-/etc/crowdsec/acquis.d/appsec.yaml}"
NGINX_APPSEC_INCLUDE="${NGINX_APPSEC_INCLUDE:-/etc/nginx/crowdsec-appsec.conf}"
# A future cleanup target. A v1.5.0-dev iteration moved http-scope AppSec
# map + log_format here; that split was reverted (nginx rejects it — see
# configure_nginx for the parse-order explanation). Path is retained so
# `rm -f "$NGINX_APPSEC_AUDIT_CONF"` in configure_nginx can clean up any
# leftover file from dev iterations or downgraded installs.
NGINX_APPSEC_AUDIT_CONF="${NGINX_APPSEC_AUDIT_CONF:-/etc/nginx/conf.d/loxprox-appsec.conf}"
# v1.5.0 — optional TLS via acme.sh + HTTP-01.
NGINX_ACME_CONF="${NGINX_ACME_CONF:-/etc/nginx/conf.d/loxprox-acme.conf}"
LOXPROX_TLS_DIR="${LOXPROX_TLS_DIR:-/etc/loxprox/tls}"
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME_WEBROOT="${ACME_WEBROOT:-/var/www/acme}"
# acme.sh pinned version + tarball SHA256. Update both together when bumping.
# Refresh procedure:
#   curl -sLI https://github.com/acmesh-official/acme.sh/releases/latest   # latest tag
#   curl -sLO https://github.com/acmesh-official/acme.sh/archive/refs/tags/<ver>.tar.gz
#   sha256sum <ver>.tar.gz
# The pin protects against tarball substitution between upstream's release
# moment and a fresh install.
ACMESH_VER="${ACMESH_VER:-3.1.3}"
ACMESH_SHA256="${ACMESH_SHA256:-efd12b265252f8875269960b6b31830731ccce2b3e6ff8e7ecfbee21fde35ab4}"
SYSCTL_CONF="${SYSCTL_CONF:-/etc/sysctl.d/99-security-gateway.conf}"
NFTABLES_CONF="${NFTABLES_CONF:-/etc/nftables.conf}"
LOGROTATE_CONF="${LOGROTATE_CONF:-/etc/logrotate.d/loxone-nginx}"
GATEWAY_CONFIG_DIR="${GATEWAY_CONFIG_DIR:-/etc/loxprox}"
GATEWAY_CONFIG_FILE="${GATEWAY_CONFIG_FILE:-$GATEWAY_CONFIG_DIR/config.env}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
info()  { log "${BLUE}[INFO]${NC}  $1"; }
warn()  { log "${YELLOW}[WARN]${NC}  $1"; }
error() { log "${RED}[ERROR]${NC} $1"; }
ok()    { log "${GREEN}[OK]${NC}    $1"; }

banner() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo ""
}

check_root()    { [[ $EUID -eq 0 ]] || { error "Run as root."; exit 1; }; }
service_active(){ systemctl is-active --quiet "$1" 2>/dev/null; }

backup_file() {
    [[ -f "$1" ]] && { mkdir -p "$BACKUP_DIR"; cp "$1" "$BACKUP_DIR/"; info "Backed up: $1"; }
    return 0
}

validate_ip() {
    # Strict RFC 1918-style IPv4 validation: each octet 0-255
    local ip="$1"
    if [[ "$ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
        return 0
    fi
    # Fallback: try ipcalc if available for authoritative validation
    if command -v ipcalc &>/dev/null && ipcalc -c "$ip" &>/dev/null; then
        return 0
    fi
    error "Invalid IP: $ip"
    return 1
}

validate_network() {
    # Strict CIDR validation: each octet 0-255, prefix 0-32.
    # Shape-only checks (e.g. accepting 999.999.1.0/24) would slip through
    # preflight and yield invalid or unintended firewall behavior at reload.
    local cidr="$1"
    if [[ "$cidr" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[0-2])$ ]]; then
        return 0
    fi
    if command -v ipcalc &>/dev/null && ipcalc -c "$cidr" &>/dev/null; then
        return 0
    fi
    error "Invalid CIDR: $cidr"
    return 1
}

# ─── Configuration loader ────────────────────────────────────────────────────
#
# v1.5.0 split: REQUIRED/OPTIONAL values live in /etc/loxprox/deploy.conf, not
# in this script. The loader is permissive about the file's existence and
# returns 1 instead of exiting, so main() can decide how to react (offer the
# operator a bootstrap path versus refuse with a clear message).
#
_loxprox_load_config() {
    if [[ ! -f "$LOXPROX_DEPLOY_CONF" ]]; then
        return 1
    fi
    # shellcheck disable=SC1090
    source "$LOXPROX_DEPLOY_CONF"
    return 0
}

# Returns 0 if signals of a previous LoxProx install are present on the box.
# Used by main() to distinguish "fresh VM, operator forgot to edit config"
# from "existing install upgrading to v1.5.0 for the first time."
_loxprox_detect_live_install() {
    [[ -f "$NGINX_SITE" ]] && return 0
    [[ -d /opt/loxprox && -n "$(ls -A /opt/loxprox 2>/dev/null)" ]] && return 0
    [[ -f /etc/audit/rules.d/99-gateway.rules ]] && return 0
    return 1
}

# Extracts a deploy.conf candidate from the live state of an existing install
# and writes it to $1. Returns 0 on success, 1 if any REQUIRED value could not
# be recovered.
#
# Source of truth for each value:
#   LOXONE_IP / PORT       — /etc/nginx/sites-available/loxone (upstream block)
#   GATEWAY_IP             — `hostname -I` primary address
#   LAN_SUBNET             — first kernel-proto link-scope route
#   SSH_ALLOWED_SUBNETS    — /etc/nftables.conf "tcp dport 22 ip saddr {...}"
#   ENABLE_APPSEC          — presence of `auth_request /crowdsec-appsec` in nginx site
#   APPSEC_MODE            — /etc/crowdsec/acquis.d/appsec.yaml `mode:` key
#   CROWDSEC_WHITELIST_IPS — /etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml
#   DISCORD_WEBHOOK_URL    — /etc/loxprox/config.env (runtime config, separate file)
#
# Rate limits, timeouts, and AUTOREBOOT_TIME are NOT extracted — they're written
# as repo defaults and the operator can edit deploy.conf afterwards if they
# diverged from the defaults. The repo defaults match what every deploy from
# v1.0 through v1.4 used.
_loxprox_extract_config_from_live_state() {
    local out="$1"
    local loxone_ip="" loxone_port="80"
    local gateway_ip="" lan_subnet=""
    local ssh_subnets_arr=()
    local enable_appsec="false" appsec_mode="enforce"
    local webhook=""
    local whitelist_lines=()

    if [[ -f "$NGINX_SITE" ]]; then
        local upstream_line
        upstream_line=$(grep -oE 'server[[:space:]]+[0-9.]+:[0-9]+' "$NGINX_SITE" | head -1 | awk '{print $2}')
        if [[ -n "$upstream_line" ]]; then
            loxone_ip="${upstream_line%:*}"
            loxone_port="${upstream_line#*:}"
        fi
        # Whitespace-tolerant. Live nginx configs often have aligned columns
        # (`auth_request      /crowdsec-appsec;`), which a literal single-space
        # match misses — that bug existed in an earlier v1.5.0-dev iteration and the maintainer's own
        # upgrade-from-v1.4.0 hit it (ENABLE_APPSEC=false was extracted from a
        # VM that obviously had AppSec on, because of the column alignment in
        # its hand-edited site config). Fixed in v1.5.1.
        if grep -qE 'auth_request[[:space:]]+/crowdsec-appsec' "$NGINX_SITE"; then
            enable_appsec="true"
        fi
    fi

    if [[ -f "$NFTABLES_CONF" ]]; then
        local ssh_set
        ssh_set=$(grep -oE 'tcp dport 22 ip saddr \{[^}]+\}' "$NFTABLES_CONF" | head -1 \
                  | sed -E 's/.*\{[[:space:]]*//; s/[[:space:]]*\}.*//; s/[[:space:]]+//g')
        if [[ -n "$ssh_set" ]]; then
            local oldIFS="$IFS"; IFS=','
            local cidr
            for cidr in $ssh_set; do
                [[ -n "$cidr" ]] && ssh_subnets_arr+=("$cidr")
            done
            IFS="$oldIFS"
        fi
    fi

    gateway_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    lan_subnet=$(ip route 2>/dev/null | awk '/proto kernel/ && /scope link/{print $1; exit}')

    if [[ "$enable_appsec" == "true" && -f /etc/crowdsec/acquis.d/appsec.yaml ]]; then
        local mode_line
        mode_line=$(grep -E '^\s*mode:\s*' /etc/crowdsec/acquis.d/appsec.yaml | head -1)
        if [[ "$mode_line" =~ monitor ]]; then
            appsec_mode="monitor"
        fi
    fi

    if [[ -f /etc/loxprox/config.env ]]; then
        webhook=$(awk -F'=' '/^DISCORD_WEBHOOK_URL=/{
            v=$2; gsub(/^[ "\047]+|[ "\047]+$/, "", v); print v; exit
        }' /etc/loxprox/config.env)
    fi

    if [[ -f /etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml ]]; then
        local wl_line
        while IFS= read -r wl_line; do
            [[ -n "$wl_line" ]] && whitelist_lines+=("$wl_line")
        done < <(awk '/^[[:space:]]*-[[:space:]]+/{
            gsub(/^[[:space:]]*-[[:space:]]*"?|"?[[:space:]]*$/, "");
            print
        }' /etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml)
    fi

    local missing=()
    [[ -z "$loxone_ip" ]] && missing+=("LOXONE_IP")
    [[ -z "$gateway_ip" ]] && missing+=("GATEWAY_IP")
    [[ -z "$lan_subnet" ]] && missing+=("LAN_SUBNET")
    [[ ${#ssh_subnets_arr[@]} -eq 0 ]] && missing+=("SSH_ALLOWED_SUBNETS")
    if (( ${#missing[@]} > 0 )); then
        error "Could not extract from live state: ${missing[*]}"
        error "Live state is incomplete — you'll have to write deploy.conf by hand."
        error "Copy deploy.conf.example to $LOXPROX_DEPLOY_CONF and fill in the values."
        return 1
    fi

    {
        echo "# Generated by deploy.sh --bootstrap-config on $(date -Iseconds)"
        echo "# Extracted from the live state of an existing LoxProx install."
        echo "# Review every value before re-running deploy.sh — these are best-effort"
        echo "# reads from /etc/nginx, /etc/nftables.conf, and /etc/crowdsec."
        echo
        echo "LOXONE_IP=\"$loxone_ip\""
        echo "LOXONE_PORT=\"$loxone_port\""
        echo "GATEWAY_IP=\"$gateway_ip\""
        echo "LAN_SUBNET=\"$lan_subnet\""
        printf 'SSH_ALLOWED_SUBNETS=('
        local s
        for s in "${ssh_subnets_arr[@]}"; do
            printf ' "%s"' "$s"
        done
        printf ' )\n'
        echo
        echo "# Defaults preserved; the live nginx config still uses these. Adjust"
        echo "# only if you want to change the rate-limiting posture."
        echo "RATE_LIMIT_REQ_PER_SEC=\"10\""
        echo "RATE_LIMIT_BURST=\"100\""
        echo "RATE_LIMIT_CONN_PER_IP=\"20\""
        echo "PROXY_CONNECT_TIMEOUT=\"10\""
        echo "PROXY_SEND_TIMEOUT=\"15\""
        echo "PROXY_READ_TIMEOUT=\"15\""
        echo "CLIENT_BODY_TIMEOUT=\"10\""
        echo "CLIENT_HEADER_TIMEOUT=\"10\""
        echo
        echo "ENABLE_APPSEC=\"$enable_appsec\""
        echo "APPSEC_MODE=\"$appsec_mode\""
        echo
        echo "CROWDSEC_WHITELIST_IPS=("
        local w
        if (( ${#whitelist_lines[@]} > 0 )); then
            for w in "${whitelist_lines[@]}"; do
                echo "    \"$w\""
            done
        else
            echo "    \"$lan_subnet\"   # fallback — extracted LAN_SUBNET"
        fi
        echo ")"
        echo
        echo "DISCORD_WEBHOOK_URL=\"$webhook\""
        echo "ALERT_EMAIL=\"\""
        echo "AUTOREBOOT_TIME=\"03:00\""
    } > "$out"
    return 0
}

# Orchestrates --bootstrap-config: detect live install, extract values, show
# the candidate file, ask for confirmation, install at $LOXPROX_DEPLOY_CONF.
# Honors $LOXPROX_BOOTSTRAP_YES for non-interactive use.
_loxprox_bootstrap_config_interactive() {
    banner "Bootstrap deploy.conf from live state"
    check_root

    if ! _loxprox_detect_live_install; then
        error "No existing LoxProx install detected on this host."
        error "Bootstrap is for upgrading existing installs. For a fresh VM:"
        error "  sudo install -d -m 0750 /etc/loxprox"
        error "  sudo cp deploy.conf.example $LOXPROX_DEPLOY_CONF"
        error "  sudo \$EDITOR $LOXPROX_DEPLOY_CONF"
        return 1
    fi

    install -d -m 0750 -o root -g root "$(dirname "$LOXPROX_DEPLOY_CONF")"
    local candidate
    candidate=$(mktemp -t loxprox-deploy-conf-XXXXXX)
    # shellcheck disable=SC2064
    trap "rm -f '$candidate'" RETURN

    if ! _loxprox_extract_config_from_live_state "$candidate"; then
        return 1
    fi

    info "Extracted candidate deploy.conf — review below:"
    echo
    sed 's/^/    /' "$candidate"
    echo

    local confirm="y"
    if [[ -t 0 && -t 1 && -z "${LOXPROX_BOOTSTRAP_YES:-}" ]]; then
        read -r -p "Write this to $LOXPROX_DEPLOY_CONF? [y/N] " confirm
    fi
    if [[ "${confirm,,}" != "y" ]]; then
        warn "Aborted — no file written. Candidate left at $candidate for inspection."
        trap - RETURN
        return 1
    fi

    [[ -f "$LOXPROX_DEPLOY_CONF" ]] && cp -a "$LOXPROX_DEPLOY_CONF" "$LOXPROX_DEPLOY_CONF.bak-$(date +%Y%m%d-%H%M%S)"
    install -m 0640 -o root -g root "$candidate" "$LOXPROX_DEPLOY_CONF"
    ok "Wrote $LOXPROX_DEPLOY_CONF (0640 root). Now run: sudo bash deploy.sh"
    return 0
}

# ─── GPG cross-verification ──────────────────────────────────────────────────
#
# Why: the historical install fetched the CrowdSec packagecloud key over HTTPS
# and trusted it on first use (TOFU). A first-install MITM (rogue CA, hostile
# resolver, CDN compromise) could substitute the key and serve attacker-signed
# packages. Cross-checking the fingerprint against multiple independently
# operated public keyservers raises the bar to "simultaneously compromise N
# separate infrastructures with separate TLS chains and operators."
#
# No hardcoded fingerprint: whatever fingerprint the primary source returns is
# what we compare against. When CrowdSec rotates keys, every source picks up
# the new key — no deploy.sh update required.
#
# Behaviour:
#   - CONFLICT (any source returns a different fingerprint) → always abort,
#     regardless of mode. That is a positive attack signal, not a network blip.
#   - QUORUM MET (>= LOXPROX_GPG_QUORUM sources agree) → trust + import.
#   - QUORUM NOT MET (network failures, keyservers down) → mode decides:
#       * soft (default): warn + proceed (falls back to TOFU)
#       * hard           : abort
#
# Env vars: LOXPROX_GPG_VERIFY_MODE=soft|hard   LOXPROX_GPG_QUORUM=N
#
verify_crowdsec_key() {
    local primary_key="$1"
    local mode="${LOXPROX_GPG_VERIFY_MODE:-soft}"
    local quorum="${LOXPROX_GPG_QUORUM:-2}"

    # Independent keyservers — separate operators, separate DNS, separate TLS PKI.
    # Hagrid (community), Canonical (Ubuntu), SURFnet (NL academic).
    local sources=(
        "https://keys.openpgp.org/vks/v1/by-fingerprint/%FPR%"
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x%FPR%&options=mr"
        "https://pgp.surf.nl/pks/lookup?op=get&search=0x%FPR%&options=mr"
    )

    local primary_fpr
    primary_fpr=$(gpg --show-keys --with-fingerprint --with-colons "$primary_key" 2>/dev/null \
                  | awk -F: '$1=="fpr" {print $10; exit}')
    if [[ -z "$primary_fpr" ]]; then
        error "verify_crowdsec_key: could not extract fingerprint from primary key"
        return 1
    fi
    info "Primary key fingerprint: $primary_fpr"

    local agree=0 conflict=0 unreachable=0
    local src_tpl url tmp fpr
    for src_tpl in "${sources[@]}"; do
        url="${src_tpl//%FPR%/$primary_fpr}"
        tmp=$(mktemp)
        if ! curl -fsSL --max-time 15 -o "$tmp" "$url" 2>/dev/null; then
            unreachable=$((unreachable + 1))
            info "  unreachable: ${url%%\?*}"
            rm -f "$tmp"
            continue
        fi
        fpr=$(gpg --show-keys --with-fingerprint --with-colons "$tmp" 2>/dev/null \
              | awk -F: '$1=="fpr" {print $10; exit}')
        rm -f "$tmp"
        if [[ -z "$fpr" ]]; then
            unreachable=$((unreachable + 1))
            info "  parse failure: ${url%%\?*}"
            continue
        fi
        if [[ "$fpr" == "$primary_fpr" ]]; then
            agree=$((agree + 1))
            info "  agree:       ${url%%\?*}"
        else
            conflict=$((conflict + 1))
            warn "  CONFLICT:    ${url%%\?*} returned $fpr (expected $primary_fpr)"
        fi
    done

    # A keyserver returning a DIFFERENT fingerprint is always fatal.
    if (( conflict > 0 )); then
        error "Fingerprint conflict detected on ${conflict} keyserver(s) — refusing to import."
        error "This is a positive attack signal. Investigate before re-running."
        return 1
    fi

    if (( agree >= quorum )); then
        ok "GPG key cross-verified (${agree}/${#sources[@]} independent sources agree)."
        return 0
    fi

    # Below quorum — mode decides.
    if [[ "$mode" == "hard" ]]; then
        error "GPG quorum not met (${agree}/${quorum} required, ${unreachable} unreachable). Aborting (mode=hard)."
        return 1
    fi
    warn "GPG quorum not met (${agree}/${quorum} required, ${unreachable} unreachable). Continuing (mode=soft, falling back to TOFU)."
    warn "Set LOXPROX_GPG_VERIFY_MODE=hard to refuse install when keyservers are unreachable."
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Pre-flight
# ═══════════════════════════════════════════════════════════════════════════════

preflight() {
    banner "Pre-flight Checks"
    check_root

    info "Validating configuration..."
    validate_ip "$LOXONE_IP" || exit 1
    validate_ip "$GATEWAY_IP" || exit 1
    validate_network "$LAN_SUBNET" || exit 1

    if [[ ${#SSH_ALLOWED_SUBNETS[@]} -eq 0 ]]; then
        error "SSH_ALLOWED_SUBNETS is empty — refusing to deploy (would expose SSH)."
        exit 1
    fi
    local _ssh_subnet
    for _ssh_subnet in "${SSH_ALLOWED_SUBNETS[@]}"; do
        validate_network "$_ssh_subnet" || { error "SSH_ALLOWED_SUBNETS contains invalid CIDR: $_ssh_subnet"; exit 1; }
    done

    # F1: the :1080 listener is the gateway's only confidentiality control. With
    # TLS off, anything reaching :1080 from outside the LAN (i.e. a WAN
    # port-forward) crosses the wire in cleartext — Loxone credentials and the
    # relayed session token included. Warn loudly; non-fatal because a strictly
    # LAN-only gateway legitimately runs without TLS.
    if [[ "${ENABLE_TLS,,}" != "true" ]]; then
        warn "ENABLE_TLS=false — the :1080 listener will serve CLEARTEXT HTTP."
        warn "  For any internet-exposed gateway (WAN forward to :1080), set ENABLE_TLS=true"
        warn "  (needs a public domain + ACME). Cleartext is only safe for LAN-only deployments."
    fi

    # Debian 12 check
    if ! grep -q "bookworm\|12" /etc/os-release 2>/dev/null; then
        warn "This script targets Debian 12 (Bookworm). Detected OS may differ — continuing."
    fi

    # Substrate check — VM only, LXC unsupported.
    #
    # Several gateway defenses silently degrade or no-op in an unprivileged
    # Proxmox LXC because they touch host-kernel state the container cannot
    # write to:
    #   - kernel.unprivileged_userns_clone (Fragnesia / CVE-2026-46300 mitigation)
    #   - kernel.dmesg_restrict, kernel.kptr_restrict, kernel.randomize_va_space
    #   - fs.protected_hardlinks, fs.protected_symlinks
    #   - auditd (one audit consumer per kernel, owned by the host)
    #   - AppArmor profile enforcement (host owns the profile namespace)
    #   - nftables (requires capabilities not granted to unprivileged LXC)
    #
    # In LXC, sysctl writes fail with EPERM and the script's `|| warn` swallows
    # the error — the deployment looks green but the documented posture is not
    # delivered. Refuse to deploy by default. Operators who knowingly accept
    # the reduced posture can set ALLOW_LXC=1.
    if systemd-detect-virt --container &>/dev/null; then
        if [[ "${ALLOW_LXC:-0}" == "1" ]]; then
            warn "Running inside a container with ALLOW_LXC=1 — proceeding with reduced security posture."
            warn "The following will silently fail or no-op (script will continue past them):"
            warn "  • kernel.unprivileged_userns_clone = 0  (Fragnesia / CVE-2026-46300 mitigation)"
            warn "  • kernel.dmesg_restrict, kernel.kptr_restrict, kernel.randomize_va_space"
            warn "  • fs.protected_hardlinks, fs.protected_symlinks"
            warn "  • auditd rule loading (one audit consumer per kernel, owned by the host)"
            warn "  • aa-enforce of the nginx AppArmor profile (host owns profile namespace)"
            warn "  • nftables (depends on container caps; unprivileged LXC typically rejects table create)"
            warn "Documented posture (CIS Debian 12, OWASP IoT Top 10) does NOT apply in this configuration."
        else
            error "Container substrate detected (LXC / systemd-nspawn). This deployment is VM-only."
            error ""
            error "Why this matters:"
            error "  An LXC container shares the host's kernel. Several gateway defenses write to"
            error "  host-kernel state (sysctls in /proc/sys/kernel/*, fs.protected_*) or claim a"
            error "  per-kernel resource (the audit netlink socket has exactly one consumer, owned"
            error "  by the host). From inside an unprivileged container these writes return EPERM,"
            error "  but this script's sysctl loader uses '|| warn' and continues — so the deploy"
            error "  finishes green while the actual posture is degraded."
            error ""
            error "What specifically would silently NOT be applied in an LXC:"
            error "  • kernel.unprivileged_userns_clone = 0 — the Fragnesia (CVE-2026-46300) mitigation"
            error "    this gateway documents. EPERM from inside the container; must be set on the host."
            error "  • kernel.dmesg_restrict / kptr_restrict / randomize_va_space — host kernel concerns,"
            error "    not writable from a container namespace."
            error "  • auditd config-tampering rules (nftables.conf, nginx, sshd, sudoers) — augenrules"
            error "    --load needs CAP_AUDIT_CONTROL and exclusive access to the audit netlink socket,"
            error "    which the host owns."
            error "  • AppArmor nginx profile enforcement — aa-enforce loads profiles into the host's"
            error "    AppArmor subsystem; the container cannot do this for itself."
            error "  • nftables — unprivileged LXC default capability set rejects creating the inet"
            error "    filter table; even when it works, policy lives only in the container's netns."
            error ""
            error "Fix: re-create the target as a Debian 12 VM (qm create, not pct create on Proxmox)."
            error "Override (NOT recommended for an internet-facing gateway): ALLOW_LXC=1 ./deploy.sh"
            exit 1
        fi
    fi

    info "Checking connectivity to Loxone ($LOXONE_IP:$LOXONE_PORT)..."
    if timeout 5 bash -c "cat < /dev/tcp/$LOXONE_IP/$LOXONE_PORT" 2>/dev/null; then
        ok "Loxone is reachable"
    else
        warn "Cannot reach Loxone on $LOXONE_PORT — continuing anyway. Verify manually after deploy."
    fi

    info "Checking port 1080..."
    if ss -tlnp | grep -q ':1080 '; then
        if ss -tlnp | grep ':1080 ' | grep -q nginx; then
            info "Nginx already on :1080 — re-deploy mode."
        else
            warn "Something else is on :1080:"; ss -tlnp | grep ':1080 '
            [[ -t 0 ]] && read -rp "Continue? [y/N] " yn && [[ ! "$yn" =~ ^[Yy]$ ]] && exit 1
        fi
    else
        ok "Port 1080 available"
    fi

    mkdir -p "$BACKUP_DIR"
    ok "Pre-flight passed."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Kernel Hardening
# ═══════════════════════════════════════════════════════════════════════════════

apply_sysctls() {
    banner "Kernel Hardening (sysctl)"
    backup_file "$SYSCTL_CONF"

    cat > "$SYSCTL_CONF" <<EOF
# LoxProx — Kernel Hardening
# Generated by deploy.sh on $(date -Iseconds)

# ── Network: SYN flood protection ──────────────────────────────────────────
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_rfc1337 = 1

# ── Network: ICMP redirect hardening ───────────────────────────────────────
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# ── Network: Spoofing / routing hardening ──────────────────────────────────
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Kernel: information exposure ───────────────────────────────────────────
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2

# ── Kernel: unprivileged user namespaces ───────────────────────────────────
# Mitigates the prerequisite for CVE-2026-46300 ("Fragnesia", XFRM ESP-in-TCP
# LPE) and the broader class of unprivileged-userns kernel exploits. The
# gateway VM has no legitimate user of this feature — nothing runs as a
# non-root sandbox, no containers, no unprivileged browsers.
kernel.unprivileged_userns_clone = 0

# ── Filesystem: hardlink / symlink attacks ─────────────────────────────────
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

    sysctl -p "$SYSCTL_CONF" 2>&1 | tee -a "$LOG_FILE" || warn "Some sysctl parameters could not be applied"
    ok "Kernel hardening applied."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Firewall (nftables)
# ═══════════════════════════════════════════════════════════════════════════════

setup_firewall() {
    banner "Firewall (nftables)"
    backup_file "$NFTABLES_CONF"

    # Build SSH source set from config array
    local ssh_set
    ssh_set=$(IFS=', '; echo "${SSH_ALLOWED_SUBNETS[*]}")

    # v1.5.0: open :80 in the input chain when TLS is enabled so the ACME
    # HTTP-01 challenge listener (and its 301-to-HTTPS catch-all) is reachable
    # from the public internet. Without this, the conf.d/loxprox-acme.conf
    # listener exists but nftables drops every inbound SYN — Let's Encrypt's
    # external probe reports "Timeout during connect (likely firewall problem)".
    # Discovered the hard way on 2026-05-26 during the first live TLS deploy.
    local tls_port_rule=""
    if [[ "${ENABLE_TLS,,}" == "true" ]]; then
        tls_port_rule=$'\n        # ACME HTTP-01 + HTTPS-on-1080 301 redirector (v1.5.0)\n        tcp dport 80 accept'
    fi

    cat > "$NFTABLES_CONF" <<EOF
#!/usr/sbin/nft -f
# LoxProx — base firewall
# Generated by deploy.sh on $(date -Iseconds)
#
# CrowdSec bouncer manages 'table ip crowdsec' separately.
# This table provides the static allow/deny policy as a fallback.
# Reload order: nftables.service starts first, then crowdsec-firewall-bouncer.

# Flush only our table so CrowdSec's live table is not disturbed on reload
table inet filter
flush table inet filter

table inet filter {
    # GeoIP blocklist — populated by geoip-block.sh cron
    include "/etc/nftables.d/*.conf"

    chain input {
        type filter hook input priority filter; policy drop;

        # Established / related — always allow
        ct state established,related accept
        ct state invalid drop

        # Loopback
        iifname "lo" accept

        # ICMP (ping, unreachable, etc.)
        ip  protocol icmp  accept
        ip6 nexthdr  icmpv6 accept

        # GeoIP block — drop high-risk countries before they reach the proxy
        ip saddr @geoip_blocklist drop

        # SSH — LAN and site-to-site only
        # Note: CIDR notation in anonymous sets requires nftables >= 1.0.6
        # Debian 12 ships nftables 1.0.6 — this syntax is fully supported.
        tcp dport 22 ip saddr { ${ssh_set} } accept

        # Loxone proxy — open to internet (router forwards 1080 here)
        tcp dport 1080 accept
${tls_port_rule}
        # Everything else is dropped by policy
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

    # Ensure bouncer starts/restarts after nftables so it re-populates its table
    mkdir -p /etc/systemd/system/crowdsec-firewall-bouncer.service.d
    cat > /etc/systemd/system/crowdsec-firewall-bouncer.service.d/after-nftables.conf <<EOF
[Unit]
After=nftables.service
Wants=nftables.service
EOF

    mkdir -p /etc/nftables.d

    # Pre-seed an empty geoip set so the include glob resolves to a real
    # set definition. Without this, the `@geoip_blocklist` reference in
    # /etc/nftables.conf is undefined on first deploy (geoip-block.sh runs
    # later in main()), and `systemctl restart nftables` fails → set -e aborts.
    # geoip-block.sh overwrites this file with real CIDRs when it runs.
    if [[ ! -s /etc/nftables.d/99-geoip.conf ]]; then
        cat > /etc/nftables.d/99-geoip.conf <<'EOF'
# Placeholder — overwritten by geoip-block.sh on first run
set geoip_blocklist {
    type ipv4_addr
    flags interval
}
EOF
    fi

    systemctl enable nftables
    systemctl restart nftables
    ok "nftables firewall active — input policy: drop, allowed: SSH (LAN), :1080 (any)."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Nginx — install
# ═══════════════════════════════════════════════════════════════════════════════

install_nginx() {
    banner "Installing Nginx"
    if dpkg -l | grep -q "^ii  nginx "; then
        info "Nginx already installed."
    else
        apt-get update -q
        apt-get install -y nginx nginx-extras
    fi
    ok "Nginx installed."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Nginx — configure
# ═══════════════════════════════════════════════════════════════════════════════

configure_nginx() {
    banner "Configuring Nginx"
    rm -f /etc/nginx/sites-enabled/default

    # ── http-scope AppSec audit-log plumbing ─────────────────────────────────
    # Owned by deploy.sh, regenerated every run when ENABLE_APPSEC=true,
    # deleted when false. Lives outside the site file so hand-edits to the
    # site (WebSocket blocks, custom locations, etc.) survive future upgrades.
    # v1.5.0 originally tried to move the AppSec map + log_format out of the
    # site file into /etc/nginx/conf.d/loxprox-appsec.conf so future AppSec
    # features could land without touching the operator-customizable site.
    # That fails nginx -t on Debian 12: `auth_request_set $appsec_action ...`
    # is the directive that registers `$appsec_action` with nginx's variable
    # subsystem, and it lives inside the location block. The map (or any
    # `if=$appsec_action` reference) requires the variable to be already
    # registered at parse time — which it isn't if it sits in a conf.d file
    # that nginx loads before sites-enabled/. So in v1.5.0 the map and
    # log_format stay inline in the site file (same as v1.4.0), and the only
    # http-scope helper file we own is removed if it lingers from an earlier
    # v1.5.0 dev iteration.
    rm -f "$NGINX_APPSEC_AUDIT_CONF"

    # ── Site config ──────────────────────────────────────────────────────────
    # Write the site file ONLY if it does not already exist. Operator
    # hand-edits (WebSocket locations, custom proxy_set_header lines, etc.)
    # are preserved across every future `deploy.sh` run. Set
    # LOXPROX_FORCE_REGEN_NGINX=1 to override and regenerate from template.
    if [[ -f "$NGINX_SITE" ]] && [[ "${LOXPROX_FORCE_REGEN_NGINX:-0}" != "1" ]]; then
        info "Site config $NGINX_SITE exists — preserving operator edits."
        info "  Force regeneration with: LOXPROX_FORCE_REGEN_NGINX=1 sudo bash deploy.sh"
    else
        backup_file "$NGINX_SITE"

        local appsec_include="" appsec_auth="" appsec_http_extras="" appsec_access_log=""
        if [[ "$ENABLE_APPSEC" == "true" ]]; then
            appsec_include="    include ${NGINX_APPSEC_INCLUDE};"
            # F11: auth_request fail-closes by design — if the AppSec daemon
            # (127.0.0.1:7422) is down, nginx denies rather than bypasses the
            # WAF. That trades availability for safety: an AppSec outage degrades
            # to a gateway outage, never to an unprotected passthrough. This is
            # intentional for a security gateway; do not "fix" it into fail-open.
            appsec_auth='
        auth_request      /crowdsec-appsec;
        auth_request_set  $appsec_action $upstream_http_x_crowdsec_action;'
            # Map registers $appsec_blocked at http scope so the access_log
            # `if=$appsec_blocked` directive can resolve it at parse time.
            # Keeping map + log_format inline (rather than in conf.d/) — see
            # the comment above about why nginx rejects the split.
            appsec_http_extras='map $appsec_action $appsec_blocked {
    default       0;
    "deny"        1;
    "ban"         1;
    "captcha"     1;
}
log_format appsec_evt '\''$time_iso8601 $remote_addr "$request" '\''
                      '\''appsec=$appsec_action status=$status '\''
                      '\''ua="$http_user_agent" xff="$http_x_forwarded_for"'\'';
'
            appsec_access_log='    access_log /var/log/nginx/appsec-detections.log appsec_evt if=$appsec_blocked;'
        fi

        cat > "$NGINX_SITE" <<EOF
# Loxone Miniserver Gen 1 — Security Gateway
# Generated by deploy.sh on $(date -Iseconds)

limit_req_zone  \$binary_remote_addr zone=loxone_req:10m  rate=${RATE_LIMIT_REQ_PER_SEC}r/s;
limit_conn_zone \$binary_remote_addr zone=loxone_conn:10m;

${appsec_http_extras}
# F7: WebSocket transparency. Loxone Gen 1 speaks plain ws:// on :80; with the
# gateway terminating TLS the app connects wss:// and the Upgrade handshake must
# be relayed to the backend. For ordinary (non-Upgrade) requests
# \$connection_upgrade is empty, which leaves the Connection header empty and
# preserves the upstream keepalive behaviour below — i.e. no change for the
# HTTP-API path, native WebSocket now also works.
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    "" "";
}

# F3: scrubbed access-log format. nginx's default access_log uses the built-in
# \`combined\` format, whose \$request field is the raw request line *including
# the query string* — which for Loxone carries the gettoken HMAC/username and
# base64 command args. Those then persist at rest in loxone-access.log (0640
# www-data:adm) plus 14 days of rotated archives. This format reproduces the
# same combined shape so the CrowdSec type:nginx parser still reads
# verb/path/version/status/UA, but (a) the ?query is dropped (\$loxone_log_uri
# derives from \$uri, which is the path only) and (b) the secret suffix of
# path-embedded Loxone endpoints is redacted by the map below.
# Confirmed live (2026-06-04): the app drives commands as
# GET /jdev/sys/fenc/<encrypted-blob>?sk=<key> — the secret rides in BOTH the
# path and the query, so \$uri alone is insufficient. The map masks the blob
# while keeping the endpoint prefix visible for CrowdSec detection.
map \$uri \$loxone_log_uri {
    default                                                                      \$uri;
    "~^(?<loxsens>/jdev/sys/(?:fenc|enc|gettoken|getjwt|keyexchange|getkey2?)/)" "\${loxsens}<redacted>";
}
log_format loxone_scrubbed '\$remote_addr - \$remote_user [\$time_local] '
                           '"\$request_method \$loxone_log_uri \$server_protocol" \$status \$body_bytes_sent '
                           '"\$http_referer" "\$http_user_agent"';

upstream loxone_backend {
    server ${LOXONE_IP}:${LOXONE_PORT};
    keepalive 32;
}

server {
    listen 1080;
    server_name _;

    access_log /var/log/nginx/loxone-access.log loxone_scrubbed;
    error_log  /var/log/nginx/loxone-error.log;
${appsec_access_log}

    # Security headers
    add_header X-Frame-Options        "SAMEORIGIN"                   always;
    add_header X-Content-Type-Options "nosniff"                      always;
    add_header Referrer-Policy        "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;
    add_header Permissions-Policy     "geolocation=(), microphone=(), camera=()" always;

    # Hide backend version leakage
    proxy_hide_header Server;
    proxy_hide_header X-Powered-By;

    # Slowloris / slow-read mitigations
    proxy_connect_timeout ${PROXY_CONNECT_TIMEOUT}s;
    proxy_send_timeout    ${PROXY_SEND_TIMEOUT}s;
    proxy_read_timeout    ${PROXY_READ_TIMEOUT}s;
    send_timeout          ${PROXY_SEND_TIMEOUT}s;
    client_body_timeout   ${CLIENT_BODY_TIMEOUT}s;
    client_header_timeout ${CLIENT_HEADER_TIMEOUT}s;

    # Buffer limits
    client_body_buffer_size     16k;
    client_header_buffer_size    4k;
    large_client_header_buffers 4 8k;
    client_max_body_size        10m;

    # Rate limiting
    limit_req  zone=loxone_req  burst=${RATE_LIMIT_BURST} nodelay;
    limit_conn loxone_conn ${RATE_LIMIT_CONN_PER_IP};
${appsec_include}
    location / {
${appsec_auth}
        proxy_http_version 1.1;
        proxy_set_header Upgrade            \$http_upgrade;
        proxy_set_header Connection         \$connection_upgrade;
        proxy_set_header Host               \$host;
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  \$scheme;
        proxy_pass http://loxone_backend;
    }
}
EOF
    fi

    # Create placeholder AppSec include so nginx -t passes before CrowdSec is ready
    if [[ "$ENABLE_APPSEC" == "true" ]]; then
        touch "$NGINX_APPSEC_INCLUDE"
    fi

    ln -sf "$NGINX_SITE" "$NGINX_ENABLED"
    nginx -t 2>&1 | tee -a "$LOG_FILE"
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
    systemctl enable nginx
    ok "Nginx running on :1080."
}

# ═══════════════════════════════════════════════════════════════════════════════
# CrowdSec AppSec — nginx integration (runs AFTER CrowdSec bouncer is registered)
# ═══════════════════════════════════════════════════════════════════════════════

configure_appsec_nginx() {
    [[ "$ENABLE_APPSEC" == "true" ]] || return 0

    banner "CrowdSec AppSec — Nginx Integration"

    local bouncer_key=""
    local bouncer_local="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"

    # Wait for bouncer registration to complete (key written to .local file)
    local retries=0
    while [[ $retries -lt 30 ]]; do
        if [[ -f "$bouncer_local" ]]; then
            bouncer_key=$(awk '/^api_key:/ {print $2}' "$bouncer_local" 2>/dev/null)
            [[ -n "$bouncer_key" ]] && break
        fi
        info "Waiting for bouncer API key..."
        sleep 2
        ((retries++))
    done

    if [[ -z "$bouncer_key" ]]; then
        warn "Could not read bouncer API key from $bouncer_local"
        warn "AppSec integration will not work until the key is available."
        warn "Re-run deploy.sh after CrowdSec bouncer has registered."
        return 0
    fi

    info "Configuring AppSec nginx integration with bouncer key..."

    cat > "$NGINX_APPSEC_INCLUDE" <<EOF
# CrowdSec AppSec WAF — nginx integration
# Generated by deploy.sh on $(date -Iseconds)
# DO NOT EDIT MANUALLY — re-run deploy.sh to regenerate

# Internal subrequest target for auth_request
location = /crowdsec-appsec {
    internal;
    proxy_pass              http://127.0.0.1:7422/;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length              0;
    proxy_set_header        X-Crowdsec-Appsec-Api-Key   "$bouncer_key";
    proxy_set_header        X-Crowdsec-Appsec-Ip        \$remote_addr;
    proxy_set_header        X-Crowdsec-Appsec-Uri       \$request_uri;
    proxy_set_header        X-Crowdsec-Appsec-Verb      \$request_method;
    proxy_connect_timeout   10s;
    proxy_read_timeout      10s;
}
EOF

    chmod 640 "$NGINX_APPSEC_INCLUDE"

    nginx -t 2>&1 | tee -a "$LOG_FILE"
    systemctl reload nginx
    ok "AppSec nginx integration active — requests inspected by CrowdSec WAF."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Nginx — systemd service hardening
# ═══════════════════════════════════════════════════════════════════════════════

setup_nginx_hardening() {
    banner "Nginx systemd Service Hardening"

    mkdir -p /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/hardening.conf <<EOF
[Service]
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
EOF

    systemctl daemon-reload
    systemctl restart nginx
    ok "Nginx systemd hardening applied."
}

# ═══════════════════════════════════════════════════════════════════════════════
# TLS (v1.5.0) — optional HTTPS on :1080 via acme.sh + HTTP-01
# ═══════════════════════════════════════════════════════════════════════════════
#
# Toggle-friendly by design. The operator flips ENABLE_TLS in deploy.conf and
# re-runs `sudo bash deploy.sh`; setup_tls() reads the desired state, computes
# the minimal diff against the current state, and applies it.
#
#   ENABLE_TLS=true   → install acme.sh if missing, write the ACME challenge
#                       listener on :80, issue (or renew) the cert, install
#                       cert files at $LOXPROX_TLS_DIR, mutate the nginx site
#                       so the :1080 listener becomes `listen 1080 ssl;` with
#                       the right ssl_certificate directives + HSTS header.
#   ENABLE_TLS=false  → revert the site mutation, remove the ACME listener,
#                       cancel the renewal cron. Cert files at
#                       $LOXPROX_TLS_DIR are KEPT so a later toggle doesn't
#                       have to re-issue. `--remove-tls` does the full nuke.
#
# Site mutation is bounded by markers so it's reversible and predictable:
#     # LOXPROX-TLS-BEGIN
#     ssl_certificate     /etc/loxprox/tls/fullchain.pem;
#     ssl_certificate_key /etc/loxprox/tls/privkey.pem;
#     ssl_protocols       TLSv1.3 TLSv1.2;
#     ssl_ciphers         HIGH:!aNULL:!MD5;
#     add_header          Strict-Transport-Security "max-age=31536000" always;
#     # LOXPROX-TLS-END
# The listen directive is swapped via a strict-pattern sed:
#     `listen 1080;`    ↔    `listen 1080 ssl;`
# If the operator has hand-edited the listen line into something else
# (e.g. `listen [::]:1080;`), setup_tls() refuses to touch it and warns.
# ═══════════════════════════════════════════════════════════════════════════════

_LOXPROX_TLS_BEGIN_MARKER="# LOXPROX-TLS-BEGIN"
_LOXPROX_TLS_END_MARKER="# LOXPROX-TLS-END"

_loxprox_install_acme_sh() {
    if [[ -x "$ACME_HOME/acme.sh" ]]; then
        info "acme.sh already installed at $ACME_HOME"
        return 0
    fi
    info "Installing acme.sh ${ACMESH_VER} (SHA256-pinned tarball, no curl|bash)..."
    apt-get install -y socat curl >/dev/null

    local tmp tarball extract_dir
    tmp=$(mktemp -d -t loxprox-acmesh.XXXXXX) || return 1
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    tarball="$tmp/acme.sh-${ACMESH_VER}.tar.gz"
    if ! curl -fsSL -o "$tarball" "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACMESH_VER}.tar.gz"; then
        error "Failed to download acme.sh ${ACMESH_VER}"
        return 1
    fi

    local computed
    computed=$(sha256sum "$tarball" | awk '{print $1}')
    if [[ "$computed" != "$ACMESH_SHA256" ]]; then
        error "acme.sh tarball SHA256 mismatch — refusing to install."
        error "  expected: $ACMESH_SHA256"
        error "  got:      $computed"
        error "If acme.sh has released a new version, update ACMESH_VER + ACMESH_SHA256 in deploy.sh."
        return 1
    fi
    info "Tarball SHA256 verified."

    tar -xzf "$tarball" -C "$tmp"
    extract_dir="$tmp/acme.sh-${ACMESH_VER}"
    [[ -d "$extract_dir" ]] || { error "Extract dir $extract_dir not found"; return 1; }

    # acme.sh --install creates $ACME_HOME, drops a cron entry, sets default CA.
    # --noprofile keeps it out of operator shells; we invoke via absolute path.
    (
        cd "$extract_dir"
        ./acme.sh --install \
            --home "$ACME_HOME" \
            --accountemail "${TLS_EMAIL:-noreply@invalid}" \
            --noprofile \
            >> "$LOG_FILE" 2>&1
    )
    [[ -x "$ACME_HOME/acme.sh" ]] || { error "acme.sh install did not produce $ACME_HOME/acme.sh"; return 1; }
    ok "acme.sh ${ACMESH_VER} installed at $ACME_HOME"
}

_loxprox_write_acme_listener() {
    # On the production VM this runs as root; in the test suite we may not
    # be root, so soften the failure modes (mkdir -p + chmod, not install).
    mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge"
    chmod 0755 "$ACME_WEBROOT" "$ACME_WEBROOT/.well-known" "$ACME_WEBROOT/.well-known/acme-challenge" 2>/dev/null || true
    mkdir -p "$(dirname "$NGINX_ACME_CONF")"

    cat > "$NGINX_ACME_CONF" <<EOF
# LoxProx — ACME HTTP-01 challenge listener (v1.5.0).
# Owned by deploy.sh — overwritten on every TLS-enabled deploy, removed on
# disable. Operator router must forward WAN:80 → ${GATEWAY_IP}:80 for ACME
# validation. Everything other than /.well-known/acme-challenge/ on :80 gets
# a permanent 301 to https://\$host:1080\$request_uri.
server {
    listen      80 default_server;
    listen      [::]:80 default_server;
    server_name _;

    # ACME HTTP-01 challenge directory — read by the ACME validator.
    location ^~ /.well-known/acme-challenge/ {
        root                $ACME_WEBROOT;
        default_type        "text/plain";
        try_files           \$uri =404;
    }

    # Everything else: redirect to HTTPS on :1080. Keeps the :80 surface
    # tiny — only the challenge directory serves real content.
    location / {
        return 301 https://\$host:1080\$request_uri;
    }
}
EOF
    chmod 0644 "$NGINX_ACME_CONF"
}

_loxprox_acme_issue() {
    info "Requesting cert for $TLS_DOMAIN from $TLS_ACME_SERVER via HTTP-01..."
    # acme.sh --issue is idempotent. Exit codes:
    #   0 — issued / re-issued successfully
    #   2 — "skipped, cert not near expiry yet" (success from operator's POV)
    #   anything else — actual failure
    #
    # v1.5.0-dev follow-up: capture rc OUTSIDE the `if !` — inside the then-branch, `$?` is
    # always the result of `!` itself (0 or 1), not the original command's
    # exit code. An earlier v1.5.0-dev iteration logged "rc=0" on real failures.
    local rc=0
    "$ACME_HOME/acme.sh" --issue \
        --webroot "$ACME_WEBROOT" \
        -d "$TLS_DOMAIN" \
        --server "$TLS_ACME_SERVER" \
        --accountemail "${TLS_EMAIL:-noreply@invalid}" \
        ${TLS_ACME_EXTRA} \
        >> "$LOG_FILE" 2>&1 || rc=$?

    case "$rc" in
        0)
            ok "Cert issued for $TLS_DOMAIN."
            ;;
        2)
            info "Cert already valid; acme.sh skipped re-issue."
            ;;
        *)
            error "acme.sh --issue failed (rc=$rc). See $LOG_FILE for details."
            error "Common causes (most likely first):"
            error "  1. nftables on this gateway does not allow :80 — fixed by v1.5.0's setup_firewall"
            error "     conditional rule. If your install predates v1.5.0, re-run sudo bash deploy.sh."
            error "  2. Router WAN:80 → gateway:80 forward not in place (LE probes from outside)."
            error "  3. DNS A record for $TLS_DOMAIN not pointing at your WAN IP — verify with"
            error "     'dig +short A $TLS_DOMAIN' from a system outside your LAN (phone on cellular)."
            error "  4. ACME rate limit hit (use TLS_ACME_SERVER=letsencrypt_test while debugging)."
            return 1
            ;;
    esac
}

_loxprox_acme_install_cert() {
    install -d -m 0750 -o root -g root "$LOXPROX_TLS_DIR"
    # --install-cert writes (or re-writes) the cert files at deterministic
    # paths AND records the reload command. acme.sh's cron auto-renewer uses
    # the same paths + reloadcmd on every successful renewal.
    "$ACME_HOME/acme.sh" --install-cert \
        -d "$TLS_DOMAIN" \
        --fullchain-file "$LOXPROX_TLS_DIR/fullchain.pem" \
        --key-file       "$LOXPROX_TLS_DIR/privkey.pem" \
        --reloadcmd      "systemctl reload nginx" \
        >> "$LOG_FILE" 2>&1
    chmod 0640 "$LOXPROX_TLS_DIR/fullchain.pem" "$LOXPROX_TLS_DIR/privkey.pem"
    chown root:root "$LOXPROX_TLS_DIR/fullchain.pem" "$LOXPROX_TLS_DIR/privkey.pem"
}

_loxprox_ensure_acme_cron() {
    # acme.sh's --install step writes a daily cron line for root that runs
    # `acme.sh --cron`, which checks every installed cert and renews anything
    # within ~30 days of expiry. The --reloadcmd recorded by --install-cert
    # above is automatically called by the cron on successful renewal.
    #
    # Operators occasionally clean up crontabs and accidentally remove the
    # acme.sh entry. Verify it's present after every TLS-enabled deploy and
    # reinstall via --install-cronjob if missing. Logged either way so the
    # operator can see "auto-renew is on" without grepping crontab.
    local cron_line
    cron_line=$(crontab -l 2>/dev/null | grep -F "$ACME_HOME/acme.sh --cron" | head -1)
    if [[ -z "$cron_line" ]]; then
        warn "acme.sh cron line missing from root crontab — restoring."
        "$ACME_HOME/acme.sh" --install-cronjob >> "$LOG_FILE" 2>&1 || warn "acme.sh --install-cronjob failed"
        cron_line=$(crontab -l 2>/dev/null | grep -F "$ACME_HOME/acme.sh --cron" | head -1)
    fi
    if [[ -n "$cron_line" ]]; then
        ok "Auto-renewal cron active: $cron_line"
        info "  acme.sh checks every cert daily; certs within 30 days of expiry get renewed."
        info "  On successful renewal: nginx is reloaded via the recorded --reloadcmd."
        info "  Force a renewal anytime: sudo bash deploy.sh --renew-tls"
    else
        error "Could not establish acme.sh cron — auto-renewal will NOT happen."
        error "Run manually: $ACME_HOME/acme.sh --install-cronjob"
    fi
}

_loxprox_site_in_tls_mode() {
    [[ -f "$NGINX_SITE" ]] || return 1
    grep -q "$_LOXPROX_TLS_BEGIN_MARKER" "$NGINX_SITE"
}

_loxprox_site_enable_tls() {
    if _loxprox_site_in_tls_mode; then
        info "Site $NGINX_SITE already in TLS mode — no mutation needed."
        return 0
    fi
    # Strict pattern: only match the canonical `listen 1080;` line we ship.
    # Anything else (operator hand-edits like `listen [::]:1080;`) is treated
    # as out-of-bounds and refused — better to fail loudly than half-mutate.
    if ! grep -qE '^[[:space:]]*listen[[:space:]]+1080[[:space:]]*;[[:space:]]*$' "$NGINX_SITE"; then
        error "Site $NGINX_SITE does not contain the canonical 'listen 1080;' line."
        error "Either the operator has hand-edited it to a non-standard form, or the file is corrupted."
        error "Aborting TLS site mutation. Fix the listen line manually, then re-run deploy.sh."
        return 1
    fi
    backup_file "$NGINX_SITE"
    # awk, not sed: BSD sed (macOS) and GNU sed (Linux) disagree on multi-line
    # replacement semantics (\n expansion, \+ support). awk handles inserted
    # newlines uniformly. The match captures the per-line indent so the
    # inserted directives align with the original `listen` indentation.
    local tmp
    tmp=$(mktemp -t loxprox-site.XXXXXX) || return 1
    awk -v tls_begin="$_LOXPROX_TLS_BEGIN_MARKER" \
        -v tls_end="$_LOXPROX_TLS_END_MARKER" \
        -v tls_dir="$LOXPROX_TLS_DIR" '
        match($0, /^[[:space:]]*listen[[:space:]]+1080[[:space:]]*;[[:space:]]*$/) {
            # Extract leading whitespace as the indent string.
            indent = $0
            sub(/listen.*/, "", indent)
            printf "%slisten 1080 ssl;\n", indent
            printf "%s%s\n", indent, tls_begin
            printf "%s    ssl_certificate     %s/fullchain.pem;\n", indent, tls_dir
            printf "%s    ssl_certificate_key %s/privkey.pem;\n", indent, tls_dir
            printf "%s    ssl_protocols       TLSv1.3 TLSv1.2;\n", indent
            # F6: explicit ECDHE-only cipher list so a TLS 1.2 client cannot
            # negotiate a non-forward-secret (RSA key-exchange) suite. TLS 1.3
            # suites are all AEAD+PFS by default and unaffected by ssl_ciphers.
            printf "%s    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n", indent
            printf "%s    ssl_prefer_server_ciphers off;\n", indent
            printf "%s    ssl_session_cache   shared:loxprox_ssl:10m;\n", indent
            printf "%s    ssl_session_timeout 1d;\n", indent
            # F6: disable TLS session tickets. The nginx default is a single
            # auto-generated STEK that is never rotated for the master-process
            # lifetime; with TLS 1.2 enabled that STEK encrypts the session
            # master secret, so later key recovery would allow passive decryption
            # of recorded 1.2 sessions (no forward secrecy). Server-side
            # resumption via ssl_session_cache above stays forward-secret.
            printf "%s    ssl_session_tickets off;\n", indent
            printf "%s    add_header          Strict-Transport-Security \"max-age=31536000\" always;\n", indent
            # v1.5.0 — plain-HTTP-to-HTTPS-port grace: nginx returns 400 ("The
            # plain HTTP request was sent to HTTPS port") when a client speaks
            # cleartext to a `listen 1080 ssl` socket. CrowdSec'\''s
            # http-probing scenario interprets a burst of 400s as scanning
            # activity and bans the client IP — which Loxone iOS/Android apps
            # configured for http://gateway:1080 trip into within seconds.
            # `error_page 497` (nginx'\''s internal code for this exact case)
            # routed through a named location issues a clean 301 instead.
            # The bare `error_page 497 https://...` form does not work; the
            # named-location indirection is required.
            printf "%s    error_page 497 = @loxprox_https_redirect;\n", indent
            printf "%s    location @loxprox_https_redirect { return 301 https://$host:1080$request_uri; }\n", indent
            printf "%s%s\n", indent, tls_end
            next
        }
        { print }
    ' "$NGINX_SITE" > "$tmp"
    if [[ ! -s "$tmp" ]]; then
        error "awk produced empty output; refusing to clobber $NGINX_SITE."
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$NGINX_SITE"
    chmod 0644 "$NGINX_SITE"
    info "Site mutated → listen 1080 ssl + cert directives between markers."
}

_loxprox_site_disable_tls() {
    if ! _loxprox_site_in_tls_mode; then
        info "Site $NGINX_SITE is not in TLS mode — nothing to revert."
        return 0
    fi
    backup_file "$NGINX_SITE"
    local tmp
    tmp=$(mktemp -t loxprox-site.XXXXXX) || return 1
    # Strip everything between (and including) the markers, then revert the
    # listen directive. awk for the same portability reason as enable.
    awk -v tls_begin="$_LOXPROX_TLS_BEGIN_MARKER" \
        -v tls_end="$_LOXPROX_TLS_END_MARKER" '
        index($0, tls_begin) > 0 { in_block = 1; next }
        index($0, tls_end)   > 0 { in_block = 0; next }
        in_block { next }
        match($0, /^[[:space:]]*listen[[:space:]]+1080[[:space:]]+ssl[[:space:]]*;[[:space:]]*$/) {
            indent = $0
            sub(/listen.*/, "", indent)
            printf "%slisten 1080;\n", indent
            next
        }
        { print }
    ' "$NGINX_SITE" > "$tmp"
    if [[ ! -s "$tmp" ]]; then
        error "awk produced empty output; refusing to clobber $NGINX_SITE."
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$NGINX_SITE"
    chmod 0644 "$NGINX_SITE"
    info "Site reverted → listen 1080 (plain), marker block stripped."
}

_loxprox_tls_validate_config() {
    if [[ -z "$TLS_DOMAIN" ]]; then
        error "ENABLE_TLS=true but TLS_DOMAIN is empty."
        error "Set TLS_DOMAIN in $LOXPROX_DEPLOY_CONF to a fully-qualified public hostname."
        return 1
    fi
    # acme.sh refuses raw IPs; sanity-check that TLS_DOMAIN has at least one dot.
    if [[ "$TLS_DOMAIN" != *.* ]]; then
        error "TLS_DOMAIN=$TLS_DOMAIN does not look like an FQDN (no dots)."
        return 1
    fi
    return 0
}

setup_tls() {
    case "${ENABLE_TLS,,}" in
        true|yes|1)
            banner "TLS — enable (acme.sh + HTTP-01)"
            _loxprox_tls_validate_config || return 1
            _loxprox_install_acme_sh || return 1
            _loxprox_write_acme_listener
            # Reload nginx so the :80 challenge listener is live before the
            # ACME server probes it. systemctl reload is graceful and keeps
            # the :1080 backend traffic flowing.
            if ! nginx -t >> "$LOG_FILE" 2>&1; then
                error "nginx -t failed after writing $NGINX_ACME_CONF; rolling back."
                rm -f "$NGINX_ACME_CONF"
                return 1
            fi
            systemctl reload nginx
            _loxprox_acme_issue || return 1
            _loxprox_acme_install_cert
            _loxprox_ensure_acme_cron
            _loxprox_site_enable_tls || return 1
            if ! nginx -t >> "$LOG_FILE" 2>&1; then
                error "nginx -t failed after TLS site mutation; reverting."
                _loxprox_site_disable_tls
                nginx -t && systemctl reload nginx
                return 1
            fi
            systemctl reload nginx
            ok "HTTPS active on :1080 for $TLS_DOMAIN. Renewal cron handled by acme.sh."
            ok "  Test from outside the LAN: curl -vI https://$TLS_DOMAIN:1080/"
            ;;
        false|no|0|"")
            # Only act if there's anything to undo — keeps re-runs of a
            # never-TLS-enabled host quiet.
            if _loxprox_site_in_tls_mode || [[ -f "$NGINX_ACME_CONF" ]]; then
                banner "TLS — disable (revert site, remove ACME listener)"
                _loxprox_site_disable_tls
                rm -f "$NGINX_ACME_CONF"
                if [[ -x "$ACME_HOME/acme.sh" && -n "${TLS_DOMAIN:-}" ]]; then
                    "$ACME_HOME/acme.sh" --remove -d "$TLS_DOMAIN" >> "$LOG_FILE" 2>&1 || true
                fi
                if nginx -t >> "$LOG_FILE" 2>&1; then
                    systemctl reload nginx
                    ok "TLS disabled. Cert files kept at $LOXPROX_TLS_DIR (use --remove-tls to nuke)."
                else
                    error "nginx -t failed after disable — inspect $NGINX_SITE manually."
                    return 1
                fi
            fi
            ;;
        *)
            error "Invalid ENABLE_TLS value: '$ENABLE_TLS' (expected true/false)."
            return 1
            ;;
    esac
}

# Manual force-renew entrypoint (--renew-tls).
_loxprox_tls_renew() {
    banner "TLS — manual renewal"
    [[ -x "$ACME_HOME/acme.sh" ]] || { error "acme.sh not installed; run deploy.sh with ENABLE_TLS=true first."; return 1; }
    [[ -n "$TLS_DOMAIN" ]] || { error "TLS_DOMAIN empty in $LOXPROX_DEPLOY_CONF"; return 1; }
    "$ACME_HOME/acme.sh" --renew -d "$TLS_DOMAIN" --force >> "$LOG_FILE" 2>&1 || {
        error "acme.sh --renew failed for $TLS_DOMAIN. See $LOG_FILE."
        return 1
    }
    ok "Cert renewed for $TLS_DOMAIN. acme.sh's --reloadcmd already reloaded nginx."
}

# Full TLS nuke (--remove-tls): revert site, remove conf.d, cert files,
# acme.sh state, cron. Intentionally invasive — only run when you mean it.
_loxprox_tls_remove() {
    banner "TLS — full removal"
    _loxprox_site_disable_tls
    rm -f "$NGINX_ACME_CONF"
    nginx -t >> "$LOG_FILE" 2>&1 && systemctl reload nginx || warn "nginx -t failed during removal; inspect site config."
    if [[ -x "$ACME_HOME/acme.sh" ]]; then
        [[ -n "${TLS_DOMAIN:-}" ]] && "$ACME_HOME/acme.sh" --remove -d "$TLS_DOMAIN" >> "$LOG_FILE" 2>&1 || true
        "$ACME_HOME/acme.sh" --uninstall >> "$LOG_FILE" 2>&1 || true
        rm -rf "$ACME_HOME"
    fi
    rm -rf "$LOXPROX_TLS_DIR"
    ok "TLS fully removed: site reverted, acme.sh uninstalled, $LOXPROX_TLS_DIR deleted."
    ok "Operator: also remove the WAN:80 → gateway:80 router forward (no longer needed)."
}

# ═══════════════════════════════════════════════════════════════════════════════
# AppArmor
# ═══════════════════════════════════════════════════════════════════════════════

setup_apparmor() {
    banner "AppArmor"

    if ! dpkg -l | grep -q "^ii  apparmor "; then
        apt-get install -y apparmor apparmor-utils
    fi

    systemctl enable apparmor
    systemctl start apparmor

    # Enforce nginx profile if it exists
    if [[ -f /etc/apparmor.d/usr.sbin.nginx ]]; then
        aa-enforce /etc/apparmor.d/usr.sbin.nginx
        ok "AppArmor: nginx profile enforced."
    else
        warn "AppArmor: nginx profile not found — install 'apparmor-profiles' if needed."
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# CrowdSec — install
# ═══════════════════════════════════════════════════════════════════════════════

install_crowdsec() {
    banner "Installing CrowdSec"

    command -v curl &>/dev/null || apt-get install -y curl
    command -v gpg &>/dev/null || apt-get install -y gnupg

    if ! command -v cscli &>/dev/null; then
        info "Adding CrowdSec repository (GPG-pinned, no curl|bash)..."

        local keyring="/etc/apt/keyrings/crowdsec-archive-keyring.gpg"
        local tmp_key
        tmp_key=$(mktemp)
        # Download key to temp file first — eliminates pipe-to-shell vector
        curl -fsSL -o "$tmp_key" "https://packagecloud.io/crowdsec/crowdsec/gpgkey"

        # Minimal sanity check: must be a valid GPG key payload
        if ! gpg --dry-run --import "$tmp_key" &>/dev/null; then
            rm -f "$tmp_key"
            error "Downloaded CrowdSec GPG key is invalid. Possible MITM or CDN compromise."
            exit 1
        fi

        # Cross-verify the fingerprint against independent public keyservers
        # before importing. See verify_crowdsec_key() for design notes.
        if ! verify_crowdsec_key "$tmp_key"; then
            rm -f "$tmp_key"
            error "CrowdSec GPG cross-verification failed — refusing to install."
            exit 1
        fi

        gpg --dearmor < "$tmp_key" > "$keyring"
        rm -f "$tmp_key"

        echo "deb [signed-by=${keyring}] https://packagecloud.io/crowdsec/crowdsec/debian bookworm main" \
            > /etc/apt/sources.list.d/crowdsec.list
        apt-get update -q
        apt-get install -y crowdsec
    else
        info "CrowdSec already installed."
    fi

    dpkg -l | grep -q "crowdsec-firewall-bouncer" || apt-get install -y crowdsec-firewall-bouncer
    ok "CrowdSec and firewall bouncer installed."
}

# ═══════════════════════════════════════════════════════════════════════════════
# CrowdSec — configure
# ═══════════════════════════════════════════════════════════════════════════════

configure_crowdsec() {
    banner "Configuring CrowdSec"

    mkdir -p /etc/crowdsec/acquis.d

    # Nginx log acquisition
    backup_file "$CROWDSEC_NGINX_ACQUIS"
    cat > "$CROWDSEC_NGINX_ACQUIS" <<EOF
# Nginx log acquisition
filenames:
  - /var/log/nginx/loxone-access.log
  - /var/log/nginx/loxone-error.log
labels:
  type: nginx
EOF

    # SSH acquisition — Debian 12 has no sshd-session split, file-based works cleanly
    backup_file "$CROWDSEC_SSH_ACQUIS"
    cat > "$CROWDSEC_SSH_ACQUIS" <<EOF
# SSH acquisition (Debian 12 — no sshd-session unit split)
filenames:
  - /var/log/auth.log
labels:
  type: syslog
EOF

    # AppSec acquisition
    if [[ "$ENABLE_APPSEC" == "true" ]]; then
        backup_file "$CROWDSEC_APPSEC_ACQUIS"
        cat > "$CROWDSEC_APPSEC_ACQUIS" <<EOF
# CrowdSec AppSec WAF
source: appsec
listen_addr: 127.0.0.1:7422
appsec_config: crowdsecurity/virtual-patching
name: appsec-loxone
labels:
  type: appsec
EOF
    fi

    info "Updating CrowdSec hub catalog..."
    cscli hub update || true

    info "Installing collections (rolling, current hub catalog)..."
    # cscli does not support @version pinning on 'collections install', so these
    # names resolve to whatever 'cscli hub update' just fetched. Determinism is
    # provided instead by (a) skipping 'cscli hub upgrade' on every deploy and
    # (b) operator-driven upgrade after staging validation.
    cscli collections install crowdsecurity/nginx            --error || true
    cscli collections install crowdsecurity/sshd             --error || true
    cscli collections install crowdsecurity/linux            --error || true
    cscli collections install crowdsecurity/http-cve         --error || true
    cscli collections install crowdsecurity/base-http-scenarios --error || true

    if [[ "$ENABLE_APPSEC" == "true" ]]; then
        info "Installing AppSec collection..."
        cscli collections install crowdsecurity/appsec-virtual-patching --error || true
    fi

    # F8: the 'cscli collections install ... || true' calls above swallow
    # hub-outage / renamed-item failures, which would otherwise ship a gateway
    # silently missing detection scenarios while the deploy reports success.
    # Assert each expected collection is actually installed and warn if not.
    local _expected_collections=(crowdsecurity/nginx crowdsecurity/sshd crowdsecurity/linux crowdsecurity/http-cve crowdsecurity/base-http-scenarios)
    [[ "$ENABLE_APPSEC" == "true" ]] && _expected_collections+=(crowdsecurity/appsec-virtual-patching)
    local _installed_collections _missing_collections=() _c
    _installed_collections=$(cscli collections list -o json 2>/dev/null || echo '')
    for _c in "${_expected_collections[@]}"; do
        grep -qF "\"$_c\"" <<<"$_installed_collections" || _missing_collections+=("$_c")
    done
    if (( ${#_missing_collections[@]} > 0 )); then
        warn "CrowdSec collections missing after install: ${_missing_collections[*]}"
        warn "  The gateway is running with REDUCED detection coverage."
        warn "  Check network + 'cscli hub update', then re-run deploy.sh."
    else
        info "All expected CrowdSec collections present."
    fi

    # Intentionally NOT running 'cscli hub upgrade' — uncontrolled upgrades can
    # break parsers or scenarios. Upgrade manually after testing in staging.
    info "Hub components installed. Run 'cscli hub upgrade' manually when validated."

    # Whitelist trusted IPs
    info "Writing CrowdSec whitelist..."
    mkdir -p /etc/crowdsec/parsers/s02-enrich
    local wl="/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml"
    backup_file "$wl"

    # F10: a whitelist entry broader than a /24 disables CrowdSec for *every*
    # host in that range — including untrusted devices that share it. A normal
    # per-VLAN /24 is fine; warn on anything wider (/23, /16, ...).
    local _w _pfx
    for _w in "${CROWDSEC_WHITELIST_IPS[@]}"; do
        if [[ "$_w" =~ /([0-9]+)$ ]]; then
            _pfx="${BASH_REMATCH[1]}"
            if (( _pfx < 24 )); then
                warn "Whitelist entry '$_w' is broader than /24 — CrowdSec/IPS is disabled for ALL hosts in that range, trusted or not. Narrow it to specific trusted subnets if possible."
            fi
        fi
    done

    {
        echo "name: whitelist-loxone"
        echo "description: \"Trusted networks — never blocked\""
        echo "whitelist:"
        echo "  reason: \"Trusted network\""
        echo "  ip:"
        for ip in "${CROWDSEC_WHITELIST_IPS[@]}"; do
            [[ "$ip" =~ / ]] || echo "    - \"$ip\""
        done
        echo "  cidr:"
        for ip in "${CROWDSEC_WHITELIST_IPS[@]}"; do
            [[ "$ip" =~ / ]] && echo "    - \"$ip\""
        done
    } > "$wl"

    systemctl restart crowdsec
    systemctl enable crowdsec
    systemctl daemon-reload
    systemctl enable crowdsec-firewall-bouncer
    systemctl restart crowdsec-firewall-bouncer

    ok "CrowdSec configured and running."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Filesystem hardening — /tmp with nosuid,nodev,noexec (CIS §1.1.2)
# ═══════════════════════════════════════════════════════════════════════════════

setup_tmp_mount() {
    banner "Filesystem Hardening — /tmp (CIS §1.1.2)"

    if ! systemctl cat tmp.mount >/dev/null 2>&1; then
        warn "tmp.mount unit not present on this system — manual /etc/fstab entry needed; skipping."
        return 0
    fi

    mkdir -p /etc/systemd/system/tmp.mount.d
    local drop=/etc/systemd/system/tmp.mount.d/loxprox.conf
    backup_file "$drop"
    cat > "$drop" <<'EOF'
# LoxProx — CIS §1.1.2 /tmp hardening
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,noexec
EOF
    chmod 0644 "$drop"

    systemctl daemon-reload
    systemctl unmask tmp.mount 2>/dev/null || true
    if systemctl enable --now tmp.mount 2>>"$LOG_FILE"; then
        ok "/tmp mounted with nosuid,nodev,noexec."
    else
        warn "tmp.mount activation failed — check log; reboot may be required to remount /tmp."
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSH daemon hardening (CIS Debian 12 §5.2)
# ═══════════════════════════════════════════════════════════════════════════════

_loxprox_has_authorized_key() {
    # True (0) if at least one parseable key entry exists in root's or any
    # UID>=1000 user's authorized_keys file.
    local files=("/root/.ssh/authorized_keys") user uid home f
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" -ge 1000 ]] || continue
        [[ -d "$home" ]] || continue
        [[ "$user" == "nobody" ]] && continue
        files+=("$home/.ssh/authorized_keys")
    done < /etc/passwd
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -Ev '^\s*(#|$)' "$f" 2>/dev/null | grep -q '^\(ssh-\|ecdsa-sha2-\|sk-\)'; then
            return 0
        fi
    done
    return 1
}

_loxprox_validate_pubkey() {
    # Accepts a single-line public key string. Returns 0 if it parses.
    local key="$1" tmp
    case "$key" in
        ssh-ed25519\ *|ssh-rsa\ *|ssh-dss\ *|ecdsa-sha2-*\ *|sk-ssh-ed25519@openssh.com\ *|sk-ecdsa-sha2-*@openssh.com\ *) ;;
        *) return 1 ;;
    esac
    tmp=$(mktemp) || return 1
    printf '%s\n' "$key" > "$tmp"
    if ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"; return 0
    fi
    rm -f "$tmp"; return 1
}

_loxprox_install_pubkey() {
    local key="$1" target="${2:-/root}"
    install -d -m 0700 -o root -g root "${target}/.ssh"
    local ak="${target}/.ssh/authorized_keys"
    touch "$ak"; chmod 0600 "$ak"; chown root:root "$ak"
    if ! grep -qF "$key" "$ak" 2>/dev/null; then
        printf '%s\n' "$key" >> "$ak"
    fi
}

_loxprox_show_key_help() {
    cat <<EOF

  ${YELLOW}━━ How to create an SSH key — do this ON YOUR WORKSTATION, not here ━━${NC}

    macOS / Linux (Terminal):
        ssh-keygen -t ed25519 -C "you@workstation"

    Windows 10 / 11 (PowerShell or Git Bash):
        ssh-keygen -t ed25519 -C "you@workstation"

    Press Enter to accept the default path. Set a passphrase if you want.

    Then print the PUBLIC key (the one ending in .pub — never share the
    file without .pub):

        cat ~/.ssh/id_ed25519.pub

    Output looks like ONE line starting with 'ssh-ed25519':

        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... you@workstation

    Copy that ENTIRE line, then come back here and choose [P].

    Need more help? Search:
        "ssh-keygen ed25519 <your OS>"
        "how to create ssh key on <your OS>"

EOF
}

_loxprox_interactive_collect_pubkey() {
    # Returns:
    #   0 — public key installed, proceed with HARD hardening
    #   2 — user chose SOFT mode (password auth stays on)
    #   exits 1 — user aborted
    local choice pasted fp confirm
    while true; do
        echo
        echo -e "  ${RED}⚠  No SSH authorized_keys found on this gateway.${NC}"
        echo "  Disabling password auth NOW would lock you out of SSH."
        echo
        echo "  Choose:"
        echo "    [P] Paste your public key (recommended — we'll wait)"
        echo "    [H] Show help — how to create a key on your workstation"
        echo "    [K] Keep password auth for now (insecure; loud login banner until fixed)"
        echo "    [A] Abort deploy entirely"
        echo
        read -r -p "  > " choice
        case "${choice^^}" in
            P)
                echo
                echo "  Paste the entire public key on ONE line, then press Enter."
                echo "  Must start with: ssh-ed25519, ssh-rsa, ecdsa-sha2-…, or sk-…"
                echo "  (Press Enter on an empty line to cancel and go back to the menu.)"
                echo
                read -r -p "  pubkey> " pasted
                [[ -z "$pasted" ]] && continue
                if ! _loxprox_validate_pubkey "$pasted"; then
                    error "That doesn't parse as a public key — try again."
                    continue
                fi
                fp=$(printf '%s\n' "$pasted" | ssh-keygen -l -f /dev/stdin 2>/dev/null | head -1)
                echo
                echo "  You pasted:"
                echo "    $pasted"
                echo
                echo "  Fingerprint: $fp"
                echo
                read -r -p "  Is this YOUR key, correctly copied? [y/N] " confirm
                if [[ "${confirm,,}" == "y" ]]; then
                    _loxprox_install_pubkey "$pasted" /root
                    ok "Public key installed at /root/.ssh/authorized_keys."
                    return 0
                fi
                ;;
            H) _loxprox_show_key_help ;;
            K) return 2 ;;
            A)
                error "Deploy aborted by user. SSH config unchanged."
                error "Re-run: sudo bash deploy.sh --finalize-ssh   (after installing a key)"
                exit 1
                ;;
            *) warn "Unknown choice: ${choice:-<empty>}" ;;
        esac
    done
}

_loxprox_write_hard_ssh_drop_in() {
    local drop=/etc/ssh/sshd_config.d/99-loxprox.conf
    backup_file "$drop"
    cat > "$drop" <<'EOF'
# LoxProx — CIS Debian 12 §5.2 SSH hardening (HARD mode)
# Generated by deploy.sh — do not edit by hand.
Protocol 2
LogLevel VERBOSE
MaxAuthTries 4
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxStartups 10:30:60
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
Banner none
EOF
    chmod 0644 "$drop"
}

_loxprox_write_soft_ssh_drop_in() {
    local drop=/etc/ssh/sshd_config.d/99-loxprox.conf
    backup_file "$drop"
    cat > "$drop" <<'EOF'
# LoxProx — SOFT SSH hardening (password auth STILL ENABLED).
# Re-run `sudo bash deploy.sh --finalize-ssh` after installing an
# authorized_keys entry to swap this for the HARD profile.
Protocol 2
LogLevel VERBOSE
MaxAuthTries 4
PermitRootLogin yes
PermitEmptyPasswords no
PasswordAuthentication yes
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxStartups 10:30:60
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
EOF
    chmod 0644 "$drop"
    mkdir -p /var/lib/loxprox && chmod 0750 /var/lib/loxprox
    touch /var/lib/loxprox/ssh-keys-missing
}

_loxprox_install_ssh_motd_nag() {
    install -d -m 0755 /etc/update-motd.d
    cat > /etc/update-motd.d/99-loxprox-ssh-warn <<'MOTD'
#!/bin/sh
# LoxProx — login warning while password auth is still on.
[ -f /var/lib/loxprox/ssh-keys-missing ] || exit 0
RED=$(printf '\033[1;31m'); NC=$(printf '\033[0m')
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
printf '%s\n' "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf '%s\n' "  ⚠  LOXPROX — SSH PASSWORD AUTH IS STILL ENABLED"
printf '%s\n' ""
printf '%s\n' "  No authorized_keys was present when deploy ran. Fix it NOW:"
printf '%s\n' "    1. On your workstation:  ssh-keygen -t ed25519"
printf '%s\n' "    2.                       ssh-copy-id root@${IP:-this-gateway}"
printf '%s\n' "    3. On this gateway:      sudo bash /opt/loxprox/deploy.sh --finalize-ssh"
printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
MOTD
    chmod 0755 /etc/update-motd.d/99-loxprox-ssh-warn
}

_loxprox_remove_ssh_motd_nag() {
    rm -f /etc/update-motd.d/99-loxprox-ssh-warn /var/lib/loxprox/ssh-keys-missing
}

setup_ssh_hardening() {
    banner "SSH Daemon Hardening (CIS §5.2)"

    mkdir -p /var/lib/loxprox && chmod 0750 /var/lib/loxprox

    local mode="hard"
    if ! _loxprox_has_authorized_key; then
        warn "No SSH authorized_keys found anywhere on this gateway."
        if [[ -t 0 && -t 1 ]]; then
            if _loxprox_interactive_collect_pubkey; then
                mode="hard"
            else
                mode="soft"
            fi
        else
            warn "Non-interactive deploy (no tty) — applying SOFT hardening so the box stays reachable."
            mode="soft"
        fi
    fi

    # Defensive re-check: if we plan to go hard, keys MUST be present.
    if [[ "$mode" == "hard" ]] && ! _loxprox_has_authorized_key; then
        error "Internal error: hard hardening selected but no key present after collection. Falling back to SOFT."
        mode="soft"
    fi

    if [[ "$mode" == "hard" ]]; then
        _loxprox_write_hard_ssh_drop_in
        _loxprox_remove_ssh_motd_nag
    else
        _loxprox_write_soft_ssh_drop_in
        _loxprox_install_ssh_motd_nag
    fi

    if ! sshd -t 2>>"$LOG_FILE"; then
        error "sshd -t failed with the new drop-in; reverting."
        rm -f /etc/ssh/sshd_config.d/99-loxprox.conf
        return 1
    fi

    systemctl reload ssh 2>>"$LOG_FILE" || systemctl reload sshd 2>>"$LOG_FILE" || true

    if [[ "$mode" == "hard" ]]; then
        ok "SSH HARD-hardened (key-only, no root, VERBOSE log)."
        ok "  Verify from a SECOND terminal before logging out:  ssh root@<gateway>"
    else
        warn "SSH SOFT-hardened — password auth is STILL ENABLED."
        warn "  Login banner will nag every session until you fix it."
        warn "  From your workstation:   ssh-copy-id root@<gateway>"
        warn "  Then on this gateway:    sudo bash deploy.sh --finalize-ssh"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Unattended upgrades
# ═══════════════════════════════════════════════════════════════════════════════

setup_unattended_upgrades() {
    banner "Unattended Upgrades"

    dpkg -l | grep -q "^ii  unattended-upgrades " || apt-get install -y unattended-upgrades

    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTOREBOOT_TIME}";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    systemctl enable --now unattended-upgrades
    ok "Unattended upgrades enabled — auto-reboot at ${AUTOREBOOT_TIME} for kernel patches."
}

# ═══════════════════════════════════════════════════════════════════════════════
# auditd
# ═══════════════════════════════════════════════════════════════════════════════

setup_auditd() {
    banner "auditd (System Call Auditing)"

    dpkg -l | grep -q "^ii  auditd " || apt-get install -y auditd audispd-plugins

    cat > /etc/audit/rules.d/99-gateway.rules <<EOF
# LoxProx — audit rules
# Generated by deploy.sh on $(date -Iseconds)

# Sensitive config changes
-w /etc/nginx/           -p wa -k nginx_config
-w /etc/crowdsec/        -p wa -k crowdsec_config
-w /etc/nftables.conf    -p wa -k firewall_config
-w /etc/ssh/sshd_config  -p wa -k sshd_config

# Auth-related files
-w /etc/passwd           -p wa -k auth
-w /etc/shadow           -p wa -k auth
-w /etc/sudoers          -p wa -k auth
-w /etc/sudoers.d/       -p wa -k auth

# Privilege escalation
-w /usr/bin/sudo         -p x  -k priv_esc
-w /bin/su               -p x  -k priv_esc

# Cron changes
-w /etc/cron.d/          -p wa -k cron
-w /var/spool/cron/      -p wa -k cron

# Persistence: LD_PRELOAD hijacking (T1574.006)
-w /etc/ld.so.preload    -p wa -k persistence_ld
-w /etc/ld.so.conf       -p wa -k persistence_ld
-w /etc/ld.so.conf.d/    -p wa -k persistence_ld

# Persistence: systemd unit drops (T1543.002)
-w /etc/systemd/system/      -p wa -k persistence_systemd
-w /lib/systemd/system/      -p wa -k persistence_systemd
-w /usr/lib/systemd/system/  -p wa -k persistence_systemd

# Persistence: shell init (T1546.004)
-w /etc/profile          -p wa -k persistence_shell
-w /etc/profile.d/       -p wa -k persistence_shell
-w /etc/bash.bashrc      -p wa -k persistence_shell
-w /root/.bashrc         -p wa -k persistence_shell
-w /root/.bash_profile   -p wa -k persistence_shell
-w /root/.profile        -p wa -k persistence_shell

# Persistence: SSH backdoor keys (T1098.004)
# /home/<user>/.ssh/ paths are added in setup_auditd post-step below for any
# real user accounts that exist at deploy time.
-w /root/.ssh/           -p wa -k persistence_ssh

# Persistence: scheduled-task drops (T1053.003) — periodic cron dirs
-w /etc/cron.hourly/     -p wa -k persistence_cron
-w /etc/cron.daily/      -p wa -k persistence_cron
-w /etc/cron.weekly/     -p wa -k persistence_cron
-w /etc/cron.monthly/    -p wa -k persistence_cron
-w /etc/anacrontab       -p wa -k persistence_cron
EOF

    # Append per-user .ssh watches for non-root accounts present on the box.
    # Done dynamically so freshly created accounts get covered on subsequent
    # deploys (idempotent — augenrules dedupes identical -w lines).
    local rules_file=/etc/audit/rules.d/99-gateway.rules
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" -ge 1000 ]] || continue
        [[ -d "$home" ]] || continue
        [[ "$user" == "nobody" ]] && continue
        if ! grep -q "^-w ${home}/.ssh/ " "$rules_file"; then
            echo "-w ${home}/.ssh/           -p wa -k persistence_ssh" >> "$rules_file"
        fi
    done < /etc/passwd

    augenrules --load 2>/dev/null || service auditd restart
    systemctl enable auditd
    ok "auditd enabled with gateway-specific rules."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Log rotation
# ═══════════════════════════════════════════════════════════════════════════════

setup_logrotate() {
    banner "Log Rotation"
    backup_file "$LOGROTATE_CONF"

    cat > "$LOGROTATE_CONF" <<EOF
/var/log/nginx/loxone-*.log
/var/log/nginx/appsec-detections.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 \$(cat /var/run/nginx.pid)
    endscript
}
EOF
    ok "Logrotate: 14-day retention."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Optional alerting
# ═══════════════════════════════════════════════════════════════════════════════

setup_alerting() {
    if [[ -z "$ALERT_EMAIL" ]]; then
        info "No ALERT_EMAIL set — skipping mail alerting."
        return
    fi

    banner "Mail Alerting"
    command -v mail &>/dev/null || apt-get install -y mailutils bsd-mailx

    # Cron writes /var/lib/loxprox/last-error-count; create the dir up front so
    # alerting works on a pristine host even before setup_security_monitoring runs.
    mkdir -p /var/lib/loxprox
    chmod 0750 /var/lib/loxprox

    cat > /etc/cron.d/loxprox-alert <<EOF
*/15 * * * * root prev=\$(cat /var/lib/loxprox/last-error-count 2>/dev/null || echo 0); curr=\$(wc -l < /var/log/nginx/loxone-error.log 2>/dev/null || echo 0); echo "\$curr" > /var/lib/loxprox/last-error-count; [ \$((curr - prev)) -gt 100 ] && echo "High error rate: \$((curr - prev)) new errors in 15 min" | mail -s "Loxone Gateway Alert" "$ALERT_EMAIL"
EOF
    ok "Alerting → $ALERT_EMAIL"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Security Monitor + Backup + Progressive Ban (cron + systemd timer)
# ═══════════════════════════════════════════════════════════════════════════════
# Installs:
#   /opt/loxprox/gateway-monitor.sh       (systemd timer, 60s)
#   /opt/loxprox/gateway-backup.sh        (cron, daily 02:00)
#   /opt/loxprox/geoip-block.sh           (cron, daily 03:00)
#   /opt/loxprox/progressive-ban.py       (cron, every 15 min)
#   /opt/loxprox/discord-alert.sh         (alert dispatcher)
# ═══════════════════════════════════════════════════════════════════════════════

setup_security_monitoring() {
    banner "Security Monitoring (monitor + backup + progressive ban)"

    local install_dir="/opt/loxprox"
    local src_dir="${SCRIPT_DIR:-.}"
    mkdir -p "$install_dir"

    # Copy the five scripts that cron and the monitor timer drive
    local f
    for f in \
        "$src_dir/progressive-ban.py" \
        "$src_dir/security-monitoring/gateway-monitor.sh" \
        "$src_dir/security-monitoring/gateway-backup.sh" \
        "$src_dir/security-monitoring/geoip-block.sh" \
        "$src_dir/security-monitoring/discord-alert.sh"
    do
        if [[ -f "$f" ]]; then
            install -m 0755 "$f" "$install_dir/"
            info "Installed: $install_dir/$(basename "$f")"
        else
            warn "Missing source: $f — skipping"
        fi
    done

    # Monitor systemd timer (60s cycle)
    cat > /etc/systemd/system/loxprox-monitor.service <<'EOF'
[Unit]
Description=LoxProx Gateway Monitor
After=network.target nginx.service crowdsec.service

[Service]
Type=oneshot
ExecStart=/opt/loxprox/gateway-monitor.sh
StandardOutput=append:/var/log/loxprox-monitor.log
StandardError=append:/var/log/loxprox-monitor.log
EOF

    cat > /etc/systemd/system/loxprox-monitor.timer <<'EOF'
[Unit]
Description=Run LoxProx Gateway Monitor every 60 seconds

[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now loxprox-monitor.timer

    # Single cron file for all periodic jobs
    cat > /etc/cron.d/loxprox <<'EOF'
# LoxProx security automation
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=

# Progressive ban escalation — extend repeat offenders every 15 min
*/15 * * * * root /opt/loxprox/progressive-ban.py >> /var/log/loxprox-cron.log 2>&1

# Daily config backup
0 2 * * * root /opt/loxprox/gateway-backup.sh >> /var/log/loxprox-cron.log 2>&1

# Daily GeoIP blocklist refresh
0 3 * * * root /opt/loxprox/geoip-block.sh >> /var/log/loxprox-cron.log 2>&1
EOF
    chmod 644 /etc/cron.d/loxprox

    ok "Security monitor (60s), daily backup, daily GeoIP, progressive ban (15min) installed."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Network Stack Watchdog
# ═══════════════════════════════════════════════════════════════════════════════
# Installs a self-healing monitor that detects network-layer failures
# (dhclient death-spiral, kernel routing corruption, etc.) and attempts
# recovery via service restart or automatic reboot. See RUNDOWN.md for
# full transparency documentation.
# ═══════════════════════════════════════════════════════════════════════════════

setup_network_watchdog() {
    banner "Network Watchdog"

    local install_dir="/opt/loxprox"
    local script_src="${SCRIPT_DIR:-.}/security-monitoring/network-watchdog.sh"
    local service_src="${SCRIPT_DIR:-.}/security-monitoring/network-watchdog.service"
    local timer_src="${SCRIPT_DIR:-.}/security-monitoring/network-watchdog.timer"
    local discord_src="${SCRIPT_DIR:-.}/security-monitoring/discord-alert.sh"

    mkdir -p "$install_dir"

    # Copy watchdog script
    if [[ -f "$script_src" ]]; then
        cp "$script_src" "$install_dir/network-watchdog.sh"
        chmod 755 "$install_dir/network-watchdog.sh"
        ok "Installed: $install_dir/network-watchdog.sh"
    else
        warn "network-watchdog.sh not found at $script_src — skipping watchdog install"
        return
    fi

    # Copy Discord alert script (watchdog depends on it)
    if [[ -f "$discord_src" ]]; then
        cp "$discord_src" "$install_dir/discord-alert.sh"
        chmod 755 "$install_dir/discord-alert.sh"
        ok "Installed: $install_dir/discord-alert.sh"
    fi

    # Install systemd units
    if [[ -f "$service_src" && -f "$timer_src" ]]; then
        cp "$service_src" /etc/systemd/system/network-watchdog.service
        cp "$timer_src" /etc/systemd/system/network-watchdog.timer
        systemctl daemon-reload
        systemctl enable network-watchdog.timer
        systemctl start network-watchdog.timer
        ok "Network watchdog enabled (runs every 60s)"
        info "Disable any time: systemctl stop network-watchdog.timer"
        info "View logs: journalctl -u network-watchdog --since '10 minutes ago'"
    else
        warn "systemd unit files not found — timer not installed"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Runtime config file (for scripts that need env vars after deploy)
# ═══════════════════════════════════════════════════════════════════════════════

write_runtime_config() {
    banner "Runtime Configuration"

    mkdir -p "$GATEWAY_CONFIG_DIR"
    chmod 750 "$GATEWAY_CONFIG_DIR"

    cat > "$GATEWAY_CONFIG_FILE" <<EOF
# LoxProx — Runtime Configuration
# Generated by deploy.sh on $(date -Iseconds)
# DO NOT EDIT MANUALLY — re-run deploy.sh to regenerate

LOXONE_IP="$LOXONE_IP"
LOXONE_PORT="$LOXONE_PORT"
GATEWAY_IP="$GATEWAY_IP"
LAN_SUBNET="$LAN_SUBNET"
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
ALERT_EMAIL="$ALERT_EMAIL"
APPSEC_MODE="$APPSEC_MODE"
AUTOREBOOT_TIME="$AUTOREBOOT_TIME"
# Watchdog expects this IP on the primary interface. Auto-detected at runtime
# if unset, but pinning it here prevents false positives after IP changes.
WATCHDOG_EXPECTED_IP="$GATEWAY_IP"
EOF

    chmod 640 "$GATEWAY_CONFIG_FILE"
    ok "Runtime config written to $GATEWAY_CONFIG_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Health check
# ═══════════════════════════════════════════════════════════════════════════════

health_check() {
    banner "Health Check"
    local failures=0

    for svc in nginx crowdsec crowdsec-firewall-bouncer nftables auditd unattended-upgrades; do
        if service_active "$svc"; then
            ok "$svc active"
        else
            # nftables exits after loading rules — check enabled instead
            if [[ "$svc" == "nftables" ]] && systemctl is-enabled --quiet nftables; then
                ok "nftables enabled (one-shot service, not persistent)"
            else
                error "$svc NOT active"
                ((failures++))
            fi
        fi
    done

    info "Firewall input policy:"
    nft list chain inet filter input 2>/dev/null | grep policy || warn "Could not read nftables input chain"

    info "CrowdSec decisions (sample):"
    cscli decisions list 2>/dev/null | head -5 || true

    info "Listening ports:"
    ss -tlnp | grep -E ':22 |:1080 ' || warn "Expected ports not found"

    if [[ "$ENABLE_APPSEC" == "true" ]]; then
        info "AppSec listener:"
        ss -tlnp | grep ':7422 ' && ok "AppSec listening on 127.0.0.1:7422 (mode: ${APPSEC_MODE})" || warn "AppSec not listening on :7422 yet (CrowdSec may still be starting)"
        if [[ "$APPSEC_MODE" == "monitor" ]]; then
            info "AppSec in MONITOR mode — requests pass through, detections logged to /var/log/nginx/appsec-detections.log"
            info "Check: cscli alerts list | grep appsec"
            info "To enforce: set APPSEC_MODE=enforce in deploy.sh and re-run"
        fi
    fi

    echo ""
    if [[ $failures -eq 0 ]]; then
        echo -e "${GREEN}════════════════════════════  ALL CHECKS PASSED  ════════════════════════════${NC}"
    else
        echo -e "${RED}════════════════════════  $failures CHECK(S) FAILED  ════════════════════════${NC}"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Rollback
# ═══════════════════════════════════════════════════════════════════════════════

rollback() {
    banner "ROLLBACK"
    warn "Stops nginx/crowdsec and restores last backup."
    read -rp "Sure? [y/N] " yn
    [[ ! "$yn" =~ ^[Yy]$ ]] && { info "Cancelled."; return; }

    local latest
    latest=$(ls -td /root/loxprox-backup-[0-9]* 2>/dev/null | head -1)
    [[ -z "$latest" ]] && { error "No backup found."; exit 1; }

    info "Validating backup files before restore..."
    local validation_errors=0

    # Validate nginx config from backup (if present)
    if [[ -f "$latest/loxone" ]]; then
        if ! nginx -t -c /etc/nginx/nginx.conf 2>/dev/null; then
            error "Current nginx config invalid — aborting rollback to avoid unstartable nginx."
            validation_errors=$((validation_errors + 1))
        fi
    fi

    # Validate nftables config from backup (if present)
    if [[ -f "$latest/nftables.conf" ]]; then
        if ! nft -c -f "$latest/nftables.conf" 2>/dev/null; then
            error "Backup nftables.conf has syntax errors — aborting rollback."
            validation_errors=$((validation_errors + 1))
        fi
    fi

    # Validate CrowdSec config from backup (if present)
    if [[ -f "$latest/config.yaml" ]]; then
        if command -v cscli &>/dev/null; then
            if ! cscli config show 2>/dev/null >/dev/null; then
                warn "CrowdSec config show failed — proceeding with caution."
            fi
        fi
    fi

    if [[ $validation_errors -gt 0 ]]; then
        error "$validation_errors validation error(s) found. Rollback aborted."
        exit 1
    fi

    info "Creating pre-rollback snapshot..."
    local snapshot_dir
    snapshot_dir="/root/loxprox-backup-pre-rollback-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$snapshot_dir"
    cp /etc/nftables.conf "$snapshot_dir/" 2>/dev/null || true
    cp /etc/nginx/sites-available/loxone "$snapshot_dir/" 2>/dev/null || true
    cp /etc/crowdsec/config.yaml "$snapshot_dir/" 2>/dev/null || true

    systemctl stop nginx crowdsec crowdsec-firewall-bouncer 2>/dev/null || true

    for f in "$latest"/*; do
        local name; name=$(basename "$f")
        cp "$f" "/etc/$name" 2>/dev/null || cp "$f" "/$name" 2>/dev/null || true
    done

    systemctl start nginx || true
    ok "Rollback from $latest complete. Pre-rollback snapshot: $snapshot_dir"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════

summary() {
    banner "Deployment Summary"
    cat <<EOF
Platform:           Debian 12 (Bookworm) VM
Loxone backend:     ${LOXONE_IP}:${LOXONE_PORT}
Gateway IP:         ${GATEWAY_IP}
Rate limit:         ${RATE_LIMIT_REQ_PER_SEC} req/s (burst ${RATE_LIMIT_BURST}), ${RATE_LIMIT_CONN_PER_IP} conn/IP
AppSec WAF:         ${ENABLE_APPSEC} (mode: ${APPSEC_MODE})
Auto-reboot:        ${AUTOREBOOT_TIME} (kernel patches)
Backups:            ${BACKUP_DIR}

Services:
  nginx                     → $(service_active nginx      && echo "running" || echo "NOT RUNNING")
  crowdsec                  → $(service_active crowdsec   && echo "running" || echo "NOT RUNNING")
  crowdsec-firewall-bouncer → $(service_active crowdsec-firewall-bouncer && echo "running" || echo "NOT RUNNING")
  auditd                    → $(service_active auditd     && echo "running" || echo "NOT RUNNING")
  unattended-upgrades       → $(service_active unattended-upgrades && echo "running" || echo "NOT RUNNING")
  network-watchdog          → $(systemctl is-active --quiet network-watchdog.timer 2>/dev/null && echo "armed" || echo "NOT ARMED")

Next steps:
  1. Verify proxy: curl -v http://127.0.0.1:1080/jdev/cfg/api
  2. Allow ${GATEWAY_IP} → Loxone:${LOXONE_PORT} in Proxmox firewall
  3. Switch router port forwarding: external 1080 → ${GATEWAY_IP}:1080
  4. Watch traffic: tail -f /var/log/nginx/loxone-access.log
  5. Check blocks:  cscli decisions list

Log: ${LOG_FILE}
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    [[ "${1:-}" == "--rollback" ]] && { rollback; exit 0; }

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    # Re-entry point: extract deploy.conf from the live state of an existing
    # install (the v1.5.0 config-split upgrade path). Does NOT proceed to deploy —
    # operator reviews the file, then runs `sudo bash deploy.sh` normally.
    if [[ "${1:-}" == "--bootstrap-config" ]]; then
        _loxprox_bootstrap_config_interactive
        exit $?
    fi

    # Re-entry point for the SSH hardening bootstrap. Used after the operator
    # installs an authorized_keys entry on a box that was deployed without one
    # (SOFT mode). Swaps the soft drop-in for the hard one and removes the
    # MOTD nag. Safe to run repeatedly.
    if [[ "${1:-}" == "--finalize-ssh" ]]; then
        banner "LoxProx — --finalize-ssh"
        setup_ssh_hardening
        exit 0
    fi

    # v1.5.0 — TLS re-entry points. --renew-tls forces an acme.sh renewal;
    # --remove-tls does a full nuke (site revert + cert + acme.sh + cron).
    # Both require deploy.conf to be loaded so they know TLS_DOMAIN.
    if [[ "${1:-}" == "--renew-tls" || "${1:-}" == "--remove-tls" ]]; then
        _loxprox_load_config || { error "Need $LOXPROX_DEPLOY_CONF to know TLS_DOMAIN"; exit 1; }
        case "$1" in
            --renew-tls)  _loxprox_tls_renew  ;;
            --remove-tls) _loxprox_tls_remove ;;
        esac
        exit $?
    fi

    banner "LoxProx — Debian 12 VM Deploy"
    info "Log: $LOG_FILE"

    # Load per-host configuration. Refuse to use silent placeholder defaults —
    # that footgun bricked operators who forgot to edit deploy.sh in v1.4 and
    # earlier (nginx pointed at 192.168.1.100, nftables allowed 192.168.1.0/24,
    # whole gateway broken on first run).
    if ! _loxprox_load_config; then
        if _loxprox_detect_live_install; then
            if [[ -t 0 && -t 1 ]]; then
                error "No $LOXPROX_DEPLOY_CONF found, but an existing LoxProx install is detected."
                error "First run on this host since the v1.5.0 config split. Bootstrap your config:"
                error "    sudo bash deploy.sh --bootstrap-config"
                error "Then re-run sudo bash deploy.sh."
                exit 1
            else
                warn "Non-interactive deploy without $LOXPROX_DEPLOY_CONF — auto-bootstrapping from live state."
                LOXPROX_BOOTSTRAP_YES=1 _loxprox_bootstrap_config_interactive || exit 1
                _loxprox_load_config || { error "Bootstrap wrote the file but loading still failed."; exit 1; }
            fi
        else
            error "No $LOXPROX_DEPLOY_CONF and no existing LoxProx install detected."
            error "This looks like a fresh VM. Create your config file:"
            error "    sudo install -d -m 0750 /etc/loxprox"
            error "    sudo cp ${SCRIPT_DIR:-.}/deploy.conf.example $LOXPROX_DEPLOY_CONF"
            error "    sudo \$EDITOR $LOXPROX_DEPLOY_CONF      # fill in [REQUIRED] values"
            error "Then re-run sudo bash deploy.sh."
            exit 1
        fi
    fi
    info "Configuration loaded from $LOXPROX_DEPLOY_CONF"

    preflight
    apply_sysctls
    setup_tmp_mount
    setup_firewall

    # Install and run GeoIP blocklist updater
    local geoip_src="${SCRIPT_DIR:-.}/security-monitoring/geoip-block.sh"
    if [[ -f "$geoip_src" ]]; then
        mkdir -p /opt/loxprox
        cp "$geoip_src" /opt/loxprox/geoip-block.sh
        chmod 755 /opt/loxprox/geoip-block.sh
        bash /opt/loxprox/geoip-block.sh || warn "GeoIP blocklist initial load failed — will retry via cron"
    fi

    install_nginx
    configure_nginx
    setup_nginx_hardening
    install_crowdsec
    configure_crowdsec
    configure_appsec_nginx
    setup_apparmor
    setup_tls
    setup_ssh_hardening
    setup_unattended_upgrades
    setup_auditd
    setup_logrotate
    setup_alerting
    setup_security_monitoring
    setup_network_watchdog
    write_runtime_config
    health_check
    summary

    ok "Deployment complete."
}

# Only run main if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
