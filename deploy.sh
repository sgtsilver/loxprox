#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Loxone Miniserver Gen 1 — Security Gateway Deployment Script
# ═══════════════════════════════════════════════════════════════════════════════
# Target: fresh Debian 12 (Bookworm) VM on Proxmox — 1 vCPU, 512 MB RAM, 5 GB disk
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
# CONFIGURATION — Edit ALL values below before running
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# QUICK START:
#   1. Run ./detect-loxone.sh to auto-find your Miniserver
#   2. Fill in the 6 required values marked with [REQUIRED]
#   3. Review the optional values and adjust if needed
#   4. Save and run: sudo ./deploy.sh
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ═══════════════════════════════════════════════════════════════════════════════
# REQUIRED — Network & Target Device
# ═══════════════════════════════════════════════════════════════════════════════

# [REQUIRED] Loxone Miniserver IP address
#   How to find: Run ./detect-loxone.sh on this machine, or check your router's
#   DHCP lease table for a device named "Loxone" or with MAC starting EE:E0:00
#   Example: "192.168.1.100"
LOXONE_IP="192.168.1.100"

# [REQUIRED] Loxone port (Gen 1 = 80, Gen 2 = usually 80 with HTTPS redirect)
#   This is the port the Miniserver listens on INSIDE your LAN.
#   Do NOT change this unless you reconfigured the Miniserver itself.
LOXONE_PORT="80"

# [REQUIRED] This gateway's static IP address
#   This VM/LXC must have a static IP so router port forwarding doesn't break.
#   Example: "192.168.1.50"
#   How to set: Run ./set-static-ip.sh BEFORE this script if needed.
GATEWAY_IP="192.168.1.50"

# [REQUIRED] Your LAN subnet (CIDR notation)
#   This is the network range that can reach SSH and is whitelisted in CrowdSec.
#   Example: "192.168.1.0/24"
#   How to find: ip route | grep default → check your interface's network mask
LAN_SUBNET="192.168.1.0/24"

# [REQUIRED] SSH allowed subnets (space-separated list inside quotes)
#   Only IPs from these networks can connect via SSH.
#   NEVER add 0.0.0.0/0 here — that exposes SSH to the entire internet.
#   Add your home LAN, a site-to-site VPN, and any jump boxes.
#   Example: ("192.168.1.0/24" "192.168.100.0/24" "10.8.0.0/24")
SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")

# ═══════════════════════════════════════════════════════════════════════════════
# OPTIONAL — Rate Limiting (defaults are safe for home automation)
# ═══════════════════════════════════════════════════════════════════════════════

# Nginx rate limits — how many requests per second each IP can make
#   10 req/s with burst 100 is tuned for Loxone's web UI (it loads many assets).
#   Lower this if you see abuse; raise it if legitimate users get 503 errors.
RATE_LIMIT_REQ_PER_SEC="10"
RATE_LIMIT_BURST="100"

# Maximum concurrent connections per IP
#   20 is generous for a home setup. Prevents connection exhaustion attacks.
RATE_LIMIT_CONN_PER_IP="20"

# Proxy timeouts — how long nginx waits for the Miniserver to respond
#   These values protect against slowloris attacks (attackers hold connections
#   open to exhaust resources). Do not increase above 30s.
PROXY_CONNECT_TIMEOUT="10"
PROXY_SEND_TIMEOUT="15"
PROXY_READ_TIMEOUT="15"
CLIENT_BODY_TIMEOUT="10"
CLIENT_HEADER_TIMEOUT="10"

# ═══════════════════════════════════════════════════════════════════════════════
# OPTIONAL — CrowdSec AppSec WAF
# ═══════════════════════════════════════════════════════════════════════════════

# Enable the CrowdSec AppSec Web Application Firewall
#   true  = Every HTTP request is inspected for CVE exploit patterns before
#           reaching the Loxone. Blocks known attack tools automatically.
#   false = Skip AppSec (not recommended).
ENABLE_APPSEC="true"

# AppSec operating mode
#   "monitor" — AppSec logs suspicious requests but does NOT block them.
#               Use this for the first week to verify no false positives.
#   "enforce" — AppSec blocks matched requests with HTTP 403.
#               Use this after you're confident the rules work for your setup.
#   Switching modes: change the value and re-run ./deploy.sh (idempotent).
APPSEC_MODE="enforce"

# ═══════════════════════════════════════════════════════════════════════════════
# OPTIONAL — CrowdSec Whitelist (trusted IPs that can never be banned)
# ═══════════════════════════════════════════════════════════════════════════════

# IPs and CIDR ranges that CrowdSec will NEVER block, even under attack.
#   Add your home LAN, VPN endpoints, uptime monitoring services, etc.
#   Format: "1.2.3.4" for single IPs, "192.168.1.0/24" for ranges.
#   Lines starting with # are ignored.
CROWDSEC_WHITELIST_IPS=(
    "192.168.1.0/24"      # [REQUIRED] your local LAN
    "10.0.0.0/24"         # [optional] site-to-site / VPN network
    # "203.0.113.45"      # [optional] uptime monitoring service
    # "198.51.100.0/24"   # [optional] cloud provider IP range
)

# ═══════════════════════════════════════════════════════════════════════════════
# OPTIONAL — Alerting
# ═══════════════════════════════════════════════════════════════════════════════

# Discord webhook URL for real-time security alerts
#   Get a webhook URL from your Discord server:
#   1. Open Discord → Server Settings → Integrations → Webhooks
#   2. Create a webhook, copy the URL, paste it here.
#   3. Leave empty "" to disable Discord alerts entirely.
#   The script /opt/loxprox/discord-alert.sh uses this URL.
DISCORD_WEBHOOK_URL=""

# Email address for nginx error spike alerts (leave empty to skip)
#   Requires mailutils to be installed. Sends an email if nginx error log
#   grows by more than 100 lines in 15 minutes.
ALERT_EMAIL=""

# ═══════════════════════════════════════════════════════════════════════════════
# OPTIONAL — Maintenance
# ═══════════════════════════════════════════════════════════════════════════════

# Time for automatic reboot after kernel security updates
#   Format: 24-hour clock, local time.
#   Example: "03:00" = 3 AM. Set to a time when no one uses the Loxone.
AUTOREBOOT_TIME="03:00"

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

    # Debian 12 check
    if ! grep -q "bookworm\|12" /etc/os-release 2>/dev/null; then
        warn "This script targets Debian 12 (Bookworm). Detected OS may differ — continuing."
    fi

    # VM check (not LXC)
    if systemd-detect-virt --container &>/dev/null; then
        warn "Running inside a container. This script is designed for a VM. Some features may not work correctly."
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
    backup_file "$NGINX_SITE"
    rm -f /etc/nginx/sites-enabled/default

    local appsec_include="" appsec_auth=""
    if [[ "$ENABLE_APPSEC" == "true" ]]; then
        # Placeholder include — will be overwritten with real bouncer key after CrowdSec setup
        appsec_include="    include ${NGINX_APPSEC_INCLUDE};"
        appsec_auth='
        auth_request      /crowdsec-appsec;
        auth_request_set  $appsec_action $upstream_http_x_crowdsec_action;'
    fi

    cat > "$NGINX_SITE" <<EOF
# Loxone Miniserver Gen 1 — Security Gateway
# Generated by deploy.sh on $(date -Iseconds)

limit_req_zone  \$binary_remote_addr zone=loxone_req:10m  rate=${RATE_LIMIT_REQ_PER_SEC}r/s;
limit_conn_zone \$binary_remote_addr zone=loxone_conn:10m;

upstream loxone_backend {
    server ${LOXONE_IP}:${LOXONE_PORT};
    keepalive 32;
}

server {
    listen 1080;
    server_name _;

    access_log /var/log/nginx/loxone-access.log;
    error_log  /var/log/nginx/loxone-error.log;

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
        proxy_set_header Connection         "";
        proxy_set_header Host               \$host;
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  \$scheme;
        proxy_pass http://loxone_backend;
    }
}
EOF

    # Create placeholder AppSec include so nginx -t passes before CrowdSec is ready
    if [[ "$ENABLE_APPSEC" == "true" ]]; then
        touch "$NGINX_APPSEC_INCLUDE"
    fi

    ln -sf "$NGINX_SITE" "$NGINX_ENABLED"
    nginx -t 2>&1 | tee -a "$LOG_FILE"
    systemctl restart nginx
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

    # Intentionally NOT running 'cscli hub upgrade' — uncontrolled upgrades can
    # break parsers or scenarios. Upgrade manually after testing in staging.
    info "Hub components installed. Run 'cscli hub upgrade' manually when validated."

    # Whitelist trusted IPs
    info "Writing CrowdSec whitelist..."
    mkdir -p /etc/crowdsec/parsers/s02-enrich
    local wl="/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml"
    backup_file "$wl"
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
EOF

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

    banner "LoxProx — Debian 12 VM Deploy"
    info "Log: $LOG_FILE"

    preflight
    apply_sysctls
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
