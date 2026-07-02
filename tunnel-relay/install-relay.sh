#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Relay VPS Installer (v2.0 tunnel, server side)
# ═══════════════════════════════════════════════════════════════════════════════
# Target: fresh Debian 12 (Bookworm) VPS with a public IPv4 — the smallest
#         instance of any EU provider is plenty (1 vCPU / 1 GB RAM).
#
# What this box becomes: the public entry point for zero-open-ports remote
# access to a LoxProx gateway. The gateway's frpc dials OUT to frps here; the
# Loxone app connects to https://RELAY_DOMAIN and nginx forwards into the
# tunnel. No port needs to be opened on the home router — this is the
# CGNAT/DS-Lite escape hatch (ADR-0002).
#
#   App → nginx:443 (TLS, WS, XFF) → 127.0.0.1:TUNNEL_REMOTE_PORT (frps)
#       → tunnel → frpc on gateway → gateway nginx:1080 → Loxone:80
#
# Usage:
#   1. sudo install -d -m 0750 /etc/loxprox-relay
#   2. sudo cp relay.conf.example /etc/loxprox-relay/relay.conf
#   3. sudo $EDITOR /etc/loxprox-relay/relay.conf   # fill in [REQUIRED] values
#   4. sudo bash install-relay.sh
#
# The script is idempotent — safe to re-run after config changes.
# Companion: the GATEWAY side is enabled via ENABLE_TUNNEL=true in
# /etc/loxprox/deploy.conf + `sudo bash deploy.sh`. Full runbook:
# docs/TUNNEL-SETUP.md in the repo.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONFIGURATION — per-host values live in /etc/loxprox-relay/relay.conf
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RELAY_DOMAIN="${RELAY_DOMAIN-}"
RELAY_EMAIL="${RELAY_EMAIL-}"
TUNNEL_TOKEN="${TUNNEL_TOKEN-}"
FRP_BIND_PORT="${FRP_BIND_PORT-7000}"
TUNNEL_REMOTE_PORT="${TUNNEL_REMOTE_PORT-8443}"
RELAY_ACME_SERVER="${RELAY_ACME_SERVER-letsencrypt}"
RELAY_ACME_FALLBACK_SERVER="${RELAY_ACME_FALLBACK_SERVER-zerossl}"
RELAY_ENABLE_CROWDSEC="${RELAY_ENABLE_CROWDSEC-true}"
RELAY_RATE_LIMIT_REQ_PER_SEC="${RELAY_RATE_LIMIT_REQ_PER_SEC-10}"
RELAY_RATE_LIMIT_BURST="${RELAY_RATE_LIMIT_BURST-100}"
RELAY_RATE_LIMIT_CONN_PER_IP="${RELAY_RATE_LIMIT_CONN_PER_IP-20}"

RELAY_CONF="${RELAY_CONF:-/etc/loxprox-relay/relay.conf}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INTERNALS — Do not edit below
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LOG_FILE="${LOG_FILE:-/var/log/loxprox-relay-install.log}"
BACKUP_DIR="${BACKUP_DIR:-/root/loxprox-relay-backup-$(date +%Y%m%d-%H%M%S)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# frp pins — keep in lockstep with FRP_VER / FRP_SHA256_* in deploy.sh.
FRP_VER="${FRP_VER:-0.69.1}"
FRP_SHA256_AMD64="${FRP_SHA256_AMD64:-7be257b72dbbc60bcb3e0e25a5afd1dfac7b63f897084864d3c956dd3d5674e1}"
FRP_SHA256_ARM64="${FRP_SHA256_ARM64:-bbc0c75e896af3f292fb46ba09c844a04fa9b5ea3530c039c7af20637f836355}"
FRPS_BIN="${FRPS_BIN:-/usr/local/bin/frps}"
FRP_DIR="${FRP_DIR:-/etc/frp}"
FRPS_CONF="${FRPS_CONF:-$FRP_DIR/frps.toml}"
FRPS_UNIT="${FRPS_UNIT:-/etc/systemd/system/frps.service}"

# acme.sh pins — keep in lockstep with ACMESH_VER / ACMESH_SHA256 in deploy.sh.
ACMESH_VER="${ACMESH_VER:-3.1.3}"
ACMESH_SHA256="${ACMESH_SHA256:-efd12b265252f8875269960b6b31830731ccce2b3e6ff8e7ecfbee21fde35ab4}"
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME_WEBROOT="${ACME_WEBROOT:-/var/www/acme}"
RELAY_TLS_DIR="${RELAY_TLS_DIR:-/etc/loxprox-relay/tls}"

NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/loxone-relay}"
NGINX_ENABLED="${NGINX_ENABLED:-/etc/nginx/sites-enabled/loxone-relay}"
NFTABLES_CONF="${NFTABLES_CONF:-/etc/nftables.conf}"
CROWDSEC_NGINX_ACQUIS="${CROWDSEC_NGINX_ACQUIS:-/etc/crowdsec/acquis.d/nginx.yaml}"
CROWDSEC_SSH_ACQUIS="${CROWDSEC_SSH_ACQUIS:-/etc/crowdsec/acquis.d/ssh.yaml}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
info()  { log "${BLUE}[INFO]${NC}  $1"; }
warn()  { log "${YELLOW}[WARN]${NC}  $1"; }
error() { log "${RED}[ERROR]${NC} $1"; }
ok()    { log "${GREEN}[OK]${NC}    $1"; }

banner() {
    log ""
    log "═══════════════════════════════════════════════════════════════"
    log "  $1"
    log "═══════════════════════════════════════════════════════════════"
}

check_root()    { [[ $EUID -eq 0 ]] || { error "Run as root."; exit 1; }; }
service_active(){ systemctl is-active --quiet "$1" 2>/dev/null; }

backup_file() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    mkdir -p "$BACKUP_DIR"
    cp -a "$f" "$BACKUP_DIR/$(basename "$f")"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Config loading + validation
# ═══════════════════════════════════════════════════════════════════════════════

load_config() {
    if [[ ! -f "$RELAY_CONF" ]]; then
        error "No $RELAY_CONF found. Create your config file first:"
        error "    sudo install -d -m 0750 /etc/loxprox-relay"
        error "    sudo cp ${SCRIPT_DIR}/relay.conf.example $RELAY_CONF"
        error "    sudo \$EDITOR $RELAY_CONF      # fill in [REQUIRED] values"
        error "Then re-run sudo bash install-relay.sh."
        exit 1
    fi
    # The file carries TUNNEL_TOKEN; a hand-copied cp yields 0644 — tighten.
    chmod 0640 "$RELAY_CONF" 2>/dev/null || true
    # shellcheck source=/dev/null
    source "$RELAY_CONF"
    info "Configuration loaded from $RELAY_CONF"
}

validate_config() {
    local fail=0
    if [[ -z "$RELAY_DOMAIN" || "$RELAY_DOMAIN" != *.* ]]; then
        error "RELAY_DOMAIN='$RELAY_DOMAIN' — must be a public FQDN pointing at this VPS."
        fail=1
    fi
    if [[ -z "$RELAY_EMAIL" ]]; then
        error "RELAY_EMAIL is empty — required for ACME account registration."
        fail=1
    fi
    if [[ -z "$TUNNEL_TOKEN" ]]; then
        error "TUNNEL_TOKEN is empty. Generate one and use the SAME value on the gateway:"
        error "    openssl rand -hex 32"
        fail=1
    fi
    local p
    for p in "$FRP_BIND_PORT" "$TUNNEL_REMOTE_PORT"; do
        if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
            error "Port value '$p' is not a valid port."
            fail=1
        fi
    done
    if [[ "$FRP_BIND_PORT" == "$TUNNEL_REMOTE_PORT" ]]; then
        error "FRP_BIND_PORT and TUNNEL_REMOTE_PORT must differ."
        fail=1
    fi
    (( fail == 0 )) || exit 1
}

preflight() {
    banner "Preflight"
    check_root
    if ! grep -q "^ID=debian" /etc/os-release 2>/dev/null || \
       ! grep -q "^VERSION_ID=\"12\"" /etc/os-release 2>/dev/null; then
        warn "This installer targets Debian 12 (Bookworm). Proceeding anyway — YMMV."
    fi
    apt-get update -q
    apt-get install -y curl gnupg nginx nftables unattended-upgrades socat >/dev/null
    ok "Base packages present."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Kernel + firewall
# ═══════════════════════════════════════════════════════════════════════════════

apply_sysctls() {
    banner "Kernel Hardening (sysctl)"
    cat > /etc/sysctl.d/99-loxprox-relay.conf <<EOF
# LoxProx relay — kernel hardening
# Generated by install-relay.sh on $(date -Iseconds)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
EOF
    sysctl -p /etc/sysctl.d/99-loxprox-relay.conf 2>&1 | tee -a "$LOG_FILE" || \
        warn "Some sysctl parameters could not be applied"
    ok "Kernel hardening applied."
}

setup_firewall() {
    banner "Firewall (nftables)"
    backup_file "$NFTABLES_CONF"

    cat > "$NFTABLES_CONF" <<EOF
#!/usr/sbin/nft -f
# LoxProx relay — base firewall
# Generated by install-relay.sh on $(date -Iseconds)
#
# CrowdSec bouncer (if enabled) manages 'table ip crowdsec' separately.
# Flush only our table so the bouncer's live table is not disturbed.

table inet filter
flush table inet filter

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept

        ip  protocol icmp  accept
        ip6 nexthdr  icmpv6 accept

        # SSH — open to any source. A relay VPS is administered from dynamic
        # IPs; brute force is handled by CrowdSec + key-only auth. Narrow this
        # to your own ranges if you have static ones.
        tcp dport 22 accept

        # ACME HTTP-01 + 301-to-HTTPS
        tcp dport 80 accept

        # Public HTTPS entry point (Loxone app)
        tcp dport 443 accept

        # frp control channel — TCP and QUIC (UDP) on the same port number
        tcp dport ${FRP_BIND_PORT} accept
        udp dport ${FRP_BIND_PORT} accept

        # NOTE: TUNNEL_REMOTE_PORT (${TUNNEL_REMOTE_PORT}) is NOT opened —
        # frps binds it to 127.0.0.1 only (proxyBindAddr); nginx is the sole
        # public entry point.
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

    systemctl enable nftables
    systemctl restart nftables
    ok "nftables active — input policy: drop; allowed: 22, 80, 443, ${FRP_BIND_PORT} (tcp+udp)."
}

# ═══════════════════════════════════════════════════════════════════════════════
# frps — pinned download, hardened unit
# ═══════════════════════════════════════════════════════════════════════════════

frp_arch() {
    local deb_arch
    deb_arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$deb_arch" in
        amd64|x86_64)  echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *)
            error "Unsupported architecture for frp: '$deb_arch' (need amd64 or arm64)."
            return 1
            ;;
    esac
}

install_frps() {
    banner "frps ${FRP_VER}"

    if [[ -x "$FRPS_BIN" ]]; then
        local have_ver
        have_ver=$("$FRPS_BIN" --version 2>/dev/null || echo "unknown")
        if [[ "$have_ver" == "$FRP_VER" ]]; then
            info "frps $FRP_VER already installed at $FRPS_BIN"
            return 0
        fi
        info "frps version drift: installed=$have_ver pinned=$FRP_VER — reinstalling."
    fi

    local arch expected_sha
    arch=$(frp_arch) || exit 1
    case "$arch" in
        amd64) expected_sha="$FRP_SHA256_AMD64" ;;
        arm64) expected_sha="$FRP_SHA256_ARM64" ;;
    esac

    info "Downloading frp ${FRP_VER} (${arch}, SHA256-pinned tarball, no curl|bash)..."
    local tmp tarball
    tmp=$(mktemp -d -t loxprox-frp.XXXXXX)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'; trap - RETURN" RETURN

    tarball="$tmp/frp_${FRP_VER}_linux_${arch}.tar.gz"
    curl -fsSL -o "$tarball" \
        "https://github.com/fatedier/frp/releases/download/v${FRP_VER}/frp_${FRP_VER}_linux_${arch}.tar.gz" || {
        error "Failed to download frp ${FRP_VER} (${arch})."
        exit 1
    }

    local computed
    computed=$(sha256sum "$tarball" | awk '{print $1}')
    if [[ "$computed" != "$expected_sha" ]]; then
        error "frp tarball SHA256 mismatch — refusing to install."
        error "  expected: $expected_sha"
        error "  got:      $computed"
        error "If frp has released a new version, update FRP_VER + FRP_SHA256_* in install-relay.sh."
        exit 1
    fi
    info "Tarball SHA256 verified."

    tar -xzf "$tarball" -C "$tmp"
    local extract_dir="$tmp/frp_${FRP_VER}_linux_${arch}"
    [[ -f "$extract_dir/frps" ]] || { error "frps binary not found in tarball."; exit 1; }
    install -m 0755 -o root -g root "$extract_dir/frps" "$FRPS_BIN"
    ok "frps ${FRP_VER} installed at $FRPS_BIN"
}

configure_frps() {
    banner "frps configuration"

    if ! getent passwd frps >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir /nonexistent \
                --shell /usr/sbin/nologin frps
        info "Created system user 'frps'."
    fi

    install -d -m 0750 -o root -g frps "$FRP_DIR"
    backup_file "$FRPS_CONF"
    cat > "$FRPS_CONF" <<EOF
# LoxProx relay — frp server (v2.0 tunnel)
# Generated by install-relay.sh on $(date -Iseconds)
# DO NOT EDIT MANUALLY — edit $RELAY_CONF and re-run install-relay.sh.
bindAddr = "0.0.0.0"
bindPort = ${FRP_BIND_PORT}
# QUIC (UDP) on the SAME port number — the gateway picks the protocol via
# TUNNEL_PROTOCOL without ever changing its TUNNEL_SERVER_PORT.
quicBindPort = ${FRP_BIND_PORT}

auth.method = "token"
auth.token = "${TUNNEL_TOKEN}"

# Tunnel-exposed ports bind to loopback ONLY. nginx on :443 is the single
# public entry point; the raw tunnel port is never internet-reachable.
proxyBindAddr = "127.0.0.1"
allowPorts = [
  { single = ${TUNNEL_REMOTE_PORT} }
]
maxPortsPerClient = 1

log.to = "console"
log.level = "info"
EOF
    # Lock the token file down before the chown, independent of umask, so it is
    # never world-readable even briefly (root writes, group frps reads, world nothing).
    chmod 0640 "$FRPS_CONF"
    chown root:frps "$FRPS_CONF"

    cat > "$FRPS_UNIT" <<'EOF'
# LoxProx relay — frp server unit (v2.0 tunnel)
# Generated by install-relay.sh — DO NOT EDIT MANUALLY (re-run installer).
[Unit]
Description=LoxProx frp server (tunnel relay)
Documentation=https://github.com/sgtsilver/loxprox
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=frps
Group=frps
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml
Restart=always
RestartSec=10

# Sandbox — frps binds unprivileged ports and needs nothing else.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
UMask=0077
MemoryMax=256M
TasksMax=128

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$FRPS_UNIT"

    systemctl daemon-reload
    systemctl enable frps
    systemctl restart frps
    ok "frps running on :${FRP_BIND_PORT} (tcp+quic), proxies loopback-bound."
}

# ═══════════════════════════════════════════════════════════════════════════════
# TLS via acme.sh (pinned) — LE primary, ZeroSSL fallback
# ═══════════════════════════════════════════════════════════════════════════════

install_acme_sh() {
    if [[ -x "$ACME_HOME/acme.sh" ]]; then
        info "acme.sh already installed at $ACME_HOME"
        return 0
    fi
    info "Installing acme.sh ${ACMESH_VER} (SHA256-pinned tarball, no curl|bash)..."

    local tmp tarball extract_dir
    tmp=$(mktemp -d -t loxprox-acmesh.XXXXXX)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'; trap - RETURN" RETURN

    tarball="$tmp/acme.sh-${ACMESH_VER}.tar.gz"
    curl -fsSL -o "$tarball" \
        "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACMESH_VER}.tar.gz" || {
        error "Failed to download acme.sh ${ACMESH_VER}"
        exit 1
    }

    local computed
    computed=$(sha256sum "$tarball" | awk '{print $1}')
    if [[ "$computed" != "$ACMESH_SHA256" ]]; then
        error "acme.sh tarball SHA256 mismatch — refusing to install."
        error "  expected: $ACMESH_SHA256"
        error "  got:      $computed"
        exit 1
    fi
    info "Tarball SHA256 verified."

    tar -xzf "$tarball" -C "$tmp"
    extract_dir="$tmp/acme.sh-${ACMESH_VER}"
    (
        cd "$extract_dir"
        ./acme.sh --install --home "$ACME_HOME" --accountemail "$RELAY_EMAIL" \
            --noprofile >> "$LOG_FILE" 2>&1
    )
    [[ -x "$ACME_HOME/acme.sh" ]] || { error "acme.sh install failed."; exit 1; }
    ok "acme.sh ${ACMESH_VER} installed at $ACME_HOME"
}

write_http_site() {
    # Phase 1: :80 only — ACME challenge + 301. Written BEFORE cert issuance
    # so nginx -t passes without cert files.
    mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge"
    chmod 0755 "$ACME_WEBROOT" "$ACME_WEBROOT/.well-known" "$ACME_WEBROOT/.well-known/acme-challenge"

    backup_file "$NGINX_SITE"
    cat > "$NGINX_SITE" <<EOF
# LoxProx relay — public entry point (phase 1: ACME only)
# Generated by install-relay.sh on $(date -Iseconds)

server {
    listen      80 default_server;
    listen      [::]:80 default_server;
    server_name _;

    # No access log: this listener exists for minutes during install and
    # serves only ACME challenges + 301s — nothing worth persisting, and the
    # default combined format would log secret-bearing Loxone request lines.
    access_log  off;

    location ^~ /.well-known/acme-challenge/ {
        root         $ACME_WEBROOT;
        default_type "text/plain";
        try_files    \$uri =404;
    }

    location / {
        return 301 https://${RELAY_DOMAIN}\$request_uri;
    }
}
EOF
    rm -f /etc/nginx/sites-enabled/default
    ln -sf "$NGINX_SITE" "$NGINX_ENABLED"
    nginx -t >> "$LOG_FILE" 2>&1 || { error "nginx -t failed on phase-1 site."; exit 1; }
    systemctl reload nginx || systemctl restart nginx
    systemctl enable nginx
}

acme_issue_with_server() {
    local server="$1" rc=0
    "$ACME_HOME/acme.sh" --issue \
        --webroot "$ACME_WEBROOT" \
        -d "$RELAY_DOMAIN" \
        --server "$server" \
        --accountemail "$RELAY_EMAIL" \
        >> "$LOG_FILE" 2>&1 || rc=$?
    return "$rc"
}

issue_certificate() {
    banner "TLS certificate for $RELAY_DOMAIN"
    install_acme_sh
    write_http_site

    info "Requesting cert from $RELAY_ACME_SERVER via HTTP-01..."
    local rc=0
    acme_issue_with_server "$RELAY_ACME_SERVER" || rc=$?
    case "$rc" in
        0) ok "Cert issued for $RELAY_DOMAIN." ;;
        2) info "Cert already valid; acme.sh skipped re-issue." ;;
        *)
            if [[ -n "$RELAY_ACME_FALLBACK_SERVER" && "$RELAY_ACME_FALLBACK_SERVER" != "$RELAY_ACME_SERVER" ]]; then
                warn "Primary CA failed (rc=$rc) — trying fallback CA: $RELAY_ACME_FALLBACK_SERVER"
                rc=0
                acme_issue_with_server "$RELAY_ACME_FALLBACK_SERVER" || rc=$?
                case "$rc" in
                    0) ok "Cert issued via fallback CA $RELAY_ACME_FALLBACK_SERVER." ;;
                    2) info "Cert already valid; acme.sh skipped re-issue." ;;
                    *)
                        error "Both CAs failed (rc=$rc). Check: DNS A record for $RELAY_DOMAIN"
                        error "points at THIS VPS, and :80 is reachable from the internet."
                        exit 1
                        ;;
                esac
            else
                error "acme.sh --issue failed (rc=$rc). See $LOG_FILE."
                exit 1
            fi
            ;;
    esac

    install -d -m 0750 -o root -g root "$RELAY_TLS_DIR"
    "$ACME_HOME/acme.sh" --install-cert \
        -d "$RELAY_DOMAIN" \
        --fullchain-file "$RELAY_TLS_DIR/fullchain.pem" \
        --key-file       "$RELAY_TLS_DIR/privkey.pem" \
        --reloadcmd      "systemctl reload nginx" \
        >> "$LOG_FILE" 2>&1
    chmod 0640 "$RELAY_TLS_DIR/fullchain.pem" "$RELAY_TLS_DIR/privkey.pem"

    # Auto-renew cron (acme.sh installs it with --install; verify it's there).
    if ! crontab -l 2>/dev/null | grep -qF "$ACME_HOME/acme.sh --cron"; then
        "$ACME_HOME/acme.sh" --install-cronjob >> "$LOG_FILE" 2>&1 || \
            warn "Could not install acme.sh cron — renewals will NOT happen automatically."
    fi
    ok "Cert installed at $RELAY_TLS_DIR; auto-renewal via acme.sh cron."
}

# ═══════════════════════════════════════════════════════════════════════════════
# nginx — phase 2: the real :443 site
# ═══════════════════════════════════════════════════════════════════════════════

write_https_site() {
    banner "nginx — public HTTPS site"
    backup_file "$NGINX_SITE"

    cat > "$NGINX_SITE" <<EOF
# LoxProx relay — public entry point
# Generated by install-relay.sh on $(date -Iseconds)
#
# TLS terminates here; plain HTTP goes into the loopback-bound frps proxy
# port and through the tunnel to the gateway's nginx (which keeps its full
# CrowdSec/AppSec stack on the path).

limit_req_zone  \$binary_remote_addr zone=relay_req:10m  rate=${RELAY_RATE_LIMIT_REQ_PER_SEC}r/s;
limit_conn_zone \$binary_remote_addr zone=relay_conn:10m;

# WebSocket upgrade transparency (same construct as the gateway site).
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    "" "";
}

# Token confidentiality (v1.5.1 F3, replicated at the relay): the default
# combined log format would persist Loxone gettoken HMACs and encrypted
# command blobs at rest. Log the path only, with secret-bearing endpoint
# suffixes redacted.
map \$uri \$loxone_log_uri {
    default                                                                      \$uri;
    "~^(?<loxsens>/jdev/sys/(?:fenc|enc|gettoken|getjwt|keyexchange|getkey2?)/)" "\${loxsens}<redacted>";
}
log_format loxone_scrubbed '\$remote_addr - \$remote_user [\$time_local] '
                           '"\$request_method \$loxone_log_uri \$server_protocol" \$status \$body_bytes_sent '
                           '"\$http_referer" "\$http_user_agent"';

server {
    listen      80 default_server;
    listen      [::]:80 default_server;
    server_name _;

    # Scrubbed format here too: a Loxone app misconfigured for plain HTTP
    # would otherwise persist its gettoken HMAC / fenc blob in the default
    # combined log (v1.5.1 token-confidentiality, replicated at the relay).
    access_log /var/log/nginx/relay-access.log loxone_scrubbed;

    location ^~ /.well-known/acme-challenge/ {
        root         $ACME_WEBROOT;
        default_type "text/plain";
        try_files    \$uri =404;
    }

    location / {
        return 301 https://${RELAY_DOMAIN}\$request_uri;
    }
}

server {
    listen      443 ssl default_server;
    listen      [::]:443 ssl default_server;
    server_name ${RELAY_DOMAIN};

    ssl_certificate     ${RELAY_TLS_DIR}/fullchain.pem;
    ssl_certificate_key ${RELAY_TLS_DIR}/privkey.pem;
    ssl_protocols       TLSv1.3 TLSv1.2;
    # PFS-only cipher list for TLS 1.2 clients (TLS 1.3 suites are PFS by default).
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:relay_ssl:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    add_header          Strict-Transport-Security "max-age=31536000" always;

    access_log /var/log/nginx/relay-access.log loxone_scrubbed;
    error_log  /var/log/nginx/relay-error.log;

    # Perimeter rate limits — the first line of defense before the tunnel.
    limit_req  zone=relay_req  burst=${RELAY_RATE_LIMIT_BURST} nodelay;
    limit_conn relay_conn ${RELAY_RATE_LIMIT_CONN_PER_IP};

    client_max_body_size        10m;
    client_body_timeout         10s;
    client_header_timeout       10s;

    proxy_hide_header Server;
    proxy_hide_header X-Powered-By;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Upgrade            \$http_upgrade;
        proxy_set_header Connection         \$connection_upgrade;
        proxy_set_header Host               \$host;
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  https;
        proxy_connect_timeout 10s;
        proxy_send_timeout    30s;
        proxy_read_timeout    30s;
        proxy_pass http://127.0.0.1:${TUNNEL_REMOTE_PORT};
    }

    # Loxone native WebSocket — long-lived event stream, 24h timeouts,
    # no buffering (mirrors the gateway's /ws/ location).
    location /ws/ {
        proxy_http_version 1.1;
        proxy_set_header Upgrade            \$http_upgrade;
        proxy_set_header Connection         "upgrade";
        proxy_set_header Host               \$host;
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  https;
        proxy_read_timeout  86400s;
        proxy_send_timeout  86400s;
        proxy_buffering     off;
        proxy_pass http://127.0.0.1:${TUNNEL_REMOTE_PORT};
    }
}
EOF

    ln -sf "$NGINX_SITE" "$NGINX_ENABLED"
    nginx -t >> "$LOG_FILE" 2>&1 || { error "nginx -t failed on phase-2 site."; exit 1; }
    systemctl reload nginx
    ok "nginx serving https://${RELAY_DOMAIN} → tunnel."
}

# ═══════════════════════════════════════════════════════════════════════════════
# CrowdSec (optional, default on) — perimeter IDS + enforcement
# ═══════════════════════════════════════════════════════════════════════════════
# This is where bans against tunneled attackers actually bite: the gateway's
# own nftables never sees their packets (they arrive via loopback from frpc),
# so the relay is the enforcement point for the tunnel path.
# ═══════════════════════════════════════════════════════════════════════════════

verify_crowdsec_key() {
    # Cross-check the packagecloud key fingerprint against independent public
    # keyservers before importing (same design as deploy.sh — see there for
    # the full rationale). Conflict → abort; quorum met → trust; quorum not
    # met → warn + TOFU (soft mode).
    local primary_key="$1"
    local quorum="${LOXPROX_GPG_QUORUM:-2}"
    local sources=(
        "https://keys.openpgp.org/vks/v1/by-fingerprint/%FPR%"
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x%FPR%&options=mr"
        "https://pgp.surf.nl/pks/lookup?op=get&search=0x%FPR%&options=mr"
    )

    local primary_fpr
    primary_fpr=$(gpg --show-keys --with-fingerprint --with-colons "$primary_key" 2>/dev/null \
                  | awk -F: '$1=="fpr" {print $10; exit}')
    [[ -n "$primary_fpr" ]] || { error "Could not extract fingerprint from primary key"; return 1; }
    info "Primary key fingerprint: $primary_fpr"

    local agree=0 conflict=0
    local src_tpl url tmp fpr
    for src_tpl in "${sources[@]}"; do
        url="${src_tpl//%FPR%/$primary_fpr}"
        tmp=$(mktemp)
        if ! curl -fsSL --max-time 15 -o "$tmp" "$url" 2>/dev/null; then
            rm -f "$tmp"; continue
        fi
        fpr=$(gpg --show-keys --with-fingerprint --with-colons "$tmp" 2>/dev/null \
              | awk -F: '$1=="fpr" {print $10; exit}')
        rm -f "$tmp"
        [[ -z "$fpr" ]] && continue
        if [[ "$fpr" == "$primary_fpr" ]]; then
            agree=$((agree + 1))
        else
            conflict=$((conflict + 1))
            warn "CONFLICT: ${url%%\?*} returned $fpr (expected $primary_fpr)"
        fi
    done

    if (( conflict > 0 )); then
        error "Fingerprint conflict on ${conflict} keyserver(s) — refusing to import."
        return 1
    fi
    if (( agree >= quorum )); then
        ok "GPG key cross-verified (${agree}/${#sources[@]} sources agree)."
    else
        warn "Keyserver quorum not met (${agree}/${quorum}) — proceeding on TOFU."
    fi
    return 0
}

setup_crowdsec() {
    [[ "${RELAY_ENABLE_CROWDSEC,,}" == "true" ]] || {
        info "RELAY_ENABLE_CROWDSEC=false — skipping CrowdSec (NOT recommended)."
        return 0
    }
    banner "CrowdSec (perimeter IDS + enforcement)"

    if ! command -v cscli &>/dev/null; then
        info "Adding CrowdSec repository (GPG-pinned, no curl|bash)..."
        local keyring="/etc/apt/keyrings/crowdsec-archive-keyring.gpg"
        local tmp_key
        tmp_key=$(mktemp)
        curl -fsSL -o "$tmp_key" "https://packagecloud.io/crowdsec/crowdsec/gpgkey"
        if ! gpg --dry-run --import "$tmp_key" &>/dev/null; then
            rm -f "$tmp_key"
            error "Downloaded CrowdSec GPG key is invalid. Possible MITM."
            exit 1
        fi
        if ! verify_crowdsec_key "$tmp_key"; then
            rm -f "$tmp_key"
            error "CrowdSec GPG cross-verification failed — refusing to install."
            exit 1
        fi
        mkdir -p /etc/apt/keyrings
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

    mkdir -p /etc/crowdsec/acquis.d
    cat > "$CROWDSEC_NGINX_ACQUIS" <<EOF
# Relay nginx log acquisition
filenames:
  - /var/log/nginx/relay-access.log
  - /var/log/nginx/relay-error.log
labels:
  type: nginx
EOF
    cat > "$CROWDSEC_SSH_ACQUIS" <<EOF
# SSH acquisition
filenames:
  - /var/log/auth.log
labels:
  type: syslog
EOF

    cscli hub update || true
    cscli collections install crowdsecurity/nginx               --error || true
    cscli collections install crowdsecurity/sshd                --error || true
    cscli collections install crowdsecurity/linux               --error || true
    cscli collections install crowdsecurity/http-cve            --error || true
    cscli collections install crowdsecurity/base-http-scenarios --error || true

    # Bouncer must start after nftables so its table survives reloads.
    mkdir -p /etc/systemd/system/crowdsec-firewall-bouncer.service.d
    cat > /etc/systemd/system/crowdsec-firewall-bouncer.service.d/after-nftables.conf <<EOF
[Unit]
After=nftables.service
Wants=nftables.service
EOF
    systemctl daemon-reload
    systemctl enable --now crowdsec
    systemctl restart crowdsec
    systemctl enable --now crowdsec-firewall-bouncer
    systemctl restart crowdsec-firewall-bouncer
    ok "CrowdSec active — community blocklists + local detection at the perimeter."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Unattended upgrades
# ═══════════════════════════════════════════════════════════════════════════════

setup_unattended_upgrades() {
    banner "Unattended Upgrades"
    cat > /etc/apt/apt.conf.d/51loxprox-relay <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
EOF
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    systemctl enable --now unattended-upgrades
    ok "Unattended upgrades enabled — auto-reboot 03:30 for kernel patches."
}

# ═══════════════════════════════════════════════════════════════════════════════
# Health check + summary
# ═══════════════════════════════════════════════════════════════════════════════

health_check() {
    banner "Health Check"
    local failures=0
    local services=(nginx frps nftables unattended-upgrades)
    [[ "${RELAY_ENABLE_CROWDSEC,,}" == "true" ]] && services+=(crowdsec crowdsec-firewall-bouncer)

    for svc in "${services[@]}"; do
        if service_active "$svc"; then
            ok "$svc active"
        elif [[ "$svc" == "nftables" ]] && systemctl is-enabled --quiet nftables; then
            ok "nftables enabled (one-shot service)"
        else
            error "$svc NOT active"
            # ((failures++)) would return 1 on the first increment and abort
            # the installer under set -e before the summary prints.
            failures=$((failures + 1))
        fi
    done

    info "Listening sockets (expect :22 :80 :443 :${FRP_BIND_PORT}; :${TUNNEL_REMOTE_PORT} appears once the gateway connects):"
    ss -tlnp | grep -E ":(22|80|443|${FRP_BIND_PORT}|${TUNNEL_REMOTE_PORT}) " || true

    echo ""
    if [[ $failures -eq 0 ]]; then
        echo -e "${GREEN}════════════════════════════  ALL CHECKS PASSED  ════════════════════════════${NC}"
    else
        echo -e "${RED}════════════════════════  $failures CHECK(S) FAILED  ════════════════════════${NC}"
        exit 1
    fi
}

summary() {
    banner "Relay Summary"
    cat <<EOF
Public entry point: https://${RELAY_DOMAIN}
frp control port:   ${FRP_BIND_PORT} (tcp + quic/udp)
Tunnel proxy port:  127.0.0.1:${TUNNEL_REMOTE_PORT} (loopback only, via nginx)
CrowdSec:           ${RELAY_ENABLE_CROWDSEC}
Rate limit:         ${RELAY_RATE_LIMIT_REQ_PER_SEC} req/s (burst ${RELAY_RATE_LIMIT_BURST}), ${RELAY_RATE_LIMIT_CONN_PER_IP} conn/IP

Next steps (gateway side):
  1. In /etc/loxprox/deploy.conf on the GATEWAY set:
       ENABLE_TUNNEL="true"
       TUNNEL_SERVER_ADDR="<this VPS IP or DNS>"
       TUNNEL_SERVER_PORT="${FRP_BIND_PORT}"
       TUNNEL_TOKEN="<same token as this relay>"
       TUNNEL_REMOTE_PORT="${TUNNEL_REMOTE_PORT}"
       TUNNEL_PUBLIC_HOST="${RELAY_DOMAIN}"
  2. Run: sudo bash deploy.sh
  3. Verify from outside the LAN: curl -vI https://${RELAY_DOMAIN}/
  4. Full runbook: docs/TUNNEL-SETUP.md

Log: ${LOG_FILE}
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    banner "LoxProx — Relay VPS Install"
    check_root
    load_config
    validate_config
    preflight
    apply_sysctls
    setup_firewall
    install_frps
    configure_frps
    issue_certificate
    write_https_site
    setup_crowdsec
    setup_unattended_upgrades
    health_check
    summary
    ok "Relay deployment complete."
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
