#!/bin/bash
# REFERENCE ONLY — superseded by deploy.sh (the single-script installer that is
# the supported path). Kept as the original two-phase manual installer for
# historical reference; not invoked by deploy.sh, CI, or the docs' install flow.
# It installs Nginx, CrowdSec, and configures rate limiting.

set -e

LOXONE_IP="<LOXONE_IP>"    # Loxone Miniserver LAN IP

echo "[+] Installing Nginx..."
apt-get update
apt-get install -y nginx nginx-extras

echo "[+] Deploying Nginx config for Loxone proxy..."
cat > /etc/nginx/sites-available/loxone <<'EOF'
# Rate limit zones
limit_req_zone $binary_remote_addr zone=loxone_req:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=loxone_conn:10m;

# Upstream backend
upstream loxone_backend {
    server BACKEND_IP:80;
    keepalive 32;
}

server {
    listen 1080;
    server_name _;

    # Logging
    access_log /var/log/nginx/loxone-access.log;
    error_log /var/log/nginx/loxone-error.log;

    # Timeouts — mitigate slowloris
    proxy_connect_timeout 10s;
    proxy_send_timeout 15s;
    proxy_read_timeout 15s;
    send_timeout 15s;
    client_body_timeout 10s;
    client_header_timeout 10s;

    # Buffer limits
    client_body_buffer_size 16k;
    client_header_buffer_size 4k;
    large_client_header_buffers 4 8k;
    client_max_body_size 10m;

    # Rate limiting
    limit_req zone=loxone_req burst=20 nodelay;
    limit_conn loxone_conn 20;

    # Proxy headers
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    location / {
        proxy_pass http://loxone_backend;
    }
}
EOF

# Inject real backend IP
sed -i "s/BACKEND_IP/$LOXONE_IP/g" /etc/nginx/sites-available/loxone

# Enable site, disable default
ln -sf /etc/nginx/sites-available/loxone /etc/nginx/sites-enabled/loxone
rm -f /etc/nginx/sites-enabled/default

echo "[+] Testing Nginx config..."
nginx -t

echo "[+] Restarting Nginx..."
systemctl restart nginx
systemctl enable nginx

echo "[+] Installing CrowdSec..."
# GPG-verified install with multi-source fingerprint cross-check.
# Soft-fail (LOXPROX_GPG_VERIFY_MODE=soft, default): warn + fall back to TOFU
#   if quorum of public keyservers is unreachable.
# Hard-fail (=hard): abort when quorum can't be reached.
# Any CONFLICTING fingerprint is always fatal — that's a positive attack signal.
KEYRING="/etc/apt/keyrings/crowdsec-archive-keyring.gpg"
TMP_KEY=$(mktemp)
curl -fsSL -o "$TMP_KEY" "https://packagecloud.io/crowdsec/crowdsec/gpgkey"
if ! gpg --dry-run --import "$TMP_KEY" &>/dev/null; then
    rm -f "$TMP_KEY"
    echo "ERROR: CrowdSec GPG key download failed or is invalid."
    exit 1
fi

GPG_MODE="${LOXPROX_GPG_VERIFY_MODE:-soft}"
GPG_QUORUM="${LOXPROX_GPG_QUORUM:-2}"
PRIMARY_FPR=$(gpg --show-keys --with-fingerprint --with-colons "$TMP_KEY" 2>/dev/null \
              | awk -F: '$1=="fpr" {print $10; exit}')
if [ -z "$PRIMARY_FPR" ]; then
    rm -f "$TMP_KEY"
    echo "ERROR: could not extract fingerprint from CrowdSec GPG key."
    exit 1
fi
echo "    Primary fingerprint: $PRIMARY_FPR"

# Independent keyservers (different operators, DNS, TLS PKI).
GPG_SOURCES=(
    "https://keys.openpgp.org/vks/v1/by-fingerprint/${PRIMARY_FPR}"
    "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${PRIMARY_FPR}&options=mr"
    "https://pgp.surf.nl/pks/lookup?op=get&search=0x${PRIMARY_FPR}&options=mr"
)
AGREE=0; CONFLICT=0; UNREACHABLE=0
for URL in "${GPG_SOURCES[@]}"; do
    KS_TMP=$(mktemp)
    if ! curl -fsSL --max-time 15 -o "$KS_TMP" "$URL" 2>/dev/null; then
        UNREACHABLE=$((UNREACHABLE + 1))
        echo "    unreachable: ${URL%%\?*}"
        rm -f "$KS_TMP"; continue
    fi
    KS_FPR=$(gpg --show-keys --with-fingerprint --with-colons "$KS_TMP" 2>/dev/null \
             | awk -F: '$1=="fpr" {print $10; exit}')
    rm -f "$KS_TMP"
    if [ -z "$KS_FPR" ]; then
        UNREACHABLE=$((UNREACHABLE + 1))
        echo "    parse failure: ${URL%%\?*}"
        continue
    fi
    if [ "$KS_FPR" = "$PRIMARY_FPR" ]; then
        AGREE=$((AGREE + 1))
        echo "    agree:       ${URL%%\?*}"
    else
        CONFLICT=$((CONFLICT + 1))
        echo "    CONFLICT:    ${URL%%\?*} returned $KS_FPR"
    fi
done
if [ "$CONFLICT" -gt 0 ]; then
    rm -f "$TMP_KEY"
    echo "ERROR: ${CONFLICT} keyserver(s) returned a different fingerprint — refusing to install."
    exit 1
fi
if [ "$AGREE" -ge "$GPG_QUORUM" ]; then
    echo "    cross-verified (${AGREE}/${#GPG_SOURCES[@]} sources agree)."
elif [ "$GPG_MODE" = "hard" ]; then
    rm -f "$TMP_KEY"
    echo "ERROR: GPG quorum not met (${AGREE}/${GPG_QUORUM}, ${UNREACHABLE} unreachable). Aborting (mode=hard)."
    exit 1
else
    echo "    WARN: GPG quorum not met (${AGREE}/${GPG_QUORUM}, ${UNREACHABLE} unreachable). Continuing (mode=soft)."
fi

gpg --dearmor < "$TMP_KEY" > "$KEYRING"
rm -f "$TMP_KEY"
echo "deb [signed-by=${KEYRING}] https://packagecloud.io/crowdsec/crowdsec/debian bookworm main" \
    > /etc/apt/sources.list.d/crowdsec.list
apt-get update -q
apt-get install -y crowdsec

echo "[+] Installing CrowdSec firewall bouncer (nftables)..."
apt-get install -y crowdsec-firewall-bouncer-nftables

echo "[+] Deploying CrowdSec acquisition config..."
cat > /etc/crowdsec/acquis.d/nginx.yaml <<'EOF'
filenames:
  - /var/log/nginx/loxone-access.log
  - /var/log/nginx/loxone-error.log
labels:
  type: nginx
EOF

echo "[+] Reloading CrowdSec..."
cscli hub update
cscli collections install crowdsecurity/nginx || true
cscli parsers install crowdsecurity/nginx-logs || true
cscli scenarios install crowdsecurity/http-bf || true
cscli scenarios install crowdsecurity/http-sqli-probing || true
cscli scenarios install crowdsecurity/http-xss-probing || true
systemctl restart crowdsec

echo "[+] Enabling CrowdSec firewall bouncer..."
systemctl enable crowdsec-firewall-bouncer
systemctl start crowdsec-firewall-bouncer

echo "[+] Applying kernel hardening sysctls..."
cat > /etc/sysctl.d/99-security-gateway.conf <<'EOF'
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore source routed packets
net.ipv4.conf.all.accept_source_route = 0

# Log martians
net.ipv4.conf.all.log_martians = 1

# IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

sysctl --system

echo "[+] Setting up logrotate for nginx logs..."
cat > /etc/logrotate.d/loxone-nginx <<'EOF'
/var/log/nginx/loxone-*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
    endscript
}
EOF

echo ""
echo "============================================"
echo "Security Gateway installation complete."
echo ""
echo "Verify Nginx is listening on port 1080:"
echo "   ss -tlnp | grep 1080"
echo ""
echo "Verify CrowdSec is running:"
echo "   cscli metrics"
echo "   cscli decisions list"
echo ""
echo "Verify bouncer is active:"
echo "   systemctl status crowdsec-firewall-bouncer"
echo "============================================"
