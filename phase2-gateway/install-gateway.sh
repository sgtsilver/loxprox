#!/bin/bash
# Run this script INSIDE the Security Gateway LXC (as root).
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
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
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
