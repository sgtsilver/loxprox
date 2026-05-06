# Phase 4 — Monitoring, Tuning & Maintenance

## Daily Checks (First Week After Cutover)

Run these inside the Security Gateway LXC daily:

```bash
# View blocked IPs
cscli decisions list

# View CrowdSec metrics
cscli metrics

# Check nginx error log for anomalies
tail -n 200 /var/log/nginx/loxone-error.log

# Check most active source IPs (spot scanners)
awk '{print $1}' /var/log/nginx/loxone-access.log | sort | uniq -c | sort -rn | head -n 20
```

---

## Tuning Rate Limits

The default config uses:
- **10 req/s** per IP with burst of 20
- **20 concurrent connections** per IP

If legitimate users are being blocked (e.g., the Loxone App makes many rapid requests):

1. Edit `/etc/nginx/sites-available/loxone`
2. Adjust `rate=` in the `limit_req_zone` line:
   - Relaxed: `rate=30r/s` burst=50
   - Strict:  `rate=5r/s`  burst=10
3. Adjust `limit_conn`:
   - Relaxed: `limit_conn loxone_conn 50;`
   - Strict:  `limit_conn loxone_conn 10;`
4. Test and reload:
   ```bash
   nginx -t && systemctl reload nginx
   ```

> 💡 Monitor for 24h after each change. Balance security vs. usability.

---

## CrowdSec Maintenance

### Update Hub Collections

```bash
cscli hub update
cscli hub upgrade
systemctl reload crowdsec
```

### Add More Scenarios (Optional)

```bash
# HTTP probing / crawling
cscli scenarios install crowdsecurity/http-probing

# Known bad user-agents
cscli scenarios install crowdsecurity/http-bad-user-agent

# Brute force on generic HTTP auth
cscli scenarios install crowdsecurity/http-bf-wordpress
```

### Whitelist Your Own IPs

If you accidentally get blocked during testing:

```bash
# Inside LXC
cscli decisions delete --ip YOUR_PUBLIC_IP
```

To permanently whitelist the LAN:

```bash
cat > /etc/crowdsec/parsers/s02-enrich/whitelist-lan.yaml <<'EOF'
name: whitelist-lan
description: "Whitelist LAN traffic"
whitelist:
  reason: "LAN source"
  ip:
    - "<LAN_SUBNET>"
EOF

systemctl reload crowdsec
```

---

## Log Rotation

Already configured by `install-gateway.sh`. Verify it works:

```bash
logrotate -d /etc/logrotate.d/loxone-nginx
```

Logs are kept for **14 days** then compressed and rotated out.

---

## Backup the Gateway Config

After everything is stable, back up these files:

```bash
# Inside LXC
mkdir -p /root/gateway-backup
cp /etc/nginx/sites-available/loxone /root/gateway-backup/
cp /etc/crowdsec/acquis.d/nginx.yaml /root/gateway-backup/
cp /etc/sysctl.d/99-security-gateway.conf /root/gateway-backup/
cp /etc/logrotate.d/loxone-nginx /root/gateway-backup/
```

Also export the Proxmox LXC config from the host:

```bash
# On Proxmox host
pct config 200 > /root/loxone-gateway-lxc-config-backup.txt
```

---

## Alerting (Optional but Recommended)

### Simple: Email on High Error Rate

Install `mailutils` and configure a cron job to email if nginx error log spikes:

```bash
apt-get install -y mailutils
```

Cron entry (`crontab -e`):
```cron
# Check every 15 min; alert if > 100 errors in last 5 min
*/15 * * * * [ $(tail -n 500 /var/log/nginx/loxone-error.log | wc -l) -gt 100 ] && echo "High error rate on Loxone gateway" | mail -s "Loxone Gateway Alert" admin@yourdomain.com
```

### Advanced: Promtail + Loki / Grafana

If you run a home monitoring stack, ship nginx logs to Loki/Grafana for dashboards and alerting.

---

## Incident Response Playbook

### Scenario: Gateway is unresponsive

1. From Proxmox host: `pct exec 200 -- systemctl status nginx crowdsec`
2. Check resource usage: `pct exec 200 -- htop` (or `top`)
3. If gateway is overwhelmed, temporarily bypass it:
   - Revert router forwarding to Loxone IP directly.
   - Investigate logs later.
   - Restart gateway and re-cutover when stable.

### Scenario: Legitimate users blocked

1. Check `cscli decisions list` for their IP.
2. Whitelist if needed (see above).
3. Relax rate limits if the block was caused by nginx.

### Scenario: Loxone becomes unreachable externally

1. Verify router forwarding is still pointing to gateway IP.
2. Verify gateway LXC is running: `pct status 200`
3. Verify gateway can reach Loxone: `pct exec 200 -- curl -v http://LOXONE_IP:80/jdev/cfg/api`
4. Check nginx error log for backend timeouts.

---

## Monthly Maintenance Checklist

- [ ] CrowdSec hub updated (`cscli hub update && cscli hub upgrade`)
- [ ] LXC OS packages updated (`apt-get update && apt-get upgrade`)
- [ ] Review blocked IPs and false positives
- [ ] Check disk usage inside LXC (`df -h`)
- [ ] Verify backups exist
- [ ] Review nginx access logs for unusual patterns
