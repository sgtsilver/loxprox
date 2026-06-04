**Language:** [Deutsch](phase4-monitoring.de.md) · English

# Phase 4 — Monitoring, Tuning & Maintenance

> ⚠️ **Substrate note:** This runbook was originally written for an LXC-based deployment and still uses `LXC` / `pct` terminology in places. **LoxProx is now VM-only** — `deploy.sh` aborts on LXC by default because several defenses (kernel sysctls, Fragnesia mitigation, auditd, AppArmor enforcement, nftables) cannot be applied from inside a container. For a new deployment, substitute "Gateway VM" wherever you see "Gateway LXC", and use `qm config <vmid>` on Proxmox instead of `pct config <ctid>` for the host-side backup step. The monitoring commands inside the gateway itself are substrate-agnostic.

## Daily Checks (First Week After Cutover)

Run these inside the Security Gateway VM daily:

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
- **10 req/s** per IP with burst of 100
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

## If TLS is enabled (v1.5.0+)

Only relevant when `ENABLE_TLS="true"` in `/etc/loxprox/deploy.conf`. Skip otherwise.

### Verify the renewal cron survives

`acme.sh` installs a daily cron in **root's** crontab on first issuance. It survives reboots, but a manual `crontab -e` mishap could wipe it. The v1.5.0 `_loxprox_ensure_acme_cron` step re-asserts it after every TLS-enabled deploy, but check periodically:

```bash
crontab -l | grep acme.sh
# Expected: one line ending in '"/root/.acme.sh"/acme.sh --cron --home …'
```

If missing, the cleanest restore is just a redeploy: `sudo bash deploy.sh`. To restore the cron alone without a full deploy:

```bash
sudo /root/.acme.sh/acme.sh --install-cronjob
```

### Check expiry and force-renew manually

```bash
# Show all certs acme.sh manages, with expiry dates:
sudo /root/.acme.sh/acme.sh --list

# Manual force-renew (e.g. when rotating keys or testing the reload hook):
sudo bash deploy.sh --renew-tls
```

`--renew-tls` calls `acme.sh --renew … --force` and re-runs the install step (so `systemctl reload nginx` fires). Safe to invoke any time.

### Disable TLS cleanly

Two options, depending on how thorough you want to be:

```bash
# Soft disable: site reverts to plain :1080, ACME :80 listener removed,
# per-domain renewal cancelled in acme.sh. Cert files at /etc/loxprox/tls/
# are kept so re-enabling is fast.
sudo $EDITOR /etc/loxprox/deploy.conf       # set ENABLE_TLS="false"
sudo bash deploy.sh

# Full nuke: same as above plus acme.sh --uninstall, /etc/loxprox/tls/
# deleted, cron cancelled. Remaining operator action: remove the
# WAN:80 → gateway:80 router forward.
sudo bash deploy.sh --remove-tls
```

---

## Log Rotation

Already configured by `deploy.sh` (`setup_logrotate`). Verify it works:

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
- [ ] Verify SSH banner is **not** showing the red "password auth still enabled" warning. If it is: install a public key (`ssh-copy-id root@<gateway>`) and run `sudo bash deploy.sh --finalize-ssh` to swap from SOFT to HARD profile.
- [ ] Sanity-check AppSec detections: `tail /var/log/nginx/appsec-detections.log` — should grow under attack and stay empty under normal traffic.
- [ ] **If `ENABLE_TLS=true`:** check cert expiry — `sudo /root/.acme.sh/acme.sh --list`. Should show > 30 days remaining; `acme.sh`'s daily cron renews automatically inside the 30-day window.
- [ ] **If `ENABLE_TLS=true`:** verify the auto-renewal cron is still in root's crontab — `crontab -l | grep acme.sh`. If missing, re-run `sudo bash deploy.sh` (the v1.5.0 `_loxprox_ensure_acme_cron` step re-installs it).

---

## Known Limits & Deferred Work

Items the skills audit (`audits/2026-05-23-skills-audit.md`) raised but that are not fixed by the current `deploy.sh`. Recorded here so they're not re-raised every audit cycle.

### Port-scan visibility

nftables drops scans against `:22` from anything outside `SSH_ALLOWED_SUBNETS` silently — no log line, no CrowdSec event, no offender counter increment. CrowdSec only sees what nginx and `auth.log` surface, so a slow TCP fan-scan against the gateway's ports never makes it into the access log because nginx never accepts past the listen socket.

Fixing it cleanly is invasive: either an nftables `limit rate over … log prefix "portscan: "` rule that streams into a custom CrowdSec parser tailing `kern.log`, or installing `crowdsecurity/iptables` and feeding it. Both add noise and an extra parser. The gateway's threat model treats internet-facing scans as already-mitigated (`:1080` is the only listener on the public side, and CrowdSec's HTTP scenarios catch the actually-interesting probes). Deferred until there's a concrete reason to want scanner-level telemetry.

### No host file-integrity monitoring (AIDE)

The audit flagged the absence of AIDE. The decision to skip it stands:

- `auditd` already watches every config path AIDE would protect, with real-time event-level granularity. AIDE's value is **offline** tampering (rootkit, live-CD modification of disk while the VM is powered off) — a class auditd cannot see.
- AIDE's nightly `aide --check` of `/etc + /bin + /sbin + /usr/bin + /boot` peaks around 200 MB RSS and 5–10 minutes wall time on the 1 GB / 1 vCPU minimum hardware. Both numbers exceed the `network-watchdog.sh` tolerance window — a check running at the wrong moment looks like the box freezing.
- The offline-tampering threat requires either physical access to the Proxmox host or root on the host kernel. Both are out-of-band failures that AIDE would only confirm after the fact, and at that point the recovery path is "restore VM from a known-good snapshot," not "diff against AIDE DB."

Re-evaluate if hardware ever moves to ≥ 2 GB RAM and ≥ 2 vCPU as a hard baseline (not just the recommended floor).

### IoT-assessment skill applies to the Loxone, not the gateway

The audit's `performing-iot-security-assessment` finding targets the Loxone Miniserver Gen 1 itself (UART/JTAG, firmware extraction, default-credential audit) — not LoxProx. LoxProx **is** the compensating control for that legacy device. A real assessment of the Miniserver would require physical access to the Gen 1 unit and is out of scope for the gateway repo.
