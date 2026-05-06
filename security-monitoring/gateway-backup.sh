#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — Config Backup
# ═══════════════════════════════════════════════════════════════════════════════
# Backs up all gateway configuration files to timestamped archive.
# Run daily via cron or systemd timer.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

BACKUP_DIR="/root/loxprox-backups"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="loxone-loxprox-backup-${TIMESTAMP}"
WORK_DIR=$(mktemp -d /tmp/loxprox-backup.XXXXXXXXXX)

mkdir -p "$BACKUP_DIR"

# Config files to back up
backup_file() {
    local src="$1"
    local dest="$2"
    [ -f "$src" ] && cp "$src" "$dest/" && echo "Backed up: $src"
}

backup_file /etc/nginx/nginx.conf "$WORK_DIR"
backup_file /etc/nginx/sites-available/loxone "$WORK_DIR"
backup_file /etc/nftables.conf "$WORK_DIR"
backup_file /etc/sysctl.d/99-security-gateway.conf "$WORK_DIR"
backup_file /etc/crowdsec/config.yaml "$WORK_DIR"
backup_file /etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml "$WORK_DIR"
backup_file /etc/crowdsec/acquis.d/nginx.yaml "$WORK_DIR"
backup_file /etc/crowdsec/acquis.d/ssh.yaml "$WORK_DIR"
backup_file /etc/crowdsec/acquis.d/appsec.yaml "$WORK_DIR"
backup_file /etc/audit/rules.d/99-gateway.rules "$WORK_DIR"
backup_file /etc/logrotate.d/loxone-nginx "$WORK_DIR"
backup_file /etc/systemd/system/nginx.service.d/hardening.conf "$WORK_DIR"

# Package list
apt list --installed 2>/dev/null | grep -E "nginx|crowdsec|apparmor|auditd" > "${WORK_DIR}/installed-packages.txt"

# CrowdSec metrics snapshot
cscli metrics 2>/dev/null > "${WORK_DIR}/crowdsec-metrics.txt" || true

# Compress
tar czf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" -C /tmp "$BACKUP_NAME"
rm -rf "$WORK_DIR"

# Clean old backups
find "$BACKUP_DIR" -name "loxone-loxprox-backup-*.tar.gz" -mtime +${RETENTION_DAYS} -delete

echo "Backup created: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
ls -lh "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
