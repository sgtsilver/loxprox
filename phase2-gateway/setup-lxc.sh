#!/bin/bash
# Run this script ON THE PROXMOX HOST to create the Security Gateway LXC.
# Adjust ID, IP, and gateway to match your network.

set -e

# ─── Configuration ───────────────────────────────────────────────────────────
LXC_ID=200                    # Change if 200 is already in use
LXC_HOSTNAME="loxone-gateway"
LXC_IP="<GATEWAY_IP>/24"    # Static IP on the LAN
LXC_GW="<ROUTER_IP>"       # Router IP (UniFi Cloud Gateway Ultra)
LXC_DISK="local-lvm:5"       # Storage pool and size
LXC_MEMORY=512               # MB RAM
LXC_CORES=1
BRIDGE="vmbr0"               # Proxmox bridge connected to LAN
# ──────────────────────────────────────────────────────────────────────────────

echo "[+] Creating Debian 13 LXC template download..."
pveam update
pveam available | grep debian-12 || true
pveam download local debian-13-standard_13.x-xx_amd64.tar.zst || true

# Try to find the downloaded template
TEMPLATE=$(ls /var/lib/vz/template/cache/debian-12-standard_*.tar.zst 2>/dev/null | head -n1)
if [ -z "$TEMPLATE" ]; then
    echo "[!] Template not found. Please download it manually via Proxmox UI or cli:"
    echo "    pveam download local debian-13-standard_13.x-xx_amd64.tar.zst"
    exit 1
fi

echo "[+] Creating LXC $LXC_ID..."
pct create $LXC_ID "$TEMPLATE" \
    --hostname $LXC_HOSTNAME \
    --memory $LXC_MEMORY \
    --cores $LXC_CORES \
    --rootfs $LXC_DISK \
    --net0 name=eth0,bridge=$BRIDGE,ip=$LXC_IP,gw=$LXC_GW \
    --unprivileged 1 \
    --features nesting=1

echo "[+] Starting LXC $LXC_ID..."
pct start $LXC_ID

# Wait for network
sleep 5

echo "[+] Updating LXC packages..."
pct exec $LXC_ID -- bash -c "apt-get update && apt-get upgrade -y"

echo "[+] Installing base packages..."
pct exec $LXC_ID -- bash -c "apt-get install -y curl wget gnupg2 ca-certificates lsb-release sudo logrotate"

echo ""
echo "============================================"
echo "LXC $LXC_ID created and started."
echo "IP: ${LXC_IP%/*}"
echo ""
echo "Next steps:"
echo "1. Copy install-gateway.sh into the LXC:"
echo "   pct push $LXC_ID /path/to/install-gateway.sh /root/install-gateway.sh"
echo "2. Run it inside the LXC:"
echo "   pct exec $LXC_ID -- bash /root/install-gateway.sh"
echo "============================================"
