# Phase 1 — Proxmox Firewall & Loxone Hardening

Do these steps **before** deploying the gateway. They reduce risk immediately.

---

## 1.1 Document Current Router Forwarding

Log into the router admin panel and record:

- External port: `1080`
- Internal IP: `<LOXONE_IP>` (Loxone Miniserver)
- Protocol: `TCP` (verify; Loxone uses TCP)

Save this. You will need it for Phase 3.

---

## 1.2 Enable Proxmox Firewall on the Loxone VM/Device

If the Loxone is a **VM on Proxmox**:

1. In Proxmox web UI, select the Loxone VM → **Firewall** tab.
2. Click **Enable Firewall** at the VM level.
3. Add these rules (order matters — more specific rules first):

| Direction | Type    | Action | Source              | Dest Port | Protocol | Comment           |
|-----------|---------|--------|---------------------|-----------|----------|-------------------|
| in        | IPSet   | ACCEPT | <LAN_SUBNET>    | 1080      | tcp      | LAN direct access |
| in        | IPSet   | ACCEPT | SECURITY_GATEWAY_IP | 1080      | tcp      | Gateway (placeholder) |
| in        | Group   | DROP   | any                 | 1080      | tcp      | Block all other   |

> **Note:** Replace `SECURITY_GATEWAY_IP` with the real gateway IP after Phase 2. Until then, leave it out or use a dummy IP you will assign later.

4. Ensure the **Datacenter Firewall** is enabled and set to **Input Policy: DROP** (or at least that VM-level rules are active).

If the Loxone is a **physical device** (not a Proxmox VM):

- Proxmox firewall cannot directly filter it.
- You must rely on the **gateway + router firewall** for external protection.
- Consider enabling MAC-based or IP-based firewall rules on the router if it supports them.

---

## 1.3 Loxone Miniserver Hardening

Connect to the Miniserver with **Loxone Config** from the LAN.

### A. Disable Remote Configuration (if not needed)

1. Open **Configure Miniserver**.
2. Go to the **External Access** or **Network** tab.
3. **Uncheck:**
   - `Allow this Miniserver to be configured remotely with Loxone Config over the internet`
4. **Apply and send to Miniserver.** It will reboot.

### B. Change All Passwords

1. Go to **User Management**.
2. Change the **admin** password to a strong passphrase (16+ chars, mixed case, numbers, symbols).
3. Remove or disable any unused accounts.
4. Avoid default usernames if possible.

### C. Update Firmware

1. In Loxone Config, check **Help → Check for Updates**.
2. Install the **latest available Gen 1 firmware**.
3. Reboot the Miniserver.

> ⚠️ Gen 1 is no longer actively developed. This is the last line of defense for known CVEs.

### D. Disable Unneeded Services

- **FTP Server:** If not used, set to `Disabled` (Loxone Config → Network → FTP Server).
- **HTTP External:** Since Gen 1 does not support HTTPS, you are stuck with HTTP. Do not also forward port 80 externally if it is open.

---

## 1.4 Router Hardening (If Supported)

If the router has a built-in firewall or intrusion detection:

1. Enable **SPI Firewall** (Stateful Packet Inspection).
2. Disable **UPnP** if not needed (prevents unauthorized port openings).
3. Enable **DoS Protection** if the router offers it (basic SYN flood protection).
4. Do **NOT** place the Miniserver in a DMZ.

---

## Phase 1 Checklist

- [ ] Router forwarding rule documented
- [ ] Proxmox firewall enabled on Loxone VM (if applicable)
- [ ] Remote configuration disabled
- [ ] All passwords changed
- [ ] Firmware updated
- [ ] Unneeded services disabled
- [ ] Router UPnP disabled
