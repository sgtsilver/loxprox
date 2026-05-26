**Language:** [Deutsch](phase3-cutover.de.md) · English

# Phase 3 — Cutover to Security Gateway

> ⚠️ **Substrate note:** This runbook was originally written for an LXC-based deployment and still uses `LXC` / `pct` terminology in places. **LoxProx is now VM-only** — `deploy.sh` aborts on LXC by default because several defenses (kernel sysctls, Fragnesia mitigation, auditd, AppArmor enforcement, nftables) cannot be applied from inside a container. For a new deployment, substitute "Gateway VM" wherever you see "Gateway LXC" and use `qm` instead of `pct` on Proxmox. The cutover steps below are substrate-agnostic.

## Prerequisites

- [ ] Phase 1 hardening complete (Proxmox firewall, Loxone passwords, firmware).
- [ ] Phase 2 gateway LXC is running and healthy.
- [ ] You have verified from **inside the LXC** that it can reach the Loxone:
  ```bash
  curl -v http://<LOXONE_IP>:80/jdev/cfg/api
  ```
  (Adjust IP to your Loxone. You should get an HTTP response.)
- [ ] You have a way to access the Proxmox host or LAN if something goes wrong (e.g., VPN, TeamViewer, or physical access).

---

## Step-by-Step Cutover

### Step 1: Verify Gateway Listening

Inside the LXC:
```bash
ss -tlnp | grep 1080
# Expected: LISTEN 0.0.0.0:1080 (nginx)
```

Test the proxy locally:
```bash
curl -v http://127.0.0.1:1080/jdev/cfg/api
```

If this fails, **do not proceed**. Fix the Nginx config first.

---

### Step 2: Update Proxmox Firewall (if Loxone is a VM)

In Proxmox web UI → Loxone VM → Firewall:

1. Update the rule that references the Security Gateway IP:
   - Source: `<GATEWAY_IP>` (Security Gateway LXC)
   - Dest Port: `1080`
   - Action: `ACCEPT`

2. Ensure these rules exist and are ordered correctly:
   1. `<LAN_SUBNET>` → ACCEPT 1080
   2. `<GATEWAY_IP>` → ACCEPT 1080
   3. `any` → DROP 1080

---

### Step 3: Change Router Port Forwarding

Log into the router admin panel.

**Old rule:**
- External port `1080` → `<LOXONE_IP>:80` (Loxone IP — router was translating 1080→80)

**New rule:**
- External port `1080` → `<GATEWAY_IP>:1080` (Security Gateway IP)

Save and apply.

> ⚠️ **Do NOT delete the old rule yet.** Some routers allow you to keep notes. Write down the old target IP just in case.

---

### Step 4: Test External Access

From a device **outside the LAN** (e.g., mobile phone on cellular):

```
http://<YOUR_DOMAIN>:1080
```

You should reach the Loxone interface.

Also test the **Loxone App** if users rely on it.

---

### Step 5: Test LAN Access

From a device **inside the LAN** (`<LAN_HOST>`):

```
http://<LOXONE_IP>:80
```

This should still work directly, bypassing the gateway.

---

### Step 6: Rollback Plan (if something breaks)

If external access fails:

1. Revert router port forwarding back to the Loxone IP.
2. Check gateway logs:
   ```bash
   # Inside LXC
   tail -f /var/log/nginx/loxone-error.log
   journalctl -u nginx -f
   ```
3. Verify the gateway can reach the Loxone:
   ```bash
   curl -v http://<LOXONE_IP>:80/jdev/cfg/api
   ```
4. Fix the issue, then retry Step 3.

---

## Post-Cutover Verification

- [ ] External access works via `<YOUR_DOMAIN>:1080`
- [ ] Loxone App connects successfully from outside
- [ ] LAN access works directly to Loxone IP
- [ ] Nginx access logs show traffic: `tail -f /var/log/nginx/loxone-access.log`
- [ ] CrowdSec is running: `cscli metrics`
- [ ] CrowdSec bouncer is active: `systemctl status crowdsec-firewall-bouncer`
