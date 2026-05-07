# LoxProx — Project Rundown

**Status:** Published on GitHub  
**Repo:** https://github.com/sgtsilver/loxprox  
**Version:** 1.1.0  
**Last updated:** 2026-05-07

---

## What This Is

A drop-in security gateway for Loxone Miniserver Gen 1 (and Gen 2). It sits between the internet and your Miniserver, adding every protection the hardware lacks: TLS termination, rate limiting, WAF, IDS, firewall, audit logging, and real-time alerting.

LAN traffic bypasses the gateway entirely — only external traffic is inspected.

---

## Architecture at a Glance

```
Internet ──► Router:1080 ──► Gateway:1080 ──► Loxone:80
                                    │
                                    ├── nginx (proxy, rate limits, headers)
                                    ├── CrowdSec (IDS + CAPI blocks + AppSec WAF)
                                    ├── nftables (input DROP, allow :1080 + SSH)
                                    ├── AppArmor (nginx profile)
                                    ├── auditd (config change monitoring)
                                    └── Discord alerts (real-time)
```

---

## Key Files

| File | Purpose |
|------|---------|
| `deploy.sh` | One-shot Debian 12 hardening & installation (870 lines, idempotent) |
| `detect-loxone.sh` | Network autodetector — finds your Miniserver by MAC OUI and API fingerprint |
| `test-gateway.sh` | 29-check validation suite — run after deploy to verify every control |
| `set-static-ip.sh` | Pre-deploy VM network configuration |
| `security-monitoring/` | Discord alerts, health monitor, config backup, GeoIP block script |
| `VALIDATION-REPORT.html` | Self-contained HTML report — A- grade, 9 security frameworks |

---

## Known Quirks & Lessons Learned

### DHCP → Static Transition Kills Inbound Connections (Debian 12)
Switching `/etc/network/interfaces` from `inet dhcp` to `inet static` without rebooting leaves a stale `dhclient` running. ~24 hours later the lease renewal loop corrupts the interface state. nginx stays up but becomes unreachable. **Fix:** Kill dhclient, remove `isc-dhcp-client`, then `ifdown/ifup` — or just reboot. This is now automated in `set-static-ip.sh`.

### CrowdSec AppSec Authentication
CrowdSec AppSec requires the **firewall bouncer API key** (not the LAPI machine key) in the `X-Crowdsec-Appsec-Api-Key` header, plus `X-Crowdsec-Appsec-Ip`, `-Uri`, and `-Verb`. This was completely undocumented in standard CrowdSec guides and caused hours of 401 debugging. The bouncer `.local` file is the source of truth.

### CrowdSec Whitelist CIDR Syntax
CrowdSec's parser expects `cidr:` for ranges, not `ip:`. Using `ip:192.168.178.0/24` causes a FATAL parser error. `cidr:192.168.178.0/24` is correct.

### nftables Table Isolation
The `crowdsec-firewall-bouncer` manages its own `table ip crowdsec` with timeout-based sets. When reloading static rules, use `flush table inet filter` — never `flush ruleset` — or you wipe the bouncer's dynamic blocks.

### German Locale Breaks `free` Parsing
The monitor script parses `free -m` output. On German locales, `Mem:` becomes `Speicher:` and numbers use commas. Fix: `LC_ALL=C free -m`.

### Loxone Gen 1 Has No TLS
The Miniserver Gen 1 CPU cannot handle SSL. The gateway terminates TLS and speaks HTTP to the Miniserver. This is a hardware limitation, not a design choice.

---

## Hardware Tested

| Platform | Status | Notes |
|----------|--------|-------|
| Debian 12 VM (Proxmox) | ✅ Production | 1 vCPU, 512MB RAM, 4GB disk |
| Raspberry Pi 4/5 | ✅ Supported | Official ARM64 packages |
| Raspberry Pi 3 | ✅ Supported | Requires 64-bit Raspberry Pi OS |
| Raspberry Pi 2 | ⚠️ Partial | Needs 64-bit kernel or manual compile |
| Raspberry Pi 1 / Zero | ❌ Not supported | ARMv6, no 64-bit support |

---

## CI / GitHub Actions

Workflow in `.github/workflows/ci.yml`:
- **ShellCheck** on all `.sh` files (warning severity)
- **Syntax check** — `bash -n` on every script
- **Python unit tests** — pytest with mocked `subprocess.run()` for `progressive-ban.py`
- **Shell unit tests** — portable mock-based tests for `deploy.sh` and `detect-loxone.sh` functions
- **Integration test** — config generation validation inside a Debian 12 Docker container
- **Markdown link check** — validates all documentation links

## GitHub Repository Setup

These settings are configured on the repo and affect how code lands in `main`:

| Setting | Status | Notes |
|---------|--------|-------|
| Branch protection on `main` | ✅ Active | Requires PR + 1 approval + all CI checks pass |
| Dependabot (Actions) | ✅ Active | Weekly checks; auto-opens PRs for action updates |
| Secret scanning | ⏭️ Skipped | LAN-only project; no secrets committed |
| Release `v1.1.0` | ✅ Published | Permanent tag for rollback |

### Developer workflow (after branch protection)

Direct push to `main` is blocked. Use feature branches:

```bash
# 1. Create a feature branch
git checkout -b feature-name

# 2. Commit your changes
git add -A
git commit -m "type: description"

# 3. Push the branch
git push origin feature-name

# 4. Open a Pull Request on GitHub
#    Click the yellow "Compare & pull request" banner

# 5. Wait for CI to pass (all green checks)
# 6. Merge via GitHub UI (requires 1 approval)
```

---

## Security Improvements (Post-Audit)

All 23 findings from the 2026-05-06 Ezio audit have been addressed:

| Finding | Fix |
|---------|-----|
| CRIT-001 `curl \| bash` | GPG-key-pinned apt repository setup — no pipe-to-shell |
| HIGH-001 AppSec key on disk | Documented threat model + mitigation guidance |
| HIGH-002 Missing CSP | Added CSP + Permissions-Policy; removed deprecated X-XSS-Protection |
| HIGH-003 No integration tests | Added Docker-based CI integration test + portable unit tests |
| HIGH-004 `curl \| bash` in install-gateway.sh | Same GPG-pinned fix applied |
| MED-001 Unpinned hub collections | Removed unconditional `hub upgrade`; install at hub-index version |
| MED-002 Rollback without validation | Added `nginx -t`, `nft -c`, pre-rollback snapshot |
| MED-003 Python subprocess timeouts | Added `timeout=30` to all `subprocess.run()` calls |
| MED-004 Silent subprocess failures | Return codes checked, stderr logged |
| MED-005 No Python unit tests | Full pytest suite with mocked `subprocess` |
| MED-006 No scanner tests | Portable bash unit tests for IP math, OUI, mktemp |
| LOW-001–LOW-010 | All fixed (mktemp, stricter IP regex, logrotate, circuit breaker, proxy_hide_header, test split, webhook rotation docs, AppSec tests, nftables comment) |

## Test Infrastructure

```
tests/
├── run-tests.sh              # unified test runner
├── test_progressive_ban.py   # 17 pytest cases for ban script
├── test_deploy_integration.sh # 54 assertions for deploy.sh logic
└── test_detect_loxone.sh     # 11 assertions for scanner logic
```

Run locally:
```bash
bash tests/run-tests.sh          # all portable tests
bash tests/run-tests.sh shell    # shell tests only
bash tests/run-tests.sh python   # Python tests only
```

VM integration tests (requires live gateway):
```bash
sudo ./test-gateway.sh
```

## Roadmap / Ideas

- [ ] Ansible role for fleet deployment
- [ ] Docker/Podman container version
- [ ] Web dashboard for CrowdSec decisions + gateway metrics
- [ ] Automatic TLS certificate renewal monitoring
- [ ] Support for Loxone Miniserver Go (cloud-dependent)
- [ ] Tailscale/WireGuard integration for remote management
- [ ] Prometheus metrics export

---

## Citation

See `CITATION.cff` for academic citation metadata.
