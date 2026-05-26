**Language:** [Deutsch](UPGRADE-to-v1.5.de.md) · English

# Upgrading LoxProx v1.3.x → v1.5.0

v1.5.0 moves the REQUIRED configuration values out of `deploy.sh` into a
dedicated file at `/etc/loxprox/deploy.conf`. **You must do a one-time
bootstrap on any existing install** before re-running `deploy.sh`, or the
new safety check refuses to proceed.

If you're installing fresh on a new VM, skip to the bottom.

---

## Why this changed

In v1.4.x and earlier, the values at the top of `deploy.sh` (`LOXONE_IP`,
`SSH_ALLOWED_SUBNETS`, …) were placeholders that every operator was expected
to hand-edit before running the script. The maintainer's own production VM
demonstrated the failure mode on 2026-05-26: the hand-edited copy of
`deploy.sh` was never persisted anywhere on disk. Re-running the repo's
`deploy.sh` would have rewritten nftables with `192.168.1.0/24` and locked
the LAN out of the gateway.

v1.5.0 fixes this for good: values live in `/etc/loxprox/deploy.conf`,
which `deploy.sh` sources but never touches. Upgrades are just
`git pull && sudo bash deploy.sh`.

---

## Upgrade path for existing installs (v1.3.x → v1.5.0)

Three commands. The first one is the only new step you'll ever do.

```bash
git pull                                       # or download the v1.5.0 tarball

sudo bash deploy.sh --bootstrap-config         # extract live values → deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf          # review (highly recommended)

sudo bash deploy.sh                            # normal deploy, sources the file
```

### What `--bootstrap-config` reads

It greps the live system's existing state to reconstruct your operator config:

| Variable | Read from |
|---|---|
| `LOXONE_IP` / `LOXONE_PORT` | `upstream loxone_backend { server <IP>:<PORT>; }` in `/etc/nginx/sites-available/loxone` |
| `GATEWAY_IP` | `hostname -I` (primary interface) |
| `LAN_SUBNET` | First `proto kernel scope link` route from `ip route` |
| `SSH_ALLOWED_SUBNETS` | The set in `tcp dport 22 ip saddr { … }` in `/etc/nftables.conf` |
| `ENABLE_APPSEC` | Presence of `auth_request /crowdsec-appsec` in the nginx site |
| `APPSEC_MODE` | `mode:` key in `/etc/crowdsec/acquis.d/appsec.yaml` |
| `CROWDSEC_WHITELIST_IPS` | `/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml` |
| `DISCORD_WEBHOOK_URL` | `DISCORD_WEBHOOK_URL=` line in `/etc/loxprox/config.env` |

It prints the candidate file for review and asks "Write this to
`/etc/loxprox/deploy.conf`? [y/N]". A previous file is backed up to
`/etc/loxprox/deploy.conf.bak-<timestamp>` before being overwritten.

Rate limits, proxy timeouts, and buffer sizes are NOT extracted — `deploy.conf`
is written with the repo defaults (which match every v1.0-v1.4 deploy). Edit
the file by hand if you customized those.

### Non-interactive deploys (Ansible, CI, etc.)

If `deploy.sh` runs without a tty AND `/etc/loxprox/deploy.conf` is absent
AND a live install is detected, it auto-runs `--bootstrap-config` with no
prompt (writes the candidate file, continues with the deploy). Set
`LOXPROX_BOOTSTRAP_YES=1` explicitly if you want the same behavior over a
tty.

### What if the extraction fails?

If `/etc/nginx`, `/etc/nftables.conf`, etc. don't contain the expected
content (heavily customized install, mid-rollback state, etc.), the
extractor exits with `Could not extract: <names>` and asks you to write
`deploy.conf` by hand:

```bash
sudo install -d -m 0750 /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf
```

The format inside `deploy.conf` is the same bash-variable syntax that used
to live at the top of `deploy.sh` — no new conventions to learn.

---

## What v1.5.0 also changes (non-breaking)

- **`/etc/nginx/sites-available/loxone` is preserved on every redeploy.**
  WebSocket location blocks and other operator hand-edits no longer get
  overwritten. Use `LOXPROX_FORCE_REGEN_NGINX=1 sudo bash deploy.sh` to
  regenerate from the template if you ever need to.
- **AppSec map + log_format stay inline in the site config** (same as v1.4.0). A `conf.d/loxprox-appsec.conf` split was attempted and reverted — nginx rejects it because `$appsec_action` is registered by `auth_request_set` inside the location block, and any earlier reference fails parse-time validation. v1.5.0 cleans up the conf.d file if a v1.5.0-rc dev build wrote it.
- **`systemctl reload nginx`** (was `restart`) — graceful, preserves
  established upstream keepalives to the Miniserver.

---

## Fresh-VM install (new in v1.5.0 wording)

```bash
# 1. Set up the VM (1 GB+ RAM, 1 vCPU+, Debian 12, static IP).
#    Run set-static-ip.sh first if needed.

# 2. Copy the repo to the VM (scp / git clone — your call).

# 3. Create your deploy config from the template:
sudo install -d -m 0750 /etc/loxprox
sudo cp deploy.conf.example /etc/loxprox/deploy.conf
sudo $EDITOR /etc/loxprox/deploy.conf      # fill in [REQUIRED] values

# 4. Deploy:
sudo bash deploy.sh
```

If you forget step 3, `deploy.sh` refuses to run and prints exactly the
copy-paste commands above. The old footgun (forgot-to-edit → silently
deployed with `192.168.1.100`) is no longer reachable.

---

## Rollback

If something goes wrong:

```bash
sudo bash deploy.sh --rollback
```

Restores the most recent pre-deploy backup. `/etc/loxprox/deploy.conf`
itself is NOT touched by rollback — the next forward-deploy still uses
the values you bootstrapped.
