# LoxProx TLS — Optional HTTPS on :1080

LoxProx v1.6.0 adds optional HTTPS termination on the gateway itself, via
[`acme.sh`](https://github.com/acmesh-official/acme.sh) and the standard
HTTP-01 challenge. Disabled by default — the gateway keeps speaking plain
HTTP on `:1080` until you opt in.

When enabled:

- `:1080` is the same port you already forward to from the router, but it
  serves HTTPS instead of HTTP.
- Renewal is fully automatic via `acme.sh`'s cron (daily check, renews
  anything within ~30 days of expiry, reloads nginx on success).
- Toggling between HTTP and HTTPS later is a single deploy.conf edit + a
  re-run of `sudo bash deploy.sh`. Cert files survive a disable so you
  don't pay re-issuance time when flipping back.

---

## Prerequisites — once, before `ENABLE_TLS=true`

### 1. A public DNS name pointing at your router's WAN IP

Examples that work today:

- A dynamic-DNS hostname from a provider you already use (`selfhost.eu`,
  `ddnss.de`, Cloudflare, etc.).
- A static A record at your registrar pointing at the WAN.

The cert is issued for this FQDN. The ACME server validates it by
connecting to `http://<your-domain>/.well-known/acme-challenge/<token>`,
so the name must resolve publicly **before** you run the deploy.

```bash
# Sanity check — should return your router's public IP:
dig +short A loxprox.example.com
```

### 2. A router port forward `WAN:80 → gateway:80`

In addition to the existing `WAN:1080 → gateway:1080` forward. This is
**only used for ACME validation**. The gateway's `:80` listener answers
exactly one thing: `/.well-known/acme-challenge/*` (served from
`/var/www/acme/`). Everything else on `:80` gets a permanent 301 to
`https://<your-domain>:1080$request_uri` — so a casual visitor hitting
`http://your-domain/` lands on the HTTPS-on-1080 endpoint, which is what
you want.

The widened public surface is just the challenge directory; same threat
profile as any vanilla Let's Encrypt deployment.

### 3. Fill in `deploy.conf`

Add (or edit) these keys in `/etc/loxprox/deploy.conf`:

```bash
ENABLE_TLS="true"
TLS_DOMAIN="loxprox.example.com"
TLS_EMAIL="you@example.com"
TLS_ACME_SERVER="letsencrypt"        # or "letsencrypt_test" while debugging
TLS_ACME_EXTRA=""                    # optional --keylength ec-256 etc.
```

> **Use `letsencrypt_test` (staging) first** if you're unsure about DNS or
> the :80 forward. Staging has no rate limits and won't burn your weekly
> production issuance budget. When everything works, switch to
> `letsencrypt` and re-run.

---

## Run the deploy

```bash
sudo bash deploy.sh
```

What happens:

1. **Pre-flight + nftables + nginx + CrowdSec + AppArmor** — unchanged from v1.4.x.
2. **TLS step:**
    - `acme.sh` is installed at `/root/.acme.sh/` from a SHA256-pinned
      tarball (version + hash in `deploy.sh`; no `curl | bash`).
    - `/etc/nginx/conf.d/loxprox-acme.conf` is written — the `:80`
      challenge listener.
    - nginx is reloaded; the listener is live.
    - `acme.sh --issue` runs HTTP-01. The ACME server fetches the
      challenge token from your gateway. On success, a cert is issued and
      stored in `~/.acme.sh/<domain>/`.
    - `acme.sh --install-cert` copies the cert + key to
      `/etc/loxprox/tls/{fullchain.pem,privkey.pem}` (mode 0640 root) and
      records `systemctl reload nginx` as the reload command for future
      automatic renewals.
    - `acme.sh`'s daily renewal cron (created at `--install` time) is
      verified and restored if missing.
    - The nginx site (`/etc/nginx/sites-available/loxone`) gets a marker
      block + a `listen 1080;` → `listen 1080 ssl;` swap. This is the
      one deviation from v1.6.0's "site is fully preserved" rule. Your
      hand-edits outside the marker block (WebSocket location, etc.) are
      untouched.
    - nginx -t, reload. HTTPS is live.

After the deploy succeeds, test from outside the LAN:

```bash
curl -vI https://loxprox.example.com:1080/
```

You should see a `200 OK` (or whatever the Loxone Miniserver returns) and
a valid TLS cert chain.

---

## Renewals — fully automatic

`acme.sh` ships with a daily cron entry that runs `acme.sh --cron`. That
inspects every installed cert and renews anything within ~30 days of
expiry, then runs the `--reloadcmd` (`systemctl reload nginx`) on
success. You don't need to do anything.

**Verify the cron is in place** (the deploy logs it explicitly):

```bash
crontab -l | grep acme.sh
# 0 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null
```

**Force a renewal manually** if you want to test the path or rotate keys:

```bash
sudo bash deploy.sh --renew-tls
```

---

## Toggling later

### Switch off (back to plain HTTP)

```bash
sudo $EDITOR /etc/loxprox/deploy.conf      # ENABLE_TLS="false"
sudo bash deploy.sh
```

What happens:

- The marker block in the nginx site is stripped.
- `listen 1080 ssl;` is reverted to `listen 1080;`.
- `/etc/nginx/conf.d/loxprox-acme.conf` is removed.
- The `acme.sh` cert is removed for the domain (the cron stops touching
  it), but the cert files at `/etc/loxprox/tls/` are **kept**.
- nginx is reloaded.

A subsequent re-enable is fast because the cert is still valid and acme.sh
re-uses it.

### Switch back on

Set `ENABLE_TLS="true"`, re-run `sudo bash deploy.sh`. Same path as the
first time, but `acme.sh --issue` will skip re-issuing if the existing
cert is still well within its validity window.

### Switch domain or ACME provider

Edit `TLS_DOMAIN` or `TLS_ACME_SERVER` in `deploy.conf`, re-run
`sudo bash deploy.sh`. `acme.sh` will issue a new cert and `--install-cert`
will overwrite the files at `/etc/loxprox/tls/`. The site's cert paths
don't change (they always point at the same files), so no site mutation
is needed.

### Full nuke — cert files, acme.sh, everything

```bash
sudo bash deploy.sh --remove-tls
```

This reverts the site, removes the ACME conf.d listener, uninstalls
`acme.sh` (and its cron), and deletes `/etc/loxprox/tls/`. After this you
can also drop the `WAN:80 → gateway:80` router forward — it's no longer
needed.

---

## Troubleshooting

### `acme.sh --issue failed`

Most common causes, in order:

1. **`:80` not reachable.** From outside the LAN:
   ```bash
   curl -vI http://loxprox.example.com/.well-known/acme-challenge/test
   ```
   Should hit your gateway and return `404` (the challenge file doesn't
   exist yet) — *not* time out. If it times out, the `WAN:80` forward
   isn't in place.

2. **DNS doesn't resolve.** Verify with `dig +short A` from a system
   outside your LAN (your phone on cellular works).

3. **Let's Encrypt rate limit.** If you've been retrying a lot, swap to
   `TLS_ACME_SERVER="letsencrypt_test"` for diagnosis, then back when
   everything works. The rate limit is per-domain per-week, not per-IP.

4. **CrowdSec / AppSec blocking the ACME server.** Check
   `cscli alerts list` — the ACME server's IPs occasionally show up if
   they probe other paths. Whitelist if needed.

Detailed acme.sh logs: `tail -100 /var/log/loxprox-deploy.log`.

### `nginx -t failed after TLS site mutation`

Should self-revert (the enable path has a rollback). If you see this and
the gateway is broken, manual recovery:

```bash
sudo /opt/loxprox/gateway-backup.sh        # snapshot just in case
# Inspect the marker block:
sudo sed -n '/LOXPROX-TLS-BEGIN/,/LOXPROX-TLS-END/p' /etc/nginx/sites-available/loxone
# If it's mangled, delete the block + revert the listen line by hand, then:
sudo nginx -t && sudo systemctl reload nginx
```

### Cert file permissions / nginx can't read key

The deploy sets `/etc/loxprox/tls/*` to `0640 root:root`. nginx workers
run as `www-data` and don't need to read the key — only the master process
(root) does, before forking. If you customised nginx to drop privileges
earlier, adjust the perms accordingly.

---

## What this does NOT add

- No HSTS preload submission. The `Strict-Transport-Security: max-age=31536000`
  header is set, but you have to submit the domain to
  [hstspreload.org](https://hstspreload.org) yourself if you want it baked
  into browsers.
- No OCSP stapling configuration. Modern Let's Encrypt + nginx defaults
  handle this acceptably; tighten in the site config if you need stricter
  guarantees.
- No CT log monitoring. v1.x's threat model didn't include this; once you
  have a public hostname and a cert, consider running `certspotter` or
  polling crt.sh for unexpected issuance. (Recorded in the skills audit
  Known Limits as deferred.)
- No DNS-01 challenge support. HTTP-01 only in v1.6.0. DNS-01 is a
  future extension if your setup can't open `:80`.

---

## Reference

- Source: `setup_tls()` in `deploy.sh`
- acme.sh upstream: https://github.com/acmesh-official/acme.sh
- HTTP-01 challenge spec: RFC 8555 §8.3
- Tested against `letsencrypt` (production) and `letsencrypt_test`
  (staging). `zerossl` and `buypass` should work via the same code path
  but aren't part of the regression matrix.
