#!/usr/bin/env python3
"""LoxProx Panel — LAN-only operator and family GUI (v2.1).

Serves the family QR invitation, live gateway status, log viewing, a guarded
deploy.conf editor with one-click apply, and support actions (unban, service
restart, TLS renew, test alert). Security model (see docs/GUI-PANEL.md):
reachable only from LAN_SUBNET / SSH_ALLOWED_SUBNETS via nftables, Host-header
allowlist against DNS rebinding, X-LoxProx-Gui header on every mutation (CSRF),
optional GUI_PASSWORD enforced on mutations. Runs as root (cscli / systemctl /
deploy.sh); stdlib only, no pip dependencies.
"""

import hmac
import html
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Paths are env-overridable so the pytest suite can point them at fixtures.
DEPLOY_CONF = os.environ.get("LOXPROX_DEPLOY_CONF", "/etc/loxprox/deploy.conf")
RUNTIME_CONF = os.environ.get("LOXPROX_RUNTIME_CONF", "/etc/loxprox/config.env")
TLS_CERT = os.environ.get("LOXPROX_TLS_CERT", "/etc/loxprox/tls/fullchain.pem")
STATE_DIR = os.environ.get("LOXPROX_STATE_DIR", "/var/lib/loxprox")
BACKUP_DIR = os.environ.get("LOXPROX_BACKUP_DIR", "/root/loxprox-backups")
DISCORD_ALERT = os.environ.get("LOXPROX_DISCORD_ALERT", "/opt/loxprox/discord-alert.sh")
SETTINGS_FILE = os.path.join(STATE_DIR, "gui-settings.json")
JOB_DIR = os.path.join(STATE_DIR, "gui-jobs")

LOG_FILES = {
    "nginx-error": "/var/log/nginx/loxone-error.log",
    "nginx-access": "/var/log/nginx/loxone-access.log",
    "appsec": "/var/log/nginx/appsec-detections.log",
    "watchdog": "/var/log/loxprox-network-watchdog.log",
    "tunnel-watchdog": "/var/log/loxprox-tunnel-watchdog.log",
    "monitor": "/var/log/loxprox-monitor.log",
    "deploy": "/var/log/loxprox-deploy.log",
    "gui": "/var/log/loxprox-gui.log",
}

RESTARTABLE_SERVICES = ("nginx", "crowdsec", "crowdsec-firewall-bouncer", "frpc")

STATUS_SERVICES = (
    ("nginx", "service"),
    ("crowdsec", "service"),
    ("crowdsec-firewall-bouncer", "service"),
    ("loxprox-monitor.timer", "timer"),
    ("network-watchdog.timer", "timer"),
)

# Keys the config editor may change. GATEWAY_IP / LAN_SUBNET / SSH_ALLOWED_SUBNETS
# are deliberately excluded: a typo there bricks remote access (watchdog reboot
# loop) — those stay SSH-only.
EDITABLE_KEYS = {
    "LOXONE_IP": "ip",
    "LOXONE_PORT": "port",
    "RATE_LIMIT_REQ_PER_SEC": "int",
    "RATE_LIMIT_BURST": "int",
    "RATE_LIMIT_CONN_PER_IP": "int",
    "PROXY_CONNECT_TIMEOUT": "int",
    "PROXY_SEND_TIMEOUT": "int",
    "PROXY_READ_TIMEOUT": "int",
    "CLIENT_BODY_TIMEOUT": "int",
    "CLIENT_HEADER_TIMEOUT": "int",
    "ENABLE_APPSEC": "bool",
    "APPSEC_MODE": "appsec_mode",
    "CROWDSEC_WHITELIST_IPS": "cidr_array",
    "DISCORD_WEBHOOK_URL": "url_or_empty",
    "ALERT_EMAIL": "email_or_empty",
    "AUTOREBOOT_TIME": "hhmm",
    "ENABLE_TLS": "bool",
    "TLS_DOMAIN": "host_or_empty",
    "TLS_EMAIL": "email_or_empty",
    "ENABLE_TUNNEL": "bool",
    "TUNNEL_SERVER_ADDR": "host_or_empty",
    "TUNNEL_SERVER_PORT": "port",
    "TUNNEL_PROTOCOL": "tunnel_proto",
    "TUNNEL_TOKEN": "secret",
    "TUNNEL_PROXY_NAME": "name",
    "TUNNEL_REMOTE_PORT": "port",
    "TUNNEL_PUBLIC_HOST": "host_or_empty",
    "ENABLE_GUI": "bool",
    "GUI_PORT": "port",
    "GUI_PASSWORD": "secret",
}

MASKED_KEYS = ("TUNNEL_TOKEN", "GUI_PASSWORD", "DISCORD_WEBHOOK_URL")

_RE_KV = re.compile(r'^\s*([A-Z_][A-Z0-9_]*)=("(?:[^"\\]|\\.)*"|\((?:[^)]*)\)|[^#\s]*)')


# ---------------------------------------------------------------- config I/O

def parse_shell_conf(text):
    """Parse KEY="value" / KEY=(array ...) lines from a bash-style conf."""
    conf = {}
    for line in text.splitlines():
        m = _RE_KV.match(line)
        if not m:
            continue
        key, raw = m.group(1), m.group(2)
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            conf[key] = raw[1:-1]
        else:
            conf[key] = raw
    return conf


def load_conf(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_shell_conf(fh.read())
    except OSError:
        return {}


def is_true(val):
    return str(val).strip().lower() in ("true", "yes", "1")


def mask_secrets(conf):
    out = dict(conf)
    for key in MASKED_KEYS:
        if out.get(key):
            out[key] = "•••"
    return out


def update_conf_text(text, changes):
    """Replace KEY=... lines in-place, append missing keys at the end."""
    lines = text.splitlines()
    seen = set()
    for i, line in enumerate(lines):
        m = _RE_KV.match(line)
        if m and m.group(1) in changes:
            key = m.group(1)
            lines[i] = f'{key}={format_conf_value(key, changes[key])}'
            seen.add(key)
    for key, val in changes.items():
        if key not in seen:
            lines.append(f'{key}={format_conf_value(key, val)}')
    return "\n".join(lines) + "\n"


def format_conf_value(key, val):
    if EDITABLE_KEYS.get(key) == "cidr_array":
        parts = " ".join(f'"{p}"' for p in val)
        return f"({parts})"
    return f'"{val}"'


# --------------------------------------------------------------- validation

def valid_ip(val):
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def valid_cidr_or_ip(val):
    try:
        ipaddress.ip_network(val, strict=False)
        return True
    except ValueError:
        return False


def valid_port(val):
    return str(val).isdigit() and 1 <= int(val) <= 65535


def valid_host(val):
    # hostname or hostname:port or bare IP
    hostpart, _, port = str(val).partition(":")
    if port and not valid_port(port):
        return False
    if valid_ip(hostpart):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*", hostpart))


_VALIDATORS = {
    "ip": valid_ip,
    "port": valid_port,
    "int": lambda v: str(v).isdigit() and 0 < int(v) < 100000,
    "bool": lambda v: str(v).lower() in ("true", "false"),
    "appsec_mode": lambda v: v in ("monitor", "enforce"),
    "tunnel_proto": lambda v: v in ("quic", "tcp"),
    "hhmm": lambda v: bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(v))),
    "url_or_empty": lambda v: v == "" or str(v).startswith("https://"),
    "email_or_empty": lambda v: v == "" or bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", str(v))),
    "host_or_empty": lambda v: v == "" or valid_host(v),
    "name": lambda v: bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(v))),
    "secret": lambda v: len(str(v)) <= 256 and "\n" not in str(v) and '"' not in str(v),
    "cidr_array": lambda v: isinstance(v, list) and all(valid_cidr_or_ip(x) for x in v),
}


def validate_changes(changes):
    """Return (clean, errors) for a {key: value} dict against EDITABLE_KEYS."""
    clean, errors = {}, {}
    for key, val in changes.items():
        kind = EDITABLE_KEYS.get(key)
        if kind is None:
            errors[key] = "not editable"
            continue
        if kind == "cidr_array" and isinstance(val, str):
            val = [p for p in re.split(r"[,\s]+", val.strip()) if p]
        if _VALIDATORS[kind](val):
            clean[key] = val
        else:
            errors[key] = "invalid value"
    return clean, errors


# ------------------------------------------------------------ shell helpers

def run(cmd, timeout=10):
    """Run a command, return (rc, stdout+stderr). Never raises."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]}: timeout"


def systemctl_state(unit):
    rc, out = run(["systemctl", "is-active", unit], timeout=5)
    return out.splitlines()[0] if out else ("unknown" if rc else "active")


def tail_file(path, lines=200, max_bytes=256 * 1024):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read().decode("utf-8", "replace")
        return "\n".join(data.splitlines()[-lines:])
    except OSError as exc:
        return f"(not readable: {exc})"


# --------------------------------------------------------- status collectors

def cert_days_left():
    if not os.path.exists(TLS_CERT):
        return None
    rc, out = run(["openssl", "x509", "-enddate", "-noout", "-in", TLS_CERT], timeout=5)
    if rc != 0 or "notAfter=" not in out:
        return None
    try:
        stamp = out.split("notAfter=", 1)[1].strip()
        expires = datetime.strptime(stamp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return max(-1, int((expires - datetime.now(timezone.utc)).total_seconds() // 86400))
    except ValueError:
        return None


def miniserver_reachable(conf):
    ip, port = conf.get("LOXONE_IP", ""), conf.get("LOXONE_PORT", "80")
    if not valid_ip(ip):
        return None
    try:
        with socket.create_connection((ip, int(port)), timeout=2):
            return True
    except OSError:
        return False


def crowdsec_decisions():
    rc, out = run(["cscli", "decisions", "list", "-o", "json"], timeout=15)
    if rc != 0:
        return {"error": out[:200], "count": 0, "items": []}
    try:
        data = json.loads(out) or []  # cscli emits `null` for an empty list
    except json.JSONDecodeError:
        return {"error": "unparseable cscli output", "count": 0, "items": []}
    items = []
    for dec in data[:10]:
        items.append({
            "ip": dec.get("value", "?"),
            "origin": dec.get("origin", "?"),
            "scenario": (dec.get("scenario") or "?").replace("crowdsecurity/", ""),
            "duration": dec.get("duration", "?"),
        })
    return {"count": len(data), "items": items}


def appsec_today():
    path = LOG_FILES["appsec"]
    if not os.path.exists(path):
        return {"hits": 0, "ips": 0}
    today = datetime.now().strftime("%Y-%m-%d")
    hits, ips = 0, set()
    for line in tail_file(path, lines=2000).splitlines():
        if line.startswith(today):
            hits += 1
            fields = line.split()
            if len(fields) > 1:
                ips.add(fields[1])  # appsec_evt: $time_iso8601 $remote_addr ...
    return {"hits": hits, "ips": len(ips)}


def latest_backup():
    try:
        archives = sorted(
            (e for e in os.scandir(BACKUP_DIR) if e.name.endswith(".tar.gz")),
            key=lambda e: e.stat().st_mtime, reverse=True)
    except OSError:
        return None
    if not archives:
        return None
    stat = archives[0].stat()
    return {"name": archives[0].name,
            "age_hours": round((time.time() - stat.st_mtime) / 3600, 1),
            "size_mb": round(stat.st_size / 1048576, 1)}


def system_stats():
    stats = {}
    try:
        usage = shutil.disk_usage("/")
        stats["disk_pct"] = round(usage.used / usage.total * 100)
    except OSError:
        pass
    try:
        stats["load"] = round(os.getloadavg()[0], 2)
    except OSError:
        pass
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            mem = {k: int(v.split()[0]) for k, v, in
                   (line.split(":", 1) for line in fh if ":" in line)}
        stats["mem_pct"] = round((1 - mem["MemAvailable"] / mem["MemTotal"]) * 100)
    except (OSError, KeyError, ValueError):
        pass
    return stats


def collect_status():
    conf = load_conf(DEPLOY_CONF)
    tunnel_on = is_true(conf.get("ENABLE_TUNNEL"))
    services = {name: systemctl_state(name) for name, _ in STATUS_SERVICES}
    if tunnel_on:
        services["frpc"] = systemctl_state("frpc")
        services["tunnel-watchdog.timer"] = systemctl_state("tunnel-watchdog.timer")
    if is_true(conf.get("ENABLE_GUI", "true")):
        services["loxprox-gui"] = "active"  # we are answering, after all
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "tunnel" if tunnel_on else ("tls" if is_true(conf.get("ENABLE_TLS")) else "plain"),
        "services": services,
        "cert_days": cert_days_left(),
        "miniserver": miniserver_reachable(conf),
        "decisions": crowdsec_decisions(),
        "appsec": appsec_today(),
        "backup": latest_backup(),
        "system": system_stats(),
        "job": JOBS.current_summary(),
    }


# ----------------------------------------------------------------------- QR

def derive_host(conf, settings):
    """Public host for the invitation QR, per gateway mode."""
    if is_true(conf.get("ENABLE_TUNNEL")) and conf.get("TUNNEL_PUBLIC_HOST"):
        return conf["TUNNEL_PUBLIC_HOST"], "tunnel"
    if is_true(conf.get("ENABLE_TLS")) and conf.get("TLS_DOMAIN"):
        return f'{conf["TLS_DOMAIN"]}:1080', "tls"
    manual = settings.get("manual_host", "")
    return (manual, "manual") if manual else ("", "unset")


def qr_svg(payload):
    rc, out = run(["qrencode", "-t", "SVG", "-m", "2", "-o", "-", payload], timeout=10)
    if rc != 0:
        return None
    return out


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(settings):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(settings, fh)
    os.replace(tmp, SETTINGS_FILE)


# ---------------------------------------------------------------- job runner

class JobRunner:
    """One background job at a time (deploy apply / TLS renew)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._meta = None

    def start(self, name, cmd):
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return None, "a job is already running"
            os.makedirs(JOB_DIR, exist_ok=True)
            job_id = datetime.now().strftime("%Y%m%d-%H%M%S")
            log_path = os.path.join(JOB_DIR, f"{job_id}-{name}.log")
            log_fh = open(log_path, "w", encoding="utf-8")
            try:
                self._proc = subprocess.Popen(
                    cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True)
            except OSError as exc:
                log_fh.close()
                return None, str(exc)
            self._meta = {"id": job_id, "name": name, "log": log_path,
                          "started": time.time()}
            return job_id, None

    def current_summary(self):
        with self._lock:
            if self._meta is None:
                return None
            rc = self._proc.poll()
            return {"id": self._meta["id"], "name": self._meta["name"],
                    "running": rc is None, "rc": rc,
                    "elapsed": int(time.time() - self._meta["started"])}

    def log_tail(self, job_id):
        with self._lock:
            if self._meta is None or self._meta["id"] != job_id:
                return None
            return tail_file(self._meta["log"], lines=120)


JOBS = JobRunner()


# ------------------------------------------------------------- HTTP handler

class PanelHandler(BaseHTTPRequestHandler):
    server_version = "LoxProxPanel/2.1"
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt, *args):  # journal via unit StandardOutput
        sys.stderr.write("%s %s %s\n" % (self.address_string(),
                                         self.log_date_time_string(), fmt % args))

    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; img-src 'self' data:; "
                         "connect-src 'self'")

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self._security_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj), "application/json")

    def _host_allowed(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        return host in self.server.allowed_hosts

    def _auth_ok(self):
        password = self.server.conf.get("GUI_PASSWORD", "")
        if not password:
            return True
        supplied = self.headers.get("X-LoxProx-Auth", "")
        return hmac.compare_digest(supplied.encode(), password.encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 65536:
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return None

    # -- GET --------------------------------------------------------------

    def do_GET(self):
        if not self._host_allowed():
            return self._json({"ok": False, "error": "host not allowed"}, 403)
        url = urlparse(self.path)
        route = url.path.rstrip("/") or "/"
        query = {k: v[0] for k, v in parse_qs(url.query).items()}

        if route == "/":
            return self._send(200, render_panel())
        if route == "/invite":
            return self._send(200, render_invite(query))
        if route == "/qr.svg":
            conf = load_conf(DEPLOY_CONF)
            host = query.get("host") or derive_host(conf, load_settings())[0]
            if not host or not valid_host(host):
                return self._json({"ok": False, "error": "no host configured"}, 400)
            svg = qr_svg(f"loxone://ms?host={host}")
            if svg is None:
                return self._json({"ok": False, "error": "qrencode failed"}, 500)
            return self._send(200, svg, "image/svg+xml")
        if route == "/api/status":
            return self._json({"ok": True, "status": collect_status()})
        if route == "/api/decisions":
            return self._json({"ok": True, "decisions": crowdsec_decisions()})
        if route == "/api/config":
            conf = load_conf(DEPLOY_CONF)
            visible = {k: conf.get(k, "") for k in EDITABLE_KEYS}
            settings = load_settings()
            host, mode = derive_host(conf, settings)
            return self._json({"ok": True, "config": mask_secrets(visible),
                               "qr_host": host, "qr_mode": mode,
                               "auth_required": bool(conf.get("GUI_PASSWORD"))})
        if route.startswith("/api/log/"):
            name = route.rsplit("/", 1)[1]
            if name not in LOG_FILES:
                return self._json({"ok": False, "error": "unknown log"}, 404)
            return self._json({"ok": True, "name": name,
                               "lines": tail_file(LOG_FILES[name])})
        if route.startswith("/api/job/"):
            job_id = route.rsplit("/", 1)[1]
            summary = JOBS.current_summary()
            if summary is None or summary["id"] != job_id:
                return self._json({"ok": False, "error": "unknown job"}, 404)
            return self._json({"ok": True, "job": summary,
                               "log": JOBS.log_tail(job_id)})
        return self._json({"ok": False, "error": "not found"}, 404)

    # -- POST -------------------------------------------------------------

    def do_POST(self):
        if not self._host_allowed():
            return self._json({"ok": False, "error": "host not allowed"}, 403)
        if self.headers.get("X-LoxProx-Gui") != "1":
            return self._json({"ok": False, "error": "missing X-LoxProx-Gui header"}, 403)
        if not self._auth_ok():
            return self._json({"ok": False, "error": "auth required"}, 401)
        body = self._read_body()
        if body is None:
            return self._json({"ok": False, "error": "bad request body"}, 400)
        route = urlparse(self.path).path.rstrip("/")

        if route == "/api/unban":
            ip = str(body.get("ip", "")).strip()
            if not valid_ip(ip):
                return self._json({"ok": False, "error": "invalid IP"}, 400)
            rc, out = run(["cscli", "decisions", "delete", "--ip", ip], timeout=15)
            return self._json({"ok": rc == 0, "output": out[:500]})

        if route == "/api/restart":
            service = str(body.get("service", ""))
            if service not in RESTARTABLE_SERVICES:
                return self._json({"ok": False, "error": "service not allowed"}, 400)
            rc, out = run(["systemctl", "restart", service], timeout=30)
            return self._json({"ok": rc == 0, "output": out[:500],
                               "state": systemctl_state(service)})

        if route == "/api/test-alert":
            rc, out = run([DISCORD_ALERT, "test"], timeout=20)
            return self._json({"ok": rc == 0, "output": out[:500]})

        if route == "/api/qr-host":
            host = str(body.get("host", "")).strip()
            if host and not valid_host(host):
                return self._json({"ok": False, "error": "invalid host"}, 400)
            settings = load_settings()
            settings["manual_host"] = host
            save_settings(settings)
            return self._json({"ok": True})

        if route == "/api/config":
            changes = body.get("changes")
            if not isinstance(changes, dict) or not changes:
                return self._json({"ok": False, "error": "no changes"}, 400)
            # Masked placeholder round-trips must not overwrite real secrets.
            changes = {k: v for k, v in changes.items() if v != "•••"}
            clean, errors = validate_changes(changes)
            if errors:
                return self._json({"ok": False, "errors": errors}, 400)
            try:
                with open(DEPLOY_CONF, encoding="utf-8") as fh:
                    text = fh.read()
            except OSError as exc:
                return self._json({"ok": False, "error": str(exc)}, 500)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.copy2(DEPLOY_CONF, f"{DEPLOY_CONF}.bak-{stamp}")
            new_text = update_conf_text(text, clean)
            fd = os.open(DEPLOY_CONF + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(new_text)
            os.replace(DEPLOY_CONF + ".tmp", DEPLOY_CONF)
            self.server.conf = load_conf(DEPLOY_CONF)
            return self._json({"ok": True, "changed": sorted(clean),
                               "hint": "apply required"})

        if route in ("/api/apply", "/api/renew-tls"):
            deploy_sh = load_conf(RUNTIME_CONF).get("LOXPROX_DEPLOY_SH", "")
            if not deploy_sh or not os.path.exists(deploy_sh):
                return self._json({"ok": False, "error":
                                   "deploy.sh path unknown — re-run deploy once via SSH"}, 409)
            if route == "/api/apply":
                job_id, err = JOBS.start("apply", ["bash", deploy_sh])
            else:
                job_id, err = JOBS.start("renew-tls", ["bash", deploy_sh, "--renew-tls"])
            if err:
                return self._json({"ok": False, "error": err}, 409)
            return self._json({"ok": True, "job_id": job_id})

        return self._json({"ok": False, "error": "not found"}, 404)


# ------------------------------------------------------------------ HTML UI

def _base_css():
    return """
:root { --bg:#f5f5f7; --card:#ffffff; --text:#1d1d1f; --muted:#6e6e73;
  --line:#e5e5ea; --ok:#1f7a3d; --warn:#9a6700; --bad:#b3261e; --accent:#0a66c2; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#161617; --card:#1f1f21; --text:#f5f5f7; --muted:#98989d;
    --line:#3a3a3c; --ok:#4cc38a; --warn:#e0b429; --bad:#f2726a; --accent:#6cb2ff; } }
* { box-sizing:border-box; margin:0; }
body { font-family:'Inter',-apple-system,'SF Pro Text',system-ui,sans-serif;
  background:var(--bg); color:var(--text); line-height:1.5; padding:2rem 1.25rem 4rem; }
main { max-width:64rem; margin:0 auto; }
h1 { font-size:1.4rem; font-weight:600; letter-spacing:-.01em; }
h2 { font-size:.95rem; font-weight:600; color:var(--muted); text-transform:uppercase;
  letter-spacing:.06em; margin:2.2rem 0 .8rem; }
.card { background:var(--card); border:1px solid var(--line); border-radius:14px;
  padding:1.1rem 1.25rem; box-shadow:0 1px 3px rgba(0,0,0,.05); }
.grid { display:grid; gap:.9rem; grid-template-columns:repeat(auto-fill,minmax(13rem,1fr)); }
.tile .label { font-size:.78rem; color:var(--muted); }
.tile .value { font-size:1.15rem; font-weight:600; margin-top:.15rem; display:flex;
  align-items:center; gap:.45rem; }
.dot { width:.6rem; height:.6rem; border-radius:50%; flex:none; }
.ok .dot{background:var(--ok)} .warn .dot{background:var(--warn)} .bad .dot{background:var(--bad)}
.ok .value{color:var(--ok)} .warn .value{color:var(--warn)} .bad .value{color:var(--bad)}
table { width:100%; border-collapse:collapse; font-size:.85rem; }
th,td { text-align:left; padding:.45rem .5rem; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:500; }
button { font:inherit; font-size:.85rem; font-weight:500; border:1px solid var(--line);
  background:var(--card); color:var(--text); border-radius:9px; padding:.42rem .9rem;
  cursor:pointer; }
button:hover { border-color:var(--accent); color:var(--accent); }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
button.danger:hover { border-color:var(--bad); color:var(--bad); }
input,select { font:inherit; font-size:.85rem; background:var(--bg); color:var(--text);
  border:1px solid var(--line); border-radius:8px; padding:.4rem .6rem; width:100%; }
label { font-size:.78rem; color:var(--muted); display:block; margin-top:.7rem; }
pre { background:var(--bg); border:1px solid var(--line); border-radius:10px;
  padding:.8rem; font:.75rem/1.5 'JetBrains Mono',ui-monospace,monospace;
  overflow-x:auto; max-height:22rem; white-space:pre-wrap; }
.row { display:flex; gap:.6rem; flex-wrap:wrap; align-items:center; }
.topbar { display:flex; justify-content:space-between; align-items:center; gap:1rem; }
.qrbox { display:flex; gap:1.5rem; flex-wrap:wrap; align-items:center; }
.qrbox svg { width:11rem; height:11rem; background:#fff; border-radius:10px; padding:.5rem; }
.hint { font-size:.78rem; color:var(--muted); }
.toast { position:fixed; bottom:1.2rem; left:50%; transform:translateX(-50%);
  background:var(--text); color:var(--bg); border-radius:10px; padding:.6rem 1.1rem;
  font-size:.85rem; opacity:0; transition:opacity .25s; pointer-events:none; }
.toast.show { opacity:1; }
@media print { body{background:#fff;color:#000;padding:0} .noprint{display:none} }
"""


_ICON_SHIELD = ('<svg width="22" height="22" viewBox="0 0 24 24" fill="none" '
                'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
                'stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 '
                '4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/></svg>')


def render_panel():
    tpl = PANEL_HTML
    return (tpl.replace("__CSS__", _base_css())
               .replace("__ICON__", _ICON_SHIELD))


def render_invite(query):
    conf = load_conf(DEPLOY_CONF)
    host = query.get("host") or derive_host(conf, load_settings())[0]
    lang = "en" if query.get("lang") == "en" else "de"
    safe_host = html.escape(host) if host else ""
    svg = qr_svg(f"loxone://ms?host={host}") if host and valid_host(host) else None
    if lang == "de":
        steps = ("<ol><li><strong>Loxone App</strong> installieren (App Store / "
                 "Play Store).</li><li>Diesen QR-Code mit der Handy-Kamera scannen "
                 "&mdash; die App &ouml;ffnet sich mit der richtigen Adresse.</li>"
                 "<li>Eigenen Benutzernamen + Passwort eingeben. Fertig.</li></ol>"
                 "<p class='hint'>Funktioniert zu Hause, unterwegs und im Urlaub "
                 "&mdash; gleiche Adresse &uuml;berall. Wenn der Scan nichts "
                 "&ouml;ffnet: erst die App installieren, dann erneut scannen. "
                 "Adresse zum Abtippen: <strong>%s</strong></p>" % safe_host)
        title, no_host = "Loxone einrichten", "Keine &ouml;ffentliche Adresse konfiguriert."
    else:
        steps = ("<ol><li>Install the <strong>Loxone app</strong> (App Store / "
                 "Play Store).</li><li>Scan this QR code with your phone camera "
                 "&mdash; the app opens with the right address.</li><li>Enter your "
                 "own username + password once. Done.</li></ol>"
                 "<p class='hint'>Works at home, on the road, and abroad &mdash; "
                 "same address everywhere. If scanning does nothing: install the "
                 "app first, then rescan. Address for manual entry: "
                 "<strong>%s</strong></p>" % safe_host)
        title, no_host = "Set up Loxone", "No public host configured."
    body = svg if svg else f"<p class='hint'>{no_host}</p>"
    return (INVITE_HTML.replace("__CSS__", _base_css())
            .replace("__TITLE__", title)
            .replace("__QR__", body)
            .replace("__STEPS__", steps))


PANEL_HTML = """<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LoxProx Panel</title><style>__CSS__</style></head>
<body><main>
<div class="topbar"><h1 style="display:flex;align-items:center;gap:.5rem">__ICON__ LoxProx Panel</h1>
<div class="row noprint"><button id="langBtn"></button>
<a href="/invite" target="_blank"><button data-i18n="invite"></button></a></div></div>

<h2 data-i18n="h_status"></h2>
<div class="grid" id="tiles"></div>

<h2 data-i18n="h_qr"></h2>
<div class="card qrbox"><div id="qrHolder"><span class="hint" data-i18n="qr_none"></span></div>
<div style="flex:1;min-width:14rem"><div class="hint" id="qrModeLine"></div>
<label data-i18n="qr_host"></label><div class="row"><input id="qrHost" style="max-width:18rem">
<button id="qrSave" data-i18n="save"></button>
<button id="qrCopy" data-i18n="copy_link"></button></div>
<p class="hint" data-i18n="qr_note"></p></div></div>

<h2 data-i18n="h_bans"></h2>
<div class="card"><table id="banTable"><thead><tr><th>IP</th><th data-i18n="t_origin"></th>
<th data-i18n="t_scenario"></th><th data-i18n="t_duration"></th><th></th></tr></thead>
<tbody></tbody></table>
<div class="row" style="margin-top:.7rem"><input id="unbanIp" placeholder="1.2.3.4" style="max-width:14rem">
<button id="unbanBtn" class="danger" data-i18n="unban"></button></div></div>

<h2 data-i18n="h_actions"></h2>
<div class="card"><div class="row" id="actionRow">
<button class="danger" data-restart="nginx">nginx</button>
<button class="danger" data-restart="crowdsec">CrowdSec</button>
<button class="danger" data-restart="crowdsec-firewall-bouncer">Bouncer</button>
<button class="danger" data-restart="frpc" id="frpcBtn" hidden>frpc</button>
<button id="renewBtn" data-i18n="renew"></button>
<button id="alertBtn" data-i18n="test_alert"></button></div>
<p class="hint" data-i18n="actions_note"></p></div>

<h2 data-i18n="h_config"></h2>
<div class="card"><div id="cfgForm" class="grid" style="grid-template-columns:repeat(auto-fill,minmax(16rem,1fr))"></div>
<div class="row" style="margin-top:1rem"><button id="cfgSave" data-i18n="save_cfg"></button>
<button id="applyBtn" class="primary" data-i18n="apply"></button></div>
<p class="hint" data-i18n="cfg_note"></p><pre id="jobLog" hidden></pre></div>

<h2 data-i18n="h_logs"></h2>
<div class="card"><div class="row"><select id="logSel"></select>
<button id="logBtn" data-i18n="load_log"></button></div><pre id="logView" hidden></pre></div>
</main>
<div class="toast" id="toast"></div>
<script>
"use strict";
const I18N = {
 de:{invite:"Einladung öffnen",h_status:"Status",h_qr:"Familien-Einladung",
  qr_none:"Kein QR verfügbar", qr_host:"Öffentliche Adresse (Host[:Port])",
  save:"Speichern",copy_link:"Link kopieren",
  qr_note:"Der QR-Code enthält nur die Adresse — nie Zugangsdaten. Jedes Familienmitglied nutzt eigenen Miniserver-Benutzer.",
  h_bans:"Aktive Sperren (CrowdSec)",t_origin:"Quelle",t_scenario:"Szenario",t_duration:"Dauer",
  unban:"IP entsperren",h_actions:"Aktionen",renew:"TLS-Zertifikat erneuern",
  test_alert:"Discord-Testalarm",actions_note:"Neustarts unterbrechen aktive Verbindungen kurz.",
  h_config:"Konfiguration",save_cfg:"Konfiguration speichern",apply:"Anwenden (deploy.sh)",
  cfg_note:"Speichern schreibt /etc/loxprox/deploy.conf (mit Backup). Erst 'Anwenden' aktiviert Änderungen. Netz-Grundwerte (GATEWAY_IP, LAN_SUBNET, SSH) nur per SSH.",
  h_logs:"Logs",load_log:"Anzeigen",
  svc:"Dienste",cert:"TLS-Zertifikat",days:"Tage übrig",ms:"Miniserver",reach:"erreichbar",
  unreach:"NICHT erreichbar",bans:"Sperren aktiv",appsec:"AppSec heute",backup:"Letztes Backup",
  hours_ago:"h alt",sys:"System",mode:"Modus",no_cert:"kein Zertifikat",
  confirm_restart:"Dienst wirklich neu starten: ",confirm_unban:"IP entsperren: ",
  confirm_apply:"deploy.sh jetzt ausführen?",need_pw:"Passwort (X-LoxProx-Auth)",
  job_running:"Job läuft…",done:"Fertig",failed:"Fehlgeschlagen"},
 en:{invite:"Open invitation",h_status:"Status",h_qr:"Family invitation",
  qr_none:"No QR available",qr_host:"Public address (host[:port])",
  save:"Save",copy_link:"Copy link",
  qr_note:"The QR encodes only the address — never credentials. Give each family member their own Miniserver user.",
  h_bans:"Active bans (CrowdSec)",t_origin:"Origin",t_scenario:"Scenario",t_duration:"Duration",
  unban:"Unban IP",h_actions:"Actions",renew:"Renew TLS certificate",
  test_alert:"Discord test alert",actions_note:"Restarts briefly interrupt active connections.",
  h_config:"Configuration",save_cfg:"Save configuration",apply:"Apply (deploy.sh)",
  cfg_note:"Save writes /etc/loxprox/deploy.conf (backed up first). Only 'Apply' activates changes. Core network keys (GATEWAY_IP, LAN_SUBNET, SSH) are SSH-only.",
  h_logs:"Logs",load_log:"Show",
  svc:"Services",cert:"TLS certificate",days:"days left",ms:"Miniserver",reach:"reachable",
  unreach:"NOT reachable",bans:"active bans",appsec:"AppSec today",backup:"Last backup",
  hours_ago:"h old",sys:"System",mode:"Mode",no_cert:"no certificate",
  confirm_restart:"Really restart service: ",confirm_unban:"Unban IP: ",
  confirm_apply:"Run deploy.sh now?",need_pw:"Password (X-LoxProx-Auth)",
  job_running:"Job running…",done:"Done",failed:"Failed"}};
let lang = localStorage.getItem("lp-lang") || "de";
let authRequired = false;
const $ = id => document.getElementById(id);
const t = k => (I18N[lang][k] || k);
function applyLang(){
  document.querySelectorAll("[data-i18n]").forEach(el => el.textContent = t(el.dataset.i18n));
  $("langBtn").textContent = lang === "de" ? "EN" : "DE";
  document.documentElement.lang = lang;
}
$("langBtn").onclick = () => { lang = lang === "de" ? "en" : "de";
  localStorage.setItem("lp-lang", lang); applyLang(); refresh(); };
function toast(msg){ const el=$("toast"); el.textContent=msg; el.classList.add("show");
  setTimeout(()=>el.classList.remove("show"), 2600); }
function hdrs(){
  const h = {"Content-Type":"application/json","X-LoxProx-Gui":"1"};
  if (authRequired){
    let pw = sessionStorage.getItem("lp-pw");
    if (!pw){ pw = prompt(t("need_pw")) || ""; sessionStorage.setItem("lp-pw", pw); }
    h["X-LoxProx-Auth"] = pw;
  }
  return h;
}
async function post(url, body){
  const res = await fetch(url, {method:"POST", headers:hdrs(), body:JSON.stringify(body||{})});
  if (res.status === 401){ sessionStorage.removeItem("lp-pw"); toast("401"); }
  return res.json();
}
function tile(label, value, cls){
  return `<div class="card tile ${cls||""}"><div class="label">${label}</div>` +
         `<div class="value"><span class="dot"></span><span>${value}</span></div></div>`;
}
function esc(s){ const d=document.createElement("div"); d.textContent=String(s); return d.innerHTML; }
async function refresh(){
  const res = await fetch("/api/status").then(r=>r.json()).catch(()=>null);
  if (!res || !res.ok) return;
  const s = res.status, tiles = [];
  const badSvc = Object.entries(s.services).filter(([,v]) => v !== "active");
  tiles.push(tile(t("svc"), badSvc.length ? esc(badSvc.map(([k,v])=>k+": "+v).join(", "))
    : "OK", badSvc.length ? "bad" : "ok"));
  if (s.cert_days === null) tiles.push(tile(t("cert"), t("no_cert"), s.mode==="tls"?"warn":""));
  else tiles.push(tile(t("cert"), s.cert_days + " " + t("days"),
    s.cert_days < 7 ? "bad" : (s.cert_days < 21 ? "warn" : "ok")));
  if (s.miniserver !== null) tiles.push(tile(t("ms"),
    s.miniserver ? t("reach") : t("unreach"), s.miniserver ? "ok" : "bad"));
  tiles.push(tile(t("bans"), s.decisions.count, s.decisions.count > 0 ? "warn" : "ok"));
  tiles.push(tile("AppSec", s.appsec.hits + " (" + s.appsec.ips + " IPs)",
    s.appsec.hits ? "warn" : "ok"));
  tiles.push(tile(t("backup"), s.backup ? s.backup.age_hours + " " + t("hours_ago")
    : "—", s.backup && s.backup.age_hours < 26 ? "ok" : "bad"));
  const sy = s.system;
  tiles.push(tile(t("sys"), `disk ${sy.disk_pct??"?"}% · mem ${sy.mem_pct??"?"}% · load ${sy.load??"?"}`,
    (sy.disk_pct > 85 || sy.mem_pct > 90) ? "warn" : "ok"));
  tiles.push(tile(t("mode"), s.mode, ""));
  $("tiles").innerHTML = tiles.join("");
  $("frpcBtn").hidden = s.mode !== "tunnel";
  const tb = $("banTable").querySelector("tbody");
  tb.innerHTML = s.decisions.items.map(d =>
    `<tr><td>${esc(d.ip)}</td><td>${esc(d.origin)}</td><td>${esc(d.scenario)}</td>` +
    `<td>${esc(d.duration)}</td><td><button class="danger" data-unban="${esc(d.ip)}">×</button></td></tr>`
  ).join("") || `<tr><td colspan="5" class="hint">—</td></tr>`;
  tb.querySelectorAll("[data-unban]").forEach(b => b.onclick = () => unban(b.dataset.unban));
  if (s.job && s.job.running) pollJob(s.job.id);
}
async function loadConfig(){
  const res = await fetch("/api/config").then(r=>r.json());
  if (!res.ok) return;
  authRequired = res.auth_required;
  $("qrHost").value = res.qr_host || "";
  $("qrModeLine").textContent = "Mode: " + res.qr_mode;
  if (res.qr_host) $("qrHolder").innerHTML =
    `<img src="/qr.svg?host=${encodeURIComponent(res.qr_host)}" alt="QR" style="width:11rem;height:11rem;background:#fff;border-radius:10px;padding:.4rem">`;
  const form = $("cfgForm"); form.innerHTML = "";
  Object.entries(res.config).forEach(([k,v]) => {
    const wrap = document.createElement("div");
    wrap.innerHTML = `<label>${k}</label><input data-key="${k}">`;
    wrap.querySelector("input").value = Array.isArray(v) ? v : v;
    form.appendChild(wrap);
  });
}
async function unban(ip){
  if (!ip || !confirm(t("confirm_unban") + ip)) return;
  const res = await post("/api/unban", {ip});
  toast(res.ok ? t("done") : (res.error || t("failed"))); refresh();
}
$("unbanBtn").onclick = () => unban($("unbanIp").value.trim());
document.querySelectorAll("[data-restart]").forEach(b => b.onclick = async () => {
  const svc = b.dataset.restart;
  if (!confirm(t("confirm_restart") + svc)) return;
  const res = await post("/api/restart", {service: svc});
  toast((res.ok ? t("done") : t("failed")) + " — " + svc + " " + (res.state||"")); refresh();
});
$("alertBtn").onclick = async () => { const r = await post("/api/test-alert");
  toast(r.ok ? t("done") : t("failed")); };
$("renewBtn").onclick = async () => { const r = await post("/api/renew-tls");
  if (r.ok) pollJob(r.job_id); else toast(r.error || t("failed")); };
$("applyBtn").onclick = async () => {
  if (!confirm(t("confirm_apply"))) return;
  const r = await post("/api/apply");
  if (r.ok) pollJob(r.job_id); else toast(r.error || t("failed"));
};
$("cfgSave").onclick = async () => {
  const changes = {};
  $("cfgForm").querySelectorAll("input[data-key]").forEach(i => changes[i.dataset.key] = i.value);
  const res = await post("/api/config", {changes});
  if (res.ok) toast(t("done") + " → " + res.hint);
  else toast(JSON.stringify(res.errors || res.error));
};
$("qrSave").onclick = async () => {
  const res = await post("/api/qr-host", {host: $("qrHost").value.trim()});
  toast(res.ok ? t("done") : (res.error || t("failed"))); loadConfig();
};
$("qrCopy").onclick = () => {
  const h = $("qrHost").value.trim();
  if (h) { navigator.clipboard.writeText("loxone://ms?host=" + h); toast(t("done")); }
};
let jobTimer = null;
function pollJob(id){
  if (jobTimer) return;
  $("jobLog").hidden = false;
  jobTimer = setInterval(async () => {
    const res = await fetch("/api/job/" + id).then(r=>r.json()).catch(()=>null);
    if (!res || !res.ok){ clearInterval(jobTimer); jobTimer = null; return; }
    $("jobLog").textContent = "[" + res.job.name + " · " + res.job.elapsed + "s]\\n" + (res.log||"");
    $("jobLog").scrollTop = $("jobLog").scrollHeight;
    if (!res.job.running){ clearInterval(jobTimer); jobTimer = null;
      toast(res.job.rc === 0 ? t("done") : t("failed") + " (rc=" + res.job.rc + ")"); refresh(); }
  }, 2000);
}
const LOGS = ["nginx-error","nginx-access","appsec","watchdog","tunnel-watchdog","monitor","deploy","gui"];
$("logSel").innerHTML = LOGS.map(l => `<option>${l}</option>`).join("");
$("logBtn").onclick = async () => {
  const res = await fetch("/api/log/" + $("logSel").value).then(r=>r.json());
  $("logView").hidden = false;
  $("logView").textContent = res.ok ? res.lines : (res.error || "?");
};
applyLang(); loadConfig(); refresh(); setInterval(refresh, 10000);
</script></body></html>
"""

INVITE_HTML = """<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title><style>__CSS__</style></head>
<body><main style="max-width:34rem">
<h1>__TITLE__</h1>
<div class="card" style="margin-top:1rem;text-align:center">__QR__</div>
<div class="card" style="margin-top:1rem">__STEPS__</div>
<div class="row noprint" style="margin-top:1rem">
<button onclick="window.print()">Drucken / Print</button>
<a href="/invite?lang=de"><button>DE</button></a>
<a href="/invite?lang=en"><button>EN</button></a>
</div></main></body></html>
"""


# --------------------------------------------------------------------- main

class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_allowed_hosts(conf):
    allowed = {"127.0.0.1", "localhost", "::1"}
    gw = conf.get("GATEWAY_IP", "")
    if gw:
        allowed.add(gw.lower())
    tls = conf.get("TLS_DOMAIN", "")
    if tls:
        allowed.add(tls.lower())
    extra = os.environ.get("LOXPROX_GUI_HOSTS", "")
    allowed.update(h.strip().lower() for h in extra.split(",") if h.strip())
    return allowed


def main():
    conf = load_conf(DEPLOY_CONF)
    if not is_true(conf.get("ENABLE_GUI", "true")):
        print("ENABLE_GUI is false — exiting.")
        return 0
    port = int(conf.get("GUI_PORT") or 1081)
    server = PanelServer(("", port), PanelHandler)
    server.conf = conf
    server.allowed_hosts = build_allowed_hosts(conf)
    signal.signal(signal.SIGTERM, lambda *_: server.shutdown())
    print(f"LoxProx Panel listening on :{port} "
          f"(hosts: {', '.join(sorted(server.allowed_hosts))})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
