#!/usr/bin/env python3
"""
CrowdSec Progressive Ban Hammer
Extends ban durations for repeat offenders.

Escalation:
  1st ban  → keep default (4h, handled by CrowdSec)
  2nd ban  → 24 hours
  3rd ban  → 7 days
  4th+ ban → 30 days

An "offense" is a distinct attack incident inside a rolling window, not a raw
alert count: alerts older than PROGRESSIVE_BAN_WINDOW_DAYS are forgotten, only
alerts from local scenario/AppSec detections count (CAPI/community-list entries,
manual bans and this script's own extensions do not), and alerts within
PROGRESSIVE_BAN_DEDUP_MINUTES of each other count once, regardless of scenario —
a single multi-scenario burst is one incident, not an instant 30-day ban. IPs
covered by the CrowdSec whitelist are never escalated.

Overrides may be set in the environment or in /etc/loxprox/config.env:
  PROGRESSIVE_BAN_WINDOW_DAYS     (default 30)
  PROGRESSIVE_BAN_DEDUP_MINUTES   (default 60)
  PROGRESSIVE_BAN_WHITELIST_FILE  (default the deploy-managed whitelist YAML)

Run via cron every 15 minutes.
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("progressive-ban")

# Escalation table: offense_count -> duration
# Offense count = distinct in-window attack incidents for this IP, current one
# included (see count_offenses).
ESCALATION = {
    2: "24h",
    3: "168h",   # 7 days
    4: "720h",   # 30 days
}
DEFAULT_EXTENDED = "720h"  # 30 days for anything beyond 4th
CSCLI_TIMEOUT = 30  # seconds — MED-003 fix
STATE_FILE = "/var/lib/loxprox/extended-decisions.json"
CONFIG_FILE = os.environ.get("LOXPROX_CONFIG", "/etc/loxprox/config.env")
DEFAULT_WHITELIST_FILE = "/etc/crowdsec/parsers/s02-enrich/whitelist-loxone.yaml"
# Origin carried by decisions from local scenarios and AppSec — the only kind of
# alert that represents this IP actually misbehaving against this gateway.
ATTACK_ORIGIN = "crowdsec"
# Reason this script stamps on its own extensions. Those come back as origin
# "cscli" alerts; the prefix is the second guard for cscli builds whose
# `alerts list` payload carries no decisions.
REASON_PREFIX = "repeat-offender-"


def load_env_config(path: str) -> dict:
    """Parse the KEY="value" lines of config.env. Cron gives us no environment."""
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, raw = line.partition("=")
                key = key.strip()
                if key.isidentifier():
                    values[key] = raw.strip().strip('"').strip("'")
    except OSError:
        return {}
    return values


_CONFIG = load_env_config(CONFIG_FILE)


def setting(name: str, default: str) -> str:
    return os.environ.get(name) or _CONFIG.get(name) or default


def setting_int(name: str, default: int) -> int:
    try:
        value = int(setting(name, str(default)))
    except ValueError:
        logger.warning("%s is not a number — using default %d", name, default)
        return default
    return value if value > 0 else default


# Defaults are deliberately forgiving: every device behind the household NAT
# shares one public IP, so a month-long window plus per-incident dedup is what
# keeps one misbehaving phone from escalating a ban onto the whole family.
WINDOW_DAYS = setting_int("PROGRESSIVE_BAN_WINDOW_DAYS", 30)
DEDUP_MINUTES = setting_int("PROGRESSIVE_BAN_DEDUP_MINUTES", 60)
WHITELIST_FILE = setting("PROGRESSIVE_BAN_WHITELIST_FILE", DEFAULT_WHITELIST_FILE)


def run_cscli(args):
    cmd = ["cscli"] + args + ["-o", "json"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CSCLI_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        logger.error("cscli command timed out after %ds: %s", CSCLI_TIMEOUT, " ".join(cmd))
        return None
    except FileNotFoundError:
        logger.error("cscli not found in PATH")
        return None

    if result.returncode != 0:
        logger.error("cscli error (rc=%d): %s", result.returncode, result.stderr.strip())
        return None
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.error("cscli JSON decode error: %s", exc)
        return None
    # cscli emits `null` (not `[]`) when no decisions exist — Go's nil-slice
    # JSON marshalling. Normalise so callers can iterate without a None check.
    return [] if parsed is None else parsed


def cscli_decision_delete(decision_id: str) -> bool:
    """Delete a CrowdSec decision by ID. Returns True on success."""
    try:
        result = subprocess.run(
            ["cscli", "decisions", "delete", "--id", str(decision_id)],
            capture_output=True, text=True, timeout=CSCLI_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.error("cscli decisions delete timed out for id=%s", decision_id)
        return False
    if result.returncode != 0:
        logger.error("cscli decisions delete failed (rc=%d): %s", result.returncode, result.stderr.strip())
        return False
    return True


def cscli_decision_add(ip: str, duration: str, reason: str) -> bool:
    """Add a CrowdSec decision. Returns True on success."""
    try:
        result = subprocess.run(
            ["cscli", "decisions", "add", "--ip", ip, "--duration", duration, "--reason", reason],
            capture_output=True, text=True, timeout=CSCLI_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.error("cscli decisions add timed out for ip=%s", ip)
        return False
    if result.returncode != 0:
        logger.error("cscli decisions add failed (rc=%d): %s", result.returncode, result.stderr.strip())
        return False
    return True


def load_state() -> dict:
    """Load the extended-decisions state file. Returns empty dict on missing/corrupt file."""
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("State file unreadable (%s), starting fresh", exc)
        return {}


def save_state(state: dict) -> None:
    """Persist the extended-decisions state file. Logs warning on failure."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except OSError as exc:
        logger.warning("Failed to write state file %s: %s", STATE_FILE, exc)


def load_whitelist(path: str) -> list:
    """Networks from the deploy-managed CrowdSec whitelist YAML.

    The file is generated by deploy.sh (fixed shape: a ``whitelist:`` block with
    ``ip:`` and ``cidr:`` lists), so a line scan is enough and avoids a PyYAML
    dependency that stock Debian does not ship.
    """
    nets = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                match = re.match(r'\s*-\s*"?([0-9A-Fa-f:.]+(?:/\d{1,3})?)"?\s*$', line)
                if not match:
                    continue
                try:
                    nets.append(ipaddress.ip_network(match.group(1), strict=False))
                except ValueError:
                    continue
    except OSError as exc:
        logger.warning("Whitelist %s unreadable (%s) — no IP will be treated as trusted", path, exc)
        return []
    return nets


def is_whitelisted(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def parse_timestamp(raw: str):
    """Parse a CrowdSec RFC3339 timestamp. Returns None when unparseable."""
    if not raw:
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", raw.strip().replace("Z", "+00:00"))
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def is_attack_alert(alert: dict) -> bool:
    """True only for alerts raised by a local scenario/AppSec detection.

    Excludes CAPI/community-list imports (global reputation, not this gateway),
    manual ``cscli decisions add`` bans, and the extensions this script itself
    writes — counting those made every escalation feed the next one.
    """
    origins = {
        d.get("origin", "") for d in (alert.get("decisions") or []) if isinstance(d, dict)
    }
    if origins:
        return ATTACK_ORIGIN in origins
    scenario = (alert.get("scenario") or "").strip()
    return bool(scenario) and not scenario.startswith((REASON_PREFIX, "manual", "update :"))


def count_offenses(ip: str) -> int:
    """Distinct attack incidents for an IP inside the rolling window.

    H1: ``cscli decisions list`` only ever returns *currently-active* decisions
    (``-a`` merely un-hides CAPI/list entries, it does NOT add expired ones), so
    a decision-based counter saw at most 1 and the 2nd→24h / 3rd→7d policy never
    fired. CrowdSec **alerts** persist after a decision expires, so they are the
    durable offense history.

    M9: raw alert count is not an offense count, though. Alerts are filtered to
    genuine attack origins (see is_attack_alert), dropped once they fall outside
    WINDOW_DAYS — so offenses expire instead of accumulating for a year — and
    time-clustered across ALL scenarios within DEDUP_MINUTES: one probe burst
    routinely trips several scenarios (http-probing + bad-user-agent + AppSec)
    in the same minute, and counting each scenario separately would jump a
    single incident straight to the 30-day tier.
    """
    alerts = run_cscli(["alerts", "list", "--ip", ip, "--limit", "0"])
    if not alerts:
        return 1  # at minimum, the offense that produced the current ban

    cutoff = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    dedup = timedelta(minutes=DEDUP_MINUTES)

    stamps = []
    for alert in alerts:
        if not isinstance(alert, dict) or not is_attack_alert(alert):
            continue
        stamp = parse_timestamp(alert.get("created_at") or alert.get("start_at") or "")
        if stamp is None or stamp < cutoff:
            continue
        stamps.append(stamp)

    stamps.sort()
    incidents = 0
    last = None
    for stamp in stamps:
        if last is None or stamp - last > dedup:
            incidents += 1
        last = stamp
    return max(1, incidents)


def main():
    state = load_state()
    whitelist_nets = load_whitelist(WHITELIST_FILE)
    logger.info(
        "Window: %dd | dedup: %dmin | whitelist entries: %d",
        WINDOW_DAYS, DEDUP_MINUTES, len(whitelist_nets),
    )

    # H1: offenses are counted per-IP from CrowdSec ALERTS (see count_offenses),
    # which survive decision expiry — `cscli decisions list [-a]` only ever returns
    # currently-active decisions, so the old counter never reached 2. `-a` is dropped
    # entirely (it only un-hides CAPI/list decisions; it never returns expired ones).

    # Get currently active decisions
    active = run_cscli(["decisions", "list"])
    if active is None:
        sys.exit(1)

    # Prune stale state entries (IPs no longer with active cscli bans)
    active_cscli_ips = {
        d.get("value", "") for d in active
        if d.get("origin") == "cscli" and d.get("value")
    }
    pruned = 0
    for key in list(state.keys()):
        if key not in active_cscli_ips:
            del state[key]
            pruned += 1
    if pruned:
        logger.info("Pruned %d stale entries from state file", pruned)
        save_state(state)

    extended = 0
    skipped = 0

    for d in active:
        ip = d.get("value", "")
        origin = d.get("origin", "")
        scenario = d.get("scenario", "")
        id_ = str(d.get("id", ""))

        if not ip or not id_:
            continue

        # H1: extend local scenario/AppSec bans (origin "crowdsec"); skip CAPI /
        # community-list decisions (global reputation, not repeat local misbehavior)
        # and this script's own prior extensions (origin "cscli", guarded by state).
        if origin != ATTACK_ORIGIN:
            skipped += 1
            continue

        # M9/M10: the household NAT address can end up banned by a single
        # misbehaving device. If the operator trusts it enough to whitelist it,
        # this script must never be the thing that escalates it to 30 days.
        if is_whitelisted(ip, whitelist_nets):
            logger.info("Skipping %s — covered by the CrowdSec whitelist (%s)", ip, WHITELIST_FILE)
            skipped += 1
            continue

        offenses = count_offenses(ip)

        if offenses >= 4:
            target = DEFAULT_EXTENDED
        elif offenses in ESCALATION:
            target = ESCALATION[offenses]
        else:
            skipped += 1
            continue

        # Skip if this IP was already extended to the same target
        if ip in state and state[ip] == target:
            skipped += 1
            continue

        logger.info(
            "[NUKE] IP %s | offense #%d | scenario: %s | extending to %s",
            ip, offenses, scenario, target,
        )

        # F9: add the extended ban FIRST, then delete the original. A failure
        # between the two steps then leaves the IP *over*-banned (two overlapping
        # decisions, the longer one wins) instead of UNbanned — fail safe, not
        # fail open. The stale original simply expires on its own if the delete
        # never lands.
        if not cscli_decision_add(ip, target, f"{REASON_PREFIX}{offenses}"):
            logger.warning("Failed to add extended decision for %s — leaving original ban in place", ip)
            continue
        if not cscli_decision_delete(id_):
            logger.warning(
                "Added extended ban for %s but failed to delete original %s — "
                "harmless duplicate, original will expire on its own", ip, id_,
            )

        state[ip] = target
        extended += 1

    if extended:
        save_state(state)

    logger.info("Done. Extended: %d, Skipped: %d", extended, skipped)


if __name__ == "__main__":
    main()
