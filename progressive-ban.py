#!/usr/bin/env python3
"""
CrowdSec Progressive Ban Hammer
Extends ban durations for repeat offenders.

Escalation:
  1st ban  → keep default (4h, handled by CrowdSec)
  2nd ban  → 24 hours
  3rd ban  → 7 days
  4th+ ban → 30 days

Run via cron every 15 minutes.
"""

import json
import logging
import os
import subprocess
import sys
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("progressive-ban")

# Escalation table: offense_count -> duration
# Offense count = total number of bans for this IP (including current)
ESCALATION = {
    2: "24h",
    3: "168h",   # 7 days
    4: "720h",   # 30 days
}
DEFAULT_EXTENDED = "720h"  # 30 days for anything beyond 4th
CSCLI_TIMEOUT = 30  # seconds — MED-003 fix
STATE_FILE = "/var/lib/loxone-monitor/extended-decisions.json"


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
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.error("cscli JSON decode error: %s", exc)
        return None


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


def main():
    state = load_state()

    # Get all decisions (active + expired) to count offenses per IP
    all_decisions = run_cscli(["decisions", "list", "-a"])
    if all_decisions is None:
        sys.exit(1)

    # Count total offenses per IP
    ip_offenses = defaultdict(int)
    for d in all_decisions:
        ip = d.get("value", "")
        if ip:
            ip_offenses[ip] += 1

    # Get currently active decisions
    active = run_cscli(["decisions", "list"])
    if active is None:
        sys.exit(1)

    # Prune stale state entries (IDs no longer in active decisions)
    active_ids = {str(d.get("id", "")) for d in active}
    pruned = 0
    for key in list(state.keys()):
        if key not in active_ids:
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

        # Only extend local (cscli) bans, not CAPI community bans
        if origin != "cscli":
            skipped += 1
            continue

        offenses = ip_offenses.get(ip, 1)

        if offenses >= 4:
            target = DEFAULT_EXTENDED
        elif offenses in ESCALATION:
            target = ESCALATION[offenses]
        else:
            skipped += 1
            continue

        # Skip if this decision ID was already extended to the same target
        if id_ in state and state[id_] == target:
            skipped += 1
            continue

        logger.info(
            "[NUKE] IP %s | offense #%d | scenario: %s | extending to %s",
            ip, offenses, scenario, target,
        )

        # Delete current ban and re-add with longer duration
        if not cscli_decision_delete(id_):
            logger.warning("Failed to delete decision %s for %s — skipping add", id_, ip)
            continue
        if not cscli_decision_add(ip, target, f"repeat-offender-{offenses}"):
            logger.warning("Failed to add extended decision for %s — IP may be unbanned", ip)
            continue

        state[id_] = target
        save_state(state)
        extended += 1

    logger.info("Done. Extended: %d, Skipped: %d", extended, skipped)


if __name__ == "__main__":
    main()
