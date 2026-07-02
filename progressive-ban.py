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
STATE_FILE = "/var/lib/loxprox/extended-decisions.json"


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


def count_offenses(ip: str) -> int:
    """Lifetime local offense count for an IP.

    H1: scenario- and AppSec-triggered bans carry origin ``crowdsec`` (not
    ``cscli`` — that origin is only manual ``cscli decisions add`` and this
    script's own extensions). And ``cscli decisions list`` only ever returns
    *currently-active* decisions (``-a`` merely un-hides CAPI/list entries, it
    does NOT add expired ones), so the old per-IP counter saw at most 1 and the
    2nd→24h / 3rd→7d policy never fired. CrowdSec **alerts** persist after a
    decision expires, so they are the durable offense history — one alert per
    local scenario trigger for the source IP.
    """
    alerts = run_cscli(["alerts", "list", "--ip", ip])
    if not alerts:
        return 1  # at minimum, the offense that produced the current ban
    return max(1, len(alerts))


def main():
    state = load_state()

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
        if origin != "crowdsec":
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
        if not cscli_decision_add(ip, target, f"repeat-offender-{offenses}"):
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
