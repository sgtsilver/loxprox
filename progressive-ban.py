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
import subprocess
import sys
from collections import defaultdict

# Escalation table: offense_count -> duration
# Offense count = total number of bans for this IP (including current)
ESCALATION = {
    2: "24h",
    3: "168h",   # 7 days
    4: "720h",   # 30 days
}
DEFAULT_EXTENDED = "720h"  # 30 days for anything beyond 4th

def run_cscli(args):
    cmd = ["cscli"] + args + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"cscli error: {result.stderr}", file=sys.stderr)
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

def main():
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

    extended = 0
    skipped = 0

    for d in active:
        ip = d.get("value", "")
        origin = d.get("origin", "")
        scenario = d.get("scenario", "")
        current_duration = d.get("duration", "")
        id_ = d.get("id", "")

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

        # Check if already extended (rough check by duration string)
        if target in current_duration:
            skipped += 1
            continue

        print(f"[NUKE] IP {ip} | offense #{offenses} | scenario: {scenario} | extending to {target}")

        # Delete current ban and re-add with longer duration
        subprocess.run(["cscli", "decisions", "delete", "--id", str(id_)],
                       capture_output=True, text=True)
        subprocess.run(["cscli", "decisions", "add", "--ip", ip,
                        "--duration", target, "--reason", f"repeat-offender-{offenses}"],
                       capture_output=True, text=True)
        extended += 1

    print(f"Done. Extended: {extended}, Skipped: {skipped}")

if __name__ == "__main__":
    main()
