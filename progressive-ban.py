#!/usr/bin/env python3
"""
CrowdSec Progressive Ban Hammer
Extends ban durations for repeat offenders and for unambiguous scanners.

Two ladders (2026-10 breach hardening). Scenarios matching BAN_HARD_SCENARIOS
(CVE/vpatch probes, sensitive-file and backdoor probing, the nginx scanner
trap) are unambiguous scanners and use the HARD ladder; everything else is
ambiguous and uses the SOFT ladder:

  offence #   HARD (default)      SOFT (default)
  1           168h (7 days)       24h
  2           2160h (90 days)     168h (7 days)
  3           8760h (365 days)    720h (30 days)
  4+          8760h               2160h (90 days)

An incident is HARD if any alert in it (alerts within the dedup interval of
each other) matches BAN_HARD_SCENARIOS. The offence number n is the count of
distinct incidents inside the window; the target is ladder[min(n, len) - 1].
Tier 1 normally comes from the CrowdSec profiles, but this script also acts
on n=1: a ban is replaced whenever the target is longer than what the IP has
left, so a HARD n=1 incident banned by an older/default (4h) profile is lifted
to the HARD tier. A ban is never shortened.

An "offense" is a distinct attack incident inside a rolling window, not a raw
alert count: alerts older than PROGRESSIVE_BAN_WINDOW_DAYS are forgotten, only
alerts from local scenario/AppSec detections count (CAPI/community-list entries,
manual bans, simulated alerts and this script's own extensions do not), and
alerts within PROGRESSIVE_BAN_DEDUP_MINUTES of each other count once,
regardless of scenario — a single multi-scenario burst is one incident. IPs
covered by the CrowdSec whitelist are never escalated.

An extension is a new cscli decision with the reason repeat-offender-<n>
(SOFT) or repeat-offender-hard-<n> (HARD); gateway-monitor.sh alerts the first
per ban and counts the second into its daily HARD digest.

Overrides may be set in the environment or in /etc/loxprox/config.env. Ladder
entries may use m, h or d; days are converted to hours ('7d' -> '168h') before
any cscli call, since CrowdSec's Go duration parser has no day unit:
  BAN_HARD_LADDER                 (default "168h 2160h 8760h")
  BAN_SOFT_LADDER                 (default "24h 168h 720h 2160h")
  BAN_HARD_SCENARIOS              (default regex, see DEFAULT_HARD_SCENARIOS)
  PROGRESSIVE_BAN_WINDOW_DAYS     (default 365)
  PROGRESSIVE_BAN_DEDUP_MINUTES   (default 60)
  PROGRESSIVE_BAN_WHITELIST_FILE  (default the deploy-managed whitelist YAML)
Invalid values fall back to the default with a warning in the log.

Run via cron every 15 minutes under flock.
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

# Ladders: offence n -> duration, index min(n, len) - 1. Offence count = distinct
# in-window attack incidents for this IP, current one included (count_offenses).
DEFAULT_HARD_LADDER = "168h 2160h 8760h"        # 7d, 90d, 365d
DEFAULT_SOFT_LADDER = "24h 168h 720h 2160h"     # 24h, 7d, 30d, 90d
# Must also compile under Go RE2 (CrowdSec's expr `matches`): alternation,
# character classes and `.+` only — no lookaround, no backreferences.
DEFAULT_HARD_SCENARIOS = (
    r"^(loxprox/scanner-trap|crowdsecurity/(appsec-vpatch|vpatch-.+|http-cve-.+"
    r"|CVE-.+|[A-Za-z0-9_]+-cve-.+|http-sensitive-files|http-backdoors-attempts"
    r"|http-path-traversal-probing|http-admin-interface-probing|http-open-proxy))$"
)
# A ban is judged by its ORIGINAL length (time left + time since creation): a
# profile-made 24h/168h ban is correctly tiered however much of it has elapsed
# and must not be re-added. ORIGINAL_TOLERANCE absorbs second-level rounding
# (the alert timestamp precedes the decision's by a moment).
ORIGINAL_TOLERANCE = 0.99
# Fallback when the JSON carries no creation time: compare time LEFT against
# this fraction of the target (re-adds a correctly-tiered ban once, ~10% over).
EXTEND_SLACK = 0.9
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
# Extensions of a HARD incident carry this longer prefix (still REASON_PREFIX
# first): gateway-monitor.sh counts them into its daily HARD digest instead of
# a per-ban alert, because the reason is all the extension's decision shows.
HARD_REASON_PREFIX = REASON_PREFIX + "hard-"


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


DURATION_RE = re.compile(r"^([1-9][0-9]*)([mhd])$")
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}


def duration_to_timedelta(text: str):
    """Ladder entry such as '168h' -> timedelta; None when malformed."""
    match = DURATION_RE.match(text or "")
    if not match:
        return None
    return timedelta(seconds=int(match.group(1)) * _UNIT_SECONDS[match.group(2)])


def go_duration(text: str) -> str:
    """A ladder entry in the form `cscli decisions add --duration` accepts.

    CrowdSec parses durations with Go's time.ParseDuration, which has no `d`
    unit, so '7d' -> '168h'. h and m entries are passed through, the same rule
    as deploy.sh's _loxprox_go_duration. Anything else is returned unchanged.
    """
    match = DURATION_RE.match(text or "")
    if not match:
        return text
    count, unit = int(match.group(1)), match.group(2)
    return f"{count * 24}h" if unit == "d" else f"{count}{unit}"


def parse_ladder(name: str, raw: str, default: str) -> list:
    """Validated ladder (list of Go duration strings) or the default, with a warning.

    Entries are whitespace-separated <n>m|h|d values that never shrink from one
    offence to the next — a ladder that dips would let a repeat offender off
    lighter than the previous time. Day entries come back as hours (go_duration).
    """
    entries = raw.split()
    spans = [duration_to_timedelta(e) for e in entries]
    if not entries or any(sp is None for sp in spans) or spans != sorted(spans):
        logger.warning("%s=%r is not a non-decreasing list of <n>m|h|d durations — using default %r",
                       name, raw, default)
        entries = default.split()
    return [go_duration(e) for e in entries]


def parse_hard_regex(raw: str, default: str):
    """Compiled HARD-scenario regex, or the default's when `raw` does not compile."""
    try:
        return re.compile(raw)
    except re.error as exc:
        logger.warning("BAN_HARD_SCENARIOS is not a valid regex (%s) — using default", exc)
        return re.compile(default)


# The window is long on purpose: the SOFT ladder climbs to 90 days only if an
# IP's earlier incidents are still remembered (CrowdSec's alert flush
# `db_config.flush.max_age` must be at least as long). Per-incident dedup is
# what keeps one misbehaving phone behind the household NAT from escalating.
WINDOW_DAYS = setting_int("PROGRESSIVE_BAN_WINDOW_DAYS", 365)
DEDUP_MINUTES = setting_int("PROGRESSIVE_BAN_DEDUP_MINUTES", 60)
WHITELIST_FILE = setting("PROGRESSIVE_BAN_WHITELIST_FILE", DEFAULT_WHITELIST_FILE)
HARD_LADDER = parse_ladder("BAN_HARD_LADDER", setting("BAN_HARD_LADDER", DEFAULT_HARD_LADDER), DEFAULT_HARD_LADDER)
SOFT_LADDER = parse_ladder("BAN_SOFT_LADDER", setting("BAN_SOFT_LADDER", DEFAULT_SOFT_LADDER), DEFAULT_SOFT_LADDER)
HARD_RE = parse_hard_regex(setting("BAN_HARD_SCENARIOS", DEFAULT_HARD_SCENARIOS), DEFAULT_HARD_SCENARIOS)


def is_hard_scenario(scenario: str) -> bool:
    return bool(HARD_RE.search((scenario or "").strip()))


def ladder_duration(offenses: int, hard: bool) -> str:
    ladder = HARD_LADDER if hard else SOFT_LADDER
    return ladder[min(max(offenses, 1), len(ladder)) - 1]


_GO_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(h|ms|m|s)")
_GO_UNIT_SECONDS = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}


def remaining_duration(raw) -> timedelta:
    """Time left on a decision from cscli's Go duration ('167h59m3.5s').

    Unparseable or negative -> zero: an unknown remainder is treated as
    expired, which can only over-ban (a longer decision is added), never unban.
    """
    text = str(raw or "").strip()
    if not text or text.startswith("-"):
        return timedelta(0)
    total = sum(float(n) * _GO_UNIT_SECONDS[u] for n, u in _GO_DURATION_PART.findall(text))
    return timedelta(seconds=total)


def original_duration(decision: dict, now=None):
    """Length the decision was created with: time left + time since creation.

    None when the creation time is missing/unparseable (callers fall back).
    """
    created = parse_timestamp(decision.get("created_at") or "")
    if created is None:
        return None
    now = now or datetime.now(timezone.utc)
    return remaining_duration(decision.get("duration")) + max(now - created, timedelta(0))


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


def flatten_decisions(data) -> list:
    """The decision objects inside `cscli decisions list -o json`.

    cscli prints ALERTS there (verified on CrowdSec 1.8.1), each with a nested
    `decisions` list (`id`, `value`, `origin`, `type`, `scope`, `duration`,
    `scenario`). Reading those keys at the top level of each alert — what
    main() did — found no `value` anywhere, so every entry was dropped
    silently ("Extended: 0, Skipped: 0") and no ban was ever escalated. A flat
    list of decisions is accepted too. Every decision is kept (no dedupe):
    escalation deletes the original by its decision id.
    """
    out = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("decisions"), list) or ("value" not in item and "source" in item):
            for dec in item.get("decisions") or []:
                if isinstance(dec, dict):
                    if not dec.get("scenario") and item.get("scenario"):
                        dec = dict(dec, scenario=item["scenario"])
                    # Decisions carry no creation time in 1.8.1's nested form;
                    # the alert that raised them does (original_duration).
                    if not dec.get("created_at") and item.get("created_at"):
                        dec = dict(dec, created_at=item["created_at"])
                    out.append(dec)
        else:
            out.append(item)
    return out


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
    duration = go_duration(duration)  # '7d' would be rejected by Go's ParseDuration
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


def analyze_offenses(ip: str):
    """(offence count, current incident is HARD) for an IP inside the rolling window.

    H1: ``cscli decisions list`` only ever returns *currently-active* decisions
    (``-a`` merely un-hides CAPI/list entries, it does NOT add expired ones), so
    a decision-based counter saw at most 1 and the escalation never fired.
    CrowdSec **alerts** persist after a decision expires, so they are the
    durable offense history.

    M9: raw alert count is not an offense count, though. Alerts are filtered to
    genuine attack origins (see is_attack_alert), dropped once they fall outside
    WINDOW_DAYS — so offenses expire instead of accumulating forever — and
    time-clustered across ALL scenarios within DEDUP_MINUTES: one probe burst
    routinely trips several scenarios (http-probing + bad-user-agent + AppSec)
    in the same minute, and counting each scenario separately would jump a
    single incident straight to a high tier.

    The current incident is the newest cluster; it is HARD when any alert in
    it has a scenario matching BAN_HARD_SCENARIOS.
    """
    alerts = run_cscli(["alerts", "list", "--ip", ip, "--limit", "0"])
    if not alerts:
        return 1, False  # at minimum, the offense that produced the current ban

    cutoff = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    dedup = timedelta(minutes=DEDUP_MINUTES)

    entries = []  # (timestamp, scenario)
    for alert in alerts:
        if not isinstance(alert, dict) or not is_attack_alert(alert):
            continue
        if alert.get("simulated"):
            continue  # simulation-mode scenarios block nothing; they are not offences
        stamp = parse_timestamp(alert.get("created_at") or alert.get("start_at") or "")
        if stamp is None or stamp < cutoff:
            continue
        entries.append((stamp, alert.get("scenario") or ""))

    entries.sort(key=lambda e: e[0])
    incidents = 0
    last = None
    current_hard = False
    for stamp, scenario in entries:
        if last is None or stamp - last > dedup:
            incidents += 1
            current_hard = False
        current_hard = current_hard or is_hard_scenario(scenario)
        last = stamp
    return max(1, incidents), current_hard


def count_offenses(ip: str) -> int:
    """Distinct attack incidents for an IP inside the rolling window."""
    return analyze_offenses(ip)[0]


def main():
    state = load_state()
    whitelist_nets = load_whitelist(WHITELIST_FILE)
    logger.info(
        "Window: %dd | dedup: %dmin | whitelist entries: %d | hard ladder: %s | soft ladder: %s",
        WINDOW_DAYS, DEDUP_MINUTES, len(whitelist_nets),
        " ".join(HARD_LADDER), " ".join(SOFT_LADDER),
    )

    # H1: offenses are counted per-IP from CrowdSec ALERTS (see count_offenses),
    # which survive decision expiry — `cscli decisions list [-a]` only ever returns
    # currently-active decisions, so the old counter never reached 2. `-a` is dropped
    # entirely (it only un-hides CAPI/list decisions; it never returns expired ones).

    # Get currently active decisions (flattened out of the alerts cscli prints).
    # --limit 0: cscli returns only 100 alerts by default (1.8.1 --help), and
    # with the HARD ladder far more bans than that are active at once.
    listed = run_cscli(["decisions", "list", "--limit", "0"])
    if listed is None:
        sys.exit(1)
    active = flatten_decisions(listed)
    logger.info("Active decisions: %d (from %d listed entries)", len(active), len(listed))

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

    # Longest time left on any live local ban per IP: an extension must beat all
    # of them (our own earlier extension included), or it would shorten the ban.
    longest_left = {}
    for d in active:
        if d.get("origin") in (ATTACK_ORIGIN, "cscli") and not d.get("simulated") and d.get("value"):
            left = remaining_duration(d.get("duration"))
            longest_left[d["value"]] = max(left, longest_left.get(d["value"], timedelta(0)))

    extended = 0
    skipped = 0

    for d in active:
        ip = d.get("value", "")
        origin = d.get("origin", "")
        scenario = d.get("scenario", "")
        id_ = str(d.get("id", ""))

        if not ip or not id_:
            continue
        if d.get("simulated"):
            skipped += 1   # simulated decisions block nothing; never escalate them
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

        offenses, hard = analyze_offenses(ip)
        hard = hard or is_hard_scenario(scenario)
        target = ladder_duration(offenses, hard)
        target_td = duration_to_timedelta(target)

        # Skip if this IP was already extended to the same target. Compared as
        # spans: a state file written before day units were converted holds "7d".
        if ip in state and duration_to_timedelta(str(state[ip])) == target_td:
            skipped += 1
            continue

        # Extend only. Never shorten: the IP's longest live local ban (our own
        # earlier extension included) must be beaten by the target. Then judge
        # THIS decision by its original length: a ban the profile created at
        # the target length is correctly tiered; an old 4h default, or a lower
        # rung for a repeat offender, is not.
        left = longest_left.get(ip, timedelta(0))
        original = original_duration(d)
        if left >= target_td:
            skipped += 1
            continue
        if original is not None:
            if original >= target_td * ORIGINAL_TOLERANCE:
                skipped += 1
                continue
        else:
            logger.info("No creation time for decision %s (%s) — judging by time left", id_, ip)
            if left >= target_td * EXTEND_SLACK:
                skipped += 1
                continue

        logger.info(
            "[NUKE] IP %s | offense #%d (%s) | scenario: %s | %s left (original %s) -> extending to %s",
            ip, offenses, "hard" if hard else "soft", scenario, left,
            original if original is not None else "unknown", target,
        )

        # F9: add the extended ban FIRST, then delete the original. A failure
        # between the two steps then leaves the IP *over*-banned (two overlapping
        # decisions, the longer one wins) instead of UNbanned — fail safe, not
        # fail open. The stale original simply expires on its own if the delete
        # never lands.
        reason = f"{HARD_REASON_PREFIX if hard else REASON_PREFIX}{offenses}"
        if not cscli_decision_add(ip, target, reason):
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
