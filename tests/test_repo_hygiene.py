"""
Repo-hygiene guard suite — the automated version of the Fortune-100 deep-clean
audits, so we never have to do them by hand again.

Every check here encodes a finding class that a manual audit surfaced:
OpSec leaks, stale hardware/version/config-model references, dead-file refs,
broken internal links, bilingual-pair completeness, naming casing, and
deprecated patterns.

SCOPE: only files **tracked by git** are checked — i.e. the public GitHub
deployment. The gitignored `local-deployment/` (the live production gateway's
real config) is never enumerated by `git ls-files`, so it can hold whatever it wants.

Run: `pytest tests/test_repo_hygiene.py -v`  (or the whole `tests/` dir).
"""

import re
import subprocess
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


# ── helpers ──────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def tracked_files():
    """All git-tracked paths (relative to repo root). Excludes gitignored
    local-deployment/, .venv, audit scratch, etc. by construction."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


SELF = "tests/test_repo_hygiene.py"


@lru_cache(maxsize=1)
def text_files():
    """Tracked files we can scan as text. Skips binary-ish files and this guard
    itself — the guard intentionally contains the forbidden strings (OpSec
    patterns, `apt-key add`, `DISCORD_WEBHOOK`, …) as its detection rules, so
    scanning it would self-trip every check."""
    skip_suffix = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2")
    return [f for f in tracked_files()
            if not f.endswith(skip_suffix) and f != SELF]


@lru_cache(maxsize=1)
def md_files():
    return [f for f in tracked_files() if f.endswith(".md")]


def read(rel):
    return (REPO / rel).read_text(encoding="utf-8", errors="ignore")


def lines(rel):
    return read(rel).splitlines()


def scan(pattern, files=None, flags=re.IGNORECASE):
    """Yield (file, lineno, line) for every line matching `pattern`."""
    rx = re.compile(pattern, flags)
    for f in (files or text_files()):
        for i, line in enumerate(lines(f), 1):
            if rx.search(line):
                yield f, i, line.strip()


@lru_cache(maxsize=1)
def latest_version():
    """Ground-truth current version, from CITATION.cff (always present)."""
    m = re.search(r"^version:\s*([0-9][0-9.]*)", read("CITATION.cff"), re.MULTILINE)
    assert m, "CITATION.cff has no version field"
    return m.group(1)


def fmt(violations):
    return "\n".join(f"  {f}:{ln}: {txt}" for f, ln, txt in violations)


# ── 1. OpSec: no real production details in the public repo ───────────────────

# Real prod identifiers for the live production gateway. These must NEVER appear in a
# tracked (public) file. Placeholders (192.168.1.x, 10.0.0.x, 1.2.3.4) and the
# generic DDNS provider name "selfhost.eu" are fine and deliberately not matched.
OPSEC_FORBIDDEN = [
    (r"dewia71", "real DDNS subdomain label"),
    (r"192\.168\.178\.\d{1,3}", "real production LAN subnet"),
    (r"loxprox-wiener", "real SSH alias"),
    (r"\bwiener\b", "real deployment codename"),
    (r"discord\.com/api/webhooks/\d{15,}", "real Discord webhook (15+ digit snowflake)"),
    (r"paul\.schneider", "maintainer real name/email local-part"),
    (r"@wtnet\.de", "maintainer real email domain"),
]


def test_no_opsec_leaks():
    hits = []
    for pat, why in OPSEC_FORBIDDEN:
        for f, ln, txt in scan(pat):
            hits.append((f, ln, f"[{why}] {txt}"))
    assert not hits, (
        "Real production details leaked into tracked (public) files:\n" + fmt(hits)
        + "\n\nScrub to a placeholder, or move the file to the gitignored "
          "local-deployment/."
    )


# ── 2. Hardware: no stale 512MB-as-minimum ────────────────────────────────────

def test_no_stale_512mb_minimum():
    # 512MB is the retired RAM floor. It's legitimate ONLY when describing the
    # Pi Zero 2 W's actual onboard RAM, and in append-only history (CHANGELOG /
    # audits/) which records the figure being retired.
    hits = []
    for f, ln, txt in scan(r"512\s?MB"):
        if f == "CHANGELOG.md" or f.startswith("audits/"):
            continue
        if re.search(r"zero", txt, re.IGNORECASE):  # Pi Zero 2 W context
            continue
        hits.append((f, ln, txt))
    assert not hits, (
        "Stale 512MB-as-minimum hardware reference (current floor is 1 GB):\n" + fmt(hits)
    )


# ── 3. Versions: current is current, retired tags stay out of code ────────────

def test_citation_version_matches_latest_tag():
    try:
        tag = subprocess.run(
            ["git", "-C", str(REPO), "describe", "--tags", "--abbrev=0"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return  # shallow CI checkout without tags — skip the cross-check
    assert tag.lstrip("v") == latest_version(), (
        f"CITATION.cff version ({latest_version()}) != latest git tag ({tag}). "
        "Bump CITATION.cff when you cut a release."
    )


def test_no_retired_versions_in_code():
    # v1.4.0 and the v1.6.x same-day tags were retired/consolidated into v1.5.0.
    # They may appear in CHANGELOG/RUNDOWN prose (legit history) but must NEVER
    # label a feature in code/config (the regression we just cleaned).
    code = [f for f in text_files()
            if f.endswith((".sh", ".py", ".conf", ".example", ".yml", ".yaml",
                           ".service", ".timer"))]
    hits = list(scan(r"v1\.6\.\d", files=tuple(code), flags=0))
    assert not hits, (
        "Retired v1.6.x tag referenced as a real version in code/config "
        "(those features shipped in v1.5.0):\n" + fmt(hits)
    )


def test_rundown_version_header_is_current():
    m = re.search(r"\*\*Version:\*\*\s*([0-9][0-9.]*)", read("RUNDOWN.md"))
    if m:
        assert m.group(1) == latest_version(), (
            f"RUNDOWN.md Version header ({m.group(1)}) != current ({latest_version()})."
        )


# ── 4. Config model: post-v1.5.0 reality ──────────────────────────────────────

def test_no_stale_config_model():
    hits = []
    # The webhook key is DISCORD_WEBHOOK_URL; a bare DISCORD_WEBHOOK is the old/wrong key.
    for f, ln, txt in scan(r"DISCORD_WEBHOOK(?!_URL)\b", flags=0):
        hits.append((f, ln, f"[bare DISCORD_WEBHOOK — key is DISCORD_WEBHOOK_URL] {txt}"))
    # "set the webhook in deploy.sh" is stale (it lives in config.env / deploy.conf).
    for f, ln, txt in scan(r"DISCORD_WEBHOOK_URL[^\n]{0,30}\bin\b[^\n]{0,20}deploy\.sh"):
        hits.append((f, ln, f"[webhook is not set in deploy.sh] {txt}"))
    assert not hits, ("Stale config-model reference:\n" + fmt(hits))


def test_no_config_at_top_of_deploy_sh():
    # Config moved to /etc/loxprox/deploy.conf in v1.5.0. The UPGRADE guide and
    # CHANGELOG legitimately describe the OLD model historically; everyone else
    # must not present it as current.
    allow_prefix = ("docs/UPGRADE-to-v1.5", "CHANGELOG.md")
    # Historical / negated mentions are correct and must NOT be flagged:
    # "not at the top of deploy.sh", "values that used to live at the top of …".
    ok_context = ("not at the top", "used to", "no longer", "moved", "instead of")
    hits = []
    for f, ln, txt in scan(r"top of\s+`?deploy\.sh"):
        if f.startswith(allow_prefix) or any(k in txt.lower() for k in ok_context):
            continue
        hits.append((f, ln, txt))
    assert not hits, (
        "Stale 'config lives at the top of deploy.sh' (moved to deploy.conf in v1.5.0):\n"
        + fmt(hits)
    )


# ── 5. Dead files stay dead ───────────────────────────────────────────────────

REMOVED_FOR_GOOD = [
    "VALIDATION-REPORT.html",            # leaked prod, stale
    ".env.example",                      # orphaned; config.env is generated
    "phase2-gateway/setup-lxc.sh",       # LXC provisioner contradicting VM-only
    "security-monitoring/loxprox-monitor.service",  # deploy.sh generates inline
    "security-monitoring/loxprox-monitor.timer",
]


def test_removed_files_not_resurrected():
    back = [f for f in REMOVED_FOR_GOOD if f in tracked_files()]
    assert not back, (
        "Files removed in the deep clean are tracked again:\n  " + "\n  ".join(back)
    )


def test_no_references_to_purely_dead_files():
    # These two have no legitimate reason to be named anywhere anymore.
    # (loxprox-monitor.{service,timer} are NOT here — those names still refer to
    # the unit deploy.sh generates inline.)
    dead_names = [r"VALIDATION-REPORT\.html", r"\.env\.example"]
    hits = []
    for pat in dead_names:
        for f, ln, txt in scan(pat, files=tuple(md_files())):
            hits.append((f, ln, txt))
    assert not hits, ("Doc references a removed file:\n" + fmt(hits))


# ── 6. Internal links resolve ─────────────────────────────────────────────────

LINK_RX = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def test_internal_doc_links_resolve():
    broken = []
    for f in md_files():
        base = (REPO / f).parent
        for target in LINK_RX.findall(read(f)):
            target = target.strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if "<" in target or ">" in target:
                continue  # literal placeholder in templates, e.g. <file>.md
            path = target.split("#", 1)[0]  # drop anchor
            if not path:
                continue
            if not (base / path).resolve().exists():
                broken.append((f, 0, f"-> {target}"))
    assert not broken, ("Broken internal doc links:\n" + fmt(broken))


# ── 7. deploy.sh line-count claims stay roughly honest ────────────────────────

def test_deploy_sh_line_count_claims():
    actual = len(lines("deploy.sh"))
    # Only the living docs make a "~NNNN lines/Zeilen" claim about deploy.sh.
    hits = []
    for f in ("ABOUT.md", "ABOUT.de.md", "RUNDOWN.md"):
        for ln, line in enumerate(lines(f), 1):
            if "deploy.sh" not in line and "deploy-Script" not in line:
                pass
            for m in re.finditer(r"~?\s?(\d{3,5})[\s-]?(?:lines|Zeilen|-line)", line):
                claimed = int(m.group(1))
                if abs(claimed - actual) > 200:
                    hits.append((f, ln, f"claims {claimed} lines, deploy.sh is {actual}"))
    assert not hits, (
        "deploy.sh line-count claim drifted >200 from reality:\n" + fmt(hits)
        + f"\n(actual: {actual})"
    )


# ── 8. Bilingual completeness (the repo's own CONTRIBUTING rule) ──────────────

# Intentionally single-language / English-only files (documented exceptions).
MONOLINGUAL_OK = {
    "README.md", "README.en.md",            # README pair is .md(DE) + .en.md(EN)
    "RUNDOWN.md", "GITHUB-METADATA.md", "CHANGELOG.md",
    "grafana-integration/README.md",        # optional add-on, EN-only
}

# Directory prefixes that are exempt as a class:
#   audits/   — append-only audit history
#   docs/adr/ — architecture decision records; ADRs are immutable-once-accepted
#               single-language records by convention (translating append-only
#               history would double maintenance for zero operator value)
MONOLINGUAL_OK_PREFIXES = ("audits/", "docs/adr/")


def test_bilingual_pairs_complete():
    missing = []
    # README is the special pair.
    for a, b in [("README.md", "README.en.md")]:
        if a in tracked_files() and b not in tracked_files():
            missing.append(f"{a} has no {b}")
    for f in md_files():
        if f in MONOLINGUAL_OK or f.startswith(MONOLINGUAL_OK_PREFIXES):
            continue
        if f.endswith(".de.md"):
            en = f[:-6] + ".md"
            if en not in tracked_files():
                missing.append(f"{f} has no English {en}")
        else:  # X.md (English) should have X.de.md
            de = f[:-3] + ".de.md"
            if de not in tracked_files():
                missing.append(f"{f} has no German {de}")
    assert not missing, (
        "Bilingual pairing incomplete (CONTRIBUTING requires EN+DE for every doc):\n  "
        + "\n  ".join(missing)
        + "\n(add the missing translation, or add the file to MONOLINGUAL_OK here)"
    )


# ── 9. Deprecated / unprofessional patterns ───────────────────────────────────

def test_no_deprecated_apt_key():
    hits = list(scan(r"apt-key\s+add"))
    assert not hits, ("Deprecated `apt-key add` (removed in Debian 12):\n" + fmt(hits))


def test_project_name_casing():
    # Display name is "LoxProx"; lowercase "loxprox" is fine for repo/paths/commands;
    # LOXPROX_ env prefix and LOXPROX- markers are fine. Catch broken casings.
    # Prose only (.md). All-caps "LOXPROX" in shell banners/echo is stylistic and fine.
    hits = []
    for pat in (r"\bLoxprox\b", r"\bloxProx\b"):
        for f, ln, txt in scan(pat, files=tuple(md_files()), flags=0):
            hits.append((f, ln, txt))
    assert not hits, ("Inconsistent project-name casing (use 'LoxProx'):\n" + fmt(hits))
