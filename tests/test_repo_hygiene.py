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

import hashlib
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

# Generic leak shapes. These name no real value, so they stay readable regexes.
# Placeholders (192.168.1.x, 192.168.2.x, 10.0.0.x, 1.2.3.4, the documentation
# ranges) and generic DDNS provider names are fine and deliberately not matched.
OPSEC_FORBIDDEN = [
    (r"discord(?:app)?\.com/api/webhooks/\d{15,}", "real Discord webhook (15+ digit snowflake)"),
]

# Real identifiers of the live deployment and its maintainer. They must NEVER
# appear in a tracked (public) file, and this public guard must not spell them
# out either, so it stores only sha256(lower-cased value). Every tracked text
# file, this one included, is tokenised; each candidate string is hashed and
# looked up. A hit reports the label and path:line, never the matched text.
#
# Adding an entry: hash the value locally and commit only the hash —
#     printf %s '<value>' | tr A-Z a-z | sha256sum      (macOS: shasum -a 256)
# Run that in a terminal, never in a commit, PR, issue, or CI log. For a
# network, hash its /24 network address ('10.1.2.0'); any address or prefix
# inside that /24 then matches. See opsec_candidates() for what one token yields.
#
# Limits: sha256 keeps the values out of the source and out of search, but a
# low-entropy value (a /24, a short word) can be recovered by trying every
# candidate. This is a guard against re-publishing, not a place to keep secrets.
OPSEC_FORBIDDEN_SHA256 = {
    "fe5b65852360d95941ca2920dc1409ca99e367e246d03a1ca2aa10558049622d": "real SSH alias #1",
    "f5e74d93933870bc6075381e066eaa1d3d53f519547c3fe5bf2c1b36c22d2374": "real SSH alias #2",
    "61a13826027fc3371224b35a703586281896ccfafb962d2778a0e7586732acca": "real SSH alias #3",
    "29feb5d3b68f493955a9c688197c580c99cd2ec416221d3537ce00c48c5765f2": "real deployment codename",
    "b40c1321f736b8234bb5bd049eedd21ec503f629fc7ffce4d203a58dcca03cf2": "maintainer real email local-part",
    "91b1fc4f9af93380d481da0f760058198f69f644b66387e2a0ab8bb4e5bba276": "maintainer real email domain",
    "64987d7d98418ba06e6690f5f35d477cbdc452979a2a0524c416f7896defa1a5": "production gateway hostname",
    "e925e4871f0db772a2e276eba64101927b58859902b690caa44ce159fe2368c7": "production DDNS label",
    "50bdc3ebbbf4b3c3b3b7eb2b4700d94cec412bb6bc9b810760dd9f924214b9cd": "real site-to-site subnet",
    "b3d5c873a7a1eae8f0a740e0cf708cf0a4187ab81b642f36bc19a11af0dd674b": "real production LAN subnet",
    "ed7e163a400889ee46cc4461e536c205f3054e48db69bc1c5573188985a4dc4a": "maintainer workstation hostname",
}

_OPSEC_TOKEN_RX = re.compile(r"[A-Za-z0-9._@-]+")
_OPSEC_NET24_RX = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\.|$)")


@lru_cache(maxsize=None)
def _sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def opsec_candidates(token):
    """Lower-cased strings checked for one token: the token, its user and
    domain parts around '@', every dot-label and every '-'/'_' part of a
    label, every parent domain (a.b.c -> b.c), and, for a dotted-quad or a
    three-octet prefix, its /24 network address (192.0.2.7 and 192.0.2.x
    both -> 192.0.2.0)."""
    t = token.strip("._-@").lower()
    if not t:
        return set()
    out = {t}
    for part in t.split("@"):
        labels = [label for label in part.split(".") if label]
        if not labels:
            continue
        out.add(".".join(labels))
        out.update(labels)
        out.update(".".join(labels[i:]) for i in range(1, len(labels) - 1))
        for label in labels:
            out.update(p for p in re.split(r"[-_]", label) if p)
    m = _OPSEC_NET24_RX.match(t)
    if m:
        out.add(f"{m.group(1)}.{m.group(2)}.{m.group(3)}.0")
    return out


def opsec_hash_hits(text, deny):
    """Return [(lineno, label)] for every line of `text` containing a token
    whose candidate hashes to an entry of `deny` ({sha256: label}). Regex
    escapes (`\\.`) are undone first so an escaped value cannot slip past."""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        found = set()
        for tok in _OPSEC_TOKEN_RX.findall(line.replace("\\.", ".")):
            for cand in opsec_candidates(tok):
                if _sha256(cand) in deny:
                    found.add(deny[_sha256(cand)])
        hits.extend((i, label) for label in sorted(found))
    return hits


def test_no_opsec_leaks():
    # Report label + location only: echoing the line would re-publish the
    # very value the check exists to keep out (CI logs are public).
    hits = []
    for pat, why in OPSEC_FORBIDDEN:
        for f, ln, _txt in scan(pat):
            hits.append((f, ln, f"[{why}]"))
    for f in text_files() + [SELF]:
        for ln, why in opsec_hash_hits(read(f), OPSEC_FORBIDDEN_SHA256):
            hits.append((f, ln, f"[{why}]"))
    assert not hits, (
        "Real production details leaked into tracked (public) files:\n" + fmt(hits)
        + "\n\nScrub to a placeholder, or move the file to the gitignored "
          "local-deployment/."
    )


def test_opsec_hash_guard_matches_without_echoing():
    # Inert canaries, hashed the same way as the real entries.
    host, net = "canary-gw.example.invalid", "198.51.100.0"
    deny = {_sha256(host): "canary host", _sha256(net): "canary subnet",
            _sha256("canary-alias"): "canary alias"}
    text = "\n".join([
        "ssh admin@Canary-GW.example.invalid -p 22",   # 1: user@host, case-folded
        "allow 198.51.100.7/24 and 198.51.100.x",      # 2: address and prefix -> /24
        r"(r'198\.51\.100\.\d+', 'escaped')",          # 3: regex-escaped prefix
        "Host canary-alias",                           # 4: bare alias
        "198.51.101.7 canary-gw2.example.invalid",     # 5: neighbours must not match
        "ProxyJump canary-alias-2",                    # 6: a longer alias is another token
    ])
    assert opsec_hash_hits(text, deny) == [
        (1, "canary host"), (2, "canary subnet"), (3, "canary subnet"), (4, "canary alias"),
    ]
    report = fmt([("f", ln, f"[{why}]") for ln, why in opsec_hash_hits(text, deny)])
    assert host not in report.lower() and "198.51.100" not in report


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
