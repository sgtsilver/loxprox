"""
Static guards for the operational config deploy.sh generates — the finding
classes of the 2026-10-05 live health audit, encoded so they cannot come back:

  * cron files Debian's cron rejects as a whole (bare ``MAILTO=``),
  * logrotate stanzas that claim the same log file twice (logrotate then skips
    a whole file and the nightly run fails — the 2026-08-30 collision),
  * a persisted deploy-source copy that misses a file deploy.sh reads,
  * security headers the proxy adds itself but lets the upstream duplicate,
  * the AppArmor profile's enforce-readiness rules and containment.

Everything here reads tracked files only; the behavioural counterparts live in
tests/test_deploy_integration.sh (portable) and tests/host-integration.sh (CI,
real cron / logrotate / journald / auditd / AppArmor).

Run: ``pytest tests/test_ops_configs.py -v``
"""

import re
import subprocess
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEPLOY = "deploy.sh"


def read(rel):
    return (REPO / rel).read_text(encoding="utf-8", errors="ignore")


@lru_cache(maxsize=1)
def tracked_files():
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


# ── helpers: deploy.sh defaults + heredocs ────────────────────────────────────

@lru_cache(maxsize=1)
def deploy_defaults():
    """NAME -> default for every `NAME="${NAME:-default}"` line in deploy.sh."""
    rx = re.compile(r'^([A-Z_][A-Z0-9_]*)="\$\{\1:-([^}]*)\}"', re.MULTILINE)
    return {m.group(1): m.group(2) for m in rx.finditer(read(DEPLOY))}


def resolve(target):
    """Expand $VAR / ${VAR} in a heredoc target with deploy.sh's defaults."""
    defaults = deploy_defaults()

    def sub(m):
        return defaults.get(m.group(1) or m.group(2), m.group(0))

    for _ in range(3):  # defaults may reference other defaults
        target = re.sub(r"\$\{([A-Z_][A-Z0-9_]*)\}|\$([A-Z_][A-Z0-9_]*)", sub, target)
    return target


HEREDOC_RX = re.compile(
    r"""cat\s+>\s*(?P<q>["']?)(?P<target>[^"'\s]+)(?P=q)\s+<<(?P<dash>-?)\s*"""
    r"""(?P<dq>['"]?)(?P<delim>[A-Za-z_]+)(?P=dq)"""
)


def heredocs(rel):
    """[(resolved_target, body_lines, start_lineno)] for `cat > X <<DELIM`."""
    lines = read(rel).splitlines()
    found, i = [], 0
    while i < len(lines):
        m = HEREDOC_RX.search(lines[i])
        if not m:
            i += 1
            continue
        delim, dash, start = m.group("delim"), m.group("dash"), i + 1
        body = []
        i += 1
        while i < len(lines):
            end = lines[i].lstrip("\t") if dash else lines[i]
            if end == delim:
                break
            body.append(lines[i])
            i += 1
        found.append((resolve(m.group("target")), body, start))
        i += 1
    return found


def shell_files():
    return [f for f in tracked_files() if f.endswith(".sh")]


# ── 1. cron files Debian's cron accepts ───────────────────────────────────────

def cron_problems(lines):
    """Same rules as deploy.sh:_loxprox_cron_lint — the mistakes that make
    Debian's cron ignore the WHOLE file."""
    problems = []
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", s)
        if m:
            if m.group(2).strip() == "":
                problems.append(f"line {n}: bare {m.group(1)}= (cron reads it as a job and drops the file)")
            continue
        fields = s.split()
        if fields[0].startswith("@"):
            if len(fields) < 3:
                problems.append(f"line {n}: @keyword job without user/command")
            continue
        if len(fields) < 7:
            problems.append(f"line {n}: needs 5 time fields + user + command, has {len(fields)} fields")
            continue
        for i in range(5):
            spec = r"^[0-9*/,-]+$" if i < 3 else r"^[0-9A-Za-z*/,-]+$"
            if not re.match(spec, fields[i]):
                problems.append(f"line {n}: time field {i + 1} {fields[i]!r} is not a cron spec")
                break
    return problems


def cron_heredocs():
    """Every cron file any shipped script writes. tests/ is excluded: its
    fixtures are broken on purpose."""
    out = []
    for f in shell_files():
        if f.startswith("tests/"):
            continue
        for target, body, start in heredocs(f):
            if "/cron.d/" in target or target.endswith("/crontab"):
                out.append((f, target, body, start))
    return out


def test_cron_lint_rejects_the_shipped_bug():
    # The exact v1.3.0 → 2026-09 header, and the fixed one.
    broken = ["SHELL=/bin/bash", "PATH=/usr/bin:/bin", "MAILTO=", "",
              "*/15 * * * * root /opt/loxprox/progressive-ban.py"]
    assert any("bare MAILTO=" in p for p in cron_problems(broken))
    fixed = [line if line != "MAILTO=" else 'MAILTO=""' for line in broken]
    assert cron_problems(fixed) == []
    assert cron_problems(["0 2 * * root /x"]), "4 time fields must be rejected"
    assert cron_problems(["@daily root /x", "0 3 1 jan mon root /y"]) == []


def test_generated_cron_files_are_accepted_by_cron():
    found = cron_heredocs()
    targets = {t for _, t, _, _ in found}
    # Guard against a vacuous pass if the heredocs move or get renamed.
    assert {"/etc/cron.d/loxprox", "/etc/cron.d/loxprox-alert"} <= targets, targets
    bad = []
    for f, target, body, start in found:
        for p in cron_problems(body):
            bad.append(f"{f}:{start} ({target}) {p}")
    assert not bad, "cron heredoc(s) cron would reject:\n  " + "\n  ".join(bad)


def test_cron_mailto_is_quoted_empty():
    for _, target, body, _ in cron_heredocs():
        if target == "/etc/cron.d/loxprox":
            assert 'MAILTO=""' in body
            return
    raise AssertionError("/etc/cron.d/loxprox heredoc not found")


# ── 2. logrotate: every LoxProx log rotated exactly once ──────────────────────

def logrotate_stanzas(lines):
    """[[pattern, ...], ...] — one list of path patterns per `{ ... }` block."""
    stanzas, pending, depth = [], [], 0
    for raw in lines:
        line = raw.split("#", 1)[0].strip() if raw.strip().startswith("#") else raw.strip()
        if not line:
            continue
        if depth == 0:
            head, brace, _ = line.partition("{")
            pending.extend(head.split())
            if brace:
                stanzas.append(pending)
                pending, depth = [], 1
        elif line == "}":
            depth = 0
    assert not pending, f"dangling logrotate paths without a block: {pending}"
    return stanzas


def glob_rx(pattern):
    """logrotate uses glob(3): * and ? never cross a '/'."""
    out = []
    for ch in pattern:
        out.append({"*": "[^/]*", "?": "[^/]"}.get(ch, re.escape(ch)))
    return re.compile("^" + "".join(out) + "$")


# Debian 12 nginx-common's stock stanza, and what deploy.sh narrows it to.
STOCK_NGINX = ["/var/log/nginx/*.log"]
STOCK_NGINX_YIELDED = ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]


@lru_cache(maxsize=1)
def deploy_logrotate_stanzas():
    stanzas = []
    for target, body, _ in heredocs(DEPLOY):
        if target.startswith("/etc/logrotate.d/"):
            stanzas += [(target, s) for s in logrotate_stanzas(body)]
    return stanzas


def gateway_log_paths():
    """Every concrete /var/log/... .log path the gateway-side code names.
    tunnel-relay/ runs on a different host and ships no logrotate config."""
    rx = re.compile(r"/var/log/[A-Za-z0-9_./-]+?\.log\b")
    paths = set()
    for f in tracked_files():
        if f.startswith(("tunnel-relay/", "tests/")) or not f.endswith((".sh", ".py", ".service", ".timer")):
            continue
        paths.update(rx.findall(read(f)))
    return {p for p in paths if "*" not in p}


def collisions(stanza_sets, universe):
    out = []
    for path in sorted(universe):
        owners = [name for name, pats in stanza_sets if any(glob_rx(p).match(path) for p in pats)]
        if len(owners) > 1:
            out.append(f"{path} matched by {owners}")
    return out


def universe_for(stanza_sets):
    u = set(gateway_log_paths())
    for _, pats in stanza_sets:
        for p in pats:
            u.add(p.replace("*", "sample").replace("?", "x"))
    return u


def test_deploy_ships_the_expected_logrotate_stanzas():
    files = {t for t, _ in deploy_logrotate_stanzas()}
    assert {"/etc/logrotate.d/loxone-nginx", "/etc/logrotate.d/loxprox"} <= files, files
    pats = [p for _, s in deploy_logrotate_stanzas() for p in s]
    assert "/var/log/loxprox-*.log" in pats


def test_no_two_logrotate_stanzas_match_the_same_file():
    sets = [(f"{t}#{i}", s) for i, (t, s) in enumerate(deploy_logrotate_stanzas())]
    sets.append(("stock /etc/logrotate.d/nginx (after deploy.sh yield)", STOCK_NGINX_YIELDED))
    bad = collisions(sets, universe_for(sets))
    assert not bad, "logrotate would refuse duplicate entries:\n  " + "\n  ".join(bad)


def test_collision_check_detects_the_2026_08_30_case():
    # Negative control: the UNyielded stock glob collides with loxone-nginx —
    # the checker above must be able to see that, or it proves nothing.
    sets = [(f"{t}#{i}", s) for i, (t, s) in enumerate(deploy_logrotate_stanzas())]
    sets.append(("stock /etc/logrotate.d/nginx (unmodified)", STOCK_NGINX))
    bad = collisions(sets, universe_for(sets))
    assert any("appsec-detections.log" in b for b in bad), bad


def test_deploy_sh_yields_the_stock_nginx_glob_to_exactly_that_form():
    text = read(DEPLOY)
    assert "/var/log/nginx/access.log /var/log/nginx/error.log" in text
    assert re.search(r"/var/log/nginx/\\\*\\\.log", text), "yield must target the stock catch-all glob"


def test_every_gateway_log_is_rotated_exactly_once():
    sets = [(t, s) for t, s in deploy_logrotate_stanzas()]
    sets.append(("stock nginx (yielded)", STOCK_NGINX_YIELDED))
    unrotated, multi = [], []
    for path in sorted(gateway_log_paths()):
        if not (path.startswith("/var/log/loxprox-") or path.startswith("/var/log/nginx/")):
            continue  # system logs (auth.log, syslog, crowdsec, set-static-ip) are not ours to rotate
        n = sum(1 for _, pats in sets if any(glob_rx(p).match(path) for p in pats))
        if n == 0:
            unrotated.append(path)
        elif n > 1:
            multi.append(path)
    assert not unrotated, "never rotated: " + ", ".join(unrotated)
    assert not multi, "rotated by more than one stanza: " + ", ".join(multi)
    # The two the audit found growing unbounded must be in that set.
    assert {"/var/log/loxprox-monitor.log", "/var/log/loxprox-network-watchdog.log"} <= gateway_log_paths()


def test_loxprox_logrotate_uses_copytruncate():
    # loxprox-gui.log is held open by a long-running unit (StandardOutput=
    # append:) that never reopens it — only copytruncate rotates it correctly.
    for target, body, _ in heredocs(DEPLOY):
        if target == "/etc/logrotate.d/loxprox":
            text = "\n".join(body)
            for d in ("copytruncate", "missingok", "notifempty", "compress"):
                assert re.search(rf"^\s+{d}\s*$", text, re.MULTILINE), d
            assert not re.search(r"^\s+create\b", text, re.MULTILINE)
            return
    raise AssertionError("/etc/logrotate.d/loxprox heredoc not found")


# ── 3. persisted deploy source covers everything deploy.sh reads ─────────────

def deploy_array(name):
    m = re.search(rf"^{name}=\((.*?)^\)", read(DEPLOY), re.MULTILINE | re.DOTALL)
    assert m, f"{name} not found in deploy.sh"
    return [t for t in m.group(1).split() if not t.startswith("#")]


def test_deploy_source_manifest_covers_every_script_dir_read():
    files = deploy_array("_LOXPROX_DEPLOY_SOURCE_FILES")
    dirs = deploy_array("_LOXPROX_DEPLOY_SOURCE_DIRS")
    refs = set(re.findall(r"(?:\$\{SCRIPT_DIR:-\.\}|\$src_dir)/([A-Za-z0-9_./-]+)", read(DEPLOY)))
    refs.discard("VERSION")  # optional in the source; generated into the copy
    assert refs, "no SCRIPT_DIR-relative reads found — regex out of date?"
    uncovered = sorted(r for r in refs
                       if r not in files and not any(r == d or r.startswith(d + "/") for d in dirs))
    assert not uncovered, (
        "deploy.sh reads these relative to SCRIPT_DIR but install_deploy_source() "
        "does not persist them (add to _LOXPROX_DEPLOY_SOURCE_FILES/_DIRS): " + ", ".join(uncovered)
    )


def test_deploy_source_manifest_entries_exist():
    files = deploy_array("_LOXPROX_DEPLOY_SOURCE_FILES")
    dirs = deploy_array("_LOXPROX_DEPLOY_SOURCE_DIRS")
    tracked = set(tracked_files())
    assert all(f in tracked for f in files), [f for f in files if f not in tracked]
    assert all(any(t.startswith(d + "/") for t in tracked) for d in dirs), dirs


# ── 4. proxy-owned security headers are never duplicated ──────────────────────

def test_every_added_security_header_is_hidden_from_upstream():
    text = read(DEPLOY)
    added = set(re.findall(r"^\s*add_header\s+([A-Za-z-]+)", text, re.MULTILINE))
    # The TLS block is emitted by awk printf, not a heredoc.
    added |= set(re.findall(r'add_header\s+([A-Za-z-]+)\s+\\"', text))
    hidden = set(re.findall(r"^\s*proxy_hide_header\s+([A-Za-z-]+);", text, re.MULTILINE))
    assert {"X-Frame-Options", "Strict-Transport-Security"} <= added, added
    missing = sorted(added - hidden)
    assert not missing, f"added by nginx but not hidden from the Miniserver's response: {missing}"
    assert "X-XSS-Protection" in hidden
    assert not re.search(r"^\s*add_header\s+X-XSS-Protection", text, re.MULTILINE)


def test_site_template_version_bumped_for_the_header_change():
    m = re.search(r"^_LOXPROX_SITE_TEMPLATE_VERSION=(\d+)$", read(DEPLOY), re.MULTILINE)
    assert m and int(m.group(1)) >= 4, "template changed: bump _LOXPROX_SITE_TEMPLATE_VERSION"


# ── 5. AppArmor nginx profile: enforce-ready, still contained ────────────────

PROFILE = "apparmor/usr.sbin.nginx"


def profile_rules():
    return [line.strip() for line in read(PROFILE).splitlines()
            if line.strip() and not line.strip().startswith("#")]


def test_apparmor_profile_covers_the_soak_findings():
    rules = profile_rules()
    for rule in ("/usr/share/lua/** r,",
                 "/usr/share/perl/** r,",
                 "/sys/devices/system/node/ r,",
                 "/sys/devices/system/node/node[0-9]*/meminfo r,",
                 "/run/nginx.pid.oldbin rw,",
                 "/usr/sbin/nginx mrix,"):
        assert rule in rules, f"missing: {rule}"


def test_apparmor_profile_containment_kept():
    # File rules only ("/path perms,"); capability/network/signal rules carry
    # words like "raw" that would look like permission strings.
    files = [r for r in profile_rules() if r.startswith("/")]
    perms = {r: r.rsplit(None, 1)[-1].rstrip(",") for r in files}
    exec_rules = [r for r, p in perms.items() if "x" in p]
    assert exec_rules == ["/usr/sbin/nginx mrix,"], f"unexpected exec permission(s): {exec_rules}"
    assert perms["/usr/sbin/nginx mrix,"] == "mrix", "self re-exec must be ix (inherit), never px/ux"
    assert not [r for r in files if r.startswith("/opt/loxprox")], "nginx must not touch /opt/loxprox"
    etc_loxprox = [r for r in files if r.startswith("/etc/loxprox")]
    assert etc_loxprox and all(r.startswith("/etc/loxprox/tls/") and perms[r] == "r" for r in etc_loxprox), etc_loxprox
    writes = [r for r, p in perms.items() if "w" in p or "a" in p]
    assert all(r.startswith(("/var/log/nginx/", "/run/nginx.pid", "/var/lib/nginx/")) for r in writes), writes


def test_apparmor_mode_stays_deploy_controlled_complain_default():
    # The repo profile carries no mode flag; deploy.sh decides, default complain,
    # enforce only behind APPARMOR_NGINX_MODE="enforce" (docs/adr/0006).
    assert "flags=" not in read(PROFILE)
    text = read(DEPLOY)
    assert 'local aa_mode="${APPARMOR_NGINX_MODE:-complain}"' in text
    assert re.search(r'if \[\[ "\$aa_mode" == "enforce" \]\]; then\s+aa-enforce', text)


# ── 6. journald cap + audit coverage are wired in ─────────────────────────────

def test_journald_cap_and_audit_watches_wired():
    text = read(DEPLOY)
    assert 'JOURNALD_SYSTEM_MAX_USE="${JOURNALD_SYSTEM_MAX_USE:-300M}"' in text
    assert re.search(r'^\s*run_optional_step "journald size cap"\s+setup_journald$', text, re.MULTILINE)
    audit = next(body for target, body, _ in heredocs(DEPLOY) if target.endswith("99-gateway.rules"))
    rules = {tuple(line.split()) for line in audit if line.startswith("-w ")}
    for path, key in (("/etc/loxprox/", "loxprox_config"),
                      ("/etc/apparmor.d/", "apparmor_config"),
                      ("/opt/loxprox/", "loxprox_scripts")):
        assert ("-w", path, "-p", "wa", "-k", key) in rules, (path, key)
