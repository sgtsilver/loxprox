"""Unit tests for gui/loxprox-gui.py pure logic (no root, no network, no subprocess)."""

import importlib.util
import json
import os
import sys

import pytest

_GUI_PATH = os.path.join(os.path.dirname(__file__), "..", "gui", "loxprox-gui.py")
_spec = importlib.util.spec_from_file_location("loxprox_gui", _GUI_PATH)
gui = importlib.util.module_from_spec(_spec)
sys.modules["loxprox_gui"] = gui
_spec.loader.exec_module(gui)


# ---------------------------------------------------------------- conf parse

SAMPLE_CONF = '''
# comment
LOXONE_IP="192.168.1.100"
LOXONE_PORT="80"
ENABLE_TLS="true"
TLS_DOMAIN="gw.example.org"
ENABLE_TUNNEL="false"
TUNNEL_PUBLIC_HOST=""
SSH_ALLOWED_SUBNETS=("192.168.1.0/24" "10.0.0.0/24")
GUI_PASSWORD="s3cret"
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/x"
'''


def test_parse_shell_conf_basic():
    conf = gui.parse_shell_conf(SAMPLE_CONF)
    assert conf["LOXONE_IP"] == "192.168.1.100"
    assert conf["ENABLE_TLS"] == "true"
    assert conf["TUNNEL_PUBLIC_HOST"] == ""
    assert conf["SSH_ALLOWED_SUBNETS"].startswith("(")


def test_parse_shell_conf_ignores_comments_and_garbage():
    conf = gui.parse_shell_conf("# X=1\n  \nnot a line\nA_B="  '"v"\n')
    assert conf == {"A_B": "v"}


def test_is_true_variants():
    for val in ("true", "TRUE", "yes", "1"):
        assert gui.is_true(val)
    for val in ("false", "no", "0", "", None):
        assert not gui.is_true(val)


def test_mask_secrets_masks_only_set_values():
    conf = gui.parse_shell_conf(SAMPLE_CONF)
    masked = gui.mask_secrets(conf)
    assert masked["GUI_PASSWORD"] == "•••"
    assert masked["DISCORD_WEBHOOK_URL"] == "•••"
    assert masked["LOXONE_IP"] == "192.168.1.100"
    empty = gui.mask_secrets({"GUI_PASSWORD": ""})
    assert empty["GUI_PASSWORD"] == ""


# ------------------------------------------------------------- host derivation

def test_derive_host_tunnel_wins_over_tls():
    conf = {"ENABLE_TUNNEL": "true", "TUNNEL_PUBLIC_HOST": "relay.example.org",
            "ENABLE_TLS": "true", "TLS_DOMAIN": "gw.example.org"}
    assert gui.derive_host(conf, {}) == ("relay.example.org", "tunnel")


def test_derive_host_tls_appends_1080():
    conf = {"ENABLE_TUNNEL": "false", "ENABLE_TLS": "true", "TLS_DOMAIN": "gw.example.org"}
    assert gui.derive_host(conf, {}) == ("gw.example.org:1080", "tls")


def test_derive_host_manual_fallback_and_unset():
    conf = {"ENABLE_TUNNEL": "false", "ENABLE_TLS": "false"}
    assert gui.derive_host(conf, {"manual_host": "me.dyndns.org:1080"}) == \
        ("me.dyndns.org:1080", "manual")
    assert gui.derive_host(conf, {}) == ("", "unset")


# ---------------------------------------------------------------- validators

@pytest.mark.parametrize("value,ok", [
    ("192.168.1.1", True), ("2a01:db8::1", True),
    ("999.1.1.1", False), ("evil; rm -rf /", False), ("", False),
])
def test_valid_ip(value, ok):
    assert gui.valid_ip(value) is ok


@pytest.mark.parametrize("value,ok", [
    ("gw.example.org", True), ("gw.example.org:1080", True),
    ("192.168.1.5", True), ("host_bad", False), ("a:99999", False),
    ("host:0", False), ("-lead.example", False), ("", False),
])
def test_valid_host(value, ok):
    assert gui.valid_host(value) is ok


def test_validate_changes_accepts_good_and_rejects_bad():
    clean, errors = gui.validate_changes({
        "LOXONE_IP": "192.168.1.101",
        "RATE_LIMIT_REQ_PER_SEC": "20",
        "ENABLE_APPSEC": "false",
        "APPSEC_MODE": "monitor",
        "AUTOREBOOT_TIME": "04:30",
        "CROWDSEC_WHITELIST_IPS": "192.168.1.0/24, 10.0.0.5",
    })
    assert errors == {}
    assert clean["CROWDSEC_WHITELIST_IPS"] == ["192.168.1.0/24", "10.0.0.5"]

    clean, errors = gui.validate_changes({
        "LOXONE_IP": "not-an-ip",
        "GATEWAY_IP": "192.168.1.50",       # excluded key
        "APPSEC_MODE": "aggressive",
        "AUTOREBOOT_TIME": "25:00",
        "TUNNEL_TOKEN": 'has"quote',
    })
    assert set(errors) == {"LOXONE_IP", "GATEWAY_IP", "APPSEC_MODE",
                           "AUTOREBOOT_TIME", "TUNNEL_TOKEN"}
    assert clean == {}


def test_validate_changes_lockout_keys_never_editable():
    for key in ("GATEWAY_IP", "LAN_SUBNET", "SSH_ALLOWED_SUBNETS"):
        _, errors = gui.validate_changes({key: "192.168.1.0/24"})
        assert errors[key] == "not editable"


# -------------------------------------------------------------- conf rewrite

def test_update_conf_text_replaces_in_place_and_appends():
    text = 'LOXONE_IP="1.2.3.4"\n# keep me\nENABLE_TLS="false"\n'
    out = gui.update_conf_text(text, {"LOXONE_IP": "5.6.7.8", "GUI_PORT": "1082"})
    assert 'LOXONE_IP="5.6.7.8"' in out
    assert "# keep me" in out
    assert 'ENABLE_TLS="false"' in out
    assert out.rstrip().endswith('GUI_PORT="1082"')


def test_update_conf_text_array_formatting():
    out = gui.update_conf_text("", {"CROWDSEC_WHITELIST_IPS": ["10.0.0.1", "10.0.0.0/24"]})
    assert 'CROWDSEC_WHITELIST_IPS=("10.0.0.1" "10.0.0.0/24")' in out


def test_update_conf_text_roundtrip_parses_back():
    out = gui.update_conf_text("", {"LOXONE_IP": "9.9.9.9", "TLS_DOMAIN": "x.example"})
    conf = gui.parse_shell_conf(out)
    assert conf["LOXONE_IP"] == "9.9.9.9"
    assert conf["TLS_DOMAIN"] == "x.example"


def test_validate_changes_cidr_array_accepts_raw_bash_form():
    # The config editor round-trips the raw KEY=("a" "b") value from
    # parse_shell_conf; the validator must accept it unchanged.
    clean, errors = gui.validate_changes(
        {"CROWDSEC_WHITELIST_IPS": '("192.168.1.0/24" "10.0.0.5")'})
    assert errors == {}
    assert clean["CROWDSEC_WHITELIST_IPS"] == ["192.168.1.0/24", "10.0.0.5"]
    clean, errors = gui.validate_changes({"CROWDSEC_WHITELIST_IPS": "()"})
    assert errors == {}
    assert clean["CROWDSEC_WHITELIST_IPS"] == []


# ------------------------------------------------------------- static assets

@pytest.mark.parametrize("rel,ok", [
    ("panel.html", True),
    ("panel.css", True),
    ("panel.js", True),
    ("favicon.svg", True),
    ("fonts/inter-var.woff2", True),
    ("../loxprox-gui.py", False),          # traversal out of the asset dir
    ("fonts/../../loxprox-gui.py", False),
    ("panel.html/../../loxprox-gui.py", False),
    ("evil.py", False),                    # extension not allowlisted
    ("data.json", False),
    ("panel", False),
])
def test_safe_static_path_containment(tmp_path, rel, ok):
    base = tmp_path / "static"
    for p in ("panel.html", "panel.css", "panel.js", "favicon.svg",
              "fonts/inter-var.woff2", "evil.py", "data.json", "panel"):
        f = base / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x")
    (tmp_path / "loxprox-gui.py").write_text("x")
    resolved = gui.safe_static_path(rel, base_dir=str(base))
    if ok:
        assert resolved is not None and resolved.startswith(str(base))
    else:
        assert resolved is None


STATIC = os.path.join(os.path.dirname(_GUI_PATH), "static")


def _static_text_files():
    out = {}
    for name in sorted(os.listdir(STATIC)):
        if os.path.splitext(name)[1] in (".html", ".css", ".js", ".svg"):
            with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
                out[name] = fh.read()
    assert "panel.html" in out and "panel.js" in out, "front-end files missing"
    return out


def test_repo_static_dir_ships_all_referenced_assets():
    # The front-end and the server-rendered invite page reference assets by
    # absolute /static/ URL (including ES module imports) — every one must
    # exist, or the panel renders blank.
    import re
    refs = set()
    sources = dict(_static_text_files())
    sources["INVITE_HTML"] = gui.INVITE_HTML
    for text in sources.values():
        refs.update(re.findall(r"/static/([A-Za-z0-9_./-]+)", text))
    assert {"panel.css", "panel.js", "i18n.js", "charts.js"} <= refs
    missing = [r for r in sorted(refs) if not os.path.isfile(os.path.join(STATIC, r))]
    assert not missing, f"referenced but not shipped: {missing}"


def test_static_ships_only_allowlisted_types():
    # Everything in gui/static/ must be servable; anything else is dead weight
    # or a sign that the extension allowlist is being bypassed.
    for root, _, files in os.walk(STATIC):
        for name in files:
            assert os.path.splitext(name)[1] in gui.STATIC_TYPES, \
                f"{os.path.relpath(os.path.join(root, name), STATIC)} is not servable"


def test_no_third_party_scene_or_motion_libraries():
    # The calm-console redesign removed the vendored three.js / anime.js.
    # They must not come back (850+ KB, and the panel no longer needs them).
    assert not os.path.exists(os.path.join(STATIC, "vendor")), "gui/static/vendor/ is back"
    for name, text in _static_text_files().items():
        lowered = text.lower()
        for lib in ("three.module", "three.core", "anime.esm", "/vendor/"):
            assert lib not in lowered, f"{name} references {lib}"


def test_static_makes_no_external_requests():
    # Offline-LAN guarantee: no absolute URL may appear in any front-end file
    # (the SVG XML namespace is an identifier, not a request).
    import re
    sources = dict(_static_text_files())
    sources["INVITE_HTML"] = gui.INVITE_HTML
    for name, text in sources.items():
        text = text.replace("http://www.w3.org/2000/svg", "")
        hits = re.findall(r"(?:https?:)?//[A-Za-z0-9-]+\.[A-Za-z0-9.-]+", text)
        assert not hits, f"{name} references external URLs: {hits}"


def _html_violations(markup):
    from html.parser import HTMLParser

    class Scan(HTMLParser):
        def __init__(self):
            super().__init__()
            self.problems = []
            self.in_script = False

        def handle_starttag(self, tag, attrs):
            names = [a for a, _ in attrs]
            if tag == "style":
                self.problems.append("<style> block")
            if tag == "script":
                self.in_script = True
                if "src" not in names:
                    self.problems.append("inline <script>")
            for a in names:
                if a == "style":
                    self.problems.append(f"style= on <{tag}>")
                if a.startswith("on"):
                    self.problems.append(f"{a}= handler on <{tag}>")

        def handle_endtag(self, tag):
            if tag == "script":
                self.in_script = False

        def handle_data(self, data):
            if self.in_script and data.strip():
                self.problems.append("script body")

    scan = Scan()
    scan.feed(markup)
    return scan.problems


def test_markup_complies_with_csp_without_inline_code():
    # CSP is script-src 'self': no inline script, no on*= handlers. The panel
    # also uses no inline styles, so style-src could be tightened later.
    with open(os.path.join(STATIC, "panel.html"), encoding="utf-8") as fh:
        assert _html_violations(fh.read()) == []
    assert _html_violations(gui.INVITE_HTML) == []


def test_js_avoids_html_sinks_and_dynamic_code():
    # DOM is built with createElement/textContent only: API data (IPs,
    # scenarios, log lines, cscli errors) can never become markup or code.
    for name, text in _static_text_files().items():
        if not name.endswith(".js"):
            continue
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                     "eval(", "new Function", 'setAttribute("style"', 'style="'):
            assert sink not in text, f"{name} uses {sink}"


def test_front_end_has_no_emoji():
    # House rule: icons are inline SVG only, never Unicode emoji.
    import re
    emoji = re.compile("[\U0001F000-\U0001FAFF☀-➿⬀-⯿️]")
    sources = dict(_static_text_files())
    sources["INVITE_HTML"] = gui.INVITE_HTML
    for name, text in sources.items():
        found = emoji.findall(text)
        assert not found, f"{name} contains emoji: {found}"


def test_i18n_german_and_english_have_the_same_keys():
    import re
    with open(os.path.join(STATIC, "i18n.js"), encoding="utf-8") as fh:
        text = fh.read()
    de_block = text[text.index("    de: {"):text.index("    en: {")]
    en_block = text[text.index("    en: {"):]
    key_rx = re.compile(r"^ {8}([A-Za-z0-9_]+):", re.MULTILINE)
    de_keys, en_keys = key_rx.findall(de_block), key_rx.findall(en_block)
    assert len(de_keys) > 300, "i18n parse broke?"
    assert len(de_keys) == len(set(de_keys)), "duplicate German key"
    assert len(en_keys) == len(set(en_keys)), "duplicate English key"
    assert set(de_keys) == set(en_keys), \
        f"only DE: {sorted(set(de_keys) - set(en_keys))}, only EN: {sorted(set(en_keys) - set(de_keys))}"
    # German stays the default language of the panel.
    with open(os.path.join(STATIC, "panel.js"), encoding="utf-8") as fh:
        assert '=== "en" ? "en" : "de"' in fh.read()


def test_front_end_sends_csrf_and_auth_headers():
    with open(os.path.join(STATIC, "panel.js"), encoding="utf-8") as fh:
        text = fh.read()
    assert 'headers["X-LoxProx-Gui"] = "1"' in text
    assert 'headers["X-LoxProx-Auth"]' in text
    assert "res.status !== 401" in text   # 401 → password prompt + retry


def test_front_end_config_editor_covers_every_editable_key():
    # The typed editor groups keys by name; a key added to EDITABLE_KEYS
    # still renders (under "Other"), but it should get a label in both
    # languages and a group.
    with open(os.path.join(STATIC, "panel.js"), encoding="utf-8") as fh:
        js = fh.read()
    with open(os.path.join(STATIC, "i18n.js"), encoding="utf-8") as fh:
        i18n = fh.read()
    import re

    def defined(key):     # whole-key match: "h_ip" must not count "dec_th_ip"
        return len(re.findall(rf"^ {{8}}{re.escape(key)}:", i18n, re.MULTILINE))

    for key, kind in gui.EDITABLE_KEYS.items():
        assert f'"{key}"' in js, f"{key} is not placed in a config group"
        assert defined(f"f_{key}") == 2, f"{key} lacks a DE/EN label"
        if kind != "bool":
            assert defined(f"h_{kind}") == 2, f"no DE/EN hint for kind {kind}"


# ------------------------------------------------------------- server output

def test_csp_forbids_inline_scripts_and_foreign_origins():
    directives = dict(d.strip().split(" ", 1) for d in gui.CSP.split(";"))
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"
    assert directives["connect-src"] == "'self'"
    assert directives["font-src"] == "'self'"
    assert directives["base-uri"] == "'none'"
    assert directives["form-action"] == "'none'"


def test_static_max_age_fonts_long_app_files_short():
    assert gui.static_max_age("fonts/inter-var.woff2") == 86400
    assert gui.static_max_age("panel.js") == 300
    assert gui.static_max_age("panel.html") == 300


@pytest.fixture
def no_conf(monkeypatch):
    monkeypatch.setattr(gui, "load_conf", lambda path: {})
    monkeypatch.setattr(gui, "load_settings", lambda: {})


@pytest.mark.parametrize("lang", ["de", "en"])
def test_invite_page_language_and_markup(no_conf, monkeypatch, lang):
    monkeypatch.setattr(gui, "qr_svg", lambda payload: "<svg><rect/></svg>")
    page = gui.render_invite({"lang": lang, "host": "gw.example.org:1080"})
    assert f'<html lang="{lang}">' in page
    assert "<svg><rect/></svg>" in page
    assert "role='img'" in page and "loxone://ms?host=gw.example.org:1080" in page
    assert "<a" in page and "<button" in page
    import re
    assert not re.search(r"<a [^>]*>\s*<button", page), "button nested in a link"
    assert "aria-current='true'" in page
    assert "&amp;host=gw.example.org:1080" in page   # language switch keeps the host


def test_invite_page_escapes_host_and_reports_missing_qr(no_conf, monkeypatch):
    monkeypatch.setattr(gui, "qr_svg", lambda payload: None)   # qrencode missing
    page = gui.render_invite({"lang": "en", "host": "gw.example.org"})
    assert "could not be generated" in page
    assert "No public host configured" not in page
    page = gui.render_invite({"lang": "en", "host": "<script>x</script>"})
    assert "<script>x" not in page
    assert "No public host configured" in page


# ----------------------------------------------------------------- history

def test_log_growth_counter_counts_and_handles_rotation(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("one\ntwo\n")
    counter = gui.LogGrowthCounter(str(log))
    assert counter.delta() == 0          # first call only anchors the offset
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("three\nfour\nfive\n")
    assert counter.delta() == 3
    assert counter.delta() == 0          # nothing new
    log.write_text("rotated\n")          # shrunk file = rotation
    assert counter.delta() == 0          # re-anchors silently
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("six\n")
    assert counter.delta() == 1


def test_log_growth_counter_missing_file(tmp_path):
    counter = gui.LogGrowthCounter(str(tmp_path / "nope.log"))
    assert counter.delta() == 0


def test_history_load_prunes_old_and_garbage(tmp_path):
    now = 1_800_000_000
    fresh = {"t": now - 60, "req": 5}
    stale = {"t": now - gui.HISTORY_MAX * gui.HISTORY_INTERVAL - 10, "req": 1}
    path = tmp_path / "hist.json"
    path.write_text(json.dumps([stale, fresh, "garbage", {"no_t": 1}]))
    hist = gui.History()
    hist.load(str(path), now=now)
    assert hist.snapshot() == [fresh]


def test_history_save_roundtrip(tmp_path):
    hist = gui.History()
    hist.append({"t": 1, "req": 2})
    path = tmp_path / "sub" / "hist.json"
    hist.save(str(path))
    again = gui.History()
    again.load(str(path), now=2)
    assert again.snapshot() == [{"t": 1, "req": 2}]


def test_history_ring_caps_at_maxlen():
    hist = gui.History(maxlen=3)
    for i in range(5):
        hist.append({"t": i})
    assert [p["t"] for p in hist.snapshot()] == [2, 3, 4]
