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
    ("vendor/three.module.min.js", True),
    ("fonts/inter-var.woff2", True),
    ("../loxprox-gui.py", False),          # traversal out of the asset dir
    ("vendor/../../loxprox-gui.py", False),
    ("panel.html/../../loxprox-gui.py", False),
    ("evil.py", False),                    # extension not allowlisted
    ("panel", False),
])
def test_safe_static_path_containment(tmp_path, rel, ok):
    base = tmp_path / "static"
    for p in ("panel.html", "panel.css", "vendor/three.module.min.js",
              "fonts/inter-var.woff2", "evil.py", "panel"):
        f = base / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x")
    (tmp_path / "loxprox-gui.py").write_text("x")
    resolved = gui.safe_static_path(rel, base_dir=str(base))
    if ok:
        assert resolved is not None and resolved.startswith(str(base))
    else:
        assert resolved is None


def test_repo_static_dir_ships_all_referenced_assets():
    # panel.html/panel.css/panel.js reference each other and the vendored
    # files by absolute /static/ URL — every referenced file must exist.
    import re
    static = os.path.join(os.path.dirname(_GUI_PATH), "static")
    refs = set()
    for name in ("panel.html", "panel.css", "panel.js"):
        with open(os.path.join(static, name), encoding="utf-8") as fh:
            refs.update(re.findall(r"/static/([A-Za-z0-9_./-]+)", fh.read()))
    assert refs, "no /static/ references found — parsing broke?"
    missing = [r for r in sorted(refs)
               if not os.path.isfile(os.path.join(static, r))]
    assert not missing, f"referenced but not shipped: {missing}"


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
