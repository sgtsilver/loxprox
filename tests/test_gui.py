"""Unit tests for gui/loxprox-gui.py pure logic (no root, no network, no subprocess)."""

import importlib.util
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
