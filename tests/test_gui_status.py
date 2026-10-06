"""Panel status data — 2026-10 fixes.

* Ban table: `cscli decisions list -o json` returns ALERTS with nested
  decisions (masked live sample from CrowdSec 1.8.1 in tests/fixtures/).
  The panel read value/origin/duration at the top level: every row showed
  "?" (unban could not work) and the count counted alerts.
* GeoIP freshness: geoip-block.sh stamps success/failure; the panel turns a
  stale list into a "what to do" item.
"""

import importlib.util
import json
import os
import sys
import time

import pytest

_GUI_PATH = os.path.join(os.path.dirname(__file__), "..", "gui", "loxprox-gui.py")
_spec = importlib.util.spec_from_file_location("loxprox_gui_status", _GUI_PATH)
gui = importlib.util.module_from_spec(_spec)
sys.modules["loxprox_gui_status"] = gui
_spec.loader.exec_module(gui)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "cscli-decisions-list-1.8.1.json")
ITEM_KEYS = {"ip", "origin", "scenario", "duration"}     # front-end contract


def fixture_text():
    with open(FIXTURE, encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------- ban table

def test_active_decisions_flattens_alerts_and_dedupes_by_value():
    data = json.loads(fixture_text())
    assert len(data) == 9 and all("value" not in a for a in data)     # alerts, not decisions
    decs = gui.active_decisions(data)
    values = [d["value"] for d in decs]
    assert len(decs) == 8 and len(set(values)) == 8
    assert all(v.startswith("203.0.113.") for v in values)
    first = decs[0]
    assert first["origin"] == "crowdsec" and first["type"] == "ban" and first["scope"] == "Ip"
    assert first["scenario"].startswith("crowdsecurity/")
    assert first["country"] and len(first["country"]) == 2      # source.cn kept


def test_crowdsec_decisions_rows_are_real_and_keep_the_contract(monkeypatch):
    monkeypatch.setattr(gui, "run", lambda cmd, timeout=10: (0, fixture_text()))
    out = gui.crowdsec_decisions()
    assert out["count"] == 8
    assert len(out["items"]) == 8
    for item in out["items"]:
        assert set(item) == ITEM_KEYS
        assert "?" not in item.values(), item             # was "?" for ip/origin/duration
        assert gui.valid_ip(item["ip"])                   # what /api/unban will accept
        assert not item["scenario"].startswith("crowdsecurity/")


def test_control_old_reader_produced_question_marks():
    """The pre-fix row builder on the real shape: unusable rows, alerts counted."""
    data = json.loads(fixture_text())
    rows = [{"ip": d.get("value", "?"), "origin": d.get("origin", "?")} for d in data[:10]]
    assert {r["ip"] for r in rows} == {"?"} and len(data) == 9


def test_same_address_in_two_alerts_is_one_row():
    alert = lambda aid, dec_id, dur: {"id": aid, "scenario": "crowdsecurity/x", "source": {"cn": "DE"},
                                      "decisions": [{"id": dec_id, "value": "203.0.113.7", "origin": "crowdsec",
                                                     "type": "ban", "scope": "Ip", "duration": dur}]}
    decs = gui.active_decisions([alert(2, 20, "3h"), alert(1, 10, "1h")])
    assert len(decs) == 1 and decs[0]["id"] == 20 and decs[0]["duration"] == "3h"


def test_flat_list_null_and_simulated():
    flat = [{"id": 1, "value": "203.0.113.1", "origin": "cscli", "type": "ban", "duration": "4h",
             "scenario": "manual"},
            {"id": 2, "value": "203.0.113.2", "origin": "crowdsec", "simulated": True}]
    decs = gui.active_decisions(flat)
    assert [d["value"] for d in decs] == ["203.0.113.1"]
    assert gui.active_decisions(None) == [] and gui.active_decisions([]) == []
    assert gui.active_decisions([{"source": {"ip": "203.0.113.3"}, "decisions": None}]) == []


def test_crowdsec_decisions_empty_and_errors(monkeypatch):
    monkeypatch.setattr(gui, "run", lambda cmd, timeout=10: (0, "null"))
    assert gui.crowdsec_decisions() == {"count": 0, "items": []}
    monkeypatch.setattr(gui, "run", lambda cmd, timeout=10: (1, "LAPI down"))
    assert gui.crowdsec_decisions()["error"] == "LAPI down"


def test_history_bans_counts_decisions_not_alerts(monkeypatch, tmp_path):
    monkeypatch.setattr(gui, "run", lambda cmd, timeout=10: (0, fixture_text()))
    monkeypatch.setattr(gui, "miniserver_reachable", lambda conf: True)
    monkeypatch.setattr(gui, "DEPLOY_CONF", str(tmp_path / "missing.conf"))

    class Zero:
        def delta(self):
            return 0
    point = gui.history_sample({"req": Zero(), "sec": Zero()})
    assert point["bans"] == 8
    assert set(point) >= {"t", "load", "mem", "disk", "bans", "req", "sec", "ms"}   # format unchanged


# ------------------------------------------------------------ GeoIP freshness

@pytest.fixture
def geoip(tmp_path, monkeypatch):
    d = tmp_path / "geoip"
    d.mkdir()
    script = tmp_path / "geoip-block.sh"
    script.write_text("#!/bin/bash\n")
    nft = tmp_path / "99-geoip.conf"
    monkeypatch.setattr(gui, "GEOIP_DIR", str(d))
    monkeypatch.setattr(gui, "GEOIP_SCRIPT", str(script))
    monkeypatch.setattr(gui, "GEOIP_NFT_FILE", str(nft))
    monkeypatch.setattr(gui, "GEOIP_STALE_DAYS", 3)
    return d, nft, script


def test_geoip_fresh(geoip):
    d, _, _ = geoip
    now = 1_800_000_000
    (d / "last-success").write_text(f"{now - 3600} 22249\n")
    st = gui.geoip_status(now=now)
    assert st == {"enabled": True, "last_ok": now - 3600, "age_hours": 1.0, "ranges": 22249,
                  "stale": False, "stale_days": 3, "last_error": None}


def test_geoip_stale_with_newer_failure(geoip):
    d, _, _ = geoip
    now = 1_800_000_000
    (d / "last-success").write_text(f"{now - 4 * 86400} 22249\n")
    (d / "last-failure").write_text(f"{now - 3600} cn: curl exit 28, HTTP 000: Operation timed out\n")
    st = gui.geoip_status(now=now)
    assert st["stale"] is True and st["age_hours"] == 96.0
    assert st["last_error"].startswith("cn: curl exit 28")


def test_geoip_failure_older_than_success_is_not_reported(geoip):
    d, _, _ = geoip
    now = 1_800_000_000
    (d / "last-success").write_text(f"{now - 60} 100\n")
    (d / "last-failure").write_text(f"{now - 86400} old failure\n")
    assert gui.geoip_status(now=now)["last_error"] is None


def test_geoip_pre_stamp_install_uses_the_nft_file(geoip):
    _, nft, _ = geoip
    nft.write_text("# LoxProx — GeoIP blocklist\n# Generated: 2026-10-01T03:00:01+02:00\nset geoip_blocklist {\n")
    mtime = 1_800_000_000 - 5 * 86400
    os.utime(nft, (mtime, mtime))
    st = gui.geoip_status(now=1_800_000_000)
    assert st["last_ok"] == mtime and st["stale"] is True and st["ranges"] is None


def test_geoip_placeholder_only_means_never_loaded(geoip):
    _, nft, _ = geoip
    nft.write_text("# Placeholder — overwritten by geoip-block.sh on first run\nset geoip_blocklist {\n}\n")
    st = gui.geoip_status(now=time.time())
    assert st["last_ok"] is None and st["stale"] is True


def test_geoip_disabled_or_not_installed(geoip):
    d, _, script = geoip
    (d / "disabled").touch()
    assert gui.geoip_status() == {"enabled": False}
    (d / "disabled").unlink()
    script.unlink()
    assert gui.geoip_status() == {"enabled": False}


def test_status_carries_geoip():
    assert '"geoip": geoip_status()' in open(_GUI_PATH, encoding="utf-8").read()


def test_front_end_surfaces_a_stale_geoip_list():
    static = os.path.join(os.path.dirname(_GUI_PATH), "static")
    js = open(os.path.join(static, "panel.js"), encoding="utf-8").read()
    i18n = open(os.path.join(static, "i18n.js"), encoding="utf-8").read()
    assert 'id: "geoip"' in js and "g.stale" in js
    for key in ("att_geoip_stale_title_one", "att_geoip_stale_title_other", "att_geoip_never_title",
                "att_geoip_kept", "att_geoip_kept_n", "att_geoip_error", "att_geoip_hint"):
        assert i18n.count(f"        {key}:") == 2, key          # DE + EN
