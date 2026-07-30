#!/usr/bin/env python3
"""
Unit tests for progressive-ban.py

Run with: pytest tests/test_progressive_ban.py -v
Or: python -m pytest tests/test_progressive_ban.py -v
"""

import importlib.util
import ipaddress
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import pytest

# Load progressive-ban.py (hyphenated filename cannot be imported directly)
_PB_PATH = Path(__file__).parent.parent / "progressive-ban.py"
_spec = importlib.util.spec_from_file_location("progressive_ban", _PB_PATH)
_pb_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pb_module)
pb = _pb_module


class FakeCompletedProcess:
    """Mock for subprocess.CompletedProcess."""
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _alert(scenario="crowdsecurity/http-probing", when=None, origin="crowdsec"):
    """A realistic `cscli alerts list` entry: attack-origin decision + timestamp."""
    if when is None:
        when = datetime.now(timezone.utc)
    return {
        "scenario": scenario,
        "created_at": when.isoformat(),
        "decisions": [{"origin": origin}],
    }


class TestRunCscli:
    def test_run_cscli_success(self):
        data = [{"value": "1.2.3.4", "id": "1"}]
        with patch.object(pb.subprocess, "run", return_value=FakeCompletedProcess(stdout=json.dumps(data))) as mock_run:
            result = pb.run_cscli(["decisions", "list"])
            assert result == data
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            assert kwargs["timeout"] == pb.CSCLI_TIMEOUT
            assert kwargs["capture_output"] is True

    def test_run_cscli_timeout(self):
        with patch.object(
            pb.subprocess, "run",
            side_effect=subprocess.TimeoutExpired(cmd="cscli", timeout=30),
        ) as mock_run:
            result = pb.run_cscli(["decisions", "list"])
            assert result is None

    def test_run_cscli_nonzero_rc(self):
        with patch.object(
            pb.subprocess, "run",
            return_value=FakeCompletedProcess(returncode=1, stderr="some error"),
        ):
            result = pb.run_cscli(["decisions", "list"])
            assert result is None

    def test_run_cscli_invalid_json(self):
        with patch.object(
            pb.subprocess, "run",
            return_value=FakeCompletedProcess(stdout="not json"),
        ):
            result = pb.run_cscli(["decisions", "list"])
            assert result is None

    def test_run_cscli_null_response_returns_empty_list(self):
        # cscli emits `null` (not `[]`) when no decisions exist — Go nil-slice
        # JSON. Confirm we normalise so main() doesn't exit(1) on a clean VM.
        with patch.object(
            pb.subprocess, "run",
            return_value=FakeCompletedProcess(stdout="null\n"),
        ):
            assert pb.run_cscli(["decisions", "list"]) == []


class TestCountOffenses:
    """H1: offenses come from `cscli alerts list --ip` (durable history), because
    scenario bans are origin 'crowdsec' (not 'cscli') and `decisions list` only ever
    returns active decisions — the old counter never reached 2 and never escalated."""

    def test_counts_alerts(self):
        # These entries carry neither a decisions array nor a timestamp, so
        # is_attack_alert's scenario-fallback finds nothing and parse_timestamp
        # returns None for every one of them — all three are dropped and the
        # count floors at 1, same as an empty/error response.
        alerts = [{"a": 1}, {"a": 2}, {"a": 3}]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.count_offenses("1.2.3.4") == 1

    def test_empty_alerts_floors_at_one(self):
        with patch.object(pb, "run_cscli", return_value=[]):
            assert pb.count_offenses("1.2.3.4") == 1

    def test_cscli_error_floors_at_one(self):
        # run_cscli returns None on cscli failure → at least the current offense.
        with patch.object(pb, "run_cscli", return_value=None):
            assert pb.count_offenses("1.2.3.4") == 1

    def test_queries_by_ip(self):
        with patch.object(pb, "run_cscli", return_value=[]) as mock_run:
            pb.count_offenses("9.9.9.9")
            args, _ = mock_run.call_args
            assert args[0] == ["alerts", "list", "--ip", "9.9.9.9", "--limit", "0"]

    def test_widely_spaced_alerts_count_separately(self, monkeypatch):
        monkeypatch.setattr(pb, "WINDOW_DAYS", 30)
        monkeypatch.setattr(pb, "DEDUP_MINUTES", 60)
        now = datetime.now(timezone.utc)
        alerts = [
            _alert(when=now - timedelta(hours=6)),
            _alert(when=now - timedelta(hours=3)),
            _alert(when=now),
        ]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.count_offenses("1.2.3.4") == 3

    def test_tightly_spaced_alerts_count_as_one(self, monkeypatch):
        monkeypatch.setattr(pb, "WINDOW_DAYS", 30)
        monkeypatch.setattr(pb, "DEDUP_MINUTES", 60)
        now = datetime.now(timezone.utc)
        alerts = [
            _alert(when=now - timedelta(minutes=2)),
            _alert(when=now - timedelta(minutes=1)),
            _alert(when=now),
        ]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.count_offenses("1.2.3.4") == 1

    def test_out_of_window_alert_is_dropped(self, monkeypatch):
        monkeypatch.setattr(pb, "WINDOW_DAYS", 30)
        monkeypatch.setattr(pb, "DEDUP_MINUTES", 60)
        now = datetime.now(timezone.utc)
        alerts = [
            _alert(when=now - timedelta(days=60)),  # outside the 30d window
            _alert(when=now - timedelta(hours=6)),
            _alert(when=now),
        ]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.count_offenses("1.2.3.4") == 2

    def test_continuous_drip_chains_into_one_incident(self, monkeypatch):
        """Each gap is under DEDUP_MINUTES, but the chain spans hours: clustering
        compares against the PREVIOUS alert (which advances every alert), not the
        previous COUNTED one, so this is one long incident, not several."""
        monkeypatch.setattr(pb, "WINDOW_DAYS", 30)
        monkeypatch.setattr(pb, "DEDUP_MINUTES", 60)
        now = datetime.now(timezone.utc)
        alerts = [_alert(when=now - timedelta(minutes=50 * i)) for i in range(5)]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.count_offenses("1.2.3.4") == 1

    def test_multi_scenario_burst_counts_once(self, monkeypatch):
        monkeypatch.setattr(pb, "WINDOW_DAYS", 30)
        monkeypatch.setattr(pb, "DEDUP_MINUTES", 60)
        now = datetime.now(timezone.utc)
        alerts = [
            _alert(scenario="crowdsecurity/http-probing", when=now),
            _alert(scenario="crowdsecurity/http-bad-user-agent", when=now),
            _alert(scenario="crowdsecurity/http-generic-bf", when=now),
        ]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.count_offenses("1.2.3.4") == 1


class TestWhitelist:
    def test_load_whitelist_parses_ip_and_cidr(self, tmp_path):
        wl_path = tmp_path / "whitelist-loxone.yaml"
        wl_path.write_text(
            "name: whitelist-loxone\n"
            "whitelist:\n"
            "  ip:\n"
            '    - "203.0.113.5"\n'
            "  cidr:\n"
            '    - "198.51.100.0/24"\n'
        )
        nets = pb.load_whitelist(str(wl_path))
        assert ipaddress.ip_network("203.0.113.5/32") in nets
        assert ipaddress.ip_network("198.51.100.0/24") in nets

    def test_load_whitelist_missing_file_returns_empty(self, tmp_path):
        assert pb.load_whitelist(str(tmp_path / "does-not-exist.yaml")) == []

    def test_is_whitelisted_exact_ip(self):
        nets = [ipaddress.ip_network("203.0.113.5/32")]
        assert pb.is_whitelisted("203.0.113.5", nets) is True
        assert pb.is_whitelisted("203.0.113.6", nets) is False

    def test_is_whitelisted_cidr_membership(self):
        nets = [ipaddress.ip_network("198.51.100.0/24")]
        assert pb.is_whitelisted("198.51.100.42", nets) is True
        assert pb.is_whitelisted("198.51.101.1", nets) is False


class TestStateFile:
    def test_state_file_created_on_first_escalation(self, tmp_path, monkeypatch):
        """After extending a ban, the IP should be written to state file."""
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))

        # New model: the ban to extend is origin "crowdsec" (a local scenario ban).
        active = [{"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=2):
                with patch.object(pb, "cscli_decision_delete", return_value=True):
                    with patch.object(pb, "cscli_decision_add", return_value=True):
                        pb.main()

        assert state_path.exists()
        state = json.loads(state_path.read_text())
        assert state["1.2.3.4"] == "24h"

    def test_rerun_skips_ip_already_at_target_tier(self, tmp_path, monkeypatch):
        """Same-tier skip guard: a still-active local scenario ban whose IP is
        already extended to the matching tier must NOT be re-extended.

        This is the delete-failed-last-run case (F9): both the original
        ``crowdsec`` ban and our ``cscli`` extension are active. The cscli
        extension keeps the state entry off the prune list; the state guard then
        skips re-extending the crowdsec ban that is already at its tier.
        """
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))
        state_path.write_text(json.dumps({"1.2.3.4": "24h"}))

        active = [
            {"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
             "duration": "3h", "scenario": "ssh-bf"},
            {"value": "1.2.3.4", "id": "3", "origin": "cscli",
             "duration": "23h55m", "scenario": "ssh-bf"},
        ]

        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=2):  # still tier-2 → 24h
                with patch.object(pb, "cscli_decision_delete") as mock_del:
                    with patch.object(pb, "cscli_decision_add") as mock_add:
                        pb.main()
                        mock_del.assert_not_called()
                        mock_add.assert_not_called()
        assert "1.2.3.4" in json.loads(state_path.read_text())  # cscli extension keeps it

    def test_higher_tier_re_extends(self, tmp_path, monkeypatch):
        """When the offense count climbs to a higher tier, the IP is re-extended."""
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))
        state_path.write_text(json.dumps({"1.2.3.4": "24h"}))  # previously tier-2

        active = [{"value": "1.2.3.4", "id": "7", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=3):  # now tier-3 → 168h
                with patch.object(pb, "cscli_decision_delete", return_value=True) as mock_del:
                    with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                        pb.main()
                        mock_add.assert_called_once()
                        args, _ = mock_add.call_args
                        assert args[1] == "168h"
        assert json.loads(state_path.read_text())["1.2.3.4"] == "168h"

    def test_stale_entries_pruned(self, tmp_path, monkeypatch):
        """State entries for IPs with no active extension (cscli decision) are removed."""
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))
        state_path.write_text(json.dumps({"5.5.5.5": "24h", "1.2.3.4": "168h"}))

        # 1.2.3.4 still has our active extension (origin "cscli"); 5.5.5.5 has nothing.
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "6d23h", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "cscli_decision_delete") as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_del.assert_not_called()  # cscli-origin is skipped from extension
                    mock_add.assert_not_called()

        state = json.loads(state_path.read_text())
        assert "5.5.5.5" not in state  # stale, pruned
        assert "1.2.3.4" in state      # active extension, kept


class TestMain:
    def test_no_active_decisions(self):
        with patch.object(pb, "run_cscli", return_value=[]):
            pb.main()  # should exit cleanly

    def test_single_offense_no_extension(self):
        """1st offense — not in ESCALATION table, should be skipped."""
        active = [{"value": "1.2.3.4", "id": "1", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=1):
                with patch.object(pb, "cscli_decision_delete") as mock_del:
                    with patch.object(pb, "cscli_decision_add") as mock_add:
                        pb.main()
                        mock_del.assert_not_called()
                        mock_add.assert_not_called()

    def test_second_offense_extended(self):
        """2nd offense on a local scenario ban — should extend to 24h."""
        active = [{"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=2):
                with patch.object(pb, "cscli_decision_delete", return_value=True) as mock_del:
                    with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                        pb.main()
                        mock_del.assert_called_once_with("2")
                        mock_add.assert_called_once()
                        args, _ = mock_add.call_args
                        assert args[0] == "1.2.3.4"
                        assert args[1] == "24h"

    def test_capi_ban_skipped(self):
        """CAPI-origin bans (community reputation) are never extended."""
        active = [{"value": "1.2.3.4", "id": "1", "origin": "CAPI",
                   "duration": "3h58m", "scenario": "crowdsecurity/http-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=9) as mock_count:
                with patch.object(pb, "cscli_decision_delete") as mock_del:
                    with patch.object(pb, "cscli_decision_add") as mock_add:
                        pb.main()
                        mock_del.assert_not_called()
                        mock_add.assert_not_called()
                        mock_count.assert_not_called()  # skipped before counting

    def test_capi_history_does_not_inflate_local_offense_count(self):
        """CAPI/community decisions must never drive escalation.

        H1: offenses are counted from local ALERTS (count_offenses), and CAPI
        community-blocklist entries produce no local alert. An IP with CAPI
        decisions plus a single local scenario ban is a first-time local
        offender (offense=1 → no extension). The CAPI decisions are also skipped
        by the origin filter regardless.
        """
        active = [
            {"value": "1.2.3.4", "id": "10", "origin": "CAPI",
             "duration": "3h", "scenario": "capi"},
            {"value": "1.2.3.4", "id": "20", "origin": "crowdsec",
             "duration": "3h58m", "scenario": "ssh-bf"},
        ]
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=1):  # one local offense
                with patch.object(pb, "cscli_decision_delete") as mock_del:
                    with patch.object(pb, "cscli_decision_add") as mock_add:
                        pb.main()
                        mock_del.assert_not_called()
                        mock_add.assert_not_called()

    def test_whitelisted_ip_skipped(self, tmp_path, monkeypatch):
        """M9/M10: an IP covered by the CrowdSec whitelist is never escalated,
        not even counted — same guard shape as the CAPI-origin skip."""
        wl_path = tmp_path / "whitelist-loxone.yaml"
        wl_path.write_text('whitelist:\n  ip:\n    - "1.2.3.4"\n')
        monkeypatch.setattr(pb, "WHITELIST_FILE", str(wl_path))
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))

        active = [{"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses") as mock_count:
                with patch.object(pb, "cscli_decision_delete") as mock_del:
                    with patch.object(pb, "cscli_decision_add") as mock_add:
                        pb.main()
                        mock_count.assert_not_called()  # skipped before counting
                        mock_del.assert_not_called()
                        mock_add.assert_not_called()

    # ── F9: fail-safe ban extension (add the new ban BEFORE deleting the old) ──
    def test_extend_adds_before_deletes(self):
        """F9: the extended ban is ADDED before the original is DELETED, so a
        crash/timeout between the two steps can only over-ban, never unban."""
        active = [{"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        order = []
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=2):
                with patch.object(pb, "cscli_decision_add",
                                  side_effect=lambda *a, **k: order.append("add") or True):
                    with patch.object(pb, "cscli_decision_delete",
                                      side_effect=lambda *a, **k: order.append("delete") or True):
                        pb.main()
        assert order == ["add", "delete"], f"expected add before delete, got {order}"

    def test_add_fails_leaves_original_ban(self):
        """F9: if the extended add fails, the original is NOT deleted — the IP
        stays banned (fail safe, never an unban)."""
        active = [{"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=2):
                with patch.object(pb, "cscli_decision_add", return_value=False) as mock_add:
                    with patch.object(pb, "cscli_decision_delete") as mock_del:
                        pb.main()
                        mock_add.assert_called_once()
                        mock_del.assert_not_called()

    def test_add_succeeds_delete_fails_is_harmless(self):
        """F9: add succeeds but deleting the original fails — the IP stays
        banned via the new (longer) decision; the stale original just expires.
        main() must not crash and the delete must still have been attempted."""
        active = [{"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "count_offenses", return_value=2):
                with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                    with patch.object(pb, "cscli_decision_delete", return_value=False) as mock_del:
                        pb.main()
                        mock_add.assert_called_once()
                        mock_del.assert_called_once()


class TestEscalationTable:
    def test_escalation_values(self):
        assert pb.ESCALATION[2] == "24h"
        assert pb.ESCALATION[3] == "168h"
        assert pb.ESCALATION[4] == "720h"
        assert pb.DEFAULT_EXTENDED == "720h"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
