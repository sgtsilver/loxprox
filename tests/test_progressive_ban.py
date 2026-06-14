#!/usr/bin/env python3
"""
Unit tests for progressive-ban.py

Run with: pytest tests/test_progressive_ban.py -v
Or: python -m pytest tests/test_progressive_ban.py -v
"""

import importlib.util
import json
import subprocess
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
        alerts = [{"a": 1}, {"a": 2}, {"a": 3}]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.count_offenses("1.2.3.4") == 3

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
            assert args[0] == ["alerts", "list", "--ip", "9.9.9.9"]


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
