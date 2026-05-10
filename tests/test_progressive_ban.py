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


class TestCscliDecisionDelete:
    def test_delete_success(self):
        with patch.object(
            pb.subprocess, "run",
            return_value=FakeCompletedProcess(returncode=0),
        ) as mock_run:
            assert pb.cscli_decision_delete("42") is True
            args, kwargs = mock_run.call_args
            assert "decisions" in args[0]
            assert "delete" in args[0]
            assert kwargs["timeout"] == pb.CSCLI_TIMEOUT

    def test_delete_failure(self):
        with patch.object(
            pb.subprocess, "run",
            return_value=FakeCompletedProcess(returncode=1, stderr="fail"),
        ):
            assert pb.cscli_decision_delete("42") is False

    def test_delete_timeout(self):
        with patch.object(
            pb.subprocess, "run",
            side_effect=subprocess.TimeoutExpired(cmd="cscli", timeout=30),
        ):
            assert pb.cscli_decision_delete("42") is False


class TestCscliDecisionAdd:
    def test_add_success(self):
        with patch.object(
            pb.subprocess, "run",
            return_value=FakeCompletedProcess(returncode=0),
        ) as mock_run:
            assert pb.cscli_decision_add("1.2.3.4", "24h", "repeat-offender-2") is True
            args, kwargs = mock_run.call_args
            assert "add" in args[0]
            assert kwargs["timeout"] == pb.CSCLI_TIMEOUT

    def test_add_failure(self):
        with patch.object(
            pb.subprocess, "run",
            return_value=FakeCompletedProcess(returncode=1, stderr="fail"),
        ):
            assert pb.cscli_decision_add("1.2.3.4", "24h", "reason") is False


class TestStateFile:
    def test_state_file_created_on_first_escalation(self, tmp_path, monkeypatch):
        """After extending a ban, the IP should be written to state file."""
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))

        all_decisions = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
        ]
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "3h58m", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete", return_value=True):
                with patch.object(pb, "cscli_decision_add", return_value=True):
                    pb.main()

        assert state_path.exists()
        state = json.loads(state_path.read_text())
        assert state["1.2.3.4"] == "24h"

    def test_rerun_skips_ip_already_in_state_file(self, tmp_path, monkeypatch):
        """A second run with the same IP already escalated should skip it."""
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))

        # Pre-populate state file as if a previous run already extended it
        state_path.write_text(json.dumps({"1.2.3.4": "24h"}))

        all_decisions = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
        ]
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "23h55m", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete") as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_del.assert_not_called()
                    mock_add.assert_not_called()

    def test_new_id_after_extend_is_not_re_extended(self, tmp_path, monkeypatch):
        """After delete+add, active list has new ID — should not extend again."""
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))

        # First run: extend decision id=2 for ip 1.2.3.4
        state_path.write_text(json.dumps({}))
        all_decisions_run1 = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
        ]
        active_run1 = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                        "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions_run1, active_run1]):
            with patch.object(pb, "cscli_decision_delete", return_value=True):
                with patch.object(pb, "cscli_decision_add", return_value=True):
                    pb.main()
        # State should now track the IP, not the old ID
        assert json.loads(state_path.read_text()) == {"1.2.3.4": "24h"}

        # Second run: CrowdSec gave the new decision id=99 (new ID after delete+add)
        # Total offenses still 2 (id=1 expired, id=99 active; id=2 was deleted)
        all_decisions_run2 = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "99", "origin": "cscli"},
        ]
        active_run2 = [{"value": "1.2.3.4", "id": "99", "origin": "cscli",
                        "duration": "23h55m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions_run2, active_run2]):
            with patch.object(pb, "cscli_decision_delete") as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_del.assert_not_called()  # must NOT extend again
                    mock_add.assert_not_called()

    def test_stale_entries_pruned(self, tmp_path, monkeypatch):
        """State entries for IPs no longer with active cscli bans should be removed."""
        state_path = tmp_path / "extended-decisions.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))

        # Pre-populate with one stale and one active entry
        state_path.write_text(json.dumps({"5.5.5.5": "24h", "1.2.3.4": "168h"}))

        all_decisions = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "3", "origin": "cscli"},
        ]
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "6d23h", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete") as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    # IP 1.2.3.4 is already at 168h (offense 3), so no change needed
                    mock_del.assert_not_called()
                    mock_add.assert_not_called()

        state = json.loads(state_path.read_text())
        assert "5.5.5.5" not in state  # stale, pruned
        assert "1.2.3.4" in state     # still active, kept


class TestMain:
    def test_no_active_decisions(self):
        with patch.object(pb, "run_cscli", side_effect=[
            [],   # all decisions
            [],   # active decisions
        ]):
            # Should exit cleanly with no errors
            pb.main()

    def test_single_offense_no_extension(self):
        """1st offense — not in ESCALATION table, should be skipped."""
        all_decisions = [{"value": "1.2.3.4", "id": "1", "origin": "cscli"}]
        active = [{"value": "1.2.3.4", "id": "1", "origin": "cscli",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete") as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_del.assert_not_called()
                    mock_add.assert_not_called()

    def test_second_offense_extended(self):
        """2nd offense — should extend to 24h."""
        all_decisions = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
        ]
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete", return_value=True) as mock_del:
                with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                    pb.main()
                    mock_del.assert_called_once_with("2")
                    mock_add.assert_called_once()
                    args, _ = mock_add.call_args
                    assert args[0] == "1.2.3.4"
                    assert args[1] == "24h"

    def test_capi_ban_skipped(self):
        """CAPI origin bans should never be extended."""
        all_decisions = [{"value": "1.2.3.4", "id": "1", "origin": "CAPI"}]
        active = [{"value": "1.2.3.4", "id": "1", "origin": "CAPI",
                   "duration": "3h58m", "scenario": "crowdsecurity/http-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete") as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_del.assert_not_called()
                    mock_add.assert_not_called()

    def test_delete_fails_does_not_add(self):
        """If delete fails, add should NOT be called."""
        all_decisions = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
        ]
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete", return_value=False) as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_del.assert_called_once()
                    mock_add.assert_not_called()

    def test_add_fails_logs_warning(self):
        """If delete succeeds but add fails, should log and continue."""
        all_decisions = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
        ]
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete", return_value=True):
                with patch.object(pb, "cscli_decision_add", return_value=False) as mock_add:
                    pb.main()
                    mock_add.assert_called_once()


class TestEscalationTable:
    def test_escalation_values(self):
        assert pb.ESCALATION[2] == "24h"
        assert pb.ESCALATION[3] == "168h"
        assert pb.ESCALATION[4] == "720h"
        assert pb.DEFAULT_EXTENDED == "720h"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
