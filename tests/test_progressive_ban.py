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

    def test_already_extended_skipped(self):
        """If duration already contains target, skip."""
        all_decisions = [
            {"value": "1.2.3.4", "id": "1", "origin": "cscli"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli"},
        ]
        active = [{"value": "1.2.3.4", "id": "2", "origin": "cscli",
                   "duration": "24h", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", side_effect=[all_decisions, active]):
            with patch.object(pb, "cscli_decision_delete") as mock_del:
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_del.assert_not_called()
                    mock_add.assert_not_called()

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
