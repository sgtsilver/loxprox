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


@pytest.fixture(autouse=True)
def _isolated_host_paths(tmp_path, monkeypatch):
    """No test reads or writes the host's state file or CrowdSec whitelist.
    Run as root on a gateway, main() would otherwise overwrite the live
    /var/lib/loxprox/extended-decisions.json. Tests that need their own paths
    monkeypatch them again."""
    monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "extended-decisions.json"))
    monkeypatch.setattr(pb, "WHITELIST_FILE", str(tmp_path / "no-whitelist.yaml"))


def _alert(scenario="crowdsecurity/http-probing", when=None, origin="crowdsec"):
    """A realistic `cscli alerts list` entry: attack-origin decision + timestamp."""
    if when is None:
        when = datetime.now(timezone.utc)
    return {
        "scenario": scenario,
        "created_at": when.isoformat(),
        "decisions": [{"origin": origin}],
    }


def _offenses(n, hard=False):
    """patch.object value for pb.analyze_offenses."""
    return patch.object(pb, "analyze_offenses", return_value=(n, hard))


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
            with _offenses(2):
                with patch.object(pb, "cscli_decision_delete", return_value=True):
                    with patch.object(pb, "cscli_decision_add", return_value=True):
                        pb.main()

        assert state_path.exists()
        state = json.loads(state_path.read_text())
        assert state["1.2.3.4"] == "168h"

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
        state_path.write_text(json.dumps({"1.2.3.4": "168h"}))

        active = [
            {"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
             "duration": "3h", "scenario": "ssh-bf"},
            {"value": "1.2.3.4", "id": "3", "origin": "cscli",
             "duration": "23h55m", "scenario": "ssh-bf"},
        ]

        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(2):  # still soft tier-2 → 168h
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
        state_path.write_text(json.dumps({"1.2.3.4": "168h"}))  # previously soft tier-2

        active = [{"value": "1.2.3.4", "id": "7", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]

        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(3):  # now soft tier-3 → 720h
                with patch.object(pb, "cscli_decision_delete", return_value=True) as mock_del:
                    with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                        pb.main()
                        mock_add.assert_called_once()
                        args, _ = mock_add.call_args
                        assert args[1] == "720h"
        assert json.loads(state_path.read_text())["1.2.3.4"] == "720h"

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

    def test_first_soft_offense_with_short_profile_ban_is_lifted(self):
        """n=1 SOFT, banned 4h by an old/default profile → lifted to 24h."""
        active = [{"value": "1.2.3.4", "id": "1", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(1):
                with patch.object(pb, "cscli_decision_delete", return_value=True) as mock_del:
                    with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                        pb.main()
                        mock_add.assert_called_once()
                        assert mock_add.call_args.args[1] == "24h"
                        mock_del.assert_called_once_with("1")

    def test_first_hard_offense_with_short_profile_ban_is_lifted_to_7d(self):
        active = [{"value": "1.2.3.4", "id": "1", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "crowdsecurity/vpatch-env-access"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(1, hard=False):  # alerts unavailable; decision scenario decides
                with patch.object(pb, "cscli_decision_delete", return_value=True), \
                     patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                    pb.main()
                    assert mock_add.call_args.args[1] == "168h"

    def test_ban_already_at_tier_one_is_left_alone(self):
        """Tier 1 set by the CrowdSec profile at full length (minutes have passed)."""
        active = [{"value": "1.2.3.4", "id": "1", "origin": "crowdsec",
                   "duration": "167h41m3s", "scenario": "loxprox/scanner-trap"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(1, hard=True):
                with patch.object(pb, "cscli_decision_delete") as mock_del, \
                     patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_add.assert_not_called()
                    mock_del.assert_not_called()

    def test_never_shortens_an_existing_longer_ban(self):
        """A 400h ban with a soft n=2 target of 168h must not be replaced."""
        active = [{"value": "1.2.3.4", "id": "1", "origin": "crowdsec",
                   "duration": "400h", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(2):
                with patch.object(pb, "cscli_decision_delete") as mock_del, \
                     patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_add.assert_not_called()
                    mock_del.assert_not_called()

    def test_own_longer_extension_counts_as_time_left(self, tmp_path, monkeypatch):
        """Our earlier cscli extension (400h) on the same IP blocks a shorter re-add."""
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "state.json"))
        active = [
            {"value": "1.2.3.4", "id": "1", "origin": "crowdsec", "duration": "2h", "scenario": "ssh-bf"},
            {"value": "1.2.3.4", "id": "2", "origin": "cscli", "duration": "400h", "scenario": "x"},
        ]
        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(2):
                with patch.object(pb, "cscli_decision_add") as mock_add:
                    pb.main()
                    mock_add.assert_not_called()

    def test_second_offense_extended(self):
        """2nd soft offense on a local scenario ban — extends to 168h."""
        active = [{"value": "1.2.3.4", "id": "2", "origin": "crowdsec",
                   "duration": "3h58m", "scenario": "ssh-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with _offenses(2):
                with patch.object(pb, "cscli_decision_delete", return_value=True) as mock_del:
                    with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                        pb.main()
                        mock_del.assert_called_once_with("2")
                        mock_add.assert_called_once()
                        args, _ = mock_add.call_args
                        assert args[0] == "1.2.3.4"
                        assert args[1] == "168h"

    def test_capi_ban_skipped(self):
        """CAPI-origin bans (community reputation) are never extended."""
        active = [{"value": "1.2.3.4", "id": "1", "origin": "CAPI",
                   "duration": "3h58m", "scenario": "crowdsecurity/http-bf"}]
        with patch.object(pb, "run_cscli", return_value=active):
            with patch.object(pb, "analyze_offenses", return_value=(9, True)) as mock_count:
                with patch.object(pb, "cscli_decision_delete") as mock_del:
                    with patch.object(pb, "cscli_decision_add") as mock_add:
                        pb.main()
                        mock_del.assert_not_called()
                        mock_add.assert_not_called()
                        mock_count.assert_not_called()  # skipped before counting

    @staticmethod
    def _capi_case(local_decision):
        """main() over one IP with a CAPI decision (id 10) and a local one (id 20).

        The alert history is real input for analyze_offenses: one local alert
        now, plus CAPI / community-list alerts days earlier. If those counted,
        this would be offence #3 (720h); they must not — it is offence #1.
        """
        now = datetime.now(timezone.utc)
        active = [
            {"value": "1.2.3.4", "id": "10", "origin": "CAPI", "duration": "3h", "scenario": "capi"},
            dict({"value": "1.2.3.4", "id": "20", "origin": "crowdsec", "scenario": "ssh-bf"}, **local_decision),
        ]
        history = [
            _alert("crowdsecurity/ssh-bf", now - timedelta(minutes=5)),
            _alert("update : +15000/-0 IPs", now - timedelta(days=5), origin="CAPI"),
            _alert("firehol_cybercrime", now - timedelta(days=20), origin="lists:firehol_cybercrime"),
        ]

        def cscli(args):
            return active if args[:2] == ["decisions", "list"] else history

        with patch.object(pb, "run_cscli", side_effect=cscli), \
             patch.object(pb, "load_whitelist", return_value=[]), \
             patch.object(pb, "cscli_decision_delete", return_value=True) as mock_del, \
             patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
            pb.main()
        return mock_add, mock_del

    def test_capi_history_does_not_inflate_local_offense_count(self, tmp_path, monkeypatch):
        """CAPI/community decisions must never drive escalation.

        H1: offences are counted from local ALERTS (analyze_offenses); CAPI and
        list alerts are not local detections. The IP is a first-time local
        offender: SOFT offence #1 = 24h. Its local ban (3h58m left, no creation
        time — a legacy 4h-profile ban) is lifted to rung 1, never rung 2+.
        The CAPI decision is never touched.
        """
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        mock_add, mock_del = self._capi_case({"duration": "3h58m"})
        assert [c.args for c in mock_add.call_args_list] == [("1.2.3.4", "24h", "repeat-offender-1")]
        assert [c.args for c in mock_del.call_args_list] == [("20",)]   # never id 10

    def test_capi_history_with_a_full_tier_one_ban_is_left_alone(self, tmp_path, monkeypatch):
        """Same IP and history; the local ban carries its creation time and was
        made at 24h (3 h ago): already at rung 1, nothing to do."""
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        created = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        mock_add, mock_del = self._capi_case({"duration": "21h", "created_at": created})
        mock_add.assert_not_called()
        mock_del.assert_not_called()

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
            with patch.object(pb, "analyze_offenses") as mock_count:
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
            with _offenses(2):
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
            with _offenses(2):
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
            with _offenses(2):
                with patch.object(pb, "cscli_decision_add", return_value=True) as mock_add:
                    with patch.object(pb, "cscli_decision_delete", return_value=False) as mock_del:
                        pb.main()
                        mock_add.assert_called_once()
                        mock_del.assert_called_once()


HARD_SCENARIOS = [
    "crowdsecurity/vpatch-CVE-2025-29927", "crowdsecurity/vpatch-env-access",
    "crowdsecurity/appsec-vpatch", "crowdsecurity/http-cve-2021-41773",
    "crowdsecurity/CVE-2022-26134", "crowdsecurity/grafana-cve-2021-43798",
    "crowdsecurity/http-sensitive-files", "crowdsecurity/http-backdoors-attempts",
    "crowdsecurity/http-path-traversal-probing", "crowdsecurity/http-admin-interface-probing",
    "crowdsecurity/http-open-proxy", "loxprox/scanner-trap",
]
SOFT_SCENARIOS = [
    "crowdsecurity/http-probing", "crowdsecurity/http-bad-user-agent",
    "crowdsecurity/http-crawl-non_statics", "crowdsecurity/nginx-req-limit-exceeded",
    "crowdsecurity/http-technology-probing", "LePresidente/http-generic-401-bf",
    "loxprox/unknown-path", "loxprox/auth-bf", "repeat-offender-2",
]


class TestOriginalDuration:
    """Judge a ban by the length it was created with, not by what is left."""

    def _run(self, duration, created_ago, n, hard, scenario="ssh-bf", with_created=True, caplog=None):
        dec = {"value": "1.2.3.4", "id": "1", "origin": "crowdsec",
               "duration": duration, "scenario": scenario}
        if with_created:
            dec["created_at"] = (datetime.now(timezone.utc) - created_ago).isoformat()
        with patch.object(pb, "run_cscli", return_value=[dec]), _offenses(n, hard), \
             patch.object(pb, "load_whitelist", return_value=[]), \
             patch.object(pb, "cscli_decision_delete", return_value=True), \
             patch.object(pb, "cscli_decision_add", return_value=True) as add:
            pb.main()
        return add

    def test_soft_n1_24h_ban_created_3h_ago_is_left_alone(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        assert not self._run("21h", timedelta(hours=3), 1, False).called

    def test_hard_n1_168h_ban_created_20h_ago_is_left_alone(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        assert not self._run("148h", timedelta(hours=20), 1, True, "loxprox/scanner-trap").called

    def test_hard_n1_4h_ban_created_1h_ago_is_lifted_to_168h(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        add = self._run("3h", timedelta(hours=1), 1, True, "loxprox/scanner-trap")
        add.assert_called_once()
        assert add.call_args.args[1] == "168h"

    def test_24h_ban_at_soft_n2_is_lifted_to_168h(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        add = self._run("20h", timedelta(hours=4), 2, False)
        add.assert_called_once()
        assert add.call_args.args[1] == "168h"

    def test_missing_creation_time_falls_back_to_time_left_and_logs(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        caplog.set_level("INFO", logger="progressive-ban")
        # Threshold: EXTEND_SLACK (0.9) × 24h target = 21.6h = 21h36m.
        # 22h left is above it: left alone.
        assert not self._run("22h", timedelta(0), 1, False, with_created=False).called
        assert "No creation time" in caplog.text
        # Boundary: exactly 21h36m left is >= 90%: left alone; one second less is lifted.
        assert not self._run("21h36m", timedelta(0), 1, False, with_created=False).called
        add = self._run("21h35m59s", timedelta(0), 1, False, with_created=False)
        assert add.called and add.call_args.args[1] == "24h"
        # 3h left: well below, lifted to 24h
        add = self._run("3h", timedelta(0), 1, False, with_created=False)
        assert add.called and add.call_args.args[1] == "24h"

    def test_flatten_carries_the_alert_creation_time(self):
        alert = {"created_at": "2026-10-06T17:35:44Z", "source": {},
                 "decisions": [{"id": 1, "value": "203.0.113.9", "origin": "crowdsec", "duration": "3h"}]}
        assert pb.flatten_decisions([alert])[0]["created_at"] == "2026-10-06T17:35:44Z"


class TestScenarioClassification:
    @pytest.mark.parametrize("name", HARD_SCENARIOS)
    def test_live_hard_names_classify_hard(self, name):
        assert pb.is_hard_scenario(name)

    @pytest.mark.parametrize("name", SOFT_SCENARIOS)
    def test_live_soft_names_classify_soft(self, name):
        assert not pb.is_hard_scenario(name)

    def test_regex_is_anchored(self):
        assert not pb.is_hard_scenario("evil/loxprox/scanner-trap")
        assert not pb.is_hard_scenario("loxprox/scanner-trap-extra")
        assert not pb.is_hard_scenario("")
        assert not pb.is_hard_scenario(None)

    def test_default_regex_compiles_and_is_re2_safe(self):
        """Python `re` compiles it. Go RE2 cannot be run here; RE2 rejects
        lookaround, backreferences and possessive/atomic groups, so assert none occur."""
        import re
        re.compile(pb.DEFAULT_HARD_SCENARIOS)
        for construct in ("(?=", "(?!", "(?<=", "(?<!", "(?>", "(?P=", "*+", "++", "?+"):
            assert construct not in pb.DEFAULT_HARD_SCENARIOS
        assert not re.search(r"\\[1-9]", pb.DEFAULT_HARD_SCENARIOS)  # no backreference

    def test_current_incident_is_hard_if_any_alert_in_it_is(self, monkeypatch):
        monkeypatch.setattr(pb, "DEDUP_MINUTES", 60)
        now = datetime.now(timezone.utc)
        alerts = [
            _alert("crowdsecurity/http-probing", now - timedelta(minutes=2)),
            _alert("crowdsecurity/vpatch-env-access", now - timedelta(minutes=1)),
            _alert("crowdsecurity/http-bad-user-agent", now),
        ]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.analyze_offenses("1.2.3.4") == (1, True)

    def test_hardness_is_of_the_current_incident_not_history(self, monkeypatch):
        monkeypatch.setattr(pb, "DEDUP_MINUTES", 60)
        now = datetime.now(timezone.utc)
        alerts = [
            _alert("loxprox/scanner-trap", now - timedelta(days=10)),
            _alert("crowdsecurity/http-probing", now),
        ]
        with patch.object(pb, "run_cscli", return_value=alerts):
            assert pb.analyze_offenses("1.2.3.4") == (2, False)

    def test_simulated_alerts_do_not_count(self):
        sim = _alert("loxprox/unknown-path")
        sim["simulated"] = True
        with patch.object(pb, "run_cscli", return_value=[sim, _alert("loxprox/scanner-trap")]):
            assert pb.analyze_offenses("1.2.3.4") == (1, True)


class TestLadders:
    @pytest.mark.parametrize("n,expected", [(1, "168h"), (2, "2160h"), (3, "8760h"),
                                            (4, "8760h"), (5, "8760h"), (6, "8760h")])
    def test_hard_ladder_index(self, n, expected):
        assert pb.ladder_duration(n, True) == expected

    @pytest.mark.parametrize("n,expected", [(1, "24h"), (2, "168h"), (3, "720h"),
                                            (4, "2160h"), (5, "2160h"), (6, "2160h")])
    def test_soft_ladder_index(self, n, expected):
        assert pb.ladder_duration(n, False) == expected

    def test_defaults_match_contract(self):
        assert pb.HARD_LADDER == ["168h", "2160h", "8760h"]
        assert pb.SOFT_LADDER == ["24h", "168h", "720h", "2160h"]
        assert pb.WINDOW_DAYS == 365

    @pytest.mark.parametrize("raw", ["", "banana", "24h 7days", "168h 24h", "0h", "-5h", "24"])
    def test_bad_ladder_falls_back_with_warning(self, raw, caplog):
        caplog.set_level("WARNING", logger="progressive-ban")
        assert pb.parse_ladder("BAN_SOFT_LADDER", raw, pb.DEFAULT_SOFT_LADDER) == pb.DEFAULT_SOFT_LADDER.split()
        assert "BAN_SOFT_LADDER" in caplog.text

    def test_valid_ladder_is_accepted(self):
        # Accepted, and day entries come back as hours (Go has no `d` unit).
        assert pb.parse_ladder("X", "1h 2d 30d", "24h") == ["1h", "48h", "720h"]

    def test_bad_regex_falls_back_with_warning(self, caplog):
        caplog.set_level("WARNING", logger="progressive-ban")
        rx = pb.parse_hard_regex("(unclosed", pb.DEFAULT_HARD_SCENARIOS)
        assert rx.pattern == pb.DEFAULT_HARD_SCENARIOS
        assert "BAN_HARD_SCENARIOS" in caplog.text

    def test_bad_window_falls_back(self, monkeypatch, caplog):
        monkeypatch.setenv("PROGRESSIVE_BAN_WINDOW_DAYS", "forever")
        caplog.set_level("WARNING", logger="progressive-ban")
        assert pb.setting_int("PROGRESSIVE_BAN_WINDOW_DAYS", 365) == 365
        monkeypatch.setenv("PROGRESSIVE_BAN_WINDOW_DAYS", "-3")
        assert pb.setting_int("PROGRESSIVE_BAN_WINDOW_DAYS", 365) == 365

    def test_config_env_values_are_read(self, tmp_path):
        cfg = tmp_path / "config.env"
        cfg.write_text('BAN_HARD_LADDER="1h 2h"\nBAN_HARD_SCENARIOS="^foo$"\n')
        values = pb.load_env_config(str(cfg))
        assert values["BAN_HARD_LADDER"] == "1h 2h"
        assert values["BAN_HARD_SCENARIOS"] == "^foo$"

    @pytest.mark.parametrize("raw,secs", [("167h59m3.5s", 167 * 3600 + 59 * 60 + 3.5), ("31m5s", 1865),
                                          ("8760h", 8760 * 3600), ("-1h", 0), ("", 0), ("junk", 0)])
    def test_remaining_duration(self, raw, secs):
        assert pb.remaining_duration(raw).total_seconds() == pytest.approx(secs)


class TestDayUnits:
    """F3: deploy.sh accepts `7d` in a ladder, but CrowdSec parses
    `--duration` with Go's time.ParseDuration, which has no `d` unit — a
    verbatim `7d` made every escalation fail. Days become whole hours before
    any cscli call; comparisons stay span-based."""

    @pytest.mark.parametrize("raw,expected", [("7d", "168h"), ("90d", "2160h"), ("365d", "8760h"),
                                              ("1d", "24h"), ("24h", "24h"), ("30m", "30m"),
                                              ("junk", "junk")])
    def test_go_duration(self, raw, expected):
        assert pb.go_duration(raw) == expected

    def test_day_ladder_is_converted_to_hours(self):
        assert pb.parse_ladder("BAN_HARD_LADDER", "7d 90d 365d", pb.DEFAULT_HARD_LADDER) == \
            ["168h", "2160h", "8760h"]

    def test_mixed_units_keep_their_order(self):
        # 2d (48h) < 72h < 7d (168h): sorted by span, not by text.
        assert pb.parse_ladder("X", "2d 72h 7d", "24h") == ["48h", "72h", "168h"]

    def test_cscli_add_never_receives_a_day_unit(self):
        with patch.object(pb.subprocess, "run", return_value=FakeCompletedProcess()) as run:
            assert pb.cscli_decision_add("203.0.113.9", "7d", "repeat-offender-1")
        argv = run.call_args.args[0]
        assert argv[argv.index("--duration") + 1] == "168h"

    def test_day_ladder_escalates_with_hours(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        monkeypatch.setattr(pb, "HARD_LADDER", pb.parse_ladder("BAN_HARD_LADDER", "7d 90d 365d", pb.DEFAULT_HARD_LADDER))
        active = [{"value": "203.0.113.9", "id": "4", "origin": "crowdsec",
                   "duration": "3h", "scenario": "loxprox/scanner-trap"}]
        with patch.object(pb, "run_cscli", return_value=active), _offenses(2, True), \
             patch.object(pb, "load_whitelist", return_value=[]), \
             patch.object(pb, "cscli_decision_delete", return_value=True), \
             patch.object(pb.subprocess, "run", return_value=FakeCompletedProcess()) as run:
            pb.main()
        argv = run.call_args.args[0]
        assert argv[:3] == ["cscli", "decisions", "add"]
        assert argv[argv.index("--duration") + 1] == "2160h"

    def test_day_ladder_ban_already_at_its_tier_is_left_alone(self, tmp_path, monkeypatch):
        """A 90d ban created 2 h ago, ladder written as days: same span → skip."""
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        monkeypatch.setattr(pb, "HARD_LADDER", pb.parse_ladder("BAN_HARD_LADDER", "7d 90d 365d", pb.DEFAULT_HARD_LADDER))
        dec = {"value": "203.0.113.9", "id": "4", "origin": "crowdsec", "duration": "2158h",
               "scenario": "loxprox/scanner-trap",
               "created_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()}
        with patch.object(pb, "run_cscli", return_value=[dec]), _offenses(2, True), \
             patch.object(pb, "load_whitelist", return_value=[]), \
             patch.object(pb, "cscli_decision_add") as add:
            pb.main()
        add.assert_not_called()

    def test_state_written_with_days_counts_as_the_same_tier(self, tmp_path, monkeypatch):
        """An older state file holds "7d"; the target is now "168h". Same span:
        the state guard must skip, not re-add (string compare would re-add)."""
        state_path = tmp_path / "s.json"
        monkeypatch.setattr(pb, "STATE_FILE", str(state_path))
        state_path.write_text(json.dumps({"203.0.113.9": "7d"}))
        active = [
            {"value": "203.0.113.9", "id": "2", "origin": "crowdsec", "duration": "3h", "scenario": "ssh-bf"},
            {"value": "203.0.113.9", "id": "3", "origin": "cscli", "duration": "100h", "scenario": "repeat-offender-2"},
        ]
        with patch.object(pb, "run_cscli", return_value=active), _offenses(2), \
             patch.object(pb, "load_whitelist", return_value=[]), \
             patch.object(pb, "cscli_decision_add") as add:
            pb.main()
        add.assert_not_called()


class TestListLimits:
    """F4: `cscli decisions list` returns 100 alerts and `cscli alerts list` 50
    unless --limit 0 is passed (CrowdSec 1.8.1 --help)."""

    def test_main_lists_every_active_decision(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        with patch.object(pb, "run_cscli", return_value=[]) as run:
            pb.main()
        assert run.call_args_list[0].args[0] == ["decisions", "list", "--limit", "0"]

    def test_limit_reaches_the_cscli_command_line(self):
        with patch.object(pb.subprocess, "run", return_value=FakeCompletedProcess(stdout="[]")) as run:
            pb.run_cscli(["decisions", "list", "--limit", "0"])
        assert run.call_args.args[0] == ["cscli", "decisions", "list", "--limit", "0", "-o", "json"]


class TestExtensionReason:
    """The reason is what an extension's decision shows as its scenario:
    gateway-monitor.sh sends HARD extensions to the daily digest."""

    def _extend(self, tmp_path, monkeypatch, scenario, hard):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "s.json"))
        active = [{"value": "203.0.113.9", "id": "5", "origin": "crowdsec", "duration": "3h", "scenario": scenario}]
        with patch.object(pb, "run_cscli", return_value=active), _offenses(2, hard), \
             patch.object(pb, "load_whitelist", return_value=[]), \
             patch.object(pb, "cscli_decision_delete", return_value=True), \
             patch.object(pb, "cscli_decision_add", return_value=True) as add:
            pb.main()
        return add.call_args.args

    def test_hard_extension_reason(self, tmp_path, monkeypatch):
        ip, duration, reason = self._extend(tmp_path, monkeypatch, "loxprox/scanner-trap", True)
        assert (duration, reason) == ("2160h", "repeat-offender-hard-2")

    def test_soft_extension_reason_is_unchanged(self, tmp_path, monkeypatch):
        ip, duration, reason = self._extend(tmp_path, monkeypatch, "crowdsecurity/http-probing", False)
        assert (duration, reason) == ("168h", "repeat-offender-2")

    def test_hard_extension_alerts_are_not_offences(self):
        # cscli builds whose alert payload has no decisions: the prefix guard.
        assert not pb.is_attack_alert({"scenario": "repeat-offender-hard-2"})
        assert not pb.is_hard_scenario("repeat-offender-hard-2")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ── 2026-10: the real `cscli decisions list -o json` shape (CrowdSec 1.8.1) ──
#
# The fixture is a masked live sample: 9 ALERTS, each with a nested
# `decisions` list (8 decisions in total; one alert carries none because its
# address is already banned by another). main() read value/origin/id at the
# top level of each alert, found no value anywhere and dropped every entry —
# the production log said "Extended: 0, Skipped: 0" every 15 minutes.

FIXTURE = Path(__file__).parent / "fixtures" / "cscli-decisions-list-1.8.1.json"


def _fixture():
    return json.loads(FIXTURE.read_text())


class TestFlattenDecisions:
    def test_fixture_is_alert_shaped(self):
        data = _fixture()
        assert all("value" not in a and "decisions" in a for a in data)

    def test_flattens_every_decision(self):
        decs = pb.flatten_decisions(_fixture())
        assert len(decs) == 8
        assert all(d["value"] and d["id"] and d["origin"] == "crowdsec" for d in decs)
        assert all(d["value"].startswith("203.0.113.") for d in decs)

    def test_scenario_falls_back_to_the_alert(self):
        alert = {"scenario": "crowdsecurity/ssh-bf", "source": {"ip": "203.0.113.9"},
                 "decisions": [{"id": 1, "value": "203.0.113.9", "origin": "crowdsec"}]}
        assert pb.flatten_decisions([alert])[0]["scenario"] == "crowdsecurity/ssh-bf"

    def test_flat_list_and_null_shapes(self):
        flat = [{"id": 3, "value": "203.0.113.3", "origin": "crowdsec"}]
        assert pb.flatten_decisions(flat) == flat
        assert pb.flatten_decisions([]) == []
        assert pb.flatten_decisions(None) == []
        assert pb.flatten_decisions([{"source": {}, "decisions": None}]) == []


class TestMainOnRealShape:
    def _run(self, offenses, tmp_path, monkeypatch, caplog, hard=False):
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "state.json"))
        caplog.set_level("INFO", logger="progressive-ban")
        data = _fixture()
        for a in data:   # the sample's timestamps are weeks old; test the time-left fallback
            a.pop("created_at", None)
        with patch.object(pb, "run_cscli", return_value=data), \
             _offenses(offenses, hard), \
             patch.object(pb, "load_whitelist", return_value=[]), \
             patch.object(pb, "cscli_decision_add", return_value=True) as add, \
             patch.object(pb, "cscli_decision_delete", return_value=True) as dele:
            pb.main()
        return add, dele, caplog.text

    def test_fixture_scenarios_are_all_cve_scanners(self, tmp_path, monkeypatch, caplog):
        # Every decision in the live sample is a *-cve-* scenario → HARD even
        # when the alert history is unavailable: n=1 is lifted to the 7d tier.
        add, dele, log = self._run(1, tmp_path, monkeypatch, caplog)
        assert "Active decisions: 8 (from 9 listed entries)" in log
        assert add.call_count == 8
        assert all(c.args[1] == "168h" for c in add.call_args_list)

    def test_repeat_offenders_are_escalated_by_decision_id(self, tmp_path, monkeypatch, caplog):
        add, dele, log = self._run(2, tmp_path, monkeypatch, caplog, hard=True)
        assert add.call_count == 8 and dele.call_count == 8
        ids = {str(d["id"]) for a in _fixture() for d in (a.get("decisions") or [])}
        assert {c.args[0] for c in dele.call_args_list} == ids
        assert all(c.args[1] == "2160h" for c in add.call_args_list)
        assert "Extended: 8, Skipped: 0" in log

    def test_simulated_decisions_never_escalate(self, tmp_path, monkeypatch, caplog):
        data = _fixture()
        for a in data:
            for d in a.get("decisions") or []:
                d["simulated"] = True
        monkeypatch.setattr(pb, "STATE_FILE", str(tmp_path / "state.json"))
        with patch.object(pb, "run_cscli", return_value=data), \
             _offenses(3, True), \
             patch.object(pb, "cscli_decision_add") as add:
            pb.main()
        add.assert_not_called()
