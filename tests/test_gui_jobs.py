"""Panel background jobs (apply / renew-TLS) — 2026-10 fix.

The apply job runs deploy.sh, which restarts loxprox-gui.service. A job that
is a child of the panel dies with it (systemd KillMode=control-group) and the
restarted panel forgot it. Jobs now run as their own transient unit
(systemd-run) with persisted metadata and an exit-code file, so a restarted
panel reports them as still running or finished with the real result.

These tests drive the real JobRunner with real bash processes. systemd-run is
replaced by a stand-in that records its argv and launches the wrapped command
detached; the real-systemd behaviour (the job surviving a stop of the panel's
own unit) is proven in tests/host-integration.sh, section panel-job.
"""

import importlib.util
import json
import os
import stat
import sys
import time

import pytest

_GUI_PATH = os.path.join(os.path.dirname(__file__), "..", "gui", "loxprox-gui.py")
_spec = importlib.util.spec_from_file_location("loxprox_gui_jobs", _GUI_PATH)
gui = importlib.util.module_from_spec(_spec)
sys.modules["loxprox_gui_jobs"] = gui
_spec.loader.exec_module(gui)

SUMMARY_KEYS = {"id", "name", "running", "rc", "status", "elapsed"}


def write_exec(path, body):
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture
def fake_systemd_run(tmp_path):
    """A systemd-run stand-in: records argv, starts the command (everything
    from /bin/bash on) detached, exits 0 like `systemd-run --quiet` does."""
    args_file = tmp_path / "systemd-run.args"
    script = write_exec(tmp_path / "systemd-run", f"""
printf '%s\\n' "$@" > {args_file}
while [[ $# -gt 0 && "$1" != /bin/bash ]]; do shift; done
setsid "$@" </dev/null >/dev/null 2>&1 &
exit 0
""")
    return script, args_file


def rc_file_unit_state(job_dir):
    """Unit 'active' until the job's rc file exists — what a --collect'ed
    transient unit looks like from systemctl is-active."""
    def state(unit):
        job_id = unit.replace("loxprox-job-", "")
        done = any(n.startswith(job_id) and n.endswith(".rc") for n in os.listdir(job_dir))
        return "inactive" if done else "active"
    return state


def wait_done(runner, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = runner.current_summary()
        if s and not s["running"]:
            return s
        time.sleep(0.2)
    raise AssertionError(f"job still running after {timeout}s: {runner.current_summary()}")


def test_job_runs_as_its_own_transient_unit(tmp_path, fake_systemd_run):
    sdrun, args_file = fake_systemd_run
    job_dir = tmp_path / "jobs"
    deploy = write_exec(tmp_path / "deploy.sh", 'echo "deploying $*"; exit 3\n')
    runner = gui.JobRunner(job_dir=str(job_dir), systemd_run=sdrun,
                           unit_state=rc_file_unit_state(str(job_dir)))

    job_id, err = runner.start("apply", ["bash", deploy])
    assert err is None and job_id

    argv = args_file.read_text().splitlines() if args_file.exists() else []
    for _ in range(50):
        if argv:
            break
        time.sleep(0.1)
        argv = args_file.read_text().splitlines() if args_file.exists() else []
    assert argv[:2] == ["--unit", f"loxprox-job-{job_id}"]
    assert "--collect" in argv
    i = argv.index("/bin/bash")
    assert argv[i + 1] == "-c"
    assert argv[-2:] == ["bash", deploy], "deploy command passed through as argv"

    s = wait_done(runner)
    assert set(s) == SUMMARY_KEYS
    assert (s["status"], s["rc"], s["running"]) == ("degraded", 3, False)
    assert "deploying" in runner.log_tail(job_id)


def test_job_survives_a_panel_restart(tmp_path, fake_systemd_run):
    sdrun, _ = fake_systemd_run
    job_dir = str(tmp_path / "jobs")
    deploy = write_exec(tmp_path / "deploy.sh", "echo started; sleep 2; echo finished; exit 0\n")
    state = rc_file_unit_state(job_dir)

    panel_before = gui.JobRunner(job_dir=job_dir, systemd_run=sdrun, unit_state=state)
    job_id, err = panel_before.start("apply", ["bash", deploy])
    assert err is None
    del panel_before            # the panel restarts; the in-memory job is gone

    panel_after = gui.JobRunner(job_dir=job_dir, systemd_run=sdrun, unit_state=state)
    s = panel_after.current_summary()
    assert s["id"] == job_id and s["running"] is True and s["status"] == "running"
    assert panel_after.start("apply", ["bash", deploy]) == (None, "a job is already running")

    s = wait_done(panel_after)
    assert (s["id"], s["status"], s["rc"]) == (job_id, "ok", 0)
    log = panel_after.log_tail(job_id)
    assert "started" in log and "finished" in log
    assert s["elapsed"] >= 1


def test_job_that_vanished_without_exit_code_is_failed_not_unknown(tmp_path):
    job_dir = tmp_path / "jobs"
    job_dir.mkdir()
    meta = {"id": "20261005-120000", "name": "apply",
            "log": str(job_dir / "20261005-120000-apply.log"),
            "rc_file": str(job_dir / "20261005-120000-apply.rc"),
            "started": time.time() - 30, "unit": "loxprox-job-20261005-120000", "pid": None}
    (job_dir / "20261005-120000-apply.json").write_text(json.dumps(meta))
    (job_dir / "20261005-120000-apply.log").write_text("half a deploy\n")

    runner = gui.JobRunner(job_dir=str(job_dir), systemd_run="/bin/false",
                           unit_state=lambda unit: "inactive")
    s = runner.current_summary()
    assert set(s) == SUMMARY_KEYS
    assert (s["running"], s["status"], s["rc"]) == (False, "failed", None)
    assert runner.log_tail("20261005-120000") == "half a deploy"


def test_systemctl_hiccup_never_marks_a_live_job_failed(tmp_path):
    job_dir = tmp_path / "jobs"
    job_dir.mkdir()
    meta = {"id": "20261005-130000", "name": "renew-tls",
            "log": str(job_dir / "20261005-130000-renew-tls.log"),
            "rc_file": str(job_dir / "20261005-130000-renew-tls.rc"),
            "started": time.time(), "unit": "loxprox-job-20261005-130000", "pid": None}
    (job_dir / "20261005-130000-renew-tls.json").write_text(json.dumps(meta))
    answers = iter(["systemctl: timeout", "active", "inactive"])
    runner = gui.JobRunner(job_dir=str(job_dir), systemd_run="/bin/false",
                           unit_state=lambda unit: next(answers))
    assert runner.current_summary()["running"] is True     # timeout → still running
    assert runner.current_summary()["running"] is True
    (job_dir / "20261005-130000-renew-tls.rc").write_text("0\n")
    s = runner.current_summary()
    assert (s["status"], s["rc"]) == ("ok", 0)


def test_without_systemd_run_the_job_is_a_detached_child(tmp_path):
    job_dir = str(tmp_path / "jobs")
    deploy = write_exec(tmp_path / "deploy.sh", "sleep 1; echo fallback; exit 1\n")
    runner = gui.JobRunner(job_dir=job_dir, systemd_run="")
    job_id, err = runner.start("apply", ["bash", deploy])
    assert err is None
    restarted = gui.JobRunner(job_dir=job_dir, systemd_run="")     # tracks it by pid
    assert restarted.current_summary()["running"] is True
    s = wait_done(restarted)
    assert (s["status"], s["rc"]) == ("failed", 1)
    assert "fallback" in restarted.log_tail(job_id)


def test_job_arguments_are_never_shell_evaluated(tmp_path):
    job_dir = str(tmp_path / "jobs")
    canary = tmp_path / "PWNED"
    deploy = write_exec(tmp_path / "deploy.sh", 'printf "arg=%s\\n" "$1"\n')
    hostile = f"$(touch {canary}); `touch {canary}`"
    runner = gui.JobRunner(job_dir=job_dir, systemd_run="")
    job_id, _ = runner.start("apply", ["bash", deploy, hostile])
    s = wait_done(runner)
    assert s["status"] == "ok"
    assert not canary.exists()
    assert f"arg={hostile}" in runner.log_tail(job_id)


def test_failed_systemd_run_leaves_no_phantom_job(tmp_path):
    job_dir = tmp_path / "jobs"
    failing = write_exec(tmp_path / "systemd-run", "echo 'Failed to start transient unit' >&2; exit 1\n")
    runner = gui.JobRunner(job_dir=str(job_dir), systemd_run=failing)
    job_id, err = runner.start("apply", ["bash", "/nonexistent/deploy.sh"])
    assert job_id is None and "systemd-run failed" in err
    assert not list(job_dir.glob("*.json"))
    assert gui.JobRunner(job_dir=str(job_dir), systemd_run=failing).current_summary() is None


def test_persisted_job_pointing_outside_job_dir_is_ignored(tmp_path):
    job_dir = tmp_path / "jobs"
    job_dir.mkdir()
    meta = {"id": "20261005-140000", "name": "apply", "log": "/etc/shadow",
            "rc_file": str(job_dir / "x.rc"), "started": time.time(), "unit": None, "pid": None}
    (job_dir / "20261005-140000-apply.json").write_text(json.dumps(meta))
    runner = gui.JobRunner(job_dir=str(job_dir), systemd_run="")
    assert runner.current_summary() is None
    assert runner.log_tail("20261005-140000") is None


def test_old_job_files_are_pruned(tmp_path):
    job_dir = tmp_path / "jobs"
    job_dir.mkdir()
    for i in range(30):
        jid = f"20260101-{i:06d}"
        for ext in (".log", ".rc", ".json"):
            (job_dir / f"{jid}-apply{ext}").write_text("0\n" if ext == ".rc" else "{}")
    deploy = write_exec(tmp_path / "deploy.sh", "exit 0\n")
    runner = gui.JobRunner(job_dir=str(job_dir), systemd_run="")
    job_id, _ = runner.start("apply", ["bash", deploy])
    wait_done(runner)
    ids = {n[:15] for n in os.listdir(job_dir)}
    assert len(ids) == gui.JOB_KEEP
    assert job_id in ids and "20260101-000029" in ids and "20260101-000000" not in ids


def test_module_runner_uses_systemd_run_when_present():
    # Production wiring: the module-level runner looks systemd-run up itself.
    import shutil
    assert gui.JOBS._systemd_run == shutil.which("systemd-run")
    assert gui.JOBS._job_dir == gui.JOB_DIR
