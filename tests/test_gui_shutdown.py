"""Panel shutdown on SIGTERM — 2026-10 fix.

The SIGTERM handler called server.shutdown() inline. Signal handlers run in
the main thread, which is the one inside serve_forever(), and shutdown()
waits for serve_forever() to return: the panel waited for itself, every
`systemctl stop/restart loxprox-gui` hung until the stop timeout and ended in
SIGKILL (90 s per deploy; during a reboot it held nginx's stop back).

These tests start the real gui/loxprox-gui.py as a process (temporary config
and state dir, a free port), send SIGTERM and time the exit. A control runs
the same server with the old inline handler and shows it does not exit.
"""

import os
import signal
import socket
import subprocess
import sys
import textwrap
import time

import pytest

GUI = os.path.join(os.path.dirname(__file__), "..", "gui", "loxprox-gui.py")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def panel_env(tmp_path):
    port = free_port()
    conf = tmp_path / "deploy.conf"
    conf.write_text(f'ENABLE_GUI="true"\nGUI_PORT="{port}"\n')
    env = dict(os.environ,
               LOXPROX_DEPLOY_CONF=str(conf),
               LOXPROX_RUNTIME_CONF=str(tmp_path / "config.env"),
               LOXPROX_STATE_DIR=str(tmp_path / "state"))
    return env, port


def wait_listening(proc, port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"panel exited early: {proc.communicate()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("panel never started listening")


def test_sigterm_stops_the_panel_promptly(panel_env, tmp_path):
    env, port = panel_env
    proc = subprocess.Popen([sys.executable, GUI], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        wait_listening(proc, port)
        start = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=10)
        took = time.monotonic() - start
    finally:
        if proc.poll() is None:
            proc.kill()
    out = proc.stdout.read()
    assert rc == 0, out
    assert took < 3, f"SIGTERM took {took:.1f}s"
    assert "LoxProx Panel stopped." in out
    assert (tmp_path / "state" / "gui-history.json").exists(), "history saved on shutdown"
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()


def test_control_inline_shutdown_in_the_handler_deadlocks(panel_env):
    """The pre-fix handler, reproduced: it never returns on its own."""
    env, port = panel_env
    script = textwrap.dedent(f"""
        import importlib.util, signal, sys
        spec = importlib.util.spec_from_file_location("panel", {GUI!r})
        panel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(panel)
        server = panel.PanelServer(("127.0.0.1", {port}), panel.PanelHandler)
        signal.signal(signal.SIGTERM, lambda *_: server.shutdown())   # old code
        server.serve_forever()
    """)
    proc = subprocess.Popen([sys.executable, "-c", script], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_listening(proc, port)
        proc.send_signal(signal.SIGTERM)
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(timeout=3)
    finally:
        proc.kill()
        proc.wait(timeout=10)
