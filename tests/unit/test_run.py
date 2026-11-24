"""Running a program: bounded, no shell, the whole process group ends (DESIGN.md 10.2, 10.3)."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from shellenv import REPO
from tailnet_unlock.errors import ToolError
from tailnet_unlock.keyholder.run import run_bounded


def sh(script: str) -> tuple[str, ...]:
    return ("sh", "-c", script)


def gone(pid: int, timeout: float = 5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
        except OSError:
            return True
        if state == "Z":
            return True
        time.sleep(0.05)
    return False


def test_output_exit_code_and_stdin() -> None:
    ran = run_bounded(sh("cat; exit 3"), b"x" * 300_000, timeout=20, max_stdout=1_000_000)
    assert (ran.exit_code, ran.stdout) == (3, b"x" * 300_000)
    ran = run_bounded(sh("exit 0"), b"x" * 300_000, timeout=20)
    assert ran.exit_code == 0, "a program that never reads its stdin is no error"
    ran = run_bounded(sh("echo out; echo err >&2"), timeout=20, max_stdout=10, stderr="capture")
    assert (ran.stdout, ran.stderr) == (b"out\n", b"err\n")


def test_too_much_output_ends_the_program() -> None:
    started = time.monotonic()
    ran = run_bounded(sh("cat /dev/zero"), timeout=60, max_stdout=100)
    assert ran.exit_code == -9
    assert len(ran.stdout) == 101
    assert time.monotonic() - started < 20
    noisy = run_bounded(
        sh("head -c 500000 /dev/zero >&2"), timeout=20, max_stdout=100, stderr="capture"
    )
    assert (noisy.exit_code, len(noisy.stderr)) == (0, 16384)


def test_exactly_enough_output() -> None:
    ran = run_bounded(sh("head -c 100 /dev/zero"), timeout=20, max_stdout=100)
    assert (ran.exit_code, len(ran.stdout)) == (0, 100)
    ran = run_bounded(sh("head -c 101 /dev/zero"), timeout=20, max_stdout=100)
    assert len(ran.stdout) == 101


def test_a_hooks_output_goes_to_stderr() -> None:
    script = (
        "from tailnet_unlock.keyholder.run import run_bounded\n"
        "assert run_bounded(('echo', 'hook says'), timeout=20).stdout == b''\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
    )
    assert (done.stdout, done.stderr) == (b"", b"hook says\n")


def test_the_timeout_ends_the_whole_group(tmp_path: Path) -> None:
    pids = tmp_path / "pids"
    started = time.monotonic()
    ran = run_bounded(
        sh(f"trap '' TERM; sleep 60 & echo $! $$ >{pids}; wait; sleep 60"), timeout=1, grace=0.5
    )
    assert ran.exit_code is None
    assert time.monotonic() - started < 10
    assert all(gone(int(pid)) for pid in pids.read_text().split())


def test_the_group_gets_time_to_clean_up(tmp_path: Path) -> None:
    note = tmp_path / "note"
    ran = run_bounded(
        sh(f"trap 'echo cancelled >{note}; exit 0' TERM; echo ready; sleep 60 & wait"),
        timeout=1,
        max_stdout=100,
        grace=10,
    )
    assert ran.exit_code is None, "a program stopped at its timeout has no exit code"
    assert note.read_text() == "cancelled\n"


def test_a_straggler_does_not_outlive_the_program(tmp_path: Path) -> None:
    pid = tmp_path / "pid"
    started = time.monotonic()
    ran = run_bounded(sh(f"sleep 60 & echo $! >{pid}; echo done"), timeout=20, max_stdout=100)
    assert (ran.exit_code, ran.stdout) == (0, b"done\n")
    assert time.monotonic() - started < 10, "it waited for the straggler's end of the pipe"
    assert gone(int(pid.read_text()))


def test_a_straggler_that_never_stops_printing() -> None:
    started = time.monotonic()
    ran = run_bounded(
        sh("cat /dev/zero >&2 & echo done"), timeout=30, max_stdout=100, stderr="capture"
    )
    assert (ran.exit_code, ran.stdout) == (0, b"done\n")
    assert time.monotonic() - started < 10


def test_a_program_that_cannot_start_names_only_itself() -> None:
    with pytest.raises(ToolError) as caught:
        run_bounded(("/no/such/program", "an argument"), b"secret-key-bytes", timeout=5)
    assert "/no/such/program" in str(caught.value)
    assert "argument" not in str(caught.value)
    assert "secret" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_a_stop_ends_the_group_first(tmp_path: Path, signum: signal.Signals) -> None:
    """The parent is told to stop while its program runs: the program gets SIGTERM, time, and
    the parent leaves with 128 plus the signal."""
    note, ready = tmp_path / "note", tmp_path / "ready"
    script = (
        "from tailnet_unlock.keyholder import cli, run\n"
        "cli._stop_cleanly()\n"
        f"run.run_bounded(('sh', '-c', 'trap \"sleep 1; echo cancelled >{note}; exit 0\" TERM; "
        f"echo $$ >{ready}; sleep 60 & wait'), timeout=60)\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script], env={**os.environ, "PYTHONPATH": str(REPO / "src")}
    )
    deadline = time.monotonic() + 20
    while not (ready.exists() and ready.read_text()) and time.monotonic() < deadline:
        time.sleep(0.05)
    process.send_signal(signum)
    time.sleep(0.3)
    process.send_signal(signal.SIGTERM)  # a second signal does not cut the cleanup short
    assert process.wait(timeout=20) == 128 + signum
    assert note.read_text() == "cancelled\n"
    assert gone(int(ready.read_text()))
