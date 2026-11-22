"""The supervisor under dash and busybox sh, with stand-ins for dropbear and the unseal step.

What this covers, at the process level: no daemon output is kept (a flood cannot fill the door's
tmpfs); a daemon is never left running when the file that records its PID could not be written;
a TPM that refused at boot is asked again, and the door moves to the sealed key when it answers
(DESIGN.md 7.3, step 2).
"""

import os
import signal
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from shellenv import Sandbox, Shell, available_shells, make_sandbox

APPLETS = Path(os.environ.get("TU_TEST_APPLETS", "/tmp/tailnet-unlock-applets"))
SHELLS = available_shells(APPLETS)
pytestmark = pytest.mark.skipif(not SHELLS, reason="neither dash nor busybox is installed")

STUB_DROPBEAR = """#!/bin/sh
# a stand-in for dropbear: notes which key it was given, writes its PID file, then idles
while [ $# -gt 0 ]; do
	case "$1" in
	-P) pidfile=$2; shift ;;
	-r) key=$2; shift ;;
	esac
	shift
done
cat "$key" >>"@ROOT@/keys"
echo >>"@ROOT@/keys"
echo $$ >>"@ROOT@/pids"
echo $$ >"$pidfile"
if [ -n "${TU_STUB_FLOOD-}" ]; then
	head -c 3000000 /dev/zero | tr '\\0' x >&2
fi
while :; do sleep 1; done
"""

STUB_UNSEAL = """#!/bin/sh
[ -e "@ROOT@/unseal-ok" ] || exit 3
printf 'SEALED-KEY' >"$2"
"""


@pytest.fixture(params=SHELLS, ids=[shell.name for shell in SHELLS])
def shell(request: pytest.FixtureRequest) -> Shell:
    chosen: Shell = request.param
    return chosen


def write_script(path: Path, text: str, root: Path) -> None:
    path.write_text(text.replace("@ROOT@", str(root)))
    path.chmod(0o755)


def door_box(tmp_path: Path) -> Sandbox:
    box = make_sandbox(tmp_path)
    write_script(box.bin / "dropbear", STUB_DROPBEAR, box.root)
    write_script(box.lib / "unseal", STUB_UNSEAL, box.root)
    etc = box.root / "etc"
    (etc / "door.tpm").mkdir(parents=True)
    (etc / "recovery_host_key").write_text("RECOVERY-KEY")
    (box.root / "tpmrm0").write_text("")
    return box


def start_supervisor(box: Sandbox, shell: Shell, flood: bool = False) -> subprocess.Popen[bytes]:
    environment = {"PATH": f"{box.bin}:{shell.path}", "LC_ALL": "C", "HOME": str(box.root)}
    if flood:
        environment["TU_STUB_FLOOD"] = "1"
    return subprocess.Popen(
        [*shell.argv, str(box.lib / "supervise")],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_until(condition: Callable[[], bool], timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.2)
    raise AssertionError("timed out")


def alive(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(") ", 1)[1].split()[0] not in ("Z", "X")


def pids(box: Sandbox) -> list[int]:
    path = box.root / "pids"
    return [int(line) for line in path.read_text().split()] if path.exists() else []


def stop(process: subprocess.Popen[bytes], box: Sandbox) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for pid in pids(box):
        if alive(pid):
            os.kill(pid, signal.SIGKILL)


@pytest.fixture
def running() -> Iterator[list[tuple[subprocess.Popen[bytes], Sandbox]]]:
    started: list[tuple[subprocess.Popen[bytes], Sandbox]] = []
    yield started
    for process, box in started:
        stop(process, box)


def test_a_flood_from_the_daemons_cannot_fill_the_state_directory(
    tmp_path: Path, shell: Shell, running: list[tuple[subprocess.Popen[bytes], Sandbox]]
) -> None:
    box = door_box(tmp_path)
    process = start_supervisor(box, shell, flood=True)
    running.append((process, box))
    wait_until((box.run / "dropbear.pid").exists)
    time.sleep(2)
    used = sum(path.stat().st_size for path in box.run.rglob("*") if path.is_file())
    assert used < 4096, f"{used} bytes in the state directory after a 3 MB flood"
    assert not list(box.run.glob("*.log"))


def test_a_daemon_whose_pid_could_not_be_recorded_is_still_stopped(
    tmp_path: Path, shell: Shell, running: list[tuple[subprocess.Popen[bytes], Sandbox]]
) -> None:
    box = door_box(tmp_path)
    (box.run / ".dropbear.child.new").symlink_to("/dev/full")
    process = start_supervisor(box, shell)
    running.append((process, box))
    wait_until((box.run / "dropbear.pid").exists)
    assert not (box.run / "dropbear.child").exists(), "the record was meant to fail"
    assert "cannot record dropbear.child" in box.console.read_text()
    (daemon,) = pids(box)
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=30) == 0
    wait_until(lambda: not alive(daemon), timeout=10)


def test_a_tpm_that_refused_at_boot_is_asked_again(
    tmp_path: Path, shell: Shell, running: list[tuple[subprocess.Popen[bytes], Sandbox]]
) -> None:
    box = door_box(tmp_path)
    process = start_supervisor(box, shell)
    running.append((process, box))
    wait_until(lambda: len(pids(box)) == 1)
    assert (box.run / "seal").read_text().strip() == "unseal-failed"
    assert (box.run / "role").read_text().strip() == "recovery"
    (first,) = pids(box)
    (box.root / "unseal-ok").write_text("")
    wait_until(lambda: len(pids(box)) == 2, timeout=60)
    assert (box.run / "seal").read_text().strip() == "ok"
    assert (box.run / "role").read_text().strip() == "sealed"
    assert (box.root / "keys").read_text().split() == ["RECOVERY-KEY", "SEALED-KEY"]
    wait_until(lambda: not alive(first), timeout=10)
    second = pids(box)[1]
    assert alive(second)
    assert (box.run / "dropbear.child").read_text().strip() == str(second)
    wait_until(lambda: not (box.run / "door_key").exists(), timeout=10)
    assert "unsealed the door key on a retry" in box.console.read_text()


def test_no_retry_without_a_container(
    tmp_path: Path, shell: Shell, running: list[tuple[subprocess.Popen[bytes], Sandbox]]
) -> None:
    box = door_box(tmp_path)
    (box.root / "etc" / "door.tpm").rmdir()
    (box.root / "unseal-ok").write_text("")
    process = start_supervisor(box, shell)
    running.append((process, box))
    wait_until(lambda: len(pids(box)) == 1)
    time.sleep(6)
    assert (box.run / "seal").read_text().strip() == "no-container"
    assert len(pids(box)) == 1
