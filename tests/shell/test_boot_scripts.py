"""The panic script and the ZFS load-key extension under dash and busybox sh.

The panic script's exit paths (DESIGN.md 7.3; scenarios T9 and T28 at the process level): under
`tpm` it wipes and returns, so panic() can open its shell; under `measured`, or with
`tailnet-unlock.noshell` on the command line, it wipes, reboots and never returns. The reboot and
the sysrq trigger are files in the sandbox.
"""

import os
import pty
import select
import shutil
import signal
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from shellenv import (
    Sandbox,
    Shell,
    available_shells,
    copy_script,
    make_sandbox,
    set_dataset,
)

APPLETS = Path(os.environ.get("TU_TEST_APPLETS", "/tmp/tailnet-unlock-applets"))
SHELLS = available_shells(APPLETS)
pytestmark = pytest.mark.skipif(not SHELLS, reason="neither dash nor busybox is installed")


@pytest.fixture(params=SHELLS, ids=[shell.name for shell in SHELLS])
def shell(request: pytest.FixtureRequest) -> Shell:
    chosen: Shell = request.param
    return chosen


def environment(shell: Shell, box: Sandbox) -> dict[str, str]:
    return {"PATH": shell.path, "LC_ALL": "C", "HOME": str(box.root)}


@pytest.fixture
def daemons(tmp_path: Path) -> Iterator[list[subprocess.Popen[bytes]]]:
    """Three stand-in processes: the supervisor, dropbear and tailscaled.

    Each is `sleep` under the name of the process it stands for: the scripts only signal a PID
    whose command line carries that name.
    """
    sleep = shutil.which("sleep")
    assert sleep is not None
    started = [
        subprocess.Popen([name, "300"], executable=sleep)
        for name in ("supervise", "dropbear", "tailscaled")
    ]
    yield started
    for process in started:
        if process.poll() is None:
            process.kill()
        process.wait()


def record_daemons(box: Sandbox, daemons: list[subprocess.Popen[bytes]]) -> None:
    supervisor, dropbear, tailscaled = daemons
    (box.run / "supervise.pid").write_text(f"{supervisor.pid}\n")
    (box.run / "dropbear.child").write_text(f"{dropbear.pid}\n")
    (box.run / "tailscaled.child").write_text(f"{tailscaled.pid}\n")
    (box.run / "door_key").write_bytes(b"\x00\x00\x00\x0bssh-ed25519" + b"K" * 68)
    (box.run / "unlock.state").write_text("sealed node state\n")


def assert_wiped(box: Sandbox, daemons: list[subprocess.Popen[bytes]]) -> None:
    for process in daemons:
        process.wait(timeout=20)
    assert not (box.run / "door_key").exists()
    assert not (box.run / "unlock.state").exists()
    assert not (box.run / "dropbear.child").exists()


def test_panic_under_tpm_wipes_and_returns(
    tmp_path: Path, shell: Shell, daemons: list[subprocess.Popen[bytes]]
) -> None:
    box = make_sandbox(tmp_path)
    record_daemons(box, daemons)
    script = copy_script(box, "panic")
    completed = subprocess.run(
        [*shell.argv, str(script)],
        env=environment(shell, box),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0
    assert_wiped(box, daemons)
    assert "stopped and wiped before the shell opens" in box.console.read_text()
    assert not (box.root / "reboots").exists()


@pytest.mark.parametrize("how", ["measured profile", "noshell on the command line"])
def test_panic_under_noshell_wipes_reboots_and_never_returns(
    tmp_path: Path, shell: Shell, daemons: list[subprocess.Popen[bytes]], how: str
) -> None:
    if how == "measured profile":
        box = make_sandbox(tmp_path, {"TU_PROFILE": "measured"})
    else:
        box = make_sandbox(tmp_path)
        box.cmdline.write_text("BOOT_IMAGE=/vmlinuz ro tailnet-unlock.noshell quiet\n")
    record_daemons(box, daemons)
    script = copy_script(box, "panic")
    process = subprocess.Popen(
        [*shell.argv, str(script)],
        env=environment(shell, box),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (box.root / "sysrq-trigger").exists():
            time.sleep(0.2)
        assert (box.root / "reboots").read_text().strip() == "reboot -f"
        assert (box.root / "sysrq-trigger").read_text().strip() == "b"
        assert_wiped(box, daemons)
        for signal_number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            process.send_signal(signal_number)
        time.sleep(1)
        assert process.poll() is None, "the panic script returned, so panic() would open a shell"
        assert "No shell under the measured profile" in box.console.read_text()
    finally:
        process.kill()
        process.wait()


def test_wipe_leaves_a_process_that_reused_a_recorded_pid(
    tmp_path: Path, shell: Shell, daemons: list[subprocess.Popen[bytes]]
) -> None:
    """A PID in a state file may belong to another process by now; it is never signalled."""
    box = make_sandbox(tmp_path)
    record_daemons(box, daemons)
    stranger = subprocess.Popen(["sleep", "300"])
    try:
        (box.run / "dropbear.child").write_text(f"{stranger.pid}\n")
        script = copy_script(box, "panic")
        completed = subprocess.run(
            [*shell.argv, str(script)],
            env=environment(shell, box),
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert completed.returncode == 0
        assert stranger.poll() is None, "a recorded PID that is not dropbear was killed"
        for process in (daemons[0], daemons[2]):
            process.wait(timeout=20)
    finally:
        stranger.kill()
        stranger.wait()


def start_panic(box: Sandbox, shell: Shell) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [*shell.argv, str(copy_script(box, "panic"))],
        env=environment(shell, box),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def assert_rebooted_and_stays(
    box: Sandbox, process: subprocess.Popen[bytes], daemons: list[subprocess.Popen[bytes]]
) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not (box.root / "sysrq-trigger").exists():
        time.sleep(0.2)
    assert (box.root / "reboots").read_text().strip() == "reboot -f"
    assert_wiped(box, daemons)
    time.sleep(1)
    assert process.poll() is None, "the panic script returned, so panic() would open a shell"


def test_panic_ignores_signals_from_its_first_statement(
    tmp_path: Path, shell: Shell, daemons: list[subprocess.Popen[bytes]]
) -> None:
    """The command line is read through a pipe that blocks: signals sent meanwhile do nothing."""
    box = make_sandbox(tmp_path)
    box.cmdline.unlink()
    os.mkfifo(box.cmdline)
    record_daemons(box, daemons)
    process = start_panic(box, shell)
    try:
        time.sleep(1.5)
        for signal_number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            process.send_signal(signal_number)
        time.sleep(0.5)
        assert process.poll() is None, "a signal ended the panic script before it was ready"
        with box.cmdline.open("w") as writer:
            writer.write("BOOT_IMAGE=/vmlinuz ro tailnet-unlock.noshell quiet\n")
        assert_rebooted_and_stays(box, process, daemons)
    finally:
        process.kill()
        process.wait()


@pytest.mark.parametrize("broken", ["paths.sh", "lib.sh", "conf", "cmdline"])
def test_panic_with_a_damaged_file_wipes_reboots_and_never_returns(
    tmp_path: Path, shell: Shell, daemons: list[subprocess.Popen[bytes]], broken: str
) -> None:
    """Under `tpm`, where the shell would open: a shared file that will not source means noshell."""
    box = make_sandbox(tmp_path)
    record_daemons(box, daemons)
    garbage = "if then fi ) (\n"
    if broken == "paths.sh":
        original = (box.lib / "paths.sh").read_text()
        # a damaged paths.sh cannot say where the reboot is: keep the assignments, break the rest
        (box.lib / "paths.sh").write_text(original + garbage)
    elif broken == "lib.sh":
        (box.lib / "lib.sh").write_text(garbage)
    elif broken == "conf":
        box.conf.write_text(garbage)
    else:
        box.cmdline.unlink()
    script = copy_script(box, "panic")
    if broken == "paths.sh":
        # without paths.sh the script reboots with `reboot` from PATH: put the sandbox one there
        shell = Shell(shell.name, shell.argv, f"{box.bin}:{shell.path}")
    process = subprocess.Popen(
        [*shell.argv, str(script)],
        env=environment(shell, box),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and not (box.root / "reboots").exists():
            time.sleep(0.2)
        assert (box.root / "reboots").read_text().startswith("reboot -f")
        assert_wiped(box, daemons)
        time.sleep(1)
        assert process.poll() is None, "the panic script returned, so panic() would open a shell"
    finally:
        process.kill()
        process.wait()


def no_door_box(tmp_path: Path, how: str) -> Sandbox:
    """An image without a door: no paths.sh, no lib.sh, no run directory (the hook copies none)."""
    box = make_sandbox(tmp_path)
    box.run.rmdir()
    (box.lib / "paths.sh").unlink()
    (box.lib / "lib.sh").unlink()
    if how == "no configuration":
        box.conf.unlink()
    else:
        box.conf.write_text("TU_PROFILE='tpm'\nTU_DOOR='none'\n")
    return box


@pytest.mark.parametrize("how", ["no configuration", "TU_DOOR none"])
def test_panic_without_a_door_returns_and_opens_the_shell(
    tmp_path: Path, shell: Shell, how: str
) -> None:
    box = no_door_box(tmp_path, how)
    script = copy_script(box, "panic")
    completed = subprocess.run(
        [*shell.argv, str(script)],
        env=environment(shell, box),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0
    assert not (box.root / "reboots").exists()


@pytest.mark.parametrize("how", ["no configuration", "TU_DOOR none", "measured profile"])
def test_panic_without_a_door_still_honours_noshell(tmp_path: Path, shell: Shell, how: str) -> None:
    box = no_door_box(tmp_path, how)
    if how == "measured profile":
        box.conf.write_text("TU_PROFILE='measured'\nTU_DOOR='none'\n")
    else:
        box.cmdline.write_text("BOOT_IMAGE=/vmlinuz ro tailnet-unlock.noshell quiet\n")
    shell = Shell(shell.name, shell.argv, f"{box.bin}:{shell.path}")
    process = start_panic(box, shell)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (box.root / "reboots").exists():
            time.sleep(0.2)
        assert (box.root / "reboots").read_text().startswith("reboot -f")
        time.sleep(1)
        assert process.poll() is None, "the panic script returned, so panic() would open a shell"
    finally:
        process.kill()
        process.wait()


def run_extension(
    box: Sandbox, shell: Shell, keylocation: str, console: str | None = None
) -> subprocess.Popen[bytes]:
    """Source the extension in a subshell, the way decrypt_fs in OpenZFS's scripts/zfs does."""
    script = copy_script(box, "zfs-load-key")
    if console is not None:
        paths = box.lib / "paths.sh"
        paths.write_text(
            paths.read_text().replace(f"TU_CONSOLE='{box.console}'", f"TU_CONSOLE='{console}'")
        )
    caller = (
        f'ENCRYPTIONROOT=rpool; KEYLOCATION="{keylocation}"; '
        f'(. "{script}"); echo "rc=$?" >"{box.root}/extension.rc"'
    )
    return subprocess.Popen(
        [*shell.argv, "-c", caller],
        env=environment(shell, box),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def extension_rc(box: Sandbox, process: subprocess.Popen[bytes], timeout: float = 30) -> str:
    process.wait(timeout=timeout)
    return (box.root / "extension.rc").read_text().strip()


def wait_for(path: Path, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not path.exists():
        time.sleep(0.1)
    assert path.exists(), path


def test_extension_waits_until_the_door_loads_the_key(tmp_path: Path, shell: Shell) -> None:
    box = make_sandbox(tmp_path)
    process = run_extension(box, shell, "prompt")
    wait_for(box.run / "waiting_for")
    assert (box.run / "waiting_for").read_text().strip() == "rpool"
    assert (box.run / "keyformat").read_text().strip() == "passphrase"
    time.sleep(2)
    assert process.poll() is None
    (box.zfs_state / "keystatus").write_text("available\n")
    assert extension_rc(box, process) == "rc=0"
    assert not (box.run / "waiting_for").exists()


def test_extension_steps_aside_for_a_local_key(tmp_path: Path, shell: Shell) -> None:
    box = make_sandbox(tmp_path)
    key = box.root / "local.key"
    key.write_text("local key\n")
    process = run_extension(box, shell, f"file://{key}")
    assert extension_rc(box, process) == "rc=1"
    assert (box.run / "unlocked_by").read_text().strip() == "local"
    assert not (box.run / "waiting_for").exists()


def test_rehearsal_waits_then_lets_the_local_key_load(tmp_path: Path, shell: Shell) -> None:
    box = make_sandbox(tmp_path, {"TU_REHEARSAL_MINUTES": "3"})
    key = box.root / "local.key"
    key.write_text("local key\n")
    started = time.monotonic()
    process = run_extension(box, shell, f"file://{key}")
    wait_for(box.run / "waiting_for")
    assert extension_rc(box, process) == "rc=1"
    assert time.monotonic() - started >= 3
    assert (box.run / "unlocked_by").read_text().strip() == "local"
    assert "rehearsal" in box.console.read_text()


def test_extension_returns_1_without_a_door(tmp_path: Path, shell: Shell) -> None:
    box = make_sandbox(tmp_path)
    box.run.rmdir()
    process = run_extension(box, shell, "prompt")
    assert extension_rc(box, process) == "rc=1"


def read_until(controller: int, marker: bytes, timeout: float = 15) -> bytes:
    seen = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and marker not in seen:
        ready, _, _ = select.select([controller], [], [], 0.2)
        if ready:
            seen += os.read(controller, 4096)
    assert marker in seen, seen
    return seen


def test_console_prompt_asks_again_after_a_wrong_key(tmp_path: Path, shell: Shell) -> None:
    """T27, console half: a wrong key at the console is not an exit; the right one unlocks."""
    box = make_sandbox(tmp_path)
    controller, terminal = pty.openpty()
    process = run_extension(box, shell, "prompt", console=os.ttyname(terminal))
    try:
        read_until(controller, b"Key for rpool")
        os.write(controller, b"wrong horse battery\n")
        seen = read_until(controller, b"did not load")
        # the next prompt may arrive in the same read as the refusal
        if b"Key for rpool" not in seen.split(b"did not load", 1)[1]:
            read_until(controller, b"Key for rpool")
        os.write(controller, b"correct horse battery\n")
        assert extension_rc(box, process) == "rc=0"
        assert (box.run / "unlocked_by").read_text().strip() == "console"
        assert (box.zfs_state / "received").read_bytes() == b"correct horse battery"
    finally:
        if process.poll() is None:
            process.kill()
        os.close(controller)
        os.close(terminal)


def test_no_console_prompt_for_a_raw_key(tmp_path: Path, shell: Shell) -> None:
    box = make_sandbox(tmp_path)
    set_dataset(box, "rpool", "raw", bytes(range(32)))
    process = run_extension(box, shell, "prompt")
    wait_for(box.run / "waiting_for")
    (box.zfs_state / "keystatus").write_text("available\n")
    assert extension_rc(box, process) == "rc=0"
    assert "cannot be typed" in box.console.read_text()


def test_extension_says_so_when_the_door_cannot_be_told(tmp_path: Path, shell: Shell) -> None:
    """A state file that cannot be written (a full tmpfs) is reported; the prompt still works."""
    box = make_sandbox(tmp_path)
    set_dataset(box, "rpool", "raw", bytes(range(32)))
    (box.run / ".waiting_for.new").symlink_to("/dev/full")
    process = run_extension(box, shell, "prompt")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and "cannot record" not in box.console.read_text():
        time.sleep(0.2)
    assert "cannot record the encryption root" in box.console.read_text()
    assert not (box.run / "waiting_for").exists()
    (box.zfs_state / "keystatus").write_text("available\n")
    assert extension_rc(box, process) == "rc=0"


def test_a_failed_put_is_reported_and_leaves_no_temporary_file(
    tmp_path: Path, shell: Shell
) -> None:
    box = make_sandbox(tmp_path)
    snippet = (
        f'. "{box.lib}/paths.sh"; . "{box.lib}/lib.sh"; '
        'tu_put seal ok; echo "first=$?"; tu_put seal bad; echo "second=$?"'
    )
    # a temporary file that cannot take a write, as on a full tmpfs
    (box.run / ".seal.new").symlink_to("/dev/full")
    completed = subprocess.run(
        [*shell.argv, "-c", snippet],
        env=environment(shell, box),
        capture_output=True,
        timeout=30,
        check=False,
    )
    out = completed.stdout.decode()
    assert "first=1" in out
    assert "second=0" in out, "the failed write left its temporary file in the way"
    assert (box.run / "seal").read_text().strip() == "bad"
    assert not (box.run / ".seal.new").exists()
