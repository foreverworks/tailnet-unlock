"""The door's forced command under dash and busybox sh (DESIGN.md 7.3 step 4; scenario T22)."""

import json
import os
import pty
import select
import subprocess
import time
from pathlib import Path

import pytest

from shellenv import (
    BOOT_ID,
    Sandbox,
    Shell,
    available_shells,
    make_sandbox,
    run_door,
    set_dataset,
    wait_for_root,
)
from tailnet_unlock.keyholder.doorstatus import parse_door_status

APPLETS = Path(os.environ.get("TU_TEST_APPLETS", "/tmp/tailnet-unlock-applets"))
SHELLS = available_shells(APPLETS)

pytestmark = pytest.mark.skipif(not SHELLS, reason="neither dash nor busybox is installed")


@pytest.fixture(params=SHELLS, ids=[shell.name for shell in SHELLS])
def shell(request: pytest.FixtureRequest) -> Shell:
    chosen: Shell = request.param
    return chosen


@pytest.fixture
def box(tmp_path: Path) -> Sandbox:
    sandbox = make_sandbox(tmp_path)
    (sandbox.run / "role").write_text("sealed\n")
    (sandbox.run / "seal").write_text("ok\n")
    return sandbox


def result(completed: subprocess.CompletedProcess[bytes]) -> str:
    lines = completed.stdout.decode().strip().splitlines()
    assert lines, completed.stderr.decode()
    parsed: object = json.loads(lines[-1])
    assert isinstance(parsed, dict)
    value: object = parsed["result"]
    assert isinstance(value, str)
    return value


HOSTILE = [
    ";id",
    "status;id",
    "status\nid",
    "status ",
    " status",
    "STATUS",
    "Status",
    "status\x01",
    "unlock",
    "unlock ",
    f"unlock  {BOOT_ID}",
    f"unlock {BOOT_ID} ",
    f"unlock {BOOT_ID};id",
    f"unlock {BOOT_ID}\nid",
    f"unlock {BOOT_ID.upper()}",
    f"unlock {BOOT_ID[:-1]}",
    f"unlock {BOOT_ID}0",
    "unlock " + BOOT_ID.replace("-", ""),
    "unlock " + "?" * 8 + "-????-????-????-" + "?" * 12,
    "unlock " + "*",
    "unlock $(touch @CANARY@)",
    "unlock `touch @CANARY@`",
    "$(touch @CANARY@)",
    "touch @CANARY@",
    "unlock\t" + BOOT_ID,
    "UNLOCK " + BOOT_ID,
    "unlock " + "6f1c2b3a-0d4e-4c5f-9a8b-7e6d5c4b3a2١",
    "unlock " + "6f1c2b3a-0d4e-4c5f-9a8b-7e6d5c4b3a2g",
    "*",
    "?",
    "[",
]


@pytest.mark.parametrize("command", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_commands_are_refused(box: Sandbox, shell: Shell, command: str) -> None:
    canary = box.root / "canary"
    wait_for_root(box, "rpool", "passphrase")
    for role in ("delivery", "operator"):
        completed = run_door(
            box,
            shell,
            role,
            command.replace("@CANARY@", str(canary)),
            stdin=b"correct horse battery",
        )
        assert completed.returncode == 4, completed.stdout
        assert result(completed) == "bad-command"
    assert not canary.exists()
    assert (box.zfs_state / "keystatus").read_text().strip() == "unavailable"
    assert not (box.zfs_state / "received").exists()


def test_unknown_role_is_refused(box: Sandbox, shell: Shell) -> None:
    completed = run_door(box, shell, "root", "status")
    assert completed.returncode == 4
    assert result(completed) == "bad-command"


def test_empty_command_is_refused_for_delivery_keys(box: Sandbox, shell: Shell) -> None:
    wait_for_root(box, "rpool", "passphrase")
    for command in (None, ""):
        completed = run_door(box, shell, "delivery", command, stdin=b"correct horse battery\n")
        assert completed.returncode == 4
        assert result(completed) == "bad-command"
        assert b"Key for" not in completed.stdout
    assert not (box.zfs_state / "received").exists()


def test_empty_command_without_a_terminal_is_refused(box: Sandbox, shell: Shell) -> None:
    completed = run_door(box, shell, "operator", None, stdin=b"correct horse battery\n")
    assert completed.returncode == 4
    assert result(completed) == "bad-command"


def test_status_is_one_valid_line(box: Sandbox, shell: Shell) -> None:
    wait_for_root(box, "rpool", "passphrase")
    completed = run_door(box, shell, "delivery", "status")
    assert completed.returncode == 0, completed.stderr
    lines = completed.stdout.splitlines()
    assert len(lines) == 1
    status = parse_door_status(lines[0])
    assert status["key"] == "sealed"
    assert status["boot_id"] == BOOT_ID
    assert status["waiting_for"] == "rpool"
    assert status["keyformat"] == "passphrase"
    assert status["restarts"] == {"dropbear": 0, "tailscaled": 0}


def test_status_reports_degradations_and_recovery(tmp_path: Path, shell: Shell) -> None:
    box = make_sandbox(tmp_path, {"TU_DEGRADED": "tailscaled-missing boot-space"})
    (box.run / "role").write_text("recovery\n")
    (box.run / "seal").write_text("unseal-failed\n")
    (box.run / "degraded").write_text("tailnet-down\n")
    (box.run / "restarts.dropbear").write_text("2\n")
    completed = run_door(box, shell, "operator", "status")
    status = parse_door_status(completed.stdout.strip())
    assert status["key"] == "recovery"
    assert status["seal"] == "unseal-failed"
    assert status["degraded"] == ["tailscaled-missing", "boot-space", "tailnet-down"]
    assert status["waiting_for"] is None
    assert status["restarts"]["dropbear"] == 2


def test_status_escapes_what_it_cannot_print(box: Sandbox, shell: Shell) -> None:
    (box.run / "waiting_for").write_text('rpool"},"key":"sealed\n')
    completed = run_door(box, shell, "delivery", "status")
    status = parse_door_status(completed.stdout.strip())
    assert status["waiting_for"] == "rpool????key?:?sealed"


def test_unlock_with_the_right_boot_id_loads_the_key(box: Sandbox, shell: Shell) -> None:
    wait_for_root(box, "rpool", "passphrase")
    completed = run_door(
        box, shell, "delivery", f"unlock {BOOT_ID}", stdin=b"correct horse battery"
    )
    assert completed.returncode == 0, completed.stderr
    assert result(completed) == "loaded"
    assert (box.zfs_state / "keystatus").read_text().strip() == "available"
    assert (box.zfs_state / "received").read_bytes() == b"correct horse battery"
    assert (box.run / "unlocked_by").read_text().strip() == "sealed"


def test_a_wrong_boot_id_is_refused_before_any_key_is_read(box: Sandbox, shell: Shell) -> None:
    wait_for_root(box, "rpool", "passphrase")
    other = "0b9d1c6e-7a2f-4e1d-9c3b-5a7e8f60d4c2"
    completed = run_door(box, shell, "delivery", f"unlock {other}", stdin=b"correct horse battery")
    assert completed.returncode == 3
    assert result(completed) == "boot-mismatch"
    assert not (box.zfs_state / "received").exists()


def test_a_wrong_key_is_not_an_exit(box: Sandbox, shell: Shell) -> None:
    """T27: the door answers wrong-key, the wait goes on, the right key then loads."""
    wait_for_root(box, "rpool", "passphrase")
    wrong = run_door(box, shell, "delivery", f"unlock {BOOT_ID}", stdin=b"wrong horse battery")
    assert wrong.returncode == 1
    assert result(wrong) == "wrong-key"
    assert (box.run / "waiting_for").exists()
    right = run_door(box, shell, "delivery", f"unlock {BOOT_ID}", stdin=b"correct horse battery")
    assert result(right) == "loaded"


def test_not_waiting_when_no_root_is_named(box: Sandbox, shell: Shell) -> None:
    started = time.monotonic()
    completed = run_door(
        box, shell, "delivery", f"unlock {BOOT_ID}", stdin=b"correct horse battery"
    )
    assert completed.returncode == 2
    assert result(completed) == "not-waiting"
    assert time.monotonic() - started >= 2
    assert not (box.zfs_state / "received").exists()


def test_not_waiting_when_the_key_is_already_loaded(box: Sandbox, shell: Shell) -> None:
    wait_for_root(box, "rpool", "passphrase")
    (box.zfs_state / "keystatus").write_text("available\n")
    completed = run_door(
        box, shell, "delivery", f"unlock {BOOT_ID}", stdin=b"correct horse battery"
    )
    assert result(completed) == "not-waiting"


def test_at_most_512_bytes_reach_zfs(box: Sandbox, shell: Shell) -> None:
    wait_for_root(box, "rpool", "passphrase")
    completed = run_door(box, shell, "delivery", f"unlock {BOOT_ID}", stdin=b"x" * 5000)
    assert result(completed) == "wrong-key"
    assert len((box.zfs_state / "received").read_bytes()) == 512


def test_passphrase_with_a_trailing_newline_loads(box: Sandbox, shell: Shell) -> None:
    """The door passes bytes through; libzfs trims one newline for passphrase and hex keys."""
    wait_for_root(box, "rpool", "passphrase")
    completed = run_door(
        box, shell, "delivery", f"unlock {BOOT_ID}", stdin=b"correct horse battery\n"
    )
    assert result(completed) == "loaded"
    assert (box.zfs_state / "received").read_bytes() == b"correct horse battery\n"


def test_raw_key_with_a_trailing_newline_is_wrong(box: Sandbox, shell: Shell) -> None:
    """libzfs reads a raw key as up to 33 bytes and wants exactly 32, so the keyholder must
    send 32 bytes and nothing else (DESIGN.md 10.6)."""
    raw = bytes(range(32))
    set_dataset(box, "rpool", "raw", raw)
    wait_for_root(box, "rpool", "raw")
    with_newline = run_door(box, shell, "delivery", f"unlock {BOOT_ID}", stdin=raw + b"\n")
    assert result(with_newline) == "wrong-key"
    exact = run_door(box, shell, "delivery", f"unlock {BOOT_ID}", stdin=raw)
    assert result(exact) == "loaded"


def _prompt(box: Sandbox, shell: Shell, typed: bytes) -> tuple[int, bytes]:
    """Run the operator's empty command on a terminal and type into it."""
    environment = {"PATH": shell.path, "LC_ALL": "C", "HOME": str(box.root)}
    controller, terminal = pty.openpty()
    process = subprocess.Popen(
        [*shell.argv, str(box.lib / "door"), "operator"],
        stdin=terminal,
        stdout=terminal,
        stderr=terminal,
        env=environment,
        start_new_session=True,
    )
    os.close(terminal)
    seen = b""
    sent = False
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ready, _, _ = select.select([controller], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(controller, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
        if not sent and b"Key for rpool: " in seen:
            os.write(controller, typed)
            sent = True
        if process.poll() is not None and not ready:
            break
    code = process.wait(timeout=10)
    os.close(controller)
    return code, seen


def test_operator_prompt_reads_one_line_with_echo_off(box: Sandbox, shell: Shell) -> None:
    wait_for_root(box, "rpool", "passphrase")
    code, seen = _prompt(box, shell, b"correct horse battery\n")
    assert code == 0, seen
    assert b'"result":"loaded"' in seen
    assert b"correct horse battery" not in seen
    assert (box.zfs_state / "received").read_bytes() == b"correct horse battery"


def test_operator_prompt_refuses_a_raw_key(box: Sandbox, shell: Shell) -> None:
    set_dataset(box, "rpool", "raw", bytes(range(32)))
    wait_for_root(box, "rpool", "raw")
    code, seen = _prompt(box, shell, b"")
    assert code == 4
    assert b"cannot be typed" in seen
