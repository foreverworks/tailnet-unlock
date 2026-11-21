"""The supervisor with a real dropbear, OpenSSH client and swtpm, outside an initramfs.

Covers, at the process level: the door presents the sealed key, which keyholders pin (T1's door
half); the plaintext door key is deleted once dropbear has loaded it; a killed dropbear is started
again with the same key (T26); a wrong key then the right key (T27); the recovery fallback on
another TPM listens on the uplink only and fails the sealed pin (T5, T7); TERM wipes (D26).

It writes /root/.ssh/authorized_keys, so it runs only inside the test container
(TU_TEST_CONTAINER=1, as the Makefile sets it).
"""

import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

import swtpm
from shellenv import BOOT_ID, Sandbox, make_sandbox, wait_for_root
from tailnet_unlock.doorkey import check_dropbear_ed25519, pin_line
from tailnet_unlock.keyholder.doorstatus import parse_door_status
from tailnet_unlock.keyholder.pins import door_pins, known_hosts
from tailnet_unlock.seal import door_keygen, recovery_keygen

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(
        os.environ.get("TU_TEST_CONTAINER") != "1" or os.getuid() != 0,
        reason="writes /root/.ssh: test container only",
    ),
    pytest.mark.skipif(
        not swtpm.available() or shutil.which("dropbear") is None,
        reason="needs swtpm, tpm2-tools and dropbear",
    ),
]


@dataclass(frozen=True)
class Door:
    box: Sandbox
    port: int
    client_key: Path
    sealed_pin: str
    recovery_pin: str
    supervisor: subprocess.Popen[bytes]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_listening(address: str, port: int, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection((address, port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    raise AssertionError(f"nothing listens on {address}:{port}")


def ssh(
    door: Door, role: str, address: str, command: str, stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    pins = door_pins(door.port, door.sealed_pin, door.recovery_pin)
    hosts = door.box.root / f"known_hosts.{role}"
    hosts.write_text(known_hosts(pins, "sealed" if role == "sealed" else "recovery", address))
    return subprocess.run(
        [
            "ssh",
            "-p",
            str(door.port),
            "-i",
            str(door.client_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={hosts}",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "ConnectTimeout=5",
            f"root@{address}",
            command,
        ],
        input=stdin,
        capture_output=True,
        timeout=60,
        check=False,
    )


def start_door(tmp_path: Path, tcti_for_seal: str, tcti_for_boot: str) -> Iterator[Door]:
    port = free_port()
    box = make_sandbox(tmp_path / "box", {"TU_PORT": str(port), "TU_IDLE_TIMEOUT": "60"})
    paths = box.lib / "paths.sh"
    tpm_device = box.root / "tpmrm0"
    tpm_device.write_text("")
    paths.write_text(paths.read_text().replace("TU_TCTI='none'", f"TU_TCTI='{tcti_for_boot}'"))
    shm = Path("/dev/shm") / f"tu-supervisor-{os.urandom(4).hex()}"
    shm.mkdir(mode=0o700)
    state = box.root / "state"
    state.mkdir()
    sealed_pin = door_keygen(state, shm, None, tcti_for_seal, replace=False)
    recovery_pin = recovery_keygen(state, shm, None, replace=False)
    etc = box.root / "etc"
    etc.mkdir()
    shutil.copytree(state / "door.tpm", etc / "door.tpm")
    shutil.copy(state / "recovery_host_key", etc / "recovery_host_key")
    client_key = box.root / "client"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)], check=True
    )
    ssh_dir = Path("/root/.ssh")
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    authorized = ssh_dir / "authorized_keys"
    authorized.write_text(
        f'restrict,command="{box.lib}/door delivery" {(box.root / "client.pub").read_text()}'
    )
    authorized.chmod(0o600)
    supervisor = subprocess.Popen(
        ["sh", str(box.lib / "supervise")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    door = Door(box, port, client_key, sealed_pin, recovery_pin, supervisor)
    try:
        yield door
    finally:
        if supervisor.poll() is None:
            supervisor.terminate()
            try:
                supervisor.wait(timeout=30)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait()
        child = box.run / "dropbear.child"
        if child.exists():
            subprocess.run(["kill", "-KILL", child.read_text().strip()], check=False)
        shutil.rmtree(shm, ignore_errors=True)
        authorized.unlink(missing_ok=True)


@pytest.fixture
def sealed_door(tmp_path: Path) -> Iterator[Door]:
    with swtpm.software_tpm(tmp_path / "tpm") as tcti:
        yield from start_door(tmp_path, tcti, tcti)


@pytest.fixture
def recovery_door(tmp_path: Path) -> Iterator[Door]:
    """Sealed on one TPM, booted on another: what a copy of the disk sees."""
    with (
        swtpm.software_tpm(tmp_path / "tpm") as tcti,
        swtpm.software_tpm(tmp_path / "other-tpm") as other,
    ):
        yield from start_door(tmp_path, tcti, other)


def status(door: Door, role: str, address: str) -> dict[str, object]:
    completed = ssh(door, role, address, "status")
    assert completed.returncode == 0, completed.stderr.decode()
    parsed = parse_door_status(completed.stdout.strip())
    return dict(parsed)


def test_the_sealed_door(sealed_door: Door) -> None:
    door = sealed_door
    wait_listening("127.0.0.1", door.port)
    wait_listening("127.0.0.2", door.port)
    first = status(door, "sealed", "127.0.0.1")
    assert first["key"] == "sealed"
    assert first["seal"] == "ok"
    assert status(door, "sealed", "127.0.0.2")["key"] == "sealed"
    assert not (door.box.run / "door_key").exists(), "the plaintext outlived dropbear's start"
    refused = ssh(door, "recovery", "127.0.0.1", "status")
    assert refused.returncode == 255
    assert (
        b"REMOTE HOST IDENTIFICATION HAS CHANGED" in refused.stderr
        or b"Host key verification failed" in refused.stderr
    )
    console = door.box.console.read_text()
    assert "seal ok door sealed" in console

    # T26: dropbear dies while the box waits; the supervisor starts it again with the same key
    child = int((door.box.run / "dropbear.child").read_text())
    os.kill(child, 9)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        current = (door.box.run / "dropbear.child").read_text().strip()
        if current and int(current) != child:
            break
        time.sleep(0.5)
    wait_listening("127.0.0.1", door.port)
    again = status(door, "sealed", "127.0.0.1")
    restarts = again["restarts"]
    assert isinstance(restarts, dict)
    assert restarts["dropbear"] == 1
    assert "starting it again" in door.box.console.read_text()
    assert not (door.box.run / "door_key").exists()

    # T27: a wrong key is not an exit; the right key then loads
    wait_for_root(door.box, "rpool", "passphrase")
    wrong = ssh(door, "sealed", "127.0.0.1", f"unlock {BOOT_ID}", b"wrong horse battery")
    assert json.loads(wrong.stdout)["result"] == "wrong-key"
    right = ssh(door, "sealed", "127.0.0.1", f"unlock {BOOT_ID}", b"correct horse battery")
    assert json.loads(right.stdout)["result"] == "loaded"

    # init-bottom's half: TERM to the supervisor wipes and stops everything it started
    door.supervisor.terminate()
    assert door.supervisor.wait(timeout=30) == 0
    assert not (door.box.run / "dropbear.child").exists()
    assert not (door.box.run / "supervise.pid").exists()
    time.sleep(0.5)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", door.port), timeout=1).close()


def test_a_copy_on_another_tpm_gets_the_recovery_door_on_the_uplink_only(
    recovery_door: Door,
) -> None:
    door = recovery_door
    wait_listening("127.0.0.2", door.port)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", door.port), timeout=1).close()
    sealed = ssh(door, "sealed", "127.0.0.2", "status")
    assert sealed.returncode == 255, "the sealed pin must not verify against the recovery door"
    recovered = status(door, "recovery", "127.0.0.2")
    assert recovered["key"] == "recovery"
    assert recovered["seal"] == "unseal-failed"
    recovery_blob = (door.box.root / "etc" / "recovery_host_key").read_bytes()
    assert pin_line(check_dropbear_ed25519(recovery_blob)) == door.recovery_pin
