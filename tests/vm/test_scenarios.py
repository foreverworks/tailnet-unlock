"""The M1 VM scenarios (DESIGN.md 15.3) on a host with KVM, QEMU, OVMF and swtpm.

`make vm-test` runs them. The first run builds the guest: a builder VM boots Debian 13's official
cloud image (fetched with its SHA512SUMS, read at run time) with a NoCloud seed (an ISO made
with xorriso), writes the target
disk with provision.sh, and the target's first boot (firstboot.sh) seals an imported test door key
to the target's own swtpm and moves the root to keylocation=prompt. The result is cached by the
hash of its inputs. Each scenario then boots an overlay of that disk with a copy of that TPM.

Every key here is a made-up test value generated for the run. Written for KVM hosts and not yet
run: the host this was written on had no KVM, so only tests/vm/test_tcg_smoke.py ran.
"""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from harness import Vm, VmSpec, expect, kvm_available, send, ssh_argv, start, stop
from shellenv import REPO

pytestmark = [
    pytest.mark.vm,
    pytest.mark.skipif(not kvm_available(), reason="needs /dev/kvm"),
    pytest.mark.skipif(
        shutil.which("qemu-system-x86_64") is None or shutil.which("swtpm") is None,
        reason="needs QEMU and swtpm",
    ),
]

CLOUD = "https://cloud.debian.org/images/cloud/trixie/latest/"
CLOUD_IMAGE = "debian-13-genericcloud-amd64.qcow2"
CACHE = Path(os.environ.get("TU_VM_CACHE", Path.home() / ".cache" / "tailnet-unlock" / "vm"))
PASSPHRASE = "test passphrase " + hashlib.sha256(b"tailnet-unlock test").hexdigest()[:24]
SUMMARY = r"tailnet-unlock: \[[^]]*\] profile tpm seal (\S+) door (\S+)"
BOOT_ID = r"boot ([0-9a-f-]{36})"


@dataclass(frozen=True)
class Guest:
    disk: Path
    tpm: Path
    keys: Path
    door_pin: str
    recovery_pin: str
    mac: str


def run(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, capture_output=True, check=True, timeout=600)


def keygen(path: Path) -> str:
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)])
    return " ".join(path.with_suffix(".pub").read_text().split()[:2])


def fetch_cloud_image(cache: Path) -> Path:
    sums = urllib.request.urlopen(CLOUD + "SHA512SUMS", timeout=60).read().decode()  # noqa: S310  # constant https URL
    expected = next(line.split()[0] for line in sums.splitlines() if line.endswith(CLOUD_IMAGE))
    image = cache / f"{expected[:16]}-{CLOUD_IMAGE}"
    if not image.exists():
        partial = image.with_suffix(".part")
        with (
            urllib.request.urlopen(CLOUD + CLOUD_IMAGE, timeout=600) as response,  # noqa: S310  # constant https URL
            partial.open("wb") as out,
        ):
            shutil.copyfileobj(response, out)
        digest = hashlib.sha512(partial.read_bytes()).hexdigest()
        assert digest == expected, "the cloud image does not match SHA512SUMS"
        partial.rename(image)
    return image


def inputs_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted(
        [
            *REPO.joinpath("initramfs").iterdir(),
            *REPO.joinpath("src").rglob("*.py"),
            REPO / "tests/vm/provision.sh",
            REPO / "tests/vm/firstboot.sh",
        ]
    ):
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def expect_unless_exited(vm: Vm, pattern: str, timeout: float) -> re.Match[str]:
    """`expect`, but a VM that powered off without printing the marker fails at once."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return expect(vm.console, pattern, 10)
        except TimeoutError:
            if vm.qemu.poll() is not None:
                break
    return expect(vm.console, pattern, 10)


def build_guest() -> Guest:
    cache = CACHE / inputs_hash()
    done = cache / "guest.json"
    if done.exists():
        recorded: object = json.loads(done.read_text())
        assert isinstance(recorded, dict)
        return Guest(
            Path(str(recorded["disk"])),
            Path(str(recorded["tpm"])),
            Path(str(recorded["keys"])),
            str(recorded["door_pin"]),
            str(recorded["recovery_pin"]),
            str(recorded["mac"]),
        )
    cache.mkdir(parents=True, exist_ok=True)
    base = fetch_cloud_image(CACHE)
    seed = cache / "seed"
    keys = seed / "test-keys"
    keys.mkdir(parents=True, exist_ok=True)
    door_pin = keygen(keys / "door_key")
    recovery_pin = keygen(keys / "recovery_key")
    keygen(keys / "keyholder")
    keygen(keys / "operator")
    keygen(keys / "harness_ssh")
    # a file the builder copies, so that no shell trace line or command line carries the text
    (seed / "rpool.key").write_text(PASSPHRASE)
    shutil.copy(REPO / "tests/vm/provision.sh", seed / "provision.sh")
    shutil.copy(REPO / "tests/vm/firstboot.sh", seed / "firstboot.sh")
    run(["git", "-C", str(REPO), "archive", "-o", str(seed / "repo.tar"), "HEAD"])
    (seed / "meta-data").write_text("instance-id: tailnet-unlock-builder\n")
    (seed / "user-data").write_text(
        "#cloud-config\nruncmd:\n"
        '  - [sh, -c, "mkdir -p /run/s && mount -o ro LABEL=CIDATA /run/s && '
        "{ tail -n +1 -F /var/log/tu-provision.log >/dev/ttyS0 2>&1 & }; "
        "sh /run/s/provision.sh >/var/log/tu-provision.log 2>&1; rc=$?; sleep 3; "
        "tail -n 90 /var/log/tu-provision.log >/dev/ttyS0; "
        'echo TU-PROVISION rc=$rc >/dev/ttyS0"]\n'
    )
    builder_disk = cache / "builder.qcow2"
    run(
        [
            "qemu-img",
            "create",
            "-q",
            "-f",
            "qcow2",
            "-b",
            str(base),
            "-F",
            "qcow2",
            str(builder_disk),
            "12G",
        ]
    )
    target = cache / "target.qcow2"
    run(["qemu-img", "create", "-q", "-f", "qcow2", str(target), "8G"])
    mac = "00:00:5e:00:53:11"
    # a real ISO 9660 image: QEMU's vvfat directory emulation is experimental and gave cloud-init
    # unreadable clusters on a CI runner
    seed_iso = cache / "seed.iso"
    run(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-o",
            str(seed_iso),
            "-V",
            "CIDATA",
            "-J",
            "-R",
            str(seed),
        ]
    )
    seed_drive = f"file={seed_iso},if=virtio,format=raw,readonly=on"
    builder = VmSpec(
        name="tu-builder",
        workdir=cache / "builder",
        disk=builder_disk,
        memory_mib=4096,
        cpus=4,
        mac="00:00:5e:00:53:10",
        extra=("-drive", f"file={target},if=virtio,format=qcow2", "-drive", seed_drive),
    )
    vm = start(builder)
    try:
        # provision.sh's first trace line: the seed was read and the script started
        expect(vm.console, r"\+ seed=/run/tailnet-unlock-seed", 300)
        # the log is tailed to the console; a failed run ends with `TU-PROVISION rc=<n>`
        outcome = expect_unless_exited(vm, r"TU-PROVISION (done|rc=\d+)", 3600)
        assert outcome.group(1) == "done", f"the builder's provision.sh failed: {outcome.group(0)}"
        vm.qemu.wait(timeout=300)
    finally:
        stop(vm)
    first = VmSpec(name="tu-firstboot", workdir=cache / "target", disk=target, mac=mac)
    vm = start(first)
    try:
        expect(vm.console, r"TU-FIRSTBOOT done", 1800)
        vm.qemu.wait(timeout=300)
    finally:
        stop(vm)
    guest = Guest(target, cache / "target" / "tpm", keys, door_pin, recovery_pin, mac)
    done.write_text(
        json.dumps(
            {
                "disk": str(guest.disk),
                "tpm": str(guest.tpm),
                "keys": str(guest.keys),
                "door_pin": door_pin,
                "recovery_pin": recovery_pin,
                "mac": mac,
            }
        )
    )
    return guest


@pytest.fixture(scope="session")
def guest() -> Guest:
    return build_guest()


@dataclass(frozen=True)
class Booted:
    vm: Vm
    door_port: int
    ssh_port: int
    work: Path


type Boot = Callable[[bool], Booted]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def boot(guest: Guest, tmp_path: Path) -> Iterator[Boot]:
    started: list[Vm] = []

    def booting(fresh_tpm: bool) -> Booted:
        work = tmp_path / f"vm{len(started)}"
        work.mkdir()
        overlay = work / "disk.qcow2"
        run(
            [
                "qemu-img",
                "create",
                "-q",
                "-f",
                "qcow2",
                "-b",
                str(guest.disk),
                "-F",
                "qcow2",
                str(overlay),
            ]
        )
        if not fresh_tpm:
            shutil.copytree(guest.tpm, work / "tpm")
        shutil.copy(guest.tpm.parent / "OVMF_VARS_4M.fd", work / "OVMF_VARS_4M.fd")
        door, sshd = free_port(), free_port()
        spec = VmSpec(
            name="tu-scenario",
            workdir=work,
            disk=overlay,
            mac=guest.mac,
            forwards=((door, 2222), (sshd, 22)),
        )
        vm = start(spec)
        started.append(vm)
        return Booted(vm, door, sshd, work)

    yield booting
    for vm in started:
        stop(vm)


def door(
    guest: Guest, booted: Booted, role: str, command: str, stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    hosts = booted.work / f"known_hosts.{role}"
    pin = guest.door_pin if role == "sealed" else guest.recovery_pin
    hosts.write_text(f"[127.0.0.1]:{booted.door_port} {pin}\n")
    return subprocess.run(
        ssh_argv(booted.door_port, guest.keys / "keyholder", hosts, [command]),
        input=stdin,
        capture_output=True,
        timeout=120,
        check=False,
    )


def guest_ssh(guest: Guest, booted: Booted, command: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "ssh",
            "-p",
            str(booted.ssh_port),
            "-i",
            str(guest.keys / "harness_ssh"),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "root@127.0.0.1",
            command,
        ],
        capture_output=True,
        timeout=300,
        check=False,
    )


def wait_for_door(guest: Guest, booted: Booted, role: str) -> tuple[str, str]:
    summary = expect(booted.vm.console, SUMMARY, 600)
    boot_id = expect(booted.vm.console, BOOT_ID, 60, summary.start()).group(1)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if door(guest, booted, role, "status").returncode == 0:
            break
        time.sleep(3)
    return summary.group(2), boot_id


def boot_record(booted: Booted) -> dict[str, object]:
    line = expect(booted.vm.console, r"TU-SCENARIO boot\.json (\{.*\})", 600)
    parsed: object = json.loads(line.group(1))
    assert isinstance(parsed, dict)
    return parsed


def test_t1_t27_t22_unlock_through_the_uplink_door(guest: Guest, boot: Boot) -> None:
    booted = boot(False)
    role, boot_id = wait_for_door(guest, booted, "sealed")
    assert role == "sealed"
    other = "00000000-0000-4000-8000-000000000000"
    mismatch = door(guest, booted, "sealed", f"unlock {other}", PASSPHRASE.encode())
    assert json.loads(mismatch.stdout)["result"] == "boot-mismatch"
    wrong = door(guest, booted, "sealed", f"unlock {boot_id}", b"not the key at all")
    assert json.loads(wrong.stdout)["result"] == "wrong-key"
    right = door(guest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode() + b"\n")
    assert json.loads(right.stdout)["result"] == "loaded"
    assert boot_record(booted)["unlocked_by"] == "sealed"
    raw = guest_ssh(
        guest,
        booted,
        "sh -c 'k=/run/raw.key; head -c 32 /dev/urandom >$k; "
        "zfs create -o encryption=on -o keyformat=raw -o keylocation=file://$k "
        "rpool/rawtest && zfs unload-key rpool/rawtest && "
        "{ cat $k; echo; } | zfs load-key -L prompt rpool/rawtest; echo nl=$?; "
        "zfs load-key -L prompt rpool/rawtest <$k; echo exact=$?'",
    )
    assert b"nl=0" not in raw.stdout, "libzfs accepted a raw key with a trailing newline"
    assert b"exact=0" in raw.stdout


def test_t3_nothing_sent_the_console_still_works(guest: Guest, boot: Boot) -> None:
    booted = boot(False)
    wait_for_door(guest, booted, "sealed")
    time.sleep(30)
    status = json.loads(door(guest, booted, "sealed", "status").stdout)
    assert status["waiting_for"] == "rpool"
    mark = len(booted.vm.console.text)
    expect(booted.vm.console, r"Key for rpool", 60)
    send(booted.vm.console, PASSPHRASE + "\n")
    assert boot_record(booted)["unlocked_by"] == "console"
    assert PASSPHRASE not in booted.vm.console.text[mark:]


def test_t5_t7_a_fresh_tpm_gets_the_recovery_door_only(guest: Guest, boot: Boot) -> None:
    booted = boot(True)
    role, boot_id = wait_for_door(guest, booted, "recovery")
    assert role == "recovery"
    assert door(guest, booted, "sealed", "status").returncode == 255
    status = json.loads(door(guest, booted, "recovery", "status").stdout)
    assert status["key"] == "recovery"
    loaded = door(guest, booted, "recovery", f"unlock {boot_id}", PASSPHRASE.encode())
    assert json.loads(loaded.stdout)["result"] == "loaded"
    assert boot_record(booted)["unlocked_by"] == "recovery"


def test_t6_t21_boot_holds_no_plaintext_door_key(guest: Guest, boot: Boot) -> None:
    booted = boot(False)
    _, boot_id = wait_for_door(guest, booted, "sealed")
    door(guest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    boot_record(booted)
    seed = (
        subprocess.run(
            ["dropbearconvert", "openssh", "dropbear", str(guest.keys / "door_key"), "/dev/stdout"],
            capture_output=True,
            check=True,
        )
        .stdout[19:51]
        .hex()
    )
    found = guest_ssh(
        guest,
        booted,
        "sh -c 'for i in /boot/initrd.img-*; do d=$(mktemp -d); "
        'unmkinitramfs $i $d; find $d -type f -exec xxd -p {} + | tr -d "\\n" | '
        f"grep -c {seed}; ls $d/main/etc/tailnet-unlock 2>/dev/null; done'",
    )
    assert b"recovery_host_key" in found.stdout
    assert re.search(rb"^[1-9]", found.stdout, re.MULTILINE) is None
    pins = guest_ssh(guest, booted, "tailnet-unlock pins").stdout.decode()
    assert guest.door_pin in pins
    assert guest.recovery_pin in pins


def test_t28_break_mount_wipes_before_the_shell(guest: Guest, boot: Boot) -> None:
    booted = boot(False)
    _, boot_id = wait_for_door(guest, booted, "sealed")
    door(guest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    boot_record(booted)
    guest_ssh(guest, booted, "grub-reboot 'tailnet-unlock break=mount' && systemctl reboot")
    mark = len(booted.vm.console.text)
    expect(booted.vm.console, r"stopped and wiped before the shell opens", 600, mark)
    expect(booted.vm.console, r"\(initramfs\)", 60, mark)
    send(booted.vm.console, "echo dropbear=$(ps | grep -c '[d]ropbear')\n")
    assert expect(booted.vm.console, r"dropbear=(\d+)", 60, mark).group(1) == "0"


def test_t14_the_key_appears_in_no_log(guest: Guest, tmp_path: Path) -> None:
    """Runs last in this module: every console and QEMU log the scenarios wrote."""
    logs = [path for path in tmp_path.parent.rglob("*.log") if path.is_file()]
    logs += [path for path in guest.disk.parent.rglob("*.log") if path.is_file()]
    for path in logs:
        assert PASSPHRASE.encode() not in path.read_bytes(), path
