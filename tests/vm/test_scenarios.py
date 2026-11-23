"""The VM scenarios of the uplink door (DESIGN.md 15.3) on a host with KVM, QEMU, OVMF and swtpm.

`make vm-test` runs them. The guest is built and cached by guests.py; this module boots the
`uplink` variant (tailnet.enabled = false). Each scenario boots an overlay of its disk with a copy
of its TPM.

Every key here is a made-up test value generated for the run. Written for KVM hosts; they pass in CI
(the full workflow's vm job). tests/vm/test_tcg_smoke.py is the tier that runs without KVM.
"""

import json
import re
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from guests import (
    PASSPHRASE,
    VM_MARKS,
    Booted,
    Guest,
    boot_overlay,
    boot_record,
    build_base,
    build_uplink,
    door,
    guest_ssh,
    images_with,
    wait_for_door,
)
from harness import Vm, expect, send, stop

pytestmark = VM_MARKS


@pytest.fixture(scope="session")
def guest() -> Guest:
    return build_uplink(build_base())


type Boot = Callable[[bool], Booted]


@pytest.fixture
def boot(guest: Guest, tmp_path: Path) -> Iterator[Boot]:
    started: list[Vm] = []

    def booting(fresh_tpm: bool) -> Booted:
        booted = boot_overlay(
            guest, tmp_path / f"vm{len(started)}", "fresh" if fresh_tpm else "same"
        )
        started.append(booted.vm)
        return booted

    yield booting
    for vm in started:
        stop(vm)


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
        f"grep -c {seed}; find $d -name recovery_host_key; done'",
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


def test_t15_no_tailscale_in_any_image(guest: Guest, boot: Boot) -> None:
    """The guest has the tailscale package installed and `tailnet.enabled = false`: no image
    carries tailscaled or a node state, and the summary says the unlock node is off."""
    booted = boot(False)
    _, boot_id = wait_for_door(guest, booted, "sealed")
    assert re.search(r"unlock node off", booted.vm.console.text)
    door(guest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    boot_record(booted)
    counts = images_with(guest, booted, "-name tailscaled -o -name unlock.state")
    assert counts
    assert counts == [0] * len(counts)


def test_t14_the_key_appears_in_no_log(guest: Guest, tmp_path: Path) -> None:
    """Runs last in this module: every console and QEMU log the scenarios wrote."""
    logs = [path for path in tmp_path.parent.rglob("*.log") if path.is_file()]
    logs += [path for path in guest.disk.parent.rglob("*.log") if path.is_file()]
    for path in logs:
        assert PASSPHRASE.encode() not in path.read_bytes(), path
