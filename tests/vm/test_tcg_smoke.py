"""A real boot of the door, without KVM: Debian's kernel and the image built here, under QEMU TCG.

No disk and no ZFS pool (building a ZFS root needs the builder VM, too slow under TCG), so this
checks what a genuine initramfs does before the root: the TPM on tpm-tis, the unseal from the VM's
own swtpm, the uplink by MAC through configure_networking, dropbear with the sealed key on the
uplink, the door's `status`; then, when initramfs-tools gives up waiting for the root (30 seconds;
`rootdelay=` would sleep that long before init-premount even starts) and calls
panic(), that the panic script stops and wipes the door before the shell opens (T28 under `tpm`).

The door key is sealed to the same swtpm state the VM boots with. Runs only in the test container
(TU_TEST_CONTAINER=1) and only when TU_TCG=1, since one boot takes minutes.
"""

import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from harness import VmSpec, expect, send, start, stop
from imagekit import Installed, build, conf, install_box

pytestmark = [
    pytest.mark.vm,
    pytest.mark.skipif(
        os.environ.get("TU_TEST_CONTAINER") != "1" or os.getuid() != 0,
        reason="changes the system: test container only",
    ),
    pytest.mark.skipif(os.environ.get("TU_TCG") != "1", reason="set TU_TCG=1 to boot under TCG"),
    pytest.mark.skipif(shutil.which("qemu-system-x86_64") is None, reason="needs QEMU"),
]


SUMMARY = r"tailnet-unlock: \[[^]]*\] profile tpm seal (\S+) door (\S+)"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="module")
def booted(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Installed, Path]]:
    work = tmp_path_factory.mktemp("tcg")
    vm_dir = work / "vm"
    installed = install_box(work, vm_dir / "tpm", match="mac")
    yield installed, vm_dir


def test_door_comes_up_and_panic_wipes_it(booted: tuple[Installed, Path]) -> None:
    installed, vm_dir = booted
    image = build(installed, "tcg")
    assert image.returncode == 0, image.stderr
    assert conf(image)["TU_DOOR"] == "sealed"
    mac = Path("/sys/class/net/eth0/address").read_text().strip()
    port = free_port()
    spec = VmSpec(
        name="tailnet-unlock-tcg",
        workdir=vm_dir,
        kernel=Path(f"/boot/vmlinuz-{installed.kernel}"),
        initrd=image.path,
        append="console=ttyS0,115200 root=/dev/disk/by-label/absent",
        accel="tcg",
        memory_mib=1536,
        cpus=2,
        mac=mac,
        forwards=((port, 2222),),
        uefi=False,
    )
    vm = start(spec)
    try:
        summary = expect(vm.console, SUMMARY, 600)
        assert summary.group(1) == "ok", vm.console.text[-3000:]
        assert summary.group(2) == "sealed"
        hosts = vm_dir / "known_hosts"
        hosts.write_text(f"[127.0.0.1]:{port} {installed.door_pin}\n")
        command = [
            "ssh",
            "-p",
            str(port),
            "-i",
            str(installed.client_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={hosts}",
            "-o",
            "ConnectTimeout=20",
            "root@127.0.0.1",
            "status",
        ]
        deadline = time.monotonic() + 180
        completed = subprocess.run(command, capture_output=True, timeout=120, check=False)
        while completed.returncode != 0 and time.monotonic() < deadline:
            time.sleep(5)
            completed = subprocess.run(command, capture_output=True, timeout=120, check=False)
        assert completed.returncode == 0, completed.stderr.decode()
        status = json.loads(completed.stdout)
        assert status["key"] == "sealed"
        assert status["seal"] == "ok"
        (vm_dir / "status.json").write_bytes(completed.stdout)

        wiped = expect(vm.console, r"stopped and wiped before the shell opens", 900)
        expect(vm.console, r"\(initramfs\)", 120, wiped.end())
        mark = len(vm.console.text)
        send(
            vm.console,
            "echo dropbear=$(ps | grep -c '[d]ropbear') "
            "files=$(ls /tailnet-unlock/run 2>/dev/null | grep -c door_key)\n",
        )
        counts = expect(vm.console, r"dropbear=(\d+) files=(\d+)", 120, mark)
        assert counts.group(1) == "0"
        assert counts.group(2) == "0"
        refused = subprocess.run(command, capture_output=True, timeout=120, check=False)
        assert refused.returncode == 255
    finally:
        stop(vm)
