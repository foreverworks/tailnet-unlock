"""The VM harness (DESIGN.md section 15.2): QEMU, swtpm on tpm-tis, OVMF, the serial console.

Pure functions build every command line; the edge starts swtpm and QEMU, keeps their PIDs, and
drives the serial console through a Unix socket. The harness records the versions it ran with.
It needs only the standard library, so the same code runs on a laptop and on a CI runner.
"""

import os
import re
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

type Accel = Literal["kvm", "tcg"]

OVMF_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")


@dataclass(frozen=True)
class VmSpec:
    """One VM. `disk` is None for a direct kernel boot (`kernel` and `initrd` set)."""

    name: str
    workdir: Path
    disk: Path | None = None
    kernel: Path | None = None
    initrd: Path | None = None
    append: str = ""
    accel: Accel = "kvm"
    memory_mib: int = 2048
    cpus: int = 2
    mac: str = "00:00:5e:00:53:01"
    forwards: tuple[tuple[int, int], ...] = ()
    uefi: bool = True
    extra: tuple[str, ...] = field(default_factory=tuple)


def tpm_dir(spec: VmSpec) -> Path:
    return spec.workdir / "tpm"


def tpm_socket(spec: VmSpec) -> Path:
    return spec.workdir / "swtpm.sock"


def serial_socket(spec: VmSpec) -> Path:
    return spec.workdir / "serial.sock"


def vars_copy(spec: VmSpec) -> Path:
    return spec.workdir / "OVMF_VARS_4M.fd"


def swtpm_argv(spec: VmSpec) -> list[str]:
    return [
        "swtpm",
        "socket",
        "--tpm2",
        "--tpmstate",
        f"dir={tpm_dir(spec)}",
        "--ctrl",
        f"type=unixio,path={tpm_socket(spec)}",
        "--log",
        f"file={spec.workdir / 'swtpm.log'},level=1",
    ]


def qemu_argv(spec: VmSpec) -> list[str]:
    """The QEMU command line: q35, a TPM 2.0 on tpm-tis, a virtio NIC on user networking."""
    accel = (
        ["-accel", "kvm", "-cpu", "host"]
        if spec.accel == "kvm"
        else ["-accel", "tcg", "-cpu", "max"]
    )
    forwards = "".join(f",hostfwd=tcp:127.0.0.1:{host}-:{guest}" for host, guest in spec.forwards)
    argv = [
        "qemu-system-x86_64",
        "-name",
        spec.name,
        "-machine",
        "q35",
        *accel,
        "-m",
        str(spec.memory_mib),
        "-smp",
        str(spec.cpus),
        "-nographic",
        "-serial",
        f"unix:{serial_socket(spec)},server=on,wait=off",
        "-monitor",
        "none",
        "-chardev",
        f"socket,id=chrtpm,path={tpm_socket(spec)}",
        "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
        "-device",
        "tpm-tis,tpmdev=tpm0",
        "-netdev",
        f"user,id=net0{forwards}",
        "-device",
        f"virtio-net-pci,netdev=net0,mac={spec.mac}",
    ]
    if spec.uefi:
        argv += [
            "-drive",
            f"if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}",
            "-drive",
            f"if=pflash,format=raw,unit=1,file={vars_copy(spec)}",
        ]
    if spec.disk is not None:
        argv += ["-drive", f"file={spec.disk},if=virtio,format=qcow2"]
    if spec.kernel is not None:
        argv += ["-kernel", str(spec.kernel)]
        if spec.initrd is not None:
            argv += ["-initrd", str(spec.initrd)]
        argv += ["-append", spec.append]
    return [*argv, *spec.extra]


def versions() -> dict[str, str]:
    """What this run used, for the record."""
    found: dict[str, str] = {}
    for name, argv in (
        ("qemu", ["qemu-system-x86_64", "--version"]),
        ("swtpm", ["swtpm", "--version"]),
    ):
        if shutil.which(argv[0]):
            output = subprocess.run(argv, capture_output=True, text=True, check=False).stdout
            found[name] = output.splitlines()[0] if output else "unknown"
    return found


@dataclass
class Console:
    """The guest's serial console: everything read is kept and also written to a log file."""

    sock: socket.socket
    log: Path
    text: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)
    closed: bool = False


def _reader(console: Console) -> None:
    with console.log.open("a", encoding="utf-8", errors="replace") as log:
        while not console.closed:
            try:
                chunk = console.sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            decoded = chunk.decode("utf-8", "replace")
            log.write(decoded)
            log.flush()
            with console.lock:
                console.text += decoded


def open_console(path: Path, log: Path, timeout: float = 30) -> Console:
    deadline = time.monotonic() + timeout
    while True:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(path))
            break
        except OSError:
            sock.close()
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)
    console = Console(sock=sock, log=log)
    threading.Thread(target=_reader, args=(console,), daemon=True).start()
    return console


def expect(console: Console, pattern: str, timeout: float, start: int = 0) -> re.Match[str]:
    """Wait until the console output after `start` matches `pattern`."""
    compiled = re.compile(pattern)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with console.lock:
            match = compiled.search(console.text, start)
        if match:
            return match
        time.sleep(0.2)
    tail = console.text[-2000:]
    raise TimeoutError(f"no {pattern!r} on the console after {timeout} s; last output:\n{tail}")


def send(console: Console, text: str) -> None:
    console.sock.sendall(text.encode())


@dataclass
class Vm:
    spec: VmSpec
    swtpm: subprocess.Popen[bytes]
    qemu: subprocess.Popen[bytes]
    console: Console


def prepare(spec: VmSpec) -> None:
    spec.workdir.mkdir(parents=True, exist_ok=True)
    tpm_dir(spec).mkdir(exist_ok=True)
    if spec.uefi and not vars_copy(spec).exists():
        shutil.copy(OVMF_VARS, vars_copy(spec))


def start(spec: VmSpec) -> Vm:
    prepare(spec)
    for stale in (tpm_socket(spec), serial_socket(spec)):
        stale.unlink(missing_ok=True)
    tpm = subprocess.Popen(swtpm_argv(spec), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while not tpm_socket(spec).exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    log = (spec.workdir / "qemu.log").open("ab")
    qemu = subprocess.Popen(qemu_argv(spec), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    console = open_console(serial_socket(spec), spec.workdir / "console.log")
    return Vm(spec=spec, swtpm=tpm, qemu=qemu, console=console)


def stop(vm: Vm) -> None:
    """Stop QEMU, then swtpm, each by the PID this harness started."""
    vm.console.closed = True
    vm.console.sock.close()
    for process in (vm.qemu, vm.swtpm):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def kvm_available() -> bool:
    return os.access("/dev/kvm", os.R_OK | os.W_OK)


def ssh_argv(
    port: int,
    identity: Path,
    known_hosts: Path,
    command: Sequence[str],
    user: str = "root",
    extra: Sequence[str] = (),
) -> list[str]:
    return [
        "ssh",
        "-p",
        str(port),
        "-i",
        str(identity),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "HostKeyAlgorithms=ssh-ed25519",
        "-o",
        "ConnectTimeout=10",
        *extra,
        f"{user}@127.0.0.1",
        *command,
    ]
