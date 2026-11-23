"""The guest the VM scenarios boot (DESIGN.md 15.2), shared by the uplink and the tailnet scenarios.

The first run builds the guest: a builder VM boots Debian 13's official cloud image (fetched with
its SHA512SUMS, read at run time) with a NoCloud seed (an ISO made with xorriso), writes the
target disk with provision.sh, and the result is the base image. Each variant then boots an overlay
of the base once with its own first-boot script and its own swtpm: `uplink` seals an imported test
door key and moves the root to keylocation=prompt; `tailnet` does the same and enrols the unlock
node into the test headscale (firstboot-tailnet.sh, with the CA, the control server's URL and a
pre-auth key on a second small disk labelled TUKEY). Everything is cached by the hash of its inputs;
each scenario boots an overlay of a variant's disk with a copy of that variant's TPM.

Every key here is a made-up test value generated for the run.
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
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

from harness import Vm, VmSpec, expect, kvm_available, send, ssh_argv, start, stop
from shellenv import REPO

__all__ = ["send"]

VM_MARKS = [
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
UPLINK_MAC = "00:00:5e:00:53:11"
TAILNET_MAC = "00:00:5e:00:53:12"


@dataclass(frozen=True)
class Guest:
    """One variant of the guest: its disk, its TPM state and the keys the scenarios use."""

    disk: Path
    tpm: Path
    keys: Path
    door_pin: str
    recovery_pin: str
    mac: str


@dataclass(frozen=True)
class TailnetGuest(Guest):
    """The tailnet variant, with what its enrolment printed."""

    control_url: str = ""
    addresses: tuple[str, ...] = ()
    authkey: str = ""


@dataclass(frozen=True)
class Base:
    disk: Path
    keys: Path
    door_pin: str
    recovery_pin: str


def run(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(list(argv), capture_output=True, check=True, timeout=600)


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
            *REPO.joinpath("tests/vm").glob("*.sh"),
            REPO / "tests/vm/pins.env",
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


def make_iso(source: Path, target: Path, label: str) -> None:
    """A real ISO 9660 image: QEMU's vvfat directory emulation is experimental and gave cloud-init
    unreadable clusters on a CI runner."""
    run(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-o",
            str(target),
            "-V",
            label,
            "-J",
            "-R",
            str(source),
        ]
    )


def build_base() -> Base:
    cache = CACHE / inputs_hash()
    done = cache / "base.json"
    if done.exists():
        recorded: object = json.loads(done.read_text())
        assert isinstance(recorded, dict)
        return Base(
            Path(str(recorded["disk"])),
            Path(str(recorded["keys"])),
            str(recorded["door_pin"]),
            str(recorded["recovery_pin"]),
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
    for name in ("provision.sh", "firstboot.sh", "firstboot-tailnet.sh", "pins.env"):
        shutil.copy(REPO / "tests/vm" / name, seed / name)
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
    target = cache / "base.qcow2"
    run(["qemu-img", "create", "-q", "-f", "qcow2", str(target), "8G"])
    seed_iso = cache / "seed.iso"
    make_iso(seed, seed_iso, "CIDATA")
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
    done.write_text(
        json.dumps(
            {
                "disk": str(target),
                "keys": str(keys),
                "door_pin": door_pin,
                "recovery_pin": recovery_pin,
            }
        )
    )
    return Base(target, keys, door_pin, recovery_pin)


def first_boot(
    base: Base, name: str, mac: str, extra: tuple[str, ...] = ()
) -> tuple[Path, Path, str]:
    """Boot an overlay of the base once with its first-boot script; returns its disk, its TPM
    directory and what the first boot printed on the console."""
    cache = base.disk.parent
    disk = cache / f"{name}.qcow2"
    run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(base.disk), "-F", "qcow2", str(disk)])
    spec = VmSpec(
        name=f"tu-firstboot-{name}", workdir=cache / name, disk=disk, mac=mac, extra=extra
    )
    vm = start(spec)
    try:
        outcome = expect_unless_exited(vm, r"TU-FIRSTBOOT (done|failed)", 1800)
        assert outcome.group(1) == "done", f"the {name} first boot failed: see its console.log"
        vm.qemu.wait(timeout=300)
        text = vm.console.text
    finally:
        stop(vm)
    return disk, cache / name / "tpm", text


def build_uplink(base: Base) -> Guest:
    done = base.disk.parent / "uplink.json"
    if not done.exists():
        disk, tpm, _ = first_boot(base, "uplink", UPLINK_MAC)
        done.write_text(json.dumps({"disk": str(disk), "tpm": str(tpm)}))
    recorded: object = json.loads(done.read_text())
    assert isinstance(recorded, dict)
    return Guest(
        Path(str(recorded["disk"])),
        Path(str(recorded["tpm"])),
        base.keys,
        base.door_pin,
        base.recovery_pin,
        UPLINK_MAC,
    )


def build_tailnet(
    base: Base, control_url: str, ca: Path, mint_authkey: Callable[[], str]
) -> TailnetGuest:
    """The tailnet variant, enrolled with a key `mint_authkey` makes (called only when the variant
    is not cached; the node it enrols lives in that headscale's state, which the caller keeps
    beside the image)."""
    cache = base.disk.parent
    done = cache / "tailnet.json"
    if not done.exists():
        authkey = mint_authkey()
        keydisk = cache / "tukey"
        keydisk.mkdir(exist_ok=True)
        shutil.copy(ca, keydisk / "ca.pem")
        (keydisk / "control_url").write_text(control_url + "\n")
        (keydisk / "authkey").write_text(authkey + "\n")
        iso = cache / "tukey.iso"
        make_iso(keydisk, iso, "TUKEY")
        drive = ("-drive", f"file={iso},if=virtio,format=raw,readonly=on")
        disk, tpm, text = first_boot(base, "tailnet", TAILNET_MAC, drive)
        enrolled = re.search(r"TU-ENROLL (\{.*\})", text)
        assert enrolled, "the first boot printed no enrolment: see its console.log"
        record: object = json.loads(enrolled.group(1))
        assert isinstance(record, dict)
        addresses = [str(a) for a in record["addresses"]]
        done.write_text(
            json.dumps(
                {"disk": str(disk), "tpm": str(tpm), "addresses": addresses, "authkey": authkey}
            )
        )
    recorded: object = json.loads(done.read_text())
    assert isinstance(recorded, dict)
    return TailnetGuest(
        Path(str(recorded["disk"])),
        Path(str(recorded["tpm"])),
        base.keys,
        base.door_pin,
        base.recovery_pin,
        TAILNET_MAC,
        control_url,
        tuple(str(a) for a in recorded["addresses"]),
        str(recorded["authkey"]),
    )


# --- one scenario's VM --------------------------------------------------------------------------


@dataclass(frozen=True)
class Booted:
    vm: Vm
    door_port: int
    ssh_port: int
    work: Path


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def boot_overlay(guest: Guest, work: Path, tpm: str, restrict: bool = False) -> Booted:
    """Boot an overlay of the guest's disk. `tpm` is `same` (a copy of the guest's own TPM state),
    `fresh` (another swtpm, never seen by this disk) or `reset` (the guest's state with the TPM's
    own files removed, which is what clearing an swtpm comes to)."""
    work.mkdir(parents=True)
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
    if tpm in ("same", "reset"):
        shutil.copytree(guest.tpm, work / "tpm")
    if tpm == "reset":
        for state in (work / "tpm").iterdir():
            state.unlink()
    shutil.copy(guest.tpm.parent / "OVMF_VARS_4M.fd", work / "OVMF_VARS_4M.fd")
    door, sshd = free_port(), free_port()
    spec = VmSpec(
        name="tu-scenario",
        workdir=work,
        disk=overlay,
        mac=guest.mac,
        forwards=((door, 2222), (sshd, 22)),
        restrict=restrict,
    )
    return Booted(start(spec), door, sshd, work)


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
    """Run a command on the booted system as root, once its sshd answers.

    sshd starts after the boot record is printed, so a probe (`true`) is retried until it works
    and a probe that never does fails with ssh's own message. The command itself runs once: it
    may be one that ends the connection, like a reboot.
    """

    def run_ssh(remote: str) -> subprocess.CompletedProcess[bytes]:
        argv = [
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
            "-o",
            "ConnectTimeout=10",
            "root@127.0.0.1",
            remote,
        ]
        return subprocess.run(argv, capture_output=True, timeout=300, check=False)

    deadline = time.monotonic() + 180
    probe = run_ssh("true")
    while probe.returncode != 0 and time.monotonic() < deadline:
        time.sleep(3)
        probe = run_ssh("true")
    assert probe.returncode == 0, f"no ssh to the guest: {probe.stderr.decode(errors='replace')}"
    return run_ssh(command)


def wait_for_door(guest: Guest, booted: Booted, role: str, start: int = 0) -> tuple[str, str]:
    """Wait for the boot summary after console offset `start`, then for the uplink door to answer
    `status` as `role`; returns the role the summary names and the boot id."""
    summary = expect(booted.vm.console, SUMMARY, 600, start)
    boot_id = expect(booted.vm.console, BOOT_ID, 60, summary.start()).group(1)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if door(guest, booted, role, "status").returncode == 0:
            break
        time.sleep(3)
    return summary.group(2), boot_id


def boot_record(booted: Booted, start: int = 0) -> dict[str, object]:
    line = expect(booted.vm.console, r"TU-SCENARIO boot\.json (\{.*\})", 600, start)
    parsed: object = json.loads(line.group(1))
    assert isinstance(parsed, dict)
    return parsed


# the extraction every "what is in the images" check shares: each /boot image into its own
# directory, then a count of the files that match `find`'s predicate
IMAGES_SCRIPT = (
    "for i in /boot/initrd.img-*; do d=$(mktemp -d); unmkinitramfs $i $d; "
    'echo "$i: $(find $d -type f \\( %s \\) | wc -l)"; rm -rf $d; done'
)


def images_with(guest: Guest, booted: Booted, predicate: str) -> list[int]:
    """For each image under /boot, how many files match the `find` predicate."""
    out = guest_ssh(guest, booted, IMAGES_SCRIPT % predicate).stdout.decode()
    return [int(line.rsplit(": ", 1)[1]) for line in out.splitlines() if ": " in line]


def door_seed_hex(guest: Guest) -> str:
    """The sealed door key's 32-byte seed in hex, to search images for it as plain text."""
    dumped = subprocess.run(
        ["dropbearconvert", "openssh", "dropbear", str(guest.keys / "door_key"), "/dev/stdout"],
        capture_output=True,
        check=True,
    )
    return dumped.stdout[19:51].hex()
