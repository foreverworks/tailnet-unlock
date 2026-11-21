"""Real initramfs images built with mkinitramfs in the test container (DESIGN.md 7.2; T6, T18).

The repository is installed where the package will put it (tools/install-tree), a door key is
imported and sealed to swtpm, and each test builds an image for the container's Debian kernel and
reads it back with lsinitramfs and unmkinitramfs. The door inside one image is then started from
the image itself in a chroot, with the image's own dropbear, NSS files, busybox and door command.

It changes /etc, /var/lib and /usr of the container, so it runs only there (TU_TEST_CONTAINER=1),
and the /boot space test mounts a small tmpfs, so the container runs with --privileged (rootless
docker: privileged inside its own user namespace only).
"""

import base64
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from imagekit import CONFIG, STATE, STATE_MARK, Installed, build, conf, files, install_box
from tailnet_unlock.doorkey import check_dropbear_ed25519, pin_line
from tailnet_unlock.keyholder.doorstatus import parse_door_status

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(
        os.environ.get("TU_TEST_CONTAINER") != "1" or os.getuid() != 0,
        reason="changes the system: test container only",
    ),
    pytest.mark.skipif(shutil.which("mkinitramfs") is None, reason="needs initramfs-tools"),
]


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Installed]:
    work = tmp_path_factory.mktemp("image")
    yield install_box(work, work / "tpm")


def search(tree: Path, needles: list[bytes]) -> list[str]:
    found: list[str] = []
    for path in tree.rglob("*"):
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            found += [f"{path}" for needle in needles if needle in data]
    return found


def test_full_image(installed: Installed) -> None:
    image = build(installed, "full")
    assert image.returncode == 0, image.stderr
    listed = files(image)
    for expected in (
        "usr/sbin/dropbear",
        "etc/passwd",
        "etc/nsswitch.conf",
        "root/.ssh/authorized_keys",
        "usr/sbin/tailscaled",
        "etc/ssl/certs/ca-certificates.crt",
        "etc/tailnet-unlock/door.tpm/public",
        "etc/tailnet-unlock/door.tpm/private",
        "etc/tailnet-unlock/door.tpm/pin",
        "etc/tailnet-unlock/recovery_host_key",
        "etc/tailnet-unlock/unlock.state",
        "usr/bin/tpm2_unseal",
        "usr/bin/tpm2_startauthsession",
        "usr/lib/tailnet-unlock/door",
        "usr/lib/tailnet-unlock/supervise",
        "usr/lib/tailnet-unlock/unseal",
        "scripts/init-premount/tailnet-unlock",
        "scripts/init-bottom/tailnet-unlock",
        "scripts/panic/tailnet-unlock",
        "etc/zfs/initramfs-tools-load-key.d/tailnet-unlock",
        "conf/tailnet-unlock.conf",
    ):
        assert expected in listed, expected
    assert any("libtss2-tcti-device.so.0" in name for name in listed)
    assert any("libnss_files" in name for name in listed) or any(
        name.endswith("/libc.so.6") for name in listed
    )
    tree = image.tree
    assert (tree / "etc" / "passwd").read_text() == "root:x:0:0:root:/root:/bin/sh\n"
    assert (tree / "etc" / "nsswitch.conf").read_text() == "passwd: files\n"
    keys = tree / "root" / ".ssh" / "authorized_keys"
    assert oct(keys.stat().st_mode & 0o777) == "0o600"
    assert oct((tree / "root" / ".ssh").stat().st_mode & 0o777) == "0o700"
    lines = [line for line in keys.read_text().splitlines() if not line.startswith("#")]
    assert lines[0].startswith('restrict,command="/usr/lib/tailnet-unlock/door delivery" ')
    assert lines[1].startswith(
        "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'command="/usr/lib/tailnet-unlock/door operator" '
    )
    assert "mount -t devpts" in (tree / "init").read_text()
    values = conf(image)
    assert values["TU_DOOR"] == "sealed"
    assert values["TU_TAILNET_IN_IMAGE"] == "yes"
    assert values["TU_DEGRADED"] == ""
    assert values["TU_TAILSCALED_VERSION"].startswith("1.")
    assert values["TU_SEALED_FP"].startswith("SHA256:")
    assert oct(image.path.stat().st_mode & 0o777) == "0o600", "UMASK=0077 was not applied"
    assert (
        (STATE / "images" / installed.kernel)
        .read_text()
        .startswith("door=sealed tailnet=yes recovery=yes")
    )


def test_no_plaintext_door_key_in_the_image(installed: Installed) -> None:
    """T6 for the image: the sealed key and the node state are ciphertext; recovery is there."""
    image = build(installed, "secrets")
    assert image.returncode == 0, image.stderr
    seed = installed.door_blob[19:51]
    body = b"".join(installed.door_pem.splitlines()[1:-1])
    needles = [installed.door_blob, seed, body[:40], base64.b64decode(body)[-64:]]
    assert search(image.tree, needles) == []
    assert (image.tree / "etc/tailnet-unlock/unlock.state").read_bytes().startswith(STATE_MARK)
    recovery = (image.tree / "etc/tailnet-unlock/recovery_host_key").read_bytes()
    assert pin_line(check_dropbear_ed25519(recovery)) == installed.recovery_pin


def test_without_tailscaled_the_uplink_door_stays(installed: Installed) -> None:
    shutil.move("/usr/sbin/tailscaled", "/usr/sbin/tailscaled.away")
    try:
        image = build(installed, "no-tailscaled")
    finally:
        shutil.move("/usr/sbin/tailscaled.away", "/usr/sbin/tailscaled")
    assert image.returncode == 0
    assert "W: tailnet-unlock: tailscaled is not installed" in image.stderr
    assert "usr/sbin/tailscaled" not in files(image)
    assert "usr/sbin/dropbear" in files(image)
    assert conf(image)["TU_DEGRADED"] == "tailscaled-missing"
    assert conf(image)["TU_TAILNET"] == "no"


def test_a_small_boot_degrades_instead_of_failing(installed: Installed) -> None:
    """E: /boot too small for tailscaled: no tailnet door, the uplink door stays, loudly."""
    boot = Path("/boot")
    boot.mkdir(exist_ok=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=20m", "tmpfs", str(boot)], check=True)
    try:
        (STATE / "images" / installed.kernel).unlink(missing_ok=True)
        image = build(installed, "small-boot")
    finally:
        subprocess.run(["umount", str(boot)], check=True)
    assert image.returncode == 0, image.stderr
    assert "W: tailnet-unlock: /boot has" in image.stderr
    assert "no tailnet door, the uplink door stays" in image.stderr
    assert "usr/sbin/tailscaled" not in files(image)
    assert "usr/sbin/dropbear" in files(image)
    assert conf(image)["TU_DEGRADED"] == "boot-space"


def test_without_the_container_only_the_recovery_door(installed: Installed) -> None:
    container = STATE / "door" / "door.tpm"
    shutil.move(container, STATE / "door" / "door.tpm.away")
    try:
        image = build(installed, "no-container")
    finally:
        shutil.move(STATE / "door" / "door.tpm.away", container)
    assert image.returncode == 0
    assert "carries the recovery door only" in image.stderr
    assert conf(image)["TU_DOOR"] == "recovery"
    assert "door-key-missing" in conf(image)["TU_DEGRADED"]
    assert "etc/tailnet-unlock/door.tpm/private" not in files(image)


def test_an_invalid_configuration_never_fails_the_build(installed: Installed) -> None:
    good = (CONFIG / "box.toml").read_text()
    (CONFIG / "box.toml").write_text(good + "\n[door]\nport = 70000\n")
    try:
        image = build(installed, "invalid")
    finally:
        (CONFIG / "box.toml").write_text(good)
    assert image.returncode == 0, image.stderr
    assert "W: tailnet-unlock: the configuration is invalid" in image.stderr
    assert conf(image)["TU_DOOR"] == "none"
    assert "usr/sbin/dropbear" not in files(image)
    assert "scripts/panic/tailnet-unlock" in files(image)


def test_unconfigured_adds_nothing_but_the_scripts(installed: Installed) -> None:
    shutil.move(CONFIG / "box.toml", CONFIG / "box.toml.away")
    try:
        image = build(installed, "unconfigured")
    finally:
        shutil.move(CONFIG / "box.toml.away", CONFIG / "box.toml")
    assert image.returncode == 0
    assert "conf/tailnet-unlock.conf" not in files(image)
    assert "usr/sbin/dropbear" not in files(image)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_the_door_runs_from_the_image(installed: Installed) -> None:
    """The image's dropbear, NSS files, busybox and door, in a chroot of the unpacked image.

    It serves the recovery key (the sealed one needs the TPM device the image expects), so this
    checks what the image carries, not the unseal (tests/tpm covers that).
    """
    image = build(installed, "chroot")
    assert image.returncode == 0, image.stderr
    root = image.tree
    for directory in ("proc", "dev", "tmp", "tailnet-unlock/run"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    subprocess.run(["mount", "-t", "proc", "proc", str(root / "proc")], check=True)
    subprocess.run(["mount", "--rbind", "/dev", str(root / "dev")], check=True)
    port = free_port()
    (root / "tailnet-unlock/run/role").write_text("recovery\n")
    (root / "tailnet-unlock/run/seal").write_text("unseal-failed\n")
    dropbear = subprocess.Popen(
        [
            "chroot",
            str(root),
            "/usr/sbin/dropbear",
            "-F",
            "-E",
            "-r",
            "/etc/tailnet-unlock/recovery_host_key",
            "-p",
            f"127.0.0.3:{port}",
            "-s",
            "-j",
            "-k",
            "-P",
            "/tailnet-unlock/run/dropbear.pid",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.3", port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        hosts = installed.work / "known_hosts"
        hosts.write_text(f"[127.0.0.3]:{port} {installed.recovery_pin}\n")
        base = [
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
            "root@127.0.0.3",
        ]
        completed = subprocess.run([*base, "status"], capture_output=True, timeout=60, check=False)
        assert completed.returncode == 0, completed.stderr.decode()
        status = parse_door_status(completed.stdout.strip())
        assert status["key"] == "recovery"
        assert status["backend"] == "zfs"
        assert status["tailscaled"] is not None
        shell = subprocess.run([*base, "id"], capture_output=True, timeout=60, check=False)
        assert b'"result":"bad-command"' in shell.stdout
        forward = subprocess.run(
            [*base[:-1], "-W", "127.0.0.1:22", base[-1]],
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert forward.returncode != 0
        assert b"SSH-" not in forward.stdout
    finally:
        dropbear.terminate()
        dropbear.wait(timeout=10)
        subprocess.run(["umount", "-R", str(root / "dev")], check=False)
        subprocess.run(["umount", str(root / "proc")], check=False)
