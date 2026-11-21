import base64
import hashlib
from pathlib import Path

import pytest

from keys import DOOR, DOOR_PIN
from tailnet_unlock.container import Container, read_container, write_container
from tailnet_unlock.doorkey import (
    check_dropbear_ed25519,
    fingerprint,
    mount_fstype,
    pin_line,
    remove_tree,
)
from tailnet_unlock.errors import DoorKeyError


def test_dropbear_format_is_83_bytes_and_fits_the_tpm() -> None:
    assert len(DOOR) == 83
    assert len(DOOR) <= 128
    assert check_dropbear_ed25519(DOOR) == DOOR[51:]


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        DOOR[:-1],
        DOOR + b"x",
        b"\x00\x00\x00\x07ssh-rsa" + DOOR[11:],
        DOOR[:15] + (32).to_bytes(4, "big") + DOOR[19:],
    ],
)
def test_not_a_dropbear_ed25519_key(blob: bytes) -> None:
    with pytest.raises(DoorKeyError):
        check_dropbear_ed25519(blob)


def test_pin_and_fingerprint_match_openssh() -> None:
    blob = base64.b64decode(DOOR_PIN.split()[1])
    assert blob == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + DOOR[51:]
    expected = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert fingerprint(DOOR_PIN) == f"SHA256:{expected}"
    assert pin_line(DOOR[51:]) == DOOR_PIN


MOUNTS = """rpool/ROOT / zfs rw 0 0
tmpfs /run tmpfs rw 0 0
tmpfs /dev/shm tmpfs rw 0 0
/dev/sda1 /boot ext4 rw 0 0
"""


def test_mount_fstype_picks_the_longest_prefix() -> None:
    assert mount_fstype(Path("/run/tailnet-unlock/x"), MOUNTS) == "tmpfs"
    assert mount_fstype(Path("/runaway"), MOUNTS) == "zfs"
    assert mount_fstype(Path("/boot"), MOUNTS) == "ext4"
    assert mount_fstype(Path("/var/lib"), MOUNTS) == "zfs"


def test_remove_tree_overwrites_and_deletes(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "k").write_bytes(b"secret")
    remove_tree(work)
    assert not work.exists()


def test_container_round_trip(tmp_path: Path) -> None:
    final = tmp_path / "door.tpm"
    container = Container(profile="tpm", public=b"pub", private=b"priv", pin=DOOR_PIN)
    write_container(final, container, replace=False)
    assert read_container(final) == container
    assert (final / "format").read_text() == "tailnet-unlock door 1\n"
    assert oct((final / "private").stat().st_mode & 0o777) == "0o600"
    with pytest.raises(DoorKeyError, match="exists"):
        write_container(final, container, replace=False)
    replaced = Container(profile="tpm", public=b"pub2", private=b"priv2", pin=DOOR_PIN)
    write_container(final, replaced, replace=True)
    assert read_container(final) == replaced
    assert sorted(path.name for path in tmp_path.iterdir()) == ["door.tpm"]


def test_container_refuses_measured_for_now(tmp_path: Path) -> None:
    with pytest.raises(DoorKeyError, match="M6"):
        write_container(
            tmp_path / "door.tpm",
            Container(profile="measured", public=b"", private=b"", pin=DOOR_PIN),
            False,
        )


def test_unknown_container_format(tmp_path: Path) -> None:
    final = tmp_path / "door.tpm"
    write_container(final, Container(profile="tpm", public=b"p", private=b"q", pin=DOOR_PIN), False)
    (final / "format").write_text("tailnet-unlock door 2\n")
    with pytest.raises(DoorKeyError, match="format"):
        read_container(final)
