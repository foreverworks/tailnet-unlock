import base64
import hashlib
from pathlib import Path

import pytest

from keys import DOOR, DOOR_PIN
from tailnet_unlock import doorkey
from tailnet_unlock.container import Container, read_container, write_container
from tailnet_unlock.doorkey import (
    check_dropbear_ed25519,
    disk_swap_devices,
    ed25519_public_key,
    fingerprint,
    mount_fstype,
    pin_line,
    private_workdir,
    remove_tree,
    require_no_swap,
    swap_devices,
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


def test_the_public_half_must_be_the_seeds_own() -> None:
    forged = DOOR[:51] + bytes(32)
    with pytest.raises(DoorKeyError, match="public half"):
        check_dropbear_ed25519(forged)
    swapped = DOOR[:19] + bytes([0x33]) * 32 + DOOR[51:]
    with pytest.raises(DoorKeyError, match="public half"):
        check_dropbear_ed25519(swapped)


def test_ed25519_public_key_matches_the_rfc_8032_vectors() -> None:
    vectors = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ),
    ]
    for seed, public in vectors:
        assert ed25519_public_key(bytes.fromhex(seed)).hex() == public


def test_swap_devices_reads_proc_swaps() -> None:
    header = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
    assert swap_devices(header) == []
    assert swap_devices(header + "/dev/zram0 partition 1024 0 100\n") == ["/dev/zram0"]
    assert swap_devices("") == []


def test_zram_is_ram_and_is_not_swap_to_a_disk() -> None:
    header = "Filename Type Size Used Priority\n"
    both = header + "/dev/zram0 partition 1024 0 100\n/dev/vda4 partition 2048 0 -2\n"
    assert disk_swap_devices(both) == ["/dev/vda4"]
    assert disk_swap_devices(header + "/dev/zram0 partition 1024 0 100\n") == []


def test_allow_swap_warns_and_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    swaps = tmp_path / "swaps"
    swaps.write_text("Filename Type Size Used Priority\n/dev/vda4 partition 2048 0 -2\n")
    monkeypatch.setattr(doorkey, "PROC_SWAPS", swaps)
    with pytest.raises(DoorKeyError, match="--allow-swap"):
        require_no_swap()
    assert require_no_swap(allow_swap=True) is True
    assert "warning: swap is active (/dev/vda4)" in capsys.readouterr().err
    swaps.write_text("Filename Type Size Used Priority\n/dev/zram0 partition 1024 0 100\n")
    assert require_no_swap() is False


def test_no_plaintext_key_is_made_while_swap_is_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    swaps = tmp_path / "swaps"
    swaps.write_text("Filename Type Size Used Priority\n/swapfile file 1024 0 -2\n")
    monkeypatch.setattr(doorkey, "PROC_SWAPS", swaps)
    with pytest.raises(DoorKeyError, match="swap is active"):
        private_workdir(tmp_path)
    assert list(tmp_path.glob("tailnet-unlock.*")) == []


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
    with pytest.raises(DoorKeyError, match="built so far"):
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
