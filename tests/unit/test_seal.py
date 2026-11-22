"""The recovery key's staging files (DESIGN.md 8.1): nothing plaintext is left after a failure."""

import os
from pathlib import Path

import pytest

from keys import RECOVERY, RECOVERY_PIN
from tailnet_unlock.doorkey import mount_fstype
from tailnet_unlock.seal import RECOVERY_KEY, recovery_keygen

SHM = Path("/dev/shm")
pytestmark = pytest.mark.skipif(
    mount_fstype(SHM, Path("/proc/self/mounts").read_text()) not in ("tmpfs", "ramfs"),
    reason="needs a tmpfs at /dev/shm for the plaintext work directory",
)


@pytest.fixture
def work() -> Path:
    path = SHM / f"tu-seal-unit-{os.getpid()}-{os.urandom(4).hex()}"
    path.mkdir(mode=0o700)
    return path


def leftovers(state: Path) -> list[str]:
    return sorted(p.name for p in state.iterdir() if p.name.startswith("."))


def test_a_failed_write_leaves_no_staging_file(
    tmp_path: Path, work: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full_disk(_: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full_disk)
    with pytest.raises(OSError, match="No space"):
        recovery_keygen(tmp_path, work, RECOVERY, replace=False)
    assert leftovers(tmp_path) == []
    assert not (tmp_path / RECOVERY_KEY).exists()


def test_a_stale_staging_file_is_removed_at_the_start(tmp_path: Path, work: Path) -> None:
    stale = tmp_path / f".{RECOVERY_KEY}.new.424242"
    stale.write_bytes(RECOVERY)
    stale_public = tmp_path / f".{RECOVERY_KEY}.pub.new.424242"
    stale_public.write_text("old\n")
    pin = recovery_keygen(tmp_path, work, RECOVERY, replace=False)
    assert pin == RECOVERY_PIN
    assert leftovers(tmp_path) == []
    assert (tmp_path / RECOVERY_KEY).read_bytes() == RECOVERY
