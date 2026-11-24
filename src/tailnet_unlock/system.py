"""Where the box keeps things, as one frozen value the commands take (DESIGN.md section 12.2).

The command line builds the real one. A test builds another that points into a temporary tree, so
nothing here is a hidden global and no command needs an option that exists only for tests.
"""

import os
from dataclasses import dataclass
from pathlib import Path

STATE_ROOT = Path("/var/lib/tailnet-unlock")
CONFIG_DIR = Path("/etc/tailnet-unlock")
RUN_DIR = Path("/run/tailnet-unlock")
BOOT_DIR = Path("/boot")


@dataclass(frozen=True)
class Host:
    state_root: Path = STATE_ROOT
    config_dir: Path = CONFIG_DIR
    run_dir: Path = RUN_DIR
    boot_dir: Path = BOOT_DIR
    tpm_device: Path = Path("/dev/tpmrm0")
    unmkinitramfs: str = "unmkinitramfs"
    update_initramfs: tuple[str, ...] = ("update-initramfs", "-u", "-k", "all")
    # Python-level seams for the tests, never reachable from the command line: they are what a
    # test without root, a tmpfs or a TPM turns off.
    require_root: bool = True
    require_tmpfs: bool = True
    encrypt_state: bool = True
    stop_grace: float = 20.0
    logout_timeout: int = 60

    @property
    def door_dir(self) -> Path:
        return self.state_root / "door"

    @property
    def tailnet_dir(self) -> Path:
        return self.state_root / "tailnet"

    @property
    def node_state(self) -> Path:
        return self.tailnet_dir / "unlock.state"

    @property
    def node_file(self) -> Path:
        return self.tailnet_dir / "node.json"

    @property
    def pins_file(self) -> Path:
        return self.state_root / "pins.toml"

    @property
    def boot_record(self) -> Path:
        return self.run_dir / "boot.json"


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Write beside the file and rename into place, so a reader never sees half of it."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.new.{os.getpid()}")
    staging.unlink(missing_ok=True)  # left by a process that had this pid and was killed
    fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staging, mode)
        staging.rename(path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
