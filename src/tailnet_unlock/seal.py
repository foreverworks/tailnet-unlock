"""`door-keygen` and `seal`: make or import a door key and seal it to the TPM (DESIGN.md 8.1, 8.4).

`enroll`, which is planned, will call these. Plaintext keys exist only in a private
directory on a tmpfs, are overwritten before they are deleted, and the sealed key's plaintext
goes to tpm2_create on stdin. The recovery key is never sealed, by design (section 9).
"""

import os
from pathlib import Path

from tailnet_unlock.container import Container, write_container
from tailnet_unlock.doorkey import (
    check_dropbear_ed25519,
    generate_key,
    import_key,
    pin_line,
    private_workdir,
    remove_tree,
    wipe_file,
)
from tailnet_unlock.errors import DoorKeyError
from tailnet_unlock.tpm import MAX_SEALED_BYTES, run_sequence, seal_sequence, tpm_environment

DOOR_CONTAINER = "door.tpm"
RECOVERY_KEY = "recovery_host_key"


def seal_door_key(
    blob: bytes,
    final: Path,
    work_parent: Path,
    tcti: str | None,
    replace: bool,
    allow_swap: bool = False,
) -> str:
    """Seal one dropbear ed25519 key into the container at `final`; return its pin."""
    public_key = check_dropbear_ed25519(blob)
    if len(blob) > MAX_SEALED_BYTES:
        raise DoorKeyError(
            f"the key is {len(blob)} bytes; the TPM seals at most {MAX_SEALED_BYTES}"
        )
    work = private_workdir(work_parent, allow_swap)
    try:
        public, private = work / "public", work / "private"
        run_sequence(seal_sequence(work, public, private), tpm_environment(tcti), {2: blob})
        pin = pin_line(public_key)
        write_container(
            final,
            Container(
                profile="tpm", public=public.read_bytes(), private=private.read_bytes(), pin=pin
            ),
            replace,
        )
    finally:
        remove_tree(work)
    return pin


def make_key(work_parent: Path, imported: bytes | None, allow_swap: bool = False) -> bytes:
    work = private_workdir(work_parent, allow_swap)
    try:
        return generate_key(work) if imported is None else import_key(imported, work)
    finally:
        remove_tree(work)


def door_keygen(
    state_dir: Path,
    work_parent: Path,
    imported: bytes | None,
    tcti: str | None,
    replace: bool,
    allow_swap: bool = False,
) -> str:
    """Generate (or import) the door key, seal it into `state_dir/door.tpm`, return its pin."""
    blob = make_key(work_parent, imported, allow_swap)
    return seal_door_key(blob, state_dir / DOOR_CONTAINER, work_parent, tcti, replace, allow_swap)


def recovery_keygen(
    state_dir: Path,
    work_parent: Path,
    imported: bytes | None,
    replace: bool,
    allow_swap: bool = False,
) -> str:
    """Generate (or import) the recovery key, stored unsealed (0600); return its pin."""
    blob = make_key(work_parent, imported, allow_swap)
    pin = pin_line(check_dropbear_ed25519(blob))
    final = state_dir / RECOVERY_KEY
    if final.exists() and not replace:
        raise DoorKeyError(f"{final} exists; pass --replace to make a new recovery key")
    remove_stale_staging(state_dir)
    staging = final.with_name(f".{RECOVERY_KEY}.new.{os.getpid()}")
    public = final.with_name(RECOVERY_KEY + ".pub")
    public_staging = final.with_name(f".{RECOVERY_KEY}.pub.new.{os.getpid()}")
    try:
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        public_staging.write_text(pin + "\n", encoding="ascii")
        staging.rename(final)
        public_staging.rename(public)
    finally:
        # a failure part way (a full disk, a signal) leaves no plaintext key behind
        for leftover in (staging, public_staging):
            if leftover.exists():
                wipe_file(leftover)
    return pin


def remove_stale_staging(state_dir: Path) -> None:
    """Overwrite and delete what an earlier, interrupted run left of the recovery key."""
    for pattern in (f".{RECOVERY_KEY}.new.*", f".{RECOVERY_KEY}.pub.new.*"):
        for stale in state_dir.glob(pattern):
            if stale.is_file() and not stale.is_symlink():
                wipe_file(stale)
            else:
                stale.unlink()
