"""The sealed door key container, `door.tpm/` (DESIGN.md section 8.3).

A directory, because the initramfs's shell cannot parse a structured file safely. It is written next
to its final place and renamed into it, so a reader never sees half of one.
"""

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from tailnet_unlock.config import PROFILES, Profile
from tailnet_unlock.errors import DoorKeyError

FORMAT = "tailnet-unlock door 1"


@dataclass(frozen=True)
class Container:
    profile: Profile
    public: bytes
    private: bytes
    pin: str


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def write_container(final: Path, container: Container, replace: bool) -> None:
    if container.profile != "tpm":
        raise DoorKeyError("only the tpm profile is built in this release (measured is M6)")
    if final.exists() and not replace:
        raise DoorKeyError(f"{final} exists; pass --replace to make a new door key")
    staging = final.with_name(f".{final.name}.new.{os.getpid()}")
    staging.mkdir(mode=0o700)
    try:
        _write(staging / "format", (FORMAT + "\n").encode("ascii"))
        _write(staging / "profile", (container.profile + "\n").encode("ascii"))
        _write(staging / "public", container.public)
        _write(staging / "private", container.private)
        _write(staging / "pin", (container.pin + "\n").encode("ascii"))
        if final.exists():
            retired = final.with_name(f".{final.name}.old.{os.getpid()}")
            final.rename(retired)
            staging.rename(final)
            shutil.rmtree(retired)
        else:
            staging.rename(final)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    directory = os.open(final.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_container(path: Path) -> Container:
    try:
        format_line = (path / "format").read_text(encoding="ascii").strip()
        profile = (path / "profile").read_text(encoding="ascii").strip()
        public = (path / "public").read_bytes()
        private = (path / "private").read_bytes()
        pin = (path / "pin").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise DoorKeyError(f"{path}: not a readable door container: {error}") from error
    if format_line != FORMAT:
        raise DoorKeyError(f"{path}: unknown container format {format_line[:40]!r}")
    for known in PROFILES:
        if profile == known:
            return Container(profile=known, public=public, private=private, pin=pin)
    raise DoorKeyError(f"{path}: unknown profile {profile[:20]!r}")
