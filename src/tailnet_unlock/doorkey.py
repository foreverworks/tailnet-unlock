"""Door host keys: dropbear's ed25519 format, pins and fingerprints (DESIGN.md sections 8.1, 8.3).

dropbear writes an ed25519 private key as `string "ssh-ed25519"`, then `string` of 64 bytes
(the 32-byte seed followed by the 32-byte public key): 83 bytes, under the TPM's 128-byte limit
for sealed data. The pure functions here read that format and derive the OpenSSH public line (the
pin) and its SHA256 fingerprint without running a tool; `generate_key` and `convert_openssh_key`
are the edge that runs dropbearkey and dropbearconvert, always inside a tmpfs work directory.
"""

import base64
import hashlib
import os
import subprocess
from pathlib import Path

from tailnet_unlock.errors import DoorKeyError, ToolError

ED25519 = b"ssh-ed25519"
DROPBEAR_ED25519_LENGTH = 4 + len(ED25519) + 4 + 64
OPENSSH_PEM_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"
MAX_IMPORT_BYTES = 16384


def _string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def check_dropbear_ed25519(blob: bytes) -> bytes:
    """Return the 32-byte public key of a dropbear ed25519 private key, or raise."""
    if len(blob) != DROPBEAR_ED25519_LENGTH or not blob.startswith(_string(ED25519)):
        raise DoorKeyError("not a dropbear ed25519 private key (the door takes ed25519 only)")
    if blob[15:19] != (64).to_bytes(4, "big"):
        raise DoorKeyError("dropbear ed25519 key with an unexpected key length")
    return blob[51:83]


def public_blob(public_key: bytes) -> bytes:
    return _string(ED25519) + _string(public_key)


def pin_line(public_key: bytes) -> str:
    """The OpenSSH public key line keyholders pin: `ssh-ed25519 <base64>`."""
    return "ssh-ed25519 " + base64.b64encode(public_blob(public_key)).decode("ascii")


def fingerprint(pin: str) -> str:
    """OpenSSH's `SHA256:` fingerprint of a public key line."""
    parts = pin.split()
    if len(parts) < 2:
        raise DoorKeyError("not a public key line")
    blob = base64.b64decode(parts[1], validate=True)
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def mount_fstype(path: Path, mounts: str) -> str | None:
    """The file system type of the mount holding `path`, from /proc/self/mounts text."""
    resolved = str(path)
    best: tuple[int, str] | None = None
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        point = fields[1].replace("\\040", " ")
        inside = resolved == point or resolved.startswith(point.rstrip("/") + "/")
        if inside and (best is None or len(point) >= best[0]):
            best = (len(point), fields[2])
    return None if best is None else best[1]


def require_tmpfs(path: Path) -> None:
    """Plaintext keys are only ever written to a tmpfs; refuse any other work directory."""
    mounts = Path("/proc/self/mounts").read_text(encoding="utf-8")
    fstype = mount_fstype(path.resolve(), mounts)
    if fstype not in ("tmpfs", "ramfs"):
        raise DoorKeyError(f"{path}: the work directory must be on a tmpfs, not {fstype}")


def private_workdir(parent: Path) -> Path:
    require_tmpfs(parent)
    work = parent / f"tailnet-unlock.{os.getpid()}.{os.urandom(6).hex()}"
    work.mkdir(mode=0o700)
    return work


def remove_tree(path: Path) -> None:
    """Delete a work directory after overwriting each file in it."""
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            remove_tree(child)
            continue
        if child.is_file() and not child.is_symlink():
            wipe_file(child)
        else:
            child.unlink()
    path.rmdir()


def _run(argv: list[str], what: str) -> None:
    result = subprocess.run(argv, capture_output=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise ToolError(f"{what} failed: {detail[-1] if detail else result.returncode}")


def generate_key(work: Path) -> bytes:
    """A new dropbear ed25519 key, made in `work` (a tmpfs) and removed from it."""
    target = work / "generated"
    try:
        _run(["dropbearkey", "-t", "ed25519", "-f", str(target)], "dropbearkey")
        blob = target.read_bytes()
    finally:
        if target.exists():
            wipe_file(target)
    check_dropbear_ed25519(blob)
    return blob


def wipe_file(path: Path) -> None:
    """Overwrite a file with zeros, then delete it."""
    size = path.stat().st_size
    with path.open("r+b") as handle:
        handle.write(b"\0" * size)
    path.unlink()


def convert_openssh_key(pem: bytes, work: Path) -> bytes:
    """An OpenSSH-format ed25519 private key, converted to dropbear's format in `work`."""
    source = work / "import.openssh"
    target = work / "import.dropbear"
    fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    try:
        _run(
            ["dropbearconvert", "openssh", "dropbear", str(source), str(target)], "dropbearconvert"
        )
        blob = target.read_bytes()
    finally:
        for path in (source, target):
            if path.exists():
                wipe_file(path)
    return blob


def import_key(data: bytes, work: Path) -> bytes:
    """A private key a consumer provisions (OpenSSH or dropbear format), as dropbear ed25519."""
    if len(data) > MAX_IMPORT_BYTES:
        raise DoorKeyError("the imported key is too large to be an ed25519 private key")
    is_pem = data.lstrip().startswith(OPENSSH_PEM_BEGIN)
    blob = convert_openssh_key(data, work) if is_pem else data
    check_dropbear_ed25519(blob)
    return blob
