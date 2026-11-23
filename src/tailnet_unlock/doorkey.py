"""Door host keys: dropbear's ed25519 format, pins and fingerprints (DESIGN.md sections 8.1, 8.3).

dropbear writes an ed25519 private key as `string "ssh-ed25519"`, then `string` of 64 bytes
(the 32-byte seed followed by the 32-byte public key): 83 bytes, under the TPM's 128-byte limit
for sealed data. The pure functions here read that format and derive the OpenSSH public line (the
pin) and its SHA256 fingerprint without running a tool; `generate_key` and `convert_openssh_key`
are the edge that runs dropbearkey and dropbearconvert, always inside a tmpfs work directory and
never with swap active.
"""

import base64
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from tailnet_unlock.errors import DoorKeyError, ToolError

ED25519 = b"ssh-ed25519"
DROPBEAR_ED25519_LENGTH = 4 + len(ED25519) + 4 + 64
OPENSSH_PEM_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"
MAX_IMPORT_BYTES = 16384
PROC_SWAPS = Path("/proc/swaps")


def _string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P


def _add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    """Add two points of the edwards25519 curve (affine coordinates, RFC 8032 section 5.1.4)."""
    cross = _D * a[0] * b[0] * a[1] * b[1] % _P
    x = (a[0] * b[1] + b[0] * a[1]) * pow(1 + cross, -1, _P) % _P
    y = (a[1] * b[1] + a[0] * b[0]) * pow(1 - cross, -1, _P) % _P
    return x, y


def _base_point() -> tuple[int, int]:
    y = 4 * pow(5, -1, _P) % _P
    x_squared = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    x = pow(x_squared, (_P + 3) // 8, _P)
    if (x * x - x_squared) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    return (_P - x if x % 2 else x), y


def ed25519_public_key(seed: bytes) -> bytes:
    """The public key of an ed25519 seed (RFC 8032 section 5.1.5), stdlib only.

    Used to check that the public half stored beside a seed is the seed's own. It runs on a
    secret, offline, in the enrolment tool, where timing is not an exposure.
    """
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar = (scalar & ((1 << 254) - 8)) | (1 << 254)
    result = (0, 1)
    addend = _base_point()
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return (result[1] | (result[0] & 1) << 255).to_bytes(32, "little")


def check_dropbear_ed25519(blob: bytes) -> bytes:
    """Return the 32-byte public key of a dropbear ed25519 private key, or raise.

    The public half stored beside the seed must be the seed's own: a key whose halves differ would
    be sealed and pinned under one identity and present another.
    """
    if len(blob) != DROPBEAR_ED25519_LENGTH or not blob.startswith(_string(ED25519)):
        raise DoorKeyError("not a dropbear ed25519 private key (the door takes ed25519 only)")
    if blob[15:19] != (64).to_bytes(4, "big"):
        raise DoorKeyError("dropbear ed25519 key with an unexpected key length")
    if ed25519_public_key(blob[19:51]) != blob[51:83]:
        raise DoorKeyError("dropbear ed25519 key whose public half is not its seed's public key")
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


def swap_devices(swaps: str) -> list[str]:
    """The active swap areas listed in /proc/swaps text (the first line is the header)."""
    return [line.split()[0] for line in swaps.splitlines()[1:] if line.split()]


def disk_swap_devices(swaps: str) -> list[str]:
    """The swap areas that can reach a disk: every one but a zram device, which is RAM."""
    return [device for device in swap_devices(swaps) if not device.startswith("/dev/zram")]


def require_no_swap(allow_swap: bool = False) -> bool:
    """Plaintext keys are only ever written to RAM that cannot be swapped out.

    A tmpfs page can be written to swap, and so can the memory holding a key this process read,
    so with a swap area that reaches a disk active no plaintext key is made. `allow_swap` (the
    operator's `--allow-swap`, for a box where `swapoff -a` is unsafe) turns the refusal into a
    warning on stderr. Returns whether such swap was active, so the caller can record it.
    """
    active = disk_swap_devices(PROC_SWAPS.read_text(encoding="utf-8"))
    if not active:
        return False
    listed = ", ".join(active[:3])
    if not allow_swap:
        raise DoorKeyError(
            f"swap is active ({listed}): plaintext key material could be written to disk. "
            "Run `swapoff -a` (and keep swap off) while keys are made, or pass --allow-swap "
            "if that is unsafe on this box"
        )
    print(
        f"tailnet-unlock: warning: swap is active ({listed}); --allow-swap lets plaintext key "
        "material reach disk",
        file=sys.stderr,
    )
    return True


def require_tmpfs(path: Path) -> None:
    """Plaintext keys are only ever written to a tmpfs; refuse any other work directory."""
    mounts = Path("/proc/self/mounts").read_text(encoding="utf-8")
    fstype = mount_fstype(path.resolve(), mounts)
    if fstype not in ("tmpfs", "ramfs"):
        raise DoorKeyError(f"{path}: the work directory must be on a tmpfs, not {fstype}")


def private_workdir(parent: Path, allow_swap: bool = False) -> Path:
    require_no_swap(allow_swap)
    require_tmpfs(parent)
    work = parent / f"tailnet-unlock.{os.getpid()}.{os.urandom(6).hex()}"
    work.mkdir(mode=0o700)
    return work


def work_dir(parent: Path, kind: str) -> Path:
    """A 0700 directory below `parent` named after this process, so a later run can tell one whose
    process died before it could wipe it."""
    return Path(tempfile.mkdtemp(prefix=f"{kind}.{os.getpid()}.", dir=parent))


def reap_work_dirs(parent: Path) -> None:
    """Wipe what a killed run left behind: the `work_dir`s whose process is gone."""
    for path in parent.glob("*.*.*"):
        kind, pid, _ = path.name.split(".", 2)
        if kind not in ("enroll", "verify") or not pid.isdigit() or path.is_symlink():
            continue
        if path.is_dir() and not Path("/proc", pid).exists():
            remove_tree(path)


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
