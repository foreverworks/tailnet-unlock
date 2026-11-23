"""Read the initramfs images on /boot and rebuild them (DESIGN.md sections 7.2, 12.5 `verify`).

An image is unpacked with `unmkinitramfs` into a private tmpfs directory, read, and wiped: it holds
the recovery key in the clear. What comes out is `ImageFacts`, plain data; the verdicts are
`verify.py`'s. Nothing an image carries is ever run: its tailscaled is compared with the installed
one, byte for byte.
"""

import filecmp
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from tailnet_unlock.doorkey import reap_work_dirs, remove_tree, require_tmpfs, work_dir
from tailnet_unlock.errors import ToolError
from tailnet_unlock.sealedstate import sealed_problem
from tailnet_unlock.system import Host

CONF = "conf/tailnet-unlock.conf"
IMAGE_STATE = "etc/tailnet-unlock/unlock.state"
IMAGE_RECOVERY = "etc/tailnet-unlock/recovery_host_key"
IMAGE_PIN = "etc/tailnet-unlock/door.tpm/pin"
IMAGE_KEYS = "root/.ssh/authorized_keys"
IMAGE_TAILSCALED = "usr/sbin/tailscaled"
# what a door needs in the image, whatever its conf says; the sealed door needs its container too
DOOR_FILES = (
    *(f"usr/lib/tailnet-unlock/{name}" for name in ("door", "supervise", "unseal", "lib.sh")),
    "usr/lib/tailnet-unlock/paths.sh",
    "usr/sbin/dropbear",
    "scripts/init-premount/tailnet-unlock",
    IMAGE_KEYS,
)
CONTAINER_FILES = tuple(
    f"etc/tailnet-unlock/door.tpm/{name}"
    for name in ("format", "profile", "public", "private", "pin")
)
IGNORED_SUFFIXES = (".dpkg-bak", ".dpkg-new", ".dpkg-old", ".new", ".old", ".bak")


@dataclass(frozen=True)
class Expected:
    """What the box's own files say an image should carry, read once."""

    state: bytes | None
    authorized_keys: str | None
    recovery_key: bytes | None
    door_pin: str | None
    local_key_files: tuple[str, ...]
    tailscaled: Path | None = None  # the installed binary an image's should equal


@dataclass(frozen=True)
class ImageFacts:
    path: str
    kernel: str
    conf_present: bool
    door: str
    recovery: bool
    tailnet: bool
    degraded: tuple[str, ...]
    port: int | None
    profile: str
    conf_tailscaled_version: str
    tailscaled_current: bool | None
    has_tailscaled: bool
    has_state: bool
    state_sealed: bool | None
    state_identical: bool | None
    keys_current: bool | None
    recovery_current: bool | None
    door_pin_current: bool | None
    local_key: bool
    missing: tuple[str, ...]


def parse_conf(text: str) -> dict[str, str]:
    """The `NAME='value'` lines the hook renders, later lines winning as they do when sourced."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if not separator or line.startswith("#") or not name.isidentifier():
            continue
        try:
            words = shlex.split(value)
        except ValueError:
            continue
        values[name] = words[0] if words else ""
    return values


def list_images(boot_dir: Path) -> list[Path]:
    return [
        path
        for path in sorted(boot_dir.glob("initrd.img-*"))
        if path.is_file() and not path.name.endswith(IGNORED_SUFFIXES)
    ]


def kernel_of(image: Path) -> str:
    return image.name.removeprefix("initrd.img-")


def unpack(host: Host, image: Path, into: Path) -> Path:
    """Unpack `image` below `into`; returns the directory of the main (or only) archive."""
    result = subprocess.run(
        [host.unmkinitramfs, str(image), str(into)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        lines = result.stderr.strip().splitlines()
        raise ToolError(
            f"unmkinitramfs {image.name}: {lines[-1] if lines else result.returncode} "
            f"(it unpacks into {into.parent}, which needs room for the whole image)"
        )
    main = into / "main"
    return main if main.is_dir() else into


def _read(tree: Path, name: str) -> bytes | None:
    path = tree / name
    if path.is_symlink() or not path.is_file():
        return None
    return path.read_bytes()


def facts_from_tree(
    image: Path,
    tree: Path,
    expected: Expected,
) -> ImageFacts:
    conf_bytes = _read(tree, CONF)
    values = parse_conf(conf_bytes.decode("utf-8", "replace")) if conf_bytes is not None else {}
    tailscaled = tree / IMAGE_TAILSCALED
    has_tailscaled = tailscaled.is_file()
    state = _read(tree, IMAGE_STATE)
    keys = _read(tree, IMAGE_KEYS)
    recovery = _read(tree, IMAGE_RECOVERY)
    pin = _read(tree, IMAGE_PIN)
    port = values.get("TU_PORT", "")
    keys_dir = tree / "etc" / "zfs" / "keys"
    carries_key = keys_dir.is_dir() and any(child.is_file() for child in keys_dir.iterdir())
    carries_key = carries_key or any(
        (tree / name.lstrip("/")).is_file() for name in expected.local_key_files
    )
    door = values.get("TU_DOOR", "none") if conf_bytes is not None else "none"
    has_recovery = values.get("TU_HAS_RECOVERY") == "yes"
    needed: tuple[str, ...] = ()
    if door != "none":
        needed = DOOR_FILES
        needed += CONTAINER_FILES if door == "sealed" else ()
        needed += (IMAGE_RECOVERY,) if has_recovery or door == "recovery" else ()
    return ImageFacts(
        path=str(image),
        kernel=kernel_of(image),
        conf_present=conf_bytes is not None,
        door=door,
        recovery=has_recovery,
        tailnet=values.get("TU_TAILNET_IN_IMAGE") == "yes",
        degraded=tuple(values.get("TU_DEGRADED", "").split()),
        port=int(port) if port.isdigit() else None,
        profile=values.get("TU_PROFILE", ""),
        conf_tailscaled_version=values.get("TU_TAILSCALED_VERSION", ""),
        tailscaled_current=(
            None
            if not has_tailscaled or expected.tailscaled is None
            else filecmp.cmp(tailscaled, expected.tailscaled, shallow=False)
        ),
        has_tailscaled=has_tailscaled,
        has_state=state is not None,
        state_sealed=None if state is None else sealed_problem(state) is None,
        state_identical=None
        if state is None or expected.state is None
        else state == expected.state,
        keys_current=(
            None
            if expected.authorized_keys is None
            else keys is not None and keys.decode("utf-8", "replace") == expected.authorized_keys
        ),
        recovery_current=(
            None
            if recovery is None or expected.recovery_key is None
            else recovery == expected.recovery_key
        ),
        door_pin_current=(
            None
            if expected.door_pin is None
            else pin is not None and pin.decode("utf-8", "replace").strip() == expected.door_pin
        ),
        local_key=carries_key,
        missing=tuple(name for name in needed if not (tree / name).is_file()),
    )


def read_image(
    host: Host,
    image: Path,
    expected: Expected,
) -> ImageFacts:
    """Unpack, read the facts, wipe. The unpacked tree holds the recovery key in the clear."""
    host.run_dir.mkdir(parents=True, exist_ok=True)
    if host.require_tmpfs:
        require_tmpfs(host.run_dir)
    reap_work_dirs(host.run_dir)
    work = work_dir(host.run_dir, "verify")
    try:
        tree = unpack(host, image, work)
        return facts_from_tree(image, tree, expected)
    finally:
        remove_tree(work)


def rebuild(host: Host) -> None:
    """`update-initramfs -u -k all`: the hook builds the door into every image."""
    result = subprocess.run(
        list(host.update_initramfs), capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        lines = result.stderr.strip().splitlines()
        raise ToolError(
            f"{host.update_initramfs[0]} failed: {lines[-1] if lines else result.returncode}"
        )


def local_key_files() -> tuple[str, ...]:
    """The key files the pool's datasets name (`keylocation=file://...`), best effort.

    Without ZFS or a pool this is empty: an image can then only be flagged for a key under
    `etc/zfs/keys`, the place Debian's installers use.
    """
    try:
        result = subprocess.run(
            ["zfs", "get", "-H", "-t", "filesystem", "-o", "value", "keylocation"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if result.returncode != 0:
        return ()
    prefix = "file://"
    names = {line[len(prefix) :] for line in result.stdout.splitlines() if line.startswith(prefix)}
    return tuple(sorted(names))
