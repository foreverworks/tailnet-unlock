"""Hand-made unpacked initramfs trees and a stand-in `unmkinitramfs`, so `verify` runs anywhere.

`unmkinitramfs IMAGE DIR` here copies the tree whose path is written in IMAGE into DIR, which is
all `verify` asks of the real one. The container tier checks the same code on real images.
"""

import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from keys import DOOR_PIN
from tailnet_unlock.authorized_keys import read_authorized_keys
from tailnet_unlock.container import Container, write_container
from tailnet_unlock.system import Host
from tsfake import sealed_state

FAKE_UNMKINITRAMFS = """#!/bin/sh
# builtins only: the verify tests run it with a PATH that holds nothing but cp
set -eu
read -r tree <"$1" || :
case $tree in
FAIL*) echo "unmkinitramfs: cannot read $1" >&2; exit 1 ;;
esac
[ -d "$tree" ] || exit 1
cp -a "$tree/." "$2"/
"""


@dataclass(frozen=True)
class Tree:
    """What an image carries; the defaults are a healthy door-only image."""

    door: str = "sealed"
    recovery: bool = True
    tailnet: bool = False
    degraded: str = ""
    tailscaled: str | None = None  # the version the carried tailscaled prints, None: no binary
    conf_version: str = ""
    state: bytes | None = None
    pin: str | None = DOOR_PIN
    keys: str | None = None  # None: the box's current render
    recovery_key: bytes | None = b"recovery-key"
    extra_files: dict[str, bytes] = field(default_factory=dict)
    conf: bool = True


def write_tree(host: Host, where: Path, tree: Tree) -> Path:
    root = where / "tree"
    if root.exists():
        shutil.rmtree(root)
    (root / "conf").mkdir(parents=True)
    (root / "root" / ".ssh").mkdir(parents=True)
    keys = tree.keys if tree.keys is not None else read_authorized_keys(host.config_dir)
    (root / "root" / ".ssh" / "authorized_keys").write_text(keys)
    if tree.conf:
        (root / "conf" / "tailnet-unlock.conf").write_text(
            "TU_BACKEND=zfs\nTU_PROFILE=tpm\nTU_PORT=61022\nTU_TAILNET=yes\n"
            f"TU_DOOR='{tree.door}'\nTU_HAS_RECOVERY='{'yes' if tree.recovery else 'no'}'\n"
            f"TU_TAILNET_IN_IMAGE='{'yes' if tree.tailnet else 'no'}'\n"
            f"TU_TAILSCALED_VERSION='{tree.conf_version}'\nTU_DEGRADED='{tree.degraded}'\n"
        )
    etc = root / "etc" / "tailnet-unlock"
    etc.mkdir(parents=True)
    if tree.pin is not None:
        (etc / "door.tpm").mkdir()
        (etc / "door.tpm" / "pin").write_text(tree.pin + "\n")
    if tree.recovery_key is not None and tree.recovery:
        (etc / "recovery_host_key").write_bytes(tree.recovery_key)
    if tree.state is not None:
        (etc / "unlock.state").write_bytes(tree.state)
    if tree.tailscaled is not None:
        binary = root / "usr" / "sbin" / "tailscaled"
        binary.parent.mkdir(parents=True)
        binary.write_text(f"#!/bin/sh\necho {tree.tailscaled}\n")
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    for name, data in tree.extra_files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def install_fake_unmkinitramfs(host: Host) -> None:
    path = Path(host.unmkinitramfs)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(FAKE_UNMKINITRAMFS)
    path.chmod(0o755)
    cp = shutil.which("cp")
    assert cp is not None
    (path.parent / "cp").unlink(missing_ok=True)
    (path.parent / "cp").symlink_to(cp)


def add_image(host: Host, kernel: str, tree: Tree, scratch: Path) -> Path:
    where = scratch / kernel
    where.mkdir(parents=True, exist_ok=True)
    root = write_tree(host, where, tree)
    image = host.boot_dir / f"initrd.img-{kernel}"
    image.write_text(str(root))
    return image


def configure_door(host: Host) -> None:
    """The box's own door container, so images are checked against its pin."""
    host.door_dir.mkdir(parents=True, exist_ok=True)
    write_container(
        host.door_dir / "door.tpm",
        Container(profile="tpm", public=b"public", private=b"private", pin=DOOR_PIN),
        replace=False,
    )


def configure_node(host: Host, state: bytes | None = None) -> bytes:
    """An enrolled node: sealed state and its record."""
    from tailnet_unlock.node import Node, write_node

    data = state if state is not None else sealed_state()
    host.tailnet_dir.mkdir(parents=True, exist_ok=True)
    host.node_state.write_bytes(data)
    write_node(
        host,
        Node(
            "n1CNTRL",
            "box-unlock",
            "box-unlock.tailnet.example",
            ("192.0.2.7",),
            ("tag:unlock",),
            "",
            "2026-11-23T10:00:00Z",
        ),
    )
    return data
