"""Build real initramfs images in the test container, shared by tests/initramfs and tests/vm.

`install_box` installs the repository where the package will put it (tools/install-tree), writes a
box configuration, imports a known door key and seals it to the swtpm state in `tpm_state`, makes
a recovery key, and places an opaque stand-in for the sealed node state. It changes the
container's /etc, /var/lib and /usr, so callers run only inside the test container.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import swtpm
from shellenv import REPO
from tailnet_unlock.seal import door_keygen, recovery_keygen

CONFIG = Path("/etc/tailnet-unlock")
STATE = Path("/var/lib/tailnet-unlock")
STATE_MARK = b"TAILNET-UNLOCK-TEST-SEALED-NODE-STATE"
BOX_TOML = """[network]
interface = "eth0"
match = "@MATCH@"

[door]
port = 2222
recovery = "uplink"
key_source = "import"

[tailnet]
enabled = true
"""


@dataclass(frozen=True)
class Installed:
    kernel: str
    door_blob: bytes
    door_pem: bytes
    door_pin: str
    recovery_pin: str
    client_key: Path
    work: Path


@dataclass(frozen=True)
class Image:
    path: Path
    tree: Path
    listing: str
    stderr: str
    returncode: int


def keygen(path: Path) -> None:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)


def install_box(work: Path, tpm_state: Path, match: str = "name") -> Installed:
    subprocess.run([str(REPO / "tools" / "install-tree"), "/"], check=True)
    kernel = sorted(os.listdir("/lib/modules"))[-1]
    CONFIG.mkdir(parents=True, exist_ok=True)
    (CONFIG / "box.toml").write_text(BOX_TOML.replace("@MATCH@", match))
    client = work / "keyholder"
    keygen(client)
    (CONFIG / "delivery_keys").write_text((work / "keyholder.pub").read_text())
    keygen(work / "operator")
    (CONFIG / "operator_keys").write_text((work / "operator.pub").read_text())
    pem_path = work / "door"
    keygen(pem_path)
    pem = pem_path.read_bytes()
    converted = work / "door.dropbear"
    subprocess.run(
        ["dropbearconvert", "openssh", "dropbear", str(pem_path), str(converted)],
        capture_output=True,
        check=True,
    )
    blob = converted.read_bytes()
    converted.unlink()
    shm = Path("/dev/shm") / f"tu-image-{os.urandom(4).hex()}"
    shm.mkdir(mode=0o700)
    try:
        with swtpm.software_tpm(tpm_state) as tcti:
            (STATE / "door").mkdir(parents=True, exist_ok=True)
            door_pin = door_keygen(STATE / "door", shm, pem, tcti, replace=True)
        recovery_pin = recovery_keygen(STATE / "door", shm, None, replace=True)
    finally:
        shutil.rmtree(shm)
    (STATE / "tailnet").mkdir(parents=True, exist_ok=True)
    (STATE / "tailnet" / "unlock.state").write_bytes(STATE_MARK + b"\n")
    return Installed(kernel, blob, pem, door_pin, recovery_pin, client, work)


def build(installed: Installed, name: str) -> Image:
    out = installed.work / f"{name}.img"
    out.unlink(missing_ok=True)
    built = subprocess.run(
        ["mkinitramfs", "-o", str(out), installed.kernel],
        capture_output=True,
        text=True,
        check=False,
    )
    tree = installed.work / f"{name}.tree"
    if tree.exists():
        shutil.rmtree(tree)
    listing = ""
    if built.returncode == 0:
        listing = subprocess.run(
            ["lsinitramfs", str(out)], capture_output=True, text=True, check=True
        ).stdout
        subprocess.run(["unmkinitramfs", str(out), str(tree)], check=True)
        main = tree / "main"
        if main.is_dir():
            tree = main
    return Image(out, tree, listing, built.stderr, built.returncode)


def conf(image: Image) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (image.tree / "conf" / "tailnet-unlock.conf").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            name, _, value = line.partition("=")
            values[name] = value.strip("'")
    return values


def files(image: Image) -> set[str]:
    return {line.strip() for line in image.listing.splitlines()}
