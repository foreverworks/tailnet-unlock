"""A box in a temporary tree, for the command tests: paths, fake Tailscale, a key file."""

from dataclasses import dataclass
from pathlib import Path

import tsfake
from keys import ALICE, KEYHOLDER
from tailnet_unlock import cli
from tailnet_unlock.system import Host

BOX_TOML = """[network]
interface = "eth0"

[door]
port = 61022

[tailnet]
hostname = "box-unlock"
tags = ["tag:unlock"]
"""
SECRET = "tskey-auth-kSECRET1234567890-abcdefghijklmnop"  # noqa: S105  # made up


@dataclass(frozen=True)
class Box:
    root: Path
    host: Host
    bin: Path
    key: Path

    @property
    def staging(self) -> list[Path]:
        return sorted(self.host.run_dir.glob("*")) if self.host.run_dir.exists() else []

    def write_key(self, mode: int = 0o600, text: str = SECRET + "\n") -> None:
        self.key.write_text(text)
        self.key.chmod(mode)


def make_box(root: Path, **scenario: object) -> Box:
    host = Host(
        state_root=root / "state",
        config_dir=root / "etc",
        run_dir=root / "run",
        boot_dir=root / "boot",
        tpm_device=root / "tpmrm0",
        unmkinitramfs=str(root / "fakebin" / "unmkinitramfs"),
        update_initramfs=("true",),
        require_root=False,
        require_tmpfs=False,
        stop_grace=1.0,
    )
    host.tpm_device.write_text("")
    host.config_dir.mkdir()
    (host.config_dir / "box.toml").write_text(BOX_TOML)
    (host.config_dir / "delivery_keys").write_text(KEYHOLDER + "\n")
    (host.config_dir / "operator_keys").write_text(ALICE + "\n")
    host.state_root.mkdir()
    host.boot_dir.mkdir()
    bin_dir = root / "bin"
    tsfake.install_fakes(bin_dir, **scenario)
    box = Box(root, host, bin_dir, root / "authkey")
    box.write_key()
    return box


def with_host(host: Host) -> None:
    """Point the command line at this host (a test seam, never a command line option)."""
    cli.HOST = host
