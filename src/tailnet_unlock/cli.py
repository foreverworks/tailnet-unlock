"""The `tailnet-unlock` command line: the M1 building blocks (DESIGN.md section 12.5).

`door-keygen`, `seal`, `render-initramfs` and `pins`. The commands that use them (`enroll`,
`verify`, `deliver` and the rest) come in later milestones.
"""

import argparse
import os
import socket
import sys
from collections.abc import Sequence
from pathlib import Path

from tailnet_unlock import __version__
from tailnet_unlock.authorized_keys import parse_key_list, render_authorized_keys
from tailnet_unlock.config import parse_box_config
from tailnet_unlock.container import read_container
from tailnet_unlock.doorkey import check_dropbear_ed25519, fingerprint, pin_line
from tailnet_unlock.errors import ConfigError, DoorKeyError, ToolError, TpmError
from tailnet_unlock.render import BuildFacts, render_conf
from tailnet_unlock.seal import (
    DOOR_CONTAINER,
    RECOVERY_KEY,
    door_keygen,
    make_key,
    recovery_keygen,
    seal_door_key,
)

STATE_DIR = Path("/var/lib/tailnet-unlock/door")
WORK_DIR = Path("/run/tailnet-unlock")
CONFIG_DIR = Path("/etc/tailnet-unlock")
MAX_STDIN = 16384


def _read_input(name: str) -> bytes:
    if name == "-":
        return sys.stdin.buffer.read(MAX_STDIN + 1)
    return Path(name).read_bytes()[: MAX_STDIN + 1]


def _work_parent(argument: str | None) -> Path:
    if argument is not None:
        return Path(argument)
    WORK_DIR.mkdir(mode=0o700, exist_ok=True)
    return WORK_DIR


def _cmd_door_keygen(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    imported = None if args.import_file is None else _read_input(args.import_file)
    work = _work_parent(args.work_dir)
    if args.recovery:
        pin = recovery_keygen(state_dir, work, imported, args.replace)
        print(f'recovery_key = "{pin}"  # {fingerprint(pin)}, stored unsealed by design')
    else:
        pin = door_keygen(state_dir, work, imported, args.tcti, args.replace)
        print(f'door_key = "{pin}"  # {fingerprint(pin)}, sealed to this TPM')
    return 0


def _cmd_seal(args: argparse.Namespace) -> int:
    imported = _read_input("-")
    work = _work_parent(args.work_dir)
    blob = make_key(work, imported)
    pin = seal_door_key(blob, Path(args.container), work, args.tcti, args.replace)
    print(f'door_key = "{pin}"  # {fingerprint(pin)}, sealed to this TPM')
    return 0


def _uplink_mac(interface: str) -> str | None:
    try:
        return Path(f"/sys/class/net/{interface}/address").read_text(encoding="ascii").strip()
    except OSError:
        return None


def _cmd_render(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    config = parse_box_config((config_dir / "box.toml").read_text(encoding="utf-8"))
    delivery = parse_key_list(_read_optional(config_dir / "delivery_keys"), "delivery_keys")
    operator = parse_key_list(_read_optional(config_dir / "operator_keys"), "operator_keys")
    if not delivery and not operator:
        raise ConfigError(
            "delivery_keys and operator_keys are both empty: nobody could log in to the door"
        )
    facts = BuildFacts(
        host=args.host or socket.gethostname(),
        uplink_mac=args.uplink_mac or _uplink_mac(config.network.interface),
    )
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    (out / "tailnet-unlock.conf").write_text(render_conf(config, facts), encoding="utf-8")
    keys = out / "authorized_keys"
    keys.write_text(render_authorized_keys(delivery, operator), encoding="ascii")
    os.chmod(keys, 0o600)
    return 0


def _read_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _cmd_pins(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir)
    container = read_container(state_dir / DOOR_CONTAINER)
    lines = [
        "# Public: what keyholders pin for this box. Paste into keyholder.toml's",
        "# [hosts.<host>.door] table.",
        f"port = {args.port}",
        f'door_key = "{container.pin}"  # {fingerprint(container.pin)}',
    ]
    recovery = state_dir / RECOVERY_KEY
    if recovery.exists():
        pin = pin_line(check_dropbear_ed25519(recovery.read_bytes()))
        lines.append(f'recovery_key = "{pin}"  # {fingerprint(pin)}')
    print("\n".join(lines))
    return 0


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    print(fingerprint(Path(args.public_key).read_text(encoding="ascii").strip()))
    return 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="tailnet-unlock", description=__doc__)
    top.add_argument("--version", action="version", version=__version__)
    commands = top.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("door-keygen", help="make or import a door key and seal it")
    keygen.add_argument(
        "--recovery",
        action="store_true",
        help="the recovery key instead, stored unsealed by design",
    )
    keygen.add_argument(
        "--import",
        dest="import_file",
        metavar="FILE",
        help="import an ed25519 private key (OpenSSH or dropbear format); - is stdin",
    )
    keygen.add_argument("--state-dir", default=str(STATE_DIR))
    keygen.add_argument("--work-dir", help=f"a tmpfs directory for plaintext (default {WORK_DIR})")
    keygen.add_argument(
        "--tcti", help="the TPM transport (default $TPM2TOOLS_TCTI, then device:/dev/tpmrm0)"
    )
    keygen.add_argument("--replace", action="store_true")
    keygen.set_defaults(handler=_cmd_door_keygen)

    seal = commands.add_parser("seal", help="seal a private key read on stdin into a container")
    seal.add_argument("--container", required=True)
    seal.add_argument("--work-dir")
    seal.add_argument("--tcti")
    seal.add_argument("--replace", action="store_true")
    seal.set_defaults(handler=_cmd_seal)

    render = commands.add_parser(
        "render-initramfs", help="validate box.toml and write what the image carries"
    )
    render.add_argument("--config-dir", default=str(CONFIG_DIR))
    render.add_argument("--out", required=True)
    render.add_argument("--host")
    render.add_argument("--uplink-mac")
    render.set_defaults(handler=_cmd_render)

    pins = commands.add_parser("pins", help="print what keyholders pin for this box")
    pins.add_argument("--state-dir", default=str(STATE_DIR))
    pins.add_argument("--port", type=int, default=2222)
    pins.set_defaults(handler=_cmd_pins)
    fp = commands.add_parser(
        "fingerprint", help="print the SHA256 fingerprint of a public key file"
    )
    fp.add_argument("public_key")
    fp.set_defaults(handler=_cmd_fingerprint)
    return top


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        code: int = args.handler(args)
    except (ConfigError, DoorKeyError, TpmError, ToolError, OSError) as error:
        print(f"tailnet-unlock: {error}", file=sys.stderr)
        return 2
    return code
