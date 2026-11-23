"""The `tailnet-unlock` command line (DESIGN.md section 12.5).

`door-keygen`, `seal`, `render-initramfs`, `pins` and `fingerprint`, and the box's lifecycle:
`enroll`, `verify`, `status` and `disable --tailnet`. The rest (`deliver`, `commit`, `rotate`)
are planned.
"""

import argparse
import dataclasses
import json
import os
import signal
import socket
import sys
from collections.abc import Sequence
from pathlib import Path

from tailnet_unlock import __version__
from tailnet_unlock.authorized_keys import read_authorized_keys
from tailnet_unlock.boxpins import known_uplink, pins_text
from tailnet_unlock.checks import run_verify
from tailnet_unlock.config import BoxConfig, parse_box_config, unlock_hostname
from tailnet_unlock.disable import DISABLE_SCHEMA, disable_tailnet
from tailnet_unlock.doorkey import fingerprint
from tailnet_unlock.enroll import ENROLL_SCHEMA, EnrollRequest, enroll
from tailnet_unlock.errors import ConfigError, DoorKeyError, ToolError, TpmError
from tailnet_unlock.images import rebuild
from tailnet_unlock.node import node_json, read_node
from tailnet_unlock.render import BuildFacts, render_conf
from tailnet_unlock.seal import (
    door_keygen,
    make_key,
    recovery_keygen,
    seal_door_key,
)
from tailnet_unlock.status import gather, render_text, status_json
from tailnet_unlock.system import CONFIG_DIR, RUN_DIR, STATE_ROOT, Host
from tailnet_unlock.verify import floor_from, result_json
from tailnet_unlock.verify import render_text as render_verify_text
from tailnet_unlock.versions import FLOOR, version_text

HOST = Host()
# the commands whose --state-dir is the door keys' directory, as it always was
DOOR_DIR_COMMANDS = ("door-keygen", "pins")
WORK_DIR = RUN_DIR
MAX_STDIN = 16384
SWAP_HELP = (
    "make keys even though swap (other than zram, or dm-crypt under a random key) is active, where "
    "`swapoff -a` is unsafe; the plaintext key may reach the disk, and the output says so"
)


def _read_input(name: str) -> bytes:
    if name == "-":
        return sys.stdin.buffer.read(MAX_STDIN + 1)
    with Path(name).open("rb") as handle:
        return handle.read(MAX_STDIN + 1)


def _print_swap_note(allow_swap: bool) -> None:
    """The record that --allow-swap was used: it is in the output enroll keeps with the pins."""
    if allow_swap:
        print("# made with --allow-swap: plaintext key material may have reached a swap device")


def _work_parent(argument: str | None) -> Path:
    if argument is not None:
        return Path(argument)
    WORK_DIR.mkdir(mode=0o700, exist_ok=True)
    return WORK_DIR


def _cmd_door_keygen(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir) if args.state_dir else HOST.door_dir
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    imported = None if args.import_file is None else _read_input(args.import_file)
    work = _work_parent(args.work_dir)
    if args.recovery:
        pin = recovery_keygen(state_dir, work, imported, args.replace, args.allow_swap)
        print(f'recovery_key = "{pin}"  # {fingerprint(pin)}, stored unsealed by design')
    else:
        pin = door_keygen(state_dir, work, imported, args.tcti, args.replace, args.allow_swap)
        print(f'door_key = "{pin}"  # {fingerprint(pin)}, sealed to this TPM')
    _print_swap_note(args.allow_swap)
    return 0


def _cmd_seal(args: argparse.Namespace) -> int:
    imported = _read_input("-")
    work = _work_parent(args.work_dir)
    blob = make_key(work, imported, args.allow_swap)
    pin = seal_door_key(blob, Path(args.container), work, args.tcti, args.replace, args.allow_swap)
    print(f'door_key = "{pin}"  # {fingerprint(pin)}, sealed to this TPM')
    _print_swap_note(args.allow_swap)
    return 0


def _uplink_mac(interface: str) -> str | None:
    try:
        return Path(f"/sys/class/net/{interface}/address").read_text(encoding="ascii").strip()
    except OSError:
        return None


def _cmd_render(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    config = parse_box_config((config_dir / "box.toml").read_text(encoding="utf-8"))
    keys_text = read_authorized_keys(config_dir)
    facts = BuildFacts(
        host=args.host or socket.gethostname(),
        uplink_mac=args.uplink_mac or _uplink_mac(config.network.interface),
    )
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    (out / "tailnet-unlock.conf").write_text(render_conf(config, facts), encoding="utf-8")
    keys = out / "authorized_keys"
    keys.write_text(keys_text, encoding="ascii")
    os.chmod(keys, 0o600)
    return 0


def _host(args: argparse.Namespace) -> Host:
    """The real host, with `--state-dir` and `--config-dir` where the command has them."""
    state = getattr(args, "state_dir", None) if args.command not in DOOR_DIR_COMMANDS else None
    config = getattr(args, "config_dir", None)
    return dataclasses.replace(
        HOST,
        state_root=HOST.state_root if state is None else Path(state),
        config_dir=HOST.config_dir if config is None else Path(config),
    )


def _load_config(host: Host) -> BoxConfig:
    path = host.config_dir / "box.toml"
    try:
        return parse_box_config(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"{path} does not exist: write box.toml first") from None


def _cmd_pins(args: argparse.Namespace) -> int:
    host = _host(args)
    door_dir = Path(args.state_dir) if args.state_dir else host.door_dir
    node = read_node(dataclasses.replace(host, state_root=door_dir.parent))
    try:
        config: BoxConfig | None = _load_config(host)
    except ConfigError:
        if args.port is None:
            raise
        config = None
    port = args.port if args.port is not None else (config.door.port if config else 0)
    uplink = None if config is None else known_uplink(config)
    print(pins_text(door_dir, port, node, uplink, need_door=True), end="")
    return 0


def _on_signal(signum: int, frame: object) -> None:
    """A closed terminal or a stop leaves through the same cleanup as an error does."""
    del frame
    raise SystemExit(128 + signum)


def _check_after_rebuild(host: Host, config: BoxConfig, tailnet_expected: bool) -> int:
    """Rebuild every image and read each back; 1 when an image has a problem."""
    try:
        rebuild(host)
    except ToolError as error:
        raise ToolError(f"the images were not rebuilt: {error}") from error
    checked = dataclasses.replace(
        config, tailnet=dataclasses.replace(config.tailnet, enabled=tailnet_expected)
    )
    result = run_verify(host, checked, FLOOR, False)
    if result.ok:
        return 0
    print(render_verify_text(result), file=sys.stderr)
    return 1


def _cmd_enroll(args: argparse.Namespace) -> int:
    host = _host(args)
    config = _load_config(host)
    request = EnrollRequest(
        auth_key_file=Path(args.auth_key_file),
        replace=args.replace,
        timeout=args.timeout,
        hostname=unlock_hostname(config.tailnet, socket.gethostname()),
    )
    result = enroll(host, config, request)
    fields = {key: value for key, value in node_json(result.node).items() if key != "schema"}
    print(json.dumps({"schema": ENROLL_SCHEMA, "changed": result.changed, **fields}))
    if result.replaced_node_id is not None and result.replaced_node_id != result.node.node_id:
        print(
            f"tailnet-unlock: the replaced node {result.replaced_node_id} still exists: "
            "delete it in the Tailscale admin console",
            file=sys.stderr,
        )
    if not result.changed or args.no_rebuild:
        return 0
    try:
        return _check_after_rebuild(host, config, tailnet_expected=True)
    except (ConfigError, ToolError, OSError) as error:
        raise ToolError(f"the node is enrolled, but {error}") from error


def _cmd_verify(args: argparse.Namespace) -> int:
    host = _host(args)
    config = _load_config(host)
    boot_dir = Path(args.boot_dir) if args.boot_dir else None
    result = run_verify(
        host, config, floor_from(args.tailscale_floor), args.allow_unenrolled, boot_dir
    )
    print(result_json(result) if args.json else render_verify_text(result))
    return 0 if result.ok else 1


def _cmd_status(args: argparse.Namespace) -> int:
    result = gather(_host(args))
    print(status_json(result) if args.json else render_text(result))
    return 0


def _cmd_disable(args: argparse.Namespace) -> int:
    if not args.tailnet:
        raise ConfigError("name what to disable: only `disable --tailnet` is built")
    host = _host(args)
    outcome = disable_tailnet(host, not args.no_logout, host.logout_timeout)
    print(
        json.dumps(
            {
                "schema": DISABLE_SCHEMA,
                "changed": outcome.changed,
                "node_id": outcome.node_id,
                "logged_out": outcome.logged_out,
            }
        )
    )
    if outcome.node_id is not None:
        print(
            f"tailnet-unlock: delete the node {outcome.node_id} in the Tailscale admin console"
            + ("" if outcome.logged_out else " (it was not logged out)"),
            file=sys.stderr,
        )
    if args.no_rebuild:
        return 0
    return _check_after_rebuild(host, _load_config(host), tailnet_expected=False)


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    print(fingerprint(Path(args.public_key).read_text(encoding="ascii").strip()))
    return 0


def _state_dir(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--state-dir",
        help=f"the state directory (default {STATE_ROOT}); the door's keys are in its door/",
    )


def _door_dir(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--state-dir",
        help=f"the door keys' directory (default {STATE_ROOT / 'door'})",
    )


def _config_dir(command: argparse.ArgumentParser) -> None:
    command.add_argument("--config-dir", help=f"where box.toml is (default {CONFIG_DIR})")


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
    _door_dir(keygen)
    keygen.add_argument("--work-dir", help=f"a tmpfs directory for plaintext (default {WORK_DIR})")
    keygen.add_argument(
        "--tcti", help="the TPM transport (default $TPM2TOOLS_TCTI, then device:/dev/tpmrm0)"
    )
    keygen.add_argument("--replace", action="store_true")
    keygen.add_argument("--allow-swap", action="store_true", help=SWAP_HELP)
    keygen.set_defaults(handler=_cmd_door_keygen)

    seal = commands.add_parser("seal", help="seal a private key read on stdin into a container")
    seal.add_argument("--container", required=True)
    seal.add_argument("--work-dir")
    seal.add_argument("--tcti")
    seal.add_argument("--replace", action="store_true")
    seal.add_argument("--allow-swap", action="store_true", help=SWAP_HELP)
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
    _door_dir(pins)
    _config_dir(pins)
    pins.add_argument(
        "--port",
        type=int,
        help="the door's port (default: door.port in box.toml)",
    )
    pins.set_defaults(handler=_cmd_pins)

    enrolling = commands.add_parser(
        "enroll",
        help="enroll the unlock node on the tailnet from a one-time auth key",
        description=(
            "Joins the tailnet as the unlock node with a second tailscaled, checks its state is "
            "sealed to the TPM, installs it and rebuilds the initramfs images. The door's own "
            "keys come from `door-keygen`. The key file is overwritten and deleted, always."
        ),
    )
    enrolling.add_argument(
        "--auth-key-file",
        required=True,
        metavar="FILE",
        help="a single-use, tagged, pre-authorized auth key: a file owned by root, mode 0600",
    )
    enrolling.add_argument(
        "--replace", action="store_true", help="enroll again over an existing unlock node"
    )
    enrolling.add_argument(
        "--no-rebuild", action="store_true", help="skip `update-initramfs -u -k all` and verify"
    )
    enrolling.add_argument(
        "--timeout",
        type=int,
        default=120,
        metavar="SECONDS",
        help="how long each wait for tailscaled may take (default 120)",
    )
    _state_dir(enrolling)
    _config_dir(enrolling)
    enrolling.set_defaults(handler=_cmd_enroll)

    verifying = commands.add_parser(
        "verify", help="read every initramfs image back and report what is wrong"
    )
    verifying.add_argument("--json", action="store_true", help="print JSON instead of text")
    verifying.add_argument(
        "--tailscale-floor",
        default=version_text(FLOOR),
        metavar="X.Y.Z",
        help="the oldest tailscaled an image may carry (default %(default)s)",
    )
    verifying.add_argument("--boot-dir", help="where the images are (default /boot)")
    verifying.add_argument(
        "--allow-unenrolled",
        action="store_true",
        help="do not count a configured but unenrolled tailnet door as a problem (uplink-only box)",
    )
    _state_dir(verifying)
    _config_dir(verifying)
    verifying.set_defaults(handler=_cmd_verify)

    showing = commands.add_parser(
        "status", help="show how the box is set up and how it last booted"
    )
    showing.add_argument("--json", action="store_true", help="print JSON instead of text")
    _state_dir(showing)
    _config_dir(showing)
    showing.set_defaults(handler=_cmd_status)

    disabling = commands.add_parser(
        "disable", help="take a part of the door out of the box (only --tailnet is built)"
    )
    disabling.add_argument(
        "--tailnet",
        action="store_true",
        help="log the unlock node out, delete its state and rebuild the images without tailscaled",
    )
    disabling.add_argument(
        "--no-rebuild", action="store_true", help="skip `update-initramfs -u -k all` and verify"
    )
    disabling.add_argument(
        "--no-logout", action="store_true", help="delete the state without logging the node out"
    )
    _state_dir(disabling)
    _config_dir(disabling)
    disabling.set_defaults(handler=_cmd_disable)

    fp = commands.add_parser(
        "fingerprint", help="print the SHA256 fingerprint of a public key file"
    )
    fp.add_argument("public_key")
    fp.set_defaults(handler=_cmd_fingerprint)
    return top


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, _on_signal)
    try:
        code: int = args.handler(args)
    except (ConfigError, DoorKeyError, TpmError, ToolError, OSError) as error:
        print(f"tailnet-unlock: {error}", file=sys.stderr)
        return 2
    return code
