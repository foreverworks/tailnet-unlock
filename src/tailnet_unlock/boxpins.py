"""`pins.toml`: what keyholders pin for this box (DESIGN.md sections 10.4, 12.2).

One text, made here for the `pins` command and for the file `enroll` keeps beside the state. It is
public: ports, public keys and fingerprints, the unlock node's id and the uplink address.
"""

import ipaddress
import re
import subprocess
from pathlib import Path

from tailnet_unlock.config import BoxConfig
from tailnet_unlock.container import read_container
from tailnet_unlock.doorkey import check_dropbear_ed25519, fingerprint, pin_line
from tailnet_unlock.errors import DoorKeyError
from tailnet_unlock.node import Node
from tailnet_unlock.seal import DOOR_CONTAINER, RECOVERY_KEY

HEADER = (
    "# Public: what keyholders pin for this box. Paste into keyholder.toml's",
    "# [hosts.<host>.door] table.",
)
_INET = re.compile(r"\binet (\d+\.\d+\.\d+\.\d+)/\d+")


def known_uplink(config: BoxConfig) -> str | None:
    """The uplink's address when it is known without asking the network: a static one, or the
    address the interface holds now (best effort; a DHCP lease can change)."""
    network = config.network
    if network.static is not None:
        return str(network.static.address.ip)
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", network.interface],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    found = _INET.search(result.stdout) if result.returncode == 0 else None
    if found is None:
        return None
    address = ipaddress.IPv4Address(found.group(1))
    return None if address.is_link_local or address.is_loopback else str(address)


def pins_text(
    door_dir: Path,
    port: int,
    node: Node | None,
    uplink: str | None,
    need_door: bool,
) -> str:
    """The pins as TOML text. Without a door container this raises when `need_door`, else it
    says so in a comment, so `enroll` can record the node before the door key exists."""
    lines = [*HEADER, f"port = {port}"]
    try:
        container = read_container(door_dir / DOOR_CONTAINER)
    except DoorKeyError:
        if need_door:
            raise
        lines.append("# door_key: none yet; run `tailnet-unlock door-keygen`, then `pins`")
    else:
        lines.append(f'door_key = "{container.pin}"  # {fingerprint(container.pin)}')
    recovery = door_dir / RECOVERY_KEY
    if recovery.exists():
        pin = pin_line(check_dropbear_ed25519(recovery.read_bytes()))
        lines.append(f'recovery_key = "{pin}"  # {fingerprint(pin)}')
    if node is not None:
        lines.append(f'unlock_node_id = "{node.node_id}"')
    if uplink is not None:
        lines.append(f'uplink = "{uplink}"')
    return "\n".join(lines) + "\n"
