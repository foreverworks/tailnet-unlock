"""Pins and the door's role (DESIGN.md sections 10.1, 10.2 step 2; decision D31).

The role of a door is the pinned key the keyholder's SSH client verified, never what the door
reports: a copy of `/boot` holds the recovery key unsealed and can report anything about itself. So
the keyholder writes one known-hosts file per pin and connects with one at a time; a session that
connects proves which key the door presented.
"""

import re
from dataclasses import dataclass
from typing import Literal

from tailnet_unlock.authorized_keys import parse_public_key, public_key_line
from tailnet_unlock.errors import ConfigError, ContractError

type DoorRole = Literal["sealed", "recovery"]

# a host name or address never starts with "-", which an SSH client would read as an option
_ADDRESS = re.compile(r"[A-Za-z0-9.:][A-Za-z0-9.:-]{0,252}")


@dataclass(frozen=True)
class DoorPins:
    port: int
    door_key: str
    recovery_key: str | None


def door_pins(port: int, door_key: str, recovery_key: str | None) -> DoorPins:
    """Validate pins as pasted from a box's pins.toml: ed25519 public key lines."""
    for name, line in (("door_key", door_key), ("recovery_key", recovery_key)):
        if line is None:
            continue
        key = parse_public_key(line, name)
        if key.key_type != "ssh-ed25519":
            raise ConfigError(f"{name}: the door's host keys are ed25519")
    if (
        recovery_key is not None
        and parse_public_key(recovery_key, "recovery_key").blob
        == parse_public_key(door_key, "door_key").blob
    ):
        raise ConfigError("recovery_key: must differ from door_key")
    if not 1 <= port <= 65535:
        raise ConfigError("port: must be between 1 and 65535")
    return DoorPins(port=port, door_key=door_key, recovery_key=recovery_key)


def pinned_key(pins: DoorPins, role: DoorRole) -> str:
    if role == "sealed":
        return pins.door_key
    if pins.recovery_key is None:
        raise ConfigError("no recovery key is pinned for this host")
    return pins.recovery_key


def known_hosts(pins: DoorPins, role: DoorRole, address: str) -> str:
    """A known-hosts file holding exactly one pin, for one address."""
    if not _ADDRESS.fullmatch(address):
        raise ConfigError(f"not a host name or address: {address[:60]!r}")
    key = parse_public_key(pinned_key(pins, role), role)
    bare = key.key_type + " " + public_key_line(key).split()[1]
    return f"[{address}]:{pins.port} {bare}\n"


def roles_for_delivery(pins: DoorPins, allow_recovery_delivery: bool) -> tuple[DoorRole, ...]:
    """The pins `deliver` tries, in order: the sealed pin alone unless recovery is allowed."""
    if allow_recovery_delivery and pins.recovery_key is not None:
        return ("sealed", "recovery")
    return ("sealed",)


def roles_for_unlock(recovery: bool) -> tuple[DoorRole, ...]:
    """`unlock` by hand: the sealed pin, or with `--recovery` the recovery pin alone."""
    return ("recovery",) if recovery else ("sealed",)


def check_reported_key(verified: DoorRole, status: object) -> None:
    """Refuse a door whose `status` reports a key other than the one the client verified."""
    if not isinstance(status, dict):
        raise ContractError("door status: expected a JSON object")
    reported: object = status.get("key")
    if reported != verified:
        raise ContractError(
            f"door status reports key {str(reported)[:20]!r}, but the client "
            f"verified the {verified} pin; refusing this door"
        )
