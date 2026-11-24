"""Pins and the door's role (DESIGN.md sections 10.1, 10.2 step 2; decision D31).

The role of a door is the pinned key the keyholder's SSH client verified, never what the door
reports: a copy of `/boot` holds the recovery key unsealed and can report anything about itself. So
the keyholder writes one known-hosts file per pin and connects with one at a time; a session that
connects proves which key the door presented.
"""

import base64
import hashlib
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
    """`door_key` is None for a host that has only a recovery door (a box without a TPM)."""

    port: int
    door_key: str | None
    recovery_key: str | None


def door_pins(port: int, door_key: str | None, recovery_key: str | None) -> DoorPins:
    """Validate pins as pasted from a box's pins.toml: ed25519 public key lines."""
    if door_key is None and recovery_key is None:
        raise ConfigError("door_key: required (or recovery_key alone, for a box without a TPM)")
    for name, line in (("door_key", door_key), ("recovery_key", recovery_key)):
        if line is None:
            continue
        key = parse_public_key(line, name)
        if key.key_type != "ssh-ed25519":
            raise ConfigError(f"{name}: the door's host keys are ed25519")
    if (
        door_key is not None
        and recovery_key is not None
        and parse_public_key(recovery_key, "recovery_key").blob
        == parse_public_key(door_key, "door_key").blob
    ):
        raise ConfigError("recovery_key: must differ from door_key")
    if not 1 <= port <= 65535:
        raise ConfigError("port: must be between 1 and 65535")
    return DoorPins(port=port, door_key=door_key, recovery_key=recovery_key)


def pinned_key(pins: DoorPins, role: DoorRole) -> str:
    if role == "sealed":
        if pins.door_key is None:
            raise ConfigError("no sealed door key is pinned for this host")
        return pins.door_key
    if pins.recovery_key is None:
        raise ConfigError("no recovery key is pinned for this host")
    return pins.recovery_key


def _bare_pin(pins: DoorPins, role: DoorRole) -> str:
    key = parse_public_key(pinned_key(pins, role), role)
    return key.key_type + " " + public_key_line(key).split()[1]


def pin_fingerprint(pins: DoorPins, role: DoorRole) -> str:
    """The pinned key's SHA256 fingerprint, as `ssh-keygen -l` prints it."""
    blob = parse_public_key(pinned_key(pins, role), role).blob
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def alias_known_hosts(pins: DoorPins, role: DoorRole, alias: str) -> str:
    """A known-hosts file holding exactly one pin, under the HostKeyAlias the client is given."""
    if not _ADDRESS.fullmatch(alias):
        raise ConfigError(f"not a host key alias: {alias[:60]!r}")
    return f"{alias} {_bare_pin(pins, role)}\n"


def check_address(address: str) -> str:
    if not _ADDRESS.fullmatch(address):
        raise ConfigError(f"not a host name or address: {address[:60]!r}")
    return address


def known_hosts(pins: DoorPins, role: DoorRole, address: str) -> str:
    """A known-hosts file holding exactly one pin, for one address."""
    return f"[{check_address(address)}]:{pins.port} {_bare_pin(pins, role)}\n"


def roles_for_delivery(pins: DoorPins, allow_recovery_delivery: bool) -> tuple[DoorRole, ...]:
    """The pins `deliver` tries, in order: the sealed pin alone unless recovery is allowed.

    Empty for a host that has only a recovery door while recovery delivery is not allowed.
    """
    sealed: tuple[DoorRole, ...] = () if pins.door_key is None else ("sealed",)
    if allow_recovery_delivery and pins.recovery_key is not None:
        return (*sealed, "recovery")
    return sealed


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
