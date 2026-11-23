"""Render the door's /root/.ssh/authorized_keys from two plain lists (DESIGN.md 7.2, step 4).

`delivery_keys` and `operator_keys` hold plain public keys, one per line. A line that carries
options of its own is refused, so no line in the image can lack the options and the forced command
the hook adds. The role comes from which list a key is in, never from the client.
"""

import base64
import binascii
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from tailnet_unlock.errors import ConfigError

type Role = Literal["delivery", "operator"]

DOOR_COMMAND = "/usr/lib/tailnet-unlock/door"
DELIVERY_OPTIONS = f'restrict,command="{DOOR_COMMAND} delivery"'
OPERATOR_OPTIONS = (
    f'no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="{DOOR_COMMAND} operator"'
)

KEY_TYPES = (
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",  # push-guard: allow (an SSH key type name)
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",  # push-guard: allow (an SSH key type name)
    "ssh-rsa",
)

_COMMENT = re.compile(r"[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?")


@dataclass(frozen=True)
class PublicKey:
    key_type: str
    blob: bytes
    comment: str


def public_key_line(key: PublicKey) -> str:
    encoded = base64.b64encode(key.blob).decode("ascii")
    return f"{key.key_type} {encoded}" + (f" {key.comment}" if key.comment else "")


def _read_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise ValueError("truncated")
    length = int.from_bytes(blob[offset : offset + 4], "big")
    end = offset + 4 + length
    if end > len(blob):
        raise ValueError("truncated")
    return blob[offset + 4 : end], end


def parse_public_key(line: str, where: str) -> PublicKey:
    """One plain OpenSSH public key line: `<type> <base64> [comment]`."""
    parts = line.strip().split(None, 2)
    if len(parts) < 2:
        raise ConfigError(f"{where}: expected '<type> <base64> [comment]'")
    key_type, encoded = parts[0], parts[1]
    if key_type not in KEY_TYPES:
        raise ConfigError(
            f"{where}: {key_type[:40]!r} is not a key type the door accepts; a "
            "line must be a plain public key, without options (the hook adds them)"
        )
    try:
        blob = base64.b64decode(encoded, validate=True)
        inner_type, _ = _read_string(blob, 0)
    except (binascii.Error, ValueError) as error:
        raise ConfigError(f"{where}: the key data is not valid base64 SSH key data") from error
    if inner_type != key_type.encode("ascii"):
        raise ConfigError(
            f"{where}: the key data says {inner_type[:40]!r}, the line says {key_type!r}"
        )
    comment = parts[2].strip() if len(parts) == 3 else ""
    if comment and not _COMMENT.fullmatch(comment):
        raise ConfigError(f"{where}: the comment holds characters other than printable ASCII")
    return PublicKey(key_type=key_type, blob=blob, comment=comment)


def parse_key_list(text: str, name: str) -> tuple[PublicKey, ...]:
    keys: list[PublicKey] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keys.append(parse_public_key(stripped, f"{name}:{number}"))
    return tuple(keys)


def render_authorized_keys(delivery: tuple[PublicKey, ...], operator: tuple[PublicKey, ...]) -> str:
    seen: dict[bytes, Role] = {}
    lists: tuple[tuple[Role, tuple[PublicKey, ...]], ...] = (
        ("delivery", delivery),
        ("operator", operator),
    )
    for role, keys in lists:
        for key in keys:
            if key.blob in seen:
                raise ConfigError(
                    f"a key is listed twice (as {seen[key.blob]} and as {role}); "
                    "each key gets exactly one role"
                )
            seen[key.blob] = role
    lines = ["# Rendered by tailnet-unlock at build time from delivery_keys and operator_keys."]
    lines += ["# from delivery_keys: automation, no terminal"]
    lines += [f"{DELIVERY_OPTIONS} {public_key_line(key)}" for key in delivery]
    lines += ["# from operator_keys: people, who need a terminal for the no-echo prompt"]
    lines += [f"{OPERATOR_OPTIONS} {public_key_line(key)}" for key in operator]
    return "\n".join(lines) + "\n"


def read_authorized_keys(config_dir: Path) -> str:
    """The door's authorized_keys as the hook renders it, from the two key lists."""
    delivery = parse_key_list(_read_optional(config_dir / "delivery_keys"), "delivery_keys")
    operator = parse_key_list(_read_optional(config_dir / "operator_keys"), "operator_keys")
    if not delivery and not operator:
        raise ConfigError(
            "delivery_keys and operator_keys are both empty: nobody could log in to the door"
        )
    return render_authorized_keys(delivery, operator)


def _read_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
