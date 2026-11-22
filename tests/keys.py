"""Fixed test keys. Made-up bytes, never used anywhere real."""

import base64

from tailnet_unlock.doorkey import ed25519_public_key, pin_line


def dropbear_ed25519(seed_byte: int) -> bytes:
    """A dropbear-format ed25519 private key: a recognisable, fake seed and its real public half."""
    seed = bytes([seed_byte]) * 32
    public = ed25519_public_key(seed)
    return (
        len(b"ssh-ed25519").to_bytes(4, "big")
        + b"ssh-ed25519"
        + (64).to_bytes(4, "big")
        + seed
        + public
    )


DOOR = dropbear_ed25519(0x11)
RECOVERY = dropbear_ed25519(0x22)
DOOR_PIN = pin_line(DOOR[51:])
RECOVERY_PIN = pin_line(RECOVERY[51:])


def openssh_line(key_type: str, payload: bytes, comment: str = "") -> str:
    blob = len(key_type).to_bytes(4, "big") + key_type.encode() + payload
    line = f"{key_type} {base64.b64encode(blob).decode()}"
    return f"{line} {comment}" if comment else line


ALICE = openssh_line("ssh-ed25519", (32).to_bytes(4, "big") + b"A" * 32, "alice")
KEYHOLDER = openssh_line("ssh-ed25519", (32).to_bytes(4, "big") + b"K" * 32, "keyholder")
