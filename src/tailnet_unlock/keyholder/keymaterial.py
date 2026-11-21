"""What goes on the wire to `unlock` (DESIGN.md sections 7.3 step 4, 10.6).

The key's bytes with no framing and no trailing newline. A key source's output is read up to 513
bytes; for `passphrase` and `hex` keys exactly one trailing newline is removed, and a `raw` key
must be exactly 32 bytes.
"""

import re
from typing import Literal

from tailnet_unlock.errors import ContractError

type KeyFormat = Literal["passphrase", "hex", "raw"]

MAX_KEY_SOURCE_BYTES = 513
MAX_WIRE_BYTES = 512
_HEX = re.compile(rb"[0-9a-fA-F]{64}")


def key_format(value: object) -> KeyFormat:
    if value == "passphrase":
        return "passphrase"
    if value == "hex":
        return "hex"
    if value == "raw":
        return "raw"
    raise ContractError(f"unknown keyformat {str(value)[:20]!r}")


def wire_key(output: bytes, keyformat: KeyFormat) -> bytes:
    """Normalise a key source's output into the bytes sent to the door, or refuse it."""
    if len(output) > MAX_KEY_SOURCE_BYTES:
        raise ContractError("the key source printed more than 513 bytes")
    if keyformat == "raw":
        if len(output) != 32:
            raise ContractError(
                f"a raw key is exactly 32 bytes; the key source printed {len(output)}"
            )
        return output
    key = output[:-1] if output.endswith(b"\n") else output
    if b"\n" in key or b"\r" in key:
        raise ContractError("the key holds a line break; a passphrase or hex key is one line")
    if keyformat == "hex" and not _HEX.fullmatch(key):
        raise ContractError("a hex key is exactly 64 hexadecimal digits")
    if keyformat == "passphrase" and not 8 <= len(key) <= MAX_WIRE_BYTES:
        raise ContractError("a ZFS passphrase is 8 to 512 bytes")
    return key
