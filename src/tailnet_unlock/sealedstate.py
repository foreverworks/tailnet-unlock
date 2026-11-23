"""Is a node state file the one Tailscale's TPM store writes? (DESIGN.md sections 7.4, 8.1)

The check is pure: it reads bytes, never a TPM and never Tailscale. `enroll` runs it on the state
the second tailscaled wrote, and `verify` runs it on the copy inside each image, because a plain
state file would put the node's private keys in `/boot` in the clear.

What the check relies on, from Tailscale v1.104.7, `feature/tpm/tpm.go`:

    // encryptedData contains the secretbox-sealed data and nonce, along with a
    // TPM-sealed key. All fields are required.
    type encryptedData struct {
        Key   *tpmSealedData `json:"key"`
        Nonce []byte         `json:"nonce"`
        Data  []byte         `json:"data"`
    }
    ...
    type tpmSealedData struct {
        Private []byte
        Public  []byte
    }

and, in `newStore`, the file is refused as unsealed when

    if len(sealed.Data) == 0 || sealed.Key == nil || len(sealed.Nonce) == 0 {
        return nil, fmt.Errorf("state file %q has not been TPM-sealed or is corrupt", path)
    }

with `unseal` requiring `len(data.Nonce) == 24`. Go writes a `[]byte` as standard base64, so the
file is one JSON object with exactly the keys `key`, `nonce` and `data`. A plain state file
(`ipn.FileStore`) is a JSON object whose keys are the profile keys, such as `_machinekey` or
`_daemon`, with the secrets in the clear, so it never has this shape. The check cannot tell that
the key is sealed to this TPM; only an unseal can, which `enroll` proves by starting tailscaled on
a copy.
"""

import base64
import binascii
import json

NONCE_BYTES = 24
KEYS = {"key", "nonce", "data"}


def _bytes(value: object) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def sealed_problem(data: bytes) -> str | None:
    """Why `data` is not a TPM-sealed Tailscale state file, or None when it is one."""
    try:
        parsed: object = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return "not JSON, so not Tailscale's sealed store"
    if not isinstance(parsed, dict):
        return "not a JSON object"
    unexpected = sorted(str(name) for name in parsed if name not in KEYS)
    if unexpected:
        # a plain FileStore: the node's profile keys sit in the file in the clear
        return "holds plain state keys (" + ", ".join(unexpected[:3]) + "), not a sealed store"
    missing = sorted(KEYS - set(parsed))
    if missing:
        return "sealed store field missing: " + ", ".join(missing)
    sealed_key = parsed["key"]
    if not isinstance(sealed_key, dict):
        return "the sealed key is not an object"
    for part in ("Private", "Public"):
        if not _bytes(sealed_key.get(part)):
            return f"the sealed key has no {part} part"
    nonce = _bytes(parsed["nonce"])
    if nonce is None or len(nonce) != NONCE_BYTES:
        return "the nonce is not 24 bytes"
    if not _bytes(parsed["data"]):
        return "the sealed data is empty"
    return None
