import pytest

from tailnet_unlock.errors import ContractError
from tailnet_unlock.keyholder.keymaterial import wire_key


def test_one_trailing_newline_is_removed_for_passphrase_and_hex() -> None:
    assert wire_key(b"correct horse battery\n", "passphrase") == b"correct horse battery"
    assert wire_key(b"correct horse battery", "passphrase") == b"correct horse battery"
    assert wire_key(b"ab" * 32 + b"\n", "hex") == b"ab" * 32


def test_raw_is_exactly_32_bytes() -> None:
    raw = bytes(range(32))
    assert wire_key(raw, "raw") == raw
    with pytest.raises(ContractError):
        wire_key(raw + b"\n", "raw")
    with pytest.raises(ContractError):
        wire_key(raw[:31], "raw")
    newline_inside = b"\n" * 32
    assert wire_key(newline_inside, "raw") == newline_inside


@pytest.mark.parametrize(
    "output, keyformat",
    [
        (b"correct horse battery\n\n", "passphrase"),
        (b"two\nlines here", "passphrase"),
        (b"short\n", "passphrase"),
        (b"x" * 513, "passphrase"),
        (b"x" * 514, "passphrase"),
        (b"zz" * 32, "hex"),
        (b"ab" * 31, "hex"),
    ],
)
def test_refused(output: bytes, keyformat: str) -> None:
    with pytest.raises(ContractError):
        wire_key(output, "passphrase" if keyformat == "passphrase" else "hex")


def test_512_byte_passphrase_with_its_newline_fits() -> None:
    assert len(wire_key(b"x" * 512 + b"\n", "passphrase")) == 512
