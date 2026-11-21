import pytest

from keys import ALICE, KEYHOLDER, openssh_line
from tailnet_unlock.authorized_keys import (
    DELIVERY_OPTIONS,
    OPERATOR_OPTIONS,
    parse_key_list,
    render_authorized_keys,
)
from tailnet_unlock.errors import ConfigError


def test_render() -> None:
    delivery = parse_key_list(f"# keyholders\n{KEYHOLDER}\n\n", "delivery_keys")
    operator = parse_key_list(ALICE + "\n", "operator_keys")
    text = render_authorized_keys(delivery, operator)
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    assert lines == [f"{DELIVERY_OPTIONS} {KEYHOLDER}", f"{OPERATOR_OPTIONS} {ALICE}"]
    assert 'command="/usr/lib/tailnet-unlock/door delivery"' in lines[0]
    assert lines[0].startswith("restrict,")
    assert "restrict" not in lines[1]


@pytest.mark.parametrize(
    "line",
    [
        f'command="/bin/sh" {KEYHOLDER}',
        f"no-pty {KEYHOLDER}",
        "ssh-ed25519",
        "ssh-ed25519 not-base64!!",
        "ssh-dss AAAAB3NzaC1kc3MAAACBAP",
        openssh_line("ssh-rsa", b"\x00", "x").replace("ssh-rsa ", "ssh-ed25519 ", 1),
        KEYHOLDER + ' "quoted\x07"',
    ],
)
def test_refused(line: str) -> None:
    with pytest.raises(ConfigError):
        parse_key_list(line, "delivery_keys")


def test_a_key_gets_one_role() -> None:
    keys = parse_key_list(KEYHOLDER, "delivery_keys")
    with pytest.raises(ConfigError, match="twice"):
        render_authorized_keys(keys, keys)
