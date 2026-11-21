"""The role is the key the client verified (decision D31; scenario T25 at the unit level)."""

import pytest

from keys import DOOR_PIN, RECOVERY_PIN
from tailnet_unlock.errors import ConfigError, ContractError
from tailnet_unlock.keyholder.pins import (
    check_reported_key,
    door_pins,
    known_hosts,
    roles_for_delivery,
    roles_for_unlock,
)

PINS = door_pins(2222, DOOR_PIN, RECOVERY_PIN)


def test_one_pin_per_known_hosts_file() -> None:
    sealed = known_hosts(PINS, "sealed", "web-1-unlock")
    recovery = known_hosts(PINS, "recovery", "192.0.2.10")
    assert sealed == f"[web-1-unlock]:2222 {DOOR_PIN}\n"
    assert recovery == f"[192.0.2.10]:2222 {RECOVERY_PIN}\n"
    assert RECOVERY_PIN.split()[1] not in sealed


def test_delivery_tries_the_sealed_pin_alone_by_default() -> None:
    assert roles_for_delivery(PINS, allow_recovery_delivery=False) == ("sealed",)
    assert roles_for_delivery(PINS, allow_recovery_delivery=True) == ("sealed", "recovery")
    no_recovery = door_pins(2222, DOOR_PIN, None)
    assert roles_for_delivery(no_recovery, allow_recovery_delivery=True) == ("sealed",)
    assert roles_for_unlock(recovery=True) == ("recovery",)
    assert roles_for_unlock(recovery=False) == ("sealed",)


def test_a_copy_of_boot_claiming_sealed_is_refused() -> None:
    """The verified pin was the recovery one; the door says sealed. Refuse."""
    with pytest.raises(ContractError, match="verified the recovery pin"):
        check_reported_key("recovery", {"key": "sealed"})
    check_reported_key("recovery", {"key": "recovery"})
    check_reported_key("sealed", {"key": "sealed"})
    with pytest.raises(ContractError):
        check_reported_key("sealed", {"key": "recovery"})
    with pytest.raises(ContractError):
        check_reported_key("sealed", ["sealed"])


@pytest.mark.parametrize("address", ["", "a b", "x;id", "[::1]", "h" * 254])
def test_known_hosts_refuses_odd_addresses(address: str) -> None:
    with pytest.raises(ConfigError):
        known_hosts(PINS, "sealed", address)


def test_pins_validation() -> None:
    with pytest.raises(ConfigError):
        door_pins(2222, DOOR_PIN, DOOR_PIN)
    with pytest.raises(ConfigError):
        door_pins(0, DOOR_PIN, None)
    with pytest.raises(ConfigError):
        known_hosts(door_pins(2222, DOOR_PIN, None), "recovery", "web-1")
