import json

import pytest

from tailnet_unlock.errors import ContractError
from tailnet_unlock.keyholder.doorstatus import parse_door_status

GOOD: dict[str, object] = {
    "schema": "tailnet-unlock.door-status/1",
    "key": "sealed",
    "boot_id": "6f1c2b3a-0d4e-4c5f-9a8b-7e6d5c4b3a21",
    "profile": "tpm",
    "seal": "ok",
    "degraded": [],
    "backend": "zfs",
    "waiting_for": "rpool",
    "keyformat": "passphrase",
    "kernel": "6.12.117+deb13-amd64",
    "tailscaled": None,
    "restarts": {"dropbear": 0, "tailscaled": 0},
}


def line(**changes: object) -> bytes:
    body = dict(GOOD)
    body.update(changes)
    return json.dumps(body).encode()


def test_good() -> None:
    assert parse_door_status(line())["waiting_for"] == "rpool"


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": "other"},
        {"key": "SEALED"},
        {"boot_id": "x"},
        {"degraded": "a"},
        {"keyformat": "pem"},
        {"restarts": {"dropbear": -1, "tailscaled": 0}},
        {"restarts": {"dropbear": True, "tailscaled": 0}},
        {"waiting_for": 'a"b'},
        {"kernel": None},
    ],
)
def test_bad(changes: dict[str, object]) -> None:
    with pytest.raises(ContractError):
        parse_door_status(line(**changes))
