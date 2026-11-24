"""OpenSSH's command line, and what its exit code and stderr mean (DESIGN.md 10.1, 10.2, 10.7).

The texts are what OpenSSH 10.0 and 10.2 print at LogLevel=ERROR; tests/delivery checks them
against the real client.
"""

from pathlib import Path

import pytest

from keys import DOOR_PIN, RECOVERY_PIN
from tailnet_unlock.errors import ConfigError
from tailnet_unlock.keyholder.door import Target, classify, parse_unlock, ssh_argv
from tailnet_unlock.keyholder.pins import alias_known_hosts, door_pins, pin_fingerprint

DENIED = "root@192.0.2.10: Permission denied (publickey).\r\n"
CHANGED = (
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
    "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n"
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n"
    "Host key for tailnet-unlock-sealed-web-1 has changed and you have requested strict "
    "checking.\r\n"
    "Host key verification failed.\r\n"
)
NO_TYPE = (
    "Unable to negotiate with 192.0.2.10 port 2222: no matching host key type found. "
    "Their offer: ecdsa-sha2-nistp256\r\n"
)


@pytest.mark.parametrize(
    ("exit_code", "stderr", "outcome"),
    [
        (0, "", "session"),
        (4, "", "session"),
        (1, DENIED, "session"),
        (255, DENIED, "auth-refused"),
        (255, "root@2001:db8::1: Permission denied (publickey,password).\r\n", "auth-refused"),
        (255, CHANGED, "host-key-mismatch"),
        (255, NO_TYPE, "host-key-mismatch"),
        (255, "", "unreachable"),
        (None, DENIED, "unreachable"),
        (-9, "", "unreachable"),
        (255, "ssh: connect to host 192.0.2.10 port 2222: Connection refused\r\n", "unreachable"),
        (255, "kex_exchange_identification: read: Connection reset by peer\r\n", "unreachable"),
        # texts a server chooses before its key is verified, with line breaks of its own
        (
            255,
            "Received disconnect from 192.0.2.10 port 2222:2: x\n" + DENIED,
            "unreachable",
        ),
        (
            255,
            "Received disconnect from 192.0.2.10 port 2222:2: root@192.0.2.10: "
            "Permission denied (publickey).\r\n",
            "unreachable",
        ),
        (255, DENIED + "Connection closed by 192.0.2.10 port 2222\r\n", "unreachable"),
        (255, "\n" + DENIED, "unreachable"),
        (255, CHANGED + DENIED, "host-key-mismatch"),
    ],
)
def test_classify(exit_code: int | None, stderr: str, outcome: str) -> None:
    assert classify(exit_code, stderr) == outcome


@pytest.mark.parametrize(
    ("exit_code", "stdout", "outcome"),
    [
        (0, b'{"result":"loaded"}\n', "loaded"),
        (1, b'{"result":"wrong-key"}\n', "wrong-key"),
        (2, b'{"result":"not-waiting"}\n', "not-waiting"),
        (3, b'{"result":"boot-mismatch"}\n', "boot-mismatch"),
        (4, b'{"result":"bad-command"}\n', "bad-command"),
        (0, b"", "dropped"),
        (0, b'{"result":"wrong-key"}\n', "dropped"),
        (1, b'{"result":"loaded"}\n', "dropped"),
        (255, b'{"result":"loaded"}\n', "dropped"),
        (None, b'{"result":"loaded"}\n', "dropped"),
        (0, b'["loaded"]', "dropped"),
        (0, b"\xff", "dropped"),
        (0, b'{"result":"loaded"}' + b" " * 5000, "dropped"),
        (127, b'{"result":"loaded"}\n', "dropped"),
    ],
)
def test_parse_unlock(exit_code: int | None, stdout: bytes, outcome: str) -> None:
    assert parse_unlock(exit_code, stdout) == outcome


TARGET = Target("tailnet", "192.0.2.102", 2222, "web-1-unlock", "tailscale nc %h %p")


def test_the_command_line() -> None:
    argv = ssh_argv(TARGET, "/keys/id", Path("/tmp/x/known_hosts"), "alias", "status")
    assert argv[:4] == ("ssh", "-F", "/dev/null", "-T")
    for option in (
        "GlobalKnownHostsFile=/dev/null",
        "UserKnownHostsFile=/tmp/x/known_hosts",
        "HostKeyAlias=alias",
        "HostKeyAlgorithms=ssh-ed25519",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "IdentityFile=/keys/id",
        "BatchMode=yes",
        "ConnectTimeout=10",
        "LogLevel=ERROR",
        "ProxyCommand=tailscale nc %h %p",
    ):
        assert option in argv
    assert argv[-7:] == ("-p", "2222", "-l", "root", "--", "192.0.2.102", "status")
    keyless = ssh_argv(
        Target("uplink", "192.0.2.10", 2222, "u"), None, Path("/tmp/k"), "a", "status"
    )
    assert {"IdentityFile=none", "IdentityAgent=none"} <= set(keyless)
    assert not any(item.startswith("ProxyCommand") for item in keyless)


def test_odd_paths_and_addresses_never_reach_ssh() -> None:
    for path in ("/tmp/a b/known_hosts", "/tmp/%h", "/tmp/$HOME", '/tmp/"'):
        with pytest.raises(ConfigError):
            ssh_argv(TARGET, None, Path(path), "a", "status")
    with pytest.raises(ConfigError):
        ssh_argv(Target("uplink", "-oX", 2222, "u"), None, Path("/tmp/k"), "a", "status")


def test_one_pin_under_the_alias() -> None:
    pins = door_pins(2222, DOOR_PIN, RECOVERY_PIN)
    assert alias_known_hosts(pins, "sealed", "web-1") == f"web-1 {DOOR_PIN}\n"
    assert alias_known_hosts(pins, "recovery", "web-1") == f"web-1 {RECOVERY_PIN}\n"
    for alias in ("", "a b", "a,b\n", "*"):
        with pytest.raises(ConfigError):
            alias_known_hosts(pins, "sealed", alias)
    assert pin_fingerprint(pins, "sealed") != pin_fingerprint(pins, "recovery")
    with pytest.raises(ConfigError):
        alias_known_hosts(door_pins(2222, None, RECOVERY_PIN), "sealed", "web-1")
    with pytest.raises(ConfigError):
        door_pins(2222, None, None)
