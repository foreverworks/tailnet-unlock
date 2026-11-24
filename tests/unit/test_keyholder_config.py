"""keyholder.toml (DESIGN.md 12.4): strict, typed, and what it refuses."""

import pytest

from keys import DOOR_PIN, RECOVERY_PIN
from khkit import CONFIG, make_host
from shellenv import REPO
from tailnet_unlock.errors import ConfigError
from tailnet_unlock.keyholder.config import NodeRef, host_config, parse_keyholder_config

SECOND = f"""
[hosts.web-2]
[hosts.web-2.door]
door_key = "{DOOR_PIN}"
uplink = "192.0.2.11"
"""
WATCH_ONLY = f"""
[defaults]
on_waiting = ["/usr/local/bin/start-delivery"]
[hosts.web-1.door]
recovery_key = "{RECOVERY_PIN}"
uplink = "192.0.2.10"
"""


def test_the_whole_file() -> None:
    config = parse_keyholder_config(CONFIG)
    host = host_config(config, "web-1")
    assert config.tailscale == ("tailscale",)
    assert host.node == NodeRef("web-1", None)
    assert host.unlock_node == NodeRef(None, "nUNLOCK1CNTRL")
    assert host.key_command == ("pass", "show", "unlock/web-1")
    assert host.settings.approver == ("approve",)
    assert host.settings.door_wait_minutes == 1
    assert host.settings.approval_timeout_seconds == 900
    assert host.settings.allow_recovery_delivery is False
    assert (host.settings.alarm_after_seconds, host.settings.alarm_repeat_hours) == (60, 24)
    assert (host.uplink, host.uplink_port) == ("192.0.2.10", 2222)
    assert [str(item) for item in host.expected_endpoints] == ["198.51.100.0/24"]


def test_a_host_overrides_a_default() -> None:
    host = make_host(
        (('node = "web-1"', 'node = "web-1"\napprover = []\nallow_recovery_delivery = true'),)
    )
    assert host.settings.approver == ()
    assert host.settings.allow_recovery_delivery is True
    assert host.settings.door_wait_minutes == 1


def test_a_watch_only_file_parses_without_any_key() -> None:
    host = host_config(parse_keyholder_config(WATCH_ONLY), "web-1")
    assert host.settings.ssh_key is None
    assert host.key_command == ()
    assert host.pins.door_key is None
    assert host.unlock_node is None


def test_the_lines_pins_prints_are_the_door_table() -> None:
    """What `tailnet-unlock pins` prints is pasted into [hosts.<name>.door] as it is."""
    pasted = (
        f'port = 2222\ndoor_key = "{DOOR_PIN}"  # SHA256:x\nrecovery_key = "{RECOVERY_PIN}"\n'
        'unlock_node_id = "n1CNTRL"\nuplink = "192.0.2.10"\n'
    )
    parse_keyholder_config(f"[hosts.web-1.door]\n{pasted}")


def test_the_example_parses() -> None:
    text = (REPO / "examples" / "keyholder.toml").read_text(encoding="utf-8")
    config = parse_keyholder_config(text)
    assert config.hosts


def test_an_unknown_host() -> None:
    with pytest.raises(ConfigError, match="web-9"):
        host_config(parse_keyholder_config(CONFIG), "web-9")


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("[defaults]", "[defaults]\nsurprise = 1", "unknown key"),
        ("[defaults]", '[defaults]\non_alarm = "expire"', "API credential"),
        ("[defaults]", '[defaults]\non_alarm = "page"', "only"),
        ("[defaults]", '[defaults]\nkey_command = ["x"]', "unknown key"),
        ("door_wait_minutes = 1", "door_wait_minutes = true", "integer"),
        ("door_wait_minutes = 1", "door_wait_minutes = 9999", "between"),
        ('approver = ["approve"]', 'approver = "approve --yes"', "list of strings"),
        ('approver = ["approve"]', 'approver = [""]', "names the program"),
        ('approver = ["approve"]', 'approver = ["a\\u0000b"]', "NUL"),
        ("/etc/tailnet-unlock/keyholder/id_ed25519", "id_ed25519", "absolute"),
        ("/etc/tailnet-unlock/keyholder/id_ed25519", "/etc/%h/id", "absolute"),
        ("/etc/tailnet-unlock/keyholder/id_ed25519", "/etc/a b", "absolute"),
        ("[defaults]", '[defaults]\nssh_proxy_command = "a\\nb"', "one command line"),
        ("[hosts.web-1]", '[hosts.web-1]\ntailscale = ["x"]', "unknown key"),
        ('node = "web-1"', 'node = "-web"', "not a node name"),
        ('node = "web-1"', 'node_id = "n/1"', "not a stable node id"),
        ("198.51.100.0/24", "198.51.100.1/24", "not a network"),
        ('uplink = "192.0.2.10"', 'uplink = "-oProxyCommand=id"', "not a host name"),
        ("port = 2222", "port = 0", "between"),
        ("port = 2222", "ports = 2222", "unknown key"),
        (DOOR_PIN, "ssh-ed25519 AAAA", "key data"),
        (RECOVERY_PIN, DOOR_PIN, "must differ"),
        ("[hosts.web-1.door]", "[hosts.web-1.dor]", "unknown key"),
    ],
)
def test_refused(old: str, new: str, message: str) -> None:
    assert old in CONFIG
    with pytest.raises(ConfigError, match=message):
        parse_keyholder_config(CONFIG.replace(old, new))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "no \\[hosts"),
        ("not toml", "keyholder.toml"),
        ("[hosts.web-1]", "door: required"),
        (f'[hosts.web-1.door]\ndoor_key = "{DOOR_PIN}"', "needs uplink"),
        ('[hosts.web-1.door]\nuplink = "192.0.2.1"', "door_key: required"),
        (f'[hosts.web-1.door]\ndoor_key = "{DOOR_PIN}"\nuplink_port = 22', "needs uplink"),
        (f'[hosts."../x".door]\ndoor_key = "{DOOR_PIN}"\nuplink = "192.0.2.1"', "host name"),
        (CONFIG + SECOND, "the same key"),
    ],
)
def test_refused_files(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_keyholder_config(text)
