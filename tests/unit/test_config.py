import pytest

from tailnet_unlock.config import parse_box_config, unlock_hostname
from tailnet_unlock.errors import ConfigError

MINIMAL = '[network]\ninterface = "eno1"\n'


def test_defaults() -> None:
    config = parse_box_config(MINIMAL)
    assert config.backend == "zfs"
    assert config.profile == "tpm"
    assert config.door.port == 2222
    assert config.door.recovery == "uplink"
    assert config.door.key_source == "generate"
    assert config.door.recovery_key_source == "generate"
    assert config.network.mode == "dhcp"
    assert config.network.match == "name"
    assert config.tailnet.enabled
    assert config.tailnet.tags == ("tag:unlock",)
    assert config.rehearsal_minutes is None


def test_recovery_defaults_off_under_measured() -> None:
    config = parse_box_config(MINIMAL + '[seal]\nprofile = "measured"\n')
    assert config.door.recovery == "off"


def test_static_network() -> None:
    config = parse_box_config(
        '[network]\nmode = "static"\ninterface = "eno1"\naddress = "192.0.2.10/24"\n'
        'gateway = "192.0.2.1"\ndns = ["192.0.2.53", "198.51.100.53"]\n'
    )
    assert config.network.static is not None
    assert str(config.network.static.address) == "192.0.2.10/24"
    assert [str(item) for item in config.network.static.dns] == ["192.0.2.53", "198.51.100.53"]


@pytest.mark.parametrize(
    "text, message",
    [
        ("", "network"),
        ('[network]\ninterface = "eno1; rm -rf /"\n', "network.interface"),
        (MINIMAL + "[door]\nport = 0\n", "door.port"),
        (MINIMAL + '[door]\nport = "2222"\n', "door.port"),
        (MINIMAL + "[door]\nport = true\n", "door.port"),
        (MINIMAL + '[door]\nrecovery = "tailnet"\n', "door.recovery"),
        (MINIMAL + '[door]\nkey_source = "file"\n', "door.key_source"),
        (MINIMAL + "[door]\nportt = 2222\n", "unknown key"),
        (MINIMAL + '[seal]\nprofile = "grub"\n', "seal.profile"),
        (MINIMAL + '[root]\nbackend = "luks"\n', "root.backend"),
        (MINIMAL + '[tailnet]\ntags = ["unlock"]\n', "tailnet.tags"),
        (MINIMAL + "[tailnet]\ntags = []\n", "tailnet.tags"),
        (
            MINIMAL + '[tailnet]\nlogin_server = "http://headscale.example.com"\n',
            "tailnet.login_server",
        ),
        (MINIMAL + '[tailnet]\nhostname = "Web_1"\n', "tailnet.hostname"),
        ('[network]\nmode = "static"\ninterface = "eno1"\n', "network.address"),
        ('[network]\nmode = "static"\ninterface = "eno1"\naddress = "192.0.2.10"\n', "prefix"),
        ('[network]\ninterface = "eno1"\ndns = ["192.0.2.53"]\n', "network.dns"),
        ('[network]\ninterface = "eno1"\naddress = "192.0.2.10/24"\n', "static"),
        (MINIMAL + "[rehearsal]\nminutes = 0\n", "rehearsal.minutes"),
        ("not toml [", "box.toml"),
    ],
)
def test_invalid(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message.replace(".", r"\.")):
        parse_box_config(text)


def test_unlock_hostname() -> None:
    config = parse_box_config(MINIMAL)
    assert unlock_hostname(config.tailnet, "web-1.example.com") == "web-1-unlock"
    assert unlock_hostname(config.tailnet, "WEB_1") == "web-1-unlock"
    named = parse_box_config(MINIMAL + '[tailnet]\nhostname = "door-7"\n')
    assert unlock_hostname(named.tailnet, "web-1") == "door-7"


def test_the_example_is_valid() -> None:
    from pathlib import Path

    example = Path(__file__).resolve().parents[2] / "examples" / "box.toml"
    config = parse_box_config(example.read_text())
    assert config.door.recovery == "uplink"
