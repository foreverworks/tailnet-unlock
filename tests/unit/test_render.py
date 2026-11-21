import shlex
import subprocess

import pytest

from tailnet_unlock.config import parse_box_config
from tailnet_unlock.errors import ConfigError
from tailnet_unlock.render import BuildFacts, bootif_parameter, ip_parameter, render_conf

FACTS = BuildFacts(host="web-1", uplink_mac="00:00:5e:00:53:01")


def test_dhcp_by_name() -> None:
    config = parse_box_config('[network]\ninterface = "eno1"\n')
    assert ip_parameter(config.network) == ":::::eno1:dhcp"
    assert bootif_parameter(config.network, FACTS.uplink_mac) == ""


def test_dhcp_by_mac() -> None:
    config = parse_box_config('[network]\ninterface = "eno1"\nmatch = "mac"\n')
    assert ip_parameter(config.network) == ":::::" + ":dhcp"
    assert bootif_parameter(config.network, "00:00:5e:00:53:01") == "01-00-00-5e-00-53-01"
    with pytest.raises(ConfigError):
        bootif_parameter(config.network, None)


def test_static() -> None:
    config = parse_box_config(
        '[network]\nmode = "static"\ninterface = "eno1"\naddress = "192.0.2.10/24"\n'
        'gateway = "192.0.2.1"\ndns = ["192.0.2.53"]\n'
    )
    assert (
        ip_parameter(config.network) == "192.0.2.10::192.0.2.1:255.255.255.0::eno1:off:192.0.2.53:"
    )


def test_rendered_conf_is_safe_shell() -> None:
    config = parse_box_config('[network]\ninterface = "eno1"\n[rehearsal]\nminutes = 10\n')
    text = render_conf(config, FACTS)
    script = (
        text + 'printf "%s|%s|%s|%s" "$TU_PORT" "$TU_IP" "$TU_UNLOCK_HOSTNAME" '
        '"$TU_REHEARSAL_MINUTES"'
    )
    completed = subprocess.run(["sh", "-c", script], capture_output=True, check=True)
    assert completed.stdout.decode() == "2222|:::::eno1:dhcp|web-1-unlock|10"
    for line in text.splitlines()[1:]:
        name, _, value = line.partition("=")
        assert name.startswith("TU_")
        assert shlex.split(value) == [shlex.split(value)[0]] or value == "''"
