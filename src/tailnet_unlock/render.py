"""Render what the initramfs reads at boot from box.toml (DESIGN.md section 7.2, step 1).

The boot scripts source `conf/tailnet-unlock.conf`, so every value is validated first (config.py)
and quoted here with `shlex.quote`. The configuration keeps one source; the image carries a value
derived from it at each build.
"""

import re
import shlex
from dataclasses import dataclass

from tailnet_unlock.config import BoxConfig, NetworkConfig, unlock_hostname
from tailnet_unlock.errors import ConfigError

_MAC = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


@dataclass(frozen=True)
class BuildFacts:
    """What the hook reads from the running system at each build."""

    host: str
    uplink_mac: str | None


def ip_parameter(network: NetworkConfig) -> str:
    """The `IP=` value for initramfs-tools' `configure_networking` (the kernel's `ip=` format).

    `client:server:gateway:netmask:hostname:device:autoconf:dns0:dns1`. With `match = "mac"` the
    device is left empty, so `configure_networking` finds it by `BOOTIF=`.
    """
    device = "" if network.match == "mac" else network.interface
    if network.static is None:
        return f":::::{device}:dhcp"
    static = network.static
    dns = [str(item) for item in static.dns] + ["", ""]
    gateway = "" if static.gateway is None else str(static.gateway)
    return ":".join(
        [
            str(static.address.ip),
            "",
            gateway,
            str(static.address.netmask),
            "",
            device,
            "off",
            dns[0],
            dns[1],
        ]
    )


def bootif_parameter(network: NetworkConfig, mac: str | None) -> str:
    """`BOOTIF=01-aa-bb-cc-dd-ee-ff` when the uplink is matched by its MAC, else empty."""
    if network.match != "mac":
        return ""
    if mac is None or not _MAC.fullmatch(mac.lower()):
        raise ConfigError(
            f'network.match = "mac": could not read the MAC address of {network.interface}'
        )
    return "01-" + mac.lower().replace(":", "-")


def render_conf(config: BoxConfig, facts: BuildFacts) -> str:
    door = config.door
    network = config.network
    dns = "" if network.static is None else " ".join(str(item) for item in network.static.dns)
    values = [
        ("TU_BACKEND", config.backend),
        ("TU_PROFILE", config.profile),
        ("TU_PORT", str(door.port)),
        ("TU_RECOVERY", door.recovery),
        ("TU_IDLE_TIMEOUT", str(door.idle_timeout_seconds)),
        ("TU_INTERFACE", network.interface),
        ("TU_IP", ip_parameter(network)),
        ("TU_BOOTIF", bootif_parameter(network, facts.uplink_mac)),
        ("TU_DNS", dns),
        ("TU_FLUSH", "yes" if network.flush_on_handover else "no"),
        ("TU_TAILNET", "yes" if config.tailnet.enabled else "no"),
        ("TU_UNLOCK_HOSTNAME", unlock_hostname(config.tailnet, facts.host)),
        (
            "TU_REHEARSAL_MINUTES",
            "" if config.rehearsal_minutes is None else str(config.rehearsal_minutes),
        ),
    ]
    lines = [
        "# Rendered by tailnet-unlock render-initramfs from box.toml at build time. Do not edit."
    ]
    lines += [f"{name}={shlex.quote(value)}" for name, value in values]
    return "\n".join(lines) + "\n"
