"""The keyholder configuration, keyholder.toml (DESIGN.md section 12.4).

`parse_keyholder_config` validates the whole file and returns frozen data; nothing else in the
package reads the file. Unknown keys are refused, so a typo never silently falls back to a default.
Every key of `[defaults]` but `tailscale` may be set again in a `[hosts.<name>]` table.
"""

import ipaddress
import re
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

from tailnet_unlock.authorized_keys import parse_public_key
from tailnet_unlock.errors import ConfigError
from tailnet_unlock.keyholder.pins import DoorPins, check_address, door_pins
from tailnet_unlock.validate import (
    as_table,
    get_bool,
    get_int,
    get_opt_str,
    get_str_list,
    only_keys,
)

type Argv = tuple[str, ...]
type Network = ipaddress.IPv4Network | ipaddress.IPv6Network

CONFIG_FILE = Path("/etc/tailnet-unlock/keyholder.toml")

# a host name is also a file name in the state directory
_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?")
_NODE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
_NODE_ID = re.compile(r"[A-Za-z0-9]{1,64}")


@dataclass(frozen=True)
class Settings:
    """The keys of `[defaults]` that a host may set for itself."""

    ssh_key: str | None = None
    ssh_proxy_command: str | None = None
    approver: Argv = ()
    approval_timeout_seconds: int = 900
    door_wait_minutes: int = 30
    node_wait_seconds: int = 300
    allow_recovery_delivery: bool = False
    on_waiting: Argv = ()
    alarm: Argv = ()
    alarm_after_seconds: int = 60
    alarm_repeat_hours: int = 24
    redeliver_minutes: int = 30
    hook_timeout_seconds: int = 60


SETTING_KEYS = (*(field.name for field in fields(Settings)), "on_alarm")


@dataclass(frozen=True)
class NodeRef:
    """How a tailnet node is found: by its stable id when set, else by its name."""

    name: str | None
    node_id: str | None


@dataclass(frozen=True)
class HostConfig:
    name: str
    settings: Settings
    node: NodeRef | None
    key_command: Argv
    expected_endpoints: tuple[Network, ...]
    pins: DoorPins
    unlock_node: NodeRef | None
    uplink: str | None
    uplink_port: int


@dataclass(frozen=True)
class KeyholderConfig:
    tailscale: Argv
    hosts: tuple[HostConfig, ...]


def parse_keyholder_config(text: str) -> KeyholderConfig:
    try:
        value: object = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"keyholder.toml: {error}") from error
    top = as_table(value, "keyholder.toml", ConfigError)
    only_keys(top, ("defaults", "hosts"), "keyholder.toml", ConfigError)
    defaults = as_table(top.get("defaults", {}), "defaults", ConfigError)
    only_keys(defaults, (*SETTING_KEYS, "tailscale"), "defaults", ConfigError)
    base = _settings(defaults, Settings(), "defaults")
    tables = as_table(top.get("hosts", {}), "hosts", ConfigError)
    if not tables:
        raise ConfigError("keyholder.toml: no [hosts.<name>] table")
    hosts = tuple(_host(name, table, base) for name, table in tables.items())
    _unique(hosts)
    return KeyholderConfig(
        tailscale=_argv(defaults, "tailscale", ("tailscale",), "defaults"), hosts=hosts
    )


def host_config(config: KeyholderConfig, name: str) -> HostConfig:
    for host in config.hosts:
        if host.name == name:
            return host
    known = ", ".join(host.name for host in config.hosts)
    raise ConfigError(f"no [hosts.{name[:60]}] in the configuration (it has: {known})")


def _argv(table: dict[str, object], key: str, default: Argv, where: str) -> Argv:
    """An argument list, never a shell line; empty means not set."""
    argv = get_str_list(table, key, default, where, ConfigError)
    if argv and not argv[0]:
        raise ConfigError(f"{where}.{key}: the first item names the program")
    if any("\0" in item for item in argv):
        raise ConfigError(f"{where}.{key}: holds a NUL byte")
    return argv


def _path(table: dict[str, object], key: str, default: str | None, where: str) -> str | None:
    path = get_opt_str(table, key, where, ConfigError)
    if path is None:
        return default
    # ssh expands % and $ in a path and reads "none" as no key at all
    if not path.startswith("/") or re.search(r"[%$\"\s\0]", path):
        raise ConfigError(f"{where}.{key}: an absolute path without spaces, quotes, % or $")
    return path


def _settings(table: dict[str, object], base: Settings, where: str) -> Settings:
    on_alarm = get_opt_str(table, "on_alarm", where, ConfigError)
    if on_alarm == "expire":
        raise ConfigError(
            f'{where}.on_alarm: "expire" is not built: it needs an API credential with device '
            'write access; use "alert"'
        )
    if on_alarm not in {None, "alert"}:
        raise ConfigError(f'{where}.on_alarm: only "alert" is built')
    proxy = get_opt_str(table, "ssh_proxy_command", where, ConfigError)
    if proxy is not None and (not proxy.strip() or re.search(r"[\0\r\n]", proxy)):
        raise ConfigError(f"{where}.ssh_proxy_command: expected one command line")

    def number(key: str, default: int, low: int, high: int) -> int:
        return get_int(table, key, default, where, ConfigError, low, high)

    return Settings(
        ssh_key=_path(table, "ssh_key", base.ssh_key, where),
        ssh_proxy_command=base.ssh_proxy_command if proxy is None else proxy,
        approver=_argv(table, "approver", base.approver, where),
        approval_timeout_seconds=number(
            "approval_timeout_seconds", base.approval_timeout_seconds, 1, 86400
        ),
        door_wait_minutes=number("door_wait_minutes", base.door_wait_minutes, 0, 1440),
        node_wait_seconds=number("node_wait_seconds", base.node_wait_seconds, 0, 3600),
        allow_recovery_delivery=get_bool(
            table, "allow_recovery_delivery", base.allow_recovery_delivery, where, ConfigError
        ),
        on_waiting=_argv(table, "on_waiting", base.on_waiting, where),
        alarm=_argv(table, "alarm", base.alarm, where),
        alarm_after_seconds=number("alarm_after_seconds", base.alarm_after_seconds, 0, 600),
        alarm_repeat_hours=number("alarm_repeat_hours", base.alarm_repeat_hours, 1, 8760),
        redeliver_minutes=number("redeliver_minutes", base.redeliver_minutes, 0, 10080),
        hook_timeout_seconds=number("hook_timeout_seconds", base.hook_timeout_seconds, 1, 3600),
    )


def _node_ref(table: dict[str, object], name_key: str, id_key: str, where: str) -> NodeRef | None:
    name = get_opt_str(table, name_key, where, ConfigError)
    node_id = get_opt_str(table, id_key, where, ConfigError)
    if name is not None and not _NODE.fullmatch(name):
        raise ConfigError(f"{where}.{name_key}: not a node name: {name[:60]!r}")
    if node_id is not None and not _NODE_ID.fullmatch(node_id):
        raise ConfigError(f"{where}.{id_key}: not a stable node id: {node_id[:60]!r}")
    return None if name is None and node_id is None else NodeRef(name, node_id)


def _endpoint(text: str, where: str) -> Network:
    try:
        return ipaddress.ip_network(text)
    except ValueError as error:
        raise ConfigError(f"{where}: not a network or address: {text[:60]!r}") from error


def _host(name: str, value: object, base: Settings) -> HostConfig:
    where = f"hosts.{name[:60]}"
    if not _HOST.fullmatch(name):
        raise ConfigError(f"{where}: a host name is letters, digits, dots, dashes, underscores")
    table = as_table(value, where, ConfigError)
    only_keys(
        table,
        (*SETTING_KEYS, "node", "node_id", "key_command", "expected_endpoints", "door"),
        where,
        ConfigError,
    )
    if "door" not in table:
        raise ConfigError(f"{where}.door: required (paste the box's pins.toml)")
    door = as_table(table["door"], f"{where}.door", ConfigError)
    only_keys(
        door,
        (
            "port",
            "door_key",
            "recovery_key",
            "unlock_node_id",
            "unlock_node",
            "uplink",
            "uplink_port",
        ),
        f"{where}.door",
        ConfigError,
    )
    port = get_int(door, "port", 2222, f"{where}.door", ConfigError, 1, 65535)
    uplink = get_opt_str(door, "uplink", f"{where}.door", ConfigError)
    unlock_node = _node_ref(door, "unlock_node", "unlock_node_id", f"{where}.door")
    if uplink is None and "uplink_port" in door:
        raise ConfigError(f"{where}.door.uplink_port: needs uplink")
    if uplink is None and unlock_node is None:
        raise ConfigError(f"{where}.door: needs uplink, unlock_node_id or unlock_node")
    try:
        pins = door_pins(
            port,
            get_opt_str(door, "door_key", f"{where}.door", ConfigError),
            get_opt_str(door, "recovery_key", f"{where}.door", ConfigError),
        )
        if uplink is not None:
            check_address(uplink)
    except ConfigError as error:
        raise ConfigError(f"{where}.door: {error}") from error
    return HostConfig(
        name=name,
        settings=_settings(table, base, where),
        node=_node_ref(table, "node", "node_id", where),
        key_command=_argv(table, "key_command", (), where),
        expected_endpoints=tuple(
            _endpoint(item, f"{where}.expected_endpoints")
            for item in get_str_list(table, "expected_endpoints", (), where, ConfigError)
        ),
        pins=pins,
        unlock_node=unlock_node,
        uplink=uplink,
        uplink_port=get_int(door, "uplink_port", port, f"{where}.door", ConfigError, 1, 65535),
    )


def _unique(hosts: tuple[HostConfig, ...]) -> None:
    """Two hosts with one pin or one unlock node would send one host's key to the other's door."""
    seen: dict[str, str] = {}
    for host in hosts:
        marks: list[str] = []
        for pin in (host.pins.door_key, host.pins.recovery_key):
            if pin is not None:
                marks.append(parse_public_key(pin, host.name).blob.hex())
        if host.unlock_node is not None and host.unlock_node.node_id is not None:
            marks.append(f"node {host.unlock_node.node_id}")
        for mark in marks:
            if mark in seen:
                raise ConfigError(
                    f"hosts.{host.name}.door: the same key or node id as hosts.{seen[mark]}"
                )
            seen[mark] = host.name
