"""The box configuration, /etc/tailnet-unlock/box.toml (DESIGN.md section 12.3).

`parse_box_config` validates the whole file and returns frozen data; nothing else in the package
reads the file. Unknown keys are refused, so a typo never silently falls back to a default.
"""

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from typing import Literal

from tailnet_unlock.errors import ConfigError
from tailnet_unlock.validate import (
    as_table,
    get_bool,
    get_int,
    get_opt_str,
    get_str,
    get_str_list,
    one_of,
    only_keys,
)

type Profile = Literal["tpm", "measured"]
type Recovery = Literal["off", "uplink", "uplink+tailnet"]
type KeySource = Literal["generate", "import"]
type NetworkMode = Literal["dhcp", "static"]
type Match = Literal["name", "mac"]

PROFILES: tuple[Profile, ...] = ("tpm", "measured")
RECOVERIES: tuple[Recovery, ...] = ("off", "uplink", "uplink+tailnet")
KEY_SOURCES: tuple[KeySource, ...] = ("generate", "import")
NETWORK_MODES: tuple[NetworkMode, ...] = ("dhcp", "static")
MATCHES: tuple[Match, ...] = ("name", "mac")

_INTERFACE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")
_DNS_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_TAG = re.compile(r"tag:[a-z0-9]([a-z0-9-]{0,62})")


@dataclass(frozen=True)
class DoorConfig:
    port: int
    key_source: KeySource
    recovery: Recovery
    recovery_key_source: KeySource
    idle_timeout_seconds: int


@dataclass(frozen=True)
class StaticAddress:
    address: ipaddress.IPv4Interface
    gateway: ipaddress.IPv4Address | None
    dns: tuple[ipaddress.IPv4Address, ...]


@dataclass(frozen=True)
class NetworkConfig:
    mode: NetworkMode
    interface: str
    match: Match
    static: StaticAddress | None
    flush_on_handover: bool


@dataclass(frozen=True)
class TailnetConfig:
    enabled: bool
    login_server: str
    hostname: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class BoxConfig:
    backend: Literal["zfs"]
    door: DoorConfig
    network: NetworkConfig
    tailnet: TailnetConfig
    profile: Profile
    rehearsal_minutes: int | None


def default_recovery(profile: Profile) -> Recovery:
    """`uplink` under `tpm`, `off` under `measured` (decision D16)."""
    return "off" if profile == "measured" else "uplink"


def parse_box_config(text: str) -> BoxConfig:
    try:
        parsed: object = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"box.toml: {error}") from error
    return box_config_from(parsed)


def box_config_from(value: object) -> BoxConfig:
    top = as_table(value, "box.toml", ConfigError)
    only_keys(
        top, ("root", "door", "network", "tailnet", "seal", "rehearsal"), "box.toml", ConfigError
    )
    profile = _seal(top.get("seal", {}))
    return BoxConfig(
        backend=_root(top.get("root", {})),
        door=_door(top.get("door", {}), profile),
        network=_network(top.get("network")),
        tailnet=_tailnet(top.get("tailnet", {})),
        profile=profile,
        rehearsal_minutes=_rehearsal(top.get("rehearsal", {})),
    )


def _root(value: object) -> Literal["zfs"]:
    table = as_table(value, "root", ConfigError)
    only_keys(table, ("backend",), "root", ConfigError)
    backend = get_str(table, "backend", "zfs", "root", ConfigError)
    if backend != "zfs":
        raise ConfigError('root.backend: only "zfs" is supported in this release')
    return "zfs"


def _seal(value: object) -> Profile:
    table = as_table(value, "seal", ConfigError)
    only_keys(table, ("profile",), "seal", ConfigError)
    profile = get_str(table, "profile", "tpm", "seal", ConfigError)
    return one_of(profile, PROFILES, "seal.profile", ConfigError)


def _door(value: object, profile: Profile) -> DoorConfig:
    table = as_table(value, "door", ConfigError)
    only_keys(
        table,
        ("port", "key_source", "recovery", "recovery_key_source", "idle_timeout_seconds"),
        "door",
        ConfigError,
    )
    recovery = get_opt_str(table, "recovery", "door", ConfigError)
    return DoorConfig(
        port=get_int(table, "port", 2222, "door", ConfigError, 1, 65535),
        key_source=one_of(
            get_str(table, "key_source", "generate", "door", ConfigError),
            KEY_SOURCES,
            "door.key_source",
            ConfigError,
        ),
        recovery=(
            default_recovery(profile)
            if recovery is None
            else one_of(recovery, RECOVERIES, "door.recovery", ConfigError)
        ),
        recovery_key_source=one_of(
            get_str(table, "recovery_key_source", "generate", "door", ConfigError),
            KEY_SOURCES,
            "door.recovery_key_source",
            ConfigError,
        ),
        idle_timeout_seconds=get_int(
            table, "idle_timeout_seconds", 600, "door", ConfigError, 30, 86400
        ),
    )


def _ipv4(text: str, where: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(text)
    except ValueError as error:
        raise ConfigError(f"{where}: not an IPv4 address: {text!r}") from error


def _network(value: object) -> NetworkConfig:
    if value is None:
        raise ConfigError("network: the uplink must be configured ([network] interface)")
    table = as_table(value, "network", ConfigError)
    only_keys(
        table,
        ("mode", "interface", "match", "address", "gateway", "dns", "flush_on_handover"),
        "network",
        ConfigError,
    )
    mode = one_of(
        get_str(table, "mode", "dhcp", "network", ConfigError),
        NETWORK_MODES,
        "network.mode",
        ConfigError,
    )
    interface = (
        get_str(table, "interface", None, "network", ConfigError) if "interface" in table else ""
    )
    if not _INTERFACE.fullmatch(interface):
        raise ConfigError(
            "network.interface: required, a Linux interface name (1 to 15 of A-Z a-z 0-9 _ . : -)"
        )
    match = one_of(
        get_str(table, "match", "name", "network", ConfigError),
        MATCHES,
        "network.match",
        ConfigError,
    )
    static: StaticAddress | None = None
    address = get_opt_str(table, "address", "network", ConfigError)
    gateway = get_opt_str(table, "gateway", "network", ConfigError)
    dns = get_str_list(table, "dns", (), "network", ConfigError)
    if mode == "static":
        if address is None:
            raise ConfigError('network.address: required when mode = "static" (CIDR form)')
        try:
            interface_address = ipaddress.IPv4Interface(address)
        except ValueError as error:
            raise ConfigError(
                f"network.address: not an IPv4 address in CIDR form: {address!r}"
            ) from error
        if "/" not in address:
            raise ConfigError("network.address: give the prefix length too, as in 192.0.2.10/24")
        static = StaticAddress(
            address=interface_address,
            gateway=None if gateway is None else _ipv4(gateway, "network.gateway"),
            dns=tuple(_ipv4(item, "network.dns") for item in dns),
        )
        if len(static.dns) > 2:
            raise ConfigError("network.dns: at most two resolvers")
    elif address is not None or gateway is not None:
        raise ConfigError('network.address and network.gateway apply to mode = "static" only')
    elif dns:
        raise ConfigError('network.dns applies to mode = "static" only; DHCP brings its own')
    return NetworkConfig(
        mode=mode,
        interface=interface,
        match=match,
        static=static,
        flush_on_handover=get_bool(table, "flush_on_handover", True, "network", ConfigError),
    )


def _tailnet(value: object) -> TailnetConfig:
    table = as_table(value, "tailnet", ConfigError)
    only_keys(table, ("enabled", "login_server", "hostname", "tags"), "tailnet", ConfigError)
    login_server = get_str(table, "login_server", "", "tailnet", ConfigError)
    if login_server and not re.fullmatch(
        r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^\s]*)?", login_server
    ):
        raise ConfigError("tailnet.login_server: empty for Tailscale, or an https:// URL")
    hostname = get_str(table, "hostname", "", "tailnet", ConfigError)
    if hostname and not _DNS_LABEL.fullmatch(hostname):
        raise ConfigError("tailnet.hostname: empty, or one lowercase DNS label")
    tags = get_str_list(table, "tags", ("tag:unlock",), "tailnet", ConfigError)
    if not tags:
        raise ConfigError("tailnet.tags: at least one tag (the unlock node must be tagged)")
    for tag in tags:
        if not _TAG.fullmatch(tag):
            raise ConfigError(f"tailnet.tags: not a tag: {tag!r}")
    return TailnetConfig(
        enabled=get_bool(table, "enabled", True, "tailnet", ConfigError),
        login_server=login_server,
        hostname=hostname,
        tags=tags,
    )


def _rehearsal(value: object) -> int | None:
    table = as_table(value, "rehearsal", ConfigError)
    only_keys(table, ("minutes",), "rehearsal", ConfigError)
    if "minutes" not in table:
        return None
    return get_int(table, "minutes", None, "rehearsal", ConfigError, 1, 240)


def unlock_hostname(config: TailnetConfig, host: str) -> str:
    """The unlock node's name: configured, or `<host>-unlock` (section 7.4)."""
    if config.hostname:
        return config.hostname
    label = re.sub(r"[^a-z0-9-]", "-", host.split(".", 1)[0].lower()).strip("-") or "box"
    return f"{label[:56]}-unlock"
