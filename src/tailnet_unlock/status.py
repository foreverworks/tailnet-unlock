"""`status`: what this box is set up as and how it last booted (DESIGN.md section 12.5)."""

import json
from dataclasses import dataclass
from pathlib import Path

from tailnet_unlock.config import BoxConfig, parse_box_config
from tailnet_unlock.container import read_container
from tailnet_unlock.doorkey import fingerprint
from tailnet_unlock.errors import ConfigError, DoorKeyError
from tailnet_unlock.node import Node, node_json, read_node
from tailnet_unlock.seal import DOOR_CONTAINER, RECOVERY_KEY
from tailnet_unlock.system import Host

STATUS_SCHEMA = "tailnet-unlock.status/1"


@dataclass(frozen=True)
class Status:
    config: BoxConfig | None
    config_error: str | None
    boot: dict[str, object] | None
    node: Node | None
    node_error: str | None
    sealed_pin: str | None
    has_recovery_key: bool


def read_boot(path: Path) -> dict[str, object] | None:
    """The record init-bottom leaves of the last boot, or None if there is none."""
    try:
        parsed: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    return {str(key): value for key, value in parsed.items()}


def gather(host: Host) -> Status:
    config: BoxConfig | None = None
    config_error: str | None = None
    try:
        config = parse_box_config((host.config_dir / "box.toml").read_text(encoding="utf-8"))
    except FileNotFoundError:
        pass
    except (ConfigError, OSError) as error:
        config_error = str(error)
    node: Node | None = None
    node_error: str | None = None
    try:
        node = read_node(host)
    except ConfigError as error:
        node_error = str(error)
    try:
        pin: str | None = read_container(host.door_dir / DOOR_CONTAINER).pin
    except DoorKeyError:
        pin = None
    return Status(
        config=config,
        config_error=config_error,
        boot=read_boot(host.boot_record),
        node=node,
        node_error=node_error,
        sealed_pin=pin,
        has_recovery_key=(host.door_dir / RECOVERY_KEY).exists(),
    )


def status_json(status: Status) -> str:
    config = status.config
    summary: dict[str, object] | None = None
    if config is not None:
        summary = {
            "profile": config.profile,
            "backend": config.backend,
            "port": config.door.port,
            "recovery": config.door.recovery,
            "interface": config.network.interface,
            "tailnet_enabled": config.tailnet.enabled,
            "tags": list(config.tailnet.tags),
            "login_server": config.tailnet.login_server,
        }
    document: dict[str, object] = {
        "schema": STATUS_SCHEMA,
        "configured": config is not None,
        "config": summary,
        "config_error": status.config_error,
        "boot": status.boot,
        "node": None if status.node is None else node_json(status.node),
        "node_error": status.node_error,
        "door": {
            "sealed_key": status.sealed_pin,
            "sealed_fingerprint": None
            if status.sealed_pin is None
            else fingerprint(status.sealed_pin),
            "recovery_key": status.has_recovery_key,
        },
    }
    return json.dumps(document, indent=2)


def render_text(status: Status) -> str:
    lines: list[str] = []
    boot = status.boot
    if boot is not None:
        lines.append(
            f"last boot: unlocked by {boot.get('unlocked_by')}, door {boot.get('door')}, "
            f"seal {boot.get('seal')}, degraded {boot.get('degraded') or 'none'}"
        )
    else:
        lines.append("last boot: no record (this boot did not pass through the door)")
    node = status.node
    if node is not None:
        lines.append(
            f"unlock node: enrolled as {node.dns_name or node.hostname} "
            f"(id {node.node_id}, {', '.join(node.tags)})"
        )
    else:
        lines.append(
            f"unlock node: not enrolled{f' ({status.node_error})' if status.node_error else ''}"
        )
    if status.sealed_pin is not None:
        lines.append(f"sealed door key: present ({fingerprint(status.sealed_pin)})")
    else:
        lines.append("sealed door key: none")
    lines.append(f"recovery key: {'present' if status.has_recovery_key else 'none'}")
    config = status.config
    if config is not None:
        lines.append(
            f"config: profile {config.profile}, door port {config.door.port}, recovery "
            f"{config.door.recovery}, tailnet {'on' if config.tailnet.enabled else 'off'}"
        )
    elif status.config_error is not None:
        lines.append(f"config: invalid ({status.config_error})")
    else:
        lines.append("config: not configured (no box.toml)")
    return "\n".join(lines)
