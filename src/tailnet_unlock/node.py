"""The unlock node's public record, `tailnet/node.json` (DESIGN.md section 12.2).

Public by design: ids, names and addresses, never a key. Pure data and its file; it calls no tool.
"""

import json
from dataclasses import dataclass

from tailnet_unlock.errors import ConfigError
from tailnet_unlock.system import Host, atomic_write
from tailnet_unlock.validate import as_table, get_str, get_str_list

NODE_SCHEMA = "tailnet-unlock.node/1"


@dataclass(frozen=True)
class Node:
    node_id: str
    hostname: str
    dns_name: str
    addresses: tuple[str, ...]
    tags: tuple[str, ...]
    login_server: str
    enrolled_at: str


def node_json(node: Node) -> dict[str, object]:
    return {
        "schema": NODE_SCHEMA,
        "node_id": node.node_id,
        "hostname": node.hostname,
        "dns_name": node.dns_name,
        "addresses": list(node.addresses),
        "tags": list(node.tags),
        "login_server": node.login_server,
        "enrolled_at": node.enrolled_at,
    }


def parse_node(text: str) -> Node:
    try:
        parsed: object = json.loads(text)
    except ValueError as error:
        raise ConfigError(f"node.json: {error}") from error
    table = as_table(parsed, "node.json", ConfigError)
    if table.get("schema") != NODE_SCHEMA:
        raise ConfigError(f"node.json: schema is not {NODE_SCHEMA}")
    return Node(
        node_id=get_str(table, "node_id", None, "node.json", ConfigError),
        hostname=get_str(table, "hostname", None, "node.json", ConfigError),
        dns_name=get_str(table, "dns_name", None, "node.json", ConfigError),
        addresses=get_str_list(table, "addresses", (), "node.json", ConfigError),
        tags=get_str_list(table, "tags", (), "node.json", ConfigError),
        login_server=get_str(table, "login_server", "", "node.json", ConfigError),
        enrolled_at=get_str(table, "enrolled_at", "", "node.json", ConfigError),
    )


def read_node(host: Host) -> Node | None:
    """The recorded node, None when there is none; a damaged file is an error, not "absent"."""
    try:
        text = host.node_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return parse_node(text)


def write_node(host: Host, node: Node) -> None:
    text = json.dumps(node_json(node), indent=2) + "\n"
    atomic_write(host.node_file, text.encode("utf-8"), 0o644)
