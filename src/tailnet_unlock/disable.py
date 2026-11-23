"""`disable --tailnet`: take the unlock node out of the box (DESIGN.md sections 12.5, 13.4).

Logs the node out best effort (a tailscaled on a copy of the sealed state, `tailscale logout`),
then overwrites and deletes `tailnet/`. The person still deletes the node in the admin console or
by API: a logout only ends the node's session.
"""

import os
import shutil
import sys
from dataclasses import dataclass

from tailnet_unlock.doorkey import remove_tree
from tailnet_unlock.enroll import staging_dir
from tailnet_unlock.errors import ConfigError, ToolError
from tailnet_unlock.node import read_node
from tailnet_unlock.system import Host, atomic_write
from tailnet_unlock.tailscale import (
    find_tools,
    kill_daemon,
    logout,
    start_daemon,
    stop_daemon,
    wait_for,
)

DISABLE_SCHEMA = "tailnet-unlock.disable/1"


@dataclass(frozen=True)
class DisableResult:
    changed: bool
    node_id: str | None
    logged_out: bool


def log_out(host: Host, timeout: int) -> bool:
    """Start tailscaled on a copy of the sealed state and log the node out; True on success."""
    staging = staging_dir(host)
    try:
        tools = find_tools()
        copy = staging / "unlock.state"
        shutil.copyfile(host.node_state, copy)
        os.chmod(copy, 0o600)
        daemon = start_daemon(
            tools, copy, staging / "tailscaled.sock", staging / "tailscaled.log", host.encrypt_state
        )
        try:
            wait_for(
                tools, daemon, lambda status: status.backend_state == "Running", timeout, "the node"
            )
            done = logout(tools, daemon.socket)
        except ToolError:
            kill_daemon(daemon)
            raise
        try:
            stop_daemon(daemon, host.stop_grace)
        except ToolError:
            kill_daemon(daemon)
        return done
    finally:
        remove_tree(staging)


def drop_node_from_pins(host: Host) -> None:
    """The pins file keeps the door's pins and loses the node's id."""
    try:
        text = host.pins_file.read_text(encoding="utf-8")
    except OSError:
        return
    kept = [line for line in text.splitlines() if not line.startswith("unlock_node_id")]
    atomic_write(host.pins_file, ("\n".join(kept) + "\n").encode("utf-8"), 0o644)


def disable_tailnet(host: Host, do_logout: bool, timeout: int) -> DisableResult:
    if not host.tailnet_dir.exists():
        return DisableResult(False, None, False)
    try:
        node = read_node(host)
    except ConfigError:
        node = None
    node_id = None if node is None else node.node_id
    logged_out = False
    if do_logout and host.node_state.exists():
        try:
            logged_out = log_out(host, timeout)
        except (ToolError, OSError) as error:
            print(f"tailnet-unlock: warning: the logout did not happen: {error}", file=sys.stderr)
    remove_tree(host.tailnet_dir)
    drop_node_from_pins(host)
    return DisableResult(True, node_id, logged_out)
