"""`enroll`: join the tailnet as the unlock node, from the running system (DESIGN.md 7.4, 13.2).

A second tailscaled, with the boot flags and a state file of its own in a private tmpfs directory,
joins with a single-use key read from a file. The state it wrote is then checked three ways before
it is installed: the node is `Running` with exactly the configured tags, the file is Tailscale's
TPM-sealed store and not a plain one, and tailscaled started on a copy reaches `Running` with no
key, which is what the initramfs will ask of it. Whatever fails after the join, the node is logged
out again, so no half-enrolled node can come back. The key file is overwritten and deleted at the
end, success or failure, and nothing secret goes through a command line, the environment or the
output.
"""

import contextlib
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from tailnet_unlock.boxpins import known_uplink, pins_text
from tailnet_unlock.config import BoxConfig
from tailnet_unlock.doorkey import (
    reap_work_dirs,
    remove_tree,
    require_tmpfs,
    wipe_file,
    work_dir,
)
from tailnet_unlock.errors import ConfigError, ToolError
from tailnet_unlock.node import Node, read_node, write_node
from tailnet_unlock.sealedstate import sealed_problem
from tailnet_unlock.system import Host, atomic_write
from tailnet_unlock.tailscale import (
    Daemon,
    NodeStatus,
    Tools,
    bring_up,
    find_tools,
    kill_daemon,
    logout,
    require_floor,
    start_daemon,
    stop_daemon,
    wait_for,
)

ENROLL_SCHEMA = "tailnet-unlock.enroll/1"
TCTI_VARIABLES = ("TPM2TOOLS_TCTI", "TSS2_TCTI", "TPM2_PKCS11_TCTI")
DEFAULT_TCTIS = ("", "device:/dev/tpmrm0")


@dataclass(frozen=True)
class EnrollRequest:
    auth_key_file: Path
    replace: bool
    timeout: int
    hostname: str


@dataclass(frozen=True)
class EnrollResult:
    changed: bool
    node: Node
    replaced_node_id: str | None


def check_auth_key_file(host: Host, path: Path) -> None:
    """The key file is a regular file owned by root, readable by nobody else, and not empty."""
    try:
        info = os.lstat(path)
    except OSError as error:
        raise ToolError(f"{path}: {error.strerror or error}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ToolError(f"{path}: not a regular file")
    if info.st_nlink != 1:
        raise ToolError(f"{path}: has other hard links, which deleting it would leave behind")
    owner = 0 if host.require_root else os.geteuid()
    if info.st_uid != owner:
        raise ToolError(f"{path}: must be owned by {'root' if owner == 0 else 'the caller'}")
    if info.st_mode & 0o077:
        raise ToolError(f"{path}: must not be accessible by group or others (chmod 600)")
    if info.st_size == 0:
        raise ToolError(f"{path}: the file is empty")


def shred(path: Path) -> None:
    """Overwrite and delete. A file that is still there afterwards is said and changes nothing else:
    neither the error that led here nor an enrollment that worked."""
    try:
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            wipe_file(path)
    except OSError:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
    if path.exists():
        print(
            f"tailnet-unlock: warning: could not delete the auth key file {path}", file=sys.stderr
        )


def require_ready(host: Host, config: BoxConfig) -> None:
    if not config.tailnet.enabled:
        raise ConfigError(
            "tailnet.enabled is false in box.toml: there is no tailnet door to enroll"
        )
    if host.require_root and os.geteuid() != 0:
        raise ToolError("enroll must run as root")
    for name in TCTI_VARIABLES:
        if os.environ.get(name, "") not in DEFAULT_TCTIS:
            raise ToolError(
                f"{name} is set: enroll uses the TPM at {host.tpm_device} and refuses a "
                "transport override (unset it)"
            )


def existing_node(host: Host, replace: bool) -> Node | None:
    """The node already enrolled here, or None. A state that is not one is refused without
    `--replace`, never overwritten silently."""
    try:
        state = host.node_state.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        if replace:
            return None
        raise ToolError(f"{host.node_state}: {error.strerror or error}; use --replace") from error
    problem = sealed_problem(state)
    if problem is not None:
        if replace:
            return None
        raise ToolError(f"{host.node_state} is not a sealed node state ({problem}); use --replace")
    try:
        node = read_node(host)
    except ConfigError as error:
        if replace:
            return None
        raise ToolError(f"{error}; use --replace") from error
    if node is None:
        if replace:
            return None
        raise ToolError(f"{host.node_file} is missing; use --replace to enroll again")
    return node


def staging_dir(host: Host) -> Path:
    # the directory is shared with init-bottom's non-secret boot record; the staging dir is 0700
    host.run_dir.mkdir(parents=True, exist_ok=True)
    if host.require_tmpfs:
        require_tmpfs(host.run_dir)
    reap_work_dirs(host.run_dir)
    return work_dir(host.run_dir, "enroll")


def check_joined(status: NodeStatus, config: BoxConfig) -> None:
    if status.backend_state != "Running":
        raise ToolError(f"the node is {status.backend_state}, not Running")
    if not status.node_id:
        raise ToolError("the node reports no id")
    if set(status.tags) != set(config.tailnet.tags):
        raise ToolError(
            f"the node's tags are {sorted(status.tags) or 'none'}, not the configured "
            f"{sorted(config.tailnet.tags)}: the auth key does not grant them"
        )


def prove_unseal(host: Host, tools: Tools, staging: Path, node_id: str, timeout: int) -> None:
    """Start tailscaled on a copy of the state with no key: it must come back as the same node.

    This is the boot's own act, so it proves the TPM unseals the state and tailscaled accepts it.
    """
    copy = staging / "verify.state"
    shutil.copyfile(staging / "unlock.state", copy)
    os.chmod(copy, 0o600)
    daemon = start_daemon(
        tools, copy, staging / "verify.sock", staging / "verify.log", host.encrypt_state
    )
    try:
        wait_for(
            tools,
            daemon,
            lambda status: status.backend_state == "Running" and status.node_id == node_id,
            timeout,
            "the node to come back from the sealed state",
        )
    except BaseException:
        kill_daemon(daemon)
        raise
    stop_daemon(daemon, host.stop_grace)


def install(host: Host, config: BoxConfig, staging: Path, node: Node) -> None:
    host.tailnet_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(host.tailnet_dir, 0o700)
    atomic_write(host.node_state, (staging / "unlock.state").read_bytes(), 0o600)
    write_node(host, node)
    text = pins_text(host.door_dir, config.door.port, node, known_uplink(config), need_door=False)
    atomic_write(host.pins_file, text.encode("utf-8"), 0o644)


def installed_files(host: Host) -> tuple[Path, ...]:
    return (host.node_state, host.node_file, host.pins_file)


def read_optional(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def restore(before: dict[Path, bytes | None]) -> None:
    """Put back what the box had before a failed install: the old enrollment, or nothing."""
    for path, data in before.items():
        if data is None:
            path.unlink(missing_ok=True)
        else:
            atomic_write(path, data, 0o600 if path.name == "unlock.state" else 0o644)


def join(
    host: Host, config: BoxConfig, tools: Tools, staging: Path, request: EnrollRequest
) -> Node:
    state = staging / "unlock.state"
    log = staging / "tailscaled.log"
    daemon: Daemon | None = None
    attempted = False
    node_id = ""
    before: dict[Path, bytes | None] | None = None
    try:
        daemon = start_daemon(tools, state, staging / "tailscaled.sock", log, host.encrypt_state)
        wait_for(tools, daemon, lambda _: True, request.timeout, "tailscaled to answer")
        attempted = True
        bring_up(
            tools,
            daemon.socket,
            request.auth_key_file,
            request.hostname,
            config.tailnet.tags,
            config.tailnet.login_server,
            request.timeout,
        )
        status = wait_for(
            tools, daemon, lambda s: s.backend_state == "Running", request.timeout, "the node"
        )
        node_id = status.node_id
        check_joined(status, config)
        stop_daemon(daemon, host.stop_grace)
        daemon = None
        problem = sealed_problem(state.read_bytes())
        if problem is not None:
            raise ToolError(
                f"the node state is not Tailscale's TPM-sealed store ({problem}); not installing it"
            )
        prove_unseal(host, tools, staging, status.node_id, request.timeout)
        node = Node(
            node_id=status.node_id,
            hostname=request.hostname,
            dns_name=status.dns_name,
            addresses=status.addresses,
            tags=tuple(sorted(status.tags)),
            login_server=config.tailnet.login_server,
            enrolled_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        before = {path: read_optional(path) for path in installed_files(host)}
        install(host, config, staging, node)
        return node
    except BaseException as error:
        if before is not None:
            restore(before)
        note = ""
        if attempted:
            note = roll_back(host, tools, staging, daemon, node_id)
        if isinstance(error, ToolError) and note:
            raise ToolError(f"{error}; {note}") from error
        raise
    finally:
        if daemon is not None:
            end_daemon(daemon, host.stop_grace)


def end_daemon(daemon: Daemon, grace: float) -> None:
    """Leave no daemon behind on a failure path: a clean stop if it will, else a kill."""
    try:
        stop_daemon(daemon, grace)
    except ToolError:
        kill_daemon(daemon)


def roll_back(host: Host, tools: Tools, staging: Path, daemon: Daemon | None, node_id: str) -> str:
    """Log the node out again, best effort; returns what the person still has to do, if anything."""
    started: Daemon | None = None
    if daemon is not None and daemon.process.poll() is not None:
        daemon = None
    try:
        if daemon is None and (staging / "unlock.state").exists():
            started = daemon = start_daemon(
                tools,
                staging / "unlock.state",
                staging / "rollback.sock",
                staging / "rollback.log",
                host.encrypt_state,
            )
            wait_for(
                tools,
                daemon,
                lambda _: True,
                host.logout_timeout,
                "tailscaled to answer for the logout",
            )
        if daemon is not None and logout(tools, daemon.socket):
            return ""
    except ToolError:
        pass
    finally:
        if started is not None:
            end_daemon(started, host.stop_grace)
    if not node_id:
        return "if a node was registered, delete it in the Tailscale admin console"
    return f"the logout failed: delete the node {node_id} in the Tailscale admin console"


def enroll(host: Host, config: BoxConfig, request: EnrollRequest) -> EnrollResult:
    """Enroll, or report the node that already is. Always shreds the key file once it is valid."""
    require_ready(host, config)
    check_auth_key_file(host, request.auth_key_file)
    try:
        existing = existing_node(host, request.replace)
        if existing is not None and not request.replace:
            return EnrollResult(False, existing, None)
        old = existing.node_id if existing is not None else None
        if not host.tpm_device.exists():
            raise ToolError(f"no TPM at {host.tpm_device}: the unlock node's state needs one")
        # the pins are written after the join: a door key they cannot read is found out before it
        pins_text(host.door_dir, config.door.port, None, None, need_door=False)
        tools = find_tools()
        require_floor(tools)
        staging = staging_dir(host)
        try:
            node = join(host, config, tools, staging, request)
        finally:
            remove_tree(staging)
        return EnrollResult(True, node, old)
    finally:
        shred(request.auth_key_file)
