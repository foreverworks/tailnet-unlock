"""Everything that runs `tailscale` or `tailscaled` (DESIGN.md sections 7.4 and 13.2).

This is the one module that does. Door keys, sealing, the container, the configuration and the
rendering never import it, so the uplink door's commands work on a box with no Tailscale installed.
`enroll` and `disable --tailnet` use it to run a second tailscaled of their own beside the box's
node, and `verify` uses it to read a version.

The second daemon runs with the flags the initramfs gives the unlock node at boot (`BOOT_FLAGS`,
the same words as initramfs/supervise, which a test compares), plus `--port=0`, which only keeps it
from fighting the box's own tailscaled for the WireGuard port and changes nothing the state holds.
Nothing secret goes through a command line or the environment: the auth key is a file the CLI
reads itself, and the daemons get a minimal environment.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from tailnet_unlock.errors import ToolError
from tailnet_unlock.versions import FLOOR, Version, parse_version, version_text

# the flags initramfs/supervise starts the unlock node's tailscaled with, besides its paths
BOOT_FLAGS = ("--encrypt-state", "--tun=userspace-networking", "--no-logs-no-support")
POLL_SECONDS = 0.25


@dataclass(frozen=True)
class Tools:
    tailscale: str
    tailscaled: str


@dataclass(frozen=True)
class NodeStatus:
    """What `tailscale status --json` says about the node itself."""

    backend_state: str
    node_id: str
    hostname: str
    dns_name: str
    addresses: tuple[str, ...]
    tags: tuple[str, ...]


@dataclass(frozen=True)
class Daemon:
    process: subprocess.Popen[bytes]
    socket: Path
    log: Path


def child_env() -> dict[str, str]:
    """The environment of a tailscale process: a path and a locale, nothing else."""
    return {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C.UTF-8"}


def find_tools() -> Tools:
    tailscale = shutil.which("tailscale")
    tailscaled = shutil.which("tailscaled")
    if tailscale is None or tailscaled is None:
        missing = " and ".join(
            name
            for name, found in (("tailscale", tailscale), ("tailscaled", tailscaled))
            if not found
        )
        raise ToolError(f"{missing} not found: install Tailscale (1.86 or later)")
    return Tools(tailscale, tailscaled)


def binary_version(path: str | Path) -> Version | None:
    """The version a Tailscale binary reports with `--version`, or None if it cannot say."""
    try:
        result = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=child_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return parse_version(result.stdout.splitlines()[0] if result.stdout else "")


def require_floor(tools: Tools, floor: Version = FLOOR) -> None:
    for path in (tools.tailscale, tools.tailscaled):
        found = binary_version(path)
        if found is None:
            raise ToolError(f"cannot read the version of {path}")
        if found < floor:
            raise ToolError(
                f"{Path(path).name} {version_text(found)} is older than {version_text(floor)}"
            )


def daemon_argv(tools: Tools, state: Path, socket: Path, encrypt_state: bool = True) -> list[str]:
    """tailscaled's command line: the boot flags, this state and socket, and `--port=0`.

    `encrypt_state` is False only in the one test that has no TPM (never reachable from the CLI).
    """
    flags = [flag for flag in BOOT_FLAGS if encrypt_state or flag != "--encrypt-state"]
    return [tools.tailscaled, f"--state={state}", *flags, f"--socket={socket}", "--port=0"]


def start_daemon(
    tools: Tools, state: Path, socket: Path, log: Path, encrypt_state: bool = True
) -> Daemon:
    with log.open("wb") as handle:
        try:
            process = subprocess.Popen(
                daemon_argv(tools, state, socket, encrypt_state),
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=handle,
                env=child_env(),
            )
        except OSError as error:
            raise ToolError(f"cannot start tailscaled: {error}") from error
    return Daemon(process, socket, log)


def one_line(text: str) -> str:
    """The last line of a tool's output, short, with anything shaped like a Tailscale key masked."""
    lines = text.strip().splitlines()
    return re.sub(r"tskey-[A-Za-z0-9-]+", "tskey-***", lines[-1])[:200] if lines else ""


def last_log_line(log: Path) -> str:
    try:
        return one_line(log.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""


def stop_daemon(daemon: Daemon, grace: float = 20.0) -> None:
    """SIGTERM, then wait: tailscaled must leave on its own, with status 0.

    A daemon that needs a KILL, or that exits with anything but 0, may have left its state
    half-written, so both are errors.
    """
    process = daemon.process
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        code = process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise ToolError(f"tailscaled did not stop within {grace:.0f}s and was killed") from None
    if code != 0:
        detail = last_log_line(daemon.log)
        raise ToolError(
            f"tailscaled exited with status {code} instead of stopping cleanly"
            + (f": {detail}" if detail else "")
        )


def kill_daemon(daemon: Daemon) -> None:
    """Last resort for cleanup paths: make sure the process is gone, by its handle."""
    process = daemon.process
    if process.poll() is None:
        process.kill()
    process.wait()


def run_cli(tools: Tools, socket: Path, args: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            [tools.tailscale, f"--socket={socket}", *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=child_env(),
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"tailscale {args[0]} timed out after {timeout:.0f}s"
    except OSError as error:
        raise ToolError(f"cannot run tailscale: {error}") from error
    return result.returncode, result.stdout, result.stderr


def parse_status(text: str) -> NodeStatus | None:
    """The node's own part of `tailscale status --json`, or None if it is not a status."""
    try:
        parsed: object = json.loads(text)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    backend = parsed.get("BackendState")
    if not isinstance(backend, str):
        return None
    own = parsed.get("Self")
    if not isinstance(own, dict):
        own = {}

    def text_of(name: str) -> str:
        value = own.get(name)
        return value if isinstance(value, str) else ""

    def list_of(name: str) -> tuple[str, ...]:
        value = own.get(name)
        if not isinstance(value, list):
            return ()
        return tuple(item for item in value if isinstance(item, str))

    return NodeStatus(
        backend_state=backend,
        node_id=text_of("ID"),
        hostname=text_of("HostName"),
        dns_name=text_of("DNSName").rstrip("."),
        addresses=list_of("TailscaleIPs"),
        tags=list_of("Tags"),
    )


def read_status(tools: Tools, socket: Path) -> NodeStatus | None:
    code, out, _ = run_cli(tools, socket, ["status", "--json"], 30)
    del code  # a stopped or logged-out backend still prints its state
    return parse_status(out)


def wait_for(
    tools: Tools,
    daemon: Daemon,
    ready: Callable[[NodeStatus], bool],
    timeout: float,
    what: str,
) -> NodeStatus:
    """Poll the daemon's status until `ready` holds; fail if it exits or the time runs out."""
    deadline = time.monotonic() + timeout
    seen = "no answer"
    while True:
        if daemon.process.poll() is not None:
            detail = last_log_line(daemon.log)
            raise ToolError(
                f"tailscaled exited (status {daemon.process.returncode}) while waiting for "
                f"{what}" + (f": {detail}" if detail else "")
            )
        status = read_status(tools, daemon.socket) if daemon.socket.exists() else None
        if status is not None:
            if ready(status):
                return status
            seen = status.backend_state
        if time.monotonic() >= deadline:
            detail = last_log_line(daemon.log)
            raise ToolError(
                f"timed out waiting for {what} (last state: {seen})"
                + (f"; tailscaled said: {detail}" if detail else "")
            )
        time.sleep(POLL_SECONDS)


def bring_up(
    tools: Tools,
    socket: Path,
    auth_key_file: Path,
    hostname: str,
    tags: tuple[str, ...],
    login_server: str,
    timeout: int,
) -> None:
    """`tailscale up` with the one-time key read from its file; nothing secret in the argv."""
    args = [
        "up",
        f"--auth-key=file:{auth_key_file}",
        f"--hostname={hostname}",
        f"--advertise-tags={','.join(tags)}",
        "--accept-dns=false",
        "--accept-routes=false",
        "--ssh=false",
        "--netfilter-mode=off",
        f"--timeout={timeout}s",
    ]
    if login_server:
        args.append(f"--login-server={login_server}")
    code, _, err = run_cli(tools, socket, args, timeout + 30)
    if code != 0:
        raise ToolError(f"tailscale up failed: {one_line(err) or code}")


def logout(tools: Tools, socket: Path, timeout: float = 30) -> bool:
    """Best effort: True when `tailscale logout` succeeded."""
    try:
        code, _, _ = run_cli(tools, socket, ["logout"], timeout)
    except ToolError:
        return False
    return code == 0
