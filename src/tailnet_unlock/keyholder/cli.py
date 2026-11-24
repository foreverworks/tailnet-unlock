"""The keyholder's commands (DESIGN.md section 12.5): `deliver`, `unlock`, `watch`, `planned` and
`approver`.

`tailnet-unlock` has them beside the box's commands; the zipapp has them alone. This module builds
the real edges: ssh, the approver, the key source, the hooks, `tailscale status` and the clock.
"""

import argparse
import getpass
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

from tailnet_unlock import __version__
from tailnet_unlock.errors import ConfigError, ContractError, ToolError
from tailnet_unlock.keyholder import approvers
from tailnet_unlock.keyholder.approval import (
    MAX_RESPONSE_BYTES,
    ApprovalRequest,
    Reason,
    ReasonKind,
    timestamp,
)
from tailnet_unlock.keyholder.config import (
    CONFIG_FILE,
    Argv,
    HostConfig,
    KeyholderConfig,
    host_config,
    parse_keyholder_config,
)
from tailnet_unlock.keyholder.deliver import (
    EXIT_CODES,
    AuditLine,
    DoorChoice,
    Edge,
    Job,
    Outcome,
    Timing,
    Trace,
    audit_line,
    check_job,
    default_roles,
    run_delivery,
)
from tailnet_unlock.keyholder.door import door_answers, read_door, send_key
from tailnet_unlock.keyholder.keymaterial import MAX_KEY_SOURCE_BYTES
from tailnet_unlock.keyholder.peers import View, parse_view
from tailnet_unlock.keyholder.pins import roles_for_unlock
from tailnet_unlock.keyholder.run import Ran, run_bounded
from tailnet_unlock.keyholder.state import (
    STATE_DIR,
    Planned,
    append_audit,
    clear_planned,
    host_lock,
    parse_duration,
    prepare,
    read_last_unlock,
    read_memory,
    read_planned,
    write_last_unlock,
    write_memory,
    write_planned,
)
from tailnet_unlock.keyholder.watch import WatchEdge, WatchEvent, needs_view, run_pass
from tailnet_unlock.tailscale import child_env

STATUS_TIMEOUT = 20.0
MAX_STATUS_JSON = 32 * 1024 * 1024
KEY_SOURCE_TIMEOUT = 120.0
TIMING = Timing()
REASONS: tuple[ReasonKind, ...] = ("planned", "unplanned", "manual")
DOORS: tuple[DoorChoice, ...] = ("any", "tailnet", "uplink")
# how long a delivery the watcher started may take to clean up after a stop
CHILD_GRACE = 30.0

type Commands = "argparse._SubParsersAction[argparse.ArgumentParser]"


def _say(text: str) -> None:
    print(f"tailnet-unlock: {text}", file=sys.stderr, flush=True)


def _now() -> datetime:
    return datetime.now(UTC)


def _on_stop(signum: int, frame: object) -> NoReturn:
    """Leave through the cleanup, once: a second signal must not cut the cleanup short."""
    del frame
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def _stop_cleanly() -> None:
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, _on_stop)


def self_argv() -> Argv:
    """How this program was started, without its arguments: the interpreter, its options and the
    module or zipapp."""
    count = len(sys.orig_argv) - len(sys.argv[1:])
    return (sys.executable, *sys.orig_argv[1:count])


def _load(args: argparse.Namespace) -> KeyholderConfig:
    path = Path(str(args.config))
    try:
        return parse_keyholder_config(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"{path} does not exist: write keyholder.toml first") from None
    except UnicodeDecodeError:
        raise ConfigError(f"{path} is not UTF-8 text") from None


def _state_dir(args: argparse.Namespace) -> Path:
    path = Path(str(args.state_dir))
    prepare(path)
    return path


def _line(value: str | None, name: str) -> str | None:
    """A short line of a person's text; it goes into the request, the audit and the events."""
    if value is None:
        return None
    if not value.strip() or len(value) > 200 or not value.isprintable():
        raise ConfigError(f"{name}: one printable line of at most 200 characters")
    return value


def _require_ssh() -> None:
    if shutil.which("ssh") is None:
        raise ConfigError("ssh not found: install the OpenSSH client")


# --- the edges ----------------------------------------------------------------------------------


def read_view(config: KeyholderConfig) -> View:
    """The keyholder's own tailnet node, through `tailscale status --json`."""
    ran = run_bounded(
        (*config.tailscale, "status", "--json"),
        timeout=STATUS_TIMEOUT,
        max_stdout=MAX_STATUS_JSON,
        stderr="discard",
        env=child_env(),
    )
    if ran.exit_code != 0:
        how = "timed out" if ran.exit_code is None else f"exited {ran.exit_code}"
        raise ToolError(f"{config.tailscale[0]} status --json {how}")
    return parse_view(ran.stdout.decode("utf-8", errors="replace"))


def _approve(argv: Argv, request: ApprovalRequest, timeout: float) -> Ran:
    return run_bounded(
        argv,
        json.dumps(request).encode("utf-8") + b"\n",
        timeout=timeout,
        max_stdout=MAX_RESPONSE_BYTES,
    )


def _key_source(argv: Argv) -> bytes:
    """The key source's output. Its stderr is discarded, so nothing it says there can put the key
    in a log."""
    ran = run_bounded(
        argv, timeout=KEY_SOURCE_TIMEOUT, max_stdout=MAX_KEY_SOURCE_BYTES, stderr="discard"
    )
    if ran.exit_code != 0:
        how = "timed out" if ran.exit_code is None else f"exited {ran.exit_code}"
        raise ToolError(f"the key source {how}")
    return ran.stdout


def _typed_key(host: str) -> bytes:
    # without a terminal getpass reads stdin instead and echoes it
    try:
        os.close(os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY))
    except OSError as error:
        raise ToolError("the key is typed at a terminal, and there is none") from error
    return getpass.getpass(f"Root key of {host}: ").encode("utf-8")


def _edge(config: KeyholderConfig, host: HostConfig, approver: Argv, key_argv: Argv | None) -> Edge:
    told: list[str] = []

    def view() -> View | None:
        if not needs_view((host,)):
            return None
        try:
            return read_view(config)
        except ToolError as error:
            if str(error) not in told:
                told.append(str(error))
                _say(f"{host.name}: {error}; the tailnet door cannot be found")
            return None

    identity = host.settings.ssh_key
    return Edge(
        view=view,
        read_door=lambda role, target: read_door(host.name, host.pins, role, target, identity),
        recovery_answers=lambda target: door_answers(
            host.name, host.pins, "recovery", target, None
        ),
        approve=lambda request, timeout: _approve(approver, request, timeout),
        key_source=lambda: _typed_key(host.name) if key_argv is None else _key_source(key_argv),
        send_key=lambda role, target, boot_id, key: send_key(
            host.name, host.pins, role, target, identity, boot_id, key
        ),
        new_request_id=lambda: secrets.token_hex(16),
        now=_now,
        monotonic=time.monotonic,
        sleep=time.sleep,
        say=_say,
    )


# --- deliver and unlock -------------------------------------------------------------------------


def _recorder(state_dir: Path, host: str) -> Callable[[AuditLine, Outcome], None]:
    def record(line: AuditLine, outcome: Outcome) -> None:
        text = json.dumps(line)
        append_audit(state_dir, text)
        print(text, flush=True)
        if outcome.result == "delivered":
            # the key is in: what cannot be noted about it does not make the delivery a failure
            try:
                write_last_unlock(state_dir, host, _now())
                clear_planned(state_dir, host)
            except OSError as error:
                _say(f"{host}: delivered, and the state could not be written: {error}")

    return record


def _run(state_dir: Path, edge: Edge, job: Job) -> int:
    record = _recorder(state_dir, job.host.name)
    with host_lock(state_dir, job.host.name) as held:
        if not held:
            outcome = Outcome("busy", "another delivery for this host is under way")
            record(audit_line(job, Trace(), outcome, _now()), outcome)
        else:
            outcome = run_delivery(edge, job, record)
    return EXIT_CODES[outcome.result]


def _cmd_deliver(args: argparse.Namespace) -> int:
    config = _load(args)
    host = host_config(config, args.host)
    reason: Reason = {
        "kind": args.reason,
        "started_by": _line(args.by, "--by"),
        "note": _line(args.note, "--note"),
    }
    if args.idle_minutes is not None and not 1 <= args.idle_minutes <= 1440:
        raise ConfigError("--idle-minutes: between 1 and 1440")
    _require_ssh()
    state_dir = _state_dir(args)
    job = Job(
        host=host,
        reason=reason,
        door=args.door,
        idle_minutes=args.idle_minutes,
        last_unlock_at=read_last_unlock(state_dir, host.name),
        roles=default_roles(host),
        timing=TIMING,
    )
    check_job(job, key_configured=bool(host.key_command))
    _stop_cleanly()
    edge = _edge(config, host, host.settings.approver, host.key_command)
    return _run(state_dir, edge, job)


def _cmd_unlock(args: argparse.Namespace) -> int:
    """A person at a terminal: the `tty` approver, and the key typed when no source is configured.

    `--recovery` uses the recovery pin alone, and is the person's own decision (section 10.2).
    """
    config = _load(args)
    host = host_config(config, args.host)
    if args.recovery and host.pins.recovery_key is None:
        raise ConfigError(f"hosts.{host.name}.door: no recovery_key is pinned")
    if not args.recovery and host.pins.door_key is None:
        raise ConfigError(f"hosts.{host.name}.door: only a recovery key is pinned; use --recovery")
    _require_ssh()
    state_dir = _state_dir(args)
    job = Job(
        host=host,
        reason={"kind": "manual", "started_by": getpass.getuser(), "note": None},
        door=args.door,
        idle_minutes=None,
        last_unlock_at=read_last_unlock(state_dir, host.name),
        roles=roles_for_unlock(args.recovery),
        by_hand=True,
        timing=TIMING,
    )
    check_job(job, key_configured=True)
    _stop_cleanly()
    edge = _edge(config, host, (*self_argv(), "approver", "tty"), host.key_command or None)
    return _run(state_dir, edge, job)


# --- watch --------------------------------------------------------------------------------------


@dataclass
class Children:
    """The deliveries this watcher started, by host."""

    running: dict[str, subprocess.Popen[bytes]] = field(default_factory=dict)
    failed: bool = False


def _reap(children: Children, wait: bool) -> None:
    for name, child in list(children.running.items()):
        code = child.wait() if wait else child.poll()
        if code is None:
            continue
        del children.running[name]
        # what it decided is in its own audit line; 1, 2 and a signal mean it decided nothing
        if code in {1, 2} or code < 0:
            children.failed = True
            _say(f"{name}: the delivery exited {code}")


def _stop_children(children: Children) -> None:
    for child in children.running.values():
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
    deadline = time.monotonic() + CHILD_GRACE
    for child in children.running.values():
        try:
            child.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def _watch_edge(
    args: argparse.Namespace, config: KeyholderConfig, state_dir: Path, children: Children
) -> WatchEdge:
    def delivering(host: HostConfig) -> bool:
        if host.name in children.running:
            return True
        with host_lock(state_dir, host.name) as free:
            return not free

    def start_delivery(host: HostConfig, reason: Reason) -> None:
        argv = [
            *self_argv(),
            "deliver",
            f"--config={args.config}",
            f"--state-dir={args.state_dir}",
            f"--reason={reason['kind']}",
        ]
        if reason["started_by"] is not None:
            argv.append(f"--by={reason['started_by']}")
        if reason["note"] is not None:
            argv.append(f"--note={reason['note']}")
        children.running[host.name] = subprocess.Popen(
            [*argv, "--", host.name], stdin=subprocess.DEVNULL, process_group=0
        )

    def emit(event: WatchEvent) -> None:
        print(json.dumps(event), flush=True)

    return WatchEdge(
        view=lambda: read_view(config),
        probe=lambda host, role, target: door_answers(
            host.name, host.pins, role, target, host.settings.ssh_key
        ),
        start_delivery=start_delivery,
        delivering=delivering,
        run_hook=lambda argv, stdin, timeout: run_bounded(argv, stdin, timeout=timeout),
        read_memory=lambda host: read_memory(state_dir, host.name),
        write_memory=lambda host, memory: write_memory(state_dir, host.name, memory),
        read_planned=lambda host: read_planned(state_dir, host.name, _now()),
        now=_now,
        sleep=time.sleep,
        emit=emit,
        say=_say,
    )


def _check_watched(hosts: tuple[HostConfig, ...]) -> None:
    """A host without `on_waiting` is delivered to, so it needs what a delivery needs."""
    for host in hosts:
        if host.settings.on_waiting:
            continue
        missing = [
            name
            for name, value in (
                ("ssh_key", host.settings.ssh_key),
                ("key_command", host.key_command),
                ("approver", host.settings.approver),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                f"hosts.{host.name}: set on_waiting, or what a delivery needs "
                f"({', '.join(missing)} not set)"
            )


def _cmd_watch(args: argparse.Namespace) -> int:
    config = _load(args)
    hosts = tuple(host_config(config, name) for name in args.hosts) or config.hosts
    _check_watched(hosts)
    if args.every is not None and not 10 <= args.every <= 86400:
        raise ConfigError("--every: between 10 and 86400 seconds")
    _require_ssh()
    state_dir = _state_dir(args)
    children = Children()
    edge = _watch_edge(args, config, state_dir, children)
    _stop_cleanly()
    try:
        if args.every is None:
            good = run_pass(edge, hosts)
            _reap(children, wait=True)
            return 0 if good and not children.failed else 1
        while True:
            try:
                run_pass(edge, hosts)
            except (ConfigError, ToolError, OSError) as error:
                _say(f"this pass decided nothing more: {error}")
            _reap(children, wait=False)
            time.sleep(args.every)
    finally:
        _stop_children(children)


# --- planned, approver --------------------------------------------------------------------------


def _cmd_planned(args: argparse.Namespace) -> int:
    host = host_config(_load(args), args.host)
    state_dir = _state_dir(args)
    if args.clear:
        print(json.dumps({"host": host.name, "cleared": clear_planned(state_dir, host.name)}))
        return 0
    by = _line(args.by, "--by")
    if by is None:
        raise ConfigError("--by: say who planned the reboot")
    until = _now() + parse_duration(args.duration)
    write_planned(state_dir, host.name, Planned(by, _line(args.note, "--note"), until))
    print(json.dumps({"host": host.name, "by": by, "until": timestamp(until)}))
    return 0


def _cmd_approver(args: argparse.Namespace) -> int:
    return approvers.deny() if args.which == "deny" else approvers.tty()


def _common(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--config", default=str(CONFIG_FILE), help="keyholder.toml (default %(default)s)"
    )
    command.add_argument(
        "--state-dir", default=str(STATE_DIR), help="the state directory (default %(default)s)"
    )


def _door_choice(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--door",
        choices=DOORS,
        default="any",
        help="the tailnet door, the uplink's, or the tailnet's and then the uplink's (default)",
    )


def add_commands(commands: Commands) -> None:
    delivering = commands.add_parser(
        "deliver",
        help="wait for a box's door, ask the approver, send the root key",
        description=(
            "Exit codes: 0 delivered, 2 configuration error, 3 refused, 4 the approval timed out, "
            "5 no door found, 6 wrong key, 7 not needed, 8 only the recovery door answers, "
            "9 another delivery is under way, 10 failed after the door was found; 128 plus the "
            "signal when stopped. One JSON audit line goes to stdout and to audit.jsonl."
        ),
    )
    delivering.add_argument("host")
    delivering.add_argument("--reason", required=True, choices=REASONS)
    delivering.add_argument("--by", metavar="WHO", help="who started this, for the approver")
    delivering.add_argument("--note", metavar="TEXT", help="a line for the approver")
    _door_choice(delivering)
    delivering.add_argument(
        "--idle-minutes",
        type=int,
        metavar="N",
        help="end as not needed once the box's own node stayed online this long with no door",
    )
    _common(delivering)
    delivering.set_defaults(handler=_cmd_deliver)

    unlocking = commands.add_parser(
        "unlock", help="unlock a box by hand: approve at this terminal, then send the key"
    )
    unlocking.add_argument("host")
    unlocking.add_argument(
        "--recovery", action="store_true", help="the recovery door: its pin alone"
    )
    _door_choice(unlocking)
    _common(unlocking)
    unlocking.set_defaults(handler=_cmd_unlock)

    watching = commands.add_parser(
        "watch",
        help="notice boxes that wait at their door, and unlock nodes that should be offline",
        description=(
            "One pass, or one every --every seconds. Exits 2 when the tailnet cannot be read "
            "(nothing is decided then) and 1 when a hook failed."
        ),
    )
    watching.add_argument("hosts", nargs="*", metavar="host", help="only these (default: all)")
    watching.add_argument("--every", type=int, metavar="SECONDS")
    _common(watching)
    watching.set_defaults(handler=_cmd_watch)

    planning = commands.add_parser("planned", help="announce a reboot, for the watcher's requests")
    planning.add_argument("host")
    planning.add_argument("--by", metavar="WHO")
    planning.add_argument("--note", metavar="TEXT")
    planning.add_argument(
        "--for", dest="duration", default="30m", metavar="TIME", help="90s, 30m, 2h (default 30m)"
    )
    planning.add_argument("--clear", action="store_true", help="take the marker back")
    _common(planning)
    planning.set_defaults(handler=_cmd_planned)

    approver = commands.add_parser("approver", help="the built-in approvers, for keyholder.toml")
    approver.add_argument("which", choices=("deny", "tty"))
    approver.set_defaults(handler=_cmd_approver)


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        prog="tailnet-unlock-keyholder", description="Deliver root keys to boxes at their doors."
    )
    top.add_argument("--version", action="version", version=__version__)
    add_commands(top.add_subparsers(dest="command", required=True))
    return top


def main(argv: Sequence[str] | None = None) -> int:
    """The zipapp's entry point."""
    args = parser().parse_args(argv)
    try:
        code: int = args.handler(args)
    except (ConfigError, ContractError, ToolError, OSError) as error:
        _say(str(error))
        return 2
    return code
