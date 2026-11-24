"""Run one program for the keyholder: no shell, its own process group, bounded in time and output.

ssh, the approver, the key source, the hooks and `tailscale` all go through here. The program is
started in a process group of its own. When it ends, at its timeout, or when this process is told
to stop (SIGTERM, SIGINT), the whole group ends: at a timeout or a stop it gets SIGTERM and
`grace` seconds to clean up, such as an approver cancelling its request, and then SIGKILL.

What goes in on stdin and what comes back on stdout may be a root key, so neither is ever in an
argument, the environment, a log or an exception.
"""

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Literal

from tailnet_unlock.errors import ToolError

GRACE_SECONDS = 10.0
POLL_SECONDS = 0.05
CHUNK = 65536
DRAIN_TURNS = 64
MAX_STDERR = 16384
STDERR_FILENO = 2

type Stderr = Literal["capture", "discard", "inherit"]


@dataclass(frozen=True)
class Ran:
    """`exit_code` is None when the program was stopped at its timeout, and negative when a signal
    ended it. A program that prints too much is killed, and `stdout` then holds one byte more than
    was asked for, so "too long" shows."""

    exit_code: int | None
    stdout: bytes
    stderr: bytes


@dataclass
class _Pipes:
    """What is left to write, and what came back so far."""

    pending: bytes
    stdout: bytearray
    stderr: bytearray


def run_bounded(
    argv: tuple[str, ...],
    stdin: bytes = b"",
    *,
    timeout: float,
    max_stdout: int | None = None,
    stderr: Stderr = "inherit",
    grace: float = GRACE_SECONDS,
    env: dict[str, str] | None = None,
) -> Ran:
    """Run `argv`. Without `max_stdout`, what it prints goes to this process's stderr."""
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=STDERR_FILENO if max_stdout is None else subprocess.PIPE,
            stderr={
                "capture": subprocess.PIPE,
                "discard": subprocess.DEVNULL,
                "inherit": None,
            }[stderr],
            process_group=0,
            env=env,
        )
    except (OSError, ValueError) as error:
        reason = error.strerror if isinstance(error, OSError) else "not a usable argument list"
        raise ToolError(f"cannot run {argv[0]}: {reason}") from None
    pipes = _Pipes(stdin, bytearray(), bytearray())
    ended = False
    try:
        ended = _pump(process, pipes, time.monotonic() + timeout, (max_stdout or 0) + 1)
    finally:
        # on a signal to this process too: the group is gone before anything else happens
        _end_group(process, 0.0 if ended else grace)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    return Ran(
        process.returncode if ended else None, bytes(pipes.stdout), bytes(pipes.stderr[:MAX_STDERR])
    )


def _has_exited(process: subprocess.Popen[bytes]) -> bool:
    """Whether the leader has exited. It is not reaped, so its group id cannot be reused."""
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def _pump(
    process: subprocess.Popen[bytes], pipes: _Pipes, deadline: float, max_stdout: int
) -> bool:
    """Move bytes until the program exits or prints too much (True), or the deadline passes
    (False)."""
    with selectors.DefaultSelector() as selector:
        for stream, events in (
            (process.stdin, selectors.EVENT_WRITE),
            (process.stdout, selectors.EVENT_READ),
            (process.stderr, selectors.EVENT_READ),
        ):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, events)

        def turn(wait: float) -> bool:
            """One round; whether anything moved."""
            moved = False
            for key, _ in selector.select(wait):
                moved = True
                if key.fileobj is process.stdin:
                    done = _feed(key.fd, pipes)
                elif key.fileobj is process.stdout:
                    done = _take(key.fd, pipes.stdout, max_stdout)
                else:
                    done = _take(key.fd, pipes.stderr, MAX_STDERR)
                if done:
                    selector.unregister(key.fileobj)
                    if key.fileobj is process.stdin and process.stdin is not None:
                        process.stdin.close()
            return moved

        while True:
            if _has_exited(process):
                # whatever it left running ends first, so what is in the pipes is all there is
                _signal_group(process, signal.SIGKILL)
                for _ in range(DRAIN_TURNS):
                    if not selector.get_map() or not turn(0):
                        break
                return True
            if len(pipes.stdout) >= max_stdout:
                _signal_group(process, signal.SIGKILL)
                return True
            if time.monotonic() >= deadline:
                return False
            if selector.get_map():
                turn(POLL_SECONDS)
            else:
                time.sleep(POLL_SECONDS)


def _feed(fd: int, pipes: _Pipes) -> bool:
    try:
        written = os.write(fd, pipes.pending) if pipes.pending else 0
    except BlockingIOError:
        return False
    except BrokenPipeError:
        pipes.pending = b""
        return True
    pipes.pending = pipes.pending[written:]
    return not pipes.pending


def _take(fd: int, buffer: bytearray, limit: int) -> bool:
    try:
        block = os.read(fd, CHUNK)
    except BlockingIOError:
        return False
    buffer += block[: max(0, limit - len(buffer))]
    return not block


def _signal_group(process: subprocess.Popen[bytes], signum: int) -> None:
    try:
        os.killpg(process.pid, signum)
    except (ProcessLookupError, PermissionError):
        # PermissionError: macOS, when only the unreaped leader is left in the group
        return


def _end_group(process: subprocess.Popen[bytes], grace: float) -> None:
    """SIGTERM and time to clean up, SIGKILL for whatever is left, then reap the leader."""
    if process.returncode is None and grace > 0 and not _has_exited(process):
        _signal_group(process, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and not _has_exited(process):
            time.sleep(POLL_SECONDS)
    if process.returncode is None:
        _signal_group(process, signal.SIGKILL)
        process.wait()
