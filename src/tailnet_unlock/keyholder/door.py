"""The keyholder's SSH client: one door, one pin, one command (DESIGN.md sections 10.1, 10.2).

A session runs with a known-hosts file that holds a single pin under a HostKeyAlias of its own, so
a session that connects proves which key the door presented, and no configuration file, agent or
other known-hosts file takes part. What OpenSSH's exit code and stderr mean is decided by pure
functions.
"""

import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from tailnet_unlock.errors import ConfigError, ContractError
from tailnet_unlock.keyholder.approval import DoorKind
from tailnet_unlock.keyholder.doorstatus import MAX_STATUS_BYTES, DoorStatus, parse_door_status
from tailnet_unlock.keyholder.pins import (
    DoorPins,
    DoorRole,
    alias_known_hosts,
    check_address,
    check_reported_key,
)
from tailnet_unlock.keyholder.run import run_bounded

CONNECT_SECONDS = 10
# the door waits up to 600 s for ZFS to ask for the key, and passphrase derivation takes seconds
UNLOCK_SECONDS = 700.0
STATUS_SECONDS = 40.0
MAX_RESULT_BYTES = 4096

type SshOutcome = Literal["session", "auth-refused", "host-key-mismatch", "unreachable"]
type UnlockOutcome = Literal[
    "loaded", "wrong-key", "not-waiting", "boot-mismatch", "bad-command", "dropped"
]
type FailureKind = Literal["auth-refused", "host-key-mismatch", "unreachable", "bad-status", "lied"]

_PERMISSION_DENIED = re.compile(r"root@[^\s()]{1,300}: Permission denied \([a-z0-9,@.-]{1,200}\)\.")
# the door's exit codes (initramfs/door) with the result each one prints
_RESULTS: dict[int, UnlockOutcome] = {
    0: "loaded",
    1: "wrong-key",
    2: "not-waiting",
    3: "boot-mismatch",
    4: "bad-command",
}


@dataclass(frozen=True)
class Target:
    """One way to one door. `proxy` is the ProxyCommand for the tailnet door, if any."""

    kind: DoorKind
    address: str
    port: int
    name: str
    proxy: str | None = None


@dataclass(frozen=True)
class DoorFailure:
    kind: FailureKind
    detail: str


type DoorRead = DoorStatus | DoorFailure


def ssh_argv(
    target: Target, identity: str | None, known_hosts_file: Path, alias: str, command: str
) -> tuple[str, ...]:
    """OpenSSH's command line. Without an identity no key is offered at all: the host key is
    verified, and then authentication fails."""
    if re.search(r"[\s%$\"~]", str(known_hosts_file)):
        raise ConfigError("the temporary directory's path holds a space, quote, %, $ or ~")
    options = [
        "GlobalKnownHostsFile=/dev/null",
        f"UserKnownHostsFile={known_hosts_file}",
        f"HostKeyAlias={alias}",
        "HostKeyAlgorithms=ssh-ed25519",
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "IdentitiesOnly=yes",
        f"IdentityFile={identity or 'none'}",
        "PreferredAuthentications=publickey",
        "BatchMode=yes",
        f"ConnectTimeout={CONNECT_SECONDS}",
        "ServerAliveInterval=10",
        "ServerAliveCountMax=6",
        "ClearAllForwardings=yes",
        "LogLevel=ERROR",
    ]
    if identity is None:
        options.append("IdentityAgent=none")
    if target.proxy is not None:
        options.append(f"ProxyCommand={target.proxy}")
    flags = [item for option in options for item in ("-o", option)]
    return (
        "ssh",
        "-F",
        "/dev/null",
        "-T",
        *flags,
        "-p",
        str(target.port),
        "-l",
        "root",
        "--",
        check_address(target.address),
        command,
    )


def classify(exit_code: int | None, stderr: str) -> SshOutcome:
    """What an OpenSSH run at LogLevel=ERROR proves.

    "auth-refused" means the pinned host key was verified and then authentication failed. A server
    can put text of its own into OpenSSH's messages before its key is verified (a disconnect
    message, an algorithm list, with line breaks in it), but only behind OpenSSH's own words, so
    the proof is that the refusal is the whole of stderr.
    """
    if exit_code is None or exit_code < 0:
        return "unreachable"
    if exit_code != 255:
        return "session"
    text = stderr.replace("\r\n", "\n").removesuffix("\n")
    if _PERMISSION_DENIED.fullmatch(text):
        return "auth-refused"
    for line in text.split("\n"):
        if line == "Host key verification failed." or re.match(
            r"Unable to negotiate with \S+ port \d+: no matching host key type found", line
        ):
            return "host-key-mismatch"
    return "unreachable"


def parse_unlock(exit_code: int | None, stdout: bytes) -> UnlockOutcome:
    """The door's answer to `unlock`: its exit code and its line must say the same thing."""
    expected = None if exit_code is None else _RESULTS.get(exit_code)
    if expected is None or len(stdout) > MAX_RESULT_BYTES:
        return "dropped"
    try:
        value: object = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "dropped"
    if not isinstance(value, dict) or value.get("result") != expected:
        return "dropped"
    return expected


def _ssh(
    host: str,
    pins: DoorPins,
    role: DoorRole,
    target: Target,
    identity: str | None,
    command: str,
    stdin: bytes,
    timeout: float,
    max_stdout: int,
) -> tuple[int | None, bytes, str]:
    alias = f"tailnet-unlock-{role}-{host}".replace("_", "-")
    with tempfile.TemporaryDirectory(prefix="tailnet-unlock-") as work:
        hosts = Path(work) / "known_hosts"
        hosts.write_text(alias_known_hosts(pins, role, alias), encoding="ascii")
        ran = run_bounded(
            ssh_argv(target, identity, hosts, alias, command),
            stdin,
            timeout=timeout,
            max_stdout=max_stdout,
            stderr="capture",
            grace=2.0,
        )
    return ran.exit_code, ran.stdout, ran.stderr.decode("utf-8", errors="replace")


def read_door(
    host: str, pins: DoorPins, role: DoorRole, target: Target, identity: str | None
) -> DoorRead:
    """`status` through one pin: the parsed line, or why there is none."""
    code, stdout, stderr = _ssh(
        host, pins, role, target, identity, "status", b"", STATUS_SECONDS, MAX_STATUS_BYTES
    )
    outcome = classify(code, stderr)
    if outcome == "auth-refused":
        return DoorFailure("auth-refused", "the door refuses the keyholder's SSH key")
    if outcome == "host-key-mismatch":
        return DoorFailure("host-key-mismatch", f"not the pinned {role} key")
    if outcome == "unreachable":
        return DoorFailure("unreachable", "no answer")
    try:
        status = parse_door_status(stdout)
    except ContractError as error:
        return DoorFailure("bad-status", str(error))
    try:
        check_reported_key(role, status)
    except ContractError as error:
        return DoorFailure("lied", str(error))
    return status


def send_key(
    host: str,
    pins: DoorPins,
    role: DoorRole,
    target: Target,
    identity: str | None,
    boot_id: str,
    key: bytes,
) -> UnlockOutcome:
    """`unlock <boot_id>` with the key on ssh's stdin, and nowhere else. What the door prints back
    besides its result is not kept: a door could echo the key."""
    code, stdout, _ = _ssh(
        host,
        pins,
        role,
        target,
        identity,
        f"unlock {boot_id}",
        key,
        UNLOCK_SECONDS,
        MAX_RESULT_BYTES,
    )
    return parse_unlock(code, stdout)


def door_answers(
    host: str, pins: DoorPins, role: DoorRole, target: Target, identity: str | None
) -> bool:
    """Whether a door that holds the pinned key answers: a session, or a verified host key and
    then a refused login (a watcher may hold no key the door accepts)."""
    code, _, stderr = _ssh(
        host, pins, role, target, identity, "status", b"", STATUS_SECONDS, MAX_STATUS_BYTES
    )
    return classify(code, stderr) in {"session", "auth-refused"}
