"""One delivery (DESIGN.md section 10.2): find the door, ask, check again, send the key.

The flow is here, over an `Edge` of effects (ssh, the approver, the key source, the clock), so every
decision is tested without a network. Nothing in this module prints the key, and the only function
that gets it is the one that writes it to ssh's stdin.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal, TypedDict

from tailnet_unlock.errors import ConfigError, ContractError, ToolError
from tailnet_unlock.keyholder.approval import (
    ApprovalRequest,
    Approved,
    BootInfo,
    DoorKind,
    NetworkInfo,
    Reason,
    Refused,
    build_request,
    judge_response,
    recovery_gate,
    timestamp,
)
from tailnet_unlock.keyholder.config import HostConfig
from tailnet_unlock.keyholder.door import DoorFailure, DoorRead, Target, UnlockOutcome
from tailnet_unlock.keyholder.doorstatus import DoorStatus
from tailnet_unlock.keyholder.keymaterial import wire_key
from tailnet_unlock.keyholder.peers import (
    View,
    dial_address,
    find_peer,
    peer_name,
    presence,
    tailnet_network,
    uplink_network,
)
from tailnet_unlock.keyholder.pins import DoorRole, pin_fingerprint, roles_for_delivery
from tailnet_unlock.keyholder.run import Ran

AUDIT_SCHEMA = "tailnet-unlock.audit/1"

type DoorChoice = Literal["tailnet", "uplink", "any"]
type Result = Literal[
    "delivered",
    "refused",
    "approval-timeout",
    "door-not-found",
    "wrong-key",
    "not-needed",
    "recovery-only",
    "busy",
    "failed",
    "interrupted",
]

# 1 is left to an unexpected error, 2 to a usage or configuration error; an interrupted delivery
# exits 128 plus the signal
EXIT_CODES: dict[Result, int] = {
    "delivered": 0,
    "refused": 3,
    "approval-timeout": 4,
    "door-not-found": 5,
    "wrong-key": 6,
    "not-needed": 7,
    "recovery-only": 8,
    "busy": 9,
    "failed": 10,
    "interrupted": 130,
}


@dataclass(frozen=True)
class Timing:
    poll_seconds: float = 5.0
    # the box tries its TPM again for a while before its recovery door is final (section 7.3)
    recovery_settle_seconds: float = 120.0
    recheck_tries: int = 3


@dataclass(frozen=True)
class Edge:
    """Every effect a delivery has."""

    view: Callable[[], View | None]
    read_door: Callable[[DoorRole, Target], DoorRead]
    recovery_answers: Callable[[Target], bool]
    approve: Callable[[ApprovalRequest, float], Ran]
    key_source: Callable[[], bytes]
    send_key: Callable[[DoorRole, Target, str, bytes], UnlockOutcome]
    new_request_id: Callable[[], str]
    now: Callable[[], datetime]
    monotonic: Callable[[], float]
    sleep: Callable[[float], None]
    say: Callable[[str], None]


@dataclass(frozen=True)
class Job:
    """What to deliver. `roles` are the pins that may be tried; `by_hand` is `unlock`, where a
    person at the terminal chose the recovery door with a flag."""

    host: HostConfig
    reason: Reason
    door: DoorChoice
    idle_minutes: int | None
    last_unlock_at: str | None
    roles: tuple[DoorRole, ...]
    by_hand: bool = False
    timing: Timing = field(default_factory=Timing)


@dataclass(frozen=True)
class Found:
    target: Target
    role: DoorRole
    status: DoorStatus
    network: NetworkInfo


@dataclass(frozen=True)
class Outcome:
    result: Result
    detail: str
    warnings: tuple[str, ...] = ()


@dataclass
class Trace:
    """What is known so far, so an interrupted delivery is audited too."""

    found: Found | None = None
    request: ApprovalRequest | None = None
    decision: "Decision | None" = None
    key_handed_to_ssh: bool = False


class Decision(TypedDict):
    approved: bool
    by: str | None
    note: str | None


class AuditDoor(TypedDict):
    role: DoorRole
    kind: DoorKind
    address: str
    port: int
    host_key_sha256: str


class AuditLine(TypedDict):
    schema: str
    time: str
    host: str
    result: Result
    detail: str
    warnings: list[str]
    reason: Reason
    request_id: str | None
    door: AuditDoor | None
    boot_id: str | None
    network: NetworkInfo | None
    decision: Decision | None


def default_roles(host: HostConfig) -> tuple[DoorRole, ...]:
    return roles_for_delivery(host.pins, host.settings.allow_recovery_delivery)


def check_job(job: Job, key_configured: bool) -> None:
    """What the configuration must hold before anything starts."""
    host = job.host
    where = f"hosts.{host.name}"
    if host.settings.ssh_key is None:
        raise ConfigError(f"{where}: no ssh_key is configured, and delivery logs in with one")
    if not key_configured:
        raise ConfigError(f"{where}: no key_command is configured")
    if job.door == "uplink" and host.uplink is None:
        raise ConfigError(f"{where}.door: --door uplink, but no uplink is configured")
    if job.door == "tailnet" and host.unlock_node is None:
        raise ConfigError(f"{where}.door: --door tailnet, but no unlock node is configured")
    if job.idle_minutes is not None and host.node is None:
        raise ConfigError(f"{where}: --idle-minutes needs node (the box's own tailnet node)")


def door_targets(host: HostConfig, view: View | None, door: DoorChoice) -> tuple[Target, ...]:
    """The doors to try, in order: the tailnet's when its node is online, then the uplink's."""
    targets: list[Target] = []
    if door in {"tailnet", "any"} and view is not None and host.unlock_node is not None:
        peer = find_peer(view, host.unlock_node)
        address = None if peer is None else dial_address(peer)
        if peer is not None and peer.online and address is not None:
            targets.append(
                Target(
                    "tailnet",
                    address,
                    host.pins.port,
                    peer_name(peer),
                    host.settings.ssh_proxy_command,
                )
            )
    if door in {"uplink", "any"} and host.uplink is not None:
        targets.append(Target("uplink", host.uplink, host.uplink_port, host.uplink))
    return tuple(targets)


def network_of(host: HostConfig, target: Target, view: View | None) -> NetworkInfo:
    if target.kind == "tailnet" and view is not None and host.unlock_node is not None:
        peer = find_peer(view, host.unlock_node)
        if peer is not None:
            return tailnet_network(host, peer)
    if target.kind == "uplink":
        return uplink_network(host)
    return {
        "path": "relayed",
        "observed_endpoint": None,
        "relay": None,
        "reported_endpoints": [],
        "expected": [str(network) for network in host.expected_endpoints],
        "site_match": "unverified",
    }


def boot_info(status: DoorStatus) -> BootInfo:
    return {
        "boot_id": status["boot_id"],
        "kernel": status["kernel"],
        "profile": status["profile"],
        "seal": status["seal"],
        "degraded": status["degraded"],
        "backend": status["backend"],
        "waiting_for": status["waiting_for"],
        "keyformat": status["keyformat"],
        "tailscaled": status["tailscaled"],
    }


def changed_since(approved: DoorStatus, again: DoorStatus) -> str | None:
    """Why the door that answers now is not the one that was approved. The door key is the same
    by construction: both were read through one pin."""
    if again["boot_id"] != approved["boot_id"]:
        return "the box rebooted after the approval; a new approval is needed"
    for name, before, after in (
        ("root", approved["waiting_for"], again["waiting_for"]),
        ("key format", approved["keyformat"], again["keyformat"]),
    ):
        if before != after:
            return f"the door names another {name} than the one approved"
    return None


# --- finding the door ---------------------------------------------------------------------------


@dataclass
class _Search:
    """What the wait for a door has seen so far."""

    started: float
    mismatch_since: float | None = None
    idle_since: float | None = None
    last: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _Round:
    found: tuple[Target, DoorRole, DoorStatus] | None
    failures: tuple[tuple[Target, DoorRole, DoorFailure], ...]


def _try_doors(edge: Edge, targets: tuple[Target, ...], roles: tuple[DoorRole, ...]) -> _Round:
    """Each door through one pin at a time; the next pin only after a host key mismatch."""
    failures: list[tuple[Target, DoorRole, DoorFailure]] = []
    for target in targets:
        for role in roles:
            read = edge.read_door(role, target)
            if not isinstance(read, DoorFailure):
                if read["waiting_for"] and read["keyformat"]:
                    return _Round((target, role, read), tuple(failures))
                read = DoorFailure("bad-status", "the root is not waiting for a key yet")
            failures.append((target, role, read))
            if read.kind != "host-key-mismatch":
                break
    return _Round(None, tuple(failures))


def _recovery_only(edge: Edge, job: Job, seen: _Round) -> bool:
    """Whether a door that failed the sealed pin proves to be the pinned recovery door."""
    if job.host.pins.recovery_key is None or "recovery" in job.roles:
        return False
    return any(
        edge.recovery_answers(target)
        for target, _, failure in seen.failures
        if failure.kind == "host-key-mismatch"
    )


def find_door(edge: Edge, job: Job) -> Found | Outcome:
    host = job.host
    wait = host.settings.door_wait_minutes * 60.0
    search = _Search(started=edge.monotonic())
    while True:
        view = edge.view()
        seen = _try_doors(edge, door_targets(host, view, job.door), job.roles)
        if seen.found is not None:
            target, role, status = seen.found
            # read again: a path that was idle before the session is direct or relayed now
            network = network_of(host, target, edge.view() or view)
            return Found(target, role, status, network)
        for target, _, failure in seen.failures:
            if failure.kind == "lied":
                return Outcome("refused", f"{target.kind} door: {failure.detail}")
            search.last[target.kind] = failure.detail
        outcome = _judge_round(edge, job, search, seen, view)
        if outcome is not None:
            return outcome
        remaining = wait - (edge.monotonic() - search.started)
        if remaining <= 0:
            if _recovery_only(edge, job, seen):
                return _manual_only()
            details = [f"{kind}: {detail}" for kind, detail in sorted(search.last.items())]
            return Outcome("door-not-found", "; ".join(details) or "no door to try")
        edge.sleep(min(job.timing.poll_seconds, remaining))


def _manual_only() -> Outcome:
    return Outcome("recovery-only", "recovery door, manual only (allow_recovery_delivery is false)")


def _judge_round(
    edge: Edge, job: Job, search: _Search, seen: _Round, view: View | None
) -> Outcome | None:
    """After a round in which no door gave a usable status: whether that ends the wait early."""
    now = edge.monotonic()
    kinds = {failure.kind for _, _, failure in seen.failures}
    if "host-key-mismatch" not in kinds:
        search.mismatch_since = None
    elif search.mismatch_since is None:
        search.mismatch_since = now
    elif now - search.mismatch_since >= job.timing.recovery_settle_seconds:
        if _recovery_only(edge, job, seen):
            return _manual_only()
        search.mismatch_since = now
    answering = bool(kinds & {"auth-refused", "bad-status"})
    if job.idle_minutes is None or answering or presence(view, job.host.node) != "online":
        search.idle_since = None
    elif search.idle_since is None:
        search.idle_since = now
    elif now - search.idle_since >= job.idle_minutes * 60.0:
        return Outcome(
            "not-needed",
            f"the box's own node stayed online for {job.idle_minutes} min with no door answering",
        )
    return None


# --- the delivery -------------------------------------------------------------------------------


def deliver(edge: Edge, job: Job, trace: Trace) -> Outcome:
    host = job.host
    if not job.by_hand and not host.settings.approver:
        return Outcome("refused", "no approver is configured")
    if not job.roles:
        return _manual_only()
    found = find_door(edge, job)
    if isinstance(found, Outcome):
        return found
    trace.found = found
    gate = recovery_gate(found.role, job.by_hand or host.settings.allow_recovery_delivery)
    if gate is not None:
        return Outcome("recovery-only", gate.reason)
    approved = _ask(edge, job, found, trace)
    if isinstance(approved, Outcome):
        return approved
    changed = _check_again(edge, job, found)
    if changed is not None:
        return changed
    return _send(edge, job, found, trace)


def _ask(edge: Edge, job: Job, found: Found, trace: Trace) -> Approved | Outcome:
    host = job.host
    timeout = float(host.settings.approval_timeout_seconds)
    request = build_request(
        request_id=edge.new_request_id(),
        now=edge.now(),
        timeout=timedelta(seconds=timeout),
        host=host.name,
        reason=job.reason,
        verified_role=found.role,
        door_kind=found.target.kind,
        address=found.target.name,
        port=found.target.port,
        host_key_sha256=pin_fingerprint(host.pins, found.role),
        boot=boot_info(found.status),
        network=found.network,
        history={"last_unlock_at": job.last_unlock_at},
    )
    trace.request = request
    edge.say(f"{host.name}: the {found.role} door answers; asking for approval")
    ran = edge.approve(request, timeout)
    judged = judge_response(request, ran.stdout, ran.exit_code, edge.now())
    if isinstance(judged, Refused):
        trace.decision = {"approved": False, "by": None, "note": judged.reason}
        result: Result = "approval-timeout" if ran.exit_code is None else "refused"
        return Outcome(result, judged.reason)
    trace.decision = {"approved": True, "by": judged.by, "note": judged.note}
    return judged


def _check_again(edge: Edge, job: Job, found: Found) -> Outcome | None:
    """Step 5: the same boot id, read again through the same single pin."""
    read: DoorRead = DoorFailure("unreachable", "not tried")
    for attempt in range(job.timing.recheck_tries):
        if attempt:
            edge.sleep(job.timing.poll_seconds)
        read = edge.read_door(found.role, found.target)
        if not isinstance(read, DoorFailure) or read.kind != "unreachable":
            break
    if isinstance(read, DoorFailure):
        result: Result = "failed" if read.kind == "unreachable" else "refused"
        return Outcome(result, f"after the approval: {read.detail}; a new approval is needed")
    changed = changed_since(found.status, read)
    return None if changed is None else Outcome("refused", changed)


def _send(edge: Edge, job: Job, found: Found, trace: Trace) -> Outcome:
    keyformat = found.status["keyformat"]
    if keyformat is None:  # find_door returns no such status
        return Outcome("failed", "the door names no key format")
    was_online = presence(edge.view(), job.host.node) == "online"
    try:
        key = wire_key(edge.key_source(), keyformat)
    except (ContractError, ToolError) as error:
        return Outcome("failed", str(error))
    trace.key_handed_to_ssh = True
    answer = edge.send_key(found.role, found.target, found.status["boot_id"], key)
    del key
    match answer:
        case "loaded":
            return _wait_for_node(edge, job)
        case "wrong-key":
            return Outcome("wrong-key", "the door says the key is wrong; it keeps waiting")
        case "boot-mismatch":
            return Outcome("refused", "the box rebooted after the approval; ask again")
        case "not-waiting":
            return Outcome("failed", "the door says the root is not waiting for a key")
        case "bad-command":
            return Outcome("failed", "the door refused the unlock command")
        case "dropped":
            return _dropped(edge, job, was_online)


def _wait_for_node(edge: Edge, job: Job) -> Outcome:
    host = job.host
    if host.node is None:
        return Outcome("delivered", "the key is loaded")
    if _node_comes_online(edge, job):
        return Outcome("delivered", "the key is loaded and the box's own node is online")
    return Outcome(
        "delivered",
        "the key is loaded",
        (f"the box's own node was not online {host.settings.node_wait_seconds} s later",),
    )


def _node_comes_online(edge: Edge, job: Job) -> bool:
    deadline = edge.monotonic() + job.host.settings.node_wait_seconds
    while True:
        if presence(edge.view(), job.host.node) == "online":
            return True
        remaining = deadline - edge.monotonic()
        if remaining <= 0:
            return False
        edge.sleep(min(job.timing.poll_seconds, remaining))


def _dropped(edge: Edge, job: Job, was_online: bool) -> Outcome:
    """The session ended without the door's answer. The boot going on can cut it off just after
    the key loaded, so the box's own node coming online says it did; nothing is sent again."""
    warning = "the session ended before the door's answer"
    if job.host.node is not None and not was_online and _node_comes_online(edge, job):
        return Outcome("delivered", "the box's own node came online", (warning,))
    return Outcome("failed", f"{warning}; whether the key loaded is not known")


# --- audit --------------------------------------------------------------------------------------


def audit_line(job: Job, trace: Trace, outcome: Outcome, now: datetime) -> AuditLine:
    found, request = trace.found, trace.request
    door: AuditDoor | None = None
    if found is not None:
        door = {
            "role": found.role,
            "kind": found.target.kind,
            "address": found.target.name,
            "port": found.target.port,
            "host_key_sha256": pin_fingerprint(job.host.pins, found.role),
        }
    return {
        "schema": AUDIT_SCHEMA,
        "time": timestamp(now),
        "host": job.host.name,
        "result": outcome.result,
        "detail": outcome.detail,
        "warnings": list(outcome.warnings),
        "reason": job.reason,
        "request_id": None if request is None else request["request_id"],
        "door": door,
        "boot_id": None if found is None else found.status["boot_id"],
        "network": None if found is None else found.network,
        "decision": trace.decision,
    }


def run_delivery(edge: Edge, job: Job, record: Callable[[AuditLine, Outcome], None]) -> Outcome:
    """`deliver` with its one audit line, whatever happens on the way."""
    trace = Trace()
    try:
        outcome = deliver(edge, job, trace)
    except (ConfigError, ContractError, ToolError, OSError) as error:
        outcome = Outcome("failed", str(error))
    except BaseException as error:
        stopped = isinstance(error, SystemExit | KeyboardInterrupt)
        said = "stopped by a signal" if stopped else f"unexpected {type(error).__name__}"
        when = " while the key was being sent" if trace.key_handed_to_ssh else "; nothing was sent"
        outcome = Outcome("interrupted" if stopped else "failed", said + when)
        record(audit_line(job, trace, outcome, edge.now()), outcome)
        raise
    record(audit_line(job, trace, outcome, edge.now()), outcome)
    return outcome
