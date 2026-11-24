"""The watcher (DESIGN.md section 10.7): which boxes wait at their door, and the alarm.

`situation` is the table, a pure function of what one pass saw. `remember_*` and `due_*` are pure
too: what to keep between passes, and whether to act now. `run_pass` puts the effects around them.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal, TypedDict

from tailnet_unlock.keyholder.approval import DoorKind, NetworkInfo, Reason, timestamp
from tailnet_unlock.keyholder.config import Argv, HostConfig
from tailnet_unlock.keyholder.deliver import door_targets
from tailnet_unlock.keyholder.door import Target
from tailnet_unlock.keyholder.peers import (
    Presence,
    View,
    find_peer,
    peer_name,
    presence,
    tailnet_network,
    uplink_network,
)
from tailnet_unlock.keyholder.pins import DoorRole
from tailnet_unlock.keyholder.run import Ran
from tailnet_unlock.keyholder.state import Memory, Planned

EVENT_SCHEMA = "tailnet-unlock.watch-event/1"

type Situation = Literal["nothing", "waiting", "both-online"]


@dataclass(frozen=True)
class Seen:
    """What one pass saw of one host. `own` and `unlock` are None when the host has no such node;
    `uplink` is the role of the door that answered there, None when none did."""

    own: Presence | None
    unlock: Presence | None
    uplink: DoorRole | None


class EventDoor(TypedDict):
    kind: DoorKind
    role: DoorRole | None
    address: str


class WatchEvent(TypedDict):
    schema: str
    kind: Literal["waiting", "alarm"]
    created_at: str
    host: str
    reason: Reason
    waiting_since: str | None
    alarm_since: str | None
    own_node: Presence | None
    unlock_node: Presence | None
    doors: list[EventDoor]
    network: NetworkInfo | None


# --- pure ---------------------------------------------------------------------------------------


def situation(seen: Seen) -> Situation:
    """The table of section 10.7. A host without its own node configured is judged by its door
    alone, and can raise no alarm. An uplink door that answers while the own node still reads as
    online is the moment before the control plane notices the reboot: the next pass sees it."""
    if seen.own == "online":
        return "both-online" if seen.unlock == "online" else "nothing"
    if seen.unlock == "online" or seen.uplink is not None:
        return "waiting"
    return "nothing"


def remember_waiting(memory: Memory, seen: Seen, now: datetime) -> Memory:
    """`waiting_since` starts with the first waiting pass and is cleared once no door answers and
    the own node is online again (a host without one: once no door answers)."""
    if situation(seen) == "waiting":
        return replace(memory, waiting_since=memory.waiting_since or now)
    door = seen.unlock == "online" or seen.uplink is not None
    if not door and seen.own != "offline":
        return replace(memory, waiting_since=None, delivery_started_at=None)
    return memory


def remember_alarm(memory: Memory, seen: Seen) -> Memory:
    """An alarm episode ends when the two nodes are no longer online together."""
    if situation(seen) == "both-online":
        return memory
    return replace(memory, alarm_since=None, alarm_told_at=None)


def due_delivery(memory: Memory, now: datetime, redeliver_minutes: int) -> bool:
    """Whether to start `deliver`: once per waiting episode, then again after the interval."""
    started = memory.delivery_started_at
    return started is None or now - started >= timedelta(minutes=redeliver_minutes)


def due_alarm(memory: Memory, now: datetime, repeat_hours: int) -> bool:
    """Whether to tell a confirmed alarm: once per episode, then at most every `repeat_hours`."""
    told = memory.alarm_told_at
    return told is None or now - told >= timedelta(hours=repeat_hours)


def reason_of(planned: Planned | None) -> Reason:
    if planned is None:
        return {"kind": "unplanned", "started_by": None, "note": None}
    return {"kind": "planned", "started_by": planned.by, "note": planned.note}


def event(
    kind: Literal["waiting", "alarm"],
    host: HostConfig,
    seen: Seen,
    view: View | None,
    memory: Memory,
    planned: Planned | None,
    now: datetime,
) -> WatchEvent:
    doors: list[EventDoor] = []
    network: NetworkInfo | None = None
    peer = None if view is None or host.unlock_node is None else find_peer(view, host.unlock_node)
    if seen.unlock == "online" and peer is not None:
        doors.append({"kind": "tailnet", "role": None, "address": peer_name(peer)})
        network = tailnet_network(host, peer)
    if seen.uplink is not None and host.uplink is not None:
        doors.append({"kind": "uplink", "role": seen.uplink, "address": host.uplink})
        network = network or uplink_network(host)

    def text(moment: datetime | None) -> str | None:
        return None if moment is None else timestamp(moment)

    return {
        "schema": EVENT_SCHEMA,
        "kind": kind,
        "created_at": timestamp(now),
        "host": host.name,
        "reason": reason_of(planned),
        "waiting_since": text(memory.waiting_since),
        "alarm_since": text(memory.alarm_since),
        "own_node": seen.own,
        "unlock_node": seen.unlock,
        "doors": doors,
        "network": network,
    }


def needs_view(hosts: tuple[HostConfig, ...]) -> bool:
    """Whether any host has a tailnet node to look up at all."""
    return any(host.node is not None or host.unlock_node is not None for host in hosts)


# --- one pass -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class WatchEdge:
    """Every effect a pass has. `view` raises ToolError when the tailnet cannot be read."""

    view: Callable[[], View]
    probe: Callable[[HostConfig, DoorRole, Target], bool]
    start_delivery: Callable[[HostConfig, Reason], None]
    delivering: Callable[[HostConfig], bool]
    run_hook: Callable[[Argv, bytes, float], Ran]
    read_memory: Callable[[HostConfig], Memory]
    write_memory: Callable[[HostConfig, Memory], None]
    read_planned: Callable[[HostConfig], Planned | None]
    now: Callable[[], datetime]
    sleep: Callable[[float], None]
    emit: Callable[[WatchEvent], None]
    say: Callable[[str], None]


def probe_uplink(edge: WatchEdge, host: HostConfig) -> DoorRole | None:
    """The role of the door at the uplink, proved by its host key: the sealed pin first."""
    for target in door_targets(host, None, "uplink"):
        roles: tuple[tuple[DoorRole, str | None], ...] = (
            ("sealed", host.pins.door_key),
            ("recovery", host.pins.recovery_key),
        )
        for role, pin in roles:
            if pin is not None and edge.probe(host, role, target):
                return role
    return None


def look(edge: WatchEdge, host: HostConfig, view: View | None, memory: Memory) -> Seen:
    """A box that is up and was not waiting is not probed: its door is closed."""
    own = presence(view, host.node)
    if view is not None and host.node is not None and find_peer(view, host.node) is None:
        edge.say(f"{host.name}: its own node is not among the peers (does the policy show it?)")
    probe = own != "online" or memory.waiting_since is not None
    return Seen(
        own=own,
        unlock=presence(view, host.unlock_node),
        uplink=probe_uplink(edge, host) if probe else None,
    )


def _hook(edge: WatchEdge, host: HostConfig, name: str, argv: Argv, what: WatchEvent) -> bool:
    ran = edge.run_hook(
        argv, json.dumps(what).encode("utf-8") + b"\n", host.settings.hook_timeout_seconds
    )
    if ran.exit_code == 0:
        return True
    how = "timed out" if ran.exit_code is None else f"exited {ran.exit_code}"
    edge.say(f"{host.name}: the {name} hook {how}")
    return False


def _waiting(
    edge: WatchEdge, host: HostConfig, seen: Seen, view: View | None, memory: Memory
) -> tuple[Memory, bool]:
    """Run `on_waiting`, or start a delivery; returns the memory to keep and whether it worked."""
    now = edge.now()
    planned = edge.read_planned(host)
    what = event("waiting", host, seen, view, memory, planned, now)
    edge.emit(what)
    if host.settings.on_waiting:
        return memory, _hook(edge, host, "on_waiting", host.settings.on_waiting, what)
    if edge.delivering(host):
        edge.say(f"{host.name}: a delivery is under way")
        return memory, True
    if not due_delivery(memory, now, host.settings.redeliver_minutes):
        edge.say(f"{host.name}: a delivery was tried; the next one waits for redeliver_minutes")
        return memory, True
    memory = replace(memory, delivery_started_at=now)
    edge.write_memory(host, memory)
    edge.start_delivery(host, reason_of(planned))
    return memory, True


def _alarm(
    edge: WatchEdge, host: HostConfig, seen: Seen, view: View | None, memory: Memory
) -> tuple[Memory, bool]:
    now = edge.now()
    memory = replace(memory, alarm_since=memory.alarm_since or now)
    if not due_alarm(memory, now, host.settings.alarm_repeat_hours):
        return memory, True
    what = event("alarm", host, seen, view, memory, edge.read_planned(host), now)
    edge.emit(what)
    edge.say(f"{host.name}: ALARM: the unlock node is online while the box runs")
    if host.settings.alarm and not _hook(edge, host, "alarm", host.settings.alarm, what):
        return memory, False  # not told: the next pass tries again
    return replace(memory, alarm_told_at=now), True


def run_pass(edge: WatchEdge, hosts: tuple[HostConfig, ...]) -> bool:
    """One pass over every host; False when a hook failed.

    The boxes that wait come first. A host with both nodes online, in no episode yet, is read once
    more after `alarm_after_seconds`; the second read is one for all of them.
    """
    view = edge.view() if needs_view(hosts) else None
    good = True
    suspects: list[HostConfig] = []
    for host in hosts:
        memory = edge.read_memory(host)
        seen = look(edge, host, view, memory)
        after = remember_alarm(remember_waiting(memory, seen, edge.now()), seen)
        match situation(seen):
            case "waiting":
                after, worked = _waiting(edge, host, seen, view, after)
                good = good and worked
            case "both-online" if after.alarm_since is None:
                suspects.append(host)
            case "both-online":
                after, worked = _alarm(edge, host, seen, view, after)
                good = good and worked
            case "nothing":
                pass
        if after != memory:
            edge.write_memory(host, after)
    if not suspects:
        return good
    edge.sleep(max(host.settings.alarm_after_seconds for host in suspects))
    again = edge.view()
    for host in suspects:
        # the uplink is not probed again: the alarm is about the two nodes
        seen = Seen(presence(again, host.node), presence(again, host.unlock_node), None)
        if situation(seen) == "both-online":
            memory, worked = _alarm(edge, host, seen, again, edge.read_memory(host))
            edge.write_memory(host, memory)
            good = good and worked
    return good
