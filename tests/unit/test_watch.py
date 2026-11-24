"""The watcher's table, its memory and its hooks (DESIGN.md 10.7; scenarios T2 and T13 at the unit
level)."""

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

import pytest

from khkit import NOW, make_host, make_view
from tailnet_unlock.errors import ConfigError, ToolError
from tailnet_unlock.keyholder.approval import Reason
from tailnet_unlock.keyholder.config import Argv, HostConfig
from tailnet_unlock.keyholder.door import Target
from tailnet_unlock.keyholder.peers import Presence, View
from tailnet_unlock.keyholder.pins import DoorRole
from tailnet_unlock.keyholder.run import Ran
from tailnet_unlock.keyholder.state import Memory, Planned
from tailnet_unlock.keyholder.watch import (
    Seen,
    Situation,
    WatchEdge,
    WatchEvent,
    remember_waiting,
    run_pass,
    situation,
)


@pytest.mark.parametrize(
    ("own", "unlock", "uplink", "expected"),
    [
        # section 10.7's table
        ("online", "offline", None, "nothing"),
        ("offline", "online", None, "waiting"),
        ("online", "online", None, "both-online"),
        ("offline", "offline", None, "nothing"),
        # the uplink door
        ("offline", "offline", "sealed", "waiting"),
        ("offline", "offline", "recovery", "waiting"),
        ("offline", "online", "sealed", "waiting"),
        ("online", "offline", "sealed", "nothing"),
        ("online", "online", "sealed", "both-online"),
        # no unlock node configured
        ("online", None, None, "nothing"),
        ("offline", None, None, "nothing"),
        ("offline", None, "sealed", "waiting"),
        # no own node configured: the door alone
        (None, None, None, "nothing"),
        (None, None, "sealed", "waiting"),
        (None, None, "recovery", "waiting"),
        (None, "online", None, "waiting"),
        (None, "offline", None, "nothing"),
    ],
)
def test_the_table(
    own: Presence | None, unlock: Presence | None, uplink: DoorRole | None, expected: Situation
) -> None:
    assert situation(Seen(own, unlock, uplink)) == expected


WAITING = Seen("offline", "online", None)
UP = Seen("online", "offline", None)
DARK = Seen("offline", "offline", None)


def test_waiting_since_is_kept_until_the_box_is_up_and_no_door_answers() -> None:
    later = NOW + timedelta(minutes=5)
    first = remember_waiting(Memory(), WAITING, NOW)
    assert first.waiting_since == NOW
    assert remember_waiting(first, WAITING, later).waiting_since == NOW
    assert remember_waiting(first, DARK, later).waiting_since == NOW, "between states"
    assert remember_waiting(first, Seen("online", "offline", "sealed"), later) == first
    assert remember_waiting(first, Seen("online", "online", None), later) == first
    assert remember_waiting(first, UP, later) == Memory()
    assert remember_waiting(first, Seen(None, None, None), later) == Memory()


@dataclass
class World:
    """What a pass meets, and what it did."""

    views: list[View | None] = field(default_factory=lambda: [make_view()])
    uplink: DoorRole | None = None
    hook: Ran = field(default_factory=lambda: Ran(0, b"", b""))
    delivering: bool = False
    planned: Planned | None = None
    memory: Memory = field(default_factory=Memory)
    now: datetime = NOW
    slept: list[float] = field(default_factory=list)
    probes: list[DoorRole] = field(default_factory=list)
    hooks: list[tuple[Argv, dict[str, object]]] = field(default_factory=list)
    started: list[Reason] = field(default_factory=list)
    emitted: list[WatchEvent] = field(default_factory=list)


def make_edge(world: World) -> WatchEdge:
    def view() -> View:
        found = world.views.pop(0) if len(world.views) > 1 else world.views[0]
        if found is None:
            raise ToolError("tailscale is not running")
        return found

    def probe(host: HostConfig, role: DoorRole, target: Target) -> bool:
        assert target.kind == "uplink"
        assert host.name == "web-1"
        world.probes.append(role)
        return role == world.uplink

    def run_hook(argv: Argv, stdin: bytes, timeout: float) -> Ran:
        assert timeout == 60
        parsed: object = json.loads(stdin)
        assert isinstance(parsed, dict)
        world.hooks.append((argv, {str(key): item for key, item in parsed.items()}))
        return world.hook

    def sleep(seconds: float) -> None:
        world.slept.append(seconds)
        world.now += timedelta(seconds=seconds)

    def write(_: HostConfig, memory: Memory) -> None:
        world.memory = memory

    return WatchEdge(
        view=view,
        probe=probe,
        start_delivery=lambda _, reason: world.started.append(reason),
        delivering=lambda _: world.delivering,
        run_hook=run_hook,
        read_memory=lambda _: world.memory,
        write_memory=write,
        read_planned=lambda _: world.planned,
        now=lambda: world.now,
        sleep=sleep,
        emit=world.emitted.append,
        say=lambda _: None,
    )


HOOKED = make_host((("[defaults]", '[defaults]\non_waiting = ["told"]\nalarm = ["alarmed"]'),))
PLAIN = make_host()


def watch(world: World, host: HostConfig, minutes: float = 0) -> bool:
    world.now += timedelta(minutes=minutes)
    return run_pass(make_edge(world), (host,))


# --- waiting ------------------------------------------------------------------------------------


def test_the_hook_runs_on_every_pass_with_the_same_waiting_since() -> None:
    world = World(uplink="sealed")
    assert watch(world, HOOKED)
    assert watch(world, HOOKED, minutes=5)
    assert world.started == [], "instead of deliver, not as well"
    assert [argv for argv, _ in world.hooks] == [("told",), ("told",)]
    first, second = (event for _, event in world.hooks)
    assert first["schema"] == "tailnet-unlock.watch-event/1"
    assert (first["kind"], first["host"]) == ("waiting", "web-1")
    assert first["waiting_since"] == second["waiting_since"] == "2026-11-24T10:00:00Z"
    assert second["created_at"] == "2026-11-24T10:05:00Z"
    assert first["reason"] == {"kind": "unplanned", "started_by": None, "note": None}
    assert first["doors"] == [
        {"kind": "tailnet", "role": None, "address": "web-1-unlock"},
        {"kind": "uplink", "role": "sealed", "address": "192.0.2.10"},
    ]
    assert (first["own_node"], first["unlock_node"]) == ("offline", "online")
    network = first["network"]
    assert isinstance(network, dict)
    assert network["observed_endpoint"] == "198.51.100.7:41641"
    assert set(first) == set(WatchEvent.__annotations__)


def test_a_failing_hook_fails_the_pass_and_runs_again() -> None:
    world = World(hook=Ran(1, b"", b""))
    assert not watch(world, HOOKED)
    world.hook = Ran(None, b"", b"")
    assert not watch(world, HOOKED, minutes=1)
    world.hook = Ran(0, b"", b"")
    assert watch(world, HOOKED, minutes=1)
    assert len(world.hooks) == 3


def test_the_episode_ends_when_the_box_is_up() -> None:
    world = World()
    watch(world, HOOKED)
    world.views = [make_view(True, False)]
    watch(world, HOOKED, minutes=1)
    assert world.memory == Memory()
    assert len(world.hooks) == 1
    assert world.probes[-1] == "recovery", "the uplink was checked before the episode ended"
    world.probes.clear()
    watch(world, HOOKED, minutes=1)
    assert world.probes == [], "a box that is up is not probed"


def test_a_planned_reboot_says_so() -> None:
    world = World(planned=Planned("bob", "kernel", NOW + timedelta(minutes=30)))
    watch(world, HOOKED)
    planned = {"kind": "planned", "started_by": "bob", "note": "kernel"}
    assert world.hooks[0][1]["reason"] == planned
    watch(world, PLAIN, minutes=1)
    assert world.started == [planned]


def test_without_a_hook_a_delivery_starts_once_and_again_after_the_interval() -> None:
    world = World()
    watch(world, PLAIN)
    watch(world, PLAIN, minutes=1)
    assert len(world.started) == 1, "a refused delivery is not asked about every minute"
    watch(world, PLAIN, minutes=30)
    assert len(world.started) == 2
    world.delivering = True
    watch(world, PLAIN, minutes=60)
    assert len(world.started) == 2, "one at a time"
    world.delivering = False
    world.views = [make_view(True, False)]
    watch(world, PLAIN, minutes=1)
    world.views = [make_view()]
    watch(world, PLAIN, minutes=1)
    assert len(world.started) == 3, "the next reboot starts at once"


def test_an_uplink_only_host_needs_no_tailnet() -> None:
    host = make_host(
        (
            ('unlock_node_id = "nUNLOCK1CNTRL"', ""),
            ('node = "web-1"', 'on_waiting = ["told"]'),
        )
    )
    world = World(views=[None], uplink="recovery")
    assert watch(world, host)
    event = world.hooks[0][1]
    assert event["doors"] == [{"kind": "uplink", "role": "recovery", "address": "192.0.2.10"}]
    assert (event["own_node"], event["unlock_node"]) == (None, None)
    world.uplink = None
    watch(world, host, minutes=5)
    assert (len(world.hooks), world.memory) == (1, Memory())


def test_a_tailnet_that_cannot_be_read_decides_nothing() -> None:
    world = World(views=[None], uplink="sealed")
    with pytest.raises(ToolError):
        watch(world, HOOKED)
    assert (world.hooks, world.started, world.emitted, world.probes) == ([], [], [], [])


# --- the alarm ----------------------------------------------------------------------------------

BOTH = make_view(True, True)
NORMAL = make_view(True, False)


def test_an_alarm_is_told_after_the_second_read() -> None:
    world = World(views=[BOTH])
    assert watch(world, HOOKED)
    assert world.slept == [60]
    ((argv, event),) = world.hooks
    assert argv == ("alarmed",)
    assert (event["kind"], event["host"]) == ("alarm", "web-1")
    assert event["alarm_since"] == "2026-11-24T10:01:00Z"
    assert (event["own_node"], event["unlock_node"]) == ("online", "online")
    assert world.started == []


def test_a_node_gone_at_the_second_read_is_no_alarm() -> None:
    world = World(views=[BOTH, NORMAL])
    assert watch(world, HOOKED)
    assert (world.slept, world.hooks, world.memory) == ([60], [], Memory())


def test_an_alarm_is_told_once_an_episode_then_daily() -> None:
    world = World(views=[BOTH])
    watch(world, HOOKED)
    for _ in range(5):
        watch(world, HOOKED, minutes=10)
    assert (len(world.hooks), world.slept) == (1, [60]), "no second read inside an episode"
    watch(world, HOOKED, minutes=24 * 60)
    assert len(world.hooks) == 2
    assert world.hooks[0][1]["alarm_since"] == world.hooks[1][1]["alarm_since"]
    world.views = [NORMAL]
    watch(world, HOOKED, minutes=10)
    assert world.memory == Memory()
    world.views = [BOTH]
    watch(world, HOOKED, minutes=10)
    assert len(world.hooks) == 3, "a new episode is told at once"


def test_an_alarm_nobody_was_told_is_tried_again() -> None:
    world = World(views=[BOTH], hook=Ran(1, b"", b""))
    assert not watch(world, HOOKED)
    world.hook = Ran(0, b"", b"")
    assert watch(world, HOOKED, minutes=10)
    assert watch(world, HOOKED, minutes=10)
    assert len(world.hooks) == 2


def test_an_alarm_without_a_hook_is_still_printed() -> None:
    world = World(views=[BOTH])
    assert watch(world, PLAIN)
    assert [event["kind"] for event in world.emitted] == ["alarm"]


def test_one_second_read_for_every_suspect() -> None:
    world = World(views=[BOTH])
    run_pass(make_edge(world), (PLAIN, HOOKED))
    assert world.slept == [60]


def test_a_host_that_cannot_be_decided_stops_no_other() -> None:
    world = World()

    def read(host: HostConfig) -> Memory:
        if host is PLAIN:
            raise ConfigError("a corrupt state file")
        return world.memory

    said: list[str] = []
    edge = replace(make_edge(world), read_memory=read, say=said.append)
    assert not run_pass(edge, (PLAIN, HOOKED))
    assert [argv for argv, _ in world.hooks] == [("told",)]
    assert said == ["web-1: this pass decided nothing more: a corrupt state file"]


def test_a_failed_second_read_decides_nothing() -> None:
    world = World(views=[BOTH, None])
    with pytest.raises(ToolError):
        watch(world, HOOKED)
    assert (world.hooks, world.memory) == ([], Memory())
