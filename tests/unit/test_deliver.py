"""A delivery's decisions, step by step (DESIGN.md 10.2, 10.3; scenarios T3, T12, T24, T25 at the
unit level)."""

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta

import pytest

from keys import DOOR_PIN, RECOVERY_PIN
from khkit import (
    ALLOW_RECOVERY,
    BOOT_A,
    BOOT_B,
    DENIED,
    KEY,
    MISMATCH,
    REQUEST_ID,
    UNREACHABLE,
    World,
    door_status,
    make_edge,
    make_host,
    make_job,
    make_view,
    response,
)
from tailnet_unlock.errors import ConfigError, ToolError
from tailnet_unlock.keyholder.approval import ApprovalRequest
from tailnet_unlock.keyholder.config import HostConfig
from tailnet_unlock.keyholder.deliver import (
    EXIT_CODES,
    AuditLine,
    Job,
    Outcome,
    check_job,
    door_targets,
    run_delivery,
)
from tailnet_unlock.keyholder.door import DoorFailure, DoorRead, Target, UnlockOutcome
from tailnet_unlock.keyholder.pins import DoorRole
from tailnet_unlock.keyholder.run import Ran


def run(world: World, job: Job | None = None) -> tuple[Outcome, AuditLine]:
    lines: list[AuditLine] = []
    outcome = run_delivery(
        make_edge(world), job or make_job(make_host()), lambda line, _: lines.append(line)
    )
    assert len(lines) == 1, "one audit line per attempt"
    assert KEY.decode() not in json.dumps(lines)
    assert KEY.decode() not in " ".join(world.said)
    assert KEY.decode() not in json.dumps(world.requests)
    return outcome, lines[0]


def test_delivered() -> None:
    world = World(view=lambda t: make_view(own=t > 40))
    outcome, line = run(world)
    assert outcome.result == "delivered"
    assert outcome.warnings == ()
    assert world.sent == [("tailnet", "sealed", BOOT_A, KEY)]
    request = world.requests[0]
    assert request["door"]["role"] == "sealed"
    assert request["door"]["address"] == "web-1-unlock"
    assert request["network"]["observed_endpoint"] == "198.51.100.7:41641"
    assert request["network"]["site_match"] == "yes"
    assert request["boot"]["boot_id"] == BOOT_A
    assert line["result"] == "delivered"
    assert line["decision"] == {"approved": True, "by": "alice", "note": None}
    assert line["request_id"] == REQUEST_ID
    assert line["door"] == {
        "role": "sealed",
        "kind": "tailnet",
        "address": "web-1-unlock",
        "port": 2222,
        "host_key_sha256": request["door"]["host_key_sha256"],
    }
    assert request["door"]["host_key_sha256"].startswith("SHA256:")


def test_the_tailnet_door_first_then_the_uplink() -> None:
    host = make_host()
    online = door_targets(host, make_view(), "any")
    assert [target.kind for target in online] == ["tailnet", "uplink"]
    assert online[0].address == "192.0.2.102"
    assert [t.kind for t in door_targets(host, make_view(unlock=False), "any")] == ["uplink"]
    assert [t.kind for t in door_targets(host, None, "any")] == ["uplink"]
    assert [t.kind for t in door_targets(host, make_view(), "tailnet")] == ["tailnet"]
    assert [t.kind for t in door_targets(host, make_view(), "uplink")] == ["uplink"]


def test_the_uplink_door_without_a_readable_tailnet() -> None:
    outcome, line = run(World(view=lambda _: None))
    assert outcome.result == "delivered"
    assert outcome.warnings, "the box's own node cannot be seen"
    assert line["network"] is not None
    assert line["network"]["observed_endpoint"] == "192.0.2.10:2222"
    assert line["network"]["site_match"] == "no"


def test_a_node_that_does_not_come_online_is_a_warning() -> None:
    outcome, line = run(World())
    assert outcome.result == "delivered"
    assert line["warnings"] == ["the box's own node was not online 20 s later"]


def test_no_approver_means_refused_and_nothing_is_tried() -> None:
    world = World()
    host = make_host((('approver = ["approve"]', "approver = []"),))
    outcome, _ = run(world, make_job(host))
    assert (outcome.result, world.reads) == ("refused", [])


@pytest.mark.parametrize(
    ("approver", "result"),
    [
        (lambda r: Ran(0, response(r, decision="refuse"), b""), "refused"),
        (lambda r: Ran(None, response(r), b""), "approval-timeout"),
        (lambda r: Ran(1, response(r), b""), "refused"),
        (lambda r: Ran(-15, response(r), b""), "refused"),
        (lambda _: Ran(0, b"", b""), "refused"),
        (lambda _: Ran(0, b"approve\n", b""), "refused"),
        (lambda r: Ran(0, response(r) + response(r), b""), "refused"),
        (lambda r: Ran(0, response(r, request_id="1" * 32), b""), "refused"),
        (lambda r: Ran(0, response(r, schema="x"), b""), "refused"),
        (lambda r: Ran(0, response(r, by=""), b""), "refused"),
        (lambda r: Ran(0, response(r) + b" " * 70000, b""), "refused"),
    ],
)
def test_anything_but_an_approval_sends_nothing(
    approver: Callable[[ApprovalRequest], Ran], result: str
) -> None:
    world = World(approver=approver)
    outcome, line = run(world)
    assert outcome.result == result
    assert world.sent == []
    assert line["decision"] is not None
    assert line["decision"]["approved"] is False


def test_a_response_after_expires_at_is_refused() -> None:
    world = World()

    def late(request: ApprovalRequest) -> Ran:
        world.clock += timedelta(minutes=15).total_seconds()
        return Ran(0, response(request), b"")

    world.approver = late
    outcome, _ = run(world)
    assert (outcome.result, outcome.detail) == ("refused", "the response came after expires_at")
    assert world.sent == []


def test_the_boot_changed_between_the_approval_and_the_key() -> None:
    world = World()
    world.door = lambda *_: door_status(BOOT_B if world.requests else BOOT_A)
    outcome, _ = run(world)
    assert outcome.result == "refused"
    assert "rebooted" in outcome.detail
    assert world.sent == []


@pytest.mark.parametrize(
    "again",
    [
        MISMATCH,
        DENIED,
        DoorFailure("lied", "reports another key"),
        DoorFailure("bad-status", "not one JSON object"),
        UNREACHABLE,
        door_status(waiting_for="other"),
    ],
)
def test_another_door_after_the_approval_gets_nothing(again: DoorRead) -> None:
    world = World()
    world.door = lambda *_: again if world.requests else door_status()
    outcome, _ = run(world)
    assert outcome.result == ("failed" if again == UNREACHABLE else "refused")
    assert world.sent == []


def test_another_site_after_the_approval_gets_nothing() -> None:
    world = World()
    elsewhere = make_view(endpoint="203.0.113.9:41641")
    world.view = lambda _: elsewhere if world.requests else make_view()
    outcome, _ = run(world)
    assert (outcome.result, world.sent) == ("refused", [])
    assert "another site" in outcome.detail


def test_a_path_gone_idle_after_the_approval_is_no_other_site() -> None:
    world = World()
    world.view = lambda _: make_view(direct=False) if world.requests else make_view()
    outcome, _ = run(world)
    assert outcome.result == "delivered"


def test_a_short_outage_after_the_approval_is_ridden_out() -> None:
    world = World()
    outages = [UNREACHABLE, UNREACHABLE]
    world.door = lambda *_: outages.pop() if world.requests and outages else door_status()
    outcome, _ = run(world)
    assert outcome.result == "delivered"


@pytest.mark.parametrize(
    ("answer", "result", "exit_code"),
    [
        ("loaded", "delivered", 0),
        ("wrong-key", "wrong-key", 6),
        ("boot-mismatch", "refused", 3),
        ("not-waiting", "failed", 10),
        ("bad-command", "failed", 10),
        ("dropped", "failed", 10),
    ],
)
def test_the_doors_answers(answer: UnlockOutcome, result: str, exit_code: int) -> None:
    world = World(answer=answer)
    outcome, _ = run(world)
    assert (outcome.result, EXIT_CODES[outcome.result]) == (result, exit_code)
    assert len(world.sent) == 1, "the key is never sent again"


def test_a_dropped_session_is_a_delivery_when_the_boxs_node_comes_online() -> None:
    world = World(answer="dropped")
    world.view = lambda _: make_view(own=bool(world.sent))
    outcome, _ = run(world)
    assert (outcome.result, len(world.sent)) == ("delivered", 1)
    assert outcome.warnings
    # a node that already read as online proves nothing
    stale = World(answer="dropped", view=lambda _: make_view(own=True))
    outcome, _ = run(stale)
    assert (outcome.result, len(stale.sent)) == ("failed", 1)


@pytest.mark.parametrize("key", [b"", b"short", b"two\nlines of it", b"x" * 600])
def test_a_key_that_is_not_one_is_not_sent(key: bytes) -> None:
    world = World(key=key)
    outcome, _ = run(world)
    assert (outcome.result, world.sent) == ("failed", [])


def test_a_failing_key_source_sends_nothing() -> None:
    world = World()
    edge = make_edge(world)

    def broken() -> bytes:
        raise ToolError("the key source exited 1")

    outcome = run_delivery(replace(edge, key_source=broken), make_job(make_host()), lambda *_: None)
    assert (outcome.result, outcome.detail) == ("failed", "the key source exited 1")
    assert world.sent == []


# --- the wait for a door ------------------------------------------------------------------------


def test_no_door_within_the_wait() -> None:
    world = World(door=lambda *_: UNREACHABLE)
    outcome, line = run(world)
    assert outcome.result == "door-not-found"
    assert "uplink: no answer" in outcome.detail
    assert 60 <= world.clock < 75
    assert (line["door"], line["request_id"]) == (None, None)
    assert world.requests == []


def test_a_door_that_comes_up_later_is_found() -> None:
    world = World(door=lambda t, *_: door_status() if t > 30 else UNREACHABLE)
    outcome, _ = run(world)
    assert outcome.result == "delivered"


def test_a_door_whose_root_is_not_waiting_yet_is_not_asked_about() -> None:
    world = World(door=lambda t, *_: door_status(waiting_for="rpool" if t > 30 else None))
    outcome, _ = run(world)
    assert outcome.result == "delivered"
    assert len(world.requests) == 1
    never = World(door=lambda *_: door_status(waiting_for=None))
    outcome, _ = run(never)
    assert outcome.result == "door-not-found"
    assert "not waiting" in outcome.detail


def test_a_status_that_lies_about_its_key_ends_the_delivery() -> None:
    world = World(door=lambda *_: DoorFailure("lied", "door status reports key 'sealed'"))
    outcome, line = run(world)
    assert outcome.result == "refused"
    assert "reports key" in line["detail"]
    assert (world.requests, world.sent) == ([], [])


def test_not_needed_when_the_box_stays_up() -> None:
    host = make_host((("door_wait_minutes = 1", "door_wait_minutes = 30"),))
    world = World(view=lambda _: make_view(True, False), door=lambda *_: UNREACHABLE)
    outcome, _ = run(world, make_job(host, idle_minutes=2))
    assert (outcome.result, EXIT_CODES[outcome.result]) == ("not-needed", 7)
    assert 120 <= world.clock < 140
    assert world.requests == []


def test_idle_minutes_start_again_when_the_box_goes_down_or_a_door_answers() -> None:
    host = make_host((("door_wait_minutes = 1", "door_wait_minutes = 30"),))
    world = World(view=lambda t: make_view(not 100 < t < 110, False), door=lambda *_: UNREACHABLE)
    outcome, _ = run(world, make_job(host, idle_minutes=2))
    assert outcome.result == "not-needed"
    assert world.clock > 220
    answering = World(view=lambda _: make_view(True, False), door=lambda *_: DENIED)
    outcome, _ = run(answering, make_job(host, idle_minutes=2))
    assert outcome.result == "door-not-found"
    unreadable = World(view=lambda _: None, door=lambda *_: UNREACHABLE)
    outcome, _ = run(unreadable, make_job(host, idle_minutes=2))
    assert outcome.result == "door-not-found"


def test_without_idle_minutes_the_whole_wait_passes() -> None:
    world = World(view=lambda _: make_view(True, False), door=lambda *_: UNREACHABLE)
    outcome, _ = run(world)
    assert outcome.result == "door-not-found"


# --- the recovery door --------------------------------------------------------------------------


def recovery_world(**fields: object) -> World:
    def door(_: float, role: DoorRole, target: Target) -> DoorRead:
        del target
        return door_status(key="recovery") if role == "recovery" else MISMATCH

    world = World(view=lambda _: make_view(False, False), door=door, recovery_answers=True)
    for name, value in fields.items():
        setattr(world, name, value)
    return world


def test_the_recovery_door_is_refused_by_default_and_never_asked_about() -> None:
    host = make_host((("door_wait_minutes = 1", "door_wait_minutes = 30"),))
    world = recovery_world()
    outcome, _ = run(world, make_job(host))
    assert (outcome.result, EXIT_CODES[outcome.result]) == ("recovery-only", 8)
    assert (world.requests, world.sent) == ([], [])
    assert {role for _, role in world.reads} == {"sealed"}, "the recovery pin was used"
    assert 120 <= world.clock < 140, "the box's TPM gets its retries first"


def test_a_short_wait_still_names_the_recovery_door() -> None:
    outcome, _ = run(recovery_world())
    assert outcome.result == "recovery-only"


def test_a_server_with_neither_pin_is_not_a_door() -> None:
    outcome, _ = run(recovery_world(recovery_answers=False))
    assert outcome.result == "door-not-found"


def test_a_door_that_moves_to_the_sealed_key_is_delivered_to() -> None:
    def door(t: float, role: DoorRole, target: Target) -> DoorRead:
        del role, target
        return door_status() if t > 30 else MISMATCH

    outcome, _ = run(recovery_world(door=door))
    assert outcome.result == "delivered"


def test_a_recovery_delivery_needs_the_acknowledgement() -> None:
    host = make_host(ALLOW_RECOVERY)
    plain = recovery_world()
    outcome, line = run(plain, make_job(host))
    assert outcome.result == "refused"
    assert "recovery_acknowledged" in outcome.detail
    assert plain.sent == []
    assert plain.requests[0]["door"]["role"] == "recovery"
    assert line["door"] is not None
    assert line["door"]["role"] == "recovery"

    acknowledged = recovery_world(
        approver=lambda r: Ran(0, response(r, recovery_acknowledged=True), b"")
    )
    outcome, _ = run(acknowledged, make_job(host))
    assert outcome.result == "delivered"
    assert acknowledged.sent == [("uplink", "recovery", BOOT_A, KEY)]


def only_recovery(allow: bool) -> HostConfig:
    changes = (
        (f'door_key = "{DOOR_PIN}"\n', ""),
        ('unlock_node_id = "nUNLOCK1CNTRL"\n', ""),
        *(ALLOW_RECOVERY if allow else ()),
    )
    return make_host(changes)


def test_a_host_without_a_tpm_has_the_recovery_door_alone() -> None:
    host = only_recovery(True)
    assert host.pins.recovery_key == RECOVERY_PIN
    world = recovery_world(approver=lambda r: Ran(0, response(r, recovery_acknowledged=True), b""))
    outcome, _ = run(world, make_job(host))
    assert outcome.result == "delivered"
    assert {role for _, role in world.reads} == {"recovery"}
    refused = recovery_world()
    outcome, _ = run(refused, make_job(only_recovery(False)))
    assert (outcome.result, refused.reads) == ("recovery-only", [])


# --- the edges of a run -------------------------------------------------------------------------


@pytest.mark.parametrize("sending", [False, True])
def test_a_stop_is_audited_and_goes_on(sending: bool) -> None:
    world = World()
    edge = make_edge(world)

    def stop(*_: object) -> UnlockOutcome:
        raise SystemExit(143)

    def stop_asking(request: ApprovalRequest, timeout: float) -> Ran:
        del request, timeout
        raise SystemExit(143)

    edge = replace(edge, send_key=stop) if sending else replace(edge, approve=stop_asking)
    lines: list[AuditLine] = []
    with pytest.raises(SystemExit):
        run_delivery(edge, make_job(make_host()), lambda line, _: lines.append(line))
    assert [line["result"] for line in lines] == ["interrupted"]
    assert ("while the key was being sent" in lines[0]["detail"]) is sending
    assert ("nothing was sent" in lines[0]["detail"]) is not sending


def test_check_job() -> None:
    job = make_job(make_host())
    check_job(job, key_configured=True)
    with pytest.raises(ConfigError, match="key_command"):
        check_job(job, key_configured=False)
    no_key = make_host((('ssh_key = "/etc/tailnet-unlock/keyholder/id_ed25519"', ""),))
    with pytest.raises(ConfigError, match="ssh_key"):
        check_job(make_job(no_key), key_configured=True)
    no_node = make_host((('node = "web-1"', ""),))
    with pytest.raises(ConfigError, match="--idle-minutes"):
        check_job(make_job(no_node, idle_minutes=5), key_configured=True)
    no_uplink = make_host((('uplink = "192.0.2.10"', ""),))
    with pytest.raises(ConfigError, match="--door uplink"):
        check_job(replace(make_job(no_uplink), door="uplink"), key_configured=True)
    no_tailnet = make_host((('unlock_node_id = "nUNLOCK1CNTRL"', ""),))
    with pytest.raises(ConfigError, match="--door tailnet"):
        check_job(replace(make_job(no_tailnet), door="tailnet"), key_configured=True)


def test_every_result_has_its_own_exit_code() -> None:
    assert len(set(EXIT_CODES.values())) == len(EXIT_CODES)
    assert not {1, 2} & set(EXIT_CODES.values())
