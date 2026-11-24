"""Pieces for the keyholder's tests: a configuration, a fake tailnet status, and a delivery's edge
made of scripted answers, with a clock the test drives."""

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from keys import DOOR_PIN, RECOVERY_PIN
from tailnet_unlock.keyholder.approval import RESPONSE_SCHEMA, ApprovalRequest
from tailnet_unlock.keyholder.config import HostConfig, host_config, parse_keyholder_config
from tailnet_unlock.keyholder.deliver import Edge, Job, Timing, default_roles
from tailnet_unlock.keyholder.door import DoorFailure, DoorRead, Target, UnlockOutcome
from tailnet_unlock.keyholder.doorstatus import DoorStatus
from tailnet_unlock.keyholder.peers import View, parse_view
from tailnet_unlock.keyholder.pins import DoorRole
from tailnet_unlock.keyholder.run import Ran

NOW = datetime(2026, 11, 24, 10, 0, 0, tzinfo=UTC)
BOOT_A = "6f1c2b3a-0d4e-4c5f-9a8b-7e6d5c4b3a21"
BOOT_B = "00000000-0d4e-4c5f-9a8b-7e6d5c4b3a21"
KEY = b"correct horse battery"
REQUEST_ID = "0b9d1c6e7a2f4e1d9c3b5a7e8f60d4c2"

CONFIG = f"""
[defaults]
ssh_key = "/etc/tailnet-unlock/keyholder/id_ed25519"
approver = ["approve"]
door_wait_minutes = 1
node_wait_seconds = 20

[hosts.web-1]
node = "web-1"
key_command = ["pass", "show", "unlock/web-1"]
expected_endpoints = ["198.51.100.0/24"]

[hosts.web-1.door]
port = 2222
door_key = "{DOOR_PIN}"
recovery_key = "{RECOVERY_PIN}"
unlock_node_id = "nUNLOCK1CNTRL"
uplink = "192.0.2.10"
"""


def make_host(replace: tuple[tuple[str, str], ...] = ()) -> HostConfig:
    text = CONFIG
    for old, new in replace:
        assert old in text, old
        text = text.replace(old, new)
    return host_config(parse_keyholder_config(text), "web-1")


ALLOW_RECOVERY = (("approver = [", "allow_recovery_delivery = true\napprover = ["),)


def status_json(
    own: bool | None = False,
    unlock: bool | None = True,
    direct: bool = True,
    backend: str = "Running",
) -> str:
    """`tailscale status --json` with the box's own and unlock nodes; None leaves one out."""
    peers: dict[str, object] = {}
    if own is not None:
        peers["nodekey:own"] = {
            "ID": "nOWN1CNTRL",
            "HostName": "web-1",
            "DNSName": "web-1.tailnet.example.",
            "TailscaleIPs": ["192.0.2.101"],
            "Online": own,
        }
    if unlock is not None:
        peers["nodekey:unlock"] = {
            "ID": "nUNLOCK1CNTRL",
            "HostName": "web-1-unlock",
            "DNSName": "web-1-unlock.tailnet.example.",
            "TailscaleIPs": ["2001:db8::102", "192.0.2.102"],
            "Online": unlock,
            "CurAddr": "198.51.100.7:41641" if direct else "",
            "Relay": "fra",
            "Addrs": ["198.51.100.7:41641", "192.0.2.10:41641"],
        }
    return json.dumps({"BackendState": backend, "Self": {"ID": "nME"}, "Peer": peers})


def make_view(own: bool | None = False, unlock: bool | None = True, direct: bool = True) -> View:
    return parse_view(status_json(own, unlock, direct))


def door_status(
    boot_id: str = BOOT_A, key: DoorRole = "sealed", waiting_for: str | None = "rpool"
) -> DoorStatus:
    return {
        "schema": "tailnet-unlock.door-status/1",
        "key": key,
        "boot_id": boot_id,
        "profile": "tpm",
        "seal": "ok",
        "degraded": [],
        "backend": "zfs",
        "waiting_for": waiting_for,
        "keyformat": "passphrase" if waiting_for else None,
        "kernel": "6.12.117+deb13-amd64",
        "tailscaled": "1.104.7",
        "restarts": {"dropbear": 0, "tailscaled": 0},
    }


def response(request: ApprovalRequest, **fields: object) -> bytes:
    body: dict[str, object] = {
        "schema": RESPONSE_SCHEMA,
        "request_id": request["request_id"],
        "decision": "approve",
        "by": "alice",
    }
    body.update(fields)
    return json.dumps(body).encode()


UNREACHABLE = DoorFailure("unreachable", "no answer")
MISMATCH = DoorFailure("host-key-mismatch", "not the pinned sealed key")
DENIED = DoorFailure("auth-refused", "the door refuses the keyholder's SSH key")


@dataclass
class World:
    """What the box, the approver and the clock do, and what the delivery did to them."""

    view: Callable[[float], View | None] = lambda _: make_view()
    door: Callable[[float, DoorRole, Target], DoorRead] = lambda *_: door_status()
    recovery_answers: bool = False
    approver: Callable[[ApprovalRequest], Ran] = lambda request: Ran(0, response(request), b"")
    answer: UnlockOutcome = "loaded"
    key: bytes = KEY
    clock: float = 0.0
    reads: list[tuple[str, DoorRole]] = field(default_factory=list)
    requests: list[ApprovalRequest] = field(default_factory=list)
    sent: list[tuple[str, DoorRole, str, bytes]] = field(default_factory=list)
    said: list[str] = field(default_factory=list)


def make_edge(world: World) -> Edge:
    def sleep(seconds: float) -> None:
        assert seconds >= 0
        world.clock += max(seconds, 0.001)

    def read_door(role: DoorRole, target: Target) -> DoorRead:
        world.reads.append((target.kind, role))
        world.clock += 0.1
        return world.door(world.clock, role, target)

    def approve(request: ApprovalRequest, timeout: float) -> Ran:
        assert timeout > 0
        world.requests.append(request)
        world.clock += 30
        return world.approver(request)

    def send_key(role: DoorRole, target: Target, boot_id: str, key: bytes) -> UnlockOutcome:
        world.sent.append((target.kind, role, boot_id, key))
        return world.answer

    return Edge(
        view=lambda: world.view(world.clock),
        read_door=read_door,
        recovery_answers=lambda _: world.recovery_answers,
        approve=approve,
        key_source=lambda: world.key,
        send_key=send_key,
        new_request_id=lambda: REQUEST_ID,
        now=lambda: NOW + timedelta(seconds=world.clock),
        monotonic=lambda: world.clock,
        sleep=sleep,
        say=world.said.append,
    )


def make_job(host: HostConfig, idle_minutes: int | None = None) -> Job:
    return Job(
        host=host,
        reason={"kind": "unplanned", "started_by": None, "note": None},
        door="any",
        idle_minutes=idle_minutes,
        last_unlock_at=None,
        roles=default_roles(host),
        timing=Timing(),
    )
