"""The approver contract (DESIGN.md 10.3; scenarios T24 and T25 at the unit level)."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from tailnet_unlock.keyholder.approval import (
    RESPONSE_SCHEMA,
    ApprovalRequest,
    Approved,
    BootInfo,
    NetworkInfo,
    Refused,
    build_request,
    judge_response,
    recovery_gate,
)
from tailnet_unlock.keyholder.pins import DoorRole

NOW = datetime(2026, 11, 21, 10, 2, 11, tzinfo=UTC)
REQUEST_ID = "0b9d1c6e7a2f4e1d9c3b5a7e8f60d4c2"
BOOT: BootInfo = {
    "boot_id": "6f1c2b3a-0d4e-4c5f-9a8b-7e6d5c4b3a21",
    "kernel": "6.12.117+deb13-amd64",
    "profile": "tpm",
    "seal": "ok",
    "degraded": [],
    "backend": "zfs",
    "waiting_for": "rpool",
    "keyformat": "passphrase",
    "tailscaled": "1.104.7",
}
NETWORK: NetworkInfo = {
    "path": "relayed",
    "observed_endpoint": None,
    "relay": "fra",
    "reported_endpoints": ["198.51.100.7:41641"],
    "expected": ["198.51.100.0/24"],
    "site_match": "unverified",
}


def request(role: DoorRole) -> ApprovalRequest:
    return build_request(
        request_id=REQUEST_ID,
        now=NOW,
        timeout=timedelta(minutes=15),
        host="web-1",
        reason={"kind": "unplanned", "started_by": None, "note": None},
        verified_role=role,
        door_kind="uplink",
        address="192.0.2.10",
        port=2222,
        host_key_sha256="SHA256:EXAMPLEONLY",
        boot=BOOT,
        network=NETWORK,
        history={"last_unlock_at": None},
    )


def response(**fields: object) -> bytes:
    body: dict[str, object] = {
        "schema": RESPONSE_SCHEMA,
        "request_id": REQUEST_ID,
        "decision": "approve",
        "by": "alice",
    }
    body.update(fields)
    return json.dumps(body).encode()


def test_request_role_comes_from_the_verified_key() -> None:
    assert request("recovery")["door"]["role"] == "recovery"
    assert request("sealed")["door"]["role"] == "sealed"
    assert request("sealed")["expires_at"] == "2026-11-21T10:17:11Z"


def test_a_valid_approval() -> None:
    judged = judge_response(request("sealed"), response(note="kernel update"), 0, NOW)
    assert judged == Approved(by="alice", note="kernel update")


def test_recovery_gate_runs_before_the_approver() -> None:
    assert recovery_gate("recovery", allow_recovery_delivery=False) is not None
    assert recovery_gate("recovery", allow_recovery_delivery=True) is None
    assert recovery_gate("sealed", allow_recovery_delivery=False) is None


def test_recovery_approval_needs_the_acknowledgement() -> None:
    """T24: without recovery_acknowledged: true nothing is sent, whatever the decision says."""
    for missing in (
        response(),
        response(recovery_acknowledged=False),
        response(recovery_acknowledged="true"),
        response(recovery_acknowledged=1),
    ):
        judged = judge_response(request("recovery"), missing, 0, NOW)
        assert isinstance(judged, Refused)
        assert "recovery_acknowledged" in judged.reason
    assert isinstance(
        judge_response(request("recovery"), response(recovery_acknowledged=True), 0, NOW), Approved
    )


@pytest.mark.parametrize(
    "stdout, code, when, reason",
    [
        (response(), None, NOW, "timed out"),
        (response(), 1, NOW, "exited 1"),
        (response(), 0, NOW + timedelta(minutes=16), "expires_at"),
        (b"", 0, NOW, "JSON"),
        (b"[1]", 0, NOW, "JSON"),
        (b"\xff", 0, NOW, "JSON"),
        (response(schema="x"), 0, NOW, "schema"),
        (response(request_id="f" * 32), 0, NOW, "different request"),
        (response(decision="refuse"), 0, NOW, "refused"),
        (response(decision="yes"), 0, NOW, "neither"),
        (response(by=""), 0, NOW, "who approved"),
        (response(by=None), 0, NOW, "who approved"),
        (b" " * 70000, 0, NOW, "64 KiB"),
    ],
)
def test_anything_else_is_a_refusal(
    stdout: bytes, code: int | None, when: datetime, reason: str
) -> None:
    judged = judge_response(request("sealed"), stdout, code, when)
    assert isinstance(judged, Refused)
    assert reason in judged.reason
