"""The approver contract (DESIGN.md section 10.3): the request, and judging the response.

Every rule the keyholder enforces is here as a pure function: the response must name the request,
arrive before `expires_at`, decide `approve`, and for the recovery door also carry
`"recovery_acknowledged": true`. The recovery gate runs before any approver is asked. The request's
`door.role` comes from the caller's verified role, never from the door's status.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, TypedDict

from tailnet_unlock.keyholder.pins import DoorRole

REQUEST_SCHEMA = "tailnet-unlock.approval-request/1"
RESPONSE_SCHEMA = "tailnet-unlock.approval-response/1"
_REQUEST_ID = re.compile(r"[0-9a-f]{32}")
MAX_RESPONSE_BYTES = 65536

type ReasonKind = Literal["planned", "unplanned", "manual"]
type DoorKind = Literal["tailnet", "uplink"]
type PathKind = Literal["direct", "relayed"]
type SiteMatch = Literal["yes", "no", "unverified"]


class Reason(TypedDict):
    kind: ReasonKind
    started_by: str | None
    note: str | None


class DoorInfo(TypedDict):
    role: DoorRole
    kind: DoorKind
    address: str
    port: int
    host_key_sha256: str


class BootInfo(TypedDict):
    boot_id: str
    kernel: str
    profile: str
    seal: str
    degraded: list[str]
    backend: str
    waiting_for: str | None
    keyformat: str | None
    tailscaled: str | None


class NetworkInfo(TypedDict):
    path: PathKind
    observed_endpoint: str | None
    relay: str | None
    reported_endpoints: list[str]
    expected: list[str]
    site_match: SiteMatch


class History(TypedDict):
    last_unlock_at: str | None


class ApprovalRequest(TypedDict):
    schema: str
    request_id: str
    created_at: str
    expires_at: str
    host: str
    reason: Reason
    door: DoorInfo
    boot: BootInfo
    network: NetworkInfo
    history: History


@dataclass(frozen=True)
class Approved:
    by: str
    note: str | None


@dataclass(frozen=True)
class Refused:
    reason: str


type Judgement = Approved | Refused


def timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def build_request(
    *,
    request_id: str,
    now: datetime,
    timeout: timedelta,
    host: str,
    reason: Reason,
    verified_role: DoorRole,
    door_kind: DoorKind,
    address: str,
    port: int,
    host_key_sha256: str,
    boot: BootInfo,
    network: NetworkInfo,
    history: History,
) -> ApprovalRequest:
    """The approval request. `verified_role` is the pin the SSH client verified (D31)."""
    if not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("request_id: 32 lowercase hex digits")
    return {
        "schema": REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": timestamp(now),
        "expires_at": timestamp(now + timeout),
        "host": host,
        "reason": reason,
        "door": {
            "role": verified_role,
            "kind": door_kind,
            "address": address,
            "port": port,
            "host_key_sha256": host_key_sha256,
        },
        "boot": boot,
        "network": network,
        "history": history,
    }


def recovery_gate(role: DoorRole, allow_recovery_delivery: bool) -> Refused | None:
    """Checked before the approver runs: automated delivery refuses the recovery door by default."""
    if role == "recovery" and not allow_recovery_delivery:
        return Refused("recovery door, manual only (allow_recovery_delivery is false)")
    return None


def judge_response(
    request: ApprovalRequest, stdout: bytes, exit_code: int | None, now: datetime
) -> Judgement:
    """Decide what an approver's run means. Anything but a valid approval is a refusal.

    `exit_code` is None when the approver was killed at the timeout.
    """
    if exit_code is None:
        return Refused("the approver timed out")
    if exit_code != 0:
        return Refused(f"the approver exited {exit_code}")
    if now > parse_timestamp(request["expires_at"]):
        return Refused("the response came after expires_at")
    if len(stdout) > MAX_RESPONSE_BYTES:
        return Refused("the approver printed more than 64 KiB")
    try:
        response: object = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return Refused("the approver's output is not one JSON object")
    if not isinstance(response, dict):
        return Refused("the approver's output is not one JSON object")
    if response.get("schema") != RESPONSE_SCHEMA:
        return Refused("the response has the wrong schema")
    if response.get("request_id") != request["request_id"]:
        return Refused("the response names a different request")
    decision: object = response.get("decision")
    if decision == "refuse":
        return Refused("the approver refused")
    if decision != "approve":
        return Refused("the response's decision is neither approve nor refuse")
    by: object = response.get("by")
    if not isinstance(by, str) or not by.strip():
        return Refused("an approval must say who approved (by)")
    if request["door"]["role"] == "recovery" and response.get("recovery_acknowledged") is not True:
        return Refused('an approval for the recovery door must carry "recovery_acknowledged": true')
    note: object = response.get("note")
    return Approved(by=by, note=note if isinstance(note, str) else None)
