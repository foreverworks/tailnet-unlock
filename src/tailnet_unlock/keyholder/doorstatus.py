"""The door's `status` line (DESIGN.md section 7.3, step 4), narrowed from untrusted JSON.

Everything here is what the door says about itself: shown to a person, never evidence. The role a
keyholder acts on comes from the verified host key (pins.py), not from the `key` field.
"""

import json
import re
from typing import Literal, TypedDict

from tailnet_unlock.errors import ContractError
from tailnet_unlock.keyholder.keymaterial import KeyFormat, key_format

STATUS_SCHEMA = "tailnet-unlock.door-status/1"
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TOKEN = re.compile(r"[A-Za-z0-9 _.:/@+=?-]{0,255}")


class Restarts(TypedDict):
    dropbear: int
    tailscaled: int


class DoorStatus(TypedDict):
    schema: str
    key: Literal["sealed", "recovery"]
    boot_id: str
    profile: str
    seal: str
    degraded: list[str]
    backend: str
    waiting_for: str | None
    keyformat: KeyFormat | None
    kernel: str
    tailscaled: str | None
    restarts: Restarts


def _token(value: object, name: str, optional: bool) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ContractError(f"door status: {name} is not a short printable string")
    return value


def _required(value: object, name: str) -> str:
    token = _token(value, name, optional=False)
    if token is None:
        raise ContractError(f"door status: {name} is missing")
    return token


def _count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1_000_000:
        raise ContractError(f"door status: restarts.{name} is not a count")
    return value


def parse_door_status(line: bytes) -> DoorStatus:
    try:
        value: object = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("door status: not one JSON object") from error
    if not isinstance(value, dict):
        raise ContractError("door status: not one JSON object")
    if value.get("schema") != STATUS_SCHEMA:
        raise ContractError("door status: wrong schema")
    key: object = value.get("key")
    if key not in {"sealed", "recovery"}:
        raise ContractError("door status: key is neither sealed nor recovery")
    boot_id = _required(value.get("boot_id"), "boot_id")
    if not _BOOT_ID.fullmatch(boot_id):
        raise ContractError("door status: boot_id is not a boot id")
    degraded_value: object = value.get("degraded")
    if not isinstance(degraded_value, list):
        raise ContractError("door status: degraded is not a list")
    degraded = [_required(item, "degraded") for item in degraded_value]
    restarts_value: object = value.get("restarts")
    if not isinstance(restarts_value, dict):
        raise ContractError("door status: restarts is not an object")
    keyformat_value: object = value.get("keyformat")
    return {
        "schema": STATUS_SCHEMA,
        "key": "sealed" if key == "sealed" else "recovery",
        "boot_id": boot_id,
        "profile": _required(value.get("profile"), "profile"),
        "seal": _required(value.get("seal"), "seal"),
        "degraded": degraded,
        "backend": _required(value.get("backend"), "backend"),
        "waiting_for": _token(value.get("waiting_for"), "waiting_for", optional=True),
        "keyformat": None if keyformat_value is None else key_format(keyformat_value),
        "kernel": _required(value.get("kernel"), "kernel"),
        "tailscaled": _token(value.get("tailscaled"), "tailscaled", optional=True),
        "restarts": {
            "dropbear": _count(restarts_value.get("dropbear"), "dropbear"),
            "tailscaled": _count(restarts_value.get("tailscaled"), "tailscaled"),
        },
    }
