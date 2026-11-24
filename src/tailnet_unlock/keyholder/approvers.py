"""The built-in approvers (DESIGN.md section 10.5): `deny`, and `tty` for a person at a terminal.

Both read one request on stdin and print one response, like any approver. There is deliberately
none that says yes on its own.
"""

import json
import os
import signal
import sys
from collections.abc import Callable

from tailnet_unlock.keyholder.approval import REQUEST_SCHEMA, RESPONSE_SCHEMA

MAX_REQUEST_BYTES = 65536


def read_request(raw: bytes) -> dict[str, object] | None:
    """The request, or None when stdin holds no approval request."""
    if len(raw) > MAX_REQUEST_BYTES:
        return None
    try:
        value: object = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None
    if not isinstance(value, dict) or value.get("schema") != REQUEST_SCHEMA:
        return None
    return {str(key): item for key, item in value.items()}


def response(request: dict[str, object], approve: bool, by: str, recovery: bool) -> str:
    fields: dict[str, object] = {
        "schema": RESPONSE_SCHEMA,
        "request_id": request.get("request_id"),
        "decision": "approve" if approve else "refuse",
        "by": by,
    }
    if approve and recovery:
        fields["recovery_acknowledged"] = True
    return json.dumps(fields)


def is_recovery(request: dict[str, object]) -> bool:
    """Anything but a plainly sealed door counts as recovery: it is asked about twice."""
    door = request.get("door")
    return not isinstance(door, dict) or door.get("role") != "sealed"


def shown(request: dict[str, object]) -> str:
    """The request for a person. json.dumps escapes what a terminal would act on."""
    heading = (
        "RECOVERY DOOR: its key is on /boot in plain text; a copy of /boot can present it.\n"
        if is_recovery(request)
        else ""
    )
    return f"{heading}{json.dumps(request, indent=2, ensure_ascii=True)}\n"


def ask(
    write: Callable[[str], None], read_line: Callable[[], str], request: dict[str, object]
) -> bool:
    """Show the request and have the host's name typed; a recovery door is asked about first."""
    write(shown(request))
    if is_recovery(request):
        write("Type RECOVERY to send the key to it, or no: ")
        if read_line().strip() != "RECOVERY":
            return False
    host = request.get("host")
    write("Type the host's name to approve, or no: ")
    return isinstance(host, str) and read_line().strip() == host


def _take_terminal(fd: int) -> int | None:
    """Make this process group the terminal's foreground one (an approver runs in a group of its
    own, and a background group may not read); returns the group to give it back to."""
    before = os.tcgetpgrp(fd)
    if before == os.getpgrp():
        return None
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    os.tcsetpgrp(fd, os.getpgrp())
    return before


def deny() -> int:
    request = read_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
    if request is None:
        return 2
    print(response(request, False, "deny", False))
    return 0


def tty() -> int:
    request = read_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
    if request is None:
        return 2
    with (
        open("/dev/tty", encoding="utf-8", errors="replace") as reader,
        open("/dev/tty", "w", encoding="utf-8") as writer,
    ):

        def write(text: str) -> None:
            writer.write(text)
            writer.flush()

        before = _take_terminal(reader.fileno())
        try:
            approved = ask(write, reader.readline, request)
        finally:
            if before is not None:
                os.tcsetpgrp(reader.fileno(), before)
    name = os.environ.get("SUDO_USER") or os.environ.get("USER") or f"uid {os.getuid()}"
    print(response(request, approved, f"{name}, at the terminal", is_recovery(request)))
    return 0
