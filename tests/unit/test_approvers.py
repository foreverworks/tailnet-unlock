"""The built-in approvers and the example one (DESIGN.md 10.5)."""

import http.server
import json
import os
import pty
import select
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from khkit import BOOT_A, REQUEST_ID, door_status, make_host, make_view
from shellenv import REPO
from tailnet_unlock.keyholder import approvers
from tailnet_unlock.keyholder.approval import (
    ApprovalRequest,
    Approved,
    build_request,
    judge_response,
)
from tailnet_unlock.keyholder.deliver import boot_info, door_targets, network_of
from tailnet_unlock.keyholder.pins import DoorRole

EXAMPLE = REPO / "examples" / "approver.py"


def make_request(role: DoorRole = "sealed", seconds: int = 900) -> ApprovalRequest:
    host = make_host()
    target = door_targets(host, make_view(), "any")[0]
    return build_request(
        request_id=REQUEST_ID,
        now=datetime.now(UTC),
        timeout=timedelta(seconds=seconds),
        host="web-1",
        reason={"kind": "manual", "started_by": "alice", "note": "\x1b[2J"},
        verified_role=role,
        door_kind="tailnet",
        address=target.name,
        port=2222,
        host_key_sha256="SHA256:EXAMPLEONLY",
        boot=boot_info(door_status()),
        network=network_of(host, target, make_view()),
        history={"last_unlock_at": None},
    )


def as_read(request: ApprovalRequest) -> dict[str, object]:
    read = approvers.read_request(json.dumps(request).encode())
    assert read is not None
    return read


def test_read_request_takes_a_request_only() -> None:
    assert approvers.read_request(b"") is None
    assert approvers.read_request(b"[]") is None
    assert approvers.read_request(b'{"schema": "other"}') is None
    assert approvers.read_request(b" " * 70000) is None


@pytest.mark.parametrize(
    ("role", "typed", "approved"),
    [
        ("sealed", ["web-1\n"], True),
        ("sealed", ["no\n"], False),
        ("sealed", ["web-2\n"], False),
        ("sealed", ["\n"], False),
        ("sealed", [""], False),
        ("recovery", ["RECOVERY\n", "web-1\n"], True),
        ("recovery", ["web-1\n", "web-1\n"], False),
        ("recovery", ["RECOVERY\n", "no\n"], False),
    ],
)
def test_ask(role: DoorRole, typed: list[str], approved: bool) -> None:
    shown: list[str] = []
    answers = iter(typed)
    request = as_read(make_request(role))
    assert approvers.ask(shown.append, lambda: next(answers), request) is approved
    text = "".join(shown)
    assert BOOT_A in text
    assert "\x1b" not in text, "a control character reached the terminal"
    assert ("RECOVERY DOOR" in text) is (role == "recovery")


def test_the_response_of_a_yes_is_an_approval() -> None:
    for role in ("sealed", "recovery"):
        request = make_request("sealed" if role == "sealed" else "recovery")
        text = approvers.response(as_read(request), True, "alice", role == "recovery")
        assert isinstance(judge_response(request, text.encode(), 0, datetime.now(UTC)), Approved)


ENV = {**os.environ, "PYTHONPATH": str(REPO / "src")}


def test_deny() -> None:
    done = subprocess.run(
        [sys.executable, "-m", "tailnet_unlock", "approver", "deny"],
        input=json.dumps(make_request()).encode(),
        capture_output=True,
        check=True,
        env=ENV,
    )
    assert json.loads(done.stdout)["decision"] == "refuse"
    assert json.loads(done.stdout)["request_id"] == REQUEST_ID


def test_tty_in_a_process_group_of_its_own() -> None:
    """As `deliver` runs it: the request on stdin, a background process group, and a person at the
    controlling terminal."""
    driver = (
        "import json, sys\n"
        "from tailnet_unlock.keyholder.run import run_bounded\n"
        "request = open(sys.argv[1], 'rb').read()\n"
        "ran = run_bounded((sys.executable, '-m', 'tailnet_unlock', 'approver', 'tty'), request,\n"
        "                  timeout=20, max_stdout=4096)\n"
        "print('CODE', ran.exit_code, ran.stdout.decode(), flush=True)\n"
        "print('NEXT', input(), flush=True)\n"  # the terminal is the parent's again
    )
    request = Path(os.environ.get("TMPDIR", "/tmp")) / f"tu-request-{os.getpid()}.json"
    request.write_text(json.dumps(make_request()))
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(ENV)
        os.execv(sys.executable, [sys.executable, "-c", driver, str(request)])  # noqa: S606  # the test's own driver
    text = b""
    sent = 0
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline and b"NEXT again" not in text:
            if select.select([fd], [], [], 0.2)[0]:
                try:
                    text += os.read(fd, 65536)
                except OSError:
                    break
            if sent == 0 and b"Type the host's name" in text:
                os.write(fd, b"web-1\n")
                sent = 1
            if sent == 1 and b"CODE" in text:
                os.write(fd, b"again\n")
                sent = 2
    finally:
        os.close(fd)
        os.waitpid(pid, 0)
        request.unlink()
    assert b"CODE 0" in text, text.decode(errors="replace")
    assert b'"approve"' in text
    assert b"NEXT again" in text


# --- the example approver -----------------------------------------------------------------------


class Service(http.server.BaseHTTPRequestHandler):
    """A stand-in approval service: POST asks, GET answers, DELETE takes the request back."""

    seen: list[tuple[str, str]] = []  # noqa: RUF012  # the fixture clears it
    answers: list[dict[str, object]] = []  # noqa: RUF012  # the fixture fills it

    def _reply(self, body: dict[str, object]) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["Content-Length"]))
        Service.seen.append(("POST", self.path))
        self._reply({})

    def do_GET(self) -> None:
        Service.seen.append(("GET", self.path))
        self._reply(Service.answers.pop(0) if Service.answers else {"decision": "pending"})

    def do_DELETE(self) -> None:
        Service.seen.append(("DELETE", self.path))
        self._reply({})

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@pytest.fixture
def service() -> Iterator[str]:
    Service.seen, Service.answers = [], []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/requests"
    server.shutdown()
    server.server_close()


def example(url: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-I", str(EXAMPLE), url, "0.1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )


def test_the_example_approver(service: str) -> None:
    Service.answers = [{"decision": "pending"}, {"decision": "approve", "by": "alice"}]
    request = make_request()
    out, _ = example(service).communicate(json.dumps(request).encode(), timeout=20)
    judged = judge_response(request, out, 0, datetime.now(UTC))
    assert judged == Approved("alice", None)
    path = f"/requests/{REQUEST_ID}"
    assert Service.seen == [("POST", "/requests"), ("GET", path), ("GET", path)]


def test_the_example_approver_refuses_on_anything_else(service: str) -> None:
    Service.answers = [{"decision": "maybe"}]
    process = example(service)
    out, _ = process.communicate(json.dumps(make_request()).encode(), timeout=20)
    assert (out, process.returncode) == (b"", 1)
    plain = example("http://approvals.example.com/requests")
    out, _ = plain.communicate(json.dumps(make_request()).encode(), timeout=20)
    assert (out, plain.returncode) == (b"", 1), "a service that is not https"


def test_the_example_approver_takes_its_request_back_when_stopped(service: str) -> None:
    process = example(service)
    assert process.stdin is not None
    process.stdin.write(json.dumps(make_request()).encode())
    process.stdin.close()
    deadline = time.monotonic() + 20
    while not any(verb == "GET" for verb, _ in Service.seen) and time.monotonic() < deadline:
        time.sleep(0.05)
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=20) != 0
    assert process.stdout is not None
    assert process.stdout.read() == b""
    process.stdout.close()
    assert Service.seen[-1] == ("DELETE", f"/requests/{REQUEST_ID}")
