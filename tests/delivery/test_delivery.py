"""Deliveries end to end: the real commands, OpenSSH's client, dropbear and the door's own script.

The door is the repository's, over a sandbox with a fake `zfs` (tests/shellenv.py), behind a real
dropbear that answers on two loopback addresses: 127.0.0.1 is the uplink and 127.0.0.2 the unlock
node's tailnet address, which a fake `tailscale` reports. Covers, at the process level, T2, T3, T12,
T14, T24 and T25, the watcher's probe, and what a stop leaves behind.

It writes /root/.ssh/authorized_keys, so it runs only inside the test container
(TU_TEST_CONTAINER=1, as the Makefile sets it).
"""

import json
import os
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from keys import DOOR, DOOR_PIN, RECOVERY, RECOVERY_PIN, dropbear_ed25519
from khkit import status_json
from shellenv import BOOT_ID, REPO, Sandbox, make_sandbox, set_dataset, wait_for_root
from tailnet_unlock.keyholder.door import Target, door_answers, read_door
from tailnet_unlock.keyholder.pins import DoorRole, door_pins

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(
        os.environ.get("TU_TEST_CONTAINER") != "1" or os.getuid() != 0,
        reason="writes /root/.ssh: test container only",
    ),
    pytest.mark.skipif(shutil.which("dropbear") is None, reason="needs dropbear"),
]

KEY = b"a-root-key-that-must-never-be-seen"
OTHER_BOOT = "11111111-2222-4333-8444-555555555555"

# Approvers record what they were given, then do what their name says. One JSON request on stdin.
APPROVER = r"""#!/usr/bin/python3 -I
import json, os, signal, sys, time
here = os.path.dirname(os.path.abspath(sys.argv[0]))
mode = sys.argv[1]
raw = sys.stdin.read()
request = json.loads(raw)
with open(here + "/approver.log", "a") as log:
    log.write(json.dumps({"argv": sys.argv, "env": dict(os.environ), "request": request}) + "\n")
answer = {"schema": "tailnet-unlock.approval-response/1", "request_id": request["request_id"],
          "decision": "approve", "by": "alice"}
if mode == "acknowledge":
    answer["recovery_acknowledged"] = True
elif mode == "refuse":
    answer["decision"] = "refuse"
elif mode == "malformed":
    print("{approve")
    sys.exit(0)
elif mode == "wrong-id":
    answer["request_id"] = "0" * 32
elif mode == "fails":
    print(json.dumps(answer))
    sys.exit(1)
elif mode == "hang":
    def stop(*_):
        time.sleep(0.5)
        open(here + "/cancelled", "w").write(request["request_id"])
        sys.exit(1)
    signal.signal(signal.SIGTERM, stop)
    open(here + "/asking", "w").write(str(os.getpid()))
    time.sleep(120)
elif mode == "reboot":
    open(sys.argv[2], "w").write(sys.argv[3] + "\n")
elif mode == "kill":
    os.kill(int(sys.argv[2]), signal.SIGTERM)
    time.sleep(0.5)
print(json.dumps(answer))
"""

# ssh as it is, after a note of its command line and environment
SSH = r"""#!/usr/bin/python3 -I
import json, os, sys
with open(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "ssh.log"), "a") as log:
    log.write(json.dumps({"argv": sys.argv, "env": dict(os.environ)}) + "\n")
os.execv("/usr/bin/ssh", ["ssh", *sys.argv[1:]])
"""


@dataclass(frozen=True)
class Place:
    root: Path
    bin: Path
    state: Path
    config: Path
    box: Sandbox
    port: int

    @property
    def door_log(self) -> Path:
        return self.box.zfs_state / "received"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_listening(address: str, port: int, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection((address, port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"nothing listens on {address}:{port}")


def program(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


def see(place: Place, own: bool | None = False, unlock: bool | None = False) -> None:
    """What the fake `tailscale status --json` prints; the unlock node's address is 127.0.0.2."""
    text = status_json(own, unlock).replace("192.0.2.102", "127.0.0.2")
    (place.bin / "status.json").write_text(text)


def write_config(place: Place, approver: list[str], defaults: str = "", host: str = "") -> None:
    program(place.bin / "key-source", f"#!/bin/sh\ncat '{place.root}/root-key'\n")
    place.config.write_text(f"""
[defaults]
ssh_key = "{place.root}/client"
approver = {json.dumps([str(place.bin / "approver"), *approver] if approver else [])}
approval_timeout_seconds = 20
door_wait_minutes = 0
node_wait_seconds = 0
tailscale = ["{place.bin}/tailscale"]
{defaults}

[hosts.web-1]
node = "web-1"
key_command = ["{place.bin}/key-source"]
expected_endpoints = ["127.0.0.0/8"]
{host}

[hosts.web-1.door]
port = {place.port}
door_key = "{DOOR_PIN}"
recovery_key = "{RECOVERY_PIN}"
unlock_node_id = "nUNLOCK1CNTRL"
uplink = "127.0.0.1"
""")


def environment(place: Place) -> dict[str, str]:
    return {
        "PATH": f"{place.bin}:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LC_ALL": "C.UTF-8",
        "PYTHONPATH": str(REPO / "src"),
    }


def command(place: Place, name: str, *args: str) -> list[str]:
    places = ["--config", str(place.config), "--state-dir", str(place.state)]
    return [sys.executable, "-m", "tailnet_unlock", name, *args, *places]


@dataclass(frozen=True)
class Done:
    code: int
    lines: list[dict[str, object]]
    stderr: str


def finished(code: int, stdout: str, stderr: str) -> Done:
    lines: list[dict[str, object]] = []
    for line in stdout.splitlines():
        parsed: object = json.loads(line)
        assert isinstance(parsed, dict)
        lines.append({str(key): value for key, value in parsed.items()})
    return Done(code, lines, stderr)


def run(place: Place, name: str, *args: str) -> Done:
    with (place.root / "output.log").open("a") as log:
        done = subprocess.run(
            command(place, name, *args),
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
            env=environment(place),
            stdin=subprocess.DEVNULL,
        )
        log.write(done.stdout + done.stderr)
    return finished(done.returncode, done.stdout, done.stderr)


def deliver(place: Place, *args: str) -> Done:
    return run(place, "deliver", "web-1", "--reason", "unplanned", *args)


def requests(place: Place) -> list[dict[str, object]]:
    log = place.bin / "approver.log"
    found: list[dict[str, object]] = []
    for line in log.read_text().splitlines() if log.exists() else []:
        request: object = json.loads(line)["request"]
        assert isinstance(request, dict)
        found.append({str(key): value for key, value in request.items()})
    return found


def loaded(place: Place) -> bool:
    return (place.box.zfs_state / "keystatus").read_text().strip() == "available"


def nothing_sent(place: Place) -> bool:
    return not place.door_log.exists() and not loaded(place)


def serve(place: Place, host_key: bytes, role: DoorRole) -> subprocess.Popen[bytes]:
    """dropbear as the supervisor starts it, with this host key."""
    key_file = place.box.root / f"host_key.{role}"
    key_file.write_bytes(host_key)
    key_file.chmod(0o600)
    (place.box.run / "role").write_text(role + "\n")
    (place.box.run / "seal").write_text("ok\n" if role == "sealed" else "unseal-failed\n")
    process = subprocess.Popen(
        ["dropbear", "-F", "-E", "-r", str(key_file), "-s", "-j", "-k", "-I", "60"]
        + [item for at in ("127.0.0.1", "127.0.0.2") for item in ("-p", f"{at}:{place.port}")],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=(place.root / "dropbear.log").open("ab"),
    )
    for at in ("127.0.0.1", "127.0.0.2"):
        wait_listening(at, place.port)
    return process


def stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    process.wait(timeout=20)


@pytest.fixture
def place(tmp_path: Path) -> Iterator[Place]:
    box = make_sandbox(tmp_path / "box")
    set_dataset(box, "rpool", "passphrase", KEY)
    wait_for_root(box, "rpool", "passphrase")
    made = Place(
        root=tmp_path,
        bin=tmp_path / "bin",
        state=tmp_path / "state",
        config=tmp_path / "keyholder.toml",
        box=box,
        port=free_port(),
    )
    made.bin.mkdir()
    program(made.bin / "approver", APPROVER)
    program(made.bin / "ssh", SSH)
    program(made.bin / "tailscale", f"#!/bin/sh\ncat '{made.bin}/status.json'\n")
    (tmp_path / "root-key").write_bytes(KEY + b"\n")
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "client")], check=True
    )
    ssh_dir = Path("/root/.ssh")
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    authorized = ssh_dir / "authorized_keys"
    public = (tmp_path / "client.pub").read_text()
    authorized.write_text(f'restrict,command="{box.lib}/door delivery" {public}')
    authorized.chmod(0o600)
    see(made)
    yield made
    authorized.unlink(missing_ok=True)
    # T14: the key is in its own file and in the fake pool, and nowhere else this test wrote
    secret_places = {tmp_path / "root-key", box.zfs_state / "key", made.door_log}
    for path in tmp_path.rglob("*"):
        if path.is_file() and path not in secret_places:
            assert KEY not in path.read_bytes(), f"the root key is in {path}"


@pytest.fixture
def sealed(place: Place) -> Iterator[Place]:
    process = serve(place, DOOR, "sealed")
    yield place
    stop(process)


@pytest.fixture
def recovery(place: Place) -> Iterator[Place]:
    process = serve(place, RECOVERY, "recovery")
    yield place
    stop(process)


# --- approve, refuse, and everything in between -------------------------------------------------


def test_delivered_over_the_tailnet_door(sealed: Place) -> None:
    write_config(sealed, ["approve"])
    see(sealed, own=False, unlock=True)
    done = deliver(sealed, "--by", "bob", "--note", "after the power cut")
    assert done.code == 0, done.stderr
    assert loaded(sealed)
    assert sealed.door_log.read_bytes() == KEY, "no framing, no newline"
    (line,) = done.lines
    assert line["schema"] == "tailnet-unlock.audit/1"
    assert (line["result"], line["host"], line["boot_id"]) == ("delivered", "web-1", BOOT_ID)
    assert line["reason"] == {
        "kind": "unplanned",
        "started_by": "bob",
        "note": "after the power cut",
    }
    assert line["decision"] == {"approved": True, "by": "alice", "note": None}
    door = line["door"]
    assert isinstance(door, dict)
    assert (door["kind"], door["role"], door["address"]) == ("tailnet", "sealed", "web-1-unlock")
    assert json.loads((sealed.state / "audit.jsonl").read_text()) == line
    (request,) = requests(sealed)
    assert request["schema"] == "tailnet-unlock.approval-request/1"
    assert request["request_id"] == line["request_id"]
    assert request["history"] == {"last_unlock_at": None}
    assert (sealed.state / "history" / "web-1.json").exists()
    ssh_log = [
        json.loads(item)["argv"] for item in (sealed.bin / "ssh.log").read_text().splitlines()
    ]
    assert [argv[-1].split()[0] for argv in ssh_log] == ["status", "status", "unlock"]
    assert all(argv[-2] == "127.0.0.2" for argv in ssh_log)


def test_delivered_over_the_uplink_door(sealed: Place) -> None:
    write_config(sealed, ["approve"])
    see(sealed, own=False, unlock=True)
    done = deliver(sealed, "--door", "uplink")
    assert done.code == 0, done.stderr
    (request,) = requests(sealed)
    network = request["network"]
    assert isinstance(network, dict)
    assert network["observed_endpoint"] == f"127.0.0.1:{sealed.port}"
    assert network["site_match"] == "yes"


def test_the_uplink_door_when_the_tailnet_cannot_be_read(sealed: Place) -> None:
    write_config(sealed, ["approve"])
    program(sealed.bin / "tailscale", "#!/bin/sh\nexit 1\n")
    done = deliver(sealed)
    assert done.code == 0, done.stderr
    assert loaded(sealed)


@pytest.mark.parametrize(
    ("mode", "code", "result"),
    [
        ("refuse", 3, "refused"),
        ("malformed", 3, "refused"),
        ("wrong-id", 3, "refused"),
        ("fails", 3, "refused"),
        ("hang", 4, "approval-timeout"),
    ],
)
def test_no_approval_sends_nothing(sealed: Place, mode: str, code: int, result: str) -> None:
    write_config(sealed, [mode])
    if mode == "hang":
        text = sealed.config.read_text()
        sealed.config.write_text(text.replace("timeout_seconds = 20", "timeout_seconds = 2"))
    done = deliver(sealed)
    assert (done.code, done.lines[0]["result"]) == (code, result)
    assert nothing_sent(sealed)
    if mode == "hang":
        cancelled = (sealed.bin / "cancelled").read_text()
        assert cancelled == done.lines[0]["request_id"], "the approver had no time to clean up"


def test_no_approver_configured(sealed: Place) -> None:
    write_config(sealed, [])
    done = deliver(sealed)
    assert (done.code, done.lines[0]["detail"]) == (3, "no approver is configured")
    assert nothing_sent(sealed)


def test_the_deny_approver(sealed: Place) -> None:
    write_config(sealed, ["approve"])
    argv = json.dumps([sys.executable, "-m", "tailnet_unlock", "approver", "deny"])
    text = sealed.config.read_text()
    old = next(line for line in text.splitlines() if line.startswith("approver = "))
    sealed.config.write_text(text.replace(old, f"approver = {argv}"))
    done = deliver(sealed)
    assert (done.code, done.lines[0]["detail"]) == (3, "the approver refused")
    assert nothing_sent(sealed)


def test_an_approval_of_one_boot_is_not_one_of_the_next(sealed: Place) -> None:
    """T12: the box reboots while a person decides; its door answers with another boot id."""
    write_config(sealed, ["reboot", str(sealed.box.root / "boot_id"), OTHER_BOOT])
    done = deliver(sealed)
    assert (done.code, done.lines[0]["result"]) == (3, "refused")
    assert "rebooted" in str(done.lines[0]["detail"])
    assert nothing_sent(sealed)


def test_the_door_gone_after_the_approval(place: Place) -> None:
    process = serve(place, DOOR, "sealed")
    write_config(place, ["kill", str(process.pid)])
    try:
        done = deliver(place)
    finally:
        stop(process)
    assert (done.code, done.lines[0]["result"]) == (10, "failed")
    assert nothing_sent(place)


def test_a_wrong_key(sealed: Place) -> None:
    write_config(sealed, ["approve"])
    (sealed.root / "root-key").write_bytes(b"not the right one\n")
    done = deliver(sealed)
    assert (done.code, done.lines[0]["result"]) == (6, "wrong-key")
    assert not loaded(sealed)


@pytest.mark.parametrize(
    "source", ["exit 1", "true", "cat /dev/zero", "echo short", "/no/such/program"]
)
def test_a_bad_key_source_sends_nothing(sealed: Place, source: str) -> None:
    write_config(sealed, ["approve"])
    program(
        sealed.bin / "key-source", f"#!/bin/sh\necho {shlex.quote(KEY.decode())} >&2\n{source}\n"
    )
    done = deliver(sealed)
    (sealed.bin / "key-source").unlink()
    assert (done.code, done.lines[0]["result"]) == (10, "failed")
    assert KEY.decode() not in done.stderr, "the key source's stderr was passed on"
    assert nothing_sent(sealed)


def test_a_box_already_unlocked(sealed: Place) -> None:
    write_config(sealed, ["approve"])
    (sealed.box.zfs_state / "keystatus").write_text("available\n")
    done = deliver(sealed)
    assert (done.code, done.lines[0]["result"]) == (10, "failed")
    assert not sealed.door_log.exists()


def test_a_key_the_door_does_not_know(sealed: Place) -> None:
    write_config(sealed, ["approve"])
    Path("/root/.ssh/authorized_keys").write_text("")
    done = deliver(sealed)
    assert (done.code, done.lines[0]["result"]) == (5, "door-not-found")
    assert "refuses the keyholder's SSH key" in str(done.lines[0]["detail"])


def test_no_door_and_not_needed(place: Place) -> None:
    write_config(place, ["approve"])
    done = deliver(place)
    assert (done.code, done.lines[0]["result"]) == (5, "door-not-found")
    assert requests(place) == []
    text = place.config.read_text()
    place.config.write_text(text.replace("door_wait_minutes = 0", "door_wait_minutes = 5"))
    see(place, own=True)
    done = deliver(place, "--idle-minutes", "1")
    assert (done.code, done.lines[0]["result"]) == (7, "not-needed")
    assert requests(place) == []


@pytest.mark.parametrize("args", [["--idle-minutes", "0"], ["--note", "two\nlines"], ["--by", " "]])
def test_usage_errors(place: Place, args: list[str]) -> None:
    write_config(place, ["approve"])
    done = deliver(place, *args)
    assert (done.code, done.lines) == (2, [])
    assert done.stderr.startswith("tailnet-unlock: ")


# --- the recovery door --------------------------------------------------------------------------


def test_the_recovery_door_is_refused(recovery: Place) -> None:
    write_config(recovery, ["acknowledge"])
    done = deliver(recovery)
    assert (done.code, done.lines[0]["result"]) == (8, "recovery-only")
    assert requests(recovery) == [], "the approver was asked"
    assert nothing_sent(recovery)


def test_the_recovery_door_with_and_without_the_acknowledgement(recovery: Place) -> None:
    """T24."""
    write_config(recovery, ["approve"], defaults="allow_recovery_delivery = true")
    done = deliver(recovery)
    assert (done.code, done.lines[0]["result"]) == (3, "refused")
    assert nothing_sent(recovery)
    write_config(recovery, ["acknowledge"], defaults="allow_recovery_delivery = true")
    done = deliver(recovery)
    assert done.code == 0, done.stderr
    assert loaded(recovery)
    for request in requests(recovery):
        door = request["door"]
        assert isinstance(door, dict)
        assert door["role"] == "recovery"


def test_a_recovery_door_that_says_it_is_sealed(recovery: Place) -> None:
    """T25: a copy of /boot with a door that lies about its key."""
    (recovery.box.run / "role").write_text("sealed\n")
    write_config(recovery, ["acknowledge"], defaults="allow_recovery_delivery = true")
    done = deliver(recovery)
    assert (done.code, done.lines[0]["result"]) == (3, "refused")
    assert "reports key 'sealed'" in str(done.lines[0]["detail"])
    assert requests(recovery) == []
    assert nothing_sent(recovery)
    write_config(recovery, ["acknowledge"])
    assert deliver(recovery).code == 8, "with the setting off it ends at the gate"


def test_a_sealed_door_that_says_it_is_the_recovery_one(sealed: Place) -> None:
    (sealed.box.run / "role").write_text("recovery\n")
    write_config(sealed, ["approve"])
    done = deliver(sealed)
    assert (done.code, done.lines[0]["result"]) == (3, "refused")
    assert nothing_sent(sealed)


# --- locks, stops, the watcher ------------------------------------------------------------------


def start(place: Place, name: str, *args: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        command(place, name, *args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment(place),
        stdin=subprocess.DEVNULL,
    )


def wait_for(path: Path, timeout: float = 30) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.read_text():
            return path.read_text()
        time.sleep(0.05)
    raise AssertionError(f"{path} never appeared")


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_a_stop_during_the_approval(sealed: Place, signum: signal.Signals) -> None:
    write_config(sealed, ["hang"])
    process = start(sealed, "deliver", "web-1", "--reason", "planned")
    approver = int(wait_for(sealed.bin / "asking"))
    busy = deliver(sealed)
    assert (busy.code, busy.lines[0]["result"]) == (9, "busy")
    process.send_signal(signum)
    stdout, stderr = process.communicate(timeout=30)
    done = finished(process.returncode, stdout, stderr)
    assert done.code == 128 + signum
    assert [line["result"] for line in done.lines] == ["interrupted"]
    assert (sealed.bin / "cancelled").read_text() == done.lines[0]["request_id"]
    assert not Path(f"/proc/{approver}").exists()
    assert nothing_sent(sealed)
    write_config(sealed, ["approve"])
    assert deliver(sealed).code == 0, "the lock is free again"


def test_watch_starts_a_delivery_and_waits_for_it(sealed: Place) -> None:
    """T2, with a file standing in for the person."""
    write_config(sealed, ["approve"])
    planned = run(sealed, "planned", "web-1", "--by", "bob", "--for", "30m")
    assert planned.code == 0, planned.stderr
    see(sealed, own=False, unlock=True)
    done = run(sealed, "watch")
    assert done.code == 0, done.stderr
    assert loaded(sealed)
    assert [line["schema"] for line in done.lines] == [
        "tailnet-unlock.watch-event/1",
        "tailnet-unlock.audit/1",
    ]
    assert done.lines[1]["reason"] == {"kind": "planned", "started_by": "bob", "note": None}
    assert not (sealed.state / "planned" / "web-1.json").exists(), "one marker, one reboot"


def test_a_stopped_watcher_stops_its_delivery(sealed: Place) -> None:
    write_config(sealed, ["hang"])
    see(sealed, own=False, unlock=True)
    process = start(sealed, "watch", "--every", "10")
    wait_for(sealed.bin / "asking")
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=60)
    done = finished(process.returncode, stdout, stderr)
    assert done.code == 143
    assert done.lines[-1]["result"] == "interrupted"
    assert (sealed.bin / "cancelled").exists()


def watch_only(place: Place, extra: str = "") -> None:
    program(place.bin / "told", f"#!/bin/sh\ncat >>'{place.root}/events'\n")
    place.config.write_text(f"""
[defaults]
on_waiting = ["{place.bin}/told"]
tailscale = ["{place.bin}/tailscale"]
[hosts.web-1.door]
port = {place.port}
door_key = "{DOOR_PIN}"
recovery_key = "{RECOVERY_PIN}"
uplink = "127.0.0.1"
{extra}
""")


def events(place: Place) -> list[dict[str, object]]:
    path = place.root / "events"
    return finished(0, path.read_text() if path.exists() else "", "").lines


@pytest.mark.parametrize("role", ["sealed", "recovery"])
def test_a_watcher_without_any_key(request: pytest.FixtureRequest, role: str) -> None:
    place: Place = request.getfixturevalue(role)
    watch_only(place)
    first = run(place, "watch")
    second = run(place, "watch")
    assert (first.code, second.code) == (0, 0), first.stderr + second.stderr
    told = events(place)
    assert len(told) == 2
    assert told[0]["waiting_since"] == told[1]["waiting_since"]
    assert told[0]["doors"] == [{"kind": "uplink", "role": role, "address": "127.0.0.1"}]
    assert nothing_sent(place)


def test_a_server_with_another_key_is_no_door(place: Place) -> None:
    process = serve(place, dropbear_ed25519(0x33), "sealed")
    try:
        watch_only(place)
        assert run(place, "watch").code == 0
    finally:
        stop(process)
    assert events(place) == []


def test_watch_decides_nothing_when_the_tailnet_cannot_be_read(sealed: Place) -> None:
    watch_only(sealed, 'unlock_node = "web-1-unlock"')
    (sealed.bin / "status.json").write_text(status_json(backend="Stopped"))
    done = run(sealed, "watch")
    assert done.code == 2
    assert events(sealed) == []
    assert not (sealed.state / "watch").exists()


def test_a_watcher_that_could_do_nothing_is_refused(sealed: Place) -> None:
    write_config(sealed, [])
    done = run(sealed, "watch")
    assert done.code == 2
    assert "set on_waiting" in done.stderr


# --- the real client's words --------------------------------------------------------------------


def answers(place: Place, role: DoorRole, address: str = "127.0.0.1") -> bool:
    pins = door_pins(place.port, DOOR_PIN, RECOVERY_PIN)
    return door_answers("web-1", pins, role, Target("uplink", address, place.port, "x"), None)


def test_the_probe_against_dropbear(sealed: Place) -> None:
    assert answers(sealed, "sealed")
    assert not answers(sealed, "recovery")
    assert not answers(sealed, "sealed", "127.0.0.9")


def test_a_probe_with_a_key_the_door_takes(sealed: Place) -> None:
    pins = door_pins(sealed.port, DOOR_PIN, RECOVERY_PIN)
    target = Target("uplink", "127.0.0.1", sealed.port, "x")
    assert door_answers("web-1", pins, "sealed", target, str(sealed.root / "client"))


def test_the_probe_against_openssh(place: Place) -> None:
    sshd = shutil.which("sshd", path="/usr/sbin:/sbin")
    if sshd is None:
        pytest.skip("needs openssh-server")
    host_key = place.root / "sshd_key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True)
    Path("/run/sshd").mkdir(exist_ok=True)
    config = place.root / "sshd_config"
    config.write_text(
        f"HostKey {host_key}\nListenAddress 127.0.0.1\nPort {place.port}\n"
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPidFile none\n"
    )
    process = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], stderr=subprocess.DEVNULL)
    try:
        wait_listening("127.0.0.1", place.port)
        own = " ".join(host_key.with_suffix(".pub").read_text().split()[:2])
        target = Target("uplink", "127.0.0.1", place.port, "x")
        assert door_answers("web-1", door_pins(place.port, own, None), "sealed", target, None)
        assert not answers(place, "sealed")
        read = read_door("web-1", door_pins(place.port, own, None), "sealed", target, None)
        assert read.__class__.__name__ == "DoorFailure"
    finally:
        stop(process)


def forged(text: bytes) -> bytes:
    """An SSH_MSG_DISCONNECT before any key exchange, whose text the server chooses."""
    payload = b"\x01" + struct.pack(">I", 2) + struct.pack(">I", len(text)) + text
    payload += struct.pack(">I", 0)
    padding = 8 - (len(payload) + 5) % 8
    padding += 8 if padding < 4 else 0
    packet = struct.pack(">IB", len(payload) + padding + 1, padding) + payload
    return packet + b"\0" * padding


@pytest.mark.parametrize(
    "text",
    [
        b"x\nroot@127.0.0.1: Permission denied (publickey).",
        b"x\r\nroot@127.0.0.1: Permission denied (publickey).\r\n",
        b"root@127.0.0.1: Permission denied (publickey).",
        b"\r" + b"root@127.0.0.1: Permission denied (publickey).",
    ],
)
def test_a_server_cannot_forge_the_proof(place: Place, text: bytes) -> None:
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", place.port))
        server.listen(4)
        server.settimeout(30)

        def talk() -> None:
            conn, _ = server.accept()
            with conn:
                conn.sendall(b"SSH-2.0-forged\r\n" + forged(text))
                time.sleep(1)

        thread = threading.Thread(target=talk)
        thread.start()
        assert not answers(place, "sealed")
        thread.join()


# --- the single file ----------------------------------------------------------------------------


def test_the_zipapp_delivers_and_watches(sealed: Place) -> None:
    """With nothing installed: an isolated interpreter, no package on its path, and the watcher
    starts its delivery from the same single file."""
    built = subprocess.run(
        [sys.executable, str(REPO / "tools" / "build_pyz.py"), str(sealed.root)],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
    )
    pyz = Path(built.stdout.strip())
    write_config(sealed, ["approve"])
    see(sealed, own=False, unlock=True)
    env = environment(sealed)
    del env["PYTHONPATH"]
    done = subprocess.run(
        [str(pyz), "watch", "--config", str(sealed.config), "--state-dir", str(sealed.state)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={**env, "PATH": f"{sealed.bin}:/usr/bin:/bin"},
        cwd="/",
    )
    assert done.returncode == 0, done.stderr
    assert loaded(sealed)
