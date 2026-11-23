"""Stand-ins for `tailscale` and `tailscaled`, for the tests that have no real daemon.

One script plays both, by the name it is run under. Its behaviour comes from `scenario.json` in
its own directory, and every call is appended to `calls.log` there (the argument list, the names
and values of the environment, and whether the auth key file existed), so a test can check what
was run and that nothing secret went through a command line or the environment.

The daemon creates its socket file and an `.info` file beside it, then sleeps until SIGTERM. The
CLI reads the `.info` file to find the daemon's state file and pid. `up` writes the state (a file
shaped like Tailscale's sealed store, or a plain one when the scenario says so); a daemon started on
a state file that has content reports `Running`, as a real one does with a joined node.
"""

import base64
import json
import os
import stat
from pathlib import Path

SCRIPT = r"""#!/usr/bin/env python3
import base64, json, os, signal, sys, time
HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
NAME = os.path.basename(sys.argv[0])
SCENARIO = json.load(open(os.path.join(HERE, "scenario.json")))
ARGS = sys.argv[1:]


def log(extra):
    entry = {"tool": NAME, "argv": ARGS, "env": dict(os.environ)}
    entry.update(extra)
    with open(os.path.join(HERE, "calls.log"), "a") as handle:
        handle.write(json.dumps(entry) + "\n")


def option(prefix):
    for item in ARGS:
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


def sealed():
    b = lambda data: base64.b64encode(data).decode()
    return json.dumps({"key": {"Private": b(b"private"), "Public": b(b"public")},
                       "nonce": b(bytes(24)), "data": b(b"data")})


def info_of(socket):
    return json.load(open(socket + ".info"))


if "--version" in ARGS:
    version = SCENARIO.get("version_" + NAME, SCENARIO.get("version", "1.104.7"))
    print(version)
    print("  tailscale commit: 0000000")
    sys.exit(0)

if NAME == "tailscaled":
    state = option("--state=")
    socket = option("--socket=")
    log({"state": state, "encrypted": "--encrypt-state" in ARGS})
    is_proof = os.path.basename(state).startswith("verify")
    if is_proof and SCENARIO.get("proof_fails"):
        sys.stderr.write("failed to unseal state file\n")
        sys.exit(1)
    open(socket, "w").close()
    json.dump({"state": state, "pid": os.getpid()}, open(socket + ".info", "w"))
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    if SCENARIO.get("ignore_term"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while not stop:
        time.sleep(0.05)
    log({"stopped": True})
    sys.exit(SCENARIO.get("term_exit_code", 0))

command = [a for a in ARGS if not a.startswith("--socket=")]
socket = option("--socket=")
verb = command[0]
if verb == "status":
    info = info_of(socket)
    joined = os.path.exists(info["state"]) and os.path.getsize(info["state"]) > 0
    body = {"BackendState": "Running" if joined else "NeedsLogin"}
    if joined:
        body["Self"] = {"ID": SCENARIO.get("node_id", "n1CNTRL"), "HostName": "box-unlock",
                        "DNSName": "box-unlock.tailnet.example.",
                        "TailscaleIPs": ["192.0.2.7", "2001:db8::7"],
                        "Tags": SCENARIO.get("tags", ["tag:unlock"])}
    if SCENARIO.get("never_running"):
        body = {"BackendState": "NeedsLogin"}
    print(json.dumps(body))
elif verb == "up":
    key_file = option("--auth-key=file:")
    log({"verb": "up", "key_file": key_file,
         "key_file_existed": bool(key_file) and os.path.exists(key_file)})
    if SCENARIO.get("up_fails"):
        sys.stderr.write("backend error: invalid key\n")
        sys.exit(1)
    info = info_of(socket)
    content = sealed() if SCENARIO.get("state_kind", "sealed") == "sealed" else json.dumps(
        {"_machinekey": "privkey:0000", "_daemon": "x"})
    open(info["state"], "w").write(content)
    if SCENARIO.get("kill_daemon_on_up"):
        os.kill(info["pid"], signal.SIGKILL)
        time.sleep(0.2)
elif verb == "logout":
    log({"verb": "logout"})
    if SCENARIO.get("logout_fails"):
        sys.stderr.write("logout failed\n")
        sys.exit(1)
    info = info_of(socket)
    open(info["state"], "w").close()
else:
    sys.exit(2)
if verb == "status":
    log({"verb": "status"})
"""


def sealed_state() -> bytes:
    """A file shaped like the one Tailscale's TPM store writes (see sealedstate.py)."""

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    return json.dumps(
        {
            "key": {"Private": b64(b"private"), "Public": b64(b"public")},
            "nonce": b64(bytes(24)),
            "data": b64(b"data"),
        }
    ).encode()


def install_fakes(directory: Path, **scenario: object) -> None:
    """Put `tailscale` and `tailscaled` in `directory` with this scenario."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("tailscale", "tailscaled"):
        path = directory / name
        path.write_text(SCRIPT)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    set_scenario(directory, **scenario)
    (directory / "calls.log").write_text("")


def set_scenario(directory: Path, **scenario: object) -> None:
    (directory / "scenario.json").write_text(json.dumps(scenario))


def calls(directory: Path) -> list[dict[str, object]]:
    """Every logged call, in order. Each is a dict with `tool`, `argv`, `env` and extras."""
    entries: list[dict[str, object]] = []
    for line in (directory / "calls.log").read_text().splitlines():
        parsed: object = json.loads(line)
        assert isinstance(parsed, dict)
        entries.append({str(key): value for key, value in parsed.items()})
    return entries


def verbs(directory: Path) -> list[str]:
    """`tailscaled` for a daemon start, else the tailscale verb, one per completed call."""
    found: list[str] = []
    for entry in calls(directory):
        if entry["tool"] == "tailscaled" and "state" in entry:
            found.append("tailscaled")
        elif "verb" in entry and entry["verb"] != "status":
            found.append(str(entry["verb"]))
    return found


def live_daemons(root: Path) -> list[int]:
    """The pids of fake daemons under `root` that are still running (a test leaves none)."""
    alive: list[int] = []
    for info in root.rglob("*.info"):
        try:
            pid = int(json.loads(info.read_text())["pid"])
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
        except (OSError, ValueError, KeyError, IndexError):
            continue
        if state != "Z":
            alive.append(pid)
    return alive


def reap(root: Path) -> None:
    """Make sure no fake daemon outlives a test, by pid."""
    for pid in live_daemons(root):
        os.kill(pid, 9)
