"""The tailnet tier of the VM scenarios (DESIGN.md 15.3: T1 to T8, T12, T13, T15, T19, T20, T24 to
T26) on a host with KVM, QEMU, OVMF, swtpm and openssl.

`make vm-tailnet-test` runs them. headscale runs on the host as a process (tailnet.py, pinned in
pins.env) with the example policy; the keyholder is a userspace tailscaled on the host. The guest
is the `tailnet` variant (guests.py): its first boot enrolled the unlock node through
`tailnet-unlock enroll --auth-key-file` with a pre-auth key from the seed disk. A scenario boots an
overlay of that disk with a copy of its TPM, reaches the door over the tailnet through the
keyholder, and reads what headscale says about the node.

The delivery scenarios run the keyholder's own commands on the host, from this checkout, with that
keyholder's `tailscale` for the status and for ssh's ProxyCommand.

What headscale cannot test: Tailnet Lock (T19's signed enrolment) is Tailscale's own feature. That
half runs in the release matrix against a Tailscale tailnet; here T19 checks the other half, that
the unlock node is reachable at every boot with its state in tmpfs only.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

import tailnet
from guests import (
    CACHE,
    PASSPHRASE,
    VM_MARKS,
    Booted,
    TailnetGuest,
    boot_overlay,
    boot_record,
    build_base,
    build_tailnet,
    door,
    door_seed_hex,
    guest_ssh,
    images_with,
    wait_for_door,
)
from harness import Vm, expect, ssh_argv, stop
from shellenv import REPO
from tailnet import Headscale, Node, Tools

pytestmark = VM_MARKS

type Boot = Callable[[str, bool], Booted]


@dataclass(frozen=True)
class Net:
    tools: Tools
    hs: Headscale
    keyholder: Node
    work: Path


@pytest.fixture(scope="session")
def net(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Net]:
    if not tailnet.host_alias_ready(tailnet.CONTROL_HOST):
        pytest.skip(f"this host cannot bind {tailnet.CONTROL_HOST}: ip addr add it to lo")
    tools = tailnet.fetch_tools(CACHE)
    base = build_base()
    work = tmp_path_factory.mktemp("tailnet")
    hs = tailnet.start_headscale(tools, base.disk.parent / "headscale")
    nodes: list[Node] = []
    try:
        keyholder = tailnet.start_node(tools, hs, work / "keyholder", "keyholder", "tag:keyholder")
        nodes.append(keyholder)
        yield Net(tools, hs, keyholder, work)
    finally:
        for node in nodes:
            tailnet.stop_node(node)
        tailnet.stop_headscale(hs)


@pytest.fixture(scope="session")
def tguest(net: Net) -> TailnetGuest:
    return build_tailnet(
        build_base(),
        tailnet.headscale_url(tailnet.CONTROL_HOST),
        net.hs.ca,
        lambda: tailnet.preauth_key(net.hs, "tag:unlock", ephemeral=False),
    )


@pytest.fixture
def boot(net: Net, tguest: TailnetGuest, tmp_path: Path) -> Iterator[Boot]:
    started: list[Vm] = []

    def booting(tpm: str, restrict: bool) -> Booted:
        # the node the last scenario left must read as offline before this boot can be judged
        tailnet.wait_online(net.hs, tailnet.first_ipv4(list(tguest.addresses)), False, 90)
        booted = boot_overlay(tguest, tmp_path / f"vm{len(started)}", tpm, restrict)
        started.append(booted.vm)
        return booted

    yield booting
    for vm in started:
        stop(vm)


def unlock_ip(tguest: TailnetGuest) -> str:
    return tailnet.first_ipv4(list(tguest.addresses))


def tailnet_door(
    net: Net, tguest: TailnetGuest, work: Path, command: str, stdin: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    """Run a door command through the keyholder, over the tailnet, with the sealed key pinned."""
    ip = unlock_ip(tguest)
    hosts = work / "known_hosts.tailnet"
    hosts.write_text(f"[{ip}]:{tailnet.DOOR_PORT} {tguest.door_pin}\n")
    proxy = tailnet.proxy_command(net.tools, net.keyholder.sock)
    argv = ssh_argv(
        tailnet.DOOR_PORT,
        tguest.keys / "keyholder",
        hosts,
        [command],
        extra=("-o", f"ProxyCommand={proxy}"),
        host=ip,
    )
    return subprocess.run(argv, input=stdin, capture_output=True, timeout=120, check=False)


def wait_tailnet_door(
    net: Net, tguest: TailnetGuest, booted: Booted, timeout: float = 240
) -> dict[str, object]:
    """Wait until the door answers `status` over the tailnet; returns the status."""
    deadline = time.monotonic() + timeout
    last = b""
    while time.monotonic() < deadline:
        done = tailnet_door(net, tguest, booted.work, "status")
        if done.returncode == 0:
            status: object = json.loads(done.stdout)
            assert isinstance(status, dict)
            return status
        last = done.stderr
        time.sleep(4)
    raise AssertionError(
        f"the door never answered over the tailnet: {last.decode(errors='replace')}"
    )


def unlock_over_tailnet(net: Net, tguest: TailnetGuest, booted: Booted, boot_id: str) -> None:
    done = tailnet_door(net, tguest, booted.work, f"unlock {boot_id}", PASSPHRASE.encode() + b"\n")
    assert json.loads(done.stdout)["result"] == "loaded", done.stderr


def test_t1_unlock_over_the_uplink_and_the_tailnet(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    """Both doors answer on one boot with the sealed key; the unlock goes through the tailnet; the
    unlock node is offline before the system's own services run."""
    booted = boot("same", False)
    role, boot_id = wait_for_door(tguest, booted, "sealed")
    assert role == "sealed"
    status = wait_tailnet_door(net, tguest, booted)
    assert status["key"] == "sealed"
    assert status["boot_id"] == boot_id
    assert tailnet.node_online(net.hs, unlock_ip(tguest))
    unlock_over_tailnet(net, tguest, booted, boot_id)
    assert boot_record(booted)["unlocked_by"] == "sealed"
    assert tailnet.wait_online(net.hs, unlock_ip(tguest), False, 120), "the node is still online"
    guest_ssh(tguest, booted, "true")
    assert not tailnet.node_online(net.hs, unlock_ip(tguest))


def test_t4_control_plane_unreachable_the_uplink_door_unlocks(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    booted = boot("same", True)
    role, boot_id = wait_for_door(tguest, booted, "sealed")
    assert role == "sealed"
    assert not tailnet.wait_online(net.hs, unlock_ip(tguest), True, 40)
    done = door(tguest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    assert json.loads(done.stdout)["result"] == "loaded"
    assert boot_record(booted)["unlocked_by"] == "sealed"


def assert_recovery_only(net: Net, tguest: TailnetGuest, booted: Booted) -> None:
    """The boot of a TPM that cannot unseal: the recovery key on the uplink, nothing on the
    tailnet, the sealed key never presented."""
    role, boot_id = wait_for_door(tguest, booted, "recovery")
    assert role == "recovery"
    assert door(tguest, booted, "sealed", "status").returncode == 255
    status = json.loads(door(tguest, booted, "recovery", "status").stdout)
    assert status["key"] == "recovery"
    assert not tailnet.wait_online(net.hs, unlock_ip(tguest), True, 45), "the node came online"
    assert not tailnet.reaches(net.keyholder, unlock_ip(tguest), tailnet.DOOR_PORT, timeout=10)
    loaded = door(tguest, booted, "recovery", f"unlock {boot_id}", PASSPHRASE.encode())
    assert json.loads(loaded.stdout)["result"] == "loaded"
    assert boot_record(booted)["unlocked_by"] == "recovery"


def test_t5_a_copy_with_another_swtpm_gets_the_recovery_door_only(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    assert_recovery_only(net, tguest, boot("fresh", False))


def test_t7_a_cleared_tpm_falls_back_to_the_recovery_door(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    assert_recovery_only(net, tguest, boot("reset", False))


def test_t8_a_tampered_initramfs_on_the_same_tpm_can_unseal(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    """The documented boundary of the `tpm` profile: the seal is to the TPM, not to what booted,
    so an initramfs that was modified (here by a cpio appended to the image, which adds a script
    that prints a marker) unseals the door key and joins the tailnet."""
    booted = boot("same", False)
    _, boot_id = wait_for_door(tguest, booted, "sealed")
    door(tguest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    boot_record(booted)
    made = guest_ssh(tguest, booted, "tu-make-tamper-entry")
    assert made.returncode == 0, made.stderr.decode()
    mark = len(booted.vm.console.text)
    guest_ssh(tguest, booted, "grub-reboot 'tailnet-unlock tampered initramfs' && systemctl reboot")
    expect(booted.vm.console, r"TU-TAMPERED", 600, mark)
    role, boot_id = wait_for_door(tguest, booted, "sealed", mark)
    assert role == "sealed", "a tampered initramfs on the same TPM could not unseal"
    status = wait_tailnet_door(net, tguest, booted)
    assert status["key"] == "sealed"
    unlock_over_tailnet(net, tguest, booted, boot_id)
    assert boot_record(booted, mark)["unlocked_by"] == "sealed"


def test_t6_t19_no_plain_secret_in_boot_and_the_node_survives_boots(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    """/boot holds no door key and no node key in plain text, and the pre-auth key is nowhere on
    the box; the unlock node is reachable at two boots in a row and its state file on disk is the
    same afterwards (the running copy lives in tmpfs and is discarded at the handover)."""
    booted = boot("same", False)
    _, boot_id = wait_for_door(tguest, booted, "sealed")
    wait_tailnet_door(net, tguest, booted)
    unlock_over_tailnet(net, tguest, booted, boot_id)
    boot_record(booted)
    state = "/var/lib/tailnet-unlock/tailnet/unlock.state"
    before = guest_ssh(tguest, booted, f"sha256sum {state}").stdout.split()[0]
    seed = door_seed_hex(tguest)
    found = guest_ssh(
        tguest,
        booted,
        "sh -c 'for i in /boot/initrd.img-*; do d=$(mktemp -d); unmkinitramfs $i $d; "
        'find $d -type f -exec xxd -p {} + | tr -d "\\n" | '
        f"grep -c {seed}; "
        'grep -rlaE --exclude=tailscaled "_machinekey|(privkey|nodekey|mkey):[0-9a-f]{64}" '
        "$d | wc -l; "
        "find $d -name unlock.state | wc -l; done'",
    )
    lines = found.stdout.decode().split()
    assert lines
    assert len(lines) % 3 == 0
    for door_hits, key_hits, state_files in zip(lines[0::3], lines[1::3], lines[2::3], strict=True):
        assert door_hits == "0", "the door key is in an image in plain text"
        assert key_hits == "0", "a node or machine key is in an image in plain text"
        assert state_files == "1", "the image carries no node state"
    leaked = guest_ssh(
        tguest,
        booted,
        f"grep -rla {tguest.authkey} /boot /etc /var/lib /root /opt /home 2>/dev/null | wc -l",
    )
    assert leaked.stdout.strip() == b"0", "the pre-auth key is still on the box"
    mark = len(booted.vm.console.text)
    guest_ssh(tguest, booted, "systemctl reboot")
    _, second = wait_for_door(tguest, booted, "sealed", mark)
    assert second != boot_id
    assert wait_tailnet_door(net, tguest, booted)["boot_id"] == second
    unlock_over_tailnet(net, tguest, booted, second)
    boot_record(booted, mark)
    after = guest_ssh(tguest, booted, f"sha256sum {state}").stdout.split()[0]
    assert before == after


def test_verify_passes_on_a_good_image_and_fails_below_a_raised_floor(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    booted = boot("same", False)
    _, boot_id = wait_for_door(tguest, booted, "sealed")
    door(tguest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    boot_record(booted)
    good = guest_ssh(tguest, booted, "tailnet-unlock verify --json; echo rc=$?")
    text = good.stdout.decode()
    assert text.rstrip().endswith("rc=0"), text
    report = json.loads(text[: text.rindex("rc=")])
    assert report["ok"] is True
    assert report["images"]
    raised = guest_ssh(
        tguest, booted, "tailnet-unlock verify --json --tailscale-floor 99.0.0; echo rc=$?"
    )
    text = raised.stdout.decode()
    assert text.rstrip().endswith("rc=1"), text
    report = json.loads(text[: text.rindex("rc=")])
    assert report["ok"] is False
    assert report["problems"]


def test_disable_tailnet_rebuilds_an_image_without_tailscaled(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    booted = boot("same", False)
    _, boot_id = wait_for_door(tguest, booted, "sealed")
    door(tguest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    boot_record(booted)
    assert all(count == 1 for count in images_with(tguest, booted, "-name tailscaled"))
    disabled = guest_ssh(tguest, booted, "tailnet-unlock disable --tailnet")
    assert disabled.returncode == 0, disabled.stderr.decode()
    assert json.loads(disabled.stdout)["changed"] is True
    counts = images_with(tguest, booted, "-name tailscaled -o -name unlock.state")
    assert counts == [0] * len(counts)
    mark = len(booted.vm.console.text)
    guest_ssh(tguest, booted, "systemctl reboot")
    role, second = wait_for_door(tguest, booted, "sealed", mark)
    assert role == "sealed"
    assert not tailnet.wait_online(net.hs, unlock_ip(tguest), True, 40)
    loaded = door(tguest, booted, "sealed", f"unlock {second}", PASSPHRASE.encode())
    assert json.loads(loaded.stdout)["result"] == "loaded"


def test_t26_the_supervisor_restarts_a_killed_tailscaled_and_dropbear(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    """The test image's own initramfs script (provision.sh, off unless tu_test_kill=1 is on the
    command line) kills tailscaled and then dropbear with SIGKILL while the box waits."""
    booted = boot("same", False)
    _, boot_id = wait_for_door(tguest, booted, "sealed")
    door(tguest, booted, "sealed", f"unlock {boot_id}", PASSPHRASE.encode())
    boot_record(booted)
    mark = len(booted.vm.console.text)
    guest_ssh(tguest, booted, "grub-reboot 'tailnet-unlock kill test' && systemctl reboot")
    role, _ = wait_for_door(tguest, booted, "sealed", mark)
    assert role == "sealed"
    ip = unlock_ip(tguest)
    assert tailnet.wait_online(net.hs, ip, True, 240)
    expect(booted.vm.console, r"TU-TEST killed tailscaled", 400, mark)
    expect(booted.vm.console, r"the unlock node \(tailscaled\) exited; starting it again", 60, mark)
    assert tailnet.wait_online(net.hs, ip, True, 180), "tailscaled did not come back"
    status = wait_tailnet_door(net, tguest, booted)
    assert status["key"] == "sealed"
    restarts = status["restarts"]
    assert isinstance(restarts, dict)
    assert restarts["tailscaled"] >= 1
    expect(booted.vm.console, r"TU-TEST killed dropbear", 400, mark)
    expect(booted.vm.console, r"the door \(dropbear\) exited; starting it again", 60, mark)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and door(tguest, booted, "sealed", "status").returncode != 0:
        time.sleep(3)
    again = json.loads(door(tguest, booted, "sealed", "status").stdout)
    assert again["key"] == "sealed", "the restarted door does not present the sealed key"
    assert again["restarts"]["dropbear"] >= 1
    _, boot_id = wait_for_door(tguest, booted, "sealed", mark)
    unlock_over_tailnet(net, tguest, booted, boot_id)
    assert boot_record(booted, mark)["unlocked_by"] == "sealed"


def banner_listeners(ports: tuple[int, ...]) -> list[socket.socket]:
    """Plain servers on the host's loopback that speak first with an SSH banner: userspace nodes
    forward inbound tailnet connections to 127.0.0.1, as the guest's do to its door."""
    servers: list[socket.socket] = []
    for port in ports:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(8)
        servers.append(server)

        def serve(listener: socket.socket = server) -> None:
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                conn.sendall(b"SSH-2.0-tailnet-unlock-test\r\n")
                conn.close()

        threading.Thread(target=serve, daemon=True).start()
    return servers


def test_t20_the_example_policy_isolates_the_door(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    """Loaded into headscale as `examples/policy.hujson`: a peer that is neither keyholder nor
    operator cannot reach a door's port, the door reaches nothing, a keyholder reaches only the
    door's port, an operator the same. The policy side runs against a stand-in node with the door
    tag; the real guest is then checked from the keyholder's and an intruder's side."""
    tools, hs = net.tools, net.hs
    listeners = banner_listeners((2222, 2223))
    nodes: list[Node] = []
    try:
        standin = tailnet.start_node(
            tools, hs, net.work / "standin", "standin-unlock", "tag:unlock"
        )
        nodes.append(standin)
        intruder = tailnet.start_node(
            tools, hs, net.work / "intruder", "intruder", None, user="intruder"
        )
        nodes.append(intruder)
        operator = tailnet.start_node(tools, hs, net.work / "operator", "operator-laptop", None)
        nodes.append(operator)
        standin_ip = tailnet.node_ip(standin)
        keyholder_ip = tailnet.node_ip(net.keyholder)
        assert tailnet.wait_reaches(net.keyholder, standin_ip, 2222, 60), "keyholder is refused"
        assert tailnet.wait_reaches(operator, standin_ip, 2222, 60), "operator is refused"
        assert not tailnet.reaches(net.keyholder, standin_ip, 2223, timeout=8)
        assert not tailnet.reaches(intruder, standin_ip, 2222, timeout=8)
        assert not tailnet.reaches(standin, keyholder_ip, 2222, timeout=8)
        assert not tailnet.reaches(standin, tailnet.node_ip(intruder), 2222, timeout=8)
        checked = tailnet.check_policy(hs)
        assert checked.returncode == 0, checked.stdout + checked.stderr

        booted = boot("same", False)
        _, boot_id = wait_for_door(tguest, booted, "sealed")
        wait_tailnet_door(net, tguest, booted)
        assert not tailnet.reaches(intruder, unlock_ip(tguest), tailnet.DOOR_PORT, timeout=10)
        unlock_over_tailnet(net, tguest, booted, boot_id)
        boot_record(booted)
    finally:
        for node in nodes:
            tailnet.stop_node(node)
        for listener in listeners:
            listener.close()


# --- delivery -----------------------------------------------------------------------------------

APPROVER = r"""#!/usr/bin/env python3
import json, os, sys, time
here = os.path.dirname(os.path.abspath(sys.argv[0]))
mode = sys.argv[1]
request = json.load(sys.stdin)
with open(here + "/requests.jsonl", "a") as log:
    log.write(json.dumps(request) + "\n")
answer = {"schema": "tailnet-unlock.approval-response/1", "request_id": request["request_id"],
          "decision": "refuse" if mode == "refuse" else "approve", "by": "alice"}
if mode == "acknowledge":
    answer["recovery_acknowledged"] = True
if mode == "hang":
    time.sleep(300)
saved = here + "/approval.json"
if mode == "replay":
    answer = json.load(open(saved))
else:
    json.dump(answer, open(saved, "w"))
print(json.dumps(answer))
"""


def seen_online(node: Node, ip: str, timeout: float = 120) -> str:
    """Wait until `node` sees the peer at `ip` online; returns the peer's stable id. An id, because
    the image may have been built, and its node enrolled, more than once against one headscale."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        peers = tailnet.node_status(node).get("Peer") or {}
        assert isinstance(peers, dict)
        for peer in peers.values():
            assert isinstance(peer, dict)
            addresses = peer.get("TailscaleIPs")
            if isinstance(addresses, list) and ip in addresses and peer.get("Online") is True:
                return str(peer["ID"])
        time.sleep(1)
    raise AssertionError(f"{node.name} never saw {ip} online")


@dataclass(frozen=True)
class Delivery:
    """A keyholder's configuration and state for one scenario."""

    net: Net
    work: Path
    tguest: TailnetGuest
    door_port: int
    unlock_id: str


def keyholder_of(net: Net, tguest: TailnetGuest, booted: Booted) -> Delivery:
    """The unlock node may be offline (a recovery boot), so its id comes from headscale's list,
    which the stable id a peer shows is made from."""
    node = tailnet.node_by_ip(net.hs, unlock_ip(tguest))
    assert node is not None
    return Delivery(net, booted.work / "keyholder", tguest, booted.door_port, str(node["id"]))


def configure(delivery: Delivery, mode: str, defaults: str = "") -> None:
    net, work, tguest = delivery.net, delivery.work, delivery.tguest
    work.mkdir(exist_ok=True)
    approver = work / "approver"
    approver.write_text(APPROVER)
    approver.chmod(0o755)
    (work / "root-key").write_text(PASSPHRASE + "\n")
    (work / "keyholder.toml").write_text(f"""
[defaults]
tailscale = ["{net.tools.tailscale}", "--socket={net.keyholder.sock}"]
ssh_proxy_command = "{tailnet.proxy_command(net.tools, net.keyholder.sock)}"
ssh_key = "{tguest.keys / "keyholder"}"
approver = ["{approver}", "{mode}"]
approval_timeout_seconds = 60
door_wait_minutes = 1
node_wait_seconds = 0
{defaults}

[hosts.tu-test]
key_command = ["cat", "{work / "root-key"}"]

[hosts.tu-test.door]
port = {tailnet.DOOR_PORT}
door_key = "{tguest.door_pin}"
recovery_key = "{tguest.recovery_pin}"
unlock_node_id = "{delivery.unlock_id}"
uplink = "127.0.0.1"
uplink_port = {delivery.door_port}
""")


def keyholder(delivery: Delivery, command: str, *args: str) -> tuple[int, list[dict[str, object]]]:
    """Run a keyholder command; its exit code and its JSON lines. T14: the key is in neither its
    output nor its state."""
    work = delivery.work
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "tailnet_unlock",
            command,
            *args,
            f"--config={work / 'keyholder.toml'}",
            f"--state-dir={work / 'state'}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        stdin=subprocess.DEVNULL,
    )
    assert PASSPHRASE not in done.stdout + done.stderr
    for path in (work / "state").rglob("*"):
        assert not path.is_file() or PASSPHRASE.encode() not in path.read_bytes(), path
    lines: list[dict[str, object]] = []
    for line in done.stdout.splitlines():
        parsed: object = json.loads(line)
        assert isinstance(parsed, dict)
        lines.append({str(key): value for key, value in parsed.items()})
    print(done.stderr, file=sys.stderr)
    return done.returncode, lines


def deliver(delivery: Delivery) -> tuple[int, dict[str, object]]:
    code, lines = keyholder(delivery, "deliver", "tu-test", "--reason=unplanned")
    assert len(lines) == 1, lines
    return code, lines[0]


def requests(delivery: Delivery) -> list[dict[str, object]]:
    path = delivery.work / "requests.jsonl"
    lines = path.read_text().splitlines() if path.exists() else []
    return [dict(json.loads(line)) for line in lines]


def test_t2_the_watcher_finds_the_box_and_the_approver_approves(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    booted = boot("same", False)
    _, boot_id = wait_for_door(tguest, booted, "sealed")
    wait_tailnet_door(net, tguest, booted)
    seen_online(net.keyholder, unlock_ip(tguest))
    delivery = keyholder_of(net, tguest, booted)
    configure(delivery, "approve")
    code, lines = keyholder(delivery, "watch")
    assert code == 0
    event, audit = lines
    assert (event["kind"], event["unlock_node"]) == ("waiting", "online")
    assert (audit["result"], audit["boot_id"]) == ("delivered", boot_id)
    assert audit["decision"] == {"approved": True, "by": "alice", "note": None}
    door_line = audit["door"]
    assert isinstance(door_line, dict)
    assert (door_line["kind"], door_line["role"]) == ("tailnet", "sealed")
    assert isinstance(audit["network"], dict)
    assert audit["network"]["path"] in {"direct", "relayed"}
    assert boot_record(booted)["unlocked_by"] == "sealed"


def test_t3_a_refusal_and_a_timeout_send_nothing(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    booted = boot("same", False)
    _, boot_id = wait_for_door(tguest, booted, "sealed")
    delivery = keyholder_of(net, tguest, booted)
    configure(delivery, "refuse")
    code, audit = deliver(delivery)
    assert (code, audit["result"]) == (3, "refused")
    configure(delivery, "hang")
    config = delivery.work / "keyholder.toml"
    config.write_text(config.read_text().replace("timeout_seconds = 60", "timeout_seconds = 3"))
    code, audit = deliver(delivery)
    assert (code, audit["result"]) == (4, "approval-timeout")
    status = json.loads(door(tguest, booted, "sealed", "status").stdout)
    assert (status["boot_id"], status["waiting_for"]) == (boot_id, "rpool")
    configure(delivery, "approve")
    code, audit = deliver(delivery)
    assert (code, audit["result"]) == (0, "delivered")
    assert boot_record(booted)["unlocked_by"] == "sealed"


def test_t12_an_approval_of_one_boot_is_refused_on_the_next(
    net: Net, tguest: TailnetGuest, boot: Boot
) -> None:
    booted = boot("same", False)
    _, first = wait_for_door(tguest, booted, "sealed")
    delivery = keyholder_of(net, tguest, booted)
    configure(delivery, "approve")
    code, audit = deliver(delivery)
    assert (code, audit["boot_id"]) == (0, first)
    boot_record(booted)
    mark = len(booted.vm.console.text)
    guest_ssh(tguest, booted, "systemctl reboot")
    _, second = wait_for_door(tguest, booted, "sealed", mark)
    assert second != first
    configure(delivery, "replay")
    code, audit = deliver(delivery)
    assert (code, audit["result"], audit["boot_id"]) == (3, "refused", second)
    # and the door itself takes no key for another boot
    refused = door(tguest, booted, "sealed", f"unlock {first}", PASSPHRASE.encode())
    assert json.loads(refused.stdout)["result"] == "boot-mismatch"
    configure(delivery, "approve")
    assert deliver(delivery)[0] == 0
    assert boot_record(booted, mark)["unlocked_by"] == "sealed"


@pytest.mark.parametrize("tpm", ["reset", "fresh"])
def test_t24_t25_a_recovery_delivery(net: Net, tguest: TailnetGuest, boot: Boot, tpm: str) -> None:
    """A cleared TPM (T24) and a copy on another TPM (T25). A door changed to report another key
    than it presents is in tests/delivery."""
    booted = boot(tpm, False)
    wait_for_door(tguest, booted, "recovery")
    delivery = keyholder_of(net, tguest, booted)
    configure(delivery, "acknowledge")
    code, audit = deliver(delivery)
    assert (code, audit["result"]) == (8, "recovery-only")
    assert requests(delivery) == [], "the approver was asked"
    allow = "allow_recovery_delivery = true"
    configure(delivery, "approve", allow)
    code, audit = deliver(delivery)
    assert (code, audit["result"]) == (3, "refused")
    configure(delivery, "acknowledge", allow)
    code, audit = deliver(delivery)
    assert (code, audit["result"]) == (0, "delivered")
    for request in requests(delivery):
        asked = request["door"]
        assert isinstance(asked, dict)
        assert (asked["role"], asked["kind"]) == ("recovery", "uplink")
    assert boot_record(booted)["unlocked_by"] == "recovery"


def test_t13_an_unlock_node_online_while_the_box_runs(
    net: Net, tguest: TailnetGuest, tmp_path: Path
) -> None:
    """Two stand-in nodes, no guest: the box's own and its unlock node, both online. Both carry the
    door's tag, because the example policy shows the keyholder nothing else."""
    own = tailnet.start_node(net.tools, net.hs, tmp_path / "own", "t13-box", "tag:unlock")
    unlock = tailnet.start_node(
        net.tools, net.hs, tmp_path / "unlock", "t13-box-unlock", "tag:unlock"
    )
    told = tmp_path / "told"
    hook = tmp_path / "alarm"
    hook.write_text(f"#!/bin/sh\ncat >>'{told}'\n")
    hook.chmod(0o755)
    delivery = Delivery(net, tmp_path, tguest, 0, "")
    (tmp_path / "keyholder.toml").write_text(f"""
[defaults]
tailscale = ["{net.tools.tailscale}", "--socket={net.keyholder.sock}"]
on_waiting = ["true"]
alarm = ["{hook}"]
alarm_after_seconds = 3
[hosts.t13-box]
node_id = "{seen_online(net.keyholder, tailnet.node_ip(own))}"
[hosts.t13-box.door]
door_key = "{tguest.door_pin}"
unlock_node_id = "{seen_online(net.keyholder, tailnet.node_ip(unlock))}"
""")
    try:
        for _ in range(2):
            code, lines = keyholder(delivery, "watch")
            assert code == 0
        assert lines == [], "told twice in one episode"
        events = [json.loads(line) for line in told.read_text().splitlines()]
        assert [event["kind"] for event in events] == ["alarm"]
    finally:
        tailnet.stop_node(own)
        tailnet.stop_node(unlock)
