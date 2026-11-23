"""Process handling of `enroll` against the real tailscaled (DESIGN.md 13.2), with no TPM.

`--encrypt-state` needs /dev/tpmrm0, which a container lacks, and a real join needs a control
server, which a test has not. So this checks what can be checked for real: the daemon starts with
its flags, answers on its socket, stops cleanly on SIGTERM with status 0 (the property `enroll`
relies on), a join that cannot happen fails the way `enroll` reports it, the logout is tried, and
nothing is left behind: no process, no staging directory, no key file. The state is not encrypted
here through an internal seam of the `Host` value (`encrypt_state=False`), never a command line
option; the real TPM join is the VM scenarios' job.
"""

import dataclasses
import os
import shutil
from pathlib import Path

import pytest

from tailnet_unlock import tailscale
from tailnet_unlock.config import parse_box_config
from tailnet_unlock.enroll import EnrollRequest, enroll
from tailnet_unlock.errors import ToolError
from tailnet_unlock.system import Host

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(
        os.environ.get("TU_TEST_CONTAINER") != "1" or os.getuid() != 0,
        reason="starts daemons as root: test container only",
    ),
    pytest.mark.skipif(shutil.which("tailscaled") is None, reason="needs tailscaled"),
]

BOX_TOML = """[network]
interface = "eth0"

[tailnet]
hostname = "box-unlock"
login_server = "https://127.0.0.1:9"
"""


@pytest.fixture
def host(tmp_path: Path) -> Host:
    run = Path("/dev/shm") / f"tu-enroll-{os.getpid()}"
    made = dataclasses.replace(
        Host(),
        state_root=tmp_path / "state",
        config_dir=tmp_path / "etc",
        run_dir=run,
        tpm_device=Path("/dev/null"),
        encrypt_state=False,
    )
    made.config_dir.mkdir()
    (made.config_dir / "box.toml").write_text(BOX_TOML)
    made.state_root.mkdir()
    return made


def processes_using(path: Path) -> list[int]:
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if str(path).encode() in command and entry.name != str(os.getpid()):
            found.append(int(entry.name))
    return found


def test_the_real_daemon_answers_and_stops_cleanly_on_sigterm(tmp_path: Path) -> None:
    tools = tailscale.find_tools()
    daemon = tailscale.start_daemon(
        tools, tmp_path / "state", tmp_path / "ts.sock", tmp_path / "ts.log", encrypt_state=False
    )
    try:
        status = tailscale.wait_for(tools, daemon, lambda _: True, 30, "tailscaled")
        assert status.backend_state in {"NeedsLogin", "NoState", "Stopped"}
        assert status.node_id == ""
    except BaseException:
        tailscale.kill_daemon(daemon)
        raise
    tailscale.stop_daemon(daemon, 20)
    assert daemon.process.returncode == 0


def test_a_join_that_cannot_happen_fails_cleanly(host: Host, tmp_path: Path) -> None:
    key = tmp_path / "key"
    key.write_text("tskey-auth-kTEST000000000000-notarealkeynotarealkeynotarealkey\n")
    key.chmod(0o600)
    config = parse_box_config((host.config_dir / "box.toml").read_text())
    request = EnrollRequest(key, replace=False, timeout=8, hostname="box-unlock")
    with pytest.raises(ToolError) as caught:
        enroll(host, config, request)
    assert "tailscale up failed" in str(caught.value)
    assert "tskey" not in str(caught.value)
    assert not key.exists()
    assert not host.node_state.exists()
    assert not host.node_file.exists()
    leftover = list(host.run_dir.glob("*")) if host.run_dir.exists() else []
    assert leftover == []
    assert processes_using(host.run_dir) == []
    shutil.rmtree(host.run_dir, ignore_errors=True)
