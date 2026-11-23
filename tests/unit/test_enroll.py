"""`enroll` against fake tailscale and tailscaled (DESIGN.md 13.2): each stage, and each failure."""

import dataclasses
import json
import os
import re
import signal
import stat
import threading
from pathlib import Path

import pytest

import tsfake
from boxenv import SECRET, Box, with_host
from tailnet_unlock import cli
from tailnet_unlock.tailscale import BOOT_FLAGS

SUPERVISE = (Path(__file__).resolve().parents[2] / "initramfs" / "supervise").read_text()


def enroll(box: Box, *extra: str) -> int:
    return cli.main(["enroll", "--auth-key-file", str(box.key), "--no-rebuild", *extra])


def out_json(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    parsed: object = json.loads(capsys.readouterr().out)
    assert isinstance(parsed, dict)
    return {str(key): value for key, value in parsed.items()}


def assert_clean_failure(box: Box, capsys: pytest.CaptureFixture[str]) -> str:
    """Whatever went wrong: the key is gone, no staging left, nothing installed, no daemon alive."""
    err = capsys.readouterr().err
    assert not box.key.exists(), "the auth key file must be deleted on failure"
    assert box.staging == []
    assert not box.host.node_state.exists()
    assert not box.host.node_file.exists()
    assert not box.host.pins_file.exists()
    assert tsfake.live_daemons(box.root) == []
    assert SECRET not in err
    return err


def test_enroll_joins_checks_and_installs(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    assert enroll(box) == 0
    result = out_json(capsys)
    assert result["schema"] == "tailnet-unlock.enroll/1"
    assert result["changed"] is True
    assert result["node_id"] == "n1CNTRL"
    assert result["hostname"] == "box-unlock"
    assert result["dns_name"] == "box-unlock.tailnet.example"
    assert result["addresses"] == ["192.0.2.7", "2001:db8::7"]
    assert result["tags"] == ["tag:unlock"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", str(result["enrolled_at"]))

    host = box.host
    assert stat.S_IMODE(host.node_state.stat().st_mode) == 0o600
    assert stat.S_IMODE(host.tailnet_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(host.node_file.stat().st_mode) == 0o644
    assert json.loads(host.node_file.read_text())["schema"] == "tailnet-unlock.node/1"
    pins = host.pins_file.read_text()
    assert "port = 61022" in pins
    assert 'unlock_node_id = "n1CNTRL"' in pins
    assert not box.key.exists()
    assert box.staging == []
    assert tsfake.live_daemons(box.root) == []
    # the join, the proof on a copy, and each daemon stopped by SIGTERM with status 0
    assert tsfake.verbs(box.bin).count("tailscaled") == 2
    assert [c for c in tsfake.calls(box.bin) if c.get("stopped")].__len__() == 2


def test_the_second_daemon_runs_with_the_boot_flags(box: Box) -> None:
    assert enroll(box) == 0
    starts = [c for c in tsfake.calls(box.bin) if c["tool"] == "tailscaled" and "state" in c]
    argv = starts[0]["argv"]
    assert isinstance(argv, list)
    state = Path(str(starts[0]["state"]))
    assert state.parent.parent == box.host.run_dir
    assert state.name == "unlock.state"
    assert argv[0].startswith("--state=")
    assert set(argv[1:]) == {*BOOT_FLAGS, f"--socket={state.parent}/tailscaled.sock", "--port=0"}
    # the flags the initramfs gives the same daemon at boot
    for flag in BOOT_FLAGS:
        assert flag in SUPERVISE, flag


def test_tailscale_up_reads_the_key_from_its_file(box: Box) -> None:
    assert enroll(box) == 0
    ups = [c for c in tsfake.calls(box.bin) if c.get("verb") == "up"]
    assert len(ups) == 1
    argv = ups[0]["argv"]
    assert isinstance(argv, list)
    assert ups[0]["key_file_existed"] is True
    assert str(ups[0]["key_file"]) == str(box.key)
    for expected in (
        "--hostname=box-unlock",
        "--accept-dns=false",
        "--accept-routes=false",
        "--ssh=false",
        "--netfilter-mode=off",
        "--timeout=120s",
    ):
        assert expected in argv
    assert not any(str(item).startswith(("--login-server", "--advertise-tags")) for item in argv)


def test_a_login_server_is_passed_through(box: Box) -> None:
    text = (
        (box.host.config_dir / "box.toml")
        .read_text()
        .replace("[tailnet]\n", '[tailnet]\nlogin_server = "https://headscale.example.com"\n')
    )
    (box.host.config_dir / "box.toml").write_text(text)
    assert enroll(box) == 0
    ups = [c for c in tsfake.calls(box.bin) if c.get("verb") == "up"]
    argv = ups[0]["argv"]
    assert isinstance(argv, list)
    assert "--login-server=https://headscale.example.com" in argv
    assert (
        json.loads(box.host.node_file.read_text())["login_server"]
        == "https://headscale.example.com"
    )


def test_nothing_secret_in_argv_environment_or_output(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    assert enroll(box) == 0
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    for call in tsfake.calls(box.bin):
        assert SECRET not in json.dumps(call)
        env = call["env"]
        assert isinstance(env, dict)
        assert set(env) <= {"PATH", "LC_ALL", "LANG"} | {k for k in env if k.startswith("LC_")}
    for path in box.root.rglob("*"):
        if path.is_file() and path != box.bin / "calls.log":
            assert SECRET.encode() not in path.read_bytes(), path


def test_already_enrolled_contacts_nothing(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    assert enroll(box) == 0
    first = out_json(capsys)
    (box.bin / "calls.log").write_text("")
    box.write_key()
    assert enroll(box) == 0
    second = out_json(capsys)
    assert second["changed"] is False
    assert {k: v for k, v in second.items() if k != "changed"} == {
        k: v for k, v in first.items() if k != "changed"
    }
    assert tsfake.calls(box.bin) == []
    assert not box.key.exists()


def test_replace_enrolls_again_and_names_the_old_node(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    assert enroll(box) == 0
    capsys.readouterr()
    tsfake.set_scenario(box.bin, node_id="n2CNTRL")
    box.write_key()
    assert enroll(box, "--replace") == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["node_id"] == "n2CNTRL"
    assert "n1CNTRL" in captured.err
    assert json.loads(box.host.node_file.read_text())["node_id"] == "n2CNTRL"


def test_a_state_that_is_not_sealed_is_never_overwritten_silently(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    box.host.tailnet_dir.mkdir()
    box.host.node_state.write_text('{"_machinekey": "privkey:00"}')
    assert enroll(box) == 2
    assert "--replace" in capsys.readouterr().err
    assert tsfake.calls(box.bin) == []
    assert not box.key.exists()


@pytest.mark.parametrize(
    "case",
    ["disabled", "no-tpm", "no-tailscale", "old-tailscale", "old-tailscaled"],
)
def test_refusals_before_any_contact(
    box: Box, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    if case == "disabled":
        (box.host.config_dir / "box.toml").write_text(
            (box.host.config_dir / "box.toml")
            .read_text()
            .replace("[tailnet]\n", "[tailnet]\nenabled = false\n")
        )
    elif case == "no-tpm":
        box.host.tpm_device.unlink()
    elif case == "no-tailscale":
        monkeypatch.setenv("PATH", "/nonexistent")
    elif case == "old-tailscale":
        tsfake.set_scenario(box.bin, version_tailscale="1.80.2")
    else:
        tsfake.set_scenario(box.bin, version_tailscaled="1.85.9")
    assert enroll(box) == 2
    err = capsys.readouterr().err
    assert err.startswith("tailnet-unlock: ")
    assert [c for c in tsfake.calls(box.bin) if "verb" in c or "state" in c] == []
    assert box.staging == []
    assert not box.host.node_state.exists()
    assert not box.key.exists() or case == "disabled"


@pytest.mark.parametrize("tcti", ["TPM2TOOLS_TCTI", "TSS2_TCTI"])
def test_a_tcti_override_is_refused(
    box: Box, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tcti: str
) -> None:
    monkeypatch.setenv(tcti, "swtpm:port=2321")
    assert enroll(box) == 2
    assert tcti in capsys.readouterr().err
    monkeypatch.setenv(tcti, "device:/dev/tpmrm0")
    assert enroll(box) == 0


def test_enroll_needs_root(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    import os

    if os.geteuid() == 0:
        pytest.skip("this test runs as root")
    with_host(dataclasses.replace(box.host, require_root=True))
    assert enroll(box) == 2
    assert "root" in capsys.readouterr().err


@pytest.mark.parametrize("problem", ["mode", "empty", "symlink", "directory", "missing"])
def test_a_bad_key_file_is_refused_and_left_alone(
    box: Box, capsys: pytest.CaptureFixture[str], problem: str
) -> None:
    target = box.root / "real-key"
    if problem == "mode":
        box.write_key(mode=0o644)
    elif problem == "empty":
        box.write_key(text="")
    elif problem == "symlink":
        target.write_text(SECRET)
        target.chmod(0o600)
        box.key.unlink()
        box.key.symlink_to(target)
    elif problem == "directory":
        box.key.unlink()
        box.key.mkdir()
    else:
        box.key.unlink()
    assert enroll(box) == 2
    assert capsys.readouterr().err.startswith("tailnet-unlock: ")
    assert tsfake.calls(box.bin) == []
    if problem == "symlink":
        assert target.exists(), "a symlink's target is never touched"
    elif problem != "missing":
        assert box.key.exists() or problem == "directory"


@pytest.mark.parametrize(
    ("scenario", "message", "logout"),
    [
        ({"up_fails": True}, "tailscale up failed", True),
        ({"tags": ["tag:other"]}, "tags", True),
        ({"tags": []}, "tags", True),
        ({"state_kind": "plain"}, "sealed", True),
        ({"proof_fails": True}, "exited", True),
        ({"kill_daemon_on_up": True}, "exited", True),
        ({"ignore_term": True}, "killed", True),
        ({"term_exit_code": 3}, "status 3", True),
        ({"never_running": True}, "timed out", True),
    ],
)
def test_failure_after_the_join_logs_the_node_out_and_cleans_up(
    box: Box,
    capsys: pytest.CaptureFixture[str],
    scenario: dict[str, object],
    message: str,
    logout: bool,
) -> None:
    tsfake.set_scenario(box.bin, **scenario)
    assert enroll(box, "--timeout", "2") == 2
    err = assert_clean_failure(box, capsys)
    assert message in err
    assert err.startswith("tailnet-unlock: ")
    assert ("logout" in tsfake.verbs(box.bin)) is logout


def test_a_failed_logout_names_the_node_to_delete(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    tsfake.set_scenario(box.bin, tags=["tag:other"], logout_fails=True)
    assert enroll(box) == 2
    err = assert_clean_failure(box, capsys)
    assert "n1CNTRL" in err
    assert "admin console" in err


def test_the_node_state_is_not_installed_when_it_is_unsealed(box: Box) -> None:
    tsfake.set_scenario(box.bin, state_kind="plain")
    assert enroll(box) == 2
    assert not box.host.node_state.exists()


def test_a_previous_enrollment_survives_a_failed_replacement(box: Box) -> None:
    assert enroll(box) == 0
    before = box.host.node_state.read_bytes()
    tsfake.set_scenario(box.bin, up_fails=True)
    box.write_key()
    assert enroll(box, "--replace") == 2
    assert box.host.node_state.read_bytes() == before
    assert json.loads(box.host.node_file.read_text())["node_id"] == "n1CNTRL"


def test_a_failed_install_puts_the_previous_enrollment_back(
    box: Box, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tailnet_unlock import enroll as module

    assert enroll(box) == 0
    files = (box.host.node_state, box.host.node_file, box.host.pins_file)
    before = [path.read_bytes() for path in files]

    def fail(*args: object) -> None:
        del args
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(module, "write_node", fail)
    tsfake.set_scenario(box.bin, node_id="n2CNTRL")
    box.write_key()
    assert enroll(box, "--replace") == 2
    assert [path.read_bytes() for path in files] == before
    assert "logout" in tsfake.verbs(box.bin)
    assert box.staging == []
    capsys.readouterr()


def test_a_key_file_with_another_link_is_refused(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    (box.root / "other").hardlink_to(box.key)
    assert enroll(box) == 2
    assert "hard links" in capsys.readouterr().err
    assert box.key.exists()


def test_a_key_in_a_tools_message_is_masked(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    from tailnet_unlock.tailscale import one_line

    assert SECRET not in one_line(f"x\nbad key {SECRET} given")
    assert "tskey-***" in one_line(f"bad key {SECRET}")


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGHUP])
def test_a_signal_while_joining_cleans_up_like_a_failure(
    box: Box, capsys: pytest.CaptureFixture[str], number: signal.Signals
) -> None:
    tsfake.set_scenario(box.bin, never_running=True)
    timer = threading.Timer(1.5, os.kill, (os.getpid(), number))
    timer.start()
    try:
        with pytest.raises(SystemExit) as left:
            enroll(box, "--timeout", "30")
    finally:
        timer.cancel()
    assert left.value.code == 128 + number
    assert_clean_failure(box, capsys)


def test_enroll_after_rebuild_runs_the_rebuild_and_verify(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without --no-rebuild the images are rebuilt and read back; no images is a problem."""
    code = cli.main(["enroll", "--auth-key-file", str(box.key)])
    assert code == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["changed"] is True
    assert "no-images" in captured.err
