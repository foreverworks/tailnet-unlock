"""`disable --tailnet`, `status` and `pins` (DESIGN.md 12.5, 13.4)."""

import dataclasses
import json
from pathlib import Path

import pytest

import tsfake
from boxenv import Box, with_host
from imagetree import Tree, add_image, configure_door, configure_node, install_fake_unmkinitramfs
from tailnet_unlock import cli


def out(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    parsed: object = json.loads(capsys.readouterr().out)
    assert isinstance(parsed, dict)
    return {str(key): value for key, value in parsed.items()}


def test_disable_logs_out_wipes_and_reports_the_node(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_node(box.host)
    box.host.pins_file.write_text('port = 61022\nunlock_node_id = "n1CNTRL"\n')
    assert cli.main(["disable", "--tailnet", "--no-rebuild"]) == 0
    result = out(capsys)
    assert result == {
        "schema": "tailnet-unlock.disable/1",
        "changed": True,
        "node_id": "n1CNTRL",
        "logged_out": True,
    }
    assert "logout" in tsfake.verbs(box.bin)
    assert not box.host.tailnet_dir.exists()
    assert box.host.pins_file.read_text() == "port = 61022\n"
    assert box.staging == []
    assert tsfake.live_daemons(box.root) == []


def test_disable_is_idempotent(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    configure_node(box.host)
    assert cli.main(["disable", "--tailnet", "--no-rebuild"]) == 0
    capsys.readouterr()
    (box.bin / "calls.log").write_text("")
    assert cli.main(["disable", "--tailnet", "--no-rebuild"]) == 0
    assert out(capsys) == {
        "schema": "tailnet-unlock.disable/1",
        "changed": False,
        "node_id": None,
        "logged_out": False,
    }
    assert tsfake.calls(box.bin) == []


def test_no_logout_contacts_nothing(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    configure_node(box.host)
    assert cli.main(["disable", "--tailnet", "--no-rebuild", "--no-logout"]) == 0
    assert out(capsys)["logged_out"] is False
    assert tsfake.calls(box.bin) == []
    assert not box.host.tailnet_dir.exists()


@pytest.mark.parametrize("scenario", [{"logout_fails": True}, {"never_running": True}])
def test_a_failed_logout_still_deletes_and_says_so(
    box: Box, capsys: pytest.CaptureFixture[str], scenario: dict[str, object]
) -> None:
    with_host(dataclasses.replace(box.host, logout_timeout=2))
    tsfake.set_scenario(box.bin, **scenario)
    configure_node(box.host)
    state_dir = box.host.tailnet_dir
    assert cli.main(["disable", "--tailnet", "--no-rebuild"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["changed"] is True
    assert result["logged_out"] is False
    assert "n1CNTRL" in captured.err
    assert "admin console" in captured.err
    assert not state_dir.exists()
    assert box.staging == []
    assert tsfake.live_daemons(box.root) == []


def test_disable_without_tailscale_installed_still_deletes(
    box: Box, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    configure_node(box.host)
    monkeypatch.setenv("PATH", "/nonexistent")
    assert cli.main(["disable", "--tailnet", "--no-rebuild"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["logged_out"] is False
    assert "warning" in captured.err
    assert not box.host.tailnet_dir.exists()


def test_disable_needs_to_be_told_what(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["disable"]) == 2
    assert "--tailnet" in capsys.readouterr().err


def test_disable_rebuilds_and_passes_when_no_image_keeps_the_tailnet(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    install_fake_unmkinitramfs(box.host)
    configure_door(box.host)
    configure_node(box.host)
    add_image(box.host, "6.12.0-test", Tree(), box.root / "trees")
    assert cli.main(["disable", "--tailnet", "--no-logout"]) == 0
    assert not box.host.tailnet_dir.exists()


def test_disable_fails_when_an_image_still_carries_the_tailnet(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    install_fake_unmkinitramfs(box.host)
    configure_door(box.host)
    state = configure_node(box.host)
    stale = Tree(tailnet=True, tailscaled="1.104.7", conf_version="1.104.7", state=state)
    add_image(box.host, "6.12.0-test", stale, box.root / "trees")
    assert cli.main(["disable", "--tailnet", "--no-logout"]) == 1
    assert "tailnet-unexpected" in capsys.readouterr().err


def test_status_before_and_after_enrollment(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["status"]) == 0
    text = capsys.readouterr().out
    assert "not enrolled" in text
    assert "no record" in text
    assert cli.main(["status", "--json"]) == 0
    before = out(capsys)
    assert before["schema"] == "tailnet-unlock.status/1"
    assert before["node"] is None
    configure_node(box.host)
    configure_door(box.host)
    box.host.run_dir.mkdir()
    box.host.boot_record.write_text(
        '{"schema":"tailnet-unlock.boot/1","unlocked_by":"sealed door","door":"sealed",'
        '"profile":"tpm","seal":"ok","degraded":[]}\n'
    )
    assert cli.main(["status", "--json"]) == 0
    after = out(capsys)
    node = after["node"]
    assert isinstance(node, dict)
    assert node["node_id"] == "n1CNTRL"
    boot = after["boot"]
    assert isinstance(boot, dict)
    assert boot["unlocked_by"] == "sealed door"
    door = after["door"]
    assert isinstance(door, dict)
    assert str(door["sealed_fingerprint"]).startswith("SHA256:")
    config = after["config"]
    assert isinstance(config, dict)
    assert config["port"] == 61022
    assert cli.main(["status"]) == 0
    assert "unlocked by sealed door" in capsys.readouterr().out


def test_status_exits_zero_for_a_broken_configuration(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    (box.host.config_dir / "box.toml").write_text("[door]\nport = 99999\n")
    assert cli.main(["status"]) == 0
    assert "invalid" in capsys.readouterr().out


def test_pins_port_comes_from_box_toml(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    configure_door(box.host)
    assert cli.main(["pins"]) == 0
    text = capsys.readouterr().out
    assert "port = 61022\n" in text
    assert "port = 2222" not in text
    assert 'door_key = "ssh-ed25519 ' in text
    assert "unlock_node_id" not in text
    configure_node(box.host)
    assert cli.main(["pins"]) == 0
    assert 'unlock_node_id = "n1CNTRL"' in capsys.readouterr().out
    assert cli.main(["pins", "--port", "2222"]) == 0
    assert "port = 2222\n" in capsys.readouterr().out


def test_pins_without_box_toml_needs_a_port(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    configure_door(box.host)
    (box.host.config_dir / "box.toml").unlink()
    assert cli.main(["pins"]) == 2
    assert "box.toml" in capsys.readouterr().err
    assert cli.main(["pins", "--port", "2222"]) == 0


def test_pins_dirs_can_be_given_on_the_command_line(
    box: Box, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_door(box.host)
    assert (
        cli.main(
            [
                "pins",
                "--state-dir",
                str(box.host.door_dir),
                "--config-dir",
                str(box.host.config_dir),
            ]
        )
        == 0
    )
    assert "port = 61022" in capsys.readouterr().out


def test_a_static_uplink_address_is_recorded_in_the_pins(
    box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_door(box.host)
    path = box.host.config_dir / "box.toml"
    path.write_text(
        path.read_text().replace(
            "[network]\n", '[network]\nmode = "static"\naddress = "192.0.2.10/24"\n'
        )
    )
    assert cli.main(["pins"]) == 0
    assert 'uplink = "192.0.2.10"' in capsys.readouterr().out
