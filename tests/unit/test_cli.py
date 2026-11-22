from pathlib import Path

from keys import ALICE, KEYHOLDER
from tailnet_unlock.cli import MAX_STDIN, _read_input, main


def write_config(directory: Path, box: str) -> None:
    directory.mkdir()
    (directory / "box.toml").write_text(box)
    (directory / "delivery_keys").write_text(KEYHOLDER + "\n")
    (directory / "operator_keys").write_text(ALICE + "\n")


def test_render_initramfs(tmp_path: Path) -> None:
    config = tmp_path / "etc"
    write_config(config, '[network]\ninterface = "eno1"\n')
    out = tmp_path / "out"
    assert (
        main(
            ["render-initramfs", "--config-dir", str(config), "--out", str(out), "--host", "web-1"]
        )
        == 0
    )
    conf = (out / "tailnet-unlock.conf").read_text()
    assert "TU_PORT=2222" in conf
    assert "TU_UNLOCK_HOSTNAME=web-1-unlock" in conf
    keys = (out / "authorized_keys").read_text()
    assert 'command="/usr/lib/tailnet-unlock/door delivery"' in keys
    assert oct((out / "authorized_keys").stat().st_mode & 0o777) == "0o600"


def test_render_refuses_an_invalid_configuration(tmp_path: Path, capsys: object) -> None:
    config = tmp_path / "etc"
    write_config(config, "[door]\nport = 99999\n")
    assert (
        main(["render-initramfs", "--config-dir", str(config), "--out", str(tmp_path / "out")]) == 2
    )


def test_render_refuses_a_door_nobody_can_log_in_to(tmp_path: Path) -> None:
    config = tmp_path / "etc"
    write_config(config, '[network]\ninterface = "eno1"\n')
    (config / "delivery_keys").write_text("")
    (config / "operator_keys").unlink()
    assert (
        main(["render-initramfs", "--config-dir", str(config), "--out", str(tmp_path / "out")]) == 2
    )


def test_a_file_input_is_capped_while_it_is_read() -> None:
    # /dev/zero never ends: reading it whole first, then cutting, would never return
    assert len(_read_input("/dev/zero")) == MAX_STDIN + 1


def test_a_small_file_input_is_read_whole(tmp_path: Path) -> None:
    small = tmp_path / "key"
    small.write_bytes(b"abc")
    assert _read_input(str(small)) == b"abc"
