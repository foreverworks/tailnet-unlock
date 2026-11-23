"""`verify` on real images built with mkinitramfs (DESIGN.md 12.5): the hook's build, read back.

The image carries the real tailscaled of the test container, so the version in the hook's conf and
the one the extracted binary reports are both real. The node state is a stand-in shaped like
Tailscale's sealed store (a real one needs a TPM device, which a container lacks).
"""

import dataclasses
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from imagekit import CONFIG, STATE, Installed, build, install_box
from imagetree import configure_node
from tailnet_unlock import cli
from tailnet_unlock.system import Host
from tsfake import sealed_state

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(
        os.environ.get("TU_TEST_CONTAINER") != "1" or os.getuid() != 0,
        reason="changes the system: test container only",
    ),
    pytest.mark.skipif(shutil.which("mkinitramfs") is None, reason="needs initramfs-tools"),
]


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Installed]:
    work = tmp_path_factory.mktemp("verify-image")
    yield install_box(work, work / "tpm")


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Host]:
    # the unpacked image (the kernel's modules, tailscaled) needs more room than Docker's
    # 64 MiB /dev/shm, so the work directory is a tmpfs of its own (the tier runs privileged)
    run = tmp_path / "run"
    run.mkdir()
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=1g", "tmpfs", str(run)], check=True)
    real = dataclasses.replace(Host(), run_dir=run)
    monkeypatch.setattr(cli, "HOST", real)
    try:
        yield real
    finally:
        subprocess.run(["umount", str(run)], check=True)


def boot_with(installed: Installed, boot: Path, name: str) -> None:
    image = build(installed, name)
    assert image.returncode == 0, image.stderr
    boot.mkdir(exist_ok=True)
    shutil.copy(image.path, boot / f"initrd.img-{installed.kernel}")


def verify(boot: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> dict[str, object]:
    capsys.readouterr()
    cli.main(["verify", "--json", "--boot-dir", str(boot), *extra])
    parsed: object = json.loads(capsys.readouterr().out)
    assert isinstance(parsed, dict)
    return {str(key): value for key, value in parsed.items()}


def problems_of(result: dict[str, object]) -> list[str]:
    found = result["problems"]
    assert isinstance(found, list)
    return [str(item) for item in found]


def test_an_enrolled_image_verifies_and_each_staleness_is_found(
    installed: Installed,
    host: Host,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = configure_node(host, sealed_state())
    boot = tmp_path / "boot"
    boot_with(installed, boot, "verify-ok")
    result = verify(boot, capsys)
    assert problems_of(result) == [], result
    images = result["images"]
    assert isinstance(images, list)
    image = images[0]
    assert image["door"] == "sealed"
    assert image["recovery"] is True
    assert image["tailnet"] is True
    assert image["degraded"] == []
    assert image["port"] == 2222
    assert image["profile"] == "tpm"
    assert str(image["tailscaled_version"]).startswith("1.")
    assert image["tailscaled_version"] == image["conf_tailscaled_version"]
    assert image["state_sealed"] is True
    assert image["state_identical"] is True
    assert image["authorized_keys_current"] is True
    assert image["local_key"] is False

    # a floor above the installed tailscaled is a problem the image reports
    result = verify(boot, capsys, "--tailscale-floor", "9.0.0")
    assert f"initrd.img-{installed.kernel}: version-below-floor" in problems_of(result)

    # the box's state changes after the image was built: stale
    (STATE / "tailnet" / "unlock.state").write_bytes(
        sealed_state().replace(b"ZGF0YQ==", b"b3Rocg==")
    )
    assert (STATE / "tailnet" / "unlock.state").read_bytes() != state
    result = verify(boot, capsys)
    assert f"initrd.img-{installed.kernel}: state-stale" in problems_of(result)
    (STATE / "tailnet" / "unlock.state").write_bytes(state)

    # the keyholders change after the image was built: stale keys
    keys = CONFIG / "delivery_keys"
    original = keys.read_text()
    keys.write_text(original + original.replace("keyholder", "second").replace("K", "L", 5))
    try:
        result = verify(boot, capsys)
        assert f"initrd.img-{installed.kernel}: keys-stale" in problems_of(result)
    finally:
        keys.write_text(original)


def test_an_image_with_a_plain_state_is_refused(
    installed: Installed,
    host: Host,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The hook copies whatever is in STATE; verify is what notices it is not a sealed store."""
    configure_node(host, b'{"_machinekey": "privkey:00", "_daemon": "x"}')
    boot = tmp_path / "boot"
    boot_with(installed, boot, "verify-plain")
    result = verify(boot, capsys)
    assert any("state-unsealed" in problem for problem in problems_of(result))
    assert result["ok"] is False


def test_a_tailnet_that_is_off_must_not_leave_tailscaled_in_the_image(
    installed: Installed,
    host: Host,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_node(host, sealed_state())
    boot = tmp_path / "boot"
    boot_with(installed, boot, "verify-off")
    box_toml = CONFIG / "box.toml"
    original = box_toml.read_text()
    box_toml.write_text(original.replace("enabled = true", "enabled = false"))
    try:
        result = verify(boot, capsys)
        assert f"initrd.img-{installed.kernel}: tailnet-unexpected" in problems_of(result)
        boot_with(installed, boot, "verify-off-rebuilt")
        result = verify(boot, capsys)
        assert problems_of(result) == [], result
    finally:
        box_toml.write_text(original)
