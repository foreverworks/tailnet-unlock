"""`verify` over hand-made image trees (DESIGN.md 12.5), and the layering it promises.

A box with the tailnet off and no Tailscale installed must verify like any other: the door's
checks never reach for Tailscale.
"""

import ast
import json
import os
import shutil
from pathlib import Path

import pytest

import tsfake
from boxenv import Box
from imagetree import (
    Tree,
    add_image,
    configure_door,
    configure_node,
    install_fake_unmkinitramfs,
)
from tailnet_unlock import cli
from tailnet_unlock.sealedstate import sealed_problem

SRC = Path(__file__).resolve().parents[2] / "src" / "tailnet_unlock"
KERNEL = "6.12.0-test"


def run_verify(capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, dict[str, object]]:
    code = cli.main(["verify", "--json", *extra])
    parsed: object = json.loads(capsys.readouterr().out)
    assert isinstance(parsed, dict)
    return code, {str(key): value for key, value in parsed.items()}


def problems_of(result: dict[str, object]) -> list[str]:
    found = result["problems"]
    assert isinstance(found, list)
    return [str(item) for item in found]


@pytest.fixture
def door_box(box: Box) -> Box:
    install_fake_unmkinitramfs(box.host)
    configure_door(box.host)
    return box


def set_tailnet(box: Box, enabled: bool) -> None:
    path = box.host.config_dir / "box.toml"
    path.write_text(
        path.read_text().replace("[tailnet]\n", f"[tailnet]\nenabled = {str(enabled).lower()}\n")
    )


def test_a_door_only_box_verifies_with_no_tailscale_at_all(
    door_box: Box, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    set_tailnet(door_box, False)
    add_image(door_box.host, KERNEL, Tree(), door_box.root / "trees")
    # a PATH with nothing but the fake unmkinitramfs and cp: no tailscale, tailscaled, zfs or ip
    monkeypatch.setenv("PATH", str(Path(door_box.host.unmkinitramfs).parent))
    assert shutil.which("tailscale") is None
    code, result = run_verify(capsys)
    assert code == 0, result
    assert result["schema"] == "tailnet-unlock.verify/1"
    assert result["ok"] is True
    images = result["images"]
    assert isinstance(images, list)
    assert images[0]["door"] == "sealed"
    assert images[0]["tailnet"] is False
    assert images[0]["recovery"] is True
    assert images[0]["problems"] == []
    assert images[0]["local_key"] is False
    assert images[0]["tailscaled_version"] is None


def test_a_door_problem_is_found_without_tailscale_too(
    door_box: Box, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    set_tailnet(door_box, False)
    add_image(door_box.host, KERNEL, Tree(door="none", pin=None), door_box.root / "trees")
    monkeypatch.setenv("PATH", str(Path(door_box.host.unmkinitramfs).parent))
    code, result = run_verify(capsys)
    assert code == 1
    assert "initrd.img-6.12.0-test: door-absent" in problems_of(result)


def test_the_door_modules_never_import_the_tailscale_module() -> None:
    """Door keys, sealing, config, rendering, images and verify stay clear of tailscale.py."""
    allowed = {"enroll", "disable", "checks", "cli", "tailscale"}
    for path in sorted(SRC.rglob("*.py")):
        module = path.stem
        tree = ast.parse(path.read_text())
        imported = {
            name
            for node in ast.walk(tree)
            for name in (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""] + [f"{node.module}.{alias.name}" for alias in node.names]
                if isinstance(node, ast.ImportFrom)
                else []
            )
        }
        touches = any(
            name.endswith("tailscale") and name.startswith("tailnet_unlock") for name in imported
        )
        if module not in allowed:
            assert not touches, f"{path.name} imports tailscale.py"


def test_the_door_check_does_not_run_tailscale_even_when_the_tailnet_is_on(
    door_box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unenrolled with the tailnet on is its own problem, and an allowed one."""
    add_image(door_box.host, KERNEL, Tree(), door_box.root / "trees")
    code, result = run_verify(capsys)
    assert code == 1
    assert problems_of(result) == ["tailnet-not-enrolled"]
    code, result = run_verify(capsys, "--allow-unenrolled")
    assert code == 0
    assert result["ok"] is True


def test_an_uplink_only_hook_degradation_is_not_a_door_problem_when_unenrolled(
    door_box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    add_image(
        door_box.host,
        KERNEL,
        Tree(degraded="tailnet-state-missing"),
        door_box.root / "trees",
    )
    code, _ = run_verify(capsys, "--allow-unenrolled")
    assert code == 0


@pytest.fixture
def enrolled(door_box: Box, monkeypatch: pytest.MonkeyPatch) -> tuple[Box, bytes]:
    state = configure_node(door_box.host)
    monkeypatch.setenv("PATH", f"{door_box.bin}:{os.environ['PATH']}")
    return door_box, state


def healthy(node_state: bytes, **changes: object) -> Tree:
    base = Tree(tailnet=True, tailscaled="1.104.7", conf_version="1.104.7", state=node_state)
    return Tree(**{**base.__dict__, **changes})


def test_an_enrolled_box_with_a_tailnet_image_is_ok(
    enrolled: tuple[Box, bytes], capsys: pytest.CaptureFixture[str]
) -> None:
    door_box, state = enrolled
    add_image(door_box.host, KERNEL, healthy(state), door_box.root / "trees")
    code, result = run_verify(capsys)
    assert code == 0, result
    images = result["images"]
    assert isinstance(images, list)
    assert images[0]["tailscaled_version"] == "1.104.7"
    assert images[0]["state_sealed"] is True
    assert images[0]["state_identical"] is True
    assert images[0]["authorized_keys_current"] is True


@pytest.mark.parametrize(
    ("tree", "code", "extra"),
    [
        (
            {"tailnet": False, "tailscaled": None, "state": None, "conf_version": ""},
            "tailnet-absent",
            (),
        ),
        ({"state": b'{"_machinekey": "privkey:00"}'}, "state-unsealed", ()),
        ({"state": tsfake.sealed_state().replace(b"cHJpdmF0ZQ==", b"b3RoZXI=")}, "state-stale", ()),
        ({"tailscaled": "1.80.0", "conf_version": "1.80.0"}, "version-below-floor", ()),
        ({}, "version-below-floor", ("--tailscale-floor", "1.200.0")),
        ({"conf_version": "1.90.0"}, "version-mismatch", ()),
        ({"tailscaled": "1.100.0", "conf_version": "1.100.0"}, "version-older-than-installed", ()),
        ({"door": "recovery", "pin": None}, "sealed-door-absent", ()),
        ({"pin": "ssh-ed25519 AAAAdifferent"}, "door-pin-differs", ()),
        ({"door": "none", "pin": None, "recovery": False}, "door-absent", ()),
        ({"conf": False, "pin": None, "recovery": False}, "door-absent", ()),
        ({"degraded": "recovery-key-missing"}, "degraded", ()),
        ({"keys": "ssh-ed25519 stale\n"}, "keys-stale", ()),
        ({"recovery_key": b"an older recovery key"}, "recovery-key-stale", ()),
    ],
)
def test_each_problem_is_named(
    enrolled: tuple[Box, bytes],
    capsys: pytest.CaptureFixture[str],
    tree: dict[str, object],
    code: str,
    extra: tuple[str, ...],
) -> None:
    door_box, state = enrolled
    (door_box.host.door_dir / "recovery_host_key").write_bytes(b"recovery-key")
    add_image(door_box.host, KERNEL, healthy(state, **tree), door_box.root / "trees")
    exit_code, result = run_verify(capsys, *extra)
    assert exit_code == 1
    assert f"initrd.img-{KERNEL}: {code}" in problems_of(result)


def test_a_tailnet_that_is_off_must_leave_no_tailscaled_or_state_in_any_image(
    door_box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    set_tailnet(door_box, False)
    state = tsfake.sealed_state()
    add_image(door_box.host, "6.1.0-old", healthy(state), door_box.root / "trees")
    add_image(door_box.host, "6.12.0-new", Tree(), door_box.root / "trees")
    code, result = run_verify(capsys)
    assert code == 1
    assert problems_of(result) == ["initrd.img-6.1.0-old: tailnet-unexpected"]


def test_a_local_key_is_reported_and_is_not_a_problem(
    door_box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    set_tailnet(door_box, False)
    add_image(
        door_box.host,
        KERNEL,
        Tree(extra_files={"etc/zfs/keys/rpool.key": b"0" * 32}),
        door_box.root / "trees",
    )
    code, result = run_verify(capsys)
    assert code == 0
    images = result["images"]
    assert isinstance(images, list)
    assert images[0]["local_key"] is True


def test_an_unreadable_image_is_a_problem_and_the_rest_are_still_read(
    door_box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    set_tailnet(door_box, False)
    add_image(door_box.host, KERNEL, Tree(), door_box.root / "trees")
    (door_box.host.boot_dir / "initrd.img-6.1.0-broken").write_text("FAIL")
    (door_box.host.boot_dir / "initrd.img-6.1.0-x.dpkg-bak").write_text("FAIL")
    code, result = run_verify(capsys)
    assert code == 1
    assert [p.split(" (")[0] for p in problems_of(result)] == [
        "initrd.img-6.1.0-broken: unreadable"
    ]


def test_no_images_is_a_problem(door_box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    set_tailnet(door_box, False)
    code, result = run_verify(capsys)
    assert code == 1
    assert problems_of(result) == ["no-images"]


def test_text_output_names_each_problem(door_box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    set_tailnet(door_box, False)
    add_image(door_box.host, KERNEL, Tree(keys="stale\n"), door_box.root / "trees")
    assert cli.main(["verify"]) == 1
    text = capsys.readouterr().out
    assert "PROBLEMS" in text
    assert "keys-stale:" in text
    assert "verify found problems" in text


def test_verify_needs_a_configured_box(door_box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    (door_box.host.config_dir / "box.toml").unlink()
    assert cli.main(["verify"]) == 2
    assert "box.toml" in capsys.readouterr().err


def test_the_images_are_unpacked_in_a_private_directory_that_is_wiped(
    door_box: Box, capsys: pytest.CaptureFixture[str]
) -> None:
    set_tailnet(door_box, False)
    add_image(door_box.host, KERNEL, Tree(), door_box.root / "trees")
    cli.main(["verify"])
    assert list(door_box.host.run_dir.glob("*")) == []


SEALED_OK = tsfake.sealed_state()


def test_sealed_state_check() -> None:
    assert sealed_problem(SEALED_OK) is None
    for bad in (
        b"",
        b"not json",
        b"[]",
        b'{"_machinekey": "privkey:00", "_daemon": "x"}',
        b'{"key": {"Private": "AA==", "Public": "AA=="}, "nonce": "AA==", "data": "AA=="}',
        json.dumps({"key": None, "nonce": "", "data": ""}).encode(),
        json.dumps({**json.loads(SEALED_OK), "extra": 1}).encode(),
    ):
        assert sealed_problem(bad) is not None, bad
