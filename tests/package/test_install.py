"""Install, upgrade, remove and purge the .deb with apt and dpkg in the Debian test container.

The package is built here by tools/build-deb and installed for real, so what runs is what a box
gets: the files and their modes, the trigger that rebuilds the initramfs images when tailscaled
changes (with update-initramfs made to fail, the package must still configure), the guard that
refuses removal while the box unlocks through its door (with a fake `zfs` first on PATH), the
upgrade that the guard lets through, and the purge that leaves nothing of ours behind.

It changes the container's /usr, /etc and /var, so it runs only there (TU_TEST_CONTAINER=1).
"""

import os
import shutil
import stat
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from shellenv import REPO

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(
        os.environ.get("TU_TEST_CONTAINER") != "1" or os.getuid() != 0,
        reason="changes the system: test container only",
    ),
]

EPOCH = "1700000000"
CONFIG = Path("/etc/tailnet-unlock")
STATE = Path("/var/lib/tailnet-unlock")
DOOR = STATE / "door" / "door.tpm"
UPDATE = Path("/usr/sbin/update-initramfs")
UPDATE_KEPT = Path("/usr/sbin/update-initramfs.real")
CALLS = Path("/run/tu-update-initramfs.calls")
FAKE_BIN = Path("/run/tu-fakebin")
FAKE_ZFS_OUT = Path("/run/tu-zfs.out")

# the files the package puts on the box (install-tree's list, the command, the documents)
FILES = {
    "/usr/sbin/tailnet-unlock": 0o755,
    "/usr/lib/tailnet-unlock/door": 0o755,
    "/usr/lib/tailnet-unlock/supervise": 0o755,
    "/usr/lib/tailnet-unlock/unseal": 0o755,
    "/usr/lib/tailnet-unlock/lib.sh": 0o644,
    "/usr/lib/tailnet-unlock/paths.sh": 0o644,
    "/usr/share/initramfs-tools/hooks/tailnet-unlock": 0o755,
    "/usr/share/initramfs-tools/scripts/init-premount/tailnet-unlock": 0o755,
    "/usr/share/initramfs-tools/scripts/init-bottom/tailnet-unlock": 0o755,
    "/usr/share/initramfs-tools/scripts/panic/tailnet-unlock": 0o755,
    "/usr/share/initramfs-tools/conf.d/tailnet-unlock": 0o644,
    "/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock": 0o644,
    "/etc/initramfs/post-update.d/tailnet-unlock": 0o755,
    "/usr/lib/python3/dist-packages/tailnet_unlock/__init__.py": 0o644,
    "/usr/share/doc/tailnet-unlock/copyright": 0o644,
    "/usr/share/doc/tailnet-unlock/changelog.gz": 0o644,
    "/usr/share/doc/tailnet-unlock/examples/box.toml": 0o644,
}
LEFTOVERS = (
    "/usr/lib/tailnet-unlock",
    "/usr/lib/python3/dist-packages/tailnet_unlock",
    "/usr/share/doc/tailnet-unlock",
    "/usr/sbin/tailnet-unlock",
    "/usr/share/initramfs-tools/hooks/tailnet-unlock",
    "/etc/initramfs/post-update.d/tailnet-unlock",
    "/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock",
    "/var/lib/tailnet-unlock",
    "/etc/tailnet-unlock",
)


def sh(*argv: str, fake_zfs: bool = False) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", SOURCE_DATE_EPOCH=EPOCH)
    if fake_zfs:
        env["PATH"] = f"{FAKE_BIN}:{env['PATH']}"
    return subprocess.run(argv, capture_output=True, text=True, check=False, env=env)


def installed() -> bool:
    return sh("dpkg-query", "-W", "-f=${db:Status-Status}", "tailnet-unlock").stdout == "installed"


def set_zfs(keylocations: list[str]) -> None:
    """A fake zfs whose `get` lists these keylocation values, one dataset to a line."""
    FAKE_BIN.mkdir(exist_ok=True)
    FAKE_ZFS_OUT.write_text("".join(f"{v}\n" for v in keylocations), encoding="utf-8")
    script = FAKE_BIN / "zfs"
    script.write_text(
        '#!/bin/sh\nif [ "$1" = get ]; then cat /run/tu-zfs.out; exit 0; fi\n'
        'echo "fake zfs: unsupported: $*" >&2\nexit 2\n',
        encoding="utf-8",
    )
    script.chmod(0o755)


def set_broken_zfs() -> None:
    FAKE_BIN.mkdir(exist_ok=True)
    script = FAKE_BIN / "zfs"
    script.write_text('#!/bin/sh\necho "The ZFS modules are not loaded." >&2\nexit 1\n')
    script.chmod(0o755)


def set_update_initramfs(exit_code: int) -> None:
    """Stand in for update-initramfs: record the arguments, then exit with `exit_code`."""
    if not UPDATE_KEPT.exists():
        shutil.copy2(UPDATE, UPDATE_KEPT)
    UPDATE.write_text(
        f'#!/bin/sh\necho "$*" >>{CALLS}\necho "update-initramfs: pretending" >&2\n'
        f"exit {exit_code}\n",
        encoding="utf-8",
    )
    UPDATE.chmod(0o755)


def calls() -> list[str]:
    return CALLS.read_text(encoding="utf-8").splitlines() if CALLS.exists() else []


def scrub() -> None:
    """Back to a container without the package, whatever a test did."""
    set_zfs(["none"])
    if installed():
        sh("dpkg", "--purge", "tailnet-unlock", fake_zfs=True)
    for path in LEFTOVERS:
        p = Path(path)
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink(missing_ok=True)
    CALLS.unlink(missing_ok=True)
    if UPDATE_KEPT.exists():
        shutil.move(UPDATE_KEPT, UPDATE)


@pytest.fixture(scope="module")
def debs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    out = tmp_path_factory.mktemp("debs")
    built: dict[str, Path] = {}
    for version in ("0.1.0", "0.1.1"):
        done = sh(str(REPO / "tools" / "build-deb"), version, str(out))
        assert done.returncode == 0, done.stderr
        built[version] = Path(done.stdout.strip())
    return built


@pytest.fixture(autouse=True)
def clean() -> Iterator[None]:
    scrub()
    yield
    scrub()


def apt_install(deb: Path, fake_zfs: bool = False) -> subprocess.CompletedProcess[str]:
    return sh("apt-get", "install", "-y", "--no-install-recommends", str(deb), fake_zfs=fake_zfs)


def enroll_on_disk() -> None:
    """What a set-up box has: a configuration and a door container, and a root at the prompt."""
    CONFIG.mkdir(parents=True, exist_ok=True)
    (CONFIG / "box.toml").write_text('[network]\ninterface = "eth0"\n', encoding="utf-8")
    DOOR.mkdir(parents=True, exist_ok=True)
    (DOOR / "public").write_text("x\n", encoding="utf-8")
    set_zfs(["prompt", "none", "prompt"])


def test_install_puts_the_files_where_the_design_says(debs: dict[str, Path]) -> None:
    done = apt_install(debs["0.1.0"])
    assert done.returncode == 0, done.stderr
    assert installed()
    for path, mode in FILES.items():
        st = Path(path).stat()
        assert stat.S_IMODE(st.st_mode) == mode, path
        assert (st.st_uid, st.st_gid) == (0, 0), path
    # nothing of the box's own state or configuration comes with the package
    assert not CONFIG.exists()
    assert not STATE.exists()
    code = "import tailnet_unlock; print(tailnet_unlock.__version__)"
    version = sh("/usr/bin/python3", "-I", "-c", code)
    assert version.stdout.strip() == "0.1.0", version.stderr
    assert sh("dpkg", "--verify", "tailnet-unlock").stdout == ""
    # the conffiles are the two under /etc, so an edit or a removal by hand survives an upgrade
    status = sh("dpkg-query", "-W", "-f=${Conffiles}", "tailnet-unlock").stdout
    assert "/etc/initramfs/post-update.d/tailnet-unlock" in status
    assert "/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock" in status


def test_a_box_that_is_not_set_up_is_left_alone(debs: dict[str, Path]) -> None:
    set_update_initramfs(0)
    assert apt_install(debs["0.1.0"]).returncode == 0
    assert calls() == []


def test_configure_rebuilds_the_images_on_a_set_up_box(debs: dict[str, Path]) -> None:
    set_update_initramfs(0)
    CONFIG.mkdir(parents=True)
    (CONFIG / "box.toml").write_text('[network]\ninterface = "eth0"\n', encoding="utf-8")
    assert apt_install(debs["0.1.0"]).returncode == 0
    assert calls() == ["-u -k all"]


def fake_tailscale(version: str, out: Path) -> Path:
    """A `tailscale` package that owns /usr/sbin/tailscaled, as the real one does."""
    root = out / f"tailscale-{version}"
    (root / "DEBIAN").mkdir(parents=True)
    (root / "usr" / "sbin").mkdir(parents=True)
    (root / "usr" / "sbin" / "tailscaled").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (root / "usr" / "sbin" / "tailscaled").chmod(0o755)
    (root / "DEBIAN" / "control").write_text(
        f"Package: tailscale\nVersion: {version}\nArchitecture: all\n"
        "Maintainer: t <t@example.com>\n"
        "Description: stand-in for the trigger test\n",
        encoding="utf-8",
    )
    deb = out / f"tailscale_{version}_all.deb"
    built = sh("dpkg-deb", "--root-owner-group", "--build", str(root), str(deb))
    assert built.returncode == 0, built.stderr
    return deb


def test_the_trigger_rebuilds_images_when_tailscaled_changes(
    debs: dict[str, Path], tmp_path: Path
) -> None:
    set_update_initramfs(0)
    enroll_on_disk()
    assert apt_install(debs["0.1.0"]).returncode == 0
    CALLS.unlink()
    up = sh("dpkg", "-i", str(fake_tailscale("9.0.0", tmp_path)))
    assert up.returncode == 0, up.stderr
    assert calls() == ["-u -k all"], "the trigger ran update-initramfs once, for every kernel"


def test_the_trigger_does_nothing_before_the_box_is_set_up(
    debs: dict[str, Path], tmp_path: Path
) -> None:
    set_update_initramfs(0)
    assert apt_install(debs["0.1.0"]).returncode == 0
    up = sh("dpkg", "-i", str(fake_tailscale("9.0.1", tmp_path)))
    assert up.returncode == 0, up.stderr
    assert calls() == []


def test_a_failing_rebuild_never_fails_the_package(debs: dict[str, Path], tmp_path: Path) -> None:
    set_update_initramfs(1)
    enroll_on_disk()
    configured = apt_install(debs["0.1.0"])
    assert configured.returncode == 0, configured.stderr
    assert "W: tailnet-unlock:" in configured.stdout + configured.stderr
    assert installed()
    CALLS.unlink()
    up = sh("dpkg", "-i", str(fake_tailscale("9.0.2", tmp_path)))
    assert up.returncode == 0, up.stderr
    assert "W: tailnet-unlock:" in up.stdout + up.stderr
    assert calls() == ["-u -k all"]
    status = sh("dpkg-query", "-W", "-f=${db:Status-Status}", "tailscale").stdout
    assert status == "installed"


def test_removal_is_refused_while_the_box_is_enrolled(debs: dict[str, Path]) -> None:
    assert apt_install(debs["0.1.0"]).returncode == 0
    enroll_on_disk()
    for action in ("--remove", "--purge"):
        done = sh("dpkg", action, "tailnet-unlock", fake_zfs=True)
        assert done.returncode != 0
        assert "tailnet-unlock: refusing to remove" in done.stderr
        assert installed()
        assert Path("/usr/lib/tailnet-unlock/door").exists()
        assert DOOR.exists()


def test_removal_is_refused_when_only_the_recovery_door_exists(debs: dict[str, Path]) -> None:
    assert apt_install(debs["0.1.0"]).returncode == 0
    enroll_on_disk()
    shutil.rmtree(DOOR)
    (DOOR.parent / "recovery_host_key").write_bytes(b"x")
    done = sh("dpkg", "--remove", "tailnet-unlock", fake_zfs=True)
    assert done.returncode != 0
    assert installed()


def test_the_command_ignores_modules_in_the_current_directory(
    debs: dict[str, Path], tmp_path: Path
) -> None:
    assert apt_install(debs["0.1.0"]).returncode == 0
    (tmp_path / "tailnet_unlock").mkdir()
    (tmp_path / "tailnet_unlock" / "__init__.py").write_text("")
    (tmp_path / "tailnet_unlock" / "__main__.py").write_text("print('planted')\n")
    (tmp_path / "json.py").write_text("print('planted')\n")
    done = subprocess.run(
        ["/usr/sbin/tailnet-unlock", "--version"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env=dict(os.environ, PYTHONPATH=str(tmp_path)),
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "0.1.0"


def test_removal_is_refused_when_zfs_cannot_say(debs: dict[str, Path]) -> None:
    assert apt_install(debs["0.1.0"]).returncode == 0
    enroll_on_disk()
    set_broken_zfs()
    done = sh("dpkg", "--remove", "tailnet-unlock", fake_zfs=True)
    assert done.returncode != 0
    assert installed()


def test_an_upgrade_is_never_refused(debs: dict[str, Path]) -> None:
    assert apt_install(debs["0.1.0"]).returncode == 0
    enroll_on_disk()
    done = apt_install(debs["0.1.1"], fake_zfs=True)
    assert done.returncode == 0, done.stderr
    version = sh("dpkg-query", "-W", "-f=${Version}", "tailnet-unlock").stdout
    assert version == "0.1.1"
    assert DOOR.exists(), "an upgrade keeps the box's state"


def test_removal_is_allowed_when_the_box_is_not_enrolled(debs: dict[str, Path]) -> None:
    # a root that does not ask at the prompt, a door that does not exist, and no zfs at all
    assert apt_install(debs["0.1.0"]).returncode == 0
    DOOR.mkdir(parents=True)
    set_zfs(["none", "file:///etc/zfs/key"])
    assert sh("dpkg", "--remove", "tailnet-unlock", fake_zfs=True).returncode == 0
    assert apt_install(debs["0.1.0"]).returncode == 0
    shutil.rmtree(STATE)
    set_zfs(["prompt"])
    assert sh("dpkg", "--remove", "tailnet-unlock", fake_zfs=True).returncode == 0
    assert not installed()


def test_removal_rebuilds_the_images_without_the_door(debs: dict[str, Path]) -> None:
    set_update_initramfs(0)
    enroll_on_disk()
    assert apt_install(debs["0.1.0"]).returncode == 0
    set_zfs(["none"])
    CALLS.unlink()
    # the rebuild must see a system whose hook is gone, or the image would carry the door again
    UPDATE.write_text(
        "#!/bin/sh\n[ ! -e /usr/share/initramfs-tools/hooks/tailnet-unlock ] || exit 1\n"
        f'echo "$*" >>{CALLS}\n',
        encoding="utf-8",
    )
    done = sh("dpkg", "--remove", "tailnet-unlock", fake_zfs=True)
    assert done.returncode == 0, done.stderr
    assert calls() == ["-u -k all"]
    CALLS.unlink()
    assert sh("dpkg", "--purge", "tailnet-unlock", fake_zfs=True).returncode == 0
    assert calls() == [], "the purge that follows has nothing left to rebuild"


def test_a_failing_rebuild_never_fails_the_removal(debs: dict[str, Path]) -> None:
    set_update_initramfs(1)
    enroll_on_disk()
    assert apt_install(debs["0.1.0"]).returncode == 0
    set_zfs(["none"])
    done = sh("dpkg", "--remove", "tailnet-unlock", fake_zfs=True)
    assert done.returncode == 0, done.stderr
    assert "W: tailnet-unlock:" in done.stdout + done.stderr
    assert not installed()


def test_purge_removes_everything_of_ours(debs: dict[str, Path]) -> None:
    assert apt_install(debs["0.1.0"]).returncode == 0
    enroll_on_disk()
    (CONFIG / "delivery_keys").write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
    (STATE / "images").mkdir()
    (STATE / "images" / "6.12.0").write_text("tailnet=yes\n", encoding="utf-8")
    # python writes bytecode as root when the command runs; the purge removes that too
    assert sh("/usr/bin/python3", "-c", "import tailnet_unlock").returncode == 0
    set_zfs(["none"])
    done = sh("dpkg", "--purge", "tailnet-unlock", fake_zfs=True)
    assert done.returncode == 0, done.stderr
    assert "not empty" not in done.stderr
    for path in LEFTOVERS:
        assert not Path(path).exists(), path
    assert sh("dpkg-query", "-W", "tailnet-unlock").returncode != 0
