"""The Debian package's build (tools/build-deb): its contents, and that it is reproducible.

Needs dpkg-deb, which the CI runner and the test container have. The tests that install the .deb
are in tests/package.
"""

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from shellenv import REPO

BUILD = REPO / "tools" / "build-deb"
EPOCH = "1700000000"

pytestmark = pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="needs dpkg-deb")


def build(outdir: Path, version: str = "0.1.0", umask: str = "022", epoch: str = EPOCH) -> Path:
    done = subprocess.run(
        ["sh", "-c", f'umask {umask}; exec "$0" "$@"', str(BUILD), version, str(outdir)],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": epoch},
    )
    assert done.returncode == 0, done.stderr
    return Path(done.stdout.strip())


def test_two_builds_are_byte_equal(tmp_path: Path) -> None:
    first = build(tmp_path / "a")
    # a different umask, a different directory and a later wall clock must change nothing
    second = build(tmp_path / "b", umask="077")
    assert first.read_bytes() == second.read_bytes()
    other = build(tmp_path / "c", epoch="1700000001")
    assert other.read_bytes() != first.read_bytes()


def test_every_member_is_root_owned_and_dated_by_the_epoch(tmp_path: Path) -> None:
    deb = build(tmp_path)
    listing = subprocess.run(
        ["dpkg-deb", "-c", str(deb)], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    assert listing
    assert all(" root/root " in line for line in listing)
    # 1700000000 is 2023-11-14 22:13:20 UTC
    assert all(re.search(r" 2023-11-1[45] ", line) for line in listing)
    names = [line.split()[-1] for line in listing]
    assert names == sorted(names)


def test_control_fields(tmp_path: Path) -> None:
    deb = build(tmp_path, "0.1.0")
    assert deb.name == "tailnet-unlock_0.1.0_all.deb"
    fields = dict(
        line.split(": ", 1)
        for line in subprocess.run(
            ["dpkg-deb", "-f", str(deb)], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        if ": " in line and not line.startswith(" ")
    )
    assert fields["Package"] == "tailnet-unlock"
    assert fields["Architecture"] == "all"
    assert fields["Conflicts"] == "dropbear-initramfs"
    assert fields["Recommends"] == "tailscale (>= 1.86)"
    for needed in (
        "python3 (>= 3.13)",
        "initramfs-tools",
        "dropbear-bin",
        "tpm2-tools",
        "libtss2-tcti-device0t64",
        "zfs-initramfs",
    ):
        assert needed in fields["Depends"].split(", ")
    triggers = subprocess.run(
        ["dpkg-deb", "-I", str(deb), "triggers"], capture_output=True, text=True, check=True
    ).stdout
    assert triggers.strip() == "interest-noawait /usr/sbin/tailscaled"


@pytest.mark.parametrize("bad", ["", "v0.1.0", "0.1.0 x", "0.1.0/../x"])
def test_a_bad_version_is_refused(tmp_path: Path, bad: str) -> None:
    done = subprocess.run(
        [str(BUILD), bad, str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": EPOCH},
    )
    assert done.returncode == 2
    assert not list(tmp_path.iterdir())


def test_the_version_is_the_same_everywhere() -> None:
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    init = (REPO / "src" / "tailnet_unlock" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{version}"' in init
    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    entries = re.findall(r"^## (.+)$", changelog, re.MULTILINE)
    # work since the last release is under "Unreleased: X.Y.Z"; the release workflow refuses that
    released = [entry for entry in entries if not entry.startswith("Unreleased: ")]
    assert released[0] == version
    assert len(entries) - len(released) <= 1
