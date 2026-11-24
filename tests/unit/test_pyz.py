"""The keyholder's single file (tools/build_pyz.py): reproducible, isolated, and it starts."""

import os
import subprocess
import sys
import zipfile
from pathlib import Path

from shellenv import REPO

BUILD = REPO / "tools" / "build_pyz.py"


def build(outdir: Path, umask: int = 0o022, epoch: str = "1700000000") -> Path:
    done = subprocess.run(
        [sys.executable, str(BUILD), str(outdir)],
        capture_output=True,
        text=True,
        check=True,
        umask=umask,
        env={**os.environ, "SOURCE_DATE_EPOCH": epoch},
    )
    return Path(done.stdout.strip())


def test_two_builds_are_byte_equal(tmp_path: Path) -> None:
    first = build(tmp_path / "a")
    assert first.read_bytes() == build(tmp_path / "b", umask=0o077).read_bytes()
    assert first.read_bytes() != build(tmp_path / "c", epoch="1700000100").read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
    assert names == sorted(names)
    assert "tailnet_unlock/keyholder/deliver.py" in names
    assert not [name for name in names if not name.endswith(".py")]


def test_it_runs_isolated_with_nothing_installed(tmp_path: Path) -> None:
    pyz = build(tmp_path / "out")
    # a module beside it, or in the current directory, must not be loaded instead of Python's own
    for directory in (pyz.parent, tmp_path):
        (directory / "argparse.py").write_text("raise SystemExit('hijacked')\n")
    done = subprocess.run(
        [str(pyz), "--help"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "PYTHONPATH": str(tmp_path)},
    )
    assert done.returncode == 0, done.stderr
    for command in ("deliver", "unlock", "watch", "planned", "approver"):
        assert command in done.stdout
    assert "enroll" not in done.stdout, "the box's commands are not the keyholder's"
