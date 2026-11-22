"""door-keygen, seal and unseal against swtpm (DESIGN.md 8.1, 8.3, 8.4; T5, T7, T21 in part)."""

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

import swtpm
from shellenv import INITRAMFS, REPO
from tailnet_unlock.doorkey import check_dropbear_ed25519, fingerprint, pin_line
from tailnet_unlock.errors import TpmError
from tailnet_unlock.tpm import run_sequence, seal_sequence, tpm_environment, unseal_sequence

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(not swtpm.available(), reason="needs swtpm, tpm2-tools, dropbear"),
]


@pytest.fixture
def tcti(tmp_path: Path) -> Iterator[str]:
    with swtpm.software_tpm(tmp_path / "tpm") as value:
        yield value


@pytest.fixture
def shm() -> Iterator[Path]:
    base = Path("/dev/shm") / f"tailnet-unlock-test-{os.getpid()}-{os.urandom(4).hex()}"
    base.mkdir(mode=0o700)
    yield base
    subprocess.run(["rm", "-rf", str(base)], check=True)


def cli(*args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    # the host's swap is none of the test's business (the check has its own unit tests)
    runner = (
        "import sys; from pathlib import Path; from tailnet_unlock import doorkey; "
        "doorkey.PROC_SWAPS = Path('/dev/null'); from tailnet_unlock.cli import main; "
        "sys.exit(main(sys.argv[1:]))"
    )
    return subprocess.run(
        ["python3", "-c", runner, *args],
        input=stdin,
        capture_output=True,
        env=environment,
        check=False,
    )


def unseal(container: Path, output: Path, tcti: str, tmp_path: Path) -> int:
    """Run initramfs/unseal, the boot-time POSIX sh, with a paths.sh pointing at swtpm."""
    lib = tmp_path / "unseal-lib"
    lib.mkdir(exist_ok=True)
    (lib / "unseal").write_bytes((INITRAMFS / "unseal").read_bytes())
    (lib / "paths.sh").write_text(f"TU_TCTI='{tcti}'\n")
    return subprocess.run(
        ["sh", str(lib / "unseal"), str(container), str(output)], capture_output=True, check=False
    ).returncode


def test_generate_seal_unseal(tmp_path: Path, tcti: str, shm: Path) -> None:
    state = tmp_path / "state"
    made = cli("door-keygen", "--state-dir", str(state), "--work-dir", str(shm), "--tcti", tcti)
    assert made.returncode == 0, made.stderr
    container = state / "door.tpm"
    pin = (container / "pin").read_text().strip()
    assert pin.startswith("ssh-ed25519 ")
    assert fingerprint(pin) in made.stdout.decode()
    assert sorted(p.name for p in container.iterdir()) == [
        "format",
        "pin",
        "private",
        "profile",
        "public",
    ]
    assert list(shm.iterdir()) == []
    output = shm / "door_key"
    assert unseal(container, output, tcti, tmp_path) == 0
    blob = output.read_bytes()
    assert len(blob) == 83
    assert pin_line(check_dropbear_ed25519(blob)) == pin
    listed = subprocess.run(
        ["dropbearkey", "-y", "-f", str(output)], capture_output=True, check=True
    ).stdout.decode()
    assert pin.split()[1] in listed
    assert sorted(p.name for p in shm.iterdir()) == ["door_key"]
    assert not (container / "private").read_bytes().count(blob[19:51])


def test_import_openssh_key(tmp_path: Path, tcti: str, shm: Path) -> None:
    key = tmp_path / "imported"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    known = (tmp_path / "imported.pub").read_text().split()
    state = tmp_path / "state"
    made = cli(
        "door-keygen",
        "--import",
        "-",
        "--state-dir",
        str(state),
        "--work-dir",
        str(shm),
        "--tcti",
        tcti,
        stdin=key.read_bytes(),
    )
    assert made.returncode == 0, made.stderr
    pin = (state / "door.tpm" / "pin").read_text().split()
    assert pin == known[:2]
    assert list(shm.iterdir()) == []
    output = shm / "door_key"
    assert unseal(state / "door.tpm", output, tcti, tmp_path) == 0
    assert pin_line(check_dropbear_ed25519(output.read_bytes())).split() == known[:2]


def test_seal_a_dropbear_key_and_replace(tmp_path: Path, tcti: str, shm: Path) -> None:
    key = shm / "made"
    subprocess.run(
        ["dropbearkey", "-t", "ed25519", "-f", str(key)], capture_output=True, check=True
    )
    blob = key.read_bytes()
    key.unlink()
    container = tmp_path / "door.tpm"
    first = cli(
        "seal", "--container", str(container), "--work-dir", str(shm), "--tcti", tcti, stdin=blob
    )
    assert first.returncode == 0, first.stderr
    again = cli(
        "seal", "--container", str(container), "--work-dir", str(shm), "--tcti", tcti, stdin=blob
    )
    assert again.returncode == 2
    assert b"--replace" in again.stderr
    replaced = cli(
        "seal",
        "--container",
        str(container),
        "--work-dir",
        str(shm),
        "--tcti",
        tcti,
        "--replace",
        stdin=blob,
    )
    assert replaced.returncode == 0
    output = shm / "door_key"
    assert unseal(container, output, tcti, tmp_path) == 0
    assert output.read_bytes() == blob


def test_recovery_key_import_is_stored_unsealed(tmp_path: Path, shm: Path) -> None:
    """C: the recovery key's import flag; the recovery key is never sealed."""
    key = tmp_path / "recovery"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    state = tmp_path / "state"
    made = cli(
        "door-keygen",
        "--recovery",
        "--import",
        str(key),
        "--state-dir",
        str(state),
        "--work-dir",
        str(shm),
    )
    assert made.returncode == 0, made.stderr
    stored = state / "recovery_host_key"
    assert oct(stored.stat().st_mode & 0o777) == "0o600"
    expected = (tmp_path / "recovery.pub").read_text().split()[:2]
    assert pin_line(check_dropbear_ed25519(stored.read_bytes())).split() == expected
    assert (state / "recovery_host_key.pub").read_text().split() == expected
    assert not (state / "door.tpm").exists()
    assert b"unsealed by design" in made.stdout


def test_another_tpm_cannot_unseal(tmp_path: Path, tcti: str, shm: Path) -> None:
    """T5 at the TPM level: a copy of the container on another TPM opens nothing."""
    state = tmp_path / "state"
    assert (
        cli(
            "door-keygen", "--state-dir", str(state), "--work-dir", str(shm), "--tcti", tcti
        ).returncode
        == 0
    )
    with swtpm.software_tpm(tmp_path / "other-tpm") as other:
        assert unseal(state / "door.tpm", shm / "door_key", other, tmp_path) == 3
    assert not (shm / "door_key").exists()


def test_a_cleared_tpm_cannot_unseal(tmp_path: Path, tcti: str, shm: Path) -> None:
    """T7 at the TPM level: clearing the TPM loses the door, never anything else."""
    state = tmp_path / "state"
    assert (
        cli(
            "door-keygen", "--state-dir", str(state), "--work-dir", str(shm), "--tcti", tcti
        ).returncode
        == 0
    )
    subprocess.run(["tpm2_clear", "-Q", "-c", "p"], env=tpm_environment(tcti), check=True)
    assert unseal(state / "door.tpm", shm / "door_key", tcti, tmp_path) == 3


def test_the_sealed_data_limit_is_128_bytes(tmp_path: Path, tcti: str, shm: Path) -> None:
    environment = tpm_environment(tcti)
    for size, fits in ((128, True), (129, False)):
        work = shm / f"limit-{size}"
        work.mkdir()
        sequence = seal_sequence(work, work / "public", work / "private")
        if fits:
            run_sequence(sequence, environment, {2: b"x" * size})
            out = work / "out"
            run_sequence(
                unseal_sequence(work, work / "public", work / "private", out), environment, {}
            )
            assert out.read_bytes() == b"x" * size
        else:
            with pytest.raises(TpmError):
                run_sequence(sequence, environment, {2: b"x" * size})
            subprocess.run(["tpm2_flushcontext", "-Q", "-t"], env=environment, check=False)


def test_plaintext_only_on_a_tmpfs(tmp_path: Path, tcti: str) -> None:
    made = cli(
        "door-keygen",
        "--state-dir",
        str(tmp_path / "state"),
        "--work-dir",
        str(tmp_path),
        "--tcti",
        tcti,
    )
    assert made.returncode == 2
    assert b"must be on a tmpfs" in made.stderr
