"""The keyholder's state directory: locks, markers, memory, audit (DESIGN.md 10.8, 12.2)."""

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from khkit import NOW
from shellenv import REPO
from tailnet_unlock.errors import ConfigError
from tailnet_unlock.keyholder.state import (
    Memory,
    Planned,
    append_audit,
    clear_planned,
    host_lock,
    parse_duration,
    prepare,
    read_last_unlock,
    read_memory,
    read_planned,
    write_last_unlock,
    write_memory,
    write_planned,
)


def test_one_holder_per_host(tmp_path: Path) -> None:
    with host_lock(tmp_path, "web-1") as first:
        assert first
        with host_lock(tmp_path, "web-1") as second:
            assert not second
        with host_lock(tmp_path, "web-2") as other:
            assert other
    with host_lock(tmp_path, "web-1") as again:
        assert again


def test_a_killed_holder_lets_go(tmp_path: Path) -> None:
    script = (
        "import sys, time\nfrom pathlib import Path\n"
        "from tailnet_unlock.keyholder.state import host_lock\n"
        "with host_lock(Path(sys.argv[1]), 'web-1') as held:\n"
        "    print(held, flush=True)\n    time.sleep(60)\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path)],
        stdout=subprocess.PIPE,
        env={"PYTHONPATH": str(REPO / "src")},
    )
    assert process.stdout is not None
    assert process.stdout.readline() == b"True\n"
    with host_lock(tmp_path, "web-1") as held:
        assert not held
    process.kill()
    process.wait()
    process.stdout.close()
    with host_lock(tmp_path, "web-1") as held:
        assert held


def test_planned(tmp_path: Path) -> None:
    assert read_planned(tmp_path, "web-1", NOW) is None
    planned = Planned("bob", "kernel", NOW + timedelta(minutes=30))
    write_planned(tmp_path, "web-1", planned)
    assert read_planned(tmp_path, "web-1", NOW + timedelta(minutes=30)) == planned
    assert read_planned(tmp_path, "web-1", NOW + timedelta(minutes=31)) is None
    assert clear_planned(tmp_path, "web-1")
    assert not clear_planned(tmp_path, "web-1")


def test_memory_and_history(tmp_path: Path) -> None:
    assert read_memory(tmp_path, "web-1") == Memory()
    memory = Memory(waiting_since=NOW, alarm_told_at=NOW + timedelta(hours=1))
    write_memory(tmp_path, "web-1", memory)
    assert read_memory(tmp_path, "web-1") == memory
    assert read_last_unlock(tmp_path, "web-1") is None
    write_last_unlock(tmp_path, "web-1", NOW)
    assert read_last_unlock(tmp_path, "web-1") == "2026-11-24T10:00:00Z"


@pytest.mark.parametrize(
    "text", ["", "[]", "{", '{"waiting_since": "soon"}', '{"waiting_since": 5}']
)
def test_a_damaged_file_is_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "watch").mkdir()
    (tmp_path / "watch" / "web-1.json").write_text(text)
    with pytest.raises(ConfigError, match=r"web-1\.json"):
        read_memory(tmp_path, "web-1")


def test_audit_is_appended_and_private(tmp_path: Path) -> None:
    state = tmp_path / "state"
    prepare(state)
    append_audit(state, json.dumps({"n": 1}))
    append_audit(state, json.dumps({"n": 2}))
    path = state / "audit.jsonl"
    assert [json.loads(line)["n"] for line in path.read_text().splitlines()] == [1, 2]
    assert path.stat().st_mode & 0o777 == 0o600
    assert state.stat().st_mode & 0o777 == 0o700


def test_durations() -> None:
    assert parse_duration("90s") == timedelta(seconds=90)
    assert parse_duration("30m") == timedelta(minutes=30)
    assert parse_duration("7d") == timedelta(days=7)
    for bad in ("", "30", "m", "-5m", "1.5h", "8d", "0m", "9999999d", "٣m"):
        with pytest.raises(ConfigError):
            parse_duration(bad)
