"""The keyholder's state directory (DESIGN.md section 12.2): locks, planned markers, the last
unlock of each host, what the watcher remembers between passes, and the audit file.

Every file is small JSON written atomically. A file that does not parse is an error, not an empty
one: forgetting that an alarm was told, or that a reboot was planned, is a decision.
"""

import contextlib
import fcntl
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from tailnet_unlock.errors import ConfigError
from tailnet_unlock.keyholder.approval import parse_timestamp, timestamp
from tailnet_unlock.system import STATE_ROOT, atomic_write

STATE_DIR = STATE_ROOT / "keyholder"
MAX_STATE_BYTES = 65536


@dataclass(frozen=True)
class Planned:
    """A reboot somebody announced, until `until`."""

    by: str
    note: str | None
    until: datetime


@dataclass(frozen=True)
class Memory:
    """What the watcher remembers of one host between passes."""

    waiting_since: datetime | None = None
    delivery_started_at: datetime | None = None
    alarm_since: datetime | None = None
    alarm_told_at: datetime | None = None


def _read(path: Path) -> dict[str, object] | None:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return None
    try:
        value: object = json.loads(raw.decode("utf-8"))
    except ValueError:
        value = None
    if not isinstance(value, dict):
        raise ConfigError(f"{path} is not one JSON object; delete it if nothing needs it")
    return {str(key): item for key, item in value.items()}


def _write(path: Path, fields: dict[str, str | None]) -> None:
    atomic_write(path, json.dumps(fields).encode("utf-8") + b"\n", 0o600)


def _time(fields: dict[str, object], key: str, path: Path) -> datetime | None:
    value = fields.get(key)
    if value is None:
        return None
    try:
        return parse_timestamp(str(value))
    except ValueError:
        raise ConfigError(f"{path}: {key} is not a time; delete the file") from None


def prepare(state_dir: Path) -> None:
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)


# --- the per-host lock --------------------------------------------------------------------------


@contextlib.contextmanager
def host_lock(state_dir: Path, host: str) -> Iterator[bool]:
    """Holds the host's lock, or yields False when another process does. The kernel releases it
    when the process ends, however it ends."""
    directory = state_dir / "locks"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory / f"{host}.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:
        os.close(fd)


# --- planned markers ----------------------------------------------------------------------------


def _planned_path(state_dir: Path, host: str) -> Path:
    return state_dir / "planned" / f"{host}.json"


def write_planned(state_dir: Path, host: str, planned: Planned) -> None:
    _write(
        _planned_path(state_dir, host),
        {"by": planned.by, "note": planned.note, "until": timestamp(planned.until)},
    )


def clear_planned(state_dir: Path, host: str) -> bool:
    try:
        _planned_path(state_dir, host).unlink()
    except FileNotFoundError:
        return False
    return True


def read_planned(state_dir: Path, host: str, now: datetime) -> Planned | None:
    """The marker, unless it is over."""
    path = _planned_path(state_dir, host)
    fields = _read(path)
    if fields is None:
        return None
    until = _time(fields, "until", path)
    if until is None or now > until:
        return None
    note = fields.get("note")
    return Planned(str(fields.get("by")), note if isinstance(note, str) else None, until)


# --- history ------------------------------------------------------------------------------------


def read_last_unlock(state_dir: Path, host: str) -> str | None:
    path = state_dir / "history" / f"{host}.json"
    fields = _read(path)
    moment = None if fields is None else _time(fields, "last_unlock_at", path)
    return None if moment is None else timestamp(moment)


def write_last_unlock(state_dir: Path, host: str, moment: datetime) -> None:
    _write(state_dir / "history" / f"{host}.json", {"last_unlock_at": timestamp(moment)})


# --- the watcher's memory -----------------------------------------------------------------------


def read_memory(state_dir: Path, host: str) -> Memory:
    path = state_dir / "watch" / f"{host}.json"
    fields = _read(path)
    if fields is None:
        return Memory()
    return Memory(
        waiting_since=_time(fields, "waiting_since", path),
        delivery_started_at=_time(fields, "delivery_started_at", path),
        alarm_since=_time(fields, "alarm_since", path),
        alarm_told_at=_time(fields, "alarm_told_at", path),
    )


def write_memory(state_dir: Path, host: str, memory: Memory) -> None:
    def text(moment: datetime | None) -> str | None:
        return None if moment is None else timestamp(moment)

    _write(
        state_dir / "watch" / f"{host}.json",
        {
            "waiting_since": text(memory.waiting_since),
            "delivery_started_at": text(memory.delivery_started_at),
            "alarm_since": text(memory.alarm_since),
            "alarm_told_at": text(memory.alarm_told_at),
        },
    )


# --- audit --------------------------------------------------------------------------------------


def append_audit(state_dir: Path, line: str) -> None:
    """One whole line, appended in one write and on the disk before anything else happens."""
    fd = os.open(
        state_dir / "audit.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600
    )
    try:
        os.write(fd, line.encode("utf-8") + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_duration(text: str) -> timedelta:
    """`90s`, `30m`, `2h` or `1d`, up to seven days."""
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(text[-1:])
    number = text[:-1]
    if unit is None or not (number.isascii() and number.isdigit()) or len(number) > 6:
        raise ConfigError(f"not a duration: {text[:20]!r} (write 90s, 30m, 2h or 1d)")
    duration = timedelta(seconds=int(number) * unit)
    if not timedelta(0) < duration <= timedelta(days=7):
        raise ConfigError("a duration is more than nothing and at most 7 days")
    return duration
