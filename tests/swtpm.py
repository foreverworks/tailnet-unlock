"""A software TPM 2.0 (swtpm) for one test, reached through the swtpm TCTI on 127.0.0.1."""

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def free_port_pair() -> int:
    while True:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        if port < 65000:
            with socket.socket() as second:
                try:
                    second.bind(("127.0.0.1", port + 1))
                except OSError:
                    continue
            return port


def available() -> bool:
    return all(shutil.which(tool) for tool in ("swtpm", "tpm2_createprimary", "dropbearkey"))


@contextmanager
def software_tpm(state: Path) -> Iterator[str]:
    """Start swtpm with its state in `state`; yield the TCTI string; stop it by its PID."""
    state.mkdir(parents=True, exist_ok=True)
    port = free_port_pair()
    process = subprocess.Popen(
        [
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={state}",
            "--server",
            f"type=tcp,port={port},bindaddr=127.0.0.1",
            "--ctrl",
            f"type=tcp,port={port + 1},bindaddr=127.0.0.1",
            "--flags",
            "not-need-init,startup-clear",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        yield f"swtpm:host=127.0.0.1,port={port}"
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
