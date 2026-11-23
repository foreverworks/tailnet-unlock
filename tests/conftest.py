"""Tests run on hosts that may have swap; the swap check reads a file the tests choose."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

import tsfake
from boxenv import Box, make_box
from tailnet_unlock import cli, doorkey

NO_SWAP = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


@pytest.fixture(autouse=True, scope="session")
def no_swap(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    swaps = tmp_path_factory.mktemp("swaps") / "swaps"
    swaps.write_text(NO_SWAP, encoding="utf-8")
    real = doorkey.PROC_SWAPS
    doorkey.PROC_SWAPS = swaps
    yield
    doorkey.PROC_SWAPS = real


@pytest.fixture
def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Box]:
    """A box in a temporary tree with fake Tailscale first on PATH (tests/boxenv.py)."""
    made = make_box(tmp_path)
    monkeypatch.setenv("PATH", f"{made.bin}:{os.environ['PATH']}")
    for name in ("TPM2TOOLS_TCTI", "TSS2_TCTI", "TPM2_PKCS11_TCTI"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "HOST", made.host)
    yield made
    tsfake.reap(tmp_path)
