"""Tests run on hosts that may have swap; the swap check reads a file the tests choose."""

from collections.abc import Iterator

import pytest

from tailnet_unlock import doorkey

NO_SWAP = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


@pytest.fixture(autouse=True, scope="session")
def no_swap(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    swaps = tmp_path_factory.mktemp("swaps") / "swaps"
    swaps.write_text(NO_SWAP, encoding="utf-8")
    real = doorkey.PROC_SWAPS
    doorkey.PROC_SWAPS = swaps
    yield
    doorkey.PROC_SWAPS = real
