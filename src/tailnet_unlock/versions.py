"""Version numbers as tuples: pure, so `verify` can compare them without touching Tailscale."""

import re

type Version = tuple[int, int, int]

FLOOR: Version = (1, 86, 0)
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> Version | None:
    """The first dotted version in `text`, as numbers."""
    found = _VERSION.search(text)
    if found is None:
        return None
    return int(found.group(1)), int(found.group(2)), int(found.group(3))


def version_text(version: Version) -> str:
    return ".".join(str(part) for part in version)
