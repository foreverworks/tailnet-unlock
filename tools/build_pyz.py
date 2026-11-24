"""Build the keyholder's single file: python3 tools/build_pyz.py <outdir>

`tailnet-unlock-keyholder.pyz` holds the Python package and starts the keyholder's commands; it
needs Python 3.13 and nothing installed. It is reproducible: the same commit gives the same bytes.
Every member has the commit's time (SOURCE_DATE_EPOCH, taken from git unless the environment sets
it) and a fixed mode, the order is sorted, and nothing is compressed, so no zlib version shows.
"""

import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NAME = "tailnet-unlock-keyholder.pyz"
# -I: neither the current directory, PYTHONPATH nor a user's site can put a module in front of ours
SHEBANG = b"#!/usr/bin/env -S python3 -I\n"
MAIN = """import sys

if sys.version_info < (3, 13):
    sys.exit("tailnet-unlock-keyholder needs Python 3.13 or later")

from tailnet_unlock.keyholder.cli import main

sys.exit(main())
"""


def source_date() -> int:
    given = os.environ.get("SOURCE_DATE_EPOCH")
    if given is None:
        given = subprocess.run(
            ["git", "-C", str(REPO), "log", "-1", "--format=%ct"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    return int(given)


def members() -> list[tuple[str, bytes]]:
    package = REPO / "src" / "tailnet_unlock"
    found = [
        (str(path.relative_to(package.parent)), path.read_bytes())
        for path in package.rglob("*.py")
        if "__pycache__" not in path.parts
    ]
    return sorted([*found, ("__main__.py", MAIN.encode("ascii"))])


def build(outdir: Path) -> Path:
    moment = time.gmtime(source_date())
    date = (moment.tm_year, moment.tm_mon, moment.tm_mday, moment.tm_hour, moment.tm_min, 0)
    outdir.mkdir(parents=True, exist_ok=True)
    target = outdir / NAME
    with target.open("wb") as out:
        out.write(SHEBANG)
        with zipfile.ZipFile(out, "a", compression=zipfile.ZIP_STORED) as archive:
            for name, data in members():
                info = zipfile.ZipInfo(name, date)
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
    target.chmod(0o755)
    return target


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python3 tools/build_pyz.py <outdir>", file=sys.stderr)
        return 2
    print(build(Path(argv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
