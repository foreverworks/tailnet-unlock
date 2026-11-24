"""Fail when a type or lint suppression lacks its reason on the same line (DESIGN.md 14, D14).

A `# type: ignore` must name its code and give a reason (`# type: ignore[code]  # why`), a
`# noqa` must name its code and a reason, and a `# shellcheck disable=` must be followed by `#` and
a reason.
"""

import re
import sys
from pathlib import Path

TYPE_IGNORE = re.compile(r"#\s*type:\s*ignore(?P<rest>.*)$")
NOQA = re.compile(r"#\s*noqa(?P<rest>.*)$")
SHELLCHECK = re.compile(r"#\s*shellcheck\s+disable=(?P<rest>.*)$")
WITH_CODE_AND_REASON = re.compile(r"^\[[A-Za-z0-9_,-]+\]\s+#\s*\S")
NOQA_WITH_REASON = re.compile(r"^:\s*[A-Z]+[0-9]+(,\s*[A-Z]+[0-9]+)*\s+#\s*\S")
SHELLCHECK_WITH_REASON = re.compile(r"^SC[0-9]+(,SC[0-9]+)*\s+#\s*\S")


def problems(path: Path, text: str) -> list[str]:
    found: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        where = f"{path}:{number}"
        if (match := TYPE_IGNORE.search(line)) and not WITH_CODE_AND_REASON.match(
            match.group("rest")
        ):
            found.append(f"{where}: type: ignore without [code] and a reason")
        if (match := NOQA.search(line)) and not NOQA_WITH_REASON.match(match.group("rest")):
            found.append(f"{where}: noqa without a code and a reason")
        if (match := SHELLCHECK.search(line)) and not SHELLCHECK_WITH_REASON.match(
            match.group("rest")
        ):
            found.append(f"{where}: shellcheck disable without a reason")
    return found


def main(roots: list[str]) -> int:
    found: list[str] = []
    for root in roots:
        for path in sorted(Path(root).rglob("*")):
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and path.name != Path(__file__).name
            ):
                try:
                    text = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                found += problems(path, text)
    for problem in found:
        print(problem, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["src", "tests", "tools", "initramfs", "examples"]))
