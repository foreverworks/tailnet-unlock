"""`verify`: read every initramfs image back and say what is wrong with it (DESIGN.md 7.2, 12.5).

Two checks per image, kept apart. `door_problems` is about the uplink door and needs nothing of
Tailscale; `tailnet_problems` is about the tailnet door and runs only on facts and versions it is
given. This module never imports `tailscale.py`: what it compares with is an argument, so a box
with `tailnet.enabled = false` and no Tailscale package verifies like any other.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from tailnet_unlock.authorized_keys import read_authorized_keys
from tailnet_unlock.config import BoxConfig
from tailnet_unlock.container import read_container
from tailnet_unlock.errors import ConfigError, DoorKeyError, ToolError
from tailnet_unlock.images import (
    Expected,
    ImageFacts,
    list_images,
    local_key_files,
    read_image,
)
from tailnet_unlock.node import read_node
from tailnet_unlock.seal import DOOR_CONTAINER, RECOVERY_KEY
from tailnet_unlock.sealedstate import sealed_problem
from tailnet_unlock.system import Host
from tailnet_unlock.versions import Version, parse_version

VERIFY_SCHEMA = "tailnet-unlock.verify/1"
# what the hook records in TU_DEGRADED for the tailnet door: the door check leaves these out
TAILNET_DEGRADED = frozenset(
    {"tailscaled-missing", "tailscaled-too-old", "tailnet-state-missing", "boot-space"}
)

MESSAGES = {
    "door-absent": "the image carries no door",
    "door-incomplete": "the image says it has a door but lacks files the door needs",
    "sealed-door-absent": "a sealed door key exists but the image carries no sealed door",
    "door-pin-differs": "the image's sealed door key is not the one on the box",
    "degraded": "the build reported a degradation (see degraded)",
    "keys-stale": "the image's authorized_keys differ from what the box would render now",
    "recovery-key-stale": "the image's recovery key is not the box's",
    "tailnet-absent": "the unlock node is enrolled but the image carries no tailnet door",
    "tailnet-incomplete": "the image says it has a tailnet door but lacks tailscaled or its state",
    "tailnet-unexpected": "the image carries tailscaled or node state but the tailnet door is off",
    "state-unsealed": "the image's node state is not Tailscale's sealed store",
    "state-stale": "the image's node state differs from the box's",
    "tailscaled-differs": "the image's tailscaled is not the installed one of its version",
    "version-unknown": "the image's conf does not say which tailscaled it carries",
    "version-below-floor": "the image's tailscaled is older than the floor",
    "version-older-than-installed": "the image's tailscaled is older than the installed one",
    "tailnet-not-enrolled": "tailnet.enabled is true but the unlock node is not enrolled",
    "no-images": "there is no initramfs image to check",
}


@dataclass(frozen=True)
class TailnetView:
    """What the box says about its tailnet door, gathered once by the caller."""

    enabled: bool
    enrolled: bool
    floor: Version
    installed: Version | None
    tailscaled: Path | None = None


@dataclass(frozen=True)
class ImageReport:
    """One image: its facts (None when unreadable), its problems and, if unreadable, why."""

    path: str
    facts: ImageFacts | None
    problems: tuple[str, ...]
    error: str


@dataclass(frozen=True)
class VerifyResult:
    images: tuple[ImageReport, ...]
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.problems


def door_problems(facts: ImageFacts) -> list[str]:
    problems: list[str] = []
    if facts.door == "none":
        problems.append("door-absent")
    elif facts.door_pin_current is not None:
        if facts.door != "sealed":
            problems.append("sealed-door-absent")
        elif not facts.door_pin_current:
            problems.append("door-pin-differs")
    if facts.missing:
        problems.append("door-incomplete")
    if any(code not in TAILNET_DEGRADED for code in facts.degraded):
        problems.append("degraded")
    if facts.keys_current is False:
        problems.append("keys-stale")
    if facts.recovery_current is False:
        problems.append("recovery-key-stale")
    return problems


def tailnet_problems(facts: ImageFacts, view: TailnetView) -> list[str]:
    problems: list[str] = []
    wanted = view.enabled and view.enrolled
    if wanted and not facts.tailnet:
        problems.append("tailnet-absent")
    if facts.tailnet and not (facts.has_tailscaled and facts.has_state):
        problems.append("tailnet-incomplete")
    if not wanted and (facts.has_tailscaled or facts.has_state):
        problems.append("tailnet-unexpected")
    if facts.has_state and facts.state_sealed is False:
        problems.append("state-unsealed")
    if wanted and facts.state_identical is False:
        problems.append("state-stale")
    if facts.has_tailscaled:
        in_conf = parse_version(facts.conf_tailscaled_version)
        if in_conf is None:
            problems.append("version-unknown")
        else:
            if in_conf < view.floor:
                problems.append("version-below-floor")
            elif view.installed is not None and in_conf < view.installed:
                problems.append("version-older-than-installed")
            if facts.tailscaled_current is False and in_conf == view.installed:
                problems.append("tailscaled-differs")
    return problems


def image_json(report: ImageReport) -> dict[str, object]:
    facts = report.facts
    if facts is None:
        return {"image": report.path, "problems": list(report.problems), "error": report.error}
    return {
        "image": facts.path,
        "kernel": facts.kernel,
        "door": facts.door,
        "recovery": facts.recovery,
        "tailnet": facts.tailnet,
        "degraded": list(facts.degraded),
        "port": facts.port,
        "profile": facts.profile,
        "tailscaled_version": facts.conf_tailscaled_version or None,
        "tailscaled_current": facts.tailscaled_current,
        "state_sealed": facts.state_sealed,
        "state_identical": facts.state_identical,
        "authorized_keys_current": facts.keys_current,
        "local_key": facts.local_key,
        "missing": list(facts.missing),
        "problems": list(report.problems),
    }


def node_enrolled(host: Host) -> bool:
    """A recorded node and a sealed state file beside it."""
    try:
        state = host.node_state.read_bytes()
        node = read_node(host)
    except OSError:
        return False
    return node is not None and sealed_problem(state) is None


def _optional(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def load_expected(host: Host, tailscaled: Path | None) -> Expected:
    """What the box's own files say an image should carry."""
    try:
        pin: str | None = read_container(host.door_dir / DOOR_CONTAINER).pin
    except DoorKeyError:
        pin = None
    return Expected(
        state=_optional(host.node_state),
        authorized_keys=read_authorized_keys(host.config_dir),
        recovery_key=_optional(host.door_dir / RECOVERY_KEY),
        door_pin=pin,
        local_key_files=local_key_files(),
        tailscaled=tailscaled,
    )


def tailnet_view(
    host: Host,
    config: BoxConfig,
    floor: Version,
    installed: Version | None,
    tailscaled: Path | None,
) -> TailnetView:
    return TailnetView(
        enabled=config.tailnet.enabled,
        enrolled=node_enrolled(host),
        floor=floor,
        installed=installed,
        tailscaled=tailscaled,
    )


def verify_images(
    host: Host,
    view: TailnetView,
    allow_unenrolled: bool,
    boot_dir: Path | None = None,
) -> VerifyResult:
    """Check every image on /boot: the door first, then the tailnet part."""
    expected = load_expected(host, view.tailscaled)
    images: list[ImageReport] = []
    problems: list[str] = []
    if view.enabled and not view.enrolled and not allow_unenrolled:
        problems.append("tailnet-not-enrolled")
    found = list_images(boot_dir or host.boot_dir)
    if not found:
        problems.append("no-images")
    for path in found:
        try:
            facts = read_image(host, path, expected)
        except (ToolError, OSError) as error:
            images.append(ImageReport(str(path), None, ("unreadable",), str(error)))
            problems.append(f"{path.name}: unreadable ({error})")
            continue
        codes = (*door_problems(facts), *tailnet_problems(facts, view))
        images.append(ImageReport(str(path), facts, codes, ""))
        problems += [f"{path.name}: {code}" for code in codes]
    return VerifyResult(tuple(images), tuple(problems))


def result_json(result: VerifyResult) -> str:
    return json.dumps(
        {
            "schema": VERIFY_SCHEMA,
            "ok": result.ok,
            "images": [image_json(report) for report in result.images],
            "problems": list(result.problems),
        },
        indent=2,
    )


def render_text(result: VerifyResult) -> str:
    lines: list[str] = []
    for report in result.images:
        lines.append(f"{report.path}: {'ok' if not report.problems else 'PROBLEMS'}")
        facts = report.facts
        if facts is not None:
            lines.append(
                f"  door {facts.door}, recovery {'yes' if facts.recovery else 'no'}, tailnet "
                f"{'yes' if facts.tailnet else 'no'}, tailscaled "
                f"{facts.conf_tailscaled_version or 'none'}"
            )
            if facts.local_key:
                lines.append("  a ZFS key file is in this image: it boots without the door")
            if facts.missing:
                lines.append(f"  missing: {', '.join(facts.missing)}")
        for code in report.problems:
            lines.append(f"  {code}: {MESSAGES.get(code, report.error)}")
    for code in ("tailnet-not-enrolled", "no-images"):
        if code in result.problems:
            lines.append(f"{code}: {MESSAGES[code]}")
    lines.append("ok" if result.ok else "verify found problems")
    return "\n".join(lines)


def floor_from(text: str) -> Version:
    found = parse_version(text)
    if found is None:
        raise ConfigError(f"--tailscale-floor: not a version: {text!r}")
    return found
