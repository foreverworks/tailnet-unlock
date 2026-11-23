"""The edge between `verify` and Tailscale: what to read, and only when it matters.

`verify.py` is pure about Tailscale. This module gives it the two things that need a tool: the
version the box has installed, read only when the tailnet door is configured, and the version an
image's own tailscaled reports. A box with the tailnet off and no Tailscale installed never runs
either.
"""

import shutil
from pathlib import Path

from tailnet_unlock.config import BoxConfig
from tailnet_unlock.system import Host
from tailnet_unlock.tailscale import binary_version
from tailnet_unlock.verify import VerifyResult, tailnet_view, verify_images
from tailnet_unlock.versions import Version, version_text


def _image_version(path: Path) -> str | None:
    found = binary_version(path)
    return None if found is None else version_text(found)


def installed_version(config: BoxConfig) -> Version | None:
    if not config.tailnet.enabled:
        return None
    found = shutil.which("tailscaled")
    return None if found is None else binary_version(found)


def run_verify(
    host: Host,
    config: BoxConfig,
    floor: Version,
    allow_unenrolled: bool,
    boot_dir: Path | None = None,
) -> VerifyResult:
    view = tailnet_view(host, config, floor, installed_version(config))
    return verify_images(host, view, allow_unenrolled, _image_version, boot_dir)
