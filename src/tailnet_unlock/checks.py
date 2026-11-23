"""The edge between `verify` and Tailscale: what to read, and only when it matters.

`verify.py` is pure about Tailscale. This module gives it the tailscaled the box has installed and
its version, read only when the tailnet door is configured. A box with the tailnet off and no
Tailscale installed never runs it, and no binary from an image is ever run.
"""

import shutil
from pathlib import Path

from tailnet_unlock.config import BoxConfig
from tailnet_unlock.system import Host
from tailnet_unlock.tailscale import binary_version
from tailnet_unlock.verify import VerifyResult, tailnet_view, verify_images
from tailnet_unlock.versions import Version


def installed_tailscaled(config: BoxConfig) -> Path | None:
    found = shutil.which("tailscaled") if config.tailnet.enabled else None
    return None if found is None else Path(found)


def run_verify(
    host: Host,
    config: BoxConfig,
    floor: Version,
    allow_unenrolled: bool,
    boot_dir: Path | None = None,
) -> VerifyResult:
    tailscaled = installed_tailscaled(config)
    version = None if tailscaled is None else binary_version(tailscaled)
    view = tailnet_view(host, config, floor, version, tailscaled)
    return verify_images(host, view, allow_unenrolled, boot_dir)
