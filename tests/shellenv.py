"""A sandbox for running the initramfs shell scripts outside an initramfs.

The scripts source a fixed paths.sh. The sandbox copies them into a temporary tree with a paths.sh
of its own, so the run directory, the configuration, the boot id, `zfs`, `reboot`, the sysrq
trigger and the kernel's panic setting all point into the sandbox. Nothing a test runs can reach
the host's /proc/sysrq-trigger or reboot it.

The fake `zfs` follows libzfs 2.3.9 for `load-key -L prompt` with a stdin that is not a terminal
(lib/libzfs/libzfs_crypto.c, get_key_material_raw): passphrase and hex keys are the first line with
one trailing newline trimmed; a raw key is read as up to 33 bytes and must be exactly 32.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INITRAMFS = REPO / "initramfs"
LIB_FILES = ("door", "lib.sh", "unseal", "supervise")
BOOT_ID = "6f1c2b3a-0d4e-4c5f-9a8b-7e6d5c4b3a21"

FAKE_ZFS = r"""#!/bin/sh
# a stand-in for zfs(8): keystatus, keyformat and load-key -L prompt on one dataset
state=@STATE@
case "$1 $2 $3 $4 $5" in
"get -H -o value keystatus") cat "$state/keystatus"; exit 0 ;;
"get -H -o value keyformat") cat "$state/keyformat"; exit 0 ;;
esac
if [ "$1 $2 $3" = "load-key -L prompt" ]; then
    [ "$4" = "$(cat "$state/name")" ] || exit 1
    [ "$(cat "$state/keystatus")" = unavailable ] || { echo "Key already loaded" >&2; exit 255; }
    cat >"$state/received"
    exec python3 -I -c '
import sys
state = sys.argv[1]
received = open(state + "/received", "rb").read()
keyformat = open(state + "/keyformat").read().strip()
expected = open(state + "/key", "rb").read()
if keyformat == "raw":
    material = received[:33]
    ok = len(material) == 32 and material == expected
else:
    material = received.split(b"\n", 1)[0]
    ok = material == expected
if ok:
    open(state + "/keystatus", "w").write("available\n")
    sys.exit(0)
sys.stderr.write("Key load error: Incorrect key provided\n")
sys.exit(255)
' "$state"
fi
echo "fake zfs: unsupported: $*" >&2
exit 2
"""


@dataclass(frozen=True)
class Shell:
    name: str
    argv: tuple[str, ...]
    path: str


def available_shells(applets: Path) -> list[Shell]:
    shells: list[Shell] = []
    dash = shutil.which("dash")
    if dash is not None:
        shells.append(Shell("dash", (dash,), "/usr/local/bin:/usr/bin:/bin"))
    busybox = shutil.which("busybox")
    if busybox is not None:
        make_applets(Path(busybox), applets)
        shells.append(Shell("busybox", (busybox, "sh"), f"{applets}"))
    return shells


def make_applets(busybox: Path, target: Path) -> None:
    """A directory where every busybox applet is a link, so PATH holds busybox alone."""
    if (target / "sh").exists():
        return
    target.mkdir(parents=True, exist_ok=True)
    listing = subprocess.run([str(busybox), "--list"], capture_output=True, check=True)
    for applet in listing.stdout.decode().split():
        link = target / applet
        if not link.exists():
            link.symlink_to(busybox)
    python = shutil.which("python3")
    if python is not None and not (target / "python3").exists():
        (target / "python3").symlink_to(python)


@dataclass(frozen=True)
class Sandbox:
    root: Path
    lib: Path
    run: Path
    conf: Path
    zfs_state: Path
    bin: Path
    console: Path
    cmdline: Path


def make_sandbox(root: Path, conf: dict[str, str] | None = None) -> Sandbox:
    lib = root / "lib"
    run = root / "run"
    bin_dir = root / "bin"
    zfs_state = root / "zfs"
    for directory in (lib, run, bin_dir, zfs_state):
        directory.mkdir(parents=True, exist_ok=True)
    os.chmod(run, 0o700)
    for name in LIB_FILES:
        shutil.copy(INITRAMFS / name, lib / name)
    (root / "boot_id").write_text(BOOT_ID + "\n")
    console = root / "console"
    console.write_text("")
    cmdline = root / "cmdline"
    cmdline.write_text("BOOT_IMAGE=/vmlinuz root=ZFS=rpool/ROOT/debian ro quiet\n")
    paths = {
        "TU_LIB": str(lib),
        "TU_RUN": str(run),
        "TU_ETC": str(root / "etc"),
        "TU_CONF": str(root / "tailnet-unlock.conf"),
        "TU_RECORD_DIR": str(root / "record"),
        "TU_BOOT_ID_FILE": str(root / "boot_id"),
        "TU_CMDLINE": str(cmdline),
        "TU_CONSOLE": str(console),
        "TU_TPM_DEVICE": str(root / "tpmrm0"),
        "TU_TCTI": "none",
        "TU_ZFS": str(bin_dir / "zfs"),
        "TU_ROOT_WAIT_SECONDS": "2",
        "TU_TICK": "1",
        "TU_MINUTE": "1",
        "TU_INITRAMFS_FUNCTIONS": str(root / "functions"),
        "TU_NET_CONF_DIR": str(root / "netconf"),
        "TU_PANIC_DELAY": "1",
        "TU_REBOOT": str(bin_dir / "reboot"),
        "TU_SYSRQ": str(root / "sysrq-trigger"),
        "TU_KERNEL_PANIC": str(root / "kernel-panic"),
    }
    (root / "netconf").mkdir(exist_ok=True)
    (root / "functions").write_text(
        "# a stand-in for initramfs-tools' scripts/functions\n"
        "configure_networking() {\n"
        "\tDEVICE=tutest0\n"
        f"\tprintf 'DEVICE=tutest0\\nIPV4ADDR=127.0.0.2\\n' >'{root}/netconf/net-tutest0.conf'\n"
        "}\n"
    )
    lines = ["# test paths: everything inside the sandbox"]
    lines += [f"{name}='{value}'" for name, value in paths.items()]
    (lib / "paths.sh").write_text("\n".join(lines) + "\n")
    values = {
        "TU_BACKEND": "zfs",
        "TU_PROFILE": "tpm",
        "TU_PORT": "2222",
        "TU_RECOVERY": "uplink",
        "TU_DEGRADED": "",
        "TU_TAILSCALED_VERSION": "1.104.7",
        "TU_DOOR": "sealed",
        "TU_TAILNET": "no",
        "TU_IDLE_TIMEOUT": "600",
        "TU_IP": ":::::lo:dhcp",
        "TU_BOOTIF": "",
        "TU_DNS": "",
        "TU_FLUSH": "yes",
        "TU_UNLOCK_HOSTNAME": "web-1-unlock",
        "TU_REHEARSAL_MINUTES": "",
    }
    values.update(conf or {})
    (root / "tailnet-unlock.conf").write_text(
        "".join(f"{name}='{value}'\n" for name, value in values.items())
    )
    zfs = bin_dir / "zfs"
    zfs.write_text(FAKE_ZFS.replace("@STATE@", str(zfs_state)))
    zfs.chmod(0o755)
    reboot = bin_dir / "reboot"
    reboot.write_text(f"#!/bin/sh\necho \"reboot $*\" >>'{root}/reboots'\nexit 0\n")
    reboot.chmod(0o755)
    set_dataset(
        Sandbox(root, lib, run, root / "tailnet-unlock.conf", zfs_state, bin_dir, console, cmdline),
        "rpool",
        "passphrase",
        b"correct horse battery",
    )
    return Sandbox(
        root=root,
        lib=lib,
        run=run,
        conf=root / "tailnet-unlock.conf",
        zfs_state=zfs_state,
        bin=bin_dir,
        console=console,
        cmdline=cmdline,
    )


def set_dataset(box: Sandbox, name: str, keyformat: str, key: bytes) -> None:
    (box.zfs_state / "name").write_text(name)
    (box.zfs_state / "keyformat").write_text(keyformat + "\n")
    (box.zfs_state / "keystatus").write_text("unavailable\n")
    (box.zfs_state / "key").write_bytes(key)


def wait_for_root(box: Sandbox, name: str, keyformat: str) -> None:
    """What the load-key extension writes once ZFS asks for the key."""
    (box.run / "waiting_for").write_text(name + "\n")
    (box.run / "keyformat").write_text(keyformat + "\n")


def run_door(
    box: Sandbox,
    shell: Shell,
    role: str,
    command: str | None,
    stdin: bytes = b"",
    timeout: float = 20,
) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": shell.path, "LC_ALL": "C", "HOME": str(box.root)}
    if command is not None:
        environment["SSH_ORIGINAL_COMMAND"] = command
    return subprocess.run(
        [*shell.argv, str(box.lib / "door"), role],
        input=stdin,
        capture_output=True,
        env=environment,
        timeout=timeout,
        check=False,
    )


def copy_script(box: Sandbox, name: str) -> Path:
    """A boot script with its fixed paths.sh line pointed at the sandbox."""
    text = (INITRAMFS / name).read_text()
    text = text.replace("/usr/lib/tailnet-unlock/paths.sh", str(box.lib / "paths.sh"))
    text = text.replace("/conf/tailnet-unlock.conf", str(box.conf))
    # the panic script reads the command line, and falls back to the run directory, by itself
    text = text.replace("/proc/cmdline", str(box.cmdline))
    text = text.replace("/tailnet-unlock/run", str(box.run))
    # the defaults it falls back to when paths.sh is damaged must not reach the host either
    text = text.replace("/proc/sysrq-trigger", str(box.root / "sysrq-trigger"))
    text = text.replace("/dev/console", str(box.console))
    target = box.lib / f"script-{name}"
    target.write_text(text)
    target.chmod(0o755)
    return target
