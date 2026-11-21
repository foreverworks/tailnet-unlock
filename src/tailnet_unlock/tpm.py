"""The tpm2-tools command sequences (DESIGN.md section 8.4), as pure argument lists.

Option names were checked against tpm2-tools 5.7, the version in Debian 13. The primary key is
created transient at every use from the TCG SRK template's algorithms and attributes (ECC P-256,
AES-128-CFB), so sealing and unsealing derive the same key and nothing persists in the TPM
(decision D8). The initramfs runs the unseal half of this in POSIX sh (initramfs/unseal); the
tests check both halves agree.
"""

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

from tailnet_unlock.errors import TpmError

DEFAULT_TCTI = "device:/dev/tpmrm0"
PRIMARY_ATTRIBUTES = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt"
SEALED_ATTRIBUTES_TPM = "fixedtpm|fixedparent|userwithauth|noda"
MAX_SEALED_BYTES = 128  # MAX_SYM_DATA in the TPM 2.0 library specification


def createprimary_argv(context: Path) -> list[str]:
    return [
        "tpm2_createprimary",
        "-Q",
        "-C",
        "o",
        "-g",
        "sha256",
        "-G",
        "ecc256:aes128cfb",
        "-a",
        PRIMARY_ATTRIBUTES,
        "-c",
        str(context),
    ]


def create_sealed_argv(primary: Path, public: Path, private: Path) -> list[str]:
    """Seal stdin under `primary` for the `tpm` profile (no policy, user auth empty)."""
    return [
        "tpm2_create",
        "-Q",
        "-C",
        str(primary),
        "-g",
        "sha256",
        "-a",
        SEALED_ATTRIBUTES_TPM,
        "-i",
        "-",
        "-u",
        str(public),
        "-r",
        str(private),
    ]


def load_argv(primary: Path, public: Path, private: Path, context: Path) -> list[str]:
    return [
        "tpm2_load",
        "-Q",
        "-C",
        str(primary),
        "-u",
        str(public),
        "-r",
        str(private),
        "-c",
        str(context),
    ]


def hmac_session_argv(primary: Path, session: Path) -> list[str]:
    """A session salted with (and bound to) the primary key, for an encrypted unseal."""
    return ["tpm2_startauthsession", "-Q", "--hmac-session", "-c", str(primary), "-S", str(session)]


def enable_encrypt_argv(session: Path) -> list[str]:
    return ["tpm2_sessionconfig", "-Q", str(session), "--enable-encrypt"]


def unseal_argv(context: Path, session: Path, output: Path) -> list[str]:
    return ["tpm2_unseal", "-Q", "-c", str(context), "-p", f"session:{session}", "-o", str(output)]


def flush_session_argv(session: Path) -> list[str]:
    return ["tpm2_flushcontext", "-Q", str(session)]


def flush_objects_argv() -> list[str]:
    """Flush this connection's transient objects.

    tpm2-tools 5.7 refuses a saved object context here ("Argument neither a session nor a
    transient"), so objects go with `-t`. Through /dev/tpmrm0 the kernel's resource manager shows
    each connection only its own objects, so this never touches anyone else's.
    """
    return ["tpm2_flushcontext", "-Q", "-t"]


def seal_sequence(work: Path, public: Path, private: Path) -> list[list[str]]:
    primary = work / "primary.ctx"
    return [
        createprimary_argv(primary),
        flush_objects_argv(),
        create_sealed_argv(primary, public, private),
        flush_objects_argv(),
    ]


def unseal_sequence(work: Path, public: Path, private: Path, output: Path) -> list[list[str]]:
    """The unseal, flushing transient objects after each step that loads one.

    Every tool saves its objects as context files and loads them again in the next step; without
    a resource manager (swtpm in the tests) the loaded copies would fill the TPM's few object
    slots. Through /dev/tpmrm0 the flushes change nothing.
    """
    primary = work / "primary.ctx"
    door = work / "door.ctx"
    session = work / "session.ctx"
    return [
        createprimary_argv(primary),
        flush_objects_argv(),
        load_argv(primary, public, private, door),
        flush_objects_argv(),
        hmac_session_argv(primary, session),
        flush_objects_argv(),
        enable_encrypt_argv(session),
        unseal_argv(door, session, output),
        flush_session_argv(session),
        flush_objects_argv(),
    ]


def tpm_environment(tcti: str | None) -> dict[str, str]:
    environment = dict(os.environ)
    environment["TPM2TOOLS_TCTI"] = tcti or environment.get("TPM2TOOLS_TCTI") or DEFAULT_TCTI
    return environment


def run_sequence(
    sequence: Sequence[list[str]], environment: dict[str, str], stdin_for: dict[int, bytes]
) -> None:
    """Run each command in order; `stdin_for` maps a step's index to the bytes it reads."""
    for index, argv in enumerate(sequence):
        old_umask = os.umask(0o077)
        try:
            result = subprocess.run(
                argv,
                input=stdin_for.get(index, b""),
                capture_output=True,
                env=environment,
                check=False,
            )
        finally:
            os.umask(old_umask)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
            raise TpmError(f"{argv[0]} failed: {detail[-1] if detail else result.returncode}")
