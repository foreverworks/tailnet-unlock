from pathlib import Path

from harness import VmSpec, qemu_argv, ssh_argv, swtpm_argv


def test_qemu_has_a_tpm_on_tpm_tis_and_ovmf() -> None:
    spec = VmSpec(name="t", workdir=Path("/w"), disk=Path("/w/d.qcow2"), forwards=((2222, 2222),))
    argv = qemu_argv(spec)
    joined = " ".join(argv)
    assert "-machine q35" in joined
    assert "-accel kvm -cpu host" in joined
    assert "-chardev socket,id=chrtpm,path=/w/swtpm.sock" in joined
    assert "-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0" in joined
    assert "file=/usr/share/OVMF/OVMF_CODE_4M.fd" in joined
    assert "file=/w/OVMF_VARS_4M.fd" in joined
    assert "hostfwd=tcp:127.0.0.1:2222-:2222" in joined
    assert "unix:/w/serial.sock,server=on,wait=off" in joined


def test_direct_kernel_boot_under_tcg() -> None:
    spec = VmSpec(
        name="t",
        workdir=Path("/w"),
        kernel=Path("/k"),
        initrd=Path("/i"),
        append="console=ttyS0",
        accel="tcg",
        uefi=False,
    )
    argv = qemu_argv(spec)
    assert argv[argv.index("-kernel") + 1] == "/k"
    assert argv[argv.index("-append") + 1] == "console=ttyS0"
    assert "pflash" not in " ".join(argv)
    assert "tcg" in argv


def test_swtpm_and_ssh() -> None:
    spec = VmSpec(name="t", workdir=Path("/w"))
    assert swtpm_argv(spec)[:3] == ["swtpm", "socket", "--tpm2"]
    assert "type=unixio,path=/w/swtpm.sock" in swtpm_argv(spec)
    argv = ssh_argv(2222, Path("/k"), Path("/h"), ["status"])
    assert "StrictHostKeyChecking=yes" in argv
    assert argv[-2:] == ["root@127.0.0.1", "status"]


def test_restricted_network_and_a_ssh_host() -> None:
    spec = VmSpec(name="t", workdir=Path("/w"), forwards=((2222, 2222),), restrict=True)
    assert "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:2222-:2222" in " ".join(qemu_argv(spec))
    assert "restrict" not in " ".join(qemu_argv(VmSpec(name="t", workdir=Path("/w"))))
    argv = ssh_argv(2222, Path("/k"), Path("/h"), ["status"], host="192.0.2.2")
    assert argv[-2:] == ["root@192.0.2.2", "status"]
