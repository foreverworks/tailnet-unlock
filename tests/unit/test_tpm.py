from pathlib import Path

from tailnet_unlock.tpm import PRIMARY_ATTRIBUTES, seal_sequence, unseal_sequence

REPO = Path(__file__).resolve().parents[2]


def test_primary_template_is_the_srk_shape() -> None:
    assert set(PRIMARY_ATTRIBUTES.split("|")) == {
        "fixedtpm",
        "fixedparent",
        "sensitivedataorigin",
        "userwithauth",
        "noda",
        "restricted",
        "decrypt",
    }
    first = seal_sequence(Path("/w"), Path("/w/pub"), Path("/w/priv"))[0]
    assert first[first.index("-G") + 1] == "ecc256:aes128cfb"
    assert first[first.index("-C") + 1] == "o"


def test_seal_reads_the_key_on_stdin() -> None:
    create = next(
        step
        for step in seal_sequence(Path("/w"), Path("/w/pub"), Path("/w/priv"))
        if step[0] == "tpm2_create"
    )
    assert create[create.index("-i") + 1] == "-"


def test_unseal_uses_an_encrypted_salted_session() -> None:
    steps = unseal_sequence(Path("/w"), Path("/c/public"), Path("/c/private"), Path("/r/k"))
    tools = [step[0] for step in steps if step[0] != "tpm2_flushcontext"]
    assert tools == [
        "tpm2_createprimary",
        "tpm2_load",
        "tpm2_startauthsession",
        "tpm2_sessionconfig",
        "tpm2_unseal",
    ]
    by_tool = {step[0]: step for step in steps}
    session = by_tool["tpm2_startauthsession"]
    assert "--hmac-session" in session
    assert session[session.index("-c") + 1] == "/w/primary.ctx"
    assert "--enable-encrypt" in by_tool["tpm2_sessionconfig"]
    unseal = by_tool["tpm2_unseal"]
    assert unseal[unseal.index("-p") + 1] == "session:/w/session.ctx"
    assert steps[-1] == ["tpm2_flushcontext", "-Q", "-t"]


def test_the_shell_unseal_uses_the_same_options() -> None:
    """initramfs/unseal is the boot-time copy of unseal_sequence: same template, same session."""
    script = (REPO / "initramfs" / "unseal").read_text()
    assert f"-a '{PRIMARY_ATTRIBUTES}'" in script
    for option in ("-G ecc256:aes128cfb", "--hmac-session -c", "--enable-encrypt", '-p "session:'):
        assert option in script
