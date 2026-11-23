import json
import re
from pathlib import Path

from tailnet import (
    CONTROL_HOST,
    OPERATOR,
    Tools,
    first_ipv4,
    headscale_config,
    headscale_policy,
    headscale_url,
    parse_pins,
    proxy_command,
    read_pins,
    server_cert_ext,
    tailscale_up_argv,
    tailscaled_argv,
)

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "policy.hujson"
TOOLS = Tools(Path("/t/headscale"), Path("/t/tailscale"), Path("/t/tailscaled"))


def hujson(text: str) -> dict[str, object]:
    """JSON with comments and trailing commas, which is all the example uses of HuJSON."""
    without_comments = re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)
    without_commas = re.sub(r",(\s*[}\]])", r"\1", without_comments)
    parsed: object = json.loads(without_commas)
    assert isinstance(parsed, dict)
    return parsed


def test_pins_are_versions_and_sha256_hashes() -> None:
    pins = read_pins()
    assert re.fullmatch(r"\d+\.\d+\.\d+", pins["HEADSCALE_VERSION"])
    assert re.fullmatch(r"\d+\.\d+\.\d+", pins["TAILSCALE_VERSION"])
    for key in ("HEADSCALE_SHA256", "TAILSCALE_TGZ_SHA256", "TAILSCALE_KEYRING_SHA256"):
        assert re.fullmatch(r"[0-9a-f]{64}", pins[key]), key


def test_parse_pins_skips_comments() -> None:
    assert parse_pins("# a\n\nA=1\n  # b\nB = two\n") == {"A": "1", "B": "two"}


def test_every_pin_version_has_a_renovate_annotation() -> None:
    text = (Path(__file__).resolve().parents[2] / "tests/vm/pins.env").read_text()
    for name in re.findall(r"^([A-Z_]+_VERSION)=", text, flags=re.MULTILINE):
        assert re.search(rf"^# renovate: .*\n{name}=", text, flags=re.MULTILINE), name


def test_the_example_policy_is_the_design_policy() -> None:
    policy = hujson(EXAMPLE.read_text())
    assert set(policy) == {"groups", "tagOwners", "grants", "tests"}
    grants = policy["grants"]
    assert isinstance(grants, list)
    assert grants == [
        {
            "src": ["group:unlock-operators", "tag:keyholder"],
            "dst": ["tag:unlock"],
            "ip": ["tcp:2222"],
        }
    ]
    assert not any("tag:unlock" in grant["src"] for grant in grants)


def test_the_headscale_policy_only_renames_the_people() -> None:
    example = EXAMPLE.read_text()
    derived = headscale_policy(example)
    assert "example.com" not in derived
    assert "autogroup" not in derived
    assert f"{OPERATOR}@" in derived
    expected = example.replace("someone@example.com", f"{OPERATOR}@").replace(
        "autogroup:admin", f"{OPERATOR}@"
    )
    assert derived == expected
    assert hujson(derived)["grants"] == hujson(example)["grants"]


def test_headscale_config_is_one_tls_port_with_derp_and_the_policy() -> None:
    config = headscale_config(
        Path("/s"), "10.0.2.2", Path("/s/c.pem"), Path("/s/c.key"), Path("/p")
    )
    assert f"server_url: {headscale_url('10.0.2.2')}" in config
    assert "server_url: https://10.0.2.2:18080" in config
    assert "listen_addr: 0.0.0.0:18080" in config
    assert "tls_cert_path: /s/c.pem" in config
    assert "enabled: true" in config
    assert "path: /p" in config
    assert "magic_dns: false" in config
    assert "auto_update_enabled: false" in config


def test_the_default_control_host_is_the_guests_name_for_the_host() -> None:
    assert CONTROL_HOST == "10.0.2.2" or "TU_VM_CONTROL_HOST" in __import__("os").environ


def test_server_cert_names_the_host_and_loopback() -> None:
    assert "subjectAltName=IP:10.0.2.2,IP:127.0.0.1" in server_cert_ext("10.0.2.2")


def test_node_command_lines() -> None:
    argv = tailscaled_argv(TOOLS, Path("/n/state"), Path("/n/sock"))
    assert "--tun=userspace-networking" in argv
    assert "--socket=/n/sock" in argv
    assert "--port=0" in argv
    up = tailscale_up_argv(TOOLS, Path("/n/sock"), "https://h:1", "KEY", "kh")
    assert up[:3] == ["/t/tailscale", "--socket=/n/sock", "up"]
    assert "--login-server=https://h:1" in up
    assert "--accept-dns=false" in up
    assert proxy_command(TOOLS, Path("/n/sock")) == "/t/tailscale --socket=/n/sock nc %h %p"


def test_first_ipv4() -> None:
    assert first_ipv4(["2001:db8::1", "192.0.2.9"]) == "192.0.2.9"
