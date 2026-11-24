"""What the keyholder reads from its own `tailscale status --json` (DESIGN.md 10.4, D12)."""

import json

import pytest

from khkit import make_host, make_view, status_json
from tailnet_unlock.errors import ToolError
from tailnet_unlock.keyholder.config import NodeRef
from tailnet_unlock.keyholder.peers import (
    dial_address,
    find_peer,
    parse_view,
    presence,
    site_match,
    tailnet_network,
    uplink_network,
)

UNLOCK = NodeRef(None, "nUNLOCK1CNTRL")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "null",
        "[]",
        "{}",
        status_json(backend="Stopped"),
        status_json(backend="NeedsLogin"),
        '{"BackendState": "Running", "Peer": []}',
    ],
)
def test_a_status_that_decides_nothing(text: str) -> None:
    with pytest.raises(ToolError):
        parse_view(text)


def test_no_peers_is_an_empty_view() -> None:
    assert parse_view('{"BackendState": "Running", "Peer": null}').peers == ()


def test_presence() -> None:
    view = make_view(own=True, unlock=False)
    assert presence(view, NodeRef("web-1", None)) == "online"
    assert presence(view, UNLOCK) == "offline"
    assert presence(view, NodeRef("gone", None)) == "offline"
    assert presence(view, None) is None
    assert presence(None, UNLOCK) is None


def test_odd_peers_are_read_as_nothing() -> None:
    odd = {
        "a": None,
        "b": {"ID": 5, "Online": "yes", "TailscaleIPs": ["-oProxyCommand=id", 7], "Addrs": None},
        "c": {"HostName": "bad\nname", "DNSName": "x" * 900},
    }
    view = parse_view(json.dumps({"BackendState": "Running", "Peer": odd}))
    assert len(view.peers) == 2
    assert not any(peer.online for peer in view.peers)
    assert dial_address(view.peers[0]) is None
    assert view.peers[1].hostname == ""


def named(*peers: tuple[str, str, str]) -> str:
    return json.dumps(
        {
            "BackendState": "Running",
            "Peer": {
                str(index): {"ID": node_id, "HostName": hostname, "DNSName": dns}
                for index, (node_id, hostname, dns) in enumerate(peers)
            },
        }
    )


def test_a_node_is_found_by_id_then_by_the_name_the_control_server_keeps_unique() -> None:
    view = parse_view(
        named(
            ("n1", "web-1-unlock", "web-1-unlock.tailnet.example."),
            ("n2", "web-1-unlock", "web-1-unlock-1.tailnet.example."),
            ("n3", "only-host", ""),
        )
    )

    def found(ref: NodeRef) -> str | None:
        peer = find_peer(view, ref)
        return None if peer is None else peer.node_id

    assert found(NodeRef("web-1-unlock", "n2")) == "n2"
    assert found(NodeRef("web-1-unlock", "n9")) is None, "an id that is gone is not a name"
    assert found(NodeRef("WEB-1-unlock", None)) == "n1"
    assert found(NodeRef("web-1-unlock-1.tailnet.example", None)) == "n2"
    assert found(NodeRef("only-host", None)) == "n3"
    assert found(NodeRef("other", None)) is None
    twins = parse_view(named(("n1", "same", "a.example."), ("n2", "same", "b.example.")))
    assert find_peer(twins, NodeRef("same", None)) is None, "two nodes report the name"


def test_the_path_and_the_site() -> None:
    host = make_host()
    direct = find_peer(make_view(), UNLOCK)
    relayed = find_peer(make_view(direct=False), UNLOCK)
    assert direct is not None
    assert relayed is not None
    assert dial_address(direct) == "192.0.2.102", "the IPv4 address first"
    assert tailnet_network(host, direct) == {
        "path": "direct",
        "observed_endpoint": "198.51.100.7:41641",
        "relay": None,
        "reported_endpoints": ["198.51.100.7:41641", "192.0.2.10:41641"],
        "expected": ["198.51.100.0/24"],
        "site_match": "yes",
    }
    by_relay = tailnet_network(host, relayed)
    assert by_relay["path"] == "relayed"
    assert by_relay["observed_endpoint"] is None
    assert by_relay["relay"] == "fra"
    assert by_relay["site_match"] == "unverified", "whatever the reports say"
    assert uplink_network(host)["observed_endpoint"] == "192.0.2.10:2222"


def test_site_match() -> None:
    expected = make_host().expected_endpoints
    assert site_match("198.51.100.7:41641", expected) == "yes"
    assert site_match("203.0.113.1:41641", expected) == "no"
    assert site_match("[2001:db8::1]:41641", expected) == "no"
    assert site_match("door.example.com:2222", expected) == "unverified"
    assert site_match(None, expected) == "unverified"
    assert site_match("198.51.100.7:41641", ()) == "unverified"
