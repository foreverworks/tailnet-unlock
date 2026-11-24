"""What the keyholder's own tailnet node sees (DESIGN.md section 10.4; decision D12).

`parse_view` narrows `tailscale status --json` from untrusted JSON; the rest are pure functions of
the parsed view. A name only finds a node: the pinned host key authenticates the door behind it.
"""

import ipaddress
import json
from dataclasses import dataclass
from typing import Literal

from tailnet_unlock.errors import ToolError
from tailnet_unlock.keyholder.approval import NetworkInfo, SiteMatch
from tailnet_unlock.keyholder.config import HostConfig, Network, NodeRef

MAX_ENDPOINTS = 32
MAX_TEXT = 255

type Presence = Literal["online", "offline"]


@dataclass(frozen=True)
class Peer:
    node_id: str
    hostname: str
    dns_name: str
    addresses: tuple[str, ...]
    online: bool
    current_address: str
    relay: str
    endpoints: tuple[str, ...]


@dataclass(frozen=True)
class View:
    """The peers of a running tailnet node."""

    peers: tuple[Peer, ...]


def _text(value: object) -> str:
    return value[:MAX_TEXT] if isinstance(value, str) and value.isprintable() else ""


def _texts(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(text for item in value[:MAX_ENDPOINTS] if (text := _text(item)))


def _peer(value: object) -> Peer | None:
    if not isinstance(value, dict):
        return None
    return Peer(
        node_id=_text(value.get("ID")),
        hostname=_text(value.get("HostName")),
        dns_name=_text(value.get("DNSName")).rstrip("."),
        addresses=tuple(item for item in _texts(value.get("TailscaleIPs")) if _is_ip(item)),
        online=value.get("Online") is True,
        current_address=_text(value.get("CurAddr")),
        relay=_text(value.get("Relay")),
        endpoints=_texts(value.get("Addrs")),
    )


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def parse_view(text: str) -> View:
    """The peers, or ToolError when the status is not one of a running node."""
    try:
        value: object = json.loads(text)
    except ValueError:
        raise ToolError("tailscale status --json did not print JSON") from None
    if not isinstance(value, dict):
        raise ToolError("tailscale status --json did not print a JSON object")
    state: object = value.get("BackendState")
    if state != "Running":
        raise ToolError(f"tailscale is not running (BackendState {_text(state)[:40]!r})")
    peers: object = value.get("Peer")
    if peers is None:
        return View(())
    if not isinstance(peers, dict):
        raise ToolError("tailscale status --json has no readable Peer table")
    parsed = (_peer(item) for item in peers.values())
    return View(tuple(peer for peer in parsed if peer is not None))


def first_label(dns_name: str) -> str:
    return dns_name.split(".", 1)[0].lower()


def find_peer(view: View, ref: NodeRef) -> Peer | None:
    """By stable id when the reference has one; else by name: the whole DNS name, its first label
    (which the control server keeps unique), then a host name exactly one node reports."""
    if ref.node_id is not None:
        return next((peer for peer in view.peers if peer.node_id == ref.node_id), None)
    if ref.name is None:
        return None
    name = ref.name.lower()
    for matches in (
        [peer for peer in view.peers if peer.dns_name.lower() == name],
        [peer for peer in view.peers if first_label(peer.dns_name) == name],
        [peer for peer in view.peers if peer.hostname.lower() == name],
    ):
        if len(matches) == 1:
            return matches[0]
        if matches:
            return None
    return None


def presence(view: View | None, ref: NodeRef | None) -> Presence | None:
    """Online or offline, or None when there is nothing to say. A node the keyholder does not see
    is offline: it was deleted, expired, or the policy hides it."""
    if ref is None or view is None:
        return None
    peer = find_peer(view, ref)
    return "online" if peer is not None and peer.online else "offline"


def peer_name(peer: Peer) -> str:
    """How a person knows the node."""
    return first_label(peer.dns_name) or peer.hostname or peer.node_id


def dial_address(peer: Peer) -> str | None:
    """The address to connect to: the node's IPv4 address on the tailnet, else its IPv6 one."""
    ordered = sorted(peer.addresses, key=lambda item: ":" in item)
    return ordered[0] if ordered else None


def _host_part(endpoint: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = endpoint
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def site_match(observed: str | None, expected: tuple[Network, ...]) -> SiteMatch:
    """Whether the observed endpoint is in an expected network; unverified without either."""
    address = None if observed is None else _host_part(observed)
    if address is None or not expected:
        return "unverified"
    return "yes" if any(address in network for network in expected) else "no"


def tailnet_network(host: HostConfig, peer: Peer) -> NetworkInfo:
    direct = bool(peer.current_address)
    observed = peer.current_address if direct else None
    return {
        "path": "direct" if direct else "relayed",
        "observed_endpoint": observed,
        "relay": None if direct or not peer.relay else peer.relay,
        "reported_endpoints": list(peer.endpoints),
        "expected": [str(network) for network in host.expected_endpoints],
        "site_match": site_match(observed, host.expected_endpoints),
    }


def uplink_network(host: HostConfig) -> NetworkInfo:
    """The uplink door: the address the keyholder is configured with and connects to itself."""
    address = host.uplink or ""
    joined = f"[{address}]" if ":" in address else address
    observed = f"{joined}:{host.uplink_port}"
    return {
        "path": "direct",
        "observed_endpoint": observed,
        "relay": None,
        "reported_endpoints": [],
        "expected": [str(network) for network in host.expected_endpoints],
        "site_match": site_match(observed, host.expected_endpoints),
    }
