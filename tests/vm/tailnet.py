"""The tailnet side of the VM harness (DESIGN.md sections 15.2 and 15.3).

headscale runs on the test host as a process this module starts and stops by PID, with TLS from a
throwaway CA that the guest trusts and the embedded DERP server and STUN on, so two userspace
nodes find each other whatever the NAT between them. The keyholder and any peer a scenario needs
are userspace tailscaled processes on the host, each with its own socket and state directory.

The guest reaches the host as 10.0.2.2 (QEMU user networking), so that address is also the one the
host's own nodes use for the control server: the host needs it as a loopback alias
(`ip addr add 10.0.2.2/32 dev lo`), which `host_alias_ready` adds with sudo when it can.
`TU_VM_CONTROL_HOST` names another address, for a run with no guest.

Pure functions build every configuration and command line; the edge starts the processes. Every
key here is a made-up test value for the run. Standard library only.
"""

import hashlib
import json
import os
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL_HOST = os.environ.get("TU_VM_CONTROL_HOST", "10.0.2.2")
CONTROL_PORT = 18080
STUN_PORT = 13478
OPERATOR = "operator"
DOOR_PORT = 2222

# --- pure ---------------------------------------------------------------------------------------


def parse_pins(text: str) -> dict[str, str]:
    """KEY=value lines of pins.env; comments and blank lines are skipped."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, value = stripped.partition("=")
            pins[key.strip()] = value.strip()
    return pins


def read_pins() -> dict[str, str]:
    return parse_pins((HERE / "pins.env").read_text())


def headscale_url(host: str, port: int = CONTROL_PORT) -> str:
    return f"https://{host}:{port}"


def headscale_config(state: Path, host: str, cert: Path, key: Path, policy: Path) -> str:
    """The headscale configuration: one HTTPS port, the embedded DERP and STUN, a policy file."""
    return f"""server_url: {headscale_url(host)}
listen_addr: 0.0.0.0:{CONTROL_PORT}
metrics_listen_addr: 127.0.0.1:{CONTROL_PORT + 1}
grpc_listen_addr: 127.0.0.1:{CONTROL_PORT + 2}
tls_cert_path: {cert}
tls_key_path: {key}
unix_socket: {state}/headscale.sock
noise:
  private_key_path: {state}/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  server:
    enabled: true
    region_id: 999
    region_code: tu
    region_name: tailnet-unlock test
    stun_listen_addr: 0.0.0.0:{STUN_PORT}
    private_key_path: {state}/derp.key
    automatically_add_embedded_derp_region: true
    ipv4: {host}
  urls: []
  paths: []
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: {state}/db.sqlite
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: tailnet.test
  nameservers:
    global: []
policy:
  mode: file
  path: {policy}
log:
  level: info
"""


def headscale_policy(example: str) -> str:
    """The shipped example policy for headscale: the example's own address and admin group become
    the one user the harness creates, and nothing else changes."""
    return example.replace("someone@example.com", f"{OPERATOR}@").replace(
        "autogroup:admin", f"{OPERATOR}@"
    )


def server_cert_ext(host: str) -> str:
    return (
        f"subjectAltName=IP:{host},IP:127.0.0.1\n"
        "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n"
    )


def tailscaled_argv(tools: "Tools", state: Path, sock: Path) -> list[str]:
    return [
        str(tools.tailscaled),
        f"--state={state}",
        "--tun=userspace-networking",
        f"--socket={sock}",
        "--no-logs-no-support",
        "--port=0",
    ]


def tailscale_up_argv(
    tools: "Tools", sock: Path, login_server: str, auth_key: str, hostname: str
) -> list[str]:
    return [
        str(tools.tailscale),
        f"--socket={sock}",
        "up",
        f"--login-server={login_server}",
        f"--auth-key={auth_key}",
        f"--hostname={hostname}",
        "--accept-dns=false",
        "--accept-routes=false",
        "--timeout=90s",
    ]


def proxy_command(tools: "Tools", sock: Path) -> str:
    """The ssh ProxyCommand that reaches a tailnet address through a userspace node."""
    return f"{tools.tailscale} --socket={sock} nc %h %p"


def first_ipv4(addresses: list[str]) -> str:
    return next(address for address in addresses if "." in address)


# --- tools --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Tools:
    headscale: Path
    tailscale: Path
    tailscaled: Path


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, dest: Path, sha256: str) -> Path:
    """Fetch `url` to `dest` and keep it only when it is the file the pin names."""
    if dest.exists() and sha256_of(dest) == sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=600) as response, partial.open("wb") as out:  # noqa: S310  # https URL built from the pins
        shutil.copyfileobj(response, out)
    found = sha256_of(partial)
    if found != sha256:
        partial.unlink()
        raise RuntimeError(f"{url} has sha256 {found}, the pin says {sha256}")
    partial.rename(dest)
    return dest


def fetch_tools(cache: Path, pins: dict[str, str] | None = None) -> Tools:
    pins = pins or read_pins()
    headscale_version = pins["HEADSCALE_VERSION"]
    tailscale_version = pins["TAILSCALE_VERSION"]
    root = cache / "tools"
    headscale = download(
        f"https://github.com/juanfont/headscale/releases/download/v{headscale_version}/"
        f"headscale_{headscale_version}_linux_amd64",
        root / f"headscale-{headscale_version}",
        pins["HEADSCALE_SHA256"],
    )
    headscale.chmod(0o755)
    tgz = download(
        f"https://pkgs.tailscale.com/stable/tailscale_{tailscale_version}_amd64.tgz",
        root / f"tailscale-{tailscale_version}.tgz",
        pins["TAILSCALE_TGZ_SHA256"],
    )
    unpacked = root / f"tailscale-{tailscale_version}"
    if not (unpacked / "tailscaled").exists():
        unpacked.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tgz) as archive:
            for member in archive.getmembers():
                name = member.name.rsplit("/", 1)[-1]
                if member.isfile() and name in ("tailscale", "tailscaled"):
                    source = archive.extractfile(member)
                    assert source is not None
                    target = unpacked / name
                    target.write_bytes(source.read())
                    target.chmod(0o755)
    return Tools(headscale, unpacked / "tailscale", unpacked / "tailscaled")


# --- certificates -------------------------------------------------------------------------------


def run(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=timeout)


def ensure_ca(directory: Path) -> Path:
    """The CA the guest trusts: made once, kept beside the image it was installed in."""
    directory.mkdir(parents=True, exist_ok=True)
    ca, key = directory / "ca.pem", directory / "ca.key"
    if not ca.exists():
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(ca),
                "-days",
                "3650",
                "-subj",
                "/CN=tailnet-unlock test CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign",
            ]
        )
    return ca


def issue_server_cert(directory: Path, host: str) -> tuple[Path, Path]:
    """A fresh certificate for the control server, signed by the CA, valid for a month."""
    key, csr, cert = directory / "server.key", directory / "server.csr", directory / "server.pem"
    extension = directory / "server.ext"
    extension.write_text(server_cert_ext(host))
    run(
        [
            "openssl",
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            "/CN=headscale",
        ]
    )
    run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(directory / "ca.pem"),
            "-CAkey",
            str(directory / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "30",
            "-extfile",
            str(extension),
        ]
    )
    return cert, key


# --- headscale ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Headscale:
    proc: subprocess.Popen[bytes]
    tools: Tools
    config: Path
    url: str
    ca: Path


def host_alias_ready(host: str) -> bool:
    """Whether this host can bind `host`; adds it to the loopback with sudo when it can."""

    def bindable() -> bool:
        with socket.socket() as probe:
            try:
                probe.bind((host, 0))
            except OSError:
                return False
            return True

    if bindable():
        return True
    if shutil.which("sudo"):
        subprocess.run(
            ["sudo", "-n", "ip", "addr", "add", f"{host}/32", "dev", "lo"],
            capture_output=True,
            check=False,
            timeout=30,
        )
    return bindable()


def wait_healthy(url: str, ca: Path, proc: subprocess.Popen[bytes], timeout: float = 60) -> None:
    context = ssl.create_default_context(cafile=str(ca))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"headscale exited with {proc.returncode}")
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=3, context=context) as response:  # noqa: S310  # the harness's own https URL
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.3)
    raise TimeoutError(f"headscale at {url} did not answer /health in {timeout} s")


def start_headscale(tools: Tools, state: Path, host: str = CONTROL_HOST) -> Headscale:
    """Start headscale on `state` (kept between runs, with the nodes the image enrolled)."""
    state.mkdir(parents=True, exist_ok=True)
    ca = ensure_ca(state / "tls")
    cert, key = issue_server_cert(state / "tls", host)
    policy = state / "policy.hujson"
    policy.write_text(headscale_policy((HERE.parent.parent / "examples/policy.hujson").read_text()))
    config = state / "config.yaml"
    config.write_text(headscale_config(state, host, cert, key, policy))
    log = (state / "headscale.log").open("ab")
    proc = subprocess.Popen(
        [str(tools.headscale), "serve", "-c", str(config)],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
    )
    url = headscale_url(host)
    wait_healthy(url, ca, proc)
    return Headscale(proc, tools, config, url, ca)


def stop_process(proc: subprocess.Popen[bytes], timeout: float = 20) -> None:
    """SIGTERM by the PID this harness started, KILL when it does not go."""
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def stop_headscale(hs: Headscale) -> None:
    stop_process(hs.proc)


def hs_json(hs: Headscale, *args: str) -> object:
    done = run([str(hs.tools.headscale), "-c", str(hs.config), *args, "-o", "json"])
    return json.loads(done.stdout)


def hs_list(hs: Headscale, *args: str) -> list[dict[str, object]]:
    parsed = hs_json(hs, *args)
    if parsed is None:  # an empty list prints as null
        return []
    assert isinstance(parsed, list)
    return [item for item in parsed if isinstance(item, dict)]


def ensure_user(hs: Headscale, name: str = OPERATOR) -> int:
    for user in hs_list(hs, "users", "list"):
        if user.get("name") == name:
            return int(str(user["id"]))
    run([str(hs.tools.headscale), "-c", str(hs.config), "users", "create", name])
    return ensure_user(hs, name)


def preauth_key(
    hs: Headscale,
    tag: str | None,
    user: str = OPERATOR,
    ephemeral: bool = True,
    expiration: str = "24h",
) -> str:
    """A pre-authorized, single-use key. With a tag, the node it enrols carries that tag and
    belongs to no user; without one it belongs to `user`."""
    argv = ["preauthkeys", "create", "-u", str(ensure_user(hs, user)), "-e", expiration]
    if tag:
        argv += ["--tags", tag]
    if ephemeral:
        argv.append("--ephemeral")
    parsed = hs_json(hs, *argv)
    assert isinstance(parsed, dict)
    return str(parsed["key"])


def nodes(hs: Headscale) -> list[dict[str, object]]:
    return hs_list(hs, "nodes", "list")


def node_by_ip(hs: Headscale, ip: str) -> dict[str, object] | None:
    for node in nodes(hs):
        addresses = node.get("ip_addresses")
        if isinstance(addresses, list) and ip in addresses:
            return node
    return None


def node_online(hs: Headscale, ip: str) -> bool:
    node = node_by_ip(hs, ip)
    return bool(node and node.get("online"))


def wait_online(hs: Headscale, ip: str, online: bool, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if node_online(hs, ip) == online:
            return True
        time.sleep(2)
    return node_online(hs, ip) == online


def check_policy(hs: Headscale) -> subprocess.CompletedProcess[str]:
    """headscale's own check of the loaded policy file, which runs the policy's `tests` against the
    nodes that exist now."""
    return subprocess.run(
        [
            str(hs.tools.headscale),
            "-c",
            str(hs.config),
            "policy",
            "check",
            "-f",
            str(hs.config.parent / "policy.hujson"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


# --- userspace nodes on the host ----------------------------------------------------------------


@dataclass(frozen=True)
class Node:
    name: str
    tools: Tools
    workdir: Path
    sock: Path
    proc: subprocess.Popen[bytes]
    env: dict[str, str]


def start_node(
    tools: Tools,
    hs: Headscale,
    workdir: Path,
    name: str,
    tag: str | None,
    user: str = OPERATOR,
) -> Node:
    """A userspace tailscaled enrolled with a fresh ephemeral key: tagged with `tag`, or owned by
    `user` when there is no tag."""
    workdir.mkdir(parents=True, exist_ok=True)
    sock = workdir / "tailscaled.sock"
    env = {**os.environ, "SSL_CERT_FILE": str(hs.ca)}
    log = (workdir / "tailscaled.log").open("ab")
    proc = subprocess.Popen(
        tailscaled_argv(tools, workdir / "state", sock),
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        env=env,
    )
    deadline = time.monotonic() + 20
    while not sock.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    node = Node(name, tools, workdir, sock, proc, env)
    up = subprocess.run(
        tailscale_up_argv(tools, sock, hs.url, preauth_key(hs, tag, user), name),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env=env,
    )
    if up.returncode != 0:
        stop_node(node)
        raise RuntimeError(f"tailscale up for {name} failed: {up.stdout} {up.stderr}")
    return node


def stop_node(node: Node) -> None:
    stop_process(node.proc)


def node_status(node: Node) -> dict[str, object]:
    done = subprocess.run(
        [str(node.tools.tailscale), f"--socket={node.sock}", "status", "--json"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env=node.env,
    )
    parsed: object = json.loads(done.stdout)
    assert isinstance(parsed, dict)
    return parsed


def node_ip(node: Node) -> str:
    status = node_status(node)
    me = status["Self"]
    assert isinstance(me, dict)
    addresses = me["TailscaleIPs"]
    assert isinstance(addresses, list)
    return first_ipv4([str(a) for a in addresses])


def reaches(node: Node, ip: str, port: int, banner: bytes = b"SSH-", timeout: float = 20) -> bool:
    """Whether a TCP connection from `node` to ip:port is accepted and the server speaks first.

    The test listeners and the door both send an SSH banner at once. A connection the policy
    drops never answers, which is what a refusal looks like from the sender's side.
    """
    proc = subprocess.Popen(
        [str(node.tools.tailscale), f"--socket={node.sock}", "nc", ip, str(port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=node.env,
    )
    try:
        assert proc.stdout is not None
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            return False
        return os.read(proc.stdout.fileno(), 64).startswith(banner)
    finally:
        proc.kill()
        proc.wait()


def wait_reaches(node: Node, ip: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if reaches(node, ip, port, timeout=8):
            return True
        time.sleep(2)
    return False


# --- pins: the hashes a version bump needs ------------------------------------------------------


def published_hashes(headscale_version: str, tailscale_version: str) -> dict[str, str]:
    """What the publishers print for a version, in the form pins.env holds it."""

    def read(url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310  # https URL built from the pins
            return bytes(response.read())

    sums = read(
        f"https://github.com/juanfont/headscale/releases/download/v{headscale_version}/checksums.txt"
    ).decode()
    wanted = f"headscale_{headscale_version}_linux_amd64"
    headscale = next(line.split()[0] for line in sums.splitlines() if line.endswith(f" {wanted}"))
    tgz = (
        read(f"https://pkgs.tailscale.com/stable/tailscale_{tailscale_version}_amd64.tgz.sha256")
        .decode()
        .split()[0]
    )
    keyring = hashlib.sha256(
        read("https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg")
    ).hexdigest()
    return {
        "HEADSCALE_SHA256": headscale,
        "TAILSCALE_TGZ_SHA256": tgz,
        "TAILSCALE_KEYRING_SHA256": keyring,
    }


def main(argv: list[str]) -> int:
    if argv[1:] != ["pins"]:
        print("usage: tailnet.py pins", file=sys.stderr)
        return 2
    pins = read_pins()
    for key, value in published_hashes(
        pins["HEADSCALE_VERSION"], pins["TAILSCALE_VERSION"]
    ).items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
