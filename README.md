# periscope

[![CI](https://github.com/cbass-d/python-periscope/actions/workflows/ci.yml/badge.svg)](https://github.com/cbass-d/python-periscope/actions/workflows/ci.yml)

Audit a container's network egress. Periscope runs a container inside an isolated Linux network namespace and reports every DNS query and TCP destination it reaches.

```
$ sudo periscope profile docker.io/curlimages/curl wlp0s20f3 -- -sI https://www.google.com

=== Capture Summary (12 packets) ===

DNS queries:
   1  www.google.com

TCP destinations (outbound SYN):
   1  142.250.80.4:443
```

## Why

Running `tcpdump` on the host conflates the container's traffic with everything else. Periscope gives the container its own namespace, NATs egress through a chosen uplink, and sniffs only the veth — so the report is exactly the container's traffic, no host noise.

## Install

Linux, Python 3.14+, [`uv`](https://docs.astral.sh/uv/), `podman`, `iptables`, `nft`.

```bash
git clone https://github.com/cbass-d/python-periscope
cd python-periscope
uv sync
```

All commands need `sudo` (network namespaces, iptables, sysctl).

## Usage

```bash
sudo .venv/bin/periscope profile <IMAGE> <UPLINK_IFACE> -- [container args...]
```

The `--` separates periscope's args from the container's command.

## How it works

A run sets up the host (IP forwarding, NAT via nftables, FORWARD ACCEPT via iptables), creates the namespace + veth pair, writes a working `resolv.conf` for it, starts a scapy sniffer on the host-side veth, then `podman run --network=ns:` puts the workload directly in that namespace. When the container exits, the sniffer stops, the summary prints, and everything unwinds — atomically, with rollback on partial failure.

## Design notes

- **Podman over Docker** — `--network=ns:` joins an existing namespace in one flag; Docker has no equivalent.
- **`nft` for our own NAT, `iptables` for the system FORWARD chain** — atomic teardown for state we own (`nft delete table`), delete-by-spec for state we don't (`iptables -D`).
- **`CommandRunner` Protocol over `subprocess`** — production calls shell out; tests use `FakeRunner` to assert exact command sequences without root or network mutation.
- **`@contextmanager` composition** — `session()` nests `Egress` and `NetworkSandbox` in one `with`, getting LIFO teardown.

## Development

```bash
uv sync
uv run pytest
```

Tests use `FakeRunner` and don't touch real network state.
