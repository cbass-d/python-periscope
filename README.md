# periscope

[![CI](https://github.com/cbass-d/python-periscope/actions/workflows/ci.yml/badge.svg)](https://github.com/cbass-d/python-periscope/actions/workflows/ci.yml)

[![Release](https://github.com/cbass-d/python-periscope/actions/workflows/release.yml/badge.svg)](https://github.com/cbass-d/python-periscope/actions/workflows/release.yml)

Audit a container's network egress. Periscope runs a container inside an isolated Linux network namespace and reports every DNS query, TCP/UDP destination, QUIC endpoint, and TLS SNI it reaches.

```
$ sudo periscope profile docker.io/curlimages/curl wlp0s20f3 -- -sL https://example.com

=== Capture Summary (12 packets) ===

DNS queries:
   2  example.com

TCP destinations (outbound SYN):
   1  93.184.216.34:443

TLS SNI Entries:
example.com
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

Verify the host can run periscope:

```bash
sudo .venv/bin/periscope check <UPLINK_IFACE>
```

Profile a container:

```bash
sudo .venv/bin/periscope profile <IMAGE> <UPLINK_IFACE> [OPTIONS] -- [container args...]
```

The `--` separates periscope's options from the container's command.

### Options

| Flag | Default | Description |
|---|---|---|
| `--duration`, `-d` | `60` | Capture duration in seconds |
| `--namespace`, `-n` | `periscope-ns` | Linux netns name to create |
| `--subnet`, `-s` | `10.0.0.0/24` | Subnet for the namespace's veth pair |
| `--json` | off | Emit JSON to stdout instead of the human-readable summary |
| `--policy`, `-p` | none | TOML policy file with expected destinations; appends a diff to the output |
| `--strict` | off | Exit code 2 if any captured destination is not in the policy (requires `--policy`) |

### Examples

```bash
# Profile an HTTP/3 client — captures QUIC traffic
sudo periscope profile docker.io/ymuski/curl-http3 wlan0 -- \
    curl -4 --http3-only -s -o /dev/null https://cloudflare-quic.com

# Pipe JSON output to jq
sudo periscope profile docker.io/curlimages/curl wlan0 --json -- \
    -sL https://example.com | jq '.dns_queries'

# Custom subnet to avoid host conflicts
sudo periscope profile docker.io/curlimages/curl wlan0 -s 172.20.0.0/24 -- \
    -sI https://example.com
```

## What it captures

- **DNS queries** — every name looked up
- **TCP destinations** — outbound SYNs, keyed on `(IP, port)`
- **UDP destinations** — non-DNS UDP (NTP, gaming, etc.)
- **QUIC destinations** — UDP/443 packets matching the QUIC header bit pattern (RFC 9000 §17)
- **TLS SNI** — server name extracted from outbound `ClientHello`

Inbound responses are filtered out — "destinations" describes where the container reached, not who reached back. (DNS *responses* are an exception: they're parsed to link hostnames to the IPs the container actually received, which the policy diff uses below.)

## Policy: expected destinations

A TOML policy file declares per-channel allowlists. `periscope profile --policy egress.toml` compares the capture against the policy and appends a **diff** showing *unexpected* destinations (reached but not allowed) and *expected-unused* entries (allowed but never observed). Add `--strict` to exit nonzero on unexpected destinations — useful as a CI gate.

```toml
# egress.toml
[dns]
allowed = ["example.com", "*.cdn.example.com"]

[sni]
allowed = ["example.com"]

[tcp]
allowed = ["8.8.8.8:53", "1.1.1.1:*"]   # port "*" = any port

[udp]
allowed = ["8.8.8.8:53"]

[quic]
allowed = ["1.1.1.1:443"]
```

- Hostnames support exact match and `*.suffix` wildcards (the wildcard does *not* match the apex).
- Endpoints are `ip:port` or `ip:*`.
- Any section may be omitted.

**Hostname ↔ IP linkage.** A hostname listed under `[dns]` implicitly allows the IPs the container actually received for it via captured DNS responses. So if `example.com` is in `[dns]` and the container hits `93.184.216.34:443` after resolving it, that endpoint is treated as expected without needing an explicit `[tcp]` entry. The link comes from the run's own DNS traffic — no host-side resolution at diff time, so the result is reproducible.

```bash
# CI gate: fail the run if anything outside the policy was reached
sudo periscope profile docker.io/curlimages/curl wlan0 \
    --policy egress.toml --strict -- -sL https://example.com

# Get the diff as JSON
sudo periscope profile docker.io/curlimages/curl wlan0 \
    --policy egress.toml --json -- -sL https://example.com | jq '.policy_diff'
```

Exit codes: `0` clean, `1` argument/config error, `2` strict policy violation.

## How it works

A run sets up the host (IP forwarding, NAT via nftables, FORWARD ACCEPT via iptables), creates the namespace + veth pair, writes a working `resolv.conf` for it, starts a scapy sniffer on the host-side veth, then `podman run --network=ns:` puts the workload directly in that namespace. When the container exits, the sniffer stops, the summary prints, and everything unwinds — atomically, with rollback on partial failure.

## Design notes

- **Podman over Docker** — `--network=ns:` joins an existing namespace in one flag; Docker has no equivalent.
- **`nft` for our own NAT, `iptables` for the system FORWARD chain** — atomic teardown for state we own (`nft delete table`), delete-by-spec for state we don't (`iptables -D`).
- **`CommandRunner` Protocol over `subprocess`** — production calls shell out; tests use `FakeRunner` to assert exact command sequences without root or network mutation.
- **`@contextmanager` composition** — `session()` nests `Egress` and `NetworkSandbox` in one `with`, getting LIFO teardown.

## Limitations

- Linux only (uses Linux network namespaces).
- IPv4-only NAT/forwarding — IPv6 traffic from the namespace won't reach external IPv6 destinations.
- TLS SNI is only extracted from TCP-based TLS handshakes; QUIC Initial decryption is not implemented.
- Image must be pullable by `podman`. Use the fully qualified `docker.io/...` form unless you've configured `unqualified-search-registries`.

## Development

```bash
uv sync
uv run pytest                    # 45 tests, no root required
uv run mypy src tests
uv run ruff check src tests
```

Tests use `FakeRunner` and constructed scapy packets — no real network state is touched. Pre-commit hooks run `ruff` on commit and `mypy + pytest` on push.
