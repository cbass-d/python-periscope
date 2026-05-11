"""Compare a CaptureSummary against a Policy to surface mismatches."""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from periscope.capture import CaptureSummary
from periscope.policy import Policy, match_endpoint, match_host

Endpoint = tuple[str, int]


@dataclass
class DiffResult:
    unexpected_dns: list[str] = field(default_factory=list)
    unexpected_sni: list[str] = field(default_factory=list)
    unexpected_tcp: list[Endpoint] = field(default_factory=list)
    unexpected_udp: list[Endpoint] = field(default_factory=list)
    unexpected_quic: list[Endpoint] = field(default_factory=list)

    unused_dns: list[str] = field(default_factory=list)
    unused_sni: list[str] = field(default_factory=list)
    unused_tcp: list[tuple[str, int | None]] = field(default_factory=list)
    unused_udp: list[tuple[str, int | None]] = field(default_factory=list)
    unused_quic: list[tuple[str, int | None]] = field(default_factory=list)

    def has_unexpected(self) -> bool:
        return bool(
            self.unexpected_dns
            or self.unexpected_sni
            or self.unexpected_tcp
            or self.unexpected_udp
            or self.unexpected_quic
        )

    def to_dict(self) -> dict[str, Any]:
        def eps(items: list[Endpoint]) -> list[dict[str, Any]]:
            return [{"ip": ip, "port": port} for ip, port in items]

        def pats(
            items: list[tuple[str, int | None]],
        ) -> list[str]:
            return [f"{ip}:{'*' if port is None else port}" for ip, port in items]

        return {
            "unexpected": {
                "dns": list(self.unexpected_dns),
                "sni": list(self.unexpected_sni),
                "tcp": eps(self.unexpected_tcp),
                "udp": eps(self.unexpected_udp),
                "quic": eps(self.unexpected_quic),
            },
            "expected_unused": {
                "dns": list(self.unused_dns),
                "sni": list(self.unused_sni),
                "tcp": pats(self.unused_tcp),
                "udp": pats(self.unused_udp),
                "quic": pats(self.unused_quic),
            },
        }

    def render(self) -> str:
        lines = ["\n=== Policy Diff ==="]

        def _host_section(label: str, items: list[str]) -> None:
            if items:
                lines.append(f"\n{label}:")
                lines.extend(f"  - {name}" for name in items)

        def _ep_section(label: str, items: list[Endpoint]) -> None:
            if items:
                lines.append(f"\n{label}:")
                lines.extend(f"  - {ip}:{port}" for ip, port in items)

        def _pat_section(label: str, items: list[tuple[str, int | None]]) -> None:
            if items:
                lines.append(f"\n{label}:")
                lines.extend(f"  - {ip}:{'*' if port is None else port}" for ip, port in items)

        _host_section("Unexpected DNS queries", self.unexpected_dns)
        _host_section("Unexpected TLS SNI", self.unexpected_sni)
        _ep_section("Unexpected TCP destinations", self.unexpected_tcp)
        _ep_section("Unexpected UDP destinations", self.unexpected_udp)
        _ep_section("Unexpected QUIC destinations", self.unexpected_quic)

        _host_section("Expected DNS never queried", self.unused_dns)
        _host_section("Expected SNI never observed", self.unused_sni)
        _pat_section("Expected TCP never reached", self.unused_tcp)
        _pat_section("Expected UDP never reached", self.unused_udp)
        _pat_section("Expected QUIC never reached", self.unused_quic)

        if not self.has_unexpected() and len(lines) == 1:
            lines.append("\nAll captured destinations matched the policy.")

        return "\n".join(lines)


def compute_diff(summary: CaptureSummary, policy: Policy) -> DiffResult:
    """Diff `summary` against `policy`.

    Hostnames in `[dns].allowed` implicitly allow IP destinations the container
    actually reached for those hostnames, via captured DNS answers.
    """
    result = DiffResult()

    # IPs implicitly allowed because their hostname matched `policy.dns`.
    implicit_ips: set[str] = set()
    used_dns_patterns: set[str] = set()
    for qname, ips in summary.dns_answers.items():
        match = match_host(qname, policy.dns)
        if match is not None:
            implicit_ips.update(ips)
            used_dns_patterns.add(match)

    used_sni_patterns: set[str] = set()
    used_tcp_patterns: set[tuple[str, int | None]] = set()
    used_udp_patterns: set[tuple[str, int | None]] = set()
    used_quic_patterns: set[tuple[str, int | None]] = set()

    for qname in summary.dns_queries:
        match = match_host(qname, policy.dns)
        if match is None:
            result.unexpected_dns.append(qname)
        else:
            used_dns_patterns.add(match)

    for name in summary.sni_entries:
        match = match_host(name, policy.sni)
        if match is None:
            result.unexpected_sni.append(name)
        else:
            used_sni_patterns.add(match)

    def _check_endpoints(
        captured: Counter[tuple[str, int]],
        patterns: frozenset[tuple[str, int | None]],
        used: set[tuple[str, int | None]],
        unexpected: list[Endpoint],
    ) -> None:
        for ip, port in captured:
            pat = match_endpoint(ip, port, patterns)
            if pat is not None:
                used.add(pat)
            elif ip in implicit_ips:
                continue
            else:
                unexpected.append((ip, port))

    _check_endpoints(summary.tcp_destinations, policy.tcp, used_tcp_patterns, result.unexpected_tcp)
    _check_endpoints(summary.udp_destinations, policy.udp, used_udp_patterns, result.unexpected_udp)
    _check_endpoints(
        summary.quic_destinations, policy.quic, used_quic_patterns, result.unexpected_quic
    )

    def _ep_key(p: tuple[str, int | None]) -> tuple[str, int]:
        return (p[0], -1 if p[1] is None else p[1])

    result.unused_dns = sorted(policy.dns - used_dns_patterns)
    result.unused_sni = sorted(policy.sni - used_sni_patterns)
    result.unused_tcp = sorted(policy.tcp - used_tcp_patterns, key=_ep_key)
    result.unused_udp = sorted(policy.udp - used_udp_patterns, key=_ep_key)
    result.unused_quic = sorted(policy.quic - used_quic_patterns, key=_ep_key)

    return result
