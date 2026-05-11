from periscope.capture import CaptureSummary
from periscope.diff import compute_diff
from periscope.policy import Policy


def _summary(
    *,
    dns_queries: dict[str, int] | None = None,
    sni_entries: dict[str, int] | None = None,
    tcp: dict[tuple[str, int], int] | None = None,
    udp: dict[tuple[str, int], int] | None = None,
    quic: dict[tuple[str, int], int] | None = None,
    dns_answers: dict[str, set[str]] | None = None,
) -> CaptureSummary:
    s = CaptureSummary()
    for name, count in (dns_queries or {}).items():
        s.dns_queries[name] = count
    for name, count in (sni_entries or {}).items():
        s.sni_entries[name] = count
    for endpoint, count in (tcp or {}).items():
        s.tcp_destinations[endpoint] = count
    for endpoint, count in (udp or {}).items():
        s.udp_destinations[endpoint] = count
    for endpoint, count in (quic or {}).items():
        s.quic_destinations[endpoint] = count
    if dns_answers:
        s.dns_answers = {name: set(ips) for name, ips in dns_answers.items()}
    return s


# ===== Empty cases =====


def test_empty_summary_against_empty_policy() -> None:
    diff = compute_diff(_summary(), Policy())
    assert not diff.has_unexpected()
    assert diff.unused_dns == []


# ===== DNS / SNI =====


def test_dns_query_in_allowlist_is_expected() -> None:
    s = _summary(dns_queries={"example.com": 1})
    p = Policy(dns=frozenset({"example.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_dns == []
    assert diff.unused_dns == []


def test_dns_query_not_in_allowlist_is_unexpected() -> None:
    s = _summary(dns_queries={"evil.com": 1})
    p = Policy(dns=frozenset({"example.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_dns == ["evil.com"]
    assert diff.has_unexpected() is True


def test_dns_wildcard_matches() -> None:
    s = _summary(dns_queries={"a.cdn.com": 1, "b.cdn.com": 1})
    p = Policy(dns=frozenset({"*.cdn.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_dns == []
    assert diff.unused_dns == []


def test_sni_unexpected_when_not_in_allowlist() -> None:
    s = _summary(sni_entries={"evil.com": 1})
    p = Policy(sni=frozenset({"example.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_sni == ["evil.com"]
    assert diff.unused_sni == ["example.com"]


# ===== Endpoints (TCP/UDP/QUIC) =====


def test_tcp_endpoint_in_allowlist_is_expected() -> None:
    s = _summary(tcp={("1.2.3.4", 443): 1})
    p = Policy(tcp=frozenset({("1.2.3.4", 443)}))
    diff = compute_diff(s, p)
    assert diff.unexpected_tcp == []
    assert diff.unused_tcp == []


def test_tcp_endpoint_not_in_allowlist_is_unexpected() -> None:
    s = _summary(tcp={("9.9.9.9", 443): 1})
    p = Policy(tcp=frozenset({("1.2.3.4", 443)}))
    diff = compute_diff(s, p)
    assert diff.unexpected_tcp == [("9.9.9.9", 443)]


def test_tcp_port_wildcard_allows_any_port() -> None:
    s = _summary(tcp={("1.2.3.4", 8080): 1, ("1.2.3.4", 443): 1})
    p = Policy(tcp=frozenset({("1.2.3.4", None)}))
    diff = compute_diff(s, p)
    assert diff.unexpected_tcp == []


def test_udp_and_quic_channels() -> None:
    s = _summary(
        udp={("8.8.8.8", 53): 1},
        quic={("1.1.1.1", 443): 1},
    )
    p = Policy(
        udp=frozenset({("8.8.8.8", 53)}),
        quic=frozenset({("1.1.1.1", 443)}),
    )
    diff = compute_diff(s, p)
    assert diff.unexpected_udp == []
    assert diff.unexpected_quic == []


# ===== Hostname → IP linkage via dns_answers =====


def test_endpoint_implicitly_allowed_by_dns_answer() -> None:
    # example.com is allowed in [dns]; the resolver returned 93.184.216.34;
    # the container then hit 93.184.216.34:443. That should be expected.
    s = _summary(
        dns_queries={"example.com": 1},
        dns_answers={"example.com": {"93.184.216.34"}},
        tcp={("93.184.216.34", 443): 1},
    )
    p = Policy(dns=frozenset({"example.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_tcp == []


def test_implicit_ip_allow_does_not_apply_when_hostname_not_in_dns_policy() -> None:
    # DNS answer exists but the hostname is NOT in policy.dns → endpoint stays unexpected.
    s = _summary(
        dns_queries={"evil.com": 1},
        dns_answers={"evil.com": {"6.6.6.6"}},
        tcp={("6.6.6.6", 443): 1},
    )
    p = Policy(dns=frozenset({"example.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_tcp == [("6.6.6.6", 443)]


def test_implicit_ip_allow_works_for_udp_and_quic_too() -> None:
    s = _summary(
        dns_queries={"example.com": 1},
        dns_answers={"example.com": {"93.184.216.34"}},
        udp={("93.184.216.34", 8000): 1},
        quic={("93.184.216.34", 443): 1},
    )
    p = Policy(dns=frozenset({"example.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_udp == []
    assert diff.unexpected_quic == []


def test_implicit_ip_allow_via_wildcard_dns_pattern() -> None:
    s = _summary(
        dns_queries={"api.cdn.com": 1},
        dns_answers={"api.cdn.com": {"5.5.5.5"}},
        tcp={("5.5.5.5", 443): 1},
    )
    p = Policy(dns=frozenset({"*.cdn.com"}))
    diff = compute_diff(s, p)
    assert diff.unexpected_tcp == []


# ===== expected_unused =====


def test_unused_dns_pattern_reported() -> None:
    s = _summary(dns_queries={"example.com": 1})
    p = Policy(dns=frozenset({"example.com", "unused.com"}))
    diff = compute_diff(s, p)
    assert diff.unused_dns == ["unused.com"]


def test_unused_tcp_pattern_reported() -> None:
    s = _summary(tcp={("1.2.3.4", 443): 1})
    p = Policy(tcp=frozenset({("1.2.3.4", 443), ("9.9.9.9", 80)}))
    diff = compute_diff(s, p)
    assert diff.unused_tcp == [("9.9.9.9", 80)]


def test_unused_does_not_affect_has_unexpected() -> None:
    s = _summary()
    p = Policy(dns=frozenset({"example.com"}))
    diff = compute_diff(s, p)
    assert diff.has_unexpected() is False
    assert diff.unused_dns == ["example.com"]


# ===== Serialization =====


def test_to_dict_shape() -> None:
    s = _summary(
        dns_queries={"evil.com": 1},
        tcp={("9.9.9.9", 443): 1},
    )
    p = Policy(dns=frozenset({"example.com"}))
    out = compute_diff(s, p).to_dict()
    assert out["unexpected"]["dns"] == ["evil.com"]
    assert out["unexpected"]["tcp"] == [{"ip": "9.9.9.9", "port": 443}]
    assert out["expected_unused"]["dns"] == ["example.com"]


def test_render_reports_match_when_no_unexpected() -> None:
    s = _summary(dns_queries={"example.com": 1})
    p = Policy(dns=frozenset({"example.com"}))
    out = compute_diff(s, p).render()
    assert "All captured destinations matched" in out


def test_render_includes_unexpected_sections() -> None:
    s = _summary(
        dns_queries={"evil.com": 1},
        tcp={("9.9.9.9", 443): 1},
    )
    p = Policy()
    out = compute_diff(s, p).render()
    assert "Unexpected DNS queries" in out
    assert "evil.com" in out
    assert "Unexpected TCP destinations" in out
    assert "9.9.9.9:443" in out
