from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6
from scapy.layers.l2 import ARP
from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Raw

from periscope.capture import CaptureSummary, _is_quic_packet, _PacketHandler

# ===== _is_quic_packet =====


def test_is_quic_no_raw_layer_returns_false() -> None:
    pkt = IP() / UDP(dport=443)
    assert _is_quic_packet(pkt) is False


def test_is_quic_empty_payload_returns_false() -> None:
    pkt = IP() / UDP(dport=443) / Raw(load=b"")
    assert _is_quic_packet(pkt) is False


def test_is_quic_long_header_returns_true() -> None:
    # Long header: top 2 bits = 11 -> first byte 0xC0-0xFF
    pkt = IP() / UDP(dport=443) / Raw(load=bytes([0xC2, 0x00, 0x00, 0x00, 0x01]))
    assert _is_quic_packet(pkt) is True


def test_is_quic_short_header_returns_true() -> None:
    # Short header: top 2 bits = 01 -> first byte 0x40-0x7F
    pkt = IP() / UDP(dport=443) / Raw(load=bytes([0x44, 0x12, 0x34]))
    assert _is_quic_packet(pkt) is True


def test_is_quic_top_bits_00_returns_false() -> None:
    # Fixed Bit is 0 → not QUIC
    pkt = IP() / UDP(dport=443) / Raw(load=bytes([0x12, 0x34]))
    assert _is_quic_packet(pkt) is False


def test_is_quic_top_bits_10_returns_false() -> None:
    # Fixed Bit is 0 → not QUIC
    pkt = IP() / UDP(dport=443) / Raw(load=bytes([0x82, 0x00]))
    assert _is_quic_packet(pkt) is False


# ===== _PacketHandler dispatch =====


def test_arp_packet_is_ignored() -> None:
    handler = _PacketHandler()
    handler(ARP(op=1, psrc="10.1.0.2", pdst="10.1.0.1"))
    assert handler.summary.total_packets == 0


def test_icmpv6_packet_is_ignored() -> None:
    handler = _PacketHandler()
    handler(IPv6() / ICMPv6ND_NS())
    assert handler.summary.total_packets == 0


def test_dns_query_counted_in_dns_queries() -> None:
    handler = _PacketHandler()
    pkt = (
        IP(src="10.1.0.2", dst="1.1.1.1")
        / UDP(sport=33715, dport=53)
        / DNS(qd=DNSQR(qname="example.com"))
    )
    handler(pkt)
    assert handler.summary.dns_queries["example.com"] == 1
    assert handler.summary.total_packets == 1


def test_dns_query_not_counted_in_udp_destinations() -> None:
    handler = _PacketHandler()
    pkt = (
        IP(src="10.1.0.2", dst="1.1.1.1")
        / UDP(sport=33715, dport=53)
        / DNS(qd=DNSQR(qname="example.com"))
    )
    handler(pkt)
    assert len(handler.summary.udp_destinations) == 0


def test_dns_query_strips_trailing_dot() -> None:
    handler = _PacketHandler()
    pkt = (
        IP(src="10.1.0.2", dst="1.1.1.1")
        / UDP(sport=33715, dport=53)
        / DNS(qd=DNSQR(qname="example.com."))
    )
    handler(pkt)
    assert "example.com" in handler.summary.dns_queries
    assert "example.com." not in handler.summary.dns_queries


def test_tcp_syn_counted_as_outbound_destination() -> None:
    handler = _PacketHandler()
    pkt = IP(src="10.1.0.2", dst="93.184.216.34") / TCP(sport=12345, dport=443, flags="S")
    handler(pkt)
    assert handler.summary.tcp_destinations[("93.184.216.34", 443)] == 1


def test_tcp_syn_ack_not_counted() -> None:
    # SYN-ACK is the server's reply
    handler = _PacketHandler()
    pkt = IP(src="93.184.216.34", dst="10.1.0.2") / TCP(sport=443, dport=12345, flags="SA")
    handler(pkt)
    assert len(handler.summary.tcp_destinations) == 0


def test_tcp_ack_only_not_counted() -> None:
    handler = _PacketHandler()
    pkt = IP(src="10.1.0.2", dst="93.184.216.34") / TCP(sport=12345, dport=443, flags="A")
    handler(pkt)
    assert len(handler.summary.tcp_destinations) == 0


def test_quic_long_header_counted_as_quic() -> None:
    handler = _PacketHandler()
    pkt = (
        IP(src="10.1.0.2", dst="104.18.27.14")
        / UDP(sport=33000, dport=443)
        / Raw(load=bytes([0xC2, 0x00, 0x00, 0x00, 0x01]))
    )
    handler(pkt)
    assert handler.summary.quic_destinations[("104.18.27.14", 443)] == 1
    assert len(handler.summary.udp_destinations) == 0


def test_udp_443_with_non_quic_payload_falls_to_udp() -> None:
    # Top 2 bits 00 → not QUIC, must land in udp_destinations even on port 443.
    handler = _PacketHandler()
    pkt = (
        IP(src="10.1.0.2", dst="104.18.27.14")
        / UDP(sport=33000, dport=443)
        / Raw(load=bytes([0x00, 0x01, 0x02]))
    )
    handler(pkt)
    assert handler.summary.udp_destinations[("104.18.27.14", 443)] == 1
    assert len(handler.summary.quic_destinations) == 0


def test_udp_443_with_no_payload_falls_to_udp() -> None:
    handler = _PacketHandler()
    pkt = IP(src="10.1.0.2", dst="104.18.27.14") / UDP(sport=33000, dport=443)
    handler(pkt)
    assert handler.summary.udp_destinations[("104.18.27.14", 443)] == 1


def test_plain_udp_counted_in_udp_destinations() -> None:
    handler = _PacketHandler()
    pkt = (
        IP(src="10.1.0.2", dst="129.6.15.28")
        / UDP(sport=33000, dport=123)
        / Raw(load=b"\x1b" + b"\x00" * 47)
    )
    handler(pkt)
    assert handler.summary.udp_destinations[("129.6.15.28", 123)] == 1


def test_udp_over_ipv6_uses_ipv6_destination() -> None:
    handler = _PacketHandler()
    pkt = (
        IPv6(src="2001:db8::1", dst="2606:4700::1111")
        / UDP(sport=33000, dport=443)
        / Raw(load=bytes([0xC2, 0x00, 0x00, 0x00, 0x01]))
    )
    handler(pkt)
    assert handler.summary.quic_destinations[("2606:4700::1111", 443)] == 1


def test_tls_client_hello_sni_counted() -> None:
    handler = _PacketHandler()
    sni_ext = TLS_Ext_ServerName(servernames=[ServerName(servername=b"example.com")])  # type: ignore[no-untyped-call]
    pkt = (
        IP(src="10.1.0.2", dst="93.184.216.34")
        / TCP(sport=33000, dport=443, flags="PA")
        / TLSClientHello(ext=[sni_ext])  # type: ignore[no-untyped-call]
    )
    handler(pkt)
    assert handler.summary.sni_entries["example.com"] == 1


def test_tls_client_hello_with_multiple_servernames() -> None:
    handler = _PacketHandler()
    sni_ext = TLS_Ext_ServerName(  # type: ignore[no-untyped-call]
        servernames=[
            ServerName(servername=b"a.example.com"),
            ServerName(servername=b"b.example.com"),
        ]
    )
    pkt = (
        IP(src="10.1.0.2", dst="93.184.216.34")
        / TCP(sport=33000, dport=443, flags="PA")
        / TLSClientHello(ext=[sni_ext])  # type: ignore[no-untyped-call]
    )
    handler(pkt)
    assert handler.summary.sni_entries["a.example.com"] == 1
    assert handler.summary.sni_entries["b.example.com"] == 1


def test_total_packets_increments_only_for_tcp_or_udp() -> None:
    handler = _PacketHandler()
    handler(ARP())
    handler(IP() / TCP(dport=443, flags="S"))
    handler(IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="a.com")))
    handler(IPv6() / ICMPv6ND_NS())
    assert handler.summary.total_packets == 2


def test_repeated_destination_increments_counter() -> None:
    handler = _PacketHandler()
    pkt = IP(src="10.1.0.2", dst="93.184.216.34") / TCP(dport=443, flags="S")
    handler(pkt)
    handler(pkt)
    handler(pkt)
    assert handler.summary.tcp_destinations[("93.184.216.34", 443)] == 3


# ===== CaptureSummary.render() =====


def test_render_empty_summary_shows_no_observations() -> None:
    out = CaptureSummary().render()
    assert "no" in out.lower()


def test_render_includes_dns_section_when_populated() -> None:
    s = CaptureSummary()
    s.dns_queries["example.com"] = 3
    out = s.render()
    assert "DNS queries" in out
    assert "example.com" in out
    assert "3" in out


def test_render_includes_tcp_section_when_populated() -> None:
    s = CaptureSummary()
    s.tcp_destinations[("1.2.3.4", 443)] = 1
    out = s.render()
    assert "TCP destinations" in out
    assert "1.2.3.4:443" in out


def test_render_includes_udp_section_when_populated() -> None:
    s = CaptureSummary()
    s.udp_destinations[("1.2.3.4", 123)] = 1
    out = s.render()
    assert "UDP destinations" in out
    assert "1.2.3.4:123" in out


def test_render_includes_quic_section_when_populated() -> None:
    s = CaptureSummary()
    s.quic_destinations[("1.2.3.4", 443)] = 1
    out = s.render()
    assert "QUIC destinations" in out
    assert "1.2.3.4:443" in out


def test_render_includes_sni_section_when_populated() -> None:
    s = CaptureSummary()
    s.sni_entries["example.com"] = 1
    out = s.render()
    assert "SNI" in out
    assert "example.com" in out


def test_render_includes_total_packet_count() -> None:
    s = CaptureSummary(total_packets=42)
    out = s.render()
    assert "42" in out


def test_render_orders_destinations_by_count() -> None:
    s = CaptureSummary()
    s.tcp_destinations[("1.1.1.1", 443)] = 2
    s.tcp_destinations[("2.2.2.2", 443)] = 10
    s.tcp_destinations[("3.3.3.3", 443)] = 5
    out = s.render()
    # most_common() puts the highest first
    pos_2 = out.index("2.2.2.2")
    pos_3 = out.index("3.3.3.3")
    pos_1 = out.index("1.1.1.1")
    assert pos_2 < pos_3 < pos_1
