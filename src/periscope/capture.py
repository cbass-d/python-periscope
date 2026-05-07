from collections import Counter
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field

from loguru import logger
from scapy.all import load_layer
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer


@dataclass
class CaptureSummary:
    total_packets: int = 0
    dns_queries: Counter[str] = field(default_factory=Counter)
    tcp_destinations: Counter[tuple[str, int]] = field(default_factory=Counter)
    sni_entries: Counter[str] = field(default_factory=Counter)

    def render(self) -> str:
        lines = [f"\n=== Capture Summary ({self.total_packets} packets) ==="]

        if self.dns_queries:
            lines.append("\nDNS queries:")
            for name, count in self.dns_queries.most_common():
                lines.append(f"  {count:>4}  {name}")

        if self.tcp_destinations:
            lines.append("\nTCP destinations (outbound SYN):")
            for (ip, port), count in self.tcp_destinations.most_common():
                lines.append(f"  {count:>4}  {ip}:{port}")

        if self.sni_entries:
            lines.append("\nTLS SNI Entries:")
            for name, _count in self.sni_entries.most_common():
                lines.append(f"{name}")

        if not self.dns_queries and not self.tcp_destinations:
            lines.append("\n(no DNS queries or TCP connections observed)")

        return "\n".join(lines)


class _PacketHandler:
    def __init__(self) -> None:
        self.summary = CaptureSummary()

    def __call__(self, pkt: Packet) -> None:
        self.summary.total_packets += 1

        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            self.summary.dns_queries[qname] += 1

        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp = pkt[TCP]
            # SYN set, ACK clear → outbound connection initiation
            if tcp.flags & 0x02 and not tcp.flags & 0x10:
                dst = pkt[IP].dst
                port = tcp.dport
                self.summary.tcp_destinations[(dst, port)] += 1

        if pkt.haslayer(TLSClientHello):
            for ext in pkt[TLSClientHello].ext or []:
                if isinstance(ext, TLS_Ext_ServerName):
                    for sn in ext.servernames or []:
                        name = sn.servername.decode(errors="replace")
                        self.summary.sni_entries[name] += 1


@contextmanager
def capture(iface: str) -> Generator[CaptureSummary]:
    """Sniff packets on `iface` for the duration of the with-block.

    Yields a CaptureSummary that is populated live and finalized on exit.
    Print `summary.render()` after the block to display results.
    """
    handler = _PacketHandler()
    load_layer("tls")
    sniffer = AsyncSniffer(iface=iface, prn=handler, store=False)
    logger.info("starting capture", iface=iface)
    sniffer.start()
    try:
        yield handler.summary
    finally:
        sniffer.stop()
        logger.info("capture stopped", packets=handler.summary.total_packets)
