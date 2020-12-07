from ip_versions.ip_version import IpVersion
from .routing_with_ports import PortRouting
from utills.tracerouter import Tracerouter

from scapy.layers.inet import TCP, TCPerror


class TCPRouting(PortRouting):
    MAGIC_OPTIONS = [
        (2, b'\x05\xb4'),
        (4, b''),
        (8, b'\x48\xae\xc5\x30\x00\x00\x00\x00'),
        (1, b''),
        (3, b'\x07')
    ]

    def __init__(self, traceroute: Tracerouter, ip_version: IpVersion):
        super().__init__(
            traceroute,
            ip_version,
            TCP,
            TCPerror,
            TCPRouting.create_packet
        )

    @staticmethod
    def create_packet(src_port, dst_port):
        layer = TCP(
            dport=dst_port,
            sport=src_port,
            flags='S',
            options=TCPRouting.MAGIC_OPTIONS
        )

        return layer
