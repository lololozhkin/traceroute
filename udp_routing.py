from ip_version import IpVersion
from routing_with_ports import PortRouting
from scapy.layers.inet import UDP, UDPerror

from tracerouter import Tracerouter


class UDPRouting(PortRouting):
    def __init__(self, traceroute: Tracerouter, ip_version: IpVersion):
        super().__init__(
            traceroute,
            ip_version,
            UDP,
            UDPerror,
            UDPRouting.create_packet,
        )

    @staticmethod
    def create_packet(src_port, dst_port):
        packet = UDP(sport=src_port, dport=dst_port) / b'abacabadabacaba'
        return packet
