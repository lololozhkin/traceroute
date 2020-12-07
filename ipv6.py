from ip_version import IpVersion
from scapy.layers.inet6 import IPv6


class Ipv6(IpVersion):
    def __init__(self):
        super().__init__(self.create_packet, IPv6, 'ipv6')

    @staticmethod
    def create_packet(dst, ttl):
        return IPv6(dst=dst, hlim=ttl)
