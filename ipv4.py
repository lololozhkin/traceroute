from ip_version import IpVersion
from scapy.layers.inet import IP


class Ipv4(IpVersion):
    def __init__(self):
        super().__init__(self.create_packet, IP)

    @staticmethod
    def create_packet(dst, ttl):
        return IP(dst=dst, ttl=ttl)
