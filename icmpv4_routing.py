from icmp_routing import ICMPRouting
from ip_version import IpVersion
from tracerouter import Tracerouter

from scapy.layers.inet import ICMP, ICMPerror


class ICMPv4Routing(ICMPRouting):
    def __init__(
            self,
            traceroute: Tracerouter,
            ip_layer: IpVersion,
    ):
        super().__init__(
            traceroute,
            ip_layer,
            ICMP,
            ICMPerror,
            ICMP
        )
