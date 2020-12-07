from scapy.layers.inet import ICMP, ICMPerror

from .icmp_routing import ICMPRouting
from ip_versions.ip_version import IpVersion
from utills.tracerouter import Tracerouter


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
