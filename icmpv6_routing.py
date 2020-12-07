from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply

from icmp_routing import ICMPRouting
from ip_version import IpVersion
from tracerouter import Tracerouter


class ICMPv6Routing(ICMPRouting):
    def __init__(
            self,
            traceroute: Tracerouter,
            ip_layer: IpVersion,
    ):
        super().__init__(
            traceroute,
            ip_layer,
            ICMPv6EchoRequest,
            ICMPv6EchoRequest,
            ICMPv6EchoReply
        )
