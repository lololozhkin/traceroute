from abc import ABC, abstractmethod

import tracerouter
from ip_version import IpVersion


class RoutingType(ABC):
    def __init__(
            self,
            traceroute: 'tracerouter.Tracerouter',
            ip_version: IpVersion
    ):
        self.tracerouter = traceroute
        self.src_ip = traceroute.src_ip
        self.dst_ip = traceroute.dst_ip
        self.max_hops = traceroute.max_hops
        self.times = traceroute.times
        self.dst_port = traceroute.dst_port
        self.ip_version = ip_version
        self.ip_layer = ip_version.ip_layer
        self.ip_fabric = ip_version.ip_layer_fabric

    @abstractmethod
    def filter(self, packet):
        pass

    @abstractmethod
    def send_packet(self, ttl):
        pass

    @abstractmethod
    def handle_packet(self, packet):
        pass
