from typing import Callable
from scapy.packet import Packet


class IpVersion:
    def __init__(
            self,
            ip_layer_fabric: Callable[[str, int], Packet],
            ip_layer
    ):
        self.ip_layer_fabric = ip_layer_fabric
        self.ip_layer = ip_layer
