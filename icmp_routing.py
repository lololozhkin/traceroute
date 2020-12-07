import threading
import time
from collections import defaultdict

from scapy.sendrecv import send

from ip_version import IpVersion
from routing_type import RoutingType

from tracerouter import Tracerouter


class ICMPRouting(RoutingType):
    def __init__(
            self,
            traceroute: Tracerouter,
            ip_layer: IpVersion,
            request_layer,
            error_layer,
            response_layer
    ):
        super().__init__(traceroute, ip_layer)
        self.ttl_to_ids = defaultdict(list)
        self.id_to_ttl_and_time = {}
        self.ids = range((self.max_hops + 1) * self.times)
        self.lock = threading.Lock()
        self.req_layer = request_layer
        self.error_layer = error_layer
        self.resp_layer = response_layer

    def filter(self, packet):
        if not packet.haslayer(self.ip_layer):
            return False

        packet = packet.getlayer(self.ip_layer)
        if not packet.dst == self.src_ip:
            return False

        if packet.haslayer(self.error_layer):
            icmp = packet.getlayer(self.error_layer)
        elif packet.haslayer(self.resp_layer):
            icmp = packet.getlayer(self.resp_layer)
        else:
            icmp = None

        if icmp is not None and icmp.id in self.ids:
            return True

        if packet.src == self.dst_ip:
            return True

        return False

    def send_packet(self, ttl):
        with self.lock:
            packet_number = len(self.ttl_to_ids[ttl])
            packet_id = ttl * self.times + packet_number
            self.ttl_to_ids[ttl].append(packet_id)

        ip_layer = self.ip_fabric(self.tracerouter.dst_ip, ttl)
        icmp_layer = self.req_layer(id=packet_id)
        p = ip_layer / icmp_layer

        self.id_to_ttl_and_time[packet_id] = (ttl, time.time())
        send(p, verbose=0)

    def handle_packet(self, packet):
        ip_layer = packet.getlayer(self.ip_layer)

        if packet.haslayer(self.error_layer):
            icmp = packet.getlayer(self.error_layer)

        elif packet.haslayer(self.resp_layer):
            icmp = packet.getlayer(self.resp_layer)

        else:
            icmp = None

        packet_id = icmp.id if icmp is not None else 2 ** 16

        cur_time = time.time()
        ttl, packet_time = self.id_to_ttl_and_time[packet_id]
        delay = cur_time - packet_time

        return ip_layer.src, ttl, delay

