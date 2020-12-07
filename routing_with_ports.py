import random
import threading
import time

from collections import defaultdict

from scapy.sendrecv import send
from scapy.packet import Packet

from ip_version import IpVersion
from routing_type import RoutingType

from tracerouter import Tracerouter

from typing import Callable


class PortRouting(RoutingType):
    def __init__(
            self,
            traceroute: Tracerouter,
            ip_version: IpVersion,
            main_layer,
            error_layer,
            payload_fabric: Callable[[int, int], 'Packet']
    ):
        super().__init__(traceroute, ip_version)
        self.main_layer = main_layer
        self.error_layer = error_layer
        self.ttl_to_ports = defaultdict(list)
        self.port_to_ttl_and_time = {}
        self.used_ports = set()
        self.used_ports_lock = threading.Lock()
        self.ttl_to_ports_lock = threading.Lock()
        self.create_payload = payload_fabric

    def filter(self, packet):
        if not packet.haslayer(self.ip_layer):
            return False

        packet = packet.getlayer(self.ip_layer)
        if not packet.dst == self.src_ip:
            return False

        dst_port = self.get_dst_port_from_me(packet)
        src_port = self.get_src_port_from_me(packet)

        if dst_port == self.dst_port and src_port in self.used_ports:
            return True

        if packet.src == self.dst_ip:
            return True

        return False

    def send_packet(self, ttl):
        unused_port = self.get_unused_port()
        with self.ttl_to_ports_lock:
            self.ttl_to_ports[ttl].append(unused_port)

        layer = self.create_payload(unused_port, self.dst_port)
        p = self.ip_fabric(self.dst_ip, ttl) / layer

        self.port_to_ttl_and_time[unused_port] = (ttl, time.time())

        send(p, verbose=0)

    def handle_packet(self, packet):
        ip_layer = packet.getlayer(self.ip_layer)
        cur_time = time.time()

        port = self.get_src_port_from_me(ip_layer)
        port = port if port is not None else 2 ** 16

        ttl, packet_time = self.port_to_ttl_and_time[port]
        delay = cur_time - packet_time

        return ip_layer.src, ttl, delay

    def get_unused_port(self):
        while True:
            new_port = random.randint(49152, 65535)
            with self.used_ports_lock:
                if new_port not in self.used_ports:
                    self.used_ports.add(new_port)
                    return new_port

    def get_src_dst_port(self, packet):
        if packet.haslayer(self.error_layer):
            layer = packet.getlayer(self.error_layer)
            dst_port = layer.dport
            src_port = layer.sport
        elif packet.haslayer(self.main_layer):
            layer = packet.getlayer(self.main_layer)
            dst_port = layer.sport
            src_port = layer.dport
        else:
            dst_port, src_port = None, None

        return src_port, dst_port

    def get_dst_port_from_me(self, packet):
        _, dst = self.get_src_dst_port(packet)
        return dst

    def get_src_port_from_me(self, packet):
        src, _ = self.get_src_dst_port(packet)
        return src
