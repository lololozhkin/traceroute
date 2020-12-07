import threading
from collections import defaultdict

from scapy.sendrecv import sniff

from ip_version import IpVersion
from routing_type import RoutingType
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from typing import Callable

from concurrent.futures import ThreadPoolExecutor


def get_my_ip(version):
    if version == 'ipv4':
        p = IP(dst='8.8.8.8')
        return p.src
    else:
        p = IPv6(dst='2001:4860:4860::8888')
        return p.src


class Tracerouter:
    def __init__(
            self,
            dst_ip,
            routing_type_fabric: Callable[['Tracerouter', IpVersion], RoutingType],
            ip_version: IpVersion,
            dst_port=80,
            max_hops: int = 30,
            times: int = 3,
            timeout: float = 2.0,
            max_workers=4
    ):
        self.dst_ip = dst_ip
        self.timeout = timeout
        self.times = times
        self.max_hops = max_hops
        self.src_ip = get_my_ip(ip_version.ver_str)
        self._results = []
        self.dst_port = dst_port
        self.max_workers = max_workers
        self.ip_version = ip_version
        self.routing_type = routing_type_fabric(self, ip_version)

    @property
    def results(self):
        result = defaultdict(list)
        for ip, ttl, delay in self._results:
            result[ttl].append((ip, delay))

        ans = []
        time_to_end = False
        for ttl in range(1, self.max_hops + 1):
            ttl_res = []
            for time in range(self.times):
                if time >= len(result[ttl]):
                    ttl_res.append('*')
                else:
                    ip, delay = result[ttl][time]
                    if ip == self.dst_ip:
                        time_to_end = True

                    ttl_res.append(f'{f"{ip} ({delay * 1000:.2f} ms)":<25}')
            ans.append(f'{ttl:>2}  {" ".join(ttl_res)}')
            if time_to_end:
                break

        return ans

    def start(self):
        self._results.clear()
        sniff_thread = threading.Thread(
            target=self.sniff
        )

        sniff_thread.start()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for j in range(self.times):
                for i in range(1, self.max_hops + 1):
                    executor.submit(
                        self.routing_type.send_packet,
                        ttl=i
                    )

        sniff_thread.join()

    def sniff(self):
        sniff(
            prn=lambda p: self._results.append(
                self.routing_type.handle_packet(p)
            ),
            lfilter=self.routing_type.filter,
            timeout=self.timeout + 1
        )
