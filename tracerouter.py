import threading
import time
from collections import defaultdict

import ipwhois
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


def format_delay(delay):
    return f'{delay * 1000:.2f} ms'


def get_asn(ip):
    try:
        asn = ipwhois.IPWhois(ip).lookup_rdap()['asn']
    except ipwhois.IPDefinedError:
        asn = '-'

    return asn


def get_all_asn(ips, max_workers=16):
    ip_asn_futures = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip in ips:
            asn_future = executor.submit(get_asn, ip)
            ip_asn_futures.append((ip, asn_future))

    ip_to_asn = {}
    for ip, future in ip_asn_futures:
        ip_to_asn[ip] = future.result()

    return ip_to_asn


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
            max_workers: int = 16,
            verb: bool = False
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
        self.verb = verb

    @property
    def results(self):
        result = defaultdict(list)
        all_ips = set()
        for ip, ttl, delay in self._results:
            result[ttl].append((ip, delay))
            all_ips.add(ip)
        ans = []
        time_to_end = False
        ip_to_asn = get_all_asn(all_ips) if self.verb else None

        for ttl in range(1, self.max_hops + 1):
            ips_at_ttl = set()
            ip_to_delays = defaultdict(list)
            for time in range(self.times):
                if time >= len(result[ttl]):
                    break

                ip, delay = result[ttl][time]
                ip_to_delays[ip].append(delay)
                ips_at_ttl.add(ip)

                if ip == self.dst_ip:
                    time_to_end = True

            res = []
            ips_at_ttl = list(ips_at_ttl)
            counter = self.times
            i = 0
            while counter:
                if i >= len(ips_at_ttl):
                    res.append('*')
                    i += 1
                    counter -= 1
                    continue

                ip = ips_at_ttl[i]
                ip_str = f'{ip}'
                asn_str = f"({ip_to_asn[ip]})" if self.verb else ""

                delays = "  ".join(
                    format_delay(delay) for delay in ip_to_delays[ip]
                )

                res.append(f'{ip_str} {asn_str}  {delays}')

                counter -= len(ip_to_delays[ip])
                i += 1

            ans.append(f'{ttl:>2}  {" ".join(s for s in res)}')

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
