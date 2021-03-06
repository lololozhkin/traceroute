#!/usr/bin/env python3

from ip_versions import ipv4, ipv6
from utills.parser import get_parser

from utills import tracerouter
from scapy.layers.inet import IP
from scapy.sendrecv import send

from routing_types.with_ports import tcp_routing, udp_routing
from routing_types.icmp_routing import icmpv4_routing, icmpv6_routing

import socket


def is_able_to_send_ip():
    try:
        p = IP(dst='8.8.8.8')
        send(p, verbose=0)
    except PermissionError:
        return False

    return True


def ip_version(ip_addr):
    if ':' in ip_addr:
        return 'ipv6'
    else:
        return 'ipv4'


def correct_ipv4(ip):
    try:
        socket.inet_aton(ip)
    except socket.error:
        return False

    return True


def correct_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
    except socket.error:
        return False

    return True


def main():
    check_dict = {
        'ipv4': correct_ipv4,
        'ipv6': correct_ipv6
    }

    ip_version_dict = {
        'ipv4': ipv4.Ipv4(),
        'ipv6': ipv6.Ipv6()
    }

    if not is_able_to_send_ip():
        print('Script will not work without root privileges. '
              'Please, use sudo or run script with admin privileges.')
        return

    parser = get_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        print('Timeout must be positive')
        return

    ip_v_str = ip_version(args.address)
    if not check_dict[ip_v_str](args.address):
        print('IP address is not correct')
        return

    ip_v = ip_version_dict[ip_v_str]
    icmp = icmpv6_routing.ICMPv6Routing if ip_v_str == 'ipv6' \
        else icmpv4_routing.ICMPv4Routing

    proto_dict = {
        'icmp': icmp,
        'tcp': tcp_routing.TCPRouting,
        'udp': udp_routing.UDPRouting
    }

    traceroute = tracerouter.Tracerouter(
        args.address,
        proto_dict[args.proto],
        ip_v,
        args.port,
        timeout=args.timeout,
        max_hops=args.max_count,
        verb=args.verbose
    )

    traceroute.start()

    print(*traceroute.results, sep='\n')


if __name__ == '__main__':
    main()
