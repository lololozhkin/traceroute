import argparse


def get_parser():
    parser = argparse.ArgumentParser(
            prog='traceroute',
        )
    parser.add_argument(
        '-t',
        '--timeout',
        type=float,
        default=2.0,
        help='Set the timeout in seconds, by default timeout is 2 seconds'
    )
    parser.add_argument(
        '-p',
        '--port',
        type=int,
        help='set the port if you use tcp/udp packet sending instead of icmp. '
             'If you use icmp protocol, this flag will be ommited.'
             ' By default it is equal 80',
        default=80
    )
    parser.add_argument(
        '-n',
        '--max-count',
        type=int,
        help='Set the max request count',
        default=3
    )
    parser.add_argument(
        'address',
        type=str,
        help='Address of the endpoint'
    )
    parser.add_argument(
        'proto',
        type=str,
        choices=['tcp', 'udp', 'icmp'],
        nargs='?',
        default='icmp',
        help='By default is equal to icmp. '
             'You may specify which packets to send instead of default icmp '
             'echo requests (tcp syn for example)'
    )

    return parser
