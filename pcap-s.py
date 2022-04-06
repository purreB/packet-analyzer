import argparse
import os
import sys

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader

from timeFunction import printable_timestamp


def process_pcap(file_name):
    print("Opening {}...".format(file_name))

    client = '192.168.1.137:57080'
    server = '152.19.134.43:80'

    (client_ip, client_port) = client.split(':')
    (server_ip, server_port) = server.split(':')

    count = 0
    interesting_pkt_count = 0
    for (
        pkt_data,
        pkt_metadata,
    ) in RawPcapReader(file_name):
        count += 1
        ether_pkt = Ether(pkt_data)
        if "type" not in ether_pkt.fields:
            continue
        if ether_pkt.type != 0x0800:
            # EtherType 0x0800 is IPV4 packets, which to us is not interesting right now.
            # Other EtherTypes that you might want to filter out can be found in: https://en.wikipedia.org/wiki/EtherType
            # I might add a automatic filter setting in the future
            continue

        ip_pkt = ether_pkt[IP]

        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
            # If the ip source of the packet is not our server ip or our client ip it is not interesting for us.
            continue

        if (ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
            # If the destination ip of the packet is not our server or our clients ip adress it is not interesting for us.
            continue

        tcp_pkt = ip_pkt[TCP]

        if (tcp_pkt.sport != int(server_port)) and (tcp_pkt.sport != int(client_port)):
            # If the source port is not our server port or client port it is not interesting for us.
            continue

        if (tcp_pkt.dport != int(server_port)) and (tcp_pkt.dport != int(client_port)):
            # If the destination port is not our server port or client port it is not interesting for us.
            continue

        interesting_pkt_count += 1
        if interesting_pkt_count == 1:
            first_pkt_timestamp = (pkt_metadata.tshigh <<
                                   32) | pkt_metadata.tslow
            first_pkt_timestamp_resolution = pkt_metadata.tsresol
            first_pkt_ordinal = count

        last_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count

    print(
        "{} contains {} packets ({} interesting)".format(
            file_name, count, interesting_pkt_count
        )
    )

    print(
        'First packet in connection: Packet #{} {}'
        .format(first_pkt_ordinal, printable_timestamp(first_pkt_timestamp, first_pkt_timestamp_resolution))
    )

    print('Last packet in connection: Packet #{} {}'.format(
        last_pkt_ordinal, printable_timestamp(
            last_pkt_timestamp, last_pkt_timestamp_resolution)
    ))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP reader")

    parser.add_argument(
        "--pcap", metavar="<pcap file name>", help="pcap file to parse", required=True
    )
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)
