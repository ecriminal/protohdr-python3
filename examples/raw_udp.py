from protohdr import *
from socket import *

from os import getuid
from sys import stderr
from random import randint


if __name__ == "__main__":
    if getuid() != 0:
        print("ERROR: Root is required to create raw sockets!", file=stderr)
        exit(1)

    # Create IP header.
    ip = IPHeader(
        version     = 0x4,
        header_len  = 0x0,
        tos         = 0x00,
        total_len   = 0x0000,
        identifier  = randint(0x1000, 0xffff),
        flags       = IPFlag.DONT_FRAG,
        frag_offset = 0,
        ttl         = 0xff,
        protocol    = IPPROTO_UDP,
        checksum    = 0x0000,
        src_addr    = "1.2.3.4",
        dst_addr    = "127.0.0.1"
    )
    ip.header_len = len(ip)

    # Create UDP header.
    udp = UDPHeader(
        src_port    = 4000,
        dst_port    = 6969,
        header_len  = 0x0000,
        checksum    = 0x0000,
        data        = b'\n0MG 1m 4 UDP p4ck3t !!!'
    )
    udp.header_len = len(udp)
    udp.checksum = inet_checksum(bytes(udp))

    # Finalize IP packet.
    ip.total_len = ip.header_len + udp.header_len
    ip.checksum = inet_checksum(bytes(ip))

    pkt = bytes(ip) + bytes(udp)

    # Create raw UDP socket.
    s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)
    # Tell kernel not to include IP header.
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    # Send packet to destination address.
    s.sendto(pkt, ("127.0.0.1", 6969))

    print("Packet sent")
