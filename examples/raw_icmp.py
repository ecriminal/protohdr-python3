from protohdr import *
from socket import *

from os import getuid
from sys import stderr
from random import randint


if __name__ == "__main__":
    TARGET_IP = "127.0.0.1"

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
        protocol    = IPPROTO_ICMP,
        checksum    = 0x0000,
        src_addr    = "127.0.0.1",
        dst_addr    = TARGET_IP
    )
    ip.header_len = len(ip)

    # Create ICMP header.
    icmp = ICMPHeader(
        type        = ICMPMessage.ECHO,
        code        = 0x00,
        checksum    = 0x0000,
        identifier  = randint(0x1000, 0xffff),
        seq_num     = randint(0x1000, 0xffff),
        data        = ICMPPayload.echo(b"A" * 64)
    )
    icmp.checksum = inet_checksum(bytes(icmp))

    # Finalize IP packet.
    ip.total_len = ip.header_len + len(icmp)
    ip.checksum = inet_checksum(bytes(ip))

    pkt = bytes(ip) + bytes(icmp)

    # Create raw ICMP socket.
    s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    # Tell kernel not to create IP header.
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    # Send packet to destination address.
    s.sendto(pkt, ("127.0.0.1", 0))

    print("Packet sent")
