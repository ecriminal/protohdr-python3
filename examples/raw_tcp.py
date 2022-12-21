from protohdr import *
from socket import *

from os import getuid
from sys import stderr
from random import randint


if __name__ == "__main__":
    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 420

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
        protocol    = IPPROTO_TCP,
        checksum    = 0x0000,
        src_addr    = "1.1.1.1",
        dst_addr    = TARGET_IP
    )
    ip.header_len = len(ip)

    # Create TCP header.
    tcp = TCPHeader(
        src_port    = randint(0x1000, 0xffff),
        dst_port    = TARGET_PORT,
        seq_num     = randint(0x10000000, 0xffffffff),
        ack_num     = 0x00000000,
        data_offset = 32,
        flags       = TCPFlag.SYN,
        window      = randint(0x1000, 0xffff),
        checksum    = 0x0000,
        urg_ptr     = 0x0000,
        options     = TCPOption.nop() + TCPOption.nop() + TCPOption.ts(0xFFFFFFFF, 0xFFFFFFFF),
    )
    tcp.checksum = inet_checksum(bytes(tcp))

    # Finalize IP header.
    ip.total_len = ip.header_len + len(tcp)
    ip.checksum = inet_checksum(bytes(ip))

    pkt = bytes(ip) + bytes(tcp)

    # Create raw TCP socket.
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    # Tell kernel not to include IP header.
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    # Send packet to destination address.
    s.sendto(pkt, (TARGET_IP, TARGET_PORT))

    print("Packet sent")
