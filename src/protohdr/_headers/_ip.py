#  This file is part of protohdr-python3
#  Copyright (C) 2022 ecriminal
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from socket import inet_aton

from .._inet import *
from .._header import *


__all__ = (
    "IPRule",
    "IPFlag",
    "IPVersion",
    "IPHeader",
)


class IPRule(IntEnum):
    """ Internet Protocol limitations/rules. """
    MIN_HEADER_LEN = 0x5 # 5x4 bytes
    MAX_HEADER_LEN = 0x6 # 6x4 bytes


class IPFlag(IntEnum):
    """ Internet Protocol bit flags. """
    _RESERVED = 0b100
    DONT_FRAG = 0b010
    MORE_FRAG = 0b001


class IPVersion(IntEnum):
    """ Internet Protocol Version numbers. """
    IPV4 = 4
    IPV6 = 6


@dataclass(kw_only=True)
class IPHeader(Header):
    """ Internet Protocol header.

        https://www.rfc-editor.org/rfc/rfc791
    """
    version: int
    """ IP version: 4 bits """

    header_len: int
    """ Internet header length: 4 bits  """

    tos: int
    """ Type of service: 8 bits """

    total_len: int
    """ Total packet length: 16 bits """

    identifier: int
    """ Identification: 16 bits """

    flags: int
    """ Flags: 3 bits

        Bit 1: Reserved.
        Bit 2: Don't fragment.
        Bit 3: More fragments.
   """

    frag_offset: int
    """ Fragment offset: 13 bits """

    ttl: int
    """ Time to live: 8 bits """

    protocol: int
    """ Protocol: 8 bits """

    checksum: int
    """ Checksum: 16 bits """

    src_addr: str
    """ Source address: 32 (IPv4) / 128 (IPv6) bits """

    dst_addr: str
    """ Destination address: 32 (IPv4) / 128 (IPv6) bits """

    def __bytes__(self) -> bytes:
        header = b""
        header += i2bb(8, (self.version << 4) | (self.header_len // 4))
        header += i2bl(8, self.tos)
        header += i2bl(16, self.total_len)
        header += i2bl(16, self.identifier)
        header += i2bl(16, (self.flags << 13) | self.frag_offset) # LE?
        header += i2bl(8, self.ttl)
        header += i2bl(8, self.protocol)
        header += i2bl(16, self.checksum)
        header += inet_aton(self.src_addr)
        header += inet_aton(self.dst_addr)
        return header

    def __len__(self) -> bytes:
        addr_len = 128 if self.version == 6 else 32 # IPv4
        return ((96 + (2 * addr_len) ) // 8)
