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

from .._header import *
from .._inet import *

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._ip import IPHeader


__all__ = (
    "ICMPHeader",
    "ICMPMessage",
    "ICMPCodeDU",
    "ICMPCodeTE",
    "ICMPCodeRD",
    "ICMPPayload",
)


class ICMPMessage(IntEnum):
    """ ICMP message types. """
    ECHO_REPLY              = 0
    DESTINATION_UNREACHABLE = 3
    SOURCE_QUENCH           = 4
    REDIRECT                = 5
    ECHO                    = 8
    TIME_EXCEEDED           = 11
    PARAMETER_PROBLEM       = 12
    TIMESTAMP               = 13
    TIMESTAMP_REPLY         = 14
    INFORMATION_REQUEST     = 15
    INFORMATION_REPLY       = 16


class ICMPCodeDU(IntEnum):
    """ Codes for `ICMPMessage.DESTINATION_UNREACHABLE` message. """
    NET_UNREACHABLE = 0
    """ Net unreachable. """
    HOST_UNREACHABLE = 1
    """ Host unreachable. """
    PROTOCOL_UNREACHABLE = 2
    """ Port unreachable. """
    NEED_FRAG_DF_SET = 4
    """ Fragmentation needed and DF set. """
    SRC_ROUTE_FAILED = 5
    """ Source route failed. """


class ICMPCodeTE(IntEnum):
    """ Codes for `ICMPMessage.TIME_EXCEEDED` message. """
    TTL_EXCEEDED = 0
    """ Time to live exceeded in transit. """
    FRAG_REASM_TIME_EXCEEDED = 1
    """ Fragment reassembly time exceeded. """


class ICMPCodeRD(IntEnum):
    """ Codes for `ICMPMessage.REDIRECT` message. """
    NET = 0
    """ Redirect datagrams for the Network. """
    HOST = 1
    """ Redirect datagrams for the Host. """
    TOS_NET = 2
    """ Redirect datagrams for the Type of Service and Network. """
    TOS_HOST = 3
    """ Redirect datagrams for the Type of Service and Host. """


@dataclass(kw_only=True)
class ICMPHeader(Header):
    """ Internet Control Message Protocol header.

        https://www.rfc-editor.org/rfc/rfc792
    """
    type: int
    """ Message type: 8 bits """

    code: int
    """ Message code: 8 bits """

    checksum: int
    """ Checksum: 16 bits """

    identifier: int
    """ Identifier: 16 bits """

    seq_num: int
    """ Sequence number: 16 bits """

    data: bytes = b""
    """ ICMP message payload: <65507 bits """

    def __bytes__(self):
        header = b"" # Big endianess?
        header += i2bb(8, self.type)
        header += i2bb(8, self.code)
        header += i2bb(16, self.checksum)
        header += i2bb(16, self.identifier)
        header += i2bb(16, self.seq_num)
        header += self.data
        return header

    def __len__(self) -> int:
        return len(bytes(self))


class ICMPPayload:
    """ ICMP payload generators. """
    __slots__ = ()

    @staticmethod
    def timestamp(orig_ts: int, recv_ts: int, trans_ts: int) -> bytes:
        return i2bb(32, orig_ts) + i2bb(32, recv_ts) + i2bb(32, trans_ts)

    @staticmethod
    def echo(data: bytes):
        return data

    @staticmethod
    def info_request() -> bytes:
        return b""

    @staticmethod
    def time_exceeded(ip_hdr: IPHeader, orig_dg: Header) -> bytes:
        """ Internet Header + 64 bits of Original Data Datagram """
        return bytes(ip_hdr) + bytes(orig_dg)[:8]

    # parameter_problem = time_exceeded
    # NOTE: ICMP Parameter Problem message is not officially
    # supported yet, but can be achieved by shifting the
    # pointer value by 8 bits to the left in the `identifier`
    # header field, and leaving the `seq_num` header field as
    # zero.
