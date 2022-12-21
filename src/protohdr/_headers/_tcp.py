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


__all__ = (
    "TCPFlag",
    "TCPHeader",
    "TCPOption",
)


class TCPFlag(IntEnum):
    """ TCP control bit flags. """
    # ECN-TCP
    NS      = 0b000100000000
    CWR     = 0b000010000000
    ECE     = 0b000001000000
    # Generic TCP
    URG     = 0b000000100000
    ACK     = 0b000000010000
    PSH     = 0b000000001000
    RST     = 0b000000000100
    SYN     = 0b000000000010
    FIN     = 0b000000000001


@dataclass(kw_only=True)
class TCPHeader(Header):
    """ Transmission Control Protocol header.

        https://www.rfc-editor.org/rfc/rfc793
    """
    src_port: int
    """ Source Port: 16 bits """

    dst_port: int
    """ Destination Port: 16 bits """

    seq_num: int
    """ Sequence Number: 32 bits """

    ack_num: int
    """ Acknowledgment Number: 32 bits """

    data_offset: int
    """ Data Offset: 4 bits """

    flags: int
    """ Flags/Control Bits: 9 bits

        Bit 1: ECN Nonce.
        Bit 2: Congestion Window Reduced.
        Bit 3: ECN Echo.
        Bit 4: Urgent Pointer field significant.
        Bit 5: Acknowledgment field significant.
        Bit 6: Push Function.
        Bit 7: Reset the connection.
        Bit 8: Synchronize sequence numbers.
        Bit 9: No more data from sender.
   """

    window: int
    """ Window size: 16 bits """

    checksum: int
    """ Checksum: 16 bits """

    urg_ptr: int
    """ Urgent Pointer: 16 bits """

    options: bytes = b""
    """ TCP options: 0+ bits """

    data: bytes = b""
    """ TCP data: <65483 bits """

    def __bytes__(self) -> bytes:
        header = b"" # Big endianess?
        header += i2bb(16, self.src_port)
        header += i2bb(16, self.dst_port)
        header += i2bb(32, self.seq_num)
        header += i2bb(32, self.ack_num)
        header += i2bb(16, ((self.data_offset // 4) << 12) | (0b000 << 3) | (self.flags))
        header += i2bb(16, self.window)
        header += i2bb(16, self.checksum)
        header += i2bb(16, self.urg_ptr)
        header += self.options
        # Padding
        while len(header) < 32:
            header += b"\x00"
        header += self.data
        return header

    def __len__(self) -> int:
        return len(bytes(self))


class TCPOption:
    """ TCP option generators. """
    __slots__ = ()

    @staticmethod
    def eol() -> bytes:
        """ End of Option List. """
        kind = b'\x00'
        return kind

    @staticmethod
    def nop() -> bytes:
        """ No-operation. """
        kind = b'\x01'
        return kind

    @staticmethod
    def mss(value: int) -> bytes:
        """ Maximum Segment Size.

            Args:
                MSS Value: 16 bits
       """
        kind = b'\x02'
        length = i2bb(8, 4)
        return kind + length + i2bb(16, value)

    @staticmethod
    def ws(shift_count: int) -> bytes:
        """ Window scale.

            Args:
                Shift Count: 8 bits
       """
        kind = b'\x03'
        length = i2bb(8, 3)
        return kind + length + i2bb(8, shift_count)

    @staticmethod
    def sack_permitted() -> bytes:
        """ Selective Acknowledgements Permitted. """
        kind = b'\x04'
        length = i2bb(8, 10)
        return kind + length

    @staticmethod
    def sack(ledge: int, redge: int) -> bytes:
        """ Selective Acknowledgements.

            Args:
                Left Edge: 32 bits
                Right Edge: 32 bits
        """
        kind = b'\x05'
        length = i2bb(8, 10)
        return kind + length + i2bb(32, ledge) + i2bb(32, redge)

    @staticmethod
    def ts(tsval: int, tsecr: int) -> bytes:
        """ Timestamps.

            Args:
                TS Value: 32 bits
                TS Echo Reply 32 bits
       """
        kind = b'\x08'
        length = i2bb(8, 10)
        return kind + length + i2bb(32, tsval) + i2bb(32, tsecr)

    @staticmethod
    def fastopen(cookie: bytes):
        """ FastOpen.

            Args:
                Cookie: 128 bits
        """
        assert len(cookie) == 16, "Invalid FastOpen cookie"
        kind = b'\x22'
        length = i2bb(8, 18)
        return kind + length + cookie