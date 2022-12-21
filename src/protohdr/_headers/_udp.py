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

from .._header import *
from .._inet import *


__all__ = (
    "UDPHeader",
)


@dataclass(kw_only=True)
class UDPHeader(Header):
    """ User Datagram Protocol header.

        https://www.rfc-editor.org/rfc/rfc768
    """
    src_port: int
    """ Source port: 16 bits """

    dst_port: int
    """ Destination port: 16 bits """

    header_len: int
    """ Length of header+data: 16 bits """

    checksum: int
    """ Checksum: 16 bits """

    data: bytes
    """ UDP data: <65507 bits """

    def __bytes__(self) -> bytes:
        header = b"" # Big endianess?
        header += i2bb(16, self.src_port)
        header += i2bb(16, self.dst_port)
        header += i2bb(16, self.header_len)
        header += i2bb(16, self.checksum)
        header += self.data
        return header

    def __len__(self) -> int:
        return len(bytes(self))
