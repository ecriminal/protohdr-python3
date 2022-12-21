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

from numpy import (
    sum     as np_sum,
    arange  as np_arange,
)


__all__ = (
    "i2bl",
    "i2bb",
    "inet_checksum",
)


i2bl = lambda s, i: int(i).to_bytes(s // 8, "little")
""" Convert integer to bytes of given bit size with Little Endianess. """

i2bb = lambda s, i: int(i).to_bytes(s // 8, "big")
""" Convert integer to bytes of given bit size with Big Endianess. """


def inet_checksum(data: bytes) -> int:
    """ Calculate internet checksum (16-bit) """
    s = np_sum([(data[i] << 8) + data[i + 1] if i < len(data) - 1 else data[i] \
            for i in np_arange(0, len(data), 2)])
    return ~((s >> 16) + (s & 0xFFFF)) & 0xFFFF
