# -------------------------------------------------------------------------
#
#   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Xabier Ugarte-Pedrero
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#
# -------------------------------------------------------------------------

#!/usr/bin/python
import sys
import struct


def read_coverage(f_in):
    data = f_in.read()
    blocks = {}
    i = 0
    total_len = len(data)
    while i < total_len:
        addr = struct.unpack("<I", data[i:i + 4])[0]
        size = struct.unpack("<I", data[i + 4:i + 8])[0]
        i += 8
        if addr in blocks:
            if size >= blocks[addr]:
                blocks[addr] = size
        else:
            blocks[addr] = size
    return blocks


def main(f_in):
    blocks = read_coverage(f_in)
    for b in blocks:
        print "Addr: %08x - Size: %08x" % (b, blocks[b])


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f_in:
        main(f_in)
