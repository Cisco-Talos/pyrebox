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
import pickle
import sys

def read_stream(f_in):
    data = pickle.load(f_in)
    if type(data) is list:
        for proc in data:
            print proc.__str__()
    else:
        for proc in data.procs:
            print proc.__str__()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: %s <file>" % (sys.argv[0])
    with open(sys.argv[1], "rb") as f:
        read_stream(f)
