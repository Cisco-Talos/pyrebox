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

from idc import SetColor
from idc import CIC_ITEM
from idaapi import get_inf_structure

try:
    #   For IDA 6.8 and older using PySide
    # from PySide import QtGui, QtGui as QtWidgets, QtCore
    # from PySide.QtCore import Qt
    from PySide import QtGui as QtWidgets
except ImportError:
    try:
        # For IDA 6.9 and newer using PyQt5
        # from PyQt5 import QtGui, QtWidgets, QtCore
        # from PyQt5.QtCore import Qt
        from PyQt5 import QtWidgets
    except ImportError:
        print 'Cannot import required Qt Modules'


info = get_inf_structure()

if info.is_64bit():
    from mw_monitor.coverage_reader_64 import read_coverage
elif info.is_32bit():
    from mw_monitor.coverage_reader_32 import read_coverage

fname = QtWidgets.QFileDialog.getOpenFileName(None, 'Open file',
                                              'C:\\')
# Load the file with the coverage
f_in = open(fname[0], "rb")
cov = read_coverage(f_in)
print "Data read, painting blocks..."
for addr in cov:
    for i in range(addr, addr + cov[addr]):
        SetColor(i, CIC_ITEM, 0xc6e2ff)
f_in.close()
