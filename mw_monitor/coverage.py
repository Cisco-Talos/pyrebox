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


def block_executed(cpu_index, cpu, tb, proc=None):
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    # Get the overlapping VAD, if we don't have it, update VADs
    if TARGET_LONG_SIZE == 4:
        page = cpu.EIP & 0xFFFFF000
    elif TARGET_LONG_SIZE == 8:
        page = cpu.RIP & 0xFFFFFFFFFFFFF000

    vad = proc.get_overlapping_vad(page)

    if vad is None:
        proc.update_vads()
    return
