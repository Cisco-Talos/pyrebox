#!/bin/bash

# -------------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Jonas Zaddach
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
# -------------------------------------------------------------------------------

#This script extracts the relative position of the global buffer named agent_buffer
#that is used to copy data back and forth between the host and the guest, as well
#as its size (that is configured in the Makefile).

#This approach allows the pyrebox guest_agent plugin to check the boundaries of the buffer
#before each write operation in order to prevent overflows and arbitrary memory writes.

echo "[BUFFER]" > ../../${AGENT_NAME}.conf
echo "BufferOffset: " $(($((16#`nm ${AGENT_NAME} | grep "agent_buffer" | awk '{ print $1 }'`)) - $((16#`objdump -x ${AGENT_NAME} | grep "^ImageBase" | awk '{ print $2 }'`)))) >> ../../${AGENT_NAME}.conf
echo "BufferSize: " ${BUFFER_SIZE} >> ../../${AGENT_NAME}.conf
