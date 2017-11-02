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

# CONFIGURATION PAMATERS
# ......................

# BUFFER_SIZE: Guest agent buffer size used to copy data back and forth
# AGENT_NAME: Base of the file name of the generated guest agent binaries
#             (and their corresponding configuration files.

BUFFER_SIZE := 4096

AGENT_NAME := linux_agent

#--------------------------------------------------------------------------------

CC := gcc
CC32 := gcc
CC64 := gcc

CFLAGS_32 := -Iinclude/ -I../include -g -O0 -m32
CFLAGS_64 := -Iinclude/ -I../include -g -O0

DEFINES := -DMAX_BUFFER_SIZE=$(BUFFER_SIZE)

all: $(AGENT_NAME)_32 $(AGENT_NAME)_64

32bit_test: test.c
	$(CC32) $(CFLAGS_32) $(DEFINES) -c -o test_32.o $<
	$(CC32) -m32 test_32.o -o test_32

64bit_test: test.c
	$(CC64) $(CFLAGS_64) $(DEFINES) -c -o test_64.o $<
	$(CC64)  test_64.o -o test_64

%_32: guest_agent_32.o
	$(CC32) -m32  $^ -o $@
	AGENT_NAME=$@ BUFFER_SIZE=$(BUFFER_SIZE) bash ./configure_offsets.sh
%_64: guest_agent_64.o 
	$(CC64)  $^ -o $@
	AGENT_NAME=$@ BUFFER_SIZE=$(BUFFER_SIZE) bash ./configure_offsets.sh

%_32.o: %.c
	$(CC32) $(CFLAGS_32) $(DEFINES) -c -o $@ $<
%_64.o: %.c
	$(CC64) $(CFLAGS_64) $(DEFINES) -DPYREBOX_GUEST_64 -c -o $@ $<

.PHONY: clean dist-clean 
clean:
	rm -f $(AGENT_NAME)_32
	rm -f $(AGENT_NAME)_64
	rm -f *.o
	rm -f test_32
	rm -f test_64
