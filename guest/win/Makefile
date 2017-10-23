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

AGENT_NAME := win_agent

#--------------------------------------------------------------------------------

CC := i686-w64-mingw32-gcc
CC32 := i686-w64-mingw32-gcc
CC64 := x86_64-w64-mingw32-gcc

CFLAGS_32 := -Iinclude/ -Ilibseh/ -g -O0
CFLAGS_64 := -Iinclude/ -g -O0

DEFINES := -DMAX_BUFFER_SIZE=$(BUFFER_SIZE)

all: $(AGENT_NAME)_32.exe $(AGENT_NAME)_64.exe

test_32: test.c
	$(CC32) $(DEFINES) -c -o test_32.o $<
	$(CC32)  test_32.o -o test_32.exe

test_64: test.c
	$(CC32) $(DEFINES) -c -o test_64.o $<
	$(CC32)  test_64.o -o test_64.exe


%_32.exe: %_32
	cp $< $@
	AGENT_NAME=$@ BUFFER_SIZE=$(BUFFER_SIZE) bash ./configure_offsets.sh

%_64.exe: %_64
	cp $< $@
	AGENT_NAME=$@ BUFFER_SIZE=$(BUFFER_SIZE) bash ./configure_offsets.sh

%_32: guest_agent_32.o libseh/build/libseh.a
	$(CC32)  $^ -o $@
%_64: guest_agent_64.o 
	$(CC64)  $^ -o $@

%_32.o: %.c
	$(CC32) $(CFLAGS_32) $(DEFINES) -c -o $@ $<
%_64.o: %.c
	$(CC64) $(CFLAGS_64) $(DEFINES) -DPYREBOX_GUEST_64 -c -o $@ $<

libseh/build/libseh.a: 
	$(MAKE) -C libseh -f GNUmakefile

.PHONY: clean dist-clean 
clean:
	rm -f $(AGENT_NAME)_32 
	rm -f $(AGENT_NAME)_64 
	rm -f *.o
	make -C libseh -f GNUmakefile clean

dist-clean: clean
	rm -f $(AGENT_NAME)_32.exe
	rm -f $(AGENT_NAME)_64.exe
	rm -f test_32.exe
	rm -f test_64.exe
