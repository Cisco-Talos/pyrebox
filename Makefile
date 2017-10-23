# -------------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
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
# -------------------------------------------------------------------------------

include qemu/config-host.mak
DEFINES=-I. -I..

CC=gcc
CPP=g++
PYTHON_CFLAGS = -I./pyrebox/ -I/usr/include/python2.7 -I/usr/include/python2.7 -fno-strict-aliasing -DNDEBUG -fwrapv  -fstack-protector --param=ssp-buffer-size=4
PYTHON_LIBS = -L/usr/lib/python2.7/config -lpthread -ldl -lutil -lm -lpython2.7 -Wl,-O1 -Wl,-Bsymbolic-functions -Xlinker -export-dynamic
CFLAGS=-Wall -O2 -g -fPIC -MMD -std=c++11 -std=gnu++11 
CFLAGS+=$(PYTHON_CFLAGS)
LDFLAGS=-g -shared 
LDFLAGS+=$(PYTHON_LIBS)

#Triggers for i386-softmmu

%-i386-softmmu.o: %.c 
	@$(CC) $(CFLAGS) $(DEFINES) -I./qemu/i386-softmmu -c -o $@ $< ; \
	echo $(CPP) $@ ;

%-i386-softmmu.o: %.cpp
	@$(CPP) $(CFLAGS) $(DEFINES) -I./qemu/i386-softmmu -c -o $@ $< ; \
	echo $(CPP) $@ ;

%-i386-softmmu.so: %-i386-softmmu.o pyrebox/trigger_helpers-i386-softmmu.o pyrebox/utils-i386-softmmu.o
	@$(CPP) -Wno-builtin-macro-redefined  $(CFLAGS) $(DEFINES) -I./qemu/i386-softmmu -shared -o $@ $^ ; \
	echo $(CPP) $@

#Triggers for x86-64-softmmu

%-x86_64-softmmu.o: %.c 
	@$(CC) $(CFLAGS) $(DEFINES) -I./qemu/x86_64-softmmu -c -o $@ $< ; \
	echo $(CPP) $@ ;

%-x86_64-softmmu.o: %.cpp
	@$(CPP) $(CFLAGS) $(DEFINES) -I./qemu/x86_64-softmmu -c -o $@ $< ; \
	echo $(CPP) $@ ;

%-x86_64-softmmu.so: %-x86_64-softmmu.o pyrebox/trigger_helpers-x86_64-softmmu.o pyrebox/utils-x86_64-softmmu.o
	@$(CPP) -Wno-builtin-macro-redefined  $(CFLAGS) $(DEFINES) -I./qemu/x86_64-softmmu -shared -o $@ $^ ; \
	echo $(CPP) $@

clean-triggers:
	rm -f triggers/*.so triggers/*.o triggers/*.d

documentation: 
	$(MAKE) -C ./docs/ html 

#We place these 2 rules so that we can compile more comfortably from this directory
all: 
	@$(MAKE) -C ./qemu $@

clean: clean-triggers	
	@$(MAKE) -C ./qemu $@

test_scripts:
	flake8 ./scripts --count --select=E901,E999,F821,F822,F823 --show-source --statistics
	flake8 ./scripts --count --exit-zero --max-complexity=20 --max-line-length=127 --statistics

test_plugins:
	flake8 ./plugins --count --select=E901,E999,F821,F822,F823 --show-source --statistics
	flake8 ./plugins --count --exit-zero --max-complexity=20 --max-line-length=127 --statistics

test_pyrebox_test:
	flake8 ./pyrebox_test --count --select=E901,E999,F821,F822,F823 --show-source --statistics
	flake8 ./pyrebox_test --count --exit-zero --max-complexity=20 --max-line-length=127 --statistics

test_pyrebox:
	flake8 ./pyrebox/*.py --count --select=E901,E999,F821,F822,F823 --show-source --statistics
	flake8 ./pyrebox/*.py --count --exit-zero --max-complexity=20 --max-line-length=127 --statistics

test: 
	@$(MAKE) test_scripts test_pyrebox_test test_pyrebox test_plugins
