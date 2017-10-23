
include ../config.mk

.PHONY: all

all: detect_vm_software.exe

detect_vm_software.exe: detect_vm_software.o
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean: 
	$(RM) detect_vm_software.exe detect_vm_software.o

