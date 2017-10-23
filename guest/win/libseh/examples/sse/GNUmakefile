
include ../config.mk

.PHONY: all

all: detect_intel_sse.exe

detect_intel_sse.exe: detect_intel_sse.o
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean: 
	$(RM) detect_intel_sse.exe detect_intel_sse.o

