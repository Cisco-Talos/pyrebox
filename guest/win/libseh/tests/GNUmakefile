
CC := gcc
CXX := g++
CFLAGS := -I.. -Wall -O2 -g -fno-omit-frame-pointer $(CFLAGS_ADD) 
CXXFLAGS := $(CFLAGS) $(CXXFLAGS_ADD)
RM := del

LIBDEPS := ../build/libseh.a

LDFLAGS = -L../build -lseh

EXE_EXT = .exe
OBJ_EXT = .o

all: tests

include rules.mk


.PHONY: tests
tests: $(LIBSEH_TESTS)

%.exe: %.o
	$(CXX) -o $@ $< $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) $(LIBSEH_TESTS) $(LIBSEH_OBJS)
