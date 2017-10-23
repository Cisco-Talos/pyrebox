
BUILD_DIR := build
TOOLS_PREFIX := i686-w64-mingw32-
CC := $(TOOLS_PREFIX)gcc
CXX := $(TOOLS_PREFIX)g++
AS := $(TOOLS_PREFIX)as
AR := $(TOOLS_PREFIX)ar
RM := rm

OSNAME := windows
ARCHNAME := x86

CFLAGS += -O2 -Wall -g -std=c99 -fno-strict-aliasing $(CFLAGS_ADD)
CXXFLAGS += -O2 -Wall -g $(CXXFLAGS_ADD) $(CFLAGS_ADD)
ASFLAGS += -xassembler-with-cpp

OBJS := $(BUILD_DIR)/common.o \
        $(BUILD_DIR)/sehpp.o \
        $(BUILD_DIR)/seh-support.o \
        $(BUILD_DIR)/seh.o

TARGETS = $(BUILD_DIR)/libseh.a

all: $(TARGETS)

$(BUILD_DIR)/libseh.a: $(OBJS)
	$(AR) rs $@ $^

$(BUILD_DIR)/%.o: os/$(OSNAME)/arch/$(ARCHNAME)/%.s
	$(CC) $(ASFLAGS) -o $@ -c $^

$(BUILD_DIR)/%.o: os/$(OSNAME)/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

$(BUILD_DIR)/%.o: common/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

$(BUILD_DIR)/%.o: common/%.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $^

.PHONY: clean
clean:
	$(RM) -f $(OBJS) $(TARGETS)

