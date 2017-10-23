
BUILD_DIR = build
CC = cl.exe
CXX = cl.exe
LIB = lib.exe
RM = del

OSNAME = windows
ARCHNAME = x86

CFLAGS = /O2 /Z3
CXXFLAGS = $(CFLAGS)

OBJS = $(BUILD_DIR)\common.obj \
       $(BUILD_DIR)\sehpp.obj

TARGETS = $(BUILD_DIR)\libseh.lib

all: $(TARGETS)

$(BUILD_DIR)\libseh.lib: $(OBJS)
	$(LIB) /out:$@ $(OBJS)

$(BUILD_DIR)\common.obj: common\common.c
	$(CC) /c $? /Fo$@

$(BUILD_DIR)\sehpp.obj: common\sehpp.cpp
	$(CXX) /c $? /Fo$@ /EHa

clean:
	$(RM) $(TARGETS) $(OBJS)

