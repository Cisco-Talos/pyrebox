
CC = cl.exe
CXX = cl.exe
CFLAGS = /I.. 
CXXFLAGS = $(CFLAGS) /EHa
RM = del

EXE_EXT = .exe
OBJ_EXT = .obj

all: tests

!include "rules.mk"


tests: $(TESTS)

.SUFFIXES: .obj.exe
.obj.exe:
	$(CXX) /Fo$@ $? ..\build\libseh.lib

.SUFFIXES: .cpp.obj
.cpp.obj:
	$(CXX) /c $? $(CXXFLAGS)
clean:
	$(RM) $(TESTS) $(OBJS)
