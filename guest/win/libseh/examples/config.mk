
CC := gcc
CXX := g++
CFLAGS := -O2 -fno-omit-frame-pointer -Wall -I../..
CXXFLAGS := $(CFLAGS)
LDFLAGS := -L../../build -lseh
RM := del 

