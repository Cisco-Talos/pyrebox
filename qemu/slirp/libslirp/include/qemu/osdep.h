#ifndef OSDEP_H
#define OSDEP_H
#include "qemu/compiler.h"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#endif

