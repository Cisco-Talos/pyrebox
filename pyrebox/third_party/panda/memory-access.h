/*
 * Mount guest physical memory using FUSE.
 *
 * Copyright (C) 2011 Sandia National Laboratories
 * Author: Bryan D. Payne (bdpayne@acm.org)
 */
#include <inttypes.h>
int memory_access_start (const char *path);
uint64_t get_memory_size();
