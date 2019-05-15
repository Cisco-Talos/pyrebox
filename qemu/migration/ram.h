/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2011-2015 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef QEMU_MIGRATION_RAM_H
#define QEMU_MIGRATION_RAM_H

#include "qemu-common.h"
#include "qapi/qapi-types-migration.h"
#include "exec/cpu-common.h"
#include "io/channel.h"

extern MigrationStats ram_counters;
extern XBZRLECacheStats xbzrle_counters;
extern CompressionStats compression_counters;

int xbzrle_cache_resize(int64_t new_size, Error **errp);
uint64_t ram_bytes_remaining(void);
uint64_t ram_bytes_total(void);

int multifd_save_setup(void);
void multifd_save_cleanup(void);
int multifd_load_setup(void);
int multifd_load_cleanup(Error **errp);
bool multifd_recv_all_channels_created(void);
bool multifd_recv_new_channel(QIOChannel *ioc, Error **errp);

uint64_t ram_pagesize_summary(void);
int ram_save_queue_pages(const char *rbname, ram_addr_t start, ram_addr_t len);
void acct_update_position(QEMUFile *f, size_t size, bool zero);
void ram_debug_dump_bitmap(unsigned long *todump, bool expected,
                           unsigned long pages);
void ram_postcopy_migrated_memory_release(MigrationState *ms);
/* For outgoing discard bitmap */
int ram_postcopy_send_discard_bitmap(MigrationState *ms);
/* For incoming postcopy discard */
int ram_discard_range(const char *block_name, uint64_t start, size_t length);
int ram_postcopy_incoming_init(MigrationIncomingState *mis);

void ram_handle_compressed(void *host, uint8_t ch, uint64_t size);

int ramblock_recv_bitmap_test(RAMBlock *rb, void *host_addr);
bool ramblock_recv_bitmap_test_byte_offset(RAMBlock *rb, uint64_t byte_offset);
void ramblock_recv_bitmap_set(RAMBlock *rb, void *host_addr);
void ramblock_recv_bitmap_set_range(RAMBlock *rb, void *host_addr, size_t nr);
int64_t ramblock_recv_bitmap_send(QEMUFile *file,
                                  const char *block_name);
int ram_dirty_bitmap_reload(MigrationState *s, RAMBlock *rb);

/* ram cache */
int colo_init_ram_cache(void);
void colo_release_ram_cache(void);

#endif
