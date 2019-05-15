#ifndef BLOCK_DIRTY_BITMAP_H
#define BLOCK_DIRTY_BITMAP_H

#include "qemu-common.h"
#include "qapi/qapi-types-block-core.h"
#include "qemu/hbitmap.h"

typedef enum BitmapCheckFlags {
    BDRV_BITMAP_BUSY = 1,
    BDRV_BITMAP_RO = 2,
    BDRV_BITMAP_INCONSISTENT = 4,
} BitmapCheckFlags;

#define BDRV_BITMAP_DEFAULT (BDRV_BITMAP_BUSY | BDRV_BITMAP_RO |        \
                             BDRV_BITMAP_INCONSISTENT)
#define BDRV_BITMAP_ALLOW_RO (BDRV_BITMAP_BUSY | BDRV_BITMAP_INCONSISTENT)

BdrvDirtyBitmap *bdrv_create_dirty_bitmap(BlockDriverState *bs,
                                          uint32_t granularity,
                                          const char *name,
                                          Error **errp);
void bdrv_create_meta_dirty_bitmap(BdrvDirtyBitmap *bitmap,
                                   int chunk_size);
void bdrv_release_meta_dirty_bitmap(BdrvDirtyBitmap *bitmap);
int bdrv_dirty_bitmap_create_successor(BlockDriverState *bs,
                                       BdrvDirtyBitmap *bitmap,
                                       Error **errp);
BdrvDirtyBitmap *bdrv_dirty_bitmap_abdicate(BlockDriverState *bs,
                                            BdrvDirtyBitmap *bitmap,
                                            Error **errp);
BdrvDirtyBitmap *bdrv_reclaim_dirty_bitmap(BlockDriverState *bs,
                                           BdrvDirtyBitmap *bitmap,
                                           Error **errp);
void bdrv_dirty_bitmap_enable_successor(BdrvDirtyBitmap *bitmap);
BdrvDirtyBitmap *bdrv_find_dirty_bitmap(BlockDriverState *bs,
                                        const char *name);
int bdrv_dirty_bitmap_check(const BdrvDirtyBitmap *bitmap, uint32_t flags,
                            Error **errp);
void bdrv_release_dirty_bitmap(BlockDriverState *bs, BdrvDirtyBitmap *bitmap);
void bdrv_release_named_dirty_bitmaps(BlockDriverState *bs);
void bdrv_remove_persistent_dirty_bitmap(BlockDriverState *bs,
                                         const char *name,
                                         Error **errp);
void bdrv_disable_dirty_bitmap(BdrvDirtyBitmap *bitmap);
void bdrv_enable_dirty_bitmap(BdrvDirtyBitmap *bitmap);
void bdrv_enable_dirty_bitmap_locked(BdrvDirtyBitmap *bitmap);
BlockDirtyInfoList *bdrv_query_dirty_bitmaps(BlockDriverState *bs);
uint32_t bdrv_get_default_bitmap_granularity(BlockDriverState *bs);
uint32_t bdrv_dirty_bitmap_granularity(const BdrvDirtyBitmap *bitmap);
bool bdrv_dirty_bitmap_enabled(BdrvDirtyBitmap *bitmap);
bool bdrv_dirty_bitmap_has_successor(BdrvDirtyBitmap *bitmap);
const char *bdrv_dirty_bitmap_name(const BdrvDirtyBitmap *bitmap);
int64_t bdrv_dirty_bitmap_size(const BdrvDirtyBitmap *bitmap);
DirtyBitmapStatus bdrv_dirty_bitmap_status(BdrvDirtyBitmap *bitmap);
void bdrv_set_dirty_bitmap(BdrvDirtyBitmap *bitmap,
                           int64_t offset, int64_t bytes);
void bdrv_reset_dirty_bitmap(BdrvDirtyBitmap *bitmap,
                             int64_t offset, int64_t bytes);
BdrvDirtyBitmapIter *bdrv_dirty_meta_iter_new(BdrvDirtyBitmap *bitmap);
BdrvDirtyBitmapIter *bdrv_dirty_iter_new(BdrvDirtyBitmap *bitmap);
void bdrv_dirty_iter_free(BdrvDirtyBitmapIter *iter);

uint64_t bdrv_dirty_bitmap_serialization_size(const BdrvDirtyBitmap *bitmap,
                                              uint64_t offset, uint64_t bytes);
uint64_t bdrv_dirty_bitmap_serialization_align(const BdrvDirtyBitmap *bitmap);
void bdrv_dirty_bitmap_serialize_part(const BdrvDirtyBitmap *bitmap,
                                      uint8_t *buf, uint64_t offset,
                                      uint64_t bytes);
void bdrv_dirty_bitmap_deserialize_part(BdrvDirtyBitmap *bitmap,
                                        uint8_t *buf, uint64_t offset,
                                        uint64_t bytes, bool finish);
void bdrv_dirty_bitmap_deserialize_zeroes(BdrvDirtyBitmap *bitmap,
                                          uint64_t offset, uint64_t bytes,
                                          bool finish);
void bdrv_dirty_bitmap_deserialize_ones(BdrvDirtyBitmap *bitmap,
                                        uint64_t offset, uint64_t bytes,
                                        bool finish);
void bdrv_dirty_bitmap_deserialize_finish(BdrvDirtyBitmap *bitmap);

void bdrv_dirty_bitmap_set_readonly(BdrvDirtyBitmap *bitmap, bool value);
void bdrv_dirty_bitmap_set_persistence(BdrvDirtyBitmap *bitmap,
                                       bool persistent);
void bdrv_dirty_bitmap_set_inconsistent(BdrvDirtyBitmap *bitmap);
void bdrv_dirty_bitmap_set_busy(BdrvDirtyBitmap *bitmap, bool busy);
void bdrv_merge_dirty_bitmap(BdrvDirtyBitmap *dest, const BdrvDirtyBitmap *src,
                             HBitmap **backup, Error **errp);
void bdrv_dirty_bitmap_set_migration(BdrvDirtyBitmap *bitmap, bool migration);

/* Functions that require manual locking.  */
void bdrv_dirty_bitmap_lock(BdrvDirtyBitmap *bitmap);
void bdrv_dirty_bitmap_unlock(BdrvDirtyBitmap *bitmap);
bool bdrv_get_dirty_locked(BlockDriverState *bs, BdrvDirtyBitmap *bitmap,
                           int64_t offset);
void bdrv_set_dirty_bitmap_locked(BdrvDirtyBitmap *bitmap,
                                  int64_t offset, int64_t bytes);
void bdrv_reset_dirty_bitmap_locked(BdrvDirtyBitmap *bitmap,
                                    int64_t offset, int64_t bytes);
int64_t bdrv_dirty_iter_next(BdrvDirtyBitmapIter *iter);
void bdrv_set_dirty_iter(BdrvDirtyBitmapIter *hbi, int64_t offset);
int64_t bdrv_get_dirty_count(BdrvDirtyBitmap *bitmap);
int64_t bdrv_get_meta_dirty_count(BdrvDirtyBitmap *bitmap);
void bdrv_dirty_bitmap_truncate(BlockDriverState *bs, int64_t bytes);
bool bdrv_dirty_bitmap_readonly(const BdrvDirtyBitmap *bitmap);
bool bdrv_has_readonly_bitmaps(BlockDriverState *bs);
bool bdrv_dirty_bitmap_get_autoload(const BdrvDirtyBitmap *bitmap);
bool bdrv_dirty_bitmap_get_persistence(BdrvDirtyBitmap *bitmap);
bool bdrv_dirty_bitmap_inconsistent(const BdrvDirtyBitmap *bitmap);
bool bdrv_has_changed_persistent_bitmaps(BlockDriverState *bs);
BdrvDirtyBitmap *bdrv_dirty_bitmap_next(BlockDriverState *bs,
                                        BdrvDirtyBitmap *bitmap);
char *bdrv_dirty_bitmap_sha256(const BdrvDirtyBitmap *bitmap, Error **errp);
int64_t bdrv_dirty_bitmap_next_zero(BdrvDirtyBitmap *bitmap, uint64_t offset,
                                    uint64_t bytes);
bool bdrv_dirty_bitmap_next_dirty_area(BdrvDirtyBitmap *bitmap,
                                       uint64_t *offset, uint64_t *bytes);
BdrvDirtyBitmap *bdrv_reclaim_dirty_bitmap_locked(BlockDriverState *bs,
                                                  BdrvDirtyBitmap *bitmap,
                                                  Error **errp);

#endif
