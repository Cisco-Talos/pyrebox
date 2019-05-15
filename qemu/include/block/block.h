#ifndef BLOCK_H
#define BLOCK_H

#include "block/aio.h"
#include "qapi/qapi-types-block-core.h"
#include "block/aio-wait.h"
#include "qemu/iov.h"
#include "qemu/coroutine.h"
#include "block/accounting.h"
#include "block/dirty-bitmap.h"
#include "block/blockjob.h"
#include "qemu/hbitmap.h"

/* block.c */
typedef struct BlockDriver BlockDriver;
typedef struct BdrvChild BdrvChild;
typedef struct BdrvChildRole BdrvChildRole;

typedef struct BlockDriverInfo {
    /* in bytes, 0 if irrelevant */
    int cluster_size;
    /* offset at which the VM state can be saved (0 if not possible) */
    int64_t vm_state_offset;
    bool is_dirty;
    /*
     * True if unallocated blocks read back as zeroes. This is equivalent
     * to the LBPRZ flag in the SCSI logical block provisioning page.
     */
    bool unallocated_blocks_are_zero;
    /*
     * True if this block driver only supports compressed writes
     */
    bool needs_compressed_writes;
} BlockDriverInfo;

typedef struct BlockFragInfo {
    uint64_t allocated_clusters;
    uint64_t total_clusters;
    uint64_t fragmented_clusters;
    uint64_t compressed_clusters;
} BlockFragInfo;

typedef enum {
    BDRV_REQ_COPY_ON_READ       = 0x1,
    BDRV_REQ_ZERO_WRITE         = 0x2,

    /*
     * The BDRV_REQ_MAY_UNMAP flag is used in write_zeroes requests to indicate
     * that the block driver should unmap (discard) blocks if it is guaranteed
     * that the result will read back as zeroes. The flag is only passed to the
     * driver if the block device is opened with BDRV_O_UNMAP.
     */
    BDRV_REQ_MAY_UNMAP          = 0x4,

    /*
     * The BDRV_REQ_NO_SERIALISING flag is only valid for reads and means that
     * we don't want wait_serialising_requests() during the read operation.
     *
     * This flag is used for backup copy-on-write operations, when we need to
     * read old data before write (write notifier triggered). It is okay since
     * we already waited for other serializing requests in the initiating write
     * (see bdrv_aligned_pwritev), and it is necessary if the initiating write
     * is already serializing (without the flag, the read would deadlock
     * waiting for the serialising write to complete).
     */
    BDRV_REQ_NO_SERIALISING     = 0x8,
    BDRV_REQ_FUA                = 0x10,
    BDRV_REQ_WRITE_COMPRESSED   = 0x20,

    /* Signifies that this write request will not change the visible disk
     * content. */
    BDRV_REQ_WRITE_UNCHANGED    = 0x40,

    /*
     * BDRV_REQ_SERIALISING forces request serialisation for writes.
     * It is used to ensure that writes to the backing file of a backup process
     * target cannot race with a read of the backup target that defers to the
     * backing file.
     *
     * Note, that BDRV_REQ_SERIALISING is _not_ opposite in meaning to
     * BDRV_REQ_NO_SERIALISING. A more descriptive name for the latter might be
     * _DO_NOT_WAIT_FOR_SERIALISING, except that is too long.
     */
    BDRV_REQ_SERIALISING        = 0x80,

    /* Execute the request only if the operation can be offloaded or otherwise
     * be executed efficiently, but return an error instead of using a slow
     * fallback. */
    BDRV_REQ_NO_FALLBACK        = 0x100,

    /* Mask of valid flags */
    BDRV_REQ_MASK               = 0x1ff,
} BdrvRequestFlags;

typedef struct BlockSizes {
    uint32_t phys;
    uint32_t log;
} BlockSizes;

typedef struct HDGeometry {
    uint32_t heads;
    uint32_t sectors;
    uint32_t cylinders;
} HDGeometry;

#define BDRV_O_RDWR        0x0002
#define BDRV_O_RESIZE      0x0004 /* request permission for resizing the node */
#define BDRV_O_SNAPSHOT    0x0008 /* open the file read only and save writes in a snapshot */
#define BDRV_O_TEMPORARY   0x0010 /* delete the file after use */
#define BDRV_O_NOCACHE     0x0020 /* do not use the host page cache */
#define BDRV_O_NATIVE_AIO  0x0080 /* use native AIO instead of the thread pool */
#define BDRV_O_NO_BACKING  0x0100 /* don't open the backing file */
#define BDRV_O_NO_FLUSH    0x0200 /* disable flushing on this disk */
#define BDRV_O_COPY_ON_READ 0x0400 /* copy read backing sectors into image */
#define BDRV_O_INACTIVE    0x0800  /* consistency hint for migration handoff */
#define BDRV_O_CHECK       0x1000  /* open solely for consistency check */
#define BDRV_O_ALLOW_RDWR  0x2000  /* allow reopen to change from r/o to r/w */
#define BDRV_O_UNMAP       0x4000  /* execute guest UNMAP/TRIM operations */
#define BDRV_O_PROTOCOL    0x8000  /* if no block driver is explicitly given:
                                      select an appropriate protocol driver,
                                      ignoring the format layer */
#define BDRV_O_NO_IO       0x10000 /* don't initialize for I/O */
#define BDRV_O_AUTO_RDONLY 0x20000 /* degrade to read-only if opening read-write fails */

#define BDRV_O_CACHE_MASK  (BDRV_O_NOCACHE | BDRV_O_NO_FLUSH)


/* Option names of options parsed by the block layer */

#define BDRV_OPT_CACHE_WB       "cache.writeback"
#define BDRV_OPT_CACHE_DIRECT   "cache.direct"
#define BDRV_OPT_CACHE_NO_FLUSH "cache.no-flush"
#define BDRV_OPT_READ_ONLY      "read-only"
#define BDRV_OPT_AUTO_READ_ONLY "auto-read-only"
#define BDRV_OPT_DISCARD        "discard"
#define BDRV_OPT_FORCE_SHARE    "force-share"


#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1)

#define BDRV_REQUEST_MAX_SECTORS MIN(SIZE_MAX >> BDRV_SECTOR_BITS, \
                                     INT_MAX >> BDRV_SECTOR_BITS)
#define BDRV_REQUEST_MAX_BYTES (BDRV_REQUEST_MAX_SECTORS << BDRV_SECTOR_BITS)

/*
 * Allocation status flags for bdrv_block_status() and friends.
 *
 * Public flags:
 * BDRV_BLOCK_DATA: allocation for data at offset is tied to this layer
 * BDRV_BLOCK_ZERO: offset reads as zero
 * BDRV_BLOCK_OFFSET_VALID: an associated offset exists for accessing raw data
 * BDRV_BLOCK_ALLOCATED: the content of the block is determined by this
 *                       layer rather than any backing, set by block layer
 * BDRV_BLOCK_EOF: the returned pnum covers through end of file for this
 *                 layer, set by block layer
 *
 * Internal flag:
 * BDRV_BLOCK_RAW: for use by passthrough drivers, such as raw, to request
 *                 that the block layer recompute the answer from the returned
 *                 BDS; must be accompanied by just BDRV_BLOCK_OFFSET_VALID.
 *
 * If BDRV_BLOCK_OFFSET_VALID is set, the map parameter represents the
 * host offset within the returned BDS that is allocated for the
 * corresponding raw guest data.  However, whether that offset
 * actually contains data also depends on BDRV_BLOCK_DATA, as follows:
 *
 * DATA ZERO OFFSET_VALID
 *  t    t        t       sectors read as zero, returned file is zero at offset
 *  t    f        t       sectors read as valid from file at offset
 *  f    t        t       sectors preallocated, read as zero, returned file not
 *                        necessarily zero at offset
 *  f    f        t       sectors preallocated but read from backing_hd,
 *                        returned file contains garbage at offset
 *  t    t        f       sectors preallocated, read as zero, unknown offset
 *  t    f        f       sectors read from unknown file or offset
 *  f    t        f       not allocated or unknown offset, read as zero
 *  f    f        f       not allocated or unknown offset, read from backing_hd
 */
#define BDRV_BLOCK_DATA         0x01
#define BDRV_BLOCK_ZERO         0x02
#define BDRV_BLOCK_OFFSET_VALID 0x04
#define BDRV_BLOCK_RAW          0x08
#define BDRV_BLOCK_ALLOCATED    0x10
#define BDRV_BLOCK_EOF          0x20
#define BDRV_BLOCK_OFFSET_MASK  BDRV_SECTOR_MASK

typedef QSIMPLEQ_HEAD(BlockReopenQueue, BlockReopenQueueEntry) BlockReopenQueue;

typedef struct BDRVReopenState {
    BlockDriverState *bs;
    int flags;
    BlockdevDetectZeroesOptions detect_zeroes;
    bool backing_missing;
    bool replace_backing_bs;  /* new_backing_bs is ignored if this is false */
    BlockDriverState *new_backing_bs; /* If NULL then detach the current bs */
    uint64_t perm, shared_perm;
    QDict *options;
    QDict *explicit_options;
    void *opaque;
} BDRVReopenState;

/*
 * Block operation types
 */
typedef enum BlockOpType {
    BLOCK_OP_TYPE_BACKUP_SOURCE,
    BLOCK_OP_TYPE_BACKUP_TARGET,
    BLOCK_OP_TYPE_CHANGE,
    BLOCK_OP_TYPE_COMMIT_SOURCE,
    BLOCK_OP_TYPE_COMMIT_TARGET,
    BLOCK_OP_TYPE_DATAPLANE,
    BLOCK_OP_TYPE_DRIVE_DEL,
    BLOCK_OP_TYPE_EJECT,
    BLOCK_OP_TYPE_EXTERNAL_SNAPSHOT,
    BLOCK_OP_TYPE_INTERNAL_SNAPSHOT,
    BLOCK_OP_TYPE_INTERNAL_SNAPSHOT_DELETE,
    BLOCK_OP_TYPE_MIRROR_SOURCE,
    BLOCK_OP_TYPE_MIRROR_TARGET,
    BLOCK_OP_TYPE_RESIZE,
    BLOCK_OP_TYPE_STREAM,
    BLOCK_OP_TYPE_REPLACE,
    BLOCK_OP_TYPE_MAX,
} BlockOpType;

/* Block node permission constants */
enum {
    /**
     * A user that has the "permission" of consistent reads is guaranteed that
     * their view of the contents of the block device is complete and
     * self-consistent, representing the contents of a disk at a specific
     * point.
     *
     * For most block devices (including their backing files) this is true, but
     * the property cannot be maintained in a few situations like for
     * intermediate nodes of a commit block job.
     */
    BLK_PERM_CONSISTENT_READ    = 0x01,

    /** This permission is required to change the visible disk contents. */
    BLK_PERM_WRITE              = 0x02,

    /**
     * This permission (which is weaker than BLK_PERM_WRITE) is both enough and
     * required for writes to the block node when the caller promises that
     * the visible disk content doesn't change.
     *
     * As the BLK_PERM_WRITE permission is strictly stronger, either is
     * sufficient to perform an unchanging write.
     */
    BLK_PERM_WRITE_UNCHANGED    = 0x04,

    /** This permission is required to change the size of a block node. */
    BLK_PERM_RESIZE             = 0x08,

    /**
     * This permission is required to change the node that this BdrvChild
     * points to.
     */
    BLK_PERM_GRAPH_MOD          = 0x10,

    BLK_PERM_ALL                = 0x1f,

    DEFAULT_PERM_PASSTHROUGH    = BLK_PERM_CONSISTENT_READ
                                 | BLK_PERM_WRITE
                                 | BLK_PERM_WRITE_UNCHANGED
                                 | BLK_PERM_RESIZE,

    DEFAULT_PERM_UNCHANGED      = BLK_PERM_ALL & ~DEFAULT_PERM_PASSTHROUGH,
};

char *bdrv_perm_names(uint64_t perm);

/* disk I/O throttling */
void bdrv_init(void);
void bdrv_init_with_whitelist(void);
bool bdrv_uses_whitelist(void);
int bdrv_is_whitelisted(BlockDriver *drv, bool read_only);
BlockDriver *bdrv_find_protocol(const char *filename,
                                bool allow_protocol_prefix,
                                Error **errp);
BlockDriver *bdrv_find_format(const char *format_name);
int bdrv_create(BlockDriver *drv, const char* filename,
                QemuOpts *opts, Error **errp);
int bdrv_create_file(const char *filename, QemuOpts *opts, Error **errp);
BlockDriverState *bdrv_new(void);
void bdrv_append(BlockDriverState *bs_new, BlockDriverState *bs_top,
                 Error **errp);
void bdrv_replace_node(BlockDriverState *from, BlockDriverState *to,
                       Error **errp);

int bdrv_parse_cache_mode(const char *mode, int *flags, bool *writethrough);
int bdrv_parse_discard_flags(const char *mode, int *flags);
BdrvChild *bdrv_open_child(const char *filename,
                           QDict *options, const char *bdref_key,
                           BlockDriverState* parent,
                           const BdrvChildRole *child_role,
                           bool allow_none, Error **errp);
BlockDriverState *bdrv_open_blockdev_ref(BlockdevRef *ref, Error **errp);
void bdrv_set_backing_hd(BlockDriverState *bs, BlockDriverState *backing_hd,
                         Error **errp);
int bdrv_open_backing_file(BlockDriverState *bs, QDict *parent_options,
                           const char *bdref_key, Error **errp);
BlockDriverState *bdrv_open(const char *filename, const char *reference,
                            QDict *options, int flags, Error **errp);
BlockDriverState *bdrv_new_open_driver(BlockDriver *drv, const char *node_name,
                                       int flags, Error **errp);
BlockReopenQueue *bdrv_reopen_queue(BlockReopenQueue *bs_queue,
                                    BlockDriverState *bs, QDict *options,
                                    bool keep_old_opts);
int bdrv_reopen_multiple(BlockReopenQueue *bs_queue, Error **errp);
int bdrv_reopen_set_read_only(BlockDriverState *bs, bool read_only,
                              Error **errp);
int bdrv_reopen_prepare(BDRVReopenState *reopen_state,
                        BlockReopenQueue *queue, Error **errp);
void bdrv_reopen_commit(BDRVReopenState *reopen_state);
void bdrv_reopen_abort(BDRVReopenState *reopen_state);
int bdrv_read(BdrvChild *child, int64_t sector_num,
              uint8_t *buf, int nb_sectors);
int bdrv_write(BdrvChild *child, int64_t sector_num,
               const uint8_t *buf, int nb_sectors);
int bdrv_pwrite_zeroes(BdrvChild *child, int64_t offset,
                       int bytes, BdrvRequestFlags flags);
int bdrv_make_zero(BdrvChild *child, BdrvRequestFlags flags);
int bdrv_pread(BdrvChild *child, int64_t offset, void *buf, int bytes);
int bdrv_preadv(BdrvChild *child, int64_t offset, QEMUIOVector *qiov);
int bdrv_pwrite(BdrvChild *child, int64_t offset, const void *buf, int bytes);
int bdrv_pwritev(BdrvChild *child, int64_t offset, QEMUIOVector *qiov);
int bdrv_pwrite_sync(BdrvChild *child, int64_t offset,
                     const void *buf, int count);
/*
 * Efficiently zero a region of the disk image.  Note that this is a regular
 * I/O request like read or write and should have a reasonable size.  This
 * function is not suitable for zeroing the entire image in a single request
 * because it may allocate memory for the entire region.
 */
int coroutine_fn bdrv_co_pwrite_zeroes(BdrvChild *child, int64_t offset,
                                       int bytes, BdrvRequestFlags flags);
BlockDriverState *bdrv_find_backing_image(BlockDriverState *bs,
    const char *backing_file);
void bdrv_refresh_filename(BlockDriverState *bs);

int coroutine_fn bdrv_co_truncate(BdrvChild *child, int64_t offset,
                                  PreallocMode prealloc, Error **errp);
int bdrv_truncate(BdrvChild *child, int64_t offset, PreallocMode prealloc,
                  Error **errp);

int64_t bdrv_nb_sectors(BlockDriverState *bs);
int64_t bdrv_getlength(BlockDriverState *bs);
int64_t bdrv_get_allocated_file_size(BlockDriverState *bs);
BlockMeasureInfo *bdrv_measure(BlockDriver *drv, QemuOpts *opts,
                               BlockDriverState *in_bs, Error **errp);
void bdrv_get_geometry(BlockDriverState *bs, uint64_t *nb_sectors_ptr);
void bdrv_refresh_limits(BlockDriverState *bs, Error **errp);
int bdrv_commit(BlockDriverState *bs);
int bdrv_change_backing_file(BlockDriverState *bs,
    const char *backing_file, const char *backing_fmt);
void bdrv_register(BlockDriver *bdrv);
int bdrv_drop_intermediate(BlockDriverState *top, BlockDriverState *base,
                           const char *backing_file_str);
BlockDriverState *bdrv_find_overlay(BlockDriverState *active,
                                    BlockDriverState *bs);
BlockDriverState *bdrv_find_base(BlockDriverState *bs);
bool bdrv_is_backing_chain_frozen(BlockDriverState *bs, BlockDriverState *base,
                                  Error **errp);
int bdrv_freeze_backing_chain(BlockDriverState *bs, BlockDriverState *base,
                              Error **errp);
void bdrv_unfreeze_backing_chain(BlockDriverState *bs, BlockDriverState *base);


typedef struct BdrvCheckResult {
    int corruptions;
    int leaks;
    int check_errors;
    int corruptions_fixed;
    int leaks_fixed;
    int64_t image_end_offset;
    BlockFragInfo bfi;
} BdrvCheckResult;

typedef enum {
    BDRV_FIX_LEAKS    = 1,
    BDRV_FIX_ERRORS   = 2,
} BdrvCheckMode;

int bdrv_check(BlockDriverState *bs, BdrvCheckResult *res, BdrvCheckMode fix);

/* The units of offset and total_work_size may be chosen arbitrarily by the
 * block driver; total_work_size may change during the course of the amendment
 * operation */
typedef void BlockDriverAmendStatusCB(BlockDriverState *bs, int64_t offset,
                                      int64_t total_work_size, void *opaque);
int bdrv_amend_options(BlockDriverState *bs_new, QemuOpts *opts,
                       BlockDriverAmendStatusCB *status_cb, void *cb_opaque,
                       Error **errp);

/* external snapshots */
bool bdrv_recurse_is_first_non_filter(BlockDriverState *bs,
                                      BlockDriverState *candidate);
bool bdrv_is_first_non_filter(BlockDriverState *candidate);

/* check if a named node can be replaced when doing drive-mirror */
BlockDriverState *check_to_replace_node(BlockDriverState *parent_bs,
                                        const char *node_name, Error **errp);

/* async block I/O */
void bdrv_aio_cancel(BlockAIOCB *acb);
void bdrv_aio_cancel_async(BlockAIOCB *acb);

/* sg packet commands */
int bdrv_co_ioctl(BlockDriverState *bs, int req, void *buf);

/* Invalidate any cached metadata used by image formats */
void bdrv_invalidate_cache(BlockDriverState *bs, Error **errp);
void bdrv_invalidate_cache_all(Error **errp);
int bdrv_inactivate_all(void);

/* Ensure contents are flushed to disk.  */
int bdrv_flush(BlockDriverState *bs);
int coroutine_fn bdrv_co_flush(BlockDriverState *bs);
int bdrv_flush_all(void);
void bdrv_close_all(void);
void bdrv_drain(BlockDriverState *bs);
void coroutine_fn bdrv_co_drain(BlockDriverState *bs);
void bdrv_drain_all_begin(void);
void bdrv_drain_all_end(void);
void bdrv_drain_all(void);

#define BDRV_POLL_WHILE(bs, cond) ({                       \
    BlockDriverState *bs_ = (bs);                          \
    AIO_WAIT_WHILE(bdrv_get_aio_context(bs_),              \
                   cond); })

int bdrv_pdiscard(BdrvChild *child, int64_t offset, int bytes);
int bdrv_co_pdiscard(BdrvChild *child, int64_t offset, int bytes);
int bdrv_has_zero_init_1(BlockDriverState *bs);
int bdrv_has_zero_init(BlockDriverState *bs);
bool bdrv_unallocated_blocks_are_zero(BlockDriverState *bs);
bool bdrv_can_write_zeroes_with_unmap(BlockDriverState *bs);
int bdrv_block_status(BlockDriverState *bs, int64_t offset,
                      int64_t bytes, int64_t *pnum, int64_t *map,
                      BlockDriverState **file);
int bdrv_block_status_above(BlockDriverState *bs, BlockDriverState *base,
                            int64_t offset, int64_t bytes, int64_t *pnum,
                            int64_t *map, BlockDriverState **file);
int bdrv_is_allocated(BlockDriverState *bs, int64_t offset, int64_t bytes,
                      int64_t *pnum);
int bdrv_is_allocated_above(BlockDriverState *top, BlockDriverState *base,
                            int64_t offset, int64_t bytes, int64_t *pnum);

bool bdrv_is_read_only(BlockDriverState *bs);
int bdrv_can_set_read_only(BlockDriverState *bs, bool read_only,
                           bool ignore_allow_rdw, Error **errp);
int bdrv_apply_auto_read_only(BlockDriverState *bs, const char *errmsg,
                              Error **errp);
bool bdrv_is_writable(BlockDriverState *bs);
bool bdrv_is_sg(BlockDriverState *bs);
bool bdrv_is_inserted(BlockDriverState *bs);
void bdrv_lock_medium(BlockDriverState *bs, bool locked);
void bdrv_eject(BlockDriverState *bs, bool eject_flag);
const char *bdrv_get_format_name(BlockDriverState *bs);
BlockDriverState *bdrv_find_node(const char *node_name);
BlockDeviceInfoList *bdrv_named_nodes_list(Error **errp);
XDbgBlockGraph *bdrv_get_xdbg_block_graph(Error **errp);
BlockDriverState *bdrv_lookup_bs(const char *device,
                                 const char *node_name,
                                 Error **errp);
bool bdrv_chain_contains(BlockDriverState *top, BlockDriverState *base);
BlockDriverState *bdrv_next_node(BlockDriverState *bs);
BlockDriverState *bdrv_next_all_states(BlockDriverState *bs);

typedef struct BdrvNextIterator {
    enum {
        BDRV_NEXT_BACKEND_ROOTS,
        BDRV_NEXT_MONITOR_OWNED,
    } phase;
    BlockBackend *blk;
    BlockDriverState *bs;
} BdrvNextIterator;

BlockDriverState *bdrv_first(BdrvNextIterator *it);
BlockDriverState *bdrv_next(BdrvNextIterator *it);
void bdrv_next_cleanup(BdrvNextIterator *it);

BlockDriverState *bdrv_next_monitor_owned(BlockDriverState *bs);
bool bdrv_is_encrypted(BlockDriverState *bs);
void bdrv_iterate_format(void (*it)(void *opaque, const char *name),
                         void *opaque, bool read_only);
const char *bdrv_get_node_name(const BlockDriverState *bs);
const char *bdrv_get_device_name(const BlockDriverState *bs);
const char *bdrv_get_device_or_node_name(const BlockDriverState *bs);
int bdrv_get_flags(BlockDriverState *bs);
int bdrv_get_info(BlockDriverState *bs, BlockDriverInfo *bdi);
ImageInfoSpecific *bdrv_get_specific_info(BlockDriverState *bs,
                                          Error **errp);
void bdrv_round_to_clusters(BlockDriverState *bs,
                            int64_t offset, int64_t bytes,
                            int64_t *cluster_offset,
                            int64_t *cluster_bytes);

void bdrv_get_backing_filename(BlockDriverState *bs,
                               char *filename, int filename_size);
char *bdrv_get_full_backing_filename(BlockDriverState *bs, Error **errp);
char *bdrv_get_full_backing_filename_from_filename(const char *backed,
                                                   const char *backing,
                                                   Error **errp);
char *bdrv_dirname(BlockDriverState *bs, Error **errp);

int path_has_protocol(const char *path);
int path_is_absolute(const char *path);
char *path_combine(const char *base_path, const char *filename);

int bdrv_readv_vmstate(BlockDriverState *bs, QEMUIOVector *qiov, int64_t pos);
int bdrv_writev_vmstate(BlockDriverState *bs, QEMUIOVector *qiov, int64_t pos);
int bdrv_save_vmstate(BlockDriverState *bs, const uint8_t *buf,
                      int64_t pos, int size);

int bdrv_load_vmstate(BlockDriverState *bs, uint8_t *buf,
                      int64_t pos, int size);

void bdrv_img_create(const char *filename, const char *fmt,
                     const char *base_filename, const char *base_fmt,
                     char *options, uint64_t img_size, int flags,
                     bool quiet, Error **errp);

/* Returns the alignment in bytes that is required so that no bounce buffer
 * is required throughout the stack */
size_t bdrv_min_mem_align(BlockDriverState *bs);
/* Returns optimal alignment in bytes for bounce buffer */
size_t bdrv_opt_mem_align(BlockDriverState *bs);
void *qemu_blockalign(BlockDriverState *bs, size_t size);
void *qemu_blockalign0(BlockDriverState *bs, size_t size);
void *qemu_try_blockalign(BlockDriverState *bs, size_t size);
void *qemu_try_blockalign0(BlockDriverState *bs, size_t size);
bool bdrv_qiov_is_aligned(BlockDriverState *bs, QEMUIOVector *qiov);

void bdrv_enable_copy_on_read(BlockDriverState *bs);
void bdrv_disable_copy_on_read(BlockDriverState *bs);

void bdrv_ref(BlockDriverState *bs);
void bdrv_unref(BlockDriverState *bs);
void bdrv_unref_child(BlockDriverState *parent, BdrvChild *child);
BdrvChild *bdrv_attach_child(BlockDriverState *parent_bs,
                             BlockDriverState *child_bs,
                             const char *child_name,
                             const BdrvChildRole *child_role,
                             Error **errp);

bool bdrv_op_is_blocked(BlockDriverState *bs, BlockOpType op, Error **errp);
void bdrv_op_block(BlockDriverState *bs, BlockOpType op, Error *reason);
void bdrv_op_unblock(BlockDriverState *bs, BlockOpType op, Error *reason);
void bdrv_op_block_all(BlockDriverState *bs, Error *reason);
void bdrv_op_unblock_all(BlockDriverState *bs, Error *reason);
bool bdrv_op_blocker_is_empty(BlockDriverState *bs);

#define BLKDBG_EVENT(child, evt) \
    do { \
        if (child) { \
            bdrv_debug_event(child->bs, evt); \
        } \
    } while (0)

void bdrv_debug_event(BlockDriverState *bs, BlkdebugEvent event);

int bdrv_debug_breakpoint(BlockDriverState *bs, const char *event,
                           const char *tag);
int bdrv_debug_remove_breakpoint(BlockDriverState *bs, const char *tag);
int bdrv_debug_resume(BlockDriverState *bs, const char *tag);
bool bdrv_debug_is_suspended(BlockDriverState *bs, const char *tag);

/**
 * bdrv_get_aio_context:
 *
 * Returns: the currently bound #AioContext
 */
AioContext *bdrv_get_aio_context(BlockDriverState *bs);

/**
 * Transfer control to @co in the aio context of @bs
 */
void bdrv_coroutine_enter(BlockDriverState *bs, Coroutine *co);

/**
 * bdrv_set_aio_context:
 *
 * Changes the #AioContext used for fd handlers, timers, and BHs by this
 * BlockDriverState and all its children.
 *
 * This function must be called with iothread lock held.
 */
void bdrv_set_aio_context(BlockDriverState *bs, AioContext *new_context);
int bdrv_probe_blocksizes(BlockDriverState *bs, BlockSizes *bsz);
int bdrv_probe_geometry(BlockDriverState *bs, HDGeometry *geo);

void bdrv_io_plug(BlockDriverState *bs);
void bdrv_io_unplug(BlockDriverState *bs);

/**
 * bdrv_parent_drained_begin:
 *
 * Begin a quiesced section of all users of @bs. This is part of
 * bdrv_drained_begin.
 */
void bdrv_parent_drained_begin(BlockDriverState *bs, BdrvChild *ignore,
                               bool ignore_bds_parents);

/**
 * bdrv_parent_drained_begin_single:
 *
 * Begin a quiesced section for the parent of @c. If @poll is true, wait for
 * any pending activity to cease.
 */
void bdrv_parent_drained_begin_single(BdrvChild *c, bool poll);

/**
 * bdrv_parent_drained_end:
 *
 * End a quiesced section of all users of @bs. This is part of
 * bdrv_drained_end.
 */
void bdrv_parent_drained_end(BlockDriverState *bs, BdrvChild *ignore,
                             bool ignore_bds_parents);

/**
 * bdrv_drain_poll:
 *
 * Poll for pending requests in @bs, its parents (except for @ignore_parent),
 * and if @recursive is true its children as well (used for subtree drain).
 *
 * If @ignore_bds_parents is true, parents that are BlockDriverStates must
 * ignore the drain request because they will be drained separately (used for
 * drain_all).
 *
 * This is part of bdrv_drained_begin.
 */
bool bdrv_drain_poll(BlockDriverState *bs, bool recursive,
                     BdrvChild *ignore_parent, bool ignore_bds_parents);

/**
 * bdrv_drained_begin:
 *
 * Begin a quiesced section for exclusive access to the BDS, by disabling
 * external request sources including NBD server and device model. Note that
 * this doesn't block timers or coroutines from submitting more requests, which
 * means block_job_pause is still necessary.
 *
 * This function can be recursive.
 */
void bdrv_drained_begin(BlockDriverState *bs);

/**
 * bdrv_do_drained_begin_quiesce:
 *
 * Quiesces a BDS like bdrv_drained_begin(), but does not wait for already
 * running requests to complete.
 */
void bdrv_do_drained_begin_quiesce(BlockDriverState *bs,
                                   BdrvChild *parent, bool ignore_bds_parents);

/**
 * Like bdrv_drained_begin, but recursively begins a quiesced section for
 * exclusive access to all child nodes as well.
 */
void bdrv_subtree_drained_begin(BlockDriverState *bs);

/**
 * bdrv_drained_end:
 *
 * End a quiescent section started by bdrv_drained_begin().
 */
void bdrv_drained_end(BlockDriverState *bs);

/**
 * End a quiescent section started by bdrv_subtree_drained_begin().
 */
void bdrv_subtree_drained_end(BlockDriverState *bs);

void bdrv_add_child(BlockDriverState *parent, BlockDriverState *child,
                    Error **errp);
void bdrv_del_child(BlockDriverState *parent, BdrvChild *child, Error **errp);

bool bdrv_can_store_new_dirty_bitmap(BlockDriverState *bs, const char *name,
                                     uint32_t granularity, Error **errp);
/**
 *
 * bdrv_register_buf/bdrv_unregister_buf:
 *
 * Register/unregister a buffer for I/O. For example, VFIO drivers are
 * interested to know the memory areas that would later be used for I/O, so
 * that they can prepare IOMMU mapping etc., to get better performance.
 */
void bdrv_register_buf(BlockDriverState *bs, void *host, size_t size);
void bdrv_unregister_buf(BlockDriverState *bs, void *host);

/**
 *
 * bdrv_co_copy_range:
 *
 * Do offloaded copy between two children. If the operation is not implemented
 * by the driver, or if the backend storage doesn't support it, a negative
 * error code will be returned.
 *
 * Note: block layer doesn't emulate or fallback to a bounce buffer approach
 * because usually the caller shouldn't attempt offloaded copy any more (e.g.
 * calling copy_file_range(2)) after the first error, thus it should fall back
 * to a read+write path in the caller level.
 *
 * @src: Source child to copy data from
 * @src_offset: offset in @src image to read data
 * @dst: Destination child to copy data to
 * @dst_offset: offset in @dst image to write data
 * @bytes: number of bytes to copy
 * @flags: request flags. Supported flags:
 *         BDRV_REQ_ZERO_WRITE - treat the @src range as zero data and do zero
 *                               write on @dst as if bdrv_co_pwrite_zeroes is
 *                               called. Used to simplify caller code, or
 *                               during BlockDriver.bdrv_co_copy_range_from()
 *                               recursion.
 *         BDRV_REQ_NO_SERIALISING - do not serialize with other overlapping
 *                                   requests currently in flight.
 *
 * Returns: 0 if succeeded; negative error code if failed.
 **/
int coroutine_fn bdrv_co_copy_range(BdrvChild *src, uint64_t src_offset,
                                    BdrvChild *dst, uint64_t dst_offset,
                                    uint64_t bytes, BdrvRequestFlags read_flags,
                                    BdrvRequestFlags write_flags);
#endif
