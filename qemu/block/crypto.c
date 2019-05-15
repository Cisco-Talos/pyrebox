/*
 * QEMU block full disk encryption
 *
 * Copyright (c) 2015-2016 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"

#include "block/block_int.h"
#include "block/qdict.h"
#include "sysemu/block-backend.h"
#include "crypto/block.h"
#include "qapi/opts-visitor.h"
#include "qapi/qapi-visit-crypto.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/error.h"
#include "qemu/option.h"
#include "crypto.h"

typedef struct BlockCrypto BlockCrypto;

struct BlockCrypto {
    QCryptoBlock *block;
};


static int block_crypto_probe_generic(QCryptoBlockFormat format,
                                      const uint8_t *buf,
                                      int buf_size,
                                      const char *filename)
{
    if (qcrypto_block_has_format(format, buf, buf_size)) {
        return 100;
    } else {
        return 0;
    }
}


static ssize_t block_crypto_read_func(QCryptoBlock *block,
                                      size_t offset,
                                      uint8_t *buf,
                                      size_t buflen,
                                      void *opaque,
                                      Error **errp)
{
    BlockDriverState *bs = opaque;
    ssize_t ret;

    ret = bdrv_pread(bs->file, offset, buf, buflen);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Could not read encryption header");
        return ret;
    }
    return ret;
}


struct BlockCryptoCreateData {
    BlockBackend *blk;
    uint64_t size;
};


static ssize_t block_crypto_write_func(QCryptoBlock *block,
                                       size_t offset,
                                       const uint8_t *buf,
                                       size_t buflen,
                                       void *opaque,
                                       Error **errp)
{
    struct BlockCryptoCreateData *data = opaque;
    ssize_t ret;

    ret = blk_pwrite(data->blk, offset, buf, buflen, 0);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Could not write encryption header");
        return ret;
    }
    return ret;
}


static ssize_t block_crypto_init_func(QCryptoBlock *block,
                                      size_t headerlen,
                                      void *opaque,
                                      Error **errp)
{
    struct BlockCryptoCreateData *data = opaque;

    if (data->size > INT64_MAX || headerlen > INT64_MAX - data->size) {
        error_setg(errp, "The requested file size is too large");
        return -EFBIG;
    }

    /* User provided size should reflect amount of space made
     * available to the guest, so we must take account of that
     * which will be used by the crypto header
     */
    return blk_truncate(data->blk, data->size + headerlen, PREALLOC_MODE_OFF,
                        errp);
}


static QemuOptsList block_crypto_runtime_opts_luks = {
    .name = "crypto",
    .head = QTAILQ_HEAD_INITIALIZER(block_crypto_runtime_opts_luks.head),
    .desc = {
        BLOCK_CRYPTO_OPT_DEF_LUKS_KEY_SECRET(""),
        { /* end of list */ }
    },
};


static QemuOptsList block_crypto_create_opts_luks = {
    .name = "crypto",
    .head = QTAILQ_HEAD_INITIALIZER(block_crypto_create_opts_luks.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        BLOCK_CRYPTO_OPT_DEF_LUKS_KEY_SECRET(""),
        BLOCK_CRYPTO_OPT_DEF_LUKS_CIPHER_ALG(""),
        BLOCK_CRYPTO_OPT_DEF_LUKS_CIPHER_MODE(""),
        BLOCK_CRYPTO_OPT_DEF_LUKS_IVGEN_ALG(""),
        BLOCK_CRYPTO_OPT_DEF_LUKS_IVGEN_HASH_ALG(""),
        BLOCK_CRYPTO_OPT_DEF_LUKS_HASH_ALG(""),
        BLOCK_CRYPTO_OPT_DEF_LUKS_ITER_TIME(""),
        { /* end of list */ }
    },
};


QCryptoBlockOpenOptions *
block_crypto_open_opts_init(QDict *opts, Error **errp)
{
    Visitor *v;
    QCryptoBlockOpenOptions *ret;

    v = qobject_input_visitor_new_flat_confused(opts, errp);
    if (!v) {
        return NULL;
    }

    visit_type_QCryptoBlockOpenOptions(v, NULL, &ret, errp);

    visit_free(v);
    return ret;
}


QCryptoBlockCreateOptions *
block_crypto_create_opts_init(QDict *opts, Error **errp)
{
    Visitor *v;
    QCryptoBlockCreateOptions *ret;

    v = qobject_input_visitor_new_flat_confused(opts, errp);
    if (!v) {
        return NULL;
    }

    visit_type_QCryptoBlockCreateOptions(v, NULL, &ret, errp);

    visit_free(v);
    return ret;
}


static int block_crypto_open_generic(QCryptoBlockFormat format,
                                     QemuOptsList *opts_spec,
                                     BlockDriverState *bs,
                                     QDict *options,
                                     int flags,
                                     Error **errp)
{
    BlockCrypto *crypto = bs->opaque;
    QemuOpts *opts = NULL;
    Error *local_err = NULL;
    int ret = -EINVAL;
    QCryptoBlockOpenOptions *open_opts = NULL;
    unsigned int cflags = 0;
    QDict *cryptoopts = NULL;

    bs->file = bdrv_open_child(NULL, options, "file", bs, &child_file,
                               false, errp);
    if (!bs->file) {
        return -EINVAL;
    }

    bs->supported_write_flags = BDRV_REQ_FUA &
        bs->file->bs->supported_write_flags;

    opts = qemu_opts_create(opts_spec, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto cleanup;
    }

    cryptoopts = qemu_opts_to_qdict(opts, NULL);
    qdict_put_str(cryptoopts, "format", QCryptoBlockFormat_str(format));

    open_opts = block_crypto_open_opts_init(cryptoopts, errp);
    if (!open_opts) {
        goto cleanup;
    }

    if (flags & BDRV_O_NO_IO) {
        cflags |= QCRYPTO_BLOCK_OPEN_NO_IO;
    }
    crypto->block = qcrypto_block_open(open_opts, NULL,
                                       block_crypto_read_func,
                                       bs,
                                       cflags,
                                       1,
                                       errp);

    if (!crypto->block) {
        ret = -EIO;
        goto cleanup;
    }

    bs->encrypted = true;

    ret = 0;
 cleanup:
    qobject_unref(cryptoopts);
    qapi_free_QCryptoBlockOpenOptions(open_opts);
    return ret;
}


static int block_crypto_co_create_generic(BlockDriverState *bs,
                                          int64_t size,
                                          QCryptoBlockCreateOptions *opts,
                                          Error **errp)
{
    int ret;
    BlockBackend *blk;
    QCryptoBlock *crypto = NULL;
    struct BlockCryptoCreateData data;

    blk = blk_new(BLK_PERM_WRITE | BLK_PERM_RESIZE, BLK_PERM_ALL);

    ret = blk_insert_bs(blk, bs, errp);
    if (ret < 0) {
        goto cleanup;
    }

    data = (struct BlockCryptoCreateData) {
        .blk = blk,
        .size = size,
    };

    crypto = qcrypto_block_create(opts, NULL,
                                  block_crypto_init_func,
                                  block_crypto_write_func,
                                  &data,
                                  errp);

    if (!crypto) {
        ret = -EIO;
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qcrypto_block_free(crypto);
    blk_unref(blk);
    return ret;
}

static int coroutine_fn
block_crypto_co_truncate(BlockDriverState *bs, int64_t offset,
                         PreallocMode prealloc, Error **errp)
{
    BlockCrypto *crypto = bs->opaque;
    uint64_t payload_offset =
        qcrypto_block_get_payload_offset(crypto->block);

    if (payload_offset > INT64_MAX - offset) {
        error_setg(errp, "The requested file size is too large");
        return -EFBIG;
    }

    offset += payload_offset;

    return bdrv_co_truncate(bs->file, offset, prealloc, errp);
}

static void block_crypto_close(BlockDriverState *bs)
{
    BlockCrypto *crypto = bs->opaque;
    qcrypto_block_free(crypto->block);
}

static int block_crypto_reopen_prepare(BDRVReopenState *state,
                                       BlockReopenQueue *queue, Error **errp)
{
    /* nothing needs checking */
    return 0;
}

/*
 * 1 MB bounce buffer gives good performance / memory tradeoff
 * when using cache=none|directsync.
 */
#define BLOCK_CRYPTO_MAX_IO_SIZE (1024 * 1024)

static coroutine_fn int
block_crypto_co_preadv(BlockDriverState *bs, uint64_t offset, uint64_t bytes,
                       QEMUIOVector *qiov, int flags)
{
    BlockCrypto *crypto = bs->opaque;
    uint64_t cur_bytes; /* number of bytes in current iteration */
    uint64_t bytes_done = 0;
    uint8_t *cipher_data = NULL;
    QEMUIOVector hd_qiov;
    int ret = 0;
    uint64_t sector_size = qcrypto_block_get_sector_size(crypto->block);
    uint64_t payload_offset = qcrypto_block_get_payload_offset(crypto->block);

    assert(!flags);
    assert(payload_offset < INT64_MAX);
    assert(QEMU_IS_ALIGNED(offset, sector_size));
    assert(QEMU_IS_ALIGNED(bytes, sector_size));

    qemu_iovec_init(&hd_qiov, qiov->niov);

    /* Bounce buffer because we don't wish to expose cipher text
     * in qiov which points to guest memory.
     */
    cipher_data =
        qemu_try_blockalign(bs->file->bs, MIN(BLOCK_CRYPTO_MAX_IO_SIZE,
                                              qiov->size));
    if (cipher_data == NULL) {
        ret = -ENOMEM;
        goto cleanup;
    }

    while (bytes) {
        cur_bytes = MIN(bytes, BLOCK_CRYPTO_MAX_IO_SIZE);

        qemu_iovec_reset(&hd_qiov);
        qemu_iovec_add(&hd_qiov, cipher_data, cur_bytes);

        ret = bdrv_co_preadv(bs->file, payload_offset + offset + bytes_done,
                             cur_bytes, &hd_qiov, 0);
        if (ret < 0) {
            goto cleanup;
        }

        if (qcrypto_block_decrypt(crypto->block, offset + bytes_done,
                                  cipher_data, cur_bytes, NULL) < 0) {
            ret = -EIO;
            goto cleanup;
        }

        qemu_iovec_from_buf(qiov, bytes_done, cipher_data, cur_bytes);

        bytes -= cur_bytes;
        bytes_done += cur_bytes;
    }

 cleanup:
    qemu_iovec_destroy(&hd_qiov);
    qemu_vfree(cipher_data);

    return ret;
}


static coroutine_fn int
block_crypto_co_pwritev(BlockDriverState *bs, uint64_t offset, uint64_t bytes,
                        QEMUIOVector *qiov, int flags)
{
    BlockCrypto *crypto = bs->opaque;
    uint64_t cur_bytes; /* number of bytes in current iteration */
    uint64_t bytes_done = 0;
    uint8_t *cipher_data = NULL;
    QEMUIOVector hd_qiov;
    int ret = 0;
    uint64_t sector_size = qcrypto_block_get_sector_size(crypto->block);
    uint64_t payload_offset = qcrypto_block_get_payload_offset(crypto->block);

    assert(!(flags & ~BDRV_REQ_FUA));
    assert(payload_offset < INT64_MAX);
    assert(QEMU_IS_ALIGNED(offset, sector_size));
    assert(QEMU_IS_ALIGNED(bytes, sector_size));

    qemu_iovec_init(&hd_qiov, qiov->niov);

    /* Bounce buffer because we're not permitted to touch
     * contents of qiov - it points to guest memory.
     */
    cipher_data =
        qemu_try_blockalign(bs->file->bs, MIN(BLOCK_CRYPTO_MAX_IO_SIZE,
                                              qiov->size));
    if (cipher_data == NULL) {
        ret = -ENOMEM;
        goto cleanup;
    }

    while (bytes) {
        cur_bytes = MIN(bytes, BLOCK_CRYPTO_MAX_IO_SIZE);

        qemu_iovec_to_buf(qiov, bytes_done, cipher_data, cur_bytes);

        if (qcrypto_block_encrypt(crypto->block, offset + bytes_done,
                                  cipher_data, cur_bytes, NULL) < 0) {
            ret = -EIO;
            goto cleanup;
        }

        qemu_iovec_reset(&hd_qiov);
        qemu_iovec_add(&hd_qiov, cipher_data, cur_bytes);

        ret = bdrv_co_pwritev(bs->file, payload_offset + offset + bytes_done,
                              cur_bytes, &hd_qiov, flags);
        if (ret < 0) {
            goto cleanup;
        }

        bytes -= cur_bytes;
        bytes_done += cur_bytes;
    }

 cleanup:
    qemu_iovec_destroy(&hd_qiov);
    qemu_vfree(cipher_data);

    return ret;
}

static void block_crypto_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BlockCrypto *crypto = bs->opaque;
    uint64_t sector_size = qcrypto_block_get_sector_size(crypto->block);
    bs->bl.request_alignment = sector_size; /* No sub-sector I/O */
}


static int64_t block_crypto_getlength(BlockDriverState *bs)
{
    BlockCrypto *crypto = bs->opaque;
    int64_t len = bdrv_getlength(bs->file->bs);

    uint64_t offset = qcrypto_block_get_payload_offset(crypto->block);
    assert(offset < INT64_MAX);

    if (offset > len) {
        return -EIO;
    }

    len -= offset;

    return len;
}


static int block_crypto_probe_luks(const uint8_t *buf,
                                   int buf_size,
                                   const char *filename) {
    return block_crypto_probe_generic(Q_CRYPTO_BLOCK_FORMAT_LUKS,
                                      buf, buf_size, filename);
}

static int block_crypto_open_luks(BlockDriverState *bs,
                                  QDict *options,
                                  int flags,
                                  Error **errp)
{
    return block_crypto_open_generic(Q_CRYPTO_BLOCK_FORMAT_LUKS,
                                     &block_crypto_runtime_opts_luks,
                                     bs, options, flags, errp);
}

static int coroutine_fn
block_crypto_co_create_luks(BlockdevCreateOptions *create_options, Error **errp)
{
    BlockdevCreateOptionsLUKS *luks_opts;
    BlockDriverState *bs = NULL;
    QCryptoBlockCreateOptions create_opts;
    int ret;

    assert(create_options->driver == BLOCKDEV_DRIVER_LUKS);
    luks_opts = &create_options->u.luks;

    bs = bdrv_open_blockdev_ref(luks_opts->file, errp);
    if (bs == NULL) {
        return -EIO;
    }

    create_opts = (QCryptoBlockCreateOptions) {
        .format = Q_CRYPTO_BLOCK_FORMAT_LUKS,
        .u.luks = *qapi_BlockdevCreateOptionsLUKS_base(luks_opts),
    };

    ret = block_crypto_co_create_generic(bs, luks_opts->size, &create_opts,
                                         errp);
    if (ret < 0) {
        goto fail;
    }

    ret = 0;
fail:
    bdrv_unref(bs);
    return ret;
}

static int coroutine_fn block_crypto_co_create_opts_luks(const char *filename,
                                                         QemuOpts *opts,
                                                         Error **errp)
{
    QCryptoBlockCreateOptions *create_opts = NULL;
    BlockDriverState *bs = NULL;
    QDict *cryptoopts;
    int64_t size;
    int ret;

    /* Parse options */
    size = qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0);

    cryptoopts = qemu_opts_to_qdict_filtered(opts, NULL,
                                             &block_crypto_create_opts_luks,
                                             true);

    qdict_put_str(cryptoopts, "format", "luks");
    create_opts = block_crypto_create_opts_init(cryptoopts, errp);
    if (!create_opts) {
        ret = -EINVAL;
        goto fail;
    }

    /* Create protocol layer */
    ret = bdrv_create_file(filename, opts, errp);
    if (ret < 0) {
        goto fail;
    }

    bs = bdrv_open(filename, NULL, NULL,
                   BDRV_O_RDWR | BDRV_O_RESIZE | BDRV_O_PROTOCOL, errp);
    if (!bs) {
        ret = -EINVAL;
        goto fail;
    }

    /* Create format layer */
    ret = block_crypto_co_create_generic(bs, size, create_opts, errp);
    if (ret < 0) {
        goto fail;
    }

    ret = 0;
fail:
    bdrv_unref(bs);
    qapi_free_QCryptoBlockCreateOptions(create_opts);
    qobject_unref(cryptoopts);
    return ret;
}

static int block_crypto_get_info_luks(BlockDriverState *bs,
                                      BlockDriverInfo *bdi)
{
    BlockDriverInfo subbdi;
    int ret;

    ret = bdrv_get_info(bs->file->bs, &subbdi);
    if (ret != 0) {
        return ret;
    }

    bdi->unallocated_blocks_are_zero = false;
    bdi->cluster_size = subbdi.cluster_size;

    return 0;
}

static ImageInfoSpecific *
block_crypto_get_specific_info_luks(BlockDriverState *bs, Error **errp)
{
    BlockCrypto *crypto = bs->opaque;
    ImageInfoSpecific *spec_info;
    QCryptoBlockInfo *info;

    info = qcrypto_block_get_info(crypto->block, errp);
    if (!info) {
        return NULL;
    }
    assert(info->format == Q_CRYPTO_BLOCK_FORMAT_LUKS);

    spec_info = g_new(ImageInfoSpecific, 1);
    spec_info->type = IMAGE_INFO_SPECIFIC_KIND_LUKS;
    spec_info->u.luks.data = g_new(QCryptoBlockInfoLUKS, 1);
    *spec_info->u.luks.data = info->u.luks;

    /* Blank out pointers we've just stolen to avoid double free */
    memset(&info->u.luks, 0, sizeof(info->u.luks));

    qapi_free_QCryptoBlockInfo(info);

    return spec_info;
}

static const char *const block_crypto_strong_runtime_opts[] = {
    BLOCK_CRYPTO_OPT_LUKS_KEY_SECRET,

    NULL
};

static BlockDriver bdrv_crypto_luks = {
    .format_name        = "luks",
    .instance_size      = sizeof(BlockCrypto),
    .bdrv_probe         = block_crypto_probe_luks,
    .bdrv_open          = block_crypto_open_luks,
    .bdrv_close         = block_crypto_close,
    /* This driver doesn't modify LUKS metadata except when creating image.
     * Allow share-rw=on as a special case. */
    .bdrv_child_perm    = bdrv_filter_default_perms,
    .bdrv_co_create     = block_crypto_co_create_luks,
    .bdrv_co_create_opts = block_crypto_co_create_opts_luks,
    .bdrv_co_truncate   = block_crypto_co_truncate,
    .create_opts        = &block_crypto_create_opts_luks,

    .bdrv_reopen_prepare = block_crypto_reopen_prepare,
    .bdrv_refresh_limits = block_crypto_refresh_limits,
    .bdrv_co_preadv     = block_crypto_co_preadv,
    .bdrv_co_pwritev    = block_crypto_co_pwritev,
    .bdrv_getlength     = block_crypto_getlength,
    .bdrv_get_info      = block_crypto_get_info_luks,
    .bdrv_get_specific_info = block_crypto_get_specific_info_luks,

    .strong_runtime_opts = block_crypto_strong_runtime_opts,
};

static void block_crypto_init(void)
{
    bdrv_register(&bdrv_crypto_luks);
}

block_init(block_crypto_init);
