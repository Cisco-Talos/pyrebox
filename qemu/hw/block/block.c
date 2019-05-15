/*
 * Common code for block device models
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "sysemu/blockdev.h"
#include "sysemu/block-backend.h"
#include "hw/block/block.h"
#include "qapi/error.h"
#include "qapi/qapi-types-block.h"

/*
 * Read the entire contents of @blk into @buf.
 * @blk's contents must be @size bytes, and @size must be at most
 * BDRV_REQUEST_MAX_BYTES.
 * On success, return true.
 * On failure, store an error through @errp and return false.
 * Note that the error messages do not identify the block backend.
 * TODO Since callers don't either, this can result in confusing
 * errors.
 * This function not intended for actual block devices, which read on
 * demand.  It's for things like memory devices that (ab)use a block
 * backend to provide persistence.
 */
bool blk_check_size_and_read_all(BlockBackend *blk, void *buf, hwaddr size,
                                 Error **errp)
{
    int64_t blk_len;
    int ret;

    blk_len = blk_getlength(blk);
    if (blk_len < 0) {
        error_setg_errno(errp, -blk_len,
                         "can't get size of block backend");
        return false;
    }
    if (blk_len != size) {
        error_setg(errp, "device requires %" HWADDR_PRIu " bytes, "
                   "block backend provides %" PRIu64 " bytes",
                   size, blk_len);
        return false;
    }

    /*
     * We could loop for @size > BDRV_REQUEST_MAX_BYTES, but if we
     * ever get to the point we want to read *gigabytes* here, we
     * should probably rework the device to be more like an actual
     * block device and read only on demand.
     */
    assert(size <= BDRV_REQUEST_MAX_BYTES);
    ret = blk_pread(blk, 0, buf, size);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "can't read block backend");
        return false;
    }
    return true;
}

void blkconf_blocksizes(BlockConf *conf)
{
    BlockBackend *blk = conf->blk;
    BlockSizes blocksizes;
    int backend_ret;

    backend_ret = blk_probe_blocksizes(blk, &blocksizes);
    /* fill in detected values if they are not defined via qemu command line */
    if (!conf->physical_block_size) {
        if (!backend_ret) {
           conf->physical_block_size = blocksizes.phys;
        } else {
            conf->physical_block_size = BDRV_SECTOR_SIZE;
        }
    }
    if (!conf->logical_block_size) {
        if (!backend_ret) {
            conf->logical_block_size = blocksizes.log;
        } else {
            conf->logical_block_size = BDRV_SECTOR_SIZE;
        }
    }
}

bool blkconf_apply_backend_options(BlockConf *conf, bool readonly,
                                   bool resizable, Error **errp)
{
    BlockBackend *blk = conf->blk;
    BlockdevOnError rerror, werror;
    uint64_t perm, shared_perm;
    bool wce;
    int ret;

    perm = BLK_PERM_CONSISTENT_READ;
    if (!readonly) {
        perm |= BLK_PERM_WRITE;
    }

    shared_perm = BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE_UNCHANGED |
                  BLK_PERM_GRAPH_MOD;
    if (resizable) {
        shared_perm |= BLK_PERM_RESIZE;
    }
    if (conf->share_rw) {
        shared_perm |= BLK_PERM_WRITE;
    }

    ret = blk_set_perm(blk, perm, shared_perm, errp);
    if (ret < 0) {
        return false;
    }

    switch (conf->wce) {
    case ON_OFF_AUTO_ON:    wce = true; break;
    case ON_OFF_AUTO_OFF:   wce = false; break;
    case ON_OFF_AUTO_AUTO:  wce = blk_enable_write_cache(blk); break;
    default:
        abort();
    }

    rerror = conf->rerror;
    if (rerror == BLOCKDEV_ON_ERROR_AUTO) {
        rerror = blk_get_on_error(blk, true);
    }

    werror = conf->werror;
    if (werror == BLOCKDEV_ON_ERROR_AUTO) {
        werror = blk_get_on_error(blk, false);
    }

    blk_set_enable_write_cache(blk, wce);
    blk_set_on_error(blk, rerror, werror);

    return true;
}

bool blkconf_geometry(BlockConf *conf, int *ptrans,
                      unsigned cyls_max, unsigned heads_max, unsigned secs_max,
                      Error **errp)
{
    if (!conf->cyls && !conf->heads && !conf->secs) {
        hd_geometry_guess(conf->blk,
                          &conf->cyls, &conf->heads, &conf->secs,
                          ptrans);
    } else if (ptrans && *ptrans == BIOS_ATA_TRANSLATION_AUTO) {
        *ptrans = hd_bios_chs_auto_trans(conf->cyls, conf->heads, conf->secs);
    }
    if (conf->cyls || conf->heads || conf->secs) {
        if (conf->cyls < 1 || conf->cyls > cyls_max) {
            error_setg(errp, "cyls must be between 1 and %u", cyls_max);
            return false;
        }
        if (conf->heads < 1 || conf->heads > heads_max) {
            error_setg(errp, "heads must be between 1 and %u", heads_max);
            return false;
        }
        if (conf->secs < 1 || conf->secs > secs_max) {
            error_setg(errp, "secs must be between 1 and %u", secs_max);
            return false;
        }
    }
    return true;
}
