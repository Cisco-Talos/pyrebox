/*
 *  CFI parallel flash with AMD command set emulation
 *
 *  Copyright (c) 2005 Jocelyn Mayer
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
 */

/*
 * For now, this code can emulate flashes of 1, 2 or 4 bytes width.
 * Supported commands/modes are:
 * - flash read
 * - flash write
 * - flash ID read
 * - sector erase
 * - chip erase
 * - unlock bypass command
 * - CFI queries
 *
 * It does not support flash interleaving.
 * It does not implement boot blocs with reduced size
 * It does not implement software data protection as found in many real chips
 * It does not implement erase suspend/resume commands
 * It does not implement multiple sectors erase
 */

#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/block/block.h"
#include "hw/block/flash.h"
#include "qapi/error.h"
#include "qemu/timer.h"
#include "sysemu/block-backend.h"
#include "qemu/host-utils.h"
#include "hw/sysbus.h"
#include "trace.h"

//#define PFLASH_DEBUG
#ifdef PFLASH_DEBUG
#define DPRINTF(fmt, ...)                                  \
do {                                                       \
    fprintf(stderr, "PFLASH: " fmt , ## __VA_ARGS__);       \
} while (0)
#else
#define DPRINTF(fmt, ...) do { } while (0)
#endif

#define PFLASH_LAZY_ROMD_THRESHOLD 42

struct PFlashCFI02 {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    BlockBackend *blk;
    uint32_t sector_len;
    uint32_t nb_blocs;
    uint32_t chip_len;
    uint8_t mappings;
    uint8_t width;
    uint8_t be;
    int wcycle; /* if 0, the flash is read normally */
    int bypass;
    int ro;
    uint8_t cmd;
    uint8_t status;
    /* FIXME: implement array device properties */
    uint16_t ident0;
    uint16_t ident1;
    uint16_t ident2;
    uint16_t ident3;
    uint16_t unlock_addr0;
    uint16_t unlock_addr1;
    uint8_t cfi_table[0x52];
    QEMUTimer timer;
    /* The device replicates the flash memory across its memory space.  Emulate
     * that by having a container (.mem) filled with an array of aliases
     * (.mem_mappings) pointing to the flash memory (.orig_mem).
     */
    MemoryRegion mem;
    MemoryRegion *mem_mappings;    /* array; one per mapping */
    MemoryRegion orig_mem;
    int rom_mode;
    int read_counter; /* used for lazy switch-back to rom mode */
    char *name;
    void *storage;
};

/*
 * Set up replicated mappings of the same region.
 */
static void pflash_setup_mappings(PFlashCFI02 *pfl)
{
    unsigned i;
    hwaddr size = memory_region_size(&pfl->orig_mem);

    memory_region_init(&pfl->mem, OBJECT(pfl), "pflash", pfl->mappings * size);
    pfl->mem_mappings = g_new(MemoryRegion, pfl->mappings);
    for (i = 0; i < pfl->mappings; ++i) {
        memory_region_init_alias(&pfl->mem_mappings[i], OBJECT(pfl),
                                 "pflash-alias", &pfl->orig_mem, 0, size);
        memory_region_add_subregion(&pfl->mem, i * size, &pfl->mem_mappings[i]);
    }
}

static void pflash_register_memory(PFlashCFI02 *pfl, int rom_mode)
{
    memory_region_rom_device_set_romd(&pfl->orig_mem, rom_mode);
    pfl->rom_mode = rom_mode;
}

static void pflash_timer (void *opaque)
{
    PFlashCFI02 *pfl = opaque;

    trace_pflash_timer_expired(pfl->cmd);
    /* Reset flash */
    pfl->status ^= 0x80;
    if (pfl->bypass) {
        pfl->wcycle = 2;
    } else {
        pflash_register_memory(pfl, 1);
        pfl->wcycle = 0;
    }
    pfl->cmd = 0;
}

static uint32_t pflash_read(PFlashCFI02 *pfl, hwaddr offset,
                            int width, int be)
{
    hwaddr boff;
    uint32_t ret;
    uint8_t *p;

    ret = -1;
    trace_pflash_read(offset, pfl->cmd, width, pfl->wcycle);
    /* Lazy reset to ROMD mode after a certain amount of read accesses */
    if (!pfl->rom_mode && pfl->wcycle == 0 &&
        ++pfl->read_counter > PFLASH_LAZY_ROMD_THRESHOLD) {
        pflash_register_memory(pfl, 1);
    }
    offset &= pfl->chip_len - 1;
    boff = offset & 0xFF;
    if (pfl->width == 2)
        boff = boff >> 1;
    else if (pfl->width == 4)
        boff = boff >> 2;
    switch (pfl->cmd) {
    default:
        /* This should never happen : reset state & treat it as a read*/
        DPRINTF("%s: unknown command state: %x\n", __func__, pfl->cmd);
        pfl->wcycle = 0;
        pfl->cmd = 0;
        /* fall through to the read code */
    case 0x80:
        /* We accept reads during second unlock sequence... */
    case 0x00:
    flash_read:
        /* Flash area read */
        p = pfl->storage;
        switch (width) {
        case 1:
            ret = p[offset];
            trace_pflash_data_read8(offset, ret);
            break;
        case 2:
            if (be) {
                ret = p[offset] << 8;
                ret |= p[offset + 1];
            } else {
                ret = p[offset];
                ret |= p[offset + 1] << 8;
            }
            trace_pflash_data_read16(offset, ret);
            break;
        case 4:
            if (be) {
                ret = p[offset] << 24;
                ret |= p[offset + 1] << 16;
                ret |= p[offset + 2] << 8;
                ret |= p[offset + 3];
            } else {
                ret = p[offset];
                ret |= p[offset + 1] << 8;
                ret |= p[offset + 2] << 16;
                ret |= p[offset + 3] << 24;
            }
            trace_pflash_data_read32(offset, ret);
            break;
        }
        break;
    case 0x90:
        /* flash ID read */
        switch (boff) {
        case 0x00:
        case 0x01:
            ret = boff & 0x01 ? pfl->ident1 : pfl->ident0;
            break;
        case 0x02:
            ret = 0x00; /* Pretend all sectors are unprotected */
            break;
        case 0x0E:
        case 0x0F:
            ret = boff & 0x01 ? pfl->ident3 : pfl->ident2;
            if (ret == (uint8_t)-1) {
                goto flash_read;
            }
            break;
        default:
            goto flash_read;
        }
        DPRINTF("%s: ID " TARGET_FMT_plx " %x\n", __func__, boff, ret);
        break;
    case 0xA0:
    case 0x10:
    case 0x30:
        /* Status register read */
        ret = pfl->status;
        DPRINTF("%s: status %x\n", __func__, ret);
        /* Toggle bit 6 */
        pfl->status ^= 0x40;
        break;
    case 0x98:
        /* CFI query mode */
        if (boff < sizeof(pfl->cfi_table)) {
            ret = pfl->cfi_table[boff];
        } else {
            ret = 0;
        }
        break;
    }

    return ret;
}

/* update flash content on disk */
static void pflash_update(PFlashCFI02 *pfl, int offset,
                          int size)
{
    int offset_end;
    if (pfl->blk) {
        offset_end = offset + size;
        /* widen to sector boundaries */
        offset = QEMU_ALIGN_DOWN(offset, BDRV_SECTOR_SIZE);
        offset_end = QEMU_ALIGN_UP(offset_end, BDRV_SECTOR_SIZE);
        blk_pwrite(pfl->blk, offset, pfl->storage + offset,
                   offset_end - offset, 0);
    }
}

static void pflash_write(PFlashCFI02 *pfl, hwaddr offset,
                         uint32_t value, int width, int be)
{
    hwaddr boff;
    uint8_t *p;
    uint8_t cmd;

    cmd = value;
    if (pfl->cmd != 0xA0 && cmd == 0xF0) {
#if 0
        DPRINTF("%s: flash reset asked (%02x %02x)\n",
                __func__, pfl->cmd, cmd);
#endif
        goto reset_flash;
    }
    trace_pflash_write(offset, value, width, pfl->wcycle);
    offset &= pfl->chip_len - 1;

    DPRINTF("%s: offset " TARGET_FMT_plx " %08x %d\n", __func__,
            offset, value, width);
    boff = offset & (pfl->sector_len - 1);
    if (pfl->width == 2)
        boff = boff >> 1;
    else if (pfl->width == 4)
        boff = boff >> 2;
    switch (pfl->wcycle) {
    case 0:
        /* Set the device in I/O access mode if required */
        if (pfl->rom_mode)
            pflash_register_memory(pfl, 0);
        pfl->read_counter = 0;
        /* We're in read mode */
    check_unlock0:
        if (boff == 0x55 && cmd == 0x98) {
        enter_CFI_mode:
            /* Enter CFI query mode */
            pfl->wcycle = 7;
            pfl->cmd = 0x98;
            return;
        }
        if (boff != pfl->unlock_addr0 || cmd != 0xAA) {
            DPRINTF("%s: unlock0 failed " TARGET_FMT_plx " %02x %04x\n",
                    __func__, boff, cmd, pfl->unlock_addr0);
            goto reset_flash;
        }
        DPRINTF("%s: unlock sequence started\n", __func__);
        break;
    case 1:
        /* We started an unlock sequence */
    check_unlock1:
        if (boff != pfl->unlock_addr1 || cmd != 0x55) {
            DPRINTF("%s: unlock1 failed " TARGET_FMT_plx " %02x\n", __func__,
                    boff, cmd);
            goto reset_flash;
        }
        DPRINTF("%s: unlock sequence done\n", __func__);
        break;
    case 2:
        /* We finished an unlock sequence */
        if (!pfl->bypass && boff != pfl->unlock_addr0) {
            DPRINTF("%s: command failed " TARGET_FMT_plx " %02x\n", __func__,
                    boff, cmd);
            goto reset_flash;
        }
        switch (cmd) {
        case 0x20:
            pfl->bypass = 1;
            goto do_bypass;
        case 0x80:
        case 0x90:
        case 0xA0:
            pfl->cmd = cmd;
            DPRINTF("%s: starting command %02x\n", __func__, cmd);
            break;
        default:
            DPRINTF("%s: unknown command %02x\n", __func__, cmd);
            goto reset_flash;
        }
        break;
    case 3:
        switch (pfl->cmd) {
        case 0x80:
            /* We need another unlock sequence */
            goto check_unlock0;
        case 0xA0:
            trace_pflash_data_write(offset, value, width, 0);
            p = pfl->storage;
            if (!pfl->ro) {
                switch (width) {
                case 1:
                    p[offset] &= value;
                    pflash_update(pfl, offset, 1);
                    break;
                case 2:
                    if (be) {
                        p[offset] &= value >> 8;
                        p[offset + 1] &= value;
                    } else {
                        p[offset] &= value;
                        p[offset + 1] &= value >> 8;
                    }
                    pflash_update(pfl, offset, 2);
                    break;
                case 4:
                    if (be) {
                        p[offset] &= value >> 24;
                        p[offset + 1] &= value >> 16;
                        p[offset + 2] &= value >> 8;
                        p[offset + 3] &= value;
                    } else {
                        p[offset] &= value;
                        p[offset + 1] &= value >> 8;
                        p[offset + 2] &= value >> 16;
                        p[offset + 3] &= value >> 24;
                    }
                    pflash_update(pfl, offset, 4);
                    break;
                }
            }
            pfl->status = 0x00 | ~(value & 0x80);
            /* Let's pretend write is immediate */
            if (pfl->bypass)
                goto do_bypass;
            goto reset_flash;
        case 0x90:
            if (pfl->bypass && cmd == 0x00) {
                /* Unlock bypass reset */
                goto reset_flash;
            }
            /* We can enter CFI query mode from autoselect mode */
            if (boff == 0x55 && cmd == 0x98)
                goto enter_CFI_mode;
            /* No break here */
        default:
            DPRINTF("%s: invalid write for command %02x\n",
                    __func__, pfl->cmd);
            goto reset_flash;
        }
    case 4:
        switch (pfl->cmd) {
        case 0xA0:
            /* Ignore writes while flash data write is occurring */
            /* As we suppose write is immediate, this should never happen */
            return;
        case 0x80:
            goto check_unlock1;
        default:
            /* Should never happen */
            DPRINTF("%s: invalid command state %02x (wc 4)\n",
                    __func__, pfl->cmd);
            goto reset_flash;
        }
        break;
    case 5:
        switch (cmd) {
        case 0x10:
            if (boff != pfl->unlock_addr0) {
                DPRINTF("%s: chip erase: invalid address " TARGET_FMT_plx "\n",
                        __func__, offset);
                goto reset_flash;
            }
            /* Chip erase */
            DPRINTF("%s: start chip erase\n", __func__);
            if (!pfl->ro) {
                memset(pfl->storage, 0xFF, pfl->chip_len);
                pflash_update(pfl, 0, pfl->chip_len);
            }
            pfl->status = 0x00;
            /* Let's wait 5 seconds before chip erase is done */
            timer_mod(&pfl->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      (NANOSECONDS_PER_SECOND * 5));
            break;
        case 0x30:
            /* Sector erase */
            p = pfl->storage;
            offset &= ~(pfl->sector_len - 1);
            DPRINTF("%s: start sector erase at " TARGET_FMT_plx "\n", __func__,
                    offset);
            if (!pfl->ro) {
                memset(p + offset, 0xFF, pfl->sector_len);
                pflash_update(pfl, offset, pfl->sector_len);
            }
            pfl->status = 0x00;
            /* Let's wait 1/2 second before sector erase is done */
            timer_mod(&pfl->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      (NANOSECONDS_PER_SECOND / 2));
            break;
        default:
            DPRINTF("%s: invalid command %02x (wc 5)\n", __func__, cmd);
            goto reset_flash;
        }
        pfl->cmd = cmd;
        break;
    case 6:
        switch (pfl->cmd) {
        case 0x10:
            /* Ignore writes during chip erase */
            return;
        case 0x30:
            /* Ignore writes during sector erase */
            return;
        default:
            /* Should never happen */
            DPRINTF("%s: invalid command state %02x (wc 6)\n",
                    __func__, pfl->cmd);
            goto reset_flash;
        }
        break;
    case 7: /* Special value for CFI queries */
        DPRINTF("%s: invalid write in CFI query mode\n", __func__);
        goto reset_flash;
    default:
        /* Should never happen */
        DPRINTF("%s: invalid write state (wc 7)\n",  __func__);
        goto reset_flash;
    }
    pfl->wcycle++;

    return;

    /* Reset flash */
 reset_flash:
    trace_pflash_reset();
    pfl->bypass = 0;
    pfl->wcycle = 0;
    pfl->cmd = 0;
    return;

 do_bypass:
    pfl->wcycle = 2;
    pfl->cmd = 0;
}

static uint64_t pflash_be_readfn(void *opaque, hwaddr addr, unsigned size)
{
    return pflash_read(opaque, addr, size, 1);
}

static void pflash_be_writefn(void *opaque, hwaddr addr,
                              uint64_t value, unsigned size)
{
    pflash_write(opaque, addr, value, size, 1);
}

static uint64_t pflash_le_readfn(void *opaque, hwaddr addr, unsigned size)
{
    return pflash_read(opaque, addr, size, 0);
}

static void pflash_le_writefn(void *opaque, hwaddr addr,
                              uint64_t value, unsigned size)
{
    pflash_write(opaque, addr, value, size, 0);
}

static const MemoryRegionOps pflash_cfi02_ops_be = {
    .read = pflash_be_readfn,
    .write = pflash_be_writefn,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const MemoryRegionOps pflash_cfi02_ops_le = {
    .read = pflash_le_readfn,
    .write = pflash_le_writefn,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void pflash_cfi02_realize(DeviceState *dev, Error **errp)
{
    PFlashCFI02 *pfl = PFLASH_CFI02(dev);
    uint32_t chip_len;
    int ret;
    Error *local_err = NULL;

    if (pfl->sector_len == 0) {
        error_setg(errp, "attribute \"sector-length\" not specified or zero.");
        return;
    }
    if (pfl->nb_blocs == 0) {
        error_setg(errp, "attribute \"num-blocks\" not specified or zero.");
        return;
    }
    if (pfl->name == NULL) {
        error_setg(errp, "attribute \"name\" not specified.");
        return;
    }

    chip_len = pfl->sector_len * pfl->nb_blocs;

    memory_region_init_rom_device(&pfl->orig_mem, OBJECT(pfl), pfl->be ?
                                  &pflash_cfi02_ops_be : &pflash_cfi02_ops_le,
                                  pfl, pfl->name, chip_len, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    pfl->storage = memory_region_get_ram_ptr(&pfl->orig_mem);
    pfl->chip_len = chip_len;

    if (pfl->blk) {
        uint64_t perm;
        pfl->ro = blk_is_read_only(pfl->blk);
        perm = BLK_PERM_CONSISTENT_READ | (pfl->ro ? 0 : BLK_PERM_WRITE);
        ret = blk_set_perm(pfl->blk, perm, BLK_PERM_ALL, errp);
        if (ret < 0) {
            return;
        }
    } else {
        pfl->ro = 0;
    }

    if (pfl->blk) {
        if (!blk_check_size_and_read_all(pfl->blk, pfl->storage, chip_len,
                                         errp)) {
            vmstate_unregister_ram(&pfl->orig_mem, DEVICE(pfl));
            return;
        }
    }

    pflash_setup_mappings(pfl);
    pfl->rom_mode = 1;
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &pfl->mem);

    timer_init_ns(&pfl->timer, QEMU_CLOCK_VIRTUAL, pflash_timer, pfl);
    pfl->wcycle = 0;
    pfl->cmd = 0;
    pfl->status = 0;
    /* Hardcoded CFI table (mostly from SG29 Spansion flash) */
    /* Standard "QRY" string */
    pfl->cfi_table[0x10] = 'Q';
    pfl->cfi_table[0x11] = 'R';
    pfl->cfi_table[0x12] = 'Y';
    /* Command set (AMD/Fujitsu) */
    pfl->cfi_table[0x13] = 0x02;
    pfl->cfi_table[0x14] = 0x00;
    /* Primary extended table address */
    pfl->cfi_table[0x15] = 0x31;
    pfl->cfi_table[0x16] = 0x00;
    /* Alternate command set (none) */
    pfl->cfi_table[0x17] = 0x00;
    pfl->cfi_table[0x18] = 0x00;
    /* Alternate extended table (none) */
    pfl->cfi_table[0x19] = 0x00;
    pfl->cfi_table[0x1A] = 0x00;
    /* Vcc min */
    pfl->cfi_table[0x1B] = 0x27;
    /* Vcc max */
    pfl->cfi_table[0x1C] = 0x36;
    /* Vpp min (no Vpp pin) */
    pfl->cfi_table[0x1D] = 0x00;
    /* Vpp max (no Vpp pin) */
    pfl->cfi_table[0x1E] = 0x00;
    /* Reserved */
    pfl->cfi_table[0x1F] = 0x07;
    /* Timeout for min size buffer write (NA) */
    pfl->cfi_table[0x20] = 0x00;
    /* Typical timeout for block erase (512 ms) */
    pfl->cfi_table[0x21] = 0x09;
    /* Typical timeout for full chip erase (4096 ms) */
    pfl->cfi_table[0x22] = 0x0C;
    /* Reserved */
    pfl->cfi_table[0x23] = 0x01;
    /* Max timeout for buffer write (NA) */
    pfl->cfi_table[0x24] = 0x00;
    /* Max timeout for block erase */
    pfl->cfi_table[0x25] = 0x0A;
    /* Max timeout for chip erase */
    pfl->cfi_table[0x26] = 0x0D;
    /* Device size */
    pfl->cfi_table[0x27] = ctz32(chip_len);
    /* Flash device interface (8 & 16 bits) */
    pfl->cfi_table[0x28] = 0x02;
    pfl->cfi_table[0x29] = 0x00;
    /* Max number of bytes in multi-bytes write */
    /* XXX: disable buffered write as it's not supported */
    //    pfl->cfi_table[0x2A] = 0x05;
    pfl->cfi_table[0x2A] = 0x00;
    pfl->cfi_table[0x2B] = 0x00;
    /* Number of erase block regions (uniform) */
    pfl->cfi_table[0x2C] = 0x01;
    /* Erase block region 1 */
    pfl->cfi_table[0x2D] = pfl->nb_blocs - 1;
    pfl->cfi_table[0x2E] = (pfl->nb_blocs - 1) >> 8;
    pfl->cfi_table[0x2F] = pfl->sector_len >> 8;
    pfl->cfi_table[0x30] = pfl->sector_len >> 16;

    /* Extended */
    pfl->cfi_table[0x31] = 'P';
    pfl->cfi_table[0x32] = 'R';
    pfl->cfi_table[0x33] = 'I';

    pfl->cfi_table[0x34] = '1';
    pfl->cfi_table[0x35] = '0';

    pfl->cfi_table[0x36] = 0x00;
    pfl->cfi_table[0x37] = 0x00;
    pfl->cfi_table[0x38] = 0x00;
    pfl->cfi_table[0x39] = 0x00;

    pfl->cfi_table[0x3a] = 0x00;

    pfl->cfi_table[0x3b] = 0x00;
    pfl->cfi_table[0x3c] = 0x00;
}

static Property pflash_cfi02_properties[] = {
    DEFINE_PROP_DRIVE("drive", PFlashCFI02, blk),
    DEFINE_PROP_UINT32("num-blocks", PFlashCFI02, nb_blocs, 0),
    DEFINE_PROP_UINT32("sector-length", PFlashCFI02, sector_len, 0),
    DEFINE_PROP_UINT8("width", PFlashCFI02, width, 0),
    DEFINE_PROP_UINT8("mappings", PFlashCFI02, mappings, 0),
    DEFINE_PROP_UINT8("big-endian", PFlashCFI02, be, 0),
    DEFINE_PROP_UINT16("id0", PFlashCFI02, ident0, 0),
    DEFINE_PROP_UINT16("id1", PFlashCFI02, ident1, 0),
    DEFINE_PROP_UINT16("id2", PFlashCFI02, ident2, 0),
    DEFINE_PROP_UINT16("id3", PFlashCFI02, ident3, 0),
    DEFINE_PROP_UINT16("unlock-addr0", PFlashCFI02, unlock_addr0, 0),
    DEFINE_PROP_UINT16("unlock-addr1", PFlashCFI02, unlock_addr1, 0),
    DEFINE_PROP_STRING("name", PFlashCFI02, name),
    DEFINE_PROP_END_OF_LIST(),
};

static void pflash_cfi02_unrealize(DeviceState *dev, Error **errp)
{
    PFlashCFI02 *pfl = PFLASH_CFI02(dev);
    timer_del(&pfl->timer);
}

static void pflash_cfi02_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = pflash_cfi02_realize;
    dc->unrealize = pflash_cfi02_unrealize;
    dc->props = pflash_cfi02_properties;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
}

static const TypeInfo pflash_cfi02_info = {
    .name           = TYPE_PFLASH_CFI02,
    .parent         = TYPE_SYS_BUS_DEVICE,
    .instance_size  = sizeof(PFlashCFI02),
    .class_init     = pflash_cfi02_class_init,
};

static void pflash_cfi02_register_types(void)
{
    type_register_static(&pflash_cfi02_info);
}

type_init(pflash_cfi02_register_types)

PFlashCFI02 *pflash_cfi02_register(hwaddr base,
                                   const char *name,
                                   hwaddr size,
                                   BlockBackend *blk,
                                   uint32_t sector_len,
                                   int nb_mappings, int width,
                                   uint16_t id0, uint16_t id1,
                                   uint16_t id2, uint16_t id3,
                                   uint16_t unlock_addr0,
                                   uint16_t unlock_addr1,
                                   int be)
{
    DeviceState *dev = qdev_create(NULL, TYPE_PFLASH_CFI02);

    if (blk) {
        qdev_prop_set_drive(dev, "drive", blk, &error_abort);
    }
    assert(size % sector_len == 0);
    qdev_prop_set_uint32(dev, "num-blocks", size / sector_len);
    qdev_prop_set_uint32(dev, "sector-length", sector_len);
    qdev_prop_set_uint8(dev, "width", width);
    qdev_prop_set_uint8(dev, "mappings", nb_mappings);
    qdev_prop_set_uint8(dev, "big-endian", !!be);
    qdev_prop_set_uint16(dev, "id0", id0);
    qdev_prop_set_uint16(dev, "id1", id1);
    qdev_prop_set_uint16(dev, "id2", id2);
    qdev_prop_set_uint16(dev, "id3", id3);
    qdev_prop_set_uint16(dev, "unlock-addr0", unlock_addr0);
    qdev_prop_set_uint16(dev, "unlock-addr1", unlock_addr1);
    qdev_prop_set_string(dev, "name", name);
    qdev_init_nofail(dev);

    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, base);
    return PFLASH_CFI02(dev);
}
