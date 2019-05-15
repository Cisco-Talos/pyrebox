/*
 * QEMU Executable loader
 *
 * Copyright (c) 2006 Fabrice Bellard
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
 *
 * Gunzip functionality in this file is derived from u-boot:
 *
 * (C) Copyright 2008 Semihalf
 *
 * (C) Copyright 2000-2005
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "disas/disas.h"
#include "monitor/monitor.h"
#include "sysemu/sysemu.h"
#include "uboot_image.h"
#include "hw/loader.h"
#include "hw/nvram/fw_cfg.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "hw/boards.h"
#include "qemu/cutils.h"

#include <zlib.h>

static int roms_loaded;

/* return the size or -1 if error */
int64_t get_image_size(const char *filename)
{
    int fd;
    int64_t size;
    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        return -1;
    size = lseek(fd, 0, SEEK_END);
    close(fd);
    return size;
}

/* return the size or -1 if error */
ssize_t load_image_size(const char *filename, void *addr, size_t size)
{
    int fd;
    ssize_t actsize, l = 0;

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        return -1;
    }

    while ((actsize = read(fd, addr + l, size - l)) > 0) {
        l += actsize;
    }

    close(fd);

    return actsize < 0 ? -1 : l;
}

/* read()-like version */
ssize_t read_targphys(const char *name,
                      int fd, hwaddr dst_addr, size_t nbytes)
{
    uint8_t *buf;
    ssize_t did;

    buf = g_malloc(nbytes);
    did = read(fd, buf, nbytes);
    if (did > 0)
        rom_add_blob_fixed("read", buf, did, dst_addr);
    g_free(buf);
    return did;
}

int load_image_targphys(const char *filename,
                        hwaddr addr, uint64_t max_sz)
{
    return load_image_targphys_as(filename, addr, max_sz, NULL);
}

/* return the size or -1 if error */
int load_image_targphys_as(const char *filename,
                           hwaddr addr, uint64_t max_sz, AddressSpace *as)
{
    int size;

    size = get_image_size(filename);
    if (size < 0 || size > max_sz) {
        return -1;
    }
    if (size > 0) {
        if (rom_add_file_fixed_as(filename, addr, -1, as) < 0) {
            return -1;
        }
    }
    return size;
}

int load_image_mr(const char *filename, MemoryRegion *mr)
{
    int size;

    if (!memory_access_is_direct(mr, false)) {
        /* Can only load an image into RAM or ROM */
        return -1;
    }

    size = get_image_size(filename);

    if (size < 0 || size > memory_region_size(mr)) {
        return -1;
    }
    if (size > 0) {
        if (rom_add_file_mr(filename, mr, -1) < 0) {
            return -1;
        }
    }
    return size;
}

void pstrcpy_targphys(const char *name, hwaddr dest, int buf_size,
                      const char *source)
{
    const char *nulp;
    char *ptr;

    if (buf_size <= 0) return;
    nulp = memchr(source, 0, buf_size);
    if (nulp) {
        rom_add_blob_fixed(name, source, (nulp - source) + 1, dest);
    } else {
        rom_add_blob_fixed(name, source, buf_size, dest);
        ptr = rom_ptr(dest + buf_size - 1, sizeof(*ptr));
        *ptr = 0;
    }
}

/* A.OUT loader */

struct exec
{
  uint32_t a_info;   /* Use macros N_MAGIC, etc for access */
  uint32_t a_text;   /* length of text, in bytes */
  uint32_t a_data;   /* length of data, in bytes */
  uint32_t a_bss;    /* length of uninitialized data area, in bytes */
  uint32_t a_syms;   /* length of symbol table data in file, in bytes */
  uint32_t a_entry;  /* start address */
  uint32_t a_trsize; /* length of relocation info for text, in bytes */
  uint32_t a_drsize; /* length of relocation info for data, in bytes */
};

static void bswap_ahdr(struct exec *e)
{
    bswap32s(&e->a_info);
    bswap32s(&e->a_text);
    bswap32s(&e->a_data);
    bswap32s(&e->a_bss);
    bswap32s(&e->a_syms);
    bswap32s(&e->a_entry);
    bswap32s(&e->a_trsize);
    bswap32s(&e->a_drsize);
}

#define N_MAGIC(exec) ((exec).a_info & 0xffff)
#define OMAGIC 0407
#define NMAGIC 0410
#define ZMAGIC 0413
#define QMAGIC 0314
#define _N_HDROFF(x) (1024 - sizeof (struct exec))
#define N_TXTOFF(x)							\
    (N_MAGIC(x) == ZMAGIC ? _N_HDROFF((x)) + sizeof (struct exec) :	\
     (N_MAGIC(x) == QMAGIC ? 0 : sizeof (struct exec)))
#define N_TXTADDR(x, target_page_size) (N_MAGIC(x) == QMAGIC ? target_page_size : 0)
#define _N_SEGMENT_ROUND(x, target_page_size) (((x) + target_page_size - 1) & ~(target_page_size - 1))

#define _N_TXTENDADDR(x, target_page_size) (N_TXTADDR(x, target_page_size)+(x).a_text)

#define N_DATADDR(x, target_page_size) \
    (N_MAGIC(x)==OMAGIC? (_N_TXTENDADDR(x, target_page_size)) \
     : (_N_SEGMENT_ROUND (_N_TXTENDADDR(x, target_page_size), target_page_size)))


int load_aout(const char *filename, hwaddr addr, int max_sz,
              int bswap_needed, hwaddr target_page_size)
{
    int fd;
    ssize_t size, ret;
    struct exec e;
    uint32_t magic;

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        return -1;

    size = read(fd, &e, sizeof(e));
    if (size < 0)
        goto fail;

    if (bswap_needed) {
        bswap_ahdr(&e);
    }

    magic = N_MAGIC(e);
    switch (magic) {
    case ZMAGIC:
    case QMAGIC:
    case OMAGIC:
        if (e.a_text + e.a_data > max_sz)
            goto fail;
        lseek(fd, N_TXTOFF(e), SEEK_SET);
        size = read_targphys(filename, fd, addr, e.a_text + e.a_data);
        if (size < 0)
            goto fail;
        break;
    case NMAGIC:
        if (N_DATADDR(e, target_page_size) + e.a_data > max_sz)
            goto fail;
        lseek(fd, N_TXTOFF(e), SEEK_SET);
        size = read_targphys(filename, fd, addr, e.a_text);
        if (size < 0)
            goto fail;
        ret = read_targphys(filename, fd, addr + N_DATADDR(e, target_page_size),
                            e.a_data);
        if (ret < 0)
            goto fail;
        size += ret;
        break;
    default:
        goto fail;
    }
    close(fd);
    return size;
 fail:
    close(fd);
    return -1;
}

/* ELF loader */

static void *load_at(int fd, off_t offset, size_t size)
{
    void *ptr;
    if (lseek(fd, offset, SEEK_SET) < 0)
        return NULL;
    ptr = g_malloc(size);
    if (read(fd, ptr, size) != size) {
        g_free(ptr);
        return NULL;
    }
    return ptr;
}

#ifdef ELF_CLASS
#undef ELF_CLASS
#endif

#define ELF_CLASS   ELFCLASS32
#include "elf.h"

#define SZ		32
#define elf_word        uint32_t
#define elf_sword        int32_t
#define bswapSZs	bswap32s
#include "hw/elf_ops.h"

#undef elfhdr
#undef elf_phdr
#undef elf_shdr
#undef elf_sym
#undef elf_rela
#undef elf_note
#undef elf_word
#undef elf_sword
#undef bswapSZs
#undef SZ
#define elfhdr		elf64_hdr
#define elf_phdr	elf64_phdr
#define elf_note	elf64_note
#define elf_shdr	elf64_shdr
#define elf_sym		elf64_sym
#define elf_rela        elf64_rela
#define elf_word        uint64_t
#define elf_sword        int64_t
#define bswapSZs	bswap64s
#define SZ		64
#include "hw/elf_ops.h"

const char *load_elf_strerror(int error)
{
    switch (error) {
    case 0:
        return "No error";
    case ELF_LOAD_FAILED:
        return "Failed to load ELF";
    case ELF_LOAD_NOT_ELF:
        return "The image is not ELF";
    case ELF_LOAD_WRONG_ARCH:
        return "The image is from incompatible architecture";
    case ELF_LOAD_WRONG_ENDIAN:
        return "The image has incorrect endianness";
    default:
        return "Unknown error";
    }
}

void load_elf_hdr(const char *filename, void *hdr, bool *is64, Error **errp)
{
    int fd;
    uint8_t e_ident_local[EI_NIDENT];
    uint8_t *e_ident;
    size_t hdr_size, off;
    bool is64l;

    if (!hdr) {
        hdr = e_ident_local;
    }
    e_ident = hdr;

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        error_setg_errno(errp, errno, "Failed to open file: %s", filename);
        return;
    }
    if (read(fd, hdr, EI_NIDENT) != EI_NIDENT) {
        error_setg_errno(errp, errno, "Failed to read file: %s", filename);
        goto fail;
    }
    if (e_ident[0] != ELFMAG0 ||
        e_ident[1] != ELFMAG1 ||
        e_ident[2] != ELFMAG2 ||
        e_ident[3] != ELFMAG3) {
        error_setg(errp, "Bad ELF magic");
        goto fail;
    }

    is64l = e_ident[EI_CLASS] == ELFCLASS64;
    hdr_size = is64l ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
    if (is64) {
        *is64 = is64l;
    }

    off = EI_NIDENT;
    while (hdr != e_ident_local && off < hdr_size) {
        size_t br = read(fd, hdr + off, hdr_size - off);
        switch (br) {
        case 0:
            error_setg(errp, "File too short: %s", filename);
            goto fail;
        case -1:
            error_setg_errno(errp, errno, "Failed to read file: %s",
                             filename);
            goto fail;
        }
        off += br;
    }

fail:
    close(fd);
}

/* return < 0 if error, otherwise the number of bytes loaded in memory */
int load_elf(const char *filename,
             uint64_t (*elf_note_fn)(void *, void *, bool),
             uint64_t (*translate_fn)(void *, uint64_t),
             void *translate_opaque, uint64_t *pentry, uint64_t *lowaddr,
             uint64_t *highaddr, int big_endian, int elf_machine,
             int clear_lsb, int data_swab)
{
    return load_elf_as(filename, elf_note_fn, translate_fn, translate_opaque,
                       pentry, lowaddr, highaddr, big_endian, elf_machine,
                       clear_lsb, data_swab, NULL);
}

/* return < 0 if error, otherwise the number of bytes loaded in memory */
int load_elf_as(const char *filename,
                uint64_t (*elf_note_fn)(void *, void *, bool),
                uint64_t (*translate_fn)(void *, uint64_t),
                void *translate_opaque, uint64_t *pentry, uint64_t *lowaddr,
                uint64_t *highaddr, int big_endian, int elf_machine,
                int clear_lsb, int data_swab, AddressSpace *as)
{
    return load_elf_ram(filename, elf_note_fn, translate_fn, translate_opaque,
                        pentry, lowaddr, highaddr, big_endian, elf_machine,
                        clear_lsb, data_swab, as, true);
}

/* return < 0 if error, otherwise the number of bytes loaded in memory */
int load_elf_ram(const char *filename,
                 uint64_t (*elf_note_fn)(void *, void *, bool),
                 uint64_t (*translate_fn)(void *, uint64_t),
                 void *translate_opaque, uint64_t *pentry, uint64_t *lowaddr,
                 uint64_t *highaddr, int big_endian, int elf_machine,
                 int clear_lsb, int data_swab, AddressSpace *as,
                 bool load_rom)
{
    return load_elf_ram_sym(filename, elf_note_fn,
                            translate_fn, translate_opaque,
                            pentry, lowaddr, highaddr, big_endian,
                            elf_machine, clear_lsb, data_swab, as,
                            load_rom, NULL);
}

/* return < 0 if error, otherwise the number of bytes loaded in memory */
int load_elf_ram_sym(const char *filename,
                     uint64_t (*elf_note_fn)(void *, void *, bool),
                     uint64_t (*translate_fn)(void *, uint64_t),
                     void *translate_opaque, uint64_t *pentry,
                     uint64_t *lowaddr, uint64_t *highaddr, int big_endian,
                     int elf_machine, int clear_lsb, int data_swab,
                     AddressSpace *as, bool load_rom, symbol_fn_t sym_cb)
{
    int fd, data_order, target_data_order, must_swab, ret = ELF_LOAD_FAILED;
    uint8_t e_ident[EI_NIDENT];

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        perror(filename);
        return -1;
    }
    if (read(fd, e_ident, sizeof(e_ident)) != sizeof(e_ident))
        goto fail;
    if (e_ident[0] != ELFMAG0 ||
        e_ident[1] != ELFMAG1 ||
        e_ident[2] != ELFMAG2 ||
        e_ident[3] != ELFMAG3) {
        ret = ELF_LOAD_NOT_ELF;
        goto fail;
    }
#ifdef HOST_WORDS_BIGENDIAN
    data_order = ELFDATA2MSB;
#else
    data_order = ELFDATA2LSB;
#endif
    must_swab = data_order != e_ident[EI_DATA];
    if (big_endian) {
        target_data_order = ELFDATA2MSB;
    } else {
        target_data_order = ELFDATA2LSB;
    }

    if (target_data_order != e_ident[EI_DATA]) {
        ret = ELF_LOAD_WRONG_ENDIAN;
        goto fail;
    }

    lseek(fd, 0, SEEK_SET);
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        ret = load_elf64(filename, fd, elf_note_fn,
                         translate_fn, translate_opaque, must_swab,
                         pentry, lowaddr, highaddr, elf_machine, clear_lsb,
                         data_swab, as, load_rom, sym_cb);
    } else {
        ret = load_elf32(filename, fd, elf_note_fn,
                         translate_fn, translate_opaque, must_swab,
                         pentry, lowaddr, highaddr, elf_machine, clear_lsb,
                         data_swab, as, load_rom, sym_cb);
    }

 fail:
    close(fd);
    return ret;
}

static void bswap_uboot_header(uboot_image_header_t *hdr)
{
#ifndef HOST_WORDS_BIGENDIAN
    bswap32s(&hdr->ih_magic);
    bswap32s(&hdr->ih_hcrc);
    bswap32s(&hdr->ih_time);
    bswap32s(&hdr->ih_size);
    bswap32s(&hdr->ih_load);
    bswap32s(&hdr->ih_ep);
    bswap32s(&hdr->ih_dcrc);
#endif
}


#define ZALLOC_ALIGNMENT	16

static void *zalloc(void *x, unsigned items, unsigned size)
{
    void *p;

    size *= items;
    size = (size + ZALLOC_ALIGNMENT - 1) & ~(ZALLOC_ALIGNMENT - 1);

    p = g_malloc(size);

    return (p);
}

static void zfree(void *x, void *addr)
{
    g_free(addr);
}


#define HEAD_CRC	2
#define EXTRA_FIELD	4
#define ORIG_NAME	8
#define COMMENT		0x10
#define RESERVED	0xe0

#define DEFLATED	8

ssize_t gunzip(void *dst, size_t dstlen, uint8_t *src, size_t srclen)
{
    z_stream s;
    ssize_t dstbytes;
    int r, i, flags;

    /* skip header */
    i = 10;
    flags = src[3];
    if (src[2] != DEFLATED || (flags & RESERVED) != 0) {
        puts ("Error: Bad gzipped data\n");
        return -1;
    }
    if ((flags & EXTRA_FIELD) != 0)
        i = 12 + src[10] + (src[11] << 8);
    if ((flags & ORIG_NAME) != 0)
        while (src[i++] != 0)
            ;
    if ((flags & COMMENT) != 0)
        while (src[i++] != 0)
            ;
    if ((flags & HEAD_CRC) != 0)
        i += 2;
    if (i >= srclen) {
        puts ("Error: gunzip out of data in header\n");
        return -1;
    }

    s.zalloc = zalloc;
    s.zfree = zfree;

    r = inflateInit2(&s, -MAX_WBITS);
    if (r != Z_OK) {
        printf ("Error: inflateInit2() returned %d\n", r);
        return (-1);
    }
    s.next_in = src + i;
    s.avail_in = srclen - i;
    s.next_out = dst;
    s.avail_out = dstlen;
    r = inflate(&s, Z_FINISH);
    if (r != Z_OK && r != Z_STREAM_END) {
        printf ("Error: inflate() returned %d\n", r);
        return -1;
    }
    dstbytes = s.next_out - (unsigned char *) dst;
    inflateEnd(&s);

    return dstbytes;
}

/* Load a U-Boot image.  */
static int load_uboot_image(const char *filename, hwaddr *ep, hwaddr *loadaddr,
                            int *is_linux, uint8_t image_type,
                            uint64_t (*translate_fn)(void *, uint64_t),
                            void *translate_opaque, AddressSpace *as)
{
    int fd;
    int size;
    hwaddr address;
    uboot_image_header_t h;
    uboot_image_header_t *hdr = &h;
    uint8_t *data = NULL;
    int ret = -1;
    int do_uncompress = 0;

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        return -1;

    size = read(fd, hdr, sizeof(uboot_image_header_t));
    if (size < sizeof(uboot_image_header_t)) {
        goto out;
    }

    bswap_uboot_header(hdr);

    if (hdr->ih_magic != IH_MAGIC)
        goto out;

    if (hdr->ih_type != image_type) {
        if (!(image_type == IH_TYPE_KERNEL &&
            hdr->ih_type == IH_TYPE_KERNEL_NOLOAD)) {
            fprintf(stderr, "Wrong image type %d, expected %d\n", hdr->ih_type,
                    image_type);
            goto out;
        }
    }

    /* TODO: Implement other image types.  */
    switch (hdr->ih_type) {
    case IH_TYPE_KERNEL_NOLOAD:
        if (!loadaddr || *loadaddr == LOAD_UIMAGE_LOADADDR_INVALID) {
            fprintf(stderr, "this image format (kernel_noload) cannot be "
                    "loaded on this machine type");
            goto out;
        }

        hdr->ih_load = *loadaddr + sizeof(*hdr);
        hdr->ih_ep += hdr->ih_load;
        /* fall through */
    case IH_TYPE_KERNEL:
        address = hdr->ih_load;
        if (translate_fn) {
            address = translate_fn(translate_opaque, address);
        }
        if (loadaddr) {
            *loadaddr = hdr->ih_load;
        }

        switch (hdr->ih_comp) {
        case IH_COMP_NONE:
            break;
        case IH_COMP_GZIP:
            do_uncompress = 1;
            break;
        default:
            fprintf(stderr,
                    "Unable to load u-boot images with compression type %d\n",
                    hdr->ih_comp);
            goto out;
        }

        if (ep) {
            *ep = hdr->ih_ep;
        }

        /* TODO: Check CPU type.  */
        if (is_linux) {
            if (hdr->ih_os == IH_OS_LINUX) {
                *is_linux = 1;
            } else {
                *is_linux = 0;
            }
        }

        break;
    case IH_TYPE_RAMDISK:
        address = *loadaddr;
        break;
    default:
        fprintf(stderr, "Unsupported u-boot image type %d\n", hdr->ih_type);
        goto out;
    }

    data = g_malloc(hdr->ih_size);

    if (read(fd, data, hdr->ih_size) != hdr->ih_size) {
        fprintf(stderr, "Error reading file\n");
        goto out;
    }

    if (do_uncompress) {
        uint8_t *compressed_data;
        size_t max_bytes;
        ssize_t bytes;

        compressed_data = data;
        max_bytes = UBOOT_MAX_GUNZIP_BYTES;
        data = g_malloc(max_bytes);

        bytes = gunzip(data, max_bytes, compressed_data, hdr->ih_size);
        g_free(compressed_data);
        if (bytes < 0) {
            fprintf(stderr, "Unable to decompress gzipped image!\n");
            goto out;
        }
        hdr->ih_size = bytes;
    }

    rom_add_blob_fixed_as(filename, data, hdr->ih_size, address, as);

    ret = hdr->ih_size;

out:
    g_free(data);
    close(fd);
    return ret;
}

int load_uimage(const char *filename, hwaddr *ep, hwaddr *loadaddr,
                int *is_linux,
                uint64_t (*translate_fn)(void *, uint64_t),
                void *translate_opaque)
{
    return load_uboot_image(filename, ep, loadaddr, is_linux, IH_TYPE_KERNEL,
                            translate_fn, translate_opaque, NULL);
}

int load_uimage_as(const char *filename, hwaddr *ep, hwaddr *loadaddr,
                   int *is_linux,
                   uint64_t (*translate_fn)(void *, uint64_t),
                   void *translate_opaque, AddressSpace *as)
{
    return load_uboot_image(filename, ep, loadaddr, is_linux, IH_TYPE_KERNEL,
                            translate_fn, translate_opaque, as);
}

/* Load a ramdisk.  */
int load_ramdisk(const char *filename, hwaddr addr, uint64_t max_sz)
{
    return load_ramdisk_as(filename, addr, max_sz, NULL);
}

int load_ramdisk_as(const char *filename, hwaddr addr, uint64_t max_sz,
                    AddressSpace *as)
{
    return load_uboot_image(filename, NULL, &addr, NULL, IH_TYPE_RAMDISK,
                            NULL, NULL, as);
}

/* Load a gzip-compressed kernel to a dynamically allocated buffer. */
int load_image_gzipped_buffer(const char *filename, uint64_t max_sz,
                              uint8_t **buffer)
{
    uint8_t *compressed_data = NULL;
    uint8_t *data = NULL;
    gsize len;
    ssize_t bytes;
    int ret = -1;

    if (!g_file_get_contents(filename, (char **) &compressed_data, &len,
                             NULL)) {
        goto out;
    }

    /* Is it a gzip-compressed file? */
    if (len < 2 ||
        compressed_data[0] != 0x1f ||
        compressed_data[1] != 0x8b) {
        goto out;
    }

    if (max_sz > LOAD_IMAGE_MAX_GUNZIP_BYTES) {
        max_sz = LOAD_IMAGE_MAX_GUNZIP_BYTES;
    }

    data = g_malloc(max_sz);
    bytes = gunzip(data, max_sz, compressed_data, len);
    if (bytes < 0) {
        fprintf(stderr, "%s: unable to decompress gzipped kernel file\n",
                filename);
        goto out;
    }

    /* trim to actual size and return to caller */
    *buffer = g_realloc(data, bytes);
    ret = bytes;
    /* ownership has been transferred to caller */
    data = NULL;

 out:
    g_free(compressed_data);
    g_free(data);
    return ret;
}

/* Load a gzip-compressed kernel. */
int load_image_gzipped(const char *filename, hwaddr addr, uint64_t max_sz)
{
    int bytes;
    uint8_t *data;

    bytes = load_image_gzipped_buffer(filename, max_sz, &data);
    if (bytes != -1) {
        rom_add_blob_fixed(filename, data, bytes, addr);
        g_free(data);
    }
    return bytes;
}

/*
 * Functions for reboot-persistent memory regions.
 *  - used for vga bios and option roms.
 *  - also linux kernel (-kernel / -initrd).
 */

typedef struct Rom Rom;

struct Rom {
    char *name;
    char *path;

    /* datasize is the amount of memory allocated in "data". If datasize is less
     * than romsize, it means that the area from datasize to romsize is filled
     * with zeros.
     */
    size_t romsize;
    size_t datasize;

    uint8_t *data;
    MemoryRegion *mr;
    AddressSpace *as;
    int isrom;
    char *fw_dir;
    char *fw_file;

    bool committed;

    hwaddr addr;
    QTAILQ_ENTRY(Rom) next;
};

static FWCfgState *fw_cfg;
static QTAILQ_HEAD(, Rom) roms = QTAILQ_HEAD_INITIALIZER(roms);

/* rom->data must be heap-allocated (do not use with rom_add_elf_program()) */
static void rom_free(Rom *rom)
{
    g_free(rom->data);
    g_free(rom->path);
    g_free(rom->name);
    g_free(rom->fw_dir);
    g_free(rom->fw_file);
    g_free(rom);
}

static inline bool rom_order_compare(Rom *rom, Rom *item)
{
    return ((uintptr_t)(void *)rom->as > (uintptr_t)(void *)item->as) ||
           (rom->as == item->as && rom->addr >= item->addr);
}

static void rom_insert(Rom *rom)
{
    Rom *item;

    if (roms_loaded) {
        hw_error ("ROM images must be loaded at startup\n");
    }

    /* The user didn't specify an address space, this is the default */
    if (!rom->as) {
        rom->as = &address_space_memory;
    }

    rom->committed = false;

    /* List is ordered by load address in the same address space */
    QTAILQ_FOREACH(item, &roms, next) {
        if (rom_order_compare(rom, item)) {
            continue;
        }
        QTAILQ_INSERT_BEFORE(item, rom, next);
        return;
    }
    QTAILQ_INSERT_TAIL(&roms, rom, next);
}

static void fw_cfg_resized(const char *id, uint64_t length, void *host)
{
    if (fw_cfg) {
        fw_cfg_modify_file(fw_cfg, id + strlen("/rom@"), host, length);
    }
}

static void *rom_set_mr(Rom *rom, Object *owner, const char *name, bool ro)
{
    void *data;

    rom->mr = g_malloc(sizeof(*rom->mr));
    memory_region_init_resizeable_ram(rom->mr, owner, name,
                                      rom->datasize, rom->romsize,
                                      fw_cfg_resized,
                                      &error_fatal);
    memory_region_set_readonly(rom->mr, ro);
    vmstate_register_ram_global(rom->mr);

    data = memory_region_get_ram_ptr(rom->mr);
    memcpy(data, rom->data, rom->datasize);

    return data;
}

int rom_add_file(const char *file, const char *fw_dir,
                 hwaddr addr, int32_t bootindex,
                 bool option_rom, MemoryRegion *mr,
                 AddressSpace *as)
{
    MachineClass *mc = MACHINE_GET_CLASS(qdev_get_machine());
    Rom *rom;
    int rc, fd = -1;
    char devpath[100];

    if (as && mr) {
        fprintf(stderr, "Specifying an Address Space and Memory Region is " \
                "not valid when loading a rom\n");
        /* We haven't allocated anything so we don't need any cleanup */
        return -1;
    }

    rom = g_malloc0(sizeof(*rom));
    rom->name = g_strdup(file);
    rom->path = qemu_find_file(QEMU_FILE_TYPE_BIOS, rom->name);
    rom->as = as;
    if (rom->path == NULL) {
        rom->path = g_strdup(file);
    }

    fd = open(rom->path, O_RDONLY | O_BINARY);
    if (fd == -1) {
        fprintf(stderr, "Could not open option rom '%s': %s\n",
                rom->path, strerror(errno));
        goto err;
    }

    if (fw_dir) {
        rom->fw_dir  = g_strdup(fw_dir);
        rom->fw_file = g_strdup(file);
    }
    rom->addr     = addr;
    rom->romsize  = lseek(fd, 0, SEEK_END);
    if (rom->romsize == -1) {
        fprintf(stderr, "rom: file %-20s: get size error: %s\n",
                rom->name, strerror(errno));
        goto err;
    }

    rom->datasize = rom->romsize;
    rom->data     = g_malloc0(rom->datasize);
    lseek(fd, 0, SEEK_SET);
    rc = read(fd, rom->data, rom->datasize);
    if (rc != rom->datasize) {
        fprintf(stderr, "rom: file %-20s: read error: rc=%d (expected %zd)\n",
                rom->name, rc, rom->datasize);
        goto err;
    }
    close(fd);
    rom_insert(rom);
    if (rom->fw_file && fw_cfg) {
        const char *basename;
        char fw_file_name[FW_CFG_MAX_FILE_PATH];
        void *data;

        basename = strrchr(rom->fw_file, '/');
        if (basename) {
            basename++;
        } else {
            basename = rom->fw_file;
        }
        snprintf(fw_file_name, sizeof(fw_file_name), "%s/%s", rom->fw_dir,
                 basename);
        snprintf(devpath, sizeof(devpath), "/rom@%s", fw_file_name);

        if ((!option_rom || mc->option_rom_has_mr) && mc->rom_file_has_mr) {
            data = rom_set_mr(rom, OBJECT(fw_cfg), devpath, true);
        } else {
            data = rom->data;
        }

        fw_cfg_add_file(fw_cfg, fw_file_name, data, rom->romsize);
    } else {
        if (mr) {
            rom->mr = mr;
            snprintf(devpath, sizeof(devpath), "/rom@%s", file);
        } else {
            snprintf(devpath, sizeof(devpath), "/rom@" TARGET_FMT_plx, addr);
        }
    }

    add_boot_device_path(bootindex, NULL, devpath);
    return 0;

err:
    if (fd != -1)
        close(fd);

    rom_free(rom);
    return -1;
}

MemoryRegion *rom_add_blob(const char *name, const void *blob, size_t len,
                   size_t max_len, hwaddr addr, const char *fw_file_name,
                   FWCfgCallback fw_callback, void *callback_opaque,
                   AddressSpace *as, bool read_only)
{
    MachineClass *mc = MACHINE_GET_CLASS(qdev_get_machine());
    Rom *rom;
    MemoryRegion *mr = NULL;

    rom           = g_malloc0(sizeof(*rom));
    rom->name     = g_strdup(name);
    rom->as       = as;
    rom->addr     = addr;
    rom->romsize  = max_len ? max_len : len;
    rom->datasize = len;
    rom->data     = g_malloc0(rom->datasize);
    memcpy(rom->data, blob, len);
    rom_insert(rom);
    if (fw_file_name && fw_cfg) {
        char devpath[100];
        void *data;

        if (read_only) {
            snprintf(devpath, sizeof(devpath), "/rom@%s", fw_file_name);
        } else {
            snprintf(devpath, sizeof(devpath), "/ram@%s", fw_file_name);
        }

        if (mc->rom_file_has_mr) {
            data = rom_set_mr(rom, OBJECT(fw_cfg), devpath, read_only);
            mr = rom->mr;
        } else {
            data = rom->data;
        }

        fw_cfg_add_file_callback(fw_cfg, fw_file_name,
                                 fw_callback, NULL, callback_opaque,
                                 data, rom->datasize, read_only);
    }
    return mr;
}

/* This function is specific for elf program because we don't need to allocate
 * all the rom. We just allocate the first part and the rest is just zeros. This
 * is why romsize and datasize are different. Also, this function seize the
 * memory ownership of "data", so we don't have to allocate and copy the buffer.
 */
int rom_add_elf_program(const char *name, void *data, size_t datasize,
                        size_t romsize, hwaddr addr, AddressSpace *as)
{
    Rom *rom;

    rom           = g_malloc0(sizeof(*rom));
    rom->name     = g_strdup(name);
    rom->addr     = addr;
    rom->datasize = datasize;
    rom->romsize  = romsize;
    rom->data     = data;
    rom->as       = as;
    rom_insert(rom);
    return 0;
}

int rom_add_vga(const char *file)
{
    return rom_add_file(file, "vgaroms", 0, -1, true, NULL, NULL);
}

int rom_add_option(const char *file, int32_t bootindex)
{
    return rom_add_file(file, "genroms", 0, bootindex, true, NULL, NULL);
}

static void rom_reset(void *unused)
{
    Rom *rom;

    QTAILQ_FOREACH(rom, &roms, next) {
        if (rom->fw_file) {
            continue;
        }
        if (rom->data == NULL) {
            continue;
        }
        if (rom->mr) {
            void *host = memory_region_get_ram_ptr(rom->mr);
            memcpy(host, rom->data, rom->datasize);
        } else {
            address_space_write_rom(rom->as, rom->addr, MEMTXATTRS_UNSPECIFIED,
                                    rom->data, rom->datasize);
        }
        if (rom->isrom) {
            /* rom needs to be written only once */
            g_free(rom->data);
            rom->data = NULL;
        }
        /*
         * The rom loader is really on the same level as firmware in the guest
         * shadowing a ROM into RAM. Such a shadowing mechanism needs to ensure
         * that the instruction cache for that new region is clear, so that the
         * CPU definitely fetches its instructions from the just written data.
         */
        cpu_flush_icache_range(rom->addr, rom->datasize);
    }
}

int rom_check_and_register_reset(void)
{
    hwaddr addr = 0;
    MemoryRegionSection section;
    Rom *rom;
    AddressSpace *as = NULL;

    QTAILQ_FOREACH(rom, &roms, next) {
        if (rom->fw_file) {
            continue;
        }
        if (!rom->mr) {
            if ((addr > rom->addr) && (as == rom->as)) {
                fprintf(stderr, "rom: requested regions overlap "
                        "(rom %s. free=0x" TARGET_FMT_plx
                        ", addr=0x" TARGET_FMT_plx ")\n",
                        rom->name, addr, rom->addr);
                return -1;
            }
            addr  = rom->addr;
            addr += rom->romsize;
            as = rom->as;
        }
        section = memory_region_find(rom->mr ? rom->mr : get_system_memory(),
                                     rom->addr, 1);
        rom->isrom = int128_nz(section.size) && memory_region_is_rom(section.mr);
        memory_region_unref(section.mr);
    }
    qemu_register_reset(rom_reset, NULL);
    roms_loaded = 1;
    return 0;
}

void rom_set_fw(FWCfgState *f)
{
    fw_cfg = f;
}

void rom_set_order_override(int order)
{
    if (!fw_cfg)
        return;
    fw_cfg_set_order_override(fw_cfg, order);
}

void rom_reset_order_override(void)
{
    if (!fw_cfg)
        return;
    fw_cfg_reset_order_override(fw_cfg);
}

void rom_transaction_begin(void)
{
    Rom *rom;

    /* Ignore ROMs added without the transaction API */
    QTAILQ_FOREACH(rom, &roms, next) {
        rom->committed = true;
    }
}

void rom_transaction_end(bool commit)
{
    Rom *rom;
    Rom *tmp;

    QTAILQ_FOREACH_SAFE(rom, &roms, next, tmp) {
        if (rom->committed) {
            continue;
        }
        if (commit) {
            rom->committed = true;
        } else {
            QTAILQ_REMOVE(&roms, rom, next);
            rom_free(rom);
        }
    }
}

static Rom *find_rom(hwaddr addr, size_t size)
{
    Rom *rom;

    QTAILQ_FOREACH(rom, &roms, next) {
        if (rom->fw_file) {
            continue;
        }
        if (rom->mr) {
            continue;
        }
        if (rom->addr > addr) {
            continue;
        }
        if (rom->addr + rom->romsize < addr + size) {
            continue;
        }
        return rom;
    }
    return NULL;
}

/*
 * Copies memory from registered ROMs to dest. Any memory that is contained in
 * a ROM between addr and addr + size is copied. Note that this can involve
 * multiple ROMs, which need not start at addr and need not end at addr + size.
 */
int rom_copy(uint8_t *dest, hwaddr addr, size_t size)
{
    hwaddr end = addr + size;
    uint8_t *s, *d = dest;
    size_t l = 0;
    Rom *rom;

    QTAILQ_FOREACH(rom, &roms, next) {
        if (rom->fw_file) {
            continue;
        }
        if (rom->mr) {
            continue;
        }
        if (rom->addr + rom->romsize < addr) {
            continue;
        }
        if (rom->addr > end) {
            break;
        }

        d = dest + (rom->addr - addr);
        s = rom->data;
        l = rom->datasize;

        if ((d + l) > (dest + size)) {
            l = dest - d;
        }

        if (l > 0) {
            memcpy(d, s, l);
        }

        if (rom->romsize > rom->datasize) {
            /* If datasize is less than romsize, it means that we didn't
             * allocate all the ROM because the trailing data are only zeros.
             */

            d += l;
            l = rom->romsize - rom->datasize;

            if ((d + l) > (dest + size)) {
                /* Rom size doesn't fit in the destination area. Adjust to avoid
                 * overflow.
                 */
                l = dest - d;
            }

            if (l > 0) {
                memset(d, 0x0, l);
            }
        }
    }

    return (d + l) - dest;
}

void *rom_ptr(hwaddr addr, size_t size)
{
    Rom *rom;

    rom = find_rom(addr, size);
    if (!rom || !rom->data)
        return NULL;
    return rom->data + (addr - rom->addr);
}

void hmp_info_roms(Monitor *mon, const QDict *qdict)
{
    Rom *rom;

    QTAILQ_FOREACH(rom, &roms, next) {
        if (rom->mr) {
            monitor_printf(mon, "%s"
                           " size=0x%06zx name=\"%s\"\n",
                           memory_region_name(rom->mr),
                           rom->romsize,
                           rom->name);
        } else if (!rom->fw_file) {
            monitor_printf(mon, "addr=" TARGET_FMT_plx
                           " size=0x%06zx mem=%s name=\"%s\"\n",
                           rom->addr, rom->romsize,
                           rom->isrom ? "rom" : "ram",
                           rom->name);
        } else {
            monitor_printf(mon, "fw=%s/%s"
                           " size=0x%06zx name=\"%s\"\n",
                           rom->fw_dir,
                           rom->fw_file,
                           rom->romsize,
                           rom->name);
        }
    }
}

typedef enum HexRecord HexRecord;
enum HexRecord {
    DATA_RECORD = 0,
    EOF_RECORD,
    EXT_SEG_ADDR_RECORD,
    START_SEG_ADDR_RECORD,
    EXT_LINEAR_ADDR_RECORD,
    START_LINEAR_ADDR_RECORD,
};

/* Each record contains a 16-bit address which is combined with the upper 16
 * bits of the implicit "next address" to form a 32-bit address.
 */
#define NEXT_ADDR_MASK 0xffff0000

#define DATA_FIELD_MAX_LEN 0xff
#define LEN_EXCEPT_DATA 0x5
/* 0x5 = sizeof(byte_count) + sizeof(address) + sizeof(record_type) +
 *       sizeof(checksum) */
typedef struct {
    uint8_t byte_count;
    uint16_t address;
    uint8_t record_type;
    uint8_t data[DATA_FIELD_MAX_LEN];
    uint8_t checksum;
} HexLine;

/* return 0 or -1 if error */
static bool parse_record(HexLine *line, uint8_t *our_checksum, const uint8_t c,
                         uint32_t *index, const bool in_process)
{
    /* +-------+---------------+-------+---------------------+--------+
     * | byte  |               |record |                     |        |
     * | count |    address    | type  |        data         |checksum|
     * +-------+---------------+-------+---------------------+--------+
     * ^       ^               ^       ^                     ^        ^
     * |1 byte |    2 bytes    |1 byte |     0-255 bytes     | 1 byte |
     */
    uint8_t value = 0;
    uint32_t idx = *index;
    /* ignore space */
    if (g_ascii_isspace(c)) {
        return true;
    }
    if (!g_ascii_isxdigit(c) || !in_process) {
        return false;
    }
    value = g_ascii_xdigit_value(c);
    value = (idx & 0x1) ? (value & 0xf) : (value << 4);
    if (idx < 2) {
        line->byte_count |= value;
    } else if (2 <= idx && idx < 6) {
        line->address <<= 4;
        line->address += g_ascii_xdigit_value(c);
    } else if (6 <= idx && idx < 8) {
        line->record_type |= value;
    } else if (8 <= idx && idx < 8 + 2 * line->byte_count) {
        line->data[(idx - 8) >> 1] |= value;
    } else if (8 + 2 * line->byte_count <= idx &&
               idx < 10 + 2 * line->byte_count) {
        line->checksum |= value;
    } else {
        return false;
    }
    *our_checksum += value;
    ++(*index);
    return true;
}

typedef struct {
    const char *filename;
    HexLine line;
    uint8_t *bin_buf;
    hwaddr *start_addr;
    int total_size;
    uint32_t next_address_to_write;
    uint32_t current_address;
    uint32_t current_rom_index;
    uint32_t rom_start_address;
    AddressSpace *as;
} HexParser;

/* return size or -1 if error */
static int handle_record_type(HexParser *parser)
{
    HexLine *line = &(parser->line);
    switch (line->record_type) {
    case DATA_RECORD:
        parser->current_address =
            (parser->next_address_to_write & NEXT_ADDR_MASK) | line->address;
        /* verify this is a contiguous block of memory */
        if (parser->current_address != parser->next_address_to_write) {
            if (parser->current_rom_index != 0) {
                rom_add_blob_fixed_as(parser->filename, parser->bin_buf,
                                      parser->current_rom_index,
                                      parser->rom_start_address, parser->as);
            }
            parser->rom_start_address = parser->current_address;
            parser->current_rom_index = 0;
        }

        /* copy from line buffer to output bin_buf */
        memcpy(parser->bin_buf + parser->current_rom_index, line->data,
               line->byte_count);
        parser->current_rom_index += line->byte_count;
        parser->total_size += line->byte_count;
        /* save next address to write */
        parser->next_address_to_write =
            parser->current_address + line->byte_count;
        break;

    case EOF_RECORD:
        if (parser->current_rom_index != 0) {
            rom_add_blob_fixed_as(parser->filename, parser->bin_buf,
                                  parser->current_rom_index,
                                  parser->rom_start_address, parser->as);
        }
        return parser->total_size;
    case EXT_SEG_ADDR_RECORD:
    case EXT_LINEAR_ADDR_RECORD:
        if (line->byte_count != 2 && line->address != 0) {
            return -1;
        }

        if (parser->current_rom_index != 0) {
            rom_add_blob_fixed_as(parser->filename, parser->bin_buf,
                                  parser->current_rom_index,
                                  parser->rom_start_address, parser->as);
        }

        /* save next address to write,
         * in case of non-contiguous block of memory */
        parser->next_address_to_write = (line->data[0] << 12) |
                                        (line->data[1] << 4);
        if (line->record_type == EXT_LINEAR_ADDR_RECORD) {
            parser->next_address_to_write <<= 12;
        }

        parser->rom_start_address = parser->next_address_to_write;
        parser->current_rom_index = 0;
        break;

    case START_SEG_ADDR_RECORD:
        if (line->byte_count != 4 && line->address != 0) {
            return -1;
        }

        /* x86 16-bit CS:IP segmented addressing */
        *(parser->start_addr) = (((line->data[0] << 8) | line->data[1]) << 4) +
                                ((line->data[2] << 8) | line->data[3]);
        break;

    case START_LINEAR_ADDR_RECORD:
        if (line->byte_count != 4 && line->address != 0) {
            return -1;
        }

        *(parser->start_addr) = ldl_be_p(line->data);
        break;

    default:
        return -1;
    }

    return parser->total_size;
}

/* return size or -1 if error */
static int parse_hex_blob(const char *filename, hwaddr *addr, uint8_t *hex_blob,
                          size_t hex_blob_size, AddressSpace *as)
{
    bool in_process = false; /* avoid re-enter and
                              * check whether record begin with ':' */
    uint8_t *end = hex_blob + hex_blob_size;
    uint8_t our_checksum = 0;
    uint32_t record_index = 0;
    HexParser parser = {
        .filename = filename,
        .bin_buf = g_malloc(hex_blob_size),
        .start_addr = addr,
        .as = as,
    };

    rom_transaction_begin();

    for (; hex_blob < end; ++hex_blob) {
        switch (*hex_blob) {
        case '\r':
        case '\n':
            if (!in_process) {
                break;
            }

            in_process = false;
            if ((LEN_EXCEPT_DATA + parser.line.byte_count) * 2 !=
                    record_index ||
                our_checksum != 0) {
                parser.total_size = -1;
                goto out;
            }

            if (handle_record_type(&parser) == -1) {
                parser.total_size = -1;
                goto out;
            }
            break;

        /* start of a new record. */
        case ':':
            memset(&parser.line, 0, sizeof(HexLine));
            in_process = true;
            record_index = 0;
            break;

        /* decoding lines */
        default:
            if (!parse_record(&parser.line, &our_checksum, *hex_blob,
                              &record_index, in_process)) {
                parser.total_size = -1;
                goto out;
            }
            break;
        }
    }

out:
    g_free(parser.bin_buf);
    rom_transaction_end(parser.total_size != -1);
    return parser.total_size;
}

/* return size or -1 if error */
int load_targphys_hex_as(const char *filename, hwaddr *entry, AddressSpace *as)
{
    gsize hex_blob_size;
    gchar *hex_blob;
    int total_size = 0;

    if (!g_file_get_contents(filename, &hex_blob, &hex_blob_size, NULL)) {
        return -1;
    }

    total_size = parse_hex_blob(filename, entry, (uint8_t *)hex_blob,
                                hex_blob_size, as);

    g_free(hex_blob);
    return total_size;
}
