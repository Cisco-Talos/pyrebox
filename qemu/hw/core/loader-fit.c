/*
 * Flattened Image Tree loader.
 *
 * Copyright (c) 2016 Imagination Technologies
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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "exec/memory.h"
#include "hw/loader.h"
#include "hw/loader-fit.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "sysemu/device_tree.h"
#include "sysemu/sysemu.h"

#include <libfdt.h>
#include <zlib.h>

#define FIT_LOADER_MAX_PATH (128)

static const void *fit_load_image_alloc(const void *itb, const char *name,
                                        int *poff, size_t *psz)
{
    const void *data;
    const char *comp;
    void *uncomp_data;
    char path[FIT_LOADER_MAX_PATH];
    int off, sz;
    ssize_t uncomp_len;

    snprintf(path, sizeof(path), "/images/%s", name);

    off = fdt_path_offset(itb, path);
    if (off < 0) {
        return NULL;
    }
    if (poff) {
        *poff = off;
    }

    data = fdt_getprop(itb, off, "data", &sz);
    if (!data) {
        return NULL;
    }

    comp = fdt_getprop(itb, off, "compression", NULL);
    if (!comp || !strcmp(comp, "none")) {
        if (psz) {
            *psz = sz;
        }
        uncomp_data = g_malloc(sz);
        memmove(uncomp_data, data, sz);
        return uncomp_data;
    }

    if (!strcmp(comp, "gzip")) {
        uncomp_len = UBOOT_MAX_GUNZIP_BYTES;
        uncomp_data = g_malloc(uncomp_len);

        uncomp_len = gunzip(uncomp_data, uncomp_len, (void *) data, sz);
        if (uncomp_len < 0) {
            error_printf("unable to decompress %s image\n", name);
            g_free(uncomp_data);
            return NULL;
        }

        data = g_realloc(uncomp_data, uncomp_len);
        if (psz) {
            *psz = uncomp_len;
        }
        return data;
    }

    error_printf("unknown compression '%s'\n", comp);
    return NULL;
}

static int fit_image_addr(const void *itb, int img, const char *name,
                          hwaddr *addr)
{
    const void *prop;
    int len;

    prop = fdt_getprop(itb, img, name, &len);
    if (!prop) {
        return -ENOENT;
    }

    switch (len) {
    case 4:
        *addr = fdt32_to_cpu(*(fdt32_t *)prop);
        return 0;
    case 8:
        *addr = fdt64_to_cpu(*(fdt64_t *)prop);
        return 0;
    default:
        error_printf("invalid %s address length %d\n", name, len);
        return -EINVAL;
    }
}

static int fit_load_kernel(const struct fit_loader *ldr, const void *itb,
                           int cfg, void *opaque, hwaddr *pend)
{
    const char *name;
    const void *data;
    const void *load_data;
    hwaddr load_addr, entry_addr;
    int img_off, err;
    size_t sz;
    int ret;

    name = fdt_getprop(itb, cfg, "kernel", NULL);
    if (!name) {
        error_printf("no kernel specified by FIT configuration\n");
        return -EINVAL;
    }

    load_data = data = fit_load_image_alloc(itb, name, &img_off, &sz);
    if (!data) {
        error_printf("unable to load kernel image from FIT\n");
        return -EINVAL;
    }

    err = fit_image_addr(itb, img_off, "load", &load_addr);
    if (err) {
        error_printf("unable to read kernel load address from FIT\n");
        ret = err;
        goto out;
    }

    err = fit_image_addr(itb, img_off, "entry", &entry_addr);
    if (err) {
        error_printf("unable to read kernel entry address from FIT\n");
        ret = err;
        goto out;
    }

    if (ldr->kernel_filter) {
        load_data = ldr->kernel_filter(opaque, data, &load_addr, &entry_addr);
    }

    if (pend) {
        *pend = load_addr + sz;
    }

    load_addr = ldr->addr_to_phys(opaque, load_addr);
    rom_add_blob_fixed(name, load_data, sz, load_addr);

    ret = 0;
out:
    g_free((void *) data);
    if (data != load_data) {
        g_free((void *) load_data);
    }
    return ret;
}

static int fit_load_fdt(const struct fit_loader *ldr, const void *itb,
                        int cfg, void *opaque, const void *match_data,
                        hwaddr kernel_end)
{
    const char *name;
    const void *data;
    const void *load_data;
    hwaddr load_addr;
    int img_off, err;
    size_t sz;
    int ret;

    name = fdt_getprop(itb, cfg, "fdt", NULL);
    if (!name) {
        return 0;
    }

    load_data = data = fit_load_image_alloc(itb, name, &img_off, &sz);
    if (!data) {
        error_printf("unable to load FDT image from FIT\n");
        return -EINVAL;
    }

    err = fit_image_addr(itb, img_off, "load", &load_addr);
    if (err == -ENOENT) {
        load_addr = ROUND_UP(kernel_end, 64 * KiB) + (10 * MiB);
    } else if (err) {
        ret = err;
        goto out;
    }

    if (ldr->fdt_filter) {
        load_data = ldr->fdt_filter(opaque, data, match_data, &load_addr);
    }

    load_addr = ldr->addr_to_phys(opaque, load_addr);
    sz = fdt_totalsize(load_data);
    rom_add_blob_fixed(name, load_data, sz, load_addr);

    ret = 0;
out:
    g_free((void *) data);
    if (data != load_data) {
        g_free((void *) load_data);
    }
    return ret;
}

static bool fit_cfg_compatible(const void *itb, int cfg, const char *compat)
{
    const void *fdt;
    const char *fdt_name;
    bool ret;

    fdt_name = fdt_getprop(itb, cfg, "fdt", NULL);
    if (!fdt_name) {
        return false;
    }

    fdt = fit_load_image_alloc(itb, fdt_name, NULL, NULL);
    if (!fdt) {
        return false;
    }

    if (fdt_check_header(fdt)) {
        ret = false;
        goto out;
    }

    if (fdt_node_check_compatible(fdt, 0, compat)) {
        ret = false;
        goto out;
    }

    ret = true;
out:
    g_free((void *) fdt);
    return ret;
}

int load_fit(const struct fit_loader *ldr, const char *filename, void *opaque)
{
    const struct fit_loader_match *match;
    const void *itb, *match_data = NULL;
    const char *def_cfg_name;
    char path[FIT_LOADER_MAX_PATH];
    int itb_size, configs, cfg_off, off, err;
    hwaddr kernel_end;
    int ret;

    itb = load_device_tree(filename, &itb_size);
    if (!itb) {
        return -EINVAL;
    }

    configs = fdt_path_offset(itb, "/configurations");
    if (configs < 0) {
        ret = configs;
        goto out;
    }

    cfg_off = -FDT_ERR_NOTFOUND;

    if (ldr->matches) {
        for (match = ldr->matches; match->compatible; match++) {
            off = fdt_first_subnode(itb, configs);
            while (off >= 0) {
                if (fit_cfg_compatible(itb, off, match->compatible)) {
                    cfg_off = off;
                    match_data = match->data;
                    break;
                }

                off = fdt_next_subnode(itb, off);
            }

            if (cfg_off >= 0) {
                break;
            }
        }
    }

    if (cfg_off < 0) {
        def_cfg_name = fdt_getprop(itb, configs, "default", NULL);
        if (def_cfg_name) {
            snprintf(path, sizeof(path), "/configurations/%s", def_cfg_name);
            cfg_off = fdt_path_offset(itb, path);
        }
    }

    if (cfg_off < 0) {
        /* couldn't find a configuration to use */
        ret = cfg_off;
        goto out;
    }

    err = fit_load_kernel(ldr, itb, cfg_off, opaque, &kernel_end);
    if (err) {
        ret = err;
        goto out;
    }

    err = fit_load_fdt(ldr, itb, cfg_off, opaque, match_data, kernel_end);
    if (err) {
        ret = err;
        goto out;
    }

    ret = 0;
out:
    g_free((void *) itb);
    return ret;
}
