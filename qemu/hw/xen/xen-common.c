/*
 * Copyright (C) 2014       Citrix Systems UK Ltd.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/xen/xen-legacy-backend.h"
#include "chardev/char.h"
#include "sysemu/accel.h"
#include "migration/misc.h"
#include "migration/global_state.h"

//#define DEBUG_XEN

#ifdef DEBUG_XEN
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "xen: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

xc_interface *xen_xc;
xenforeignmemory_handle *xen_fmem;
xendevicemodel_handle *xen_dmod;

static int store_dev_info(int domid, Chardev *cs, const char *string)
{
    struct xs_handle *xs = NULL;
    char *path = NULL;
    char *newpath = NULL;
    char *pts = NULL;
    int ret = -1;

    /* Only continue if we're talking to a pty. */
    if (!CHARDEV_IS_PTY(cs)) {
        return 0;
    }
    pts = cs->filename + 4;

    /* We now have everything we need to set the xenstore entry. */
    xs = xs_open(0);
    if (xs == NULL) {
        fprintf(stderr, "Could not contact XenStore\n");
        goto out;
    }

    path = xs_get_domain_path(xs, domid);
    if (path == NULL) {
        fprintf(stderr, "xs_get_domain_path() error\n");
        goto out;
    }
    newpath = realloc(path, (strlen(path) + strlen(string) +
                strlen("/tty") + 1));
    if (newpath == NULL) {
        fprintf(stderr, "realloc error\n");
        goto out;
    }
    path = newpath;

    strcat(path, string);
    strcat(path, "/tty");
    if (!xs_write(xs, XBT_NULL, path, pts, strlen(pts))) {
        fprintf(stderr, "xs_write for '%s' fail", string);
        goto out;
    }
    ret = 0;

out:
    free(path);
    xs_close(xs);

    return ret;
}

void xenstore_store_pv_console_info(int i, Chardev *chr)
{
    if (i == 0) {
        store_dev_info(xen_domid, chr, "/console");
    } else {
        char buf[32];
        snprintf(buf, sizeof(buf), "/device/console/%d", i);
        store_dev_info(xen_domid, chr, buf);
    }
}


static void xenstore_record_dm_state(struct xs_handle *xs, const char *state)
{
    char path[50];

    if (xs == NULL) {
        error_report("xenstore connection not initialized");
        exit(1);
    }

    snprintf(path, sizeof (path), "device-model/%u/state", xen_domid);
    /*
     * This call may fail when running restricted so don't make it fatal in
     * that case. Toolstacks should instead use QMP to listen for state changes.
     */
    if (!xs_write(xs, XBT_NULL, path, state, strlen(state)) &&
            !xen_domid_restrict) {
        error_report("error recording dm state");
        exit(1);
    }
}


static void xen_change_state_handler(void *opaque, int running,
                                     RunState state)
{
    if (running) {
        /* record state running */
        xenstore_record_dm_state(xenstore, "running");
    }
}

static void xen_setup_post(MachineState *ms, AccelState *accel)
{
    int rc;

    if (xen_domid_restrict) {
        rc = xen_restrict(xen_domid);
        if (rc < 0) {
            perror("xen: failed to restrict");
            exit(1);
        }
    }
}

static int xen_init(MachineState *ms)
{
    xen_xc = xc_interface_open(0, 0, 0);
    if (xen_xc == NULL) {
        xen_pv_printf(NULL, 0, "can't open xen interface\n");
        return -1;
    }
    xen_fmem = xenforeignmemory_open(0, 0);
    if (xen_fmem == NULL) {
        xen_pv_printf(NULL, 0, "can't open xen fmem interface\n");
        xc_interface_close(xen_xc);
        return -1;
    }
    xen_dmod = xendevicemodel_open(0, 0);
    if (xen_dmod == NULL) {
        xen_pv_printf(NULL, 0, "can't open xen devicemodel interface\n");
        xenforeignmemory_close(xen_fmem);
        xc_interface_close(xen_xc);
        return -1;
    }
    qemu_add_vm_change_state_handler(xen_change_state_handler, NULL);
    return 0;
}

static void xen_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    static GlobalProperty compat[] = {
        { "migration", "store-global-state", "off" },
        { "migration", "send-configuration", "off" },
        { "migration", "send-section-footer", "off" },
    };

    ac->name = "Xen";
    ac->init_machine = xen_init;
    ac->setup_post = xen_setup_post;
    ac->allowed = &xen_allowed;
    ac->compat_props = g_ptr_array_new();

    compat_props_add(ac->compat_props, compat, G_N_ELEMENTS(compat));
}

#define TYPE_XEN_ACCEL ACCEL_CLASS_NAME("xen")

static const TypeInfo xen_accel_type = {
    .name = TYPE_XEN_ACCEL,
    .parent = TYPE_ACCEL,
    .class_init = xen_accel_class_init,
};

static void xen_type_init(void)
{
    type_register_static(&xen_accel_type);
}

type_init(xen_type_init);
