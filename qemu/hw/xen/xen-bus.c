/*
 * Copyright (c) 2018  Citrix Systems Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/uuid.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/xen/xen.h"
#include "hw/xen/xen-backend.h"
#include "hw/xen/xen-bus.h"
#include "hw/xen/xen-bus-helper.h"
#include "monitor/monitor.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "sysemu/sysemu.h"
#include "trace.h"

static char *xen_device_get_backend_path(XenDevice *xendev)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    XenDeviceClass *xendev_class = XEN_DEVICE_GET_CLASS(xendev);
    const char *type = object_get_typename(OBJECT(xendev));
    const char *backend = xendev_class->backend;

    if (!backend) {
        backend = type;
    }

    return g_strdup_printf("/local/domain/%u/backend/%s/%u/%s",
                           xenbus->backend_id, backend, xendev->frontend_id,
                           xendev->name);
}

static char *xen_device_get_frontend_path(XenDevice *xendev)
{
    XenDeviceClass *xendev_class = XEN_DEVICE_GET_CLASS(xendev);
    const char *type = object_get_typename(OBJECT(xendev));
    const char *device = xendev_class->device;

    if (!device) {
        device = type;
    }

    return g_strdup_printf("/local/domain/%u/device/%s/%s",
                           xendev->frontend_id, device, xendev->name);
}

static void xen_device_unplug(XenDevice *xendev, Error **errp)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    const char *type = object_get_typename(OBJECT(xendev));
    Error *local_err = NULL;
    xs_transaction_t tid;

    trace_xen_device_unplug(type, xendev->name);

    /* Mimic the way the Xen toolstack does an unplug */
again:
    tid = xs_transaction_start(xenbus->xsh);
    if (tid == XBT_NULL) {
        error_setg_errno(errp, errno, "failed xs_transaction_start");
        return;
    }

    xs_node_printf(xenbus->xsh, tid, xendev->backend_path, "online",
                   &local_err, "%u", 0);
    if (local_err) {
        goto abort;
    }

    xs_node_printf(xenbus->xsh, tid, xendev->backend_path, "state",
                   &local_err, "%u", XenbusStateClosing);
    if (local_err) {
        goto abort;
    }

    if (!xs_transaction_end(xenbus->xsh, tid, false)) {
        if (errno == EAGAIN) {
            goto again;
        }

        error_setg_errno(errp, errno, "failed xs_transaction_end");
    }

    return;

abort:
    /*
     * We only abort if there is already a failure so ignore any error
     * from ending the transaction.
     */
    xs_transaction_end(xenbus->xsh, tid, true);
    error_propagate(errp, local_err);
}

static void xen_bus_print_dev(Monitor *mon, DeviceState *dev, int indent)
{
    XenDevice *xendev = XEN_DEVICE(dev);

    monitor_printf(mon, "%*sname = '%s' frontend_id = %u\n",
                   indent, "", xendev->name, xendev->frontend_id);
}

static char *xen_bus_get_dev_path(DeviceState *dev)
{
    return xen_device_get_backend_path(XEN_DEVICE(dev));
}

struct XenWatch {
    char *node, *key;
    char *token;
    XenWatchHandler handler;
    void *opaque;
    Notifier notifier;
};

static void watch_notify(Notifier *n, void *data)
{
    XenWatch *watch = container_of(n, XenWatch, notifier);
    const char *token = data;

    if (!strcmp(watch->token, token)) {
        watch->handler(watch->opaque);
    }
}

static XenWatch *new_watch(const char *node, const char *key,
                           XenWatchHandler handler, void *opaque)
{
    XenWatch *watch = g_new0(XenWatch, 1);
    QemuUUID uuid;

    qemu_uuid_generate(&uuid);

    watch->token = qemu_uuid_unparse_strdup(&uuid);
    watch->node = g_strdup(node);
    watch->key = g_strdup(key);
    watch->handler = handler;
    watch->opaque = opaque;
    watch->notifier.notify = watch_notify;

    return watch;
}

static void free_watch(XenWatch *watch)
{
    g_free(watch->token);
    g_free(watch->key);
    g_free(watch->node);

    g_free(watch);
}

static XenWatch *xen_bus_add_watch(XenBus *xenbus, const char *node,
                                   const char *key, XenWatchHandler handler,
                                   void *opaque, Error **errp)
{
    XenWatch *watch = new_watch(node, key, handler, opaque);
    Error *local_err = NULL;

    trace_xen_bus_add_watch(watch->node, watch->key, watch->token);

    notifier_list_add(&xenbus->watch_notifiers, &watch->notifier);

    xs_node_watch(xenbus->xsh, node, key, watch->token, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);

        notifier_remove(&watch->notifier);
        free_watch(watch);

        return NULL;
    }

    return watch;
}

static void xen_bus_remove_watch(XenBus *xenbus, XenWatch *watch,
                                 Error **errp)
{
    trace_xen_bus_remove_watch(watch->node, watch->key, watch->token);

    xs_node_unwatch(xenbus->xsh, watch->node, watch->key, watch->token,
                    errp);

    notifier_remove(&watch->notifier);
    free_watch(watch);
}

static void xen_bus_backend_create(XenBus *xenbus, const char *type,
                                   const char *name, char *path,
                                   Error **errp)
{
    xs_transaction_t tid;
    char **key;
    QDict *opts;
    unsigned int i, n;
    Error *local_err = NULL;

    trace_xen_bus_backend_create(type, path);

again:
    tid = xs_transaction_start(xenbus->xsh);
    if (tid == XBT_NULL) {
        error_setg(errp, "failed xs_transaction_start");
        return;
    }

    key = xs_directory(xenbus->xsh, tid, path, &n);
    if (!key) {
        if (!xs_transaction_end(xenbus->xsh, tid, true)) {
            error_setg_errno(errp, errno, "failed xs_transaction_end");
        }
        return;
    }

    opts = qdict_new();
    for (i = 0; i < n; i++) {
        char *val;

        /*
         * Assume anything found in the xenstore backend area, other than
         * the keys created for a generic XenDevice, are parameters
         * to be used to configure the backend.
         */
        if (!strcmp(key[i], "state") ||
            !strcmp(key[i], "online") ||
            !strcmp(key[i], "frontend") ||
            !strcmp(key[i], "frontend-id") ||
            !strcmp(key[i], "hotplug-status"))
            continue;

        if (xs_node_scanf(xenbus->xsh, tid, path, key[i], NULL, "%ms",
                          &val) == 1) {
            qdict_put_str(opts, key[i], val);
            free(val);
        }
    }

    free(key);

    if (!xs_transaction_end(xenbus->xsh, tid, false)) {
        qobject_unref(opts);

        if (errno == EAGAIN) {
            goto again;
        }

        error_setg_errno(errp, errno, "failed xs_transaction_end");
        return;
    }

    xen_backend_device_create(xenbus, type, name, opts, &local_err);
    qobject_unref(opts);

    if (local_err) {
        error_propagate_prepend(errp, local_err,
                                "failed to create '%s' device '%s': ",
                                type, name);
    }
}

static void xen_bus_type_enumerate(XenBus *xenbus, const char *type)
{
    char *domain_path = g_strdup_printf("backend/%s/%u", type, xen_domid);
    char **backend;
    unsigned int i, n;

    trace_xen_bus_type_enumerate(type);

    backend = xs_directory(xenbus->xsh, XBT_NULL, domain_path, &n);
    if (!backend) {
        goto out;
    }

    for (i = 0; i < n; i++) {
        char *backend_path = g_strdup_printf("%s/%s", domain_path,
                                             backend[i]);
        enum xenbus_state backend_state;

        if (xs_node_scanf(xenbus->xsh, XBT_NULL, backend_path, "state",
                          NULL, "%u", &backend_state) != 1)
            backend_state = XenbusStateUnknown;

        if (backend_state == XenbusStateInitialising) {
            Error *local_err = NULL;

            xen_bus_backend_create(xenbus, type, backend[i], backend_path,
                                   &local_err);
            if (local_err) {
                error_report_err(local_err);
            }
        }

        g_free(backend_path);
    }

    free(backend);

out:
    g_free(domain_path);
}

static void xen_bus_enumerate(void *opaque)
{
    XenBus *xenbus = opaque;
    char **type;
    unsigned int i, n;

    trace_xen_bus_enumerate();

    type = xs_directory(xenbus->xsh, XBT_NULL, "backend", &n);
    if (!type) {
        return;
    }

    for (i = 0; i < n; i++) {
        xen_bus_type_enumerate(xenbus, type[i]);
    }

    free(type);
}

static void xen_bus_unrealize(BusState *bus, Error **errp)
{
    XenBus *xenbus = XEN_BUS(bus);

    trace_xen_bus_unrealize();

    if (xenbus->backend_watch) {
        xen_bus_remove_watch(xenbus, xenbus->backend_watch, NULL);
        xenbus->backend_watch = NULL;
    }

    if (!xenbus->xsh) {
        return;
    }

    qemu_set_fd_handler(xs_fileno(xenbus->xsh), NULL, NULL, NULL);

    xs_close(xenbus->xsh);
}

static void xen_bus_watch(void *opaque)
{
    XenBus *xenbus = opaque;
    char **v;
    const char *token;

    g_assert(xenbus->xsh);

    v = xs_check_watch(xenbus->xsh);
    if (!v) {
        return;
    }

    token = v[XS_WATCH_TOKEN];

    trace_xen_bus_watch(token);

    notifier_list_notify(&xenbus->watch_notifiers, (void *)token);

    free(v);
}

static void xen_bus_realize(BusState *bus, Error **errp)
{
    XenBus *xenbus = XEN_BUS(bus);
    unsigned int domid;
    Error *local_err = NULL;

    trace_xen_bus_realize();

    xenbus->xsh = xs_open(0);
    if (!xenbus->xsh) {
        error_setg_errno(errp, errno, "failed xs_open");
        goto fail;
    }

    if (xs_node_scanf(xenbus->xsh, XBT_NULL, "", /* domain root node */
                      "domid", NULL, "%u", &domid) == 1) {
        xenbus->backend_id = domid;
    } else {
        xenbus->backend_id = 0; /* Assume lack of node means dom0 */
    }

    notifier_list_init(&xenbus->watch_notifiers);
    qemu_set_fd_handler(xs_fileno(xenbus->xsh), xen_bus_watch, NULL,
                        xenbus);

    module_call_init(MODULE_INIT_XEN_BACKEND);

    xenbus->backend_watch =
        xen_bus_add_watch(xenbus, "", /* domain root node */
                          "backend", xen_bus_enumerate, xenbus, &local_err);
    if (local_err) {
        /* This need not be treated as a hard error so don't propagate */
        error_reportf_err(local_err,
                          "failed to set up enumeration watch: ");
    }

    return;

fail:
    xen_bus_unrealize(bus, &error_abort);
}

static void xen_bus_unplug_request(HotplugHandler *hotplug,
                                   DeviceState *dev,
                                   Error **errp)
{
    XenDevice *xendev = XEN_DEVICE(dev);

    xen_device_unplug(xendev, errp);
}

static void xen_bus_class_init(ObjectClass *class, void *data)
{
    BusClass *bus_class = BUS_CLASS(class);
    HotplugHandlerClass *hotplug_class = HOTPLUG_HANDLER_CLASS(class);

    bus_class->print_dev = xen_bus_print_dev;
    bus_class->get_dev_path = xen_bus_get_dev_path;
    bus_class->realize = xen_bus_realize;
    bus_class->unrealize = xen_bus_unrealize;

    hotplug_class->unplug_request = xen_bus_unplug_request;
}

static const TypeInfo xen_bus_type_info = {
    .name = TYPE_XEN_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(XenBus),
    .class_size = sizeof(XenBusClass),
    .class_init = xen_bus_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_HOTPLUG_HANDLER },
        { }
    },
};

void xen_device_backend_printf(XenDevice *xendev, const char *key,
                               const char *fmt, ...)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    Error *local_err = NULL;
    va_list ap;

    g_assert(xenbus->xsh);

    va_start(ap, fmt);
    xs_node_vprintf(xenbus->xsh, XBT_NULL, xendev->backend_path, key,
                    &local_err, fmt, ap);
    va_end(ap);

    if (local_err) {
        error_report_err(local_err);
    }
}

static int xen_device_backend_scanf(XenDevice *xendev, const char *key,
                                    const char *fmt, ...)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    va_list ap;
    int rc;

    g_assert(xenbus->xsh);

    va_start(ap, fmt);
    rc = xs_node_vscanf(xenbus->xsh, XBT_NULL, xendev->backend_path, key,
                        NULL, fmt, ap);
    va_end(ap);

    return rc;
}

void xen_device_backend_set_state(XenDevice *xendev,
                                  enum xenbus_state state)
{
    const char *type = object_get_typename(OBJECT(xendev));

    if (xendev->backend_state == state) {
        return;
    }

    trace_xen_device_backend_state(type, xendev->name,
                                   xs_strstate(state));

    xendev->backend_state = state;
    xen_device_backend_printf(xendev, "state", "%u", state);
}

enum xenbus_state xen_device_backend_get_state(XenDevice *xendev)
{
    return xendev->backend_state;
}

static void xen_device_backend_set_online(XenDevice *xendev, bool online)
{
    const char *type = object_get_typename(OBJECT(xendev));

    if (xendev->backend_online == online) {
        return;
    }

    trace_xen_device_backend_online(type, xendev->name, online);

    xendev->backend_online = online;
    xen_device_backend_printf(xendev, "online", "%u", online);
}

static void xen_device_backend_changed(void *opaque)
{
    XenDevice *xendev = opaque;
    const char *type = object_get_typename(OBJECT(xendev));
    enum xenbus_state state;
    unsigned int online;

    trace_xen_device_backend_changed(type, xendev->name);

    if (xen_device_backend_scanf(xendev, "state", "%u", &state) != 1) {
        state = XenbusStateUnknown;
    }

    xen_device_backend_set_state(xendev, state);

    if (xen_device_backend_scanf(xendev, "online", "%u", &online) != 1) {
        online = 0;
    }

    xen_device_backend_set_online(xendev, !!online);

    /*
     * If the toolstack (or unplug request callback) has set the backend
     * state to Closing, but there is no active frontend (i.e. the
     * state is not Connected) then set the backend state to Closed.
     */
    if (xendev->backend_state == XenbusStateClosing &&
        xendev->frontend_state != XenbusStateConnected) {
        xen_device_backend_set_state(xendev, XenbusStateClosed);
    }

    /*
     * If a backend is still 'online' then we should leave it alone but,
     * if a backend is not 'online', then the device should be destroyed
     * once the state is Closed.
     */
    if (!xendev->backend_online &&
        (xendev->backend_state == XenbusStateClosed ||
         xendev->backend_state == XenbusStateInitialising ||
         xendev->backend_state == XenbusStateInitWait ||
         xendev->backend_state == XenbusStateUnknown)) {
        Error *local_err = NULL;

        if (!xen_backend_try_device_destroy(xendev, &local_err)) {
            object_unparent(OBJECT(xendev));
        }

        if (local_err) {
            error_report_err(local_err);
        }
    }
}

static void xen_device_backend_create(XenDevice *xendev, Error **errp)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    struct xs_permissions perms[2];
    Error *local_err = NULL;

    xendev->backend_path = xen_device_get_backend_path(xendev);

    perms[0].id = xenbus->backend_id;
    perms[0].perms = XS_PERM_NONE;
    perms[1].id = xendev->frontend_id;
    perms[1].perms = XS_PERM_READ;

    g_assert(xenbus->xsh);

    xs_node_create(xenbus->xsh, XBT_NULL, xendev->backend_path, perms,
                   ARRAY_SIZE(perms), &local_err);
    if (local_err) {
        error_propagate_prepend(errp, local_err,
                                "failed to create backend: ");
        return;
    }

    xendev->backend_state_watch =
        xen_bus_add_watch(xenbus, xendev->backend_path,
                          "state", xen_device_backend_changed,
                          xendev, &local_err);
    if (local_err) {
        error_propagate_prepend(errp, local_err,
                                "failed to watch backend state: ");
        return;
    }

    xendev->backend_online_watch =
        xen_bus_add_watch(xenbus, xendev->backend_path,
                          "online", xen_device_backend_changed,
                          xendev, &local_err);
    if (local_err) {
        error_propagate_prepend(errp, local_err,
                                "failed to watch backend online: ");
        return;
    }
}

static void xen_device_backend_destroy(XenDevice *xendev)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    Error *local_err = NULL;

    if (xendev->backend_online_watch) {
        xen_bus_remove_watch(xenbus, xendev->backend_online_watch, NULL);
        xendev->backend_online_watch = NULL;
    }

    if (xendev->backend_state_watch) {
        xen_bus_remove_watch(xenbus, xendev->backend_state_watch, NULL);
        xendev->backend_state_watch = NULL;
    }

    if (!xendev->backend_path) {
        return;
    }

    g_assert(xenbus->xsh);

    xs_node_destroy(xenbus->xsh, XBT_NULL, xendev->backend_path,
                    &local_err);
    g_free(xendev->backend_path);
    xendev->backend_path = NULL;

    if (local_err) {
        error_report_err(local_err);
    }
}

void xen_device_frontend_printf(XenDevice *xendev, const char *key,
                                const char *fmt, ...)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    Error *local_err = NULL;
    va_list ap;

    g_assert(xenbus->xsh);

    va_start(ap, fmt);
    xs_node_vprintf(xenbus->xsh, XBT_NULL, xendev->frontend_path, key,
                    &local_err, fmt, ap);
    va_end(ap);

    if (local_err) {
        error_report_err(local_err);
    }
}

int xen_device_frontend_scanf(XenDevice *xendev, const char *key,
                              const char *fmt, ...)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    va_list ap;
    int rc;

    g_assert(xenbus->xsh);

    va_start(ap, fmt);
    rc = xs_node_vscanf(xenbus->xsh, XBT_NULL, xendev->frontend_path, key,
                        NULL, fmt, ap);
    va_end(ap);

    return rc;
}

static void xen_device_frontend_set_state(XenDevice *xendev,
                                          enum xenbus_state state)
{
    const char *type = object_get_typename(OBJECT(xendev));

    if (xendev->frontend_state == state) {
        return;
    }

    trace_xen_device_frontend_state(type, xendev->name,
                                    xs_strstate(state));

    xendev->frontend_state = state;
    xen_device_frontend_printf(xendev, "state", "%u", state);
}

static void xen_device_frontend_changed(void *opaque)
{
    XenDevice *xendev = opaque;
    XenDeviceClass *xendev_class = XEN_DEVICE_GET_CLASS(xendev);
    const char *type = object_get_typename(OBJECT(xendev));
    enum xenbus_state state;

    trace_xen_device_frontend_changed(type, xendev->name);

    if (xen_device_frontend_scanf(xendev, "state", "%u", &state) != 1) {
        state = XenbusStateUnknown;
    }

    xen_device_frontend_set_state(xendev, state);

    if (state == XenbusStateInitialising &&
        xendev->backend_state == XenbusStateClosed &&
        xendev->backend_online) {
        /*
         * The frontend is re-initializing so switch back to
         * InitWait.
         */
        xen_device_backend_set_state(xendev, XenbusStateInitWait);
        return;
    }

    if (xendev_class->frontend_changed) {
        Error *local_err = NULL;

        xendev_class->frontend_changed(xendev, state, &local_err);

        if (local_err) {
            error_reportf_err(local_err, "frontend change error: ");
        }
    }
}

static void xen_device_frontend_create(XenDevice *xendev, Error **errp)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    struct xs_permissions perms[2];
    Error *local_err = NULL;

    xendev->frontend_path = xen_device_get_frontend_path(xendev);

    perms[0].id = xendev->frontend_id;
    perms[0].perms = XS_PERM_NONE;
    perms[1].id = xenbus->backend_id;
    perms[1].perms = XS_PERM_READ | XS_PERM_WRITE;

    g_assert(xenbus->xsh);

    xs_node_create(xenbus->xsh, XBT_NULL, xendev->frontend_path, perms,
                   ARRAY_SIZE(perms), &local_err);
    if (local_err) {
        error_propagate_prepend(errp, local_err,
                                "failed to create frontend: ");
        return;
    }

    xendev->frontend_state_watch =
        xen_bus_add_watch(xenbus, xendev->frontend_path, "state",
                          xen_device_frontend_changed, xendev, &local_err);
    if (local_err) {
        error_propagate_prepend(errp, local_err,
                                "failed to watch frontend state: ");
    }
}

static void xen_device_frontend_destroy(XenDevice *xendev)
{
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    Error *local_err = NULL;

    if (xendev->frontend_state_watch) {
        xen_bus_remove_watch(xenbus, xendev->frontend_state_watch, NULL);
        xendev->frontend_state_watch = NULL;
    }

    if (!xendev->frontend_path) {
        return;
    }

    g_assert(xenbus->xsh);

    xs_node_destroy(xenbus->xsh, XBT_NULL, xendev->frontend_path,
                    &local_err);
    g_free(xendev->frontend_path);
    xendev->frontend_path = NULL;

    if (local_err) {
        error_report_err(local_err);
    }
}

void xen_device_set_max_grant_refs(XenDevice *xendev, unsigned int nr_refs,
                                   Error **errp)
{
    if (xengnttab_set_max_grants(xendev->xgth, nr_refs)) {
        error_setg_errno(errp, errno, "xengnttab_set_max_grants failed");
    }
}

void *xen_device_map_grant_refs(XenDevice *xendev, uint32_t *refs,
                                unsigned int nr_refs, int prot,
                                Error **errp)
{
    void *map = xengnttab_map_domain_grant_refs(xendev->xgth, nr_refs,
                                                xendev->frontend_id, refs,
                                                prot);

    if (!map) {
        error_setg_errno(errp, errno,
                         "xengnttab_map_domain_grant_refs failed");
    }

    return map;
}

void xen_device_unmap_grant_refs(XenDevice *xendev, void *map,
                                 unsigned int nr_refs, Error **errp)
{
    if (xengnttab_unmap(xendev->xgth, map, nr_refs)) {
        error_setg_errno(errp, errno, "xengnttab_unmap failed");
    }
}

static void compat_copy_grant_refs(XenDevice *xendev, bool to_domain,
                                   XenDeviceGrantCopySegment segs[],
                                   unsigned int nr_segs, Error **errp)
{
    uint32_t *refs = g_new(uint32_t, nr_segs);
    int prot = to_domain ? PROT_WRITE : PROT_READ;
    void *map;
    unsigned int i;

    for (i = 0; i < nr_segs; i++) {
        XenDeviceGrantCopySegment *seg = &segs[i];

        refs[i] = to_domain ? seg->dest.foreign.ref :
            seg->source.foreign.ref;
    }

    map = xengnttab_map_domain_grant_refs(xendev->xgth, nr_segs,
                                          xendev->frontend_id, refs,
                                          prot);
    if (!map) {
        error_setg_errno(errp, errno,
                         "xengnttab_map_domain_grant_refs failed");
        goto done;
    }

    for (i = 0; i < nr_segs; i++) {
        XenDeviceGrantCopySegment *seg = &segs[i];
        void *page = map + (i * XC_PAGE_SIZE);

        if (to_domain) {
            memcpy(page + seg->dest.foreign.offset, seg->source.virt,
                   seg->len);
        } else {
            memcpy(seg->dest.virt, page + seg->source.foreign.offset,
                   seg->len);
        }
    }

    if (xengnttab_unmap(xendev->xgth, map, nr_segs)) {
        error_setg_errno(errp, errno, "xengnttab_unmap failed");
    }

done:
    g_free(refs);
}

void xen_device_copy_grant_refs(XenDevice *xendev, bool to_domain,
                                XenDeviceGrantCopySegment segs[],
                                unsigned int nr_segs, Error **errp)
{
    xengnttab_grant_copy_segment_t *xengnttab_segs;
    unsigned int i;

    if (!xendev->feature_grant_copy) {
        compat_copy_grant_refs(xendev, to_domain, segs, nr_segs, errp);
        return;
    }

    xengnttab_segs = g_new0(xengnttab_grant_copy_segment_t, nr_segs);

    for (i = 0; i < nr_segs; i++) {
        XenDeviceGrantCopySegment *seg = &segs[i];
        xengnttab_grant_copy_segment_t *xengnttab_seg = &xengnttab_segs[i];

        if (to_domain) {
            xengnttab_seg->flags = GNTCOPY_dest_gref;
            xengnttab_seg->dest.foreign.domid = xendev->frontend_id;
            xengnttab_seg->dest.foreign.ref = seg->dest.foreign.ref;
            xengnttab_seg->dest.foreign.offset = seg->dest.foreign.offset;
            xengnttab_seg->source.virt = seg->source.virt;
        } else {
            xengnttab_seg->flags = GNTCOPY_source_gref;
            xengnttab_seg->source.foreign.domid = xendev->frontend_id;
            xengnttab_seg->source.foreign.ref = seg->source.foreign.ref;
            xengnttab_seg->source.foreign.offset =
                seg->source.foreign.offset;
            xengnttab_seg->dest.virt = seg->dest.virt;
        }

        xengnttab_seg->len = seg->len;
    }

    if (xengnttab_grant_copy(xendev->xgth, nr_segs, xengnttab_segs)) {
        error_setg_errno(errp, errno, "xengnttab_grant_copy failed");
        goto done;
    }

    for (i = 0; i < nr_segs; i++) {
        xengnttab_grant_copy_segment_t *xengnttab_seg = &xengnttab_segs[i];

        if (xengnttab_seg->status != GNTST_okay) {
            error_setg(errp, "xengnttab_grant_copy seg[%u] failed", i);
            break;
        }
    }

done:
    g_free(xengnttab_segs);
}

struct XenEventChannel {
    evtchn_port_t local_port;
    XenEventHandler handler;
    void *opaque;
    Notifier notifier;
};

static void event_notify(Notifier *n, void *data)
{
    XenEventChannel *channel = container_of(n, XenEventChannel, notifier);
    unsigned long port = (unsigned long)data;

    if (port == channel->local_port) {
        channel->handler(channel->opaque);
    }
}

XenEventChannel *xen_device_bind_event_channel(XenDevice *xendev,
                                               unsigned int port,
                                               XenEventHandler handler,
                                               void *opaque, Error **errp)
{
    XenEventChannel *channel = g_new0(XenEventChannel, 1);
    xenevtchn_port_or_error_t local_port;

    local_port = xenevtchn_bind_interdomain(xendev->xeh,
                                            xendev->frontend_id,
                                            port);
    if (local_port < 0) {
        error_setg_errno(errp, errno, "xenevtchn_bind_interdomain failed");

        g_free(channel);
        return NULL;
    }

    channel->local_port = local_port;
    channel->handler = handler;
    channel->opaque = opaque;
    channel->notifier.notify = event_notify;

    notifier_list_add(&xendev->event_notifiers, &channel->notifier);

    return channel;
}

void xen_device_notify_event_channel(XenDevice *xendev,
                                     XenEventChannel *channel,
                                     Error **errp)
{
    if (!channel) {
        error_setg(errp, "bad channel");
        return;
    }

    if (xenevtchn_notify(xendev->xeh, channel->local_port) < 0) {
        error_setg_errno(errp, errno, "xenevtchn_notify failed");
    }
}

void xen_device_unbind_event_channel(XenDevice *xendev,
                                     XenEventChannel *channel,
                                     Error **errp)
{
    if (!channel) {
        error_setg(errp, "bad channel");
        return;
    }

    notifier_remove(&channel->notifier);

    if (xenevtchn_unbind(xendev->xeh, channel->local_port) < 0) {
        error_setg_errno(errp, errno, "xenevtchn_unbind failed");
    }

    g_free(channel);
}

static void xen_device_unrealize(DeviceState *dev, Error **errp)
{
    XenDevice *xendev = XEN_DEVICE(dev);
    XenDeviceClass *xendev_class = XEN_DEVICE_GET_CLASS(xendev);
    const char *type = object_get_typename(OBJECT(xendev));

    if (!xendev->name) {
        return;
    }

    trace_xen_device_unrealize(type, xendev->name);

    if (xendev->exit.notify) {
        qemu_remove_exit_notifier(&xendev->exit);
        xendev->exit.notify = NULL;
    }

    if (xendev_class->unrealize) {
        xendev_class->unrealize(xendev, errp);
    }

    xen_device_frontend_destroy(xendev);
    xen_device_backend_destroy(xendev);

    if (xendev->xeh) {
        qemu_set_fd_handler(xenevtchn_fd(xendev->xeh), NULL, NULL, NULL);
        xenevtchn_close(xendev->xeh);
        xendev->xeh = NULL;
    }

    if (xendev->xgth) {
        xengnttab_close(xendev->xgth);
        xendev->xgth = NULL;
    }

    g_free(xendev->name);
    xendev->name = NULL;
}

static void xen_device_exit(Notifier *n, void *data)
{
    XenDevice *xendev = container_of(n, XenDevice, exit);

    xen_device_unrealize(DEVICE(xendev), &error_abort);
}

static void xen_device_event(void *opaque)
{
    XenDevice *xendev = opaque;
    unsigned long port = xenevtchn_pending(xendev->xeh);

    notifier_list_notify(&xendev->event_notifiers, (void *)port);

    xenevtchn_unmask(xendev->xeh, port);
}

static void xen_device_realize(DeviceState *dev, Error **errp)
{
    XenDevice *xendev = XEN_DEVICE(dev);
    XenDeviceClass *xendev_class = XEN_DEVICE_GET_CLASS(xendev);
    XenBus *xenbus = XEN_BUS(qdev_get_parent_bus(DEVICE(xendev)));
    const char *type = object_get_typename(OBJECT(xendev));
    Error *local_err = NULL;

    if (xendev->frontend_id == DOMID_INVALID) {
        xendev->frontend_id = xen_domid;
    }

    if (xendev->frontend_id >= DOMID_FIRST_RESERVED) {
        error_setg(errp, "invalid frontend-id");
        goto unrealize;
    }

    if (!xendev_class->get_name) {
        error_setg(errp, "get_name method not implemented");
        goto unrealize;
    }

    xendev->name = xendev_class->get_name(xendev, &local_err);
    if (local_err) {
        error_propagate_prepend(errp, local_err,
                                "failed to get device name: ");
        goto unrealize;
    }

    trace_xen_device_realize(type, xendev->name);

    xendev->xgth = xengnttab_open(NULL, 0);
    if (!xendev->xgth) {
        error_setg_errno(errp, errno, "failed xengnttab_open");
        goto unrealize;
    }

    xendev->feature_grant_copy =
        (xengnttab_grant_copy(xendev->xgth, 0, NULL) == 0);

    xendev->xeh = xenevtchn_open(NULL, 0);
    if (!xendev->xeh) {
        error_setg_errno(errp, errno, "failed xenevtchn_open");
        goto unrealize;
    }

    notifier_list_init(&xendev->event_notifiers);
    qemu_set_fd_handler(xenevtchn_fd(xendev->xeh), xen_device_event, NULL,
                        xendev);

    xen_device_backend_create(xendev, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto unrealize;
    }

    xen_device_frontend_create(xendev, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto unrealize;
    }

    if (xendev_class->realize) {
        xendev_class->realize(xendev, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            goto unrealize;
        }
    }

    xen_device_backend_printf(xendev, "frontend", "%s",
                              xendev->frontend_path);
    xen_device_backend_printf(xendev, "frontend-id", "%u",
                              xendev->frontend_id);
    xen_device_backend_printf(xendev, "hotplug-status", "connected");

    xen_device_backend_set_online(xendev, true);
    xen_device_backend_set_state(xendev, XenbusStateInitWait);

    xen_device_frontend_printf(xendev, "backend", "%s",
                               xendev->backend_path);
    xen_device_frontend_printf(xendev, "backend-id", "%u",
                               xenbus->backend_id);

    xen_device_frontend_set_state(xendev, XenbusStateInitialising);

    xendev->exit.notify = xen_device_exit;
    qemu_add_exit_notifier(&xendev->exit);
    return;

unrealize:
    xen_device_unrealize(dev, &error_abort);
}

static Property xen_device_props[] = {
    DEFINE_PROP_UINT16("frontend-id", XenDevice, frontend_id,
                       DOMID_INVALID),
    DEFINE_PROP_END_OF_LIST()
};

static void xen_device_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dev_class = DEVICE_CLASS(class);

    dev_class->realize = xen_device_realize;
    dev_class->unrealize = xen_device_unrealize;
    dev_class->props = xen_device_props;
    dev_class->bus_type = TYPE_XEN_BUS;
}

static const TypeInfo xen_device_type_info = {
    .name = TYPE_XEN_DEVICE,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(XenDevice),
    .abstract = true,
    .class_size = sizeof(XenDeviceClass),
    .class_init = xen_device_class_init,
};

typedef struct XenBridge {
    SysBusDevice busdev;
} XenBridge;

#define TYPE_XEN_BRIDGE "xen-bridge"

static const TypeInfo xen_bridge_type_info = {
    .name = TYPE_XEN_BRIDGE,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(XenBridge),
};

static void xen_register_types(void)
{
    type_register_static(&xen_bridge_type_info);
    type_register_static(&xen_bus_type_info);
    type_register_static(&xen_device_type_info);
}

type_init(xen_register_types)

void xen_bus_init(void)
{
    DeviceState *dev = qdev_create(NULL, TYPE_XEN_BRIDGE);
    BusState *bus = qbus_create(TYPE_XEN_BUS, dev, NULL);

    qdev_init_nofail(dev);
    qbus_set_bus_hotplug_handler(bus, &error_abort);
}
