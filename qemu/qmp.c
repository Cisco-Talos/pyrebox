/*
 * QEMU Management Protocol
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu-version.h"
#include "qemu/cutils.h"
#include "qemu/option.h"
#include "monitor/monitor.h"
#include "sysemu/sysemu.h"
#include "qemu/config-file.h"
#include "qemu/uuid.h"
#include "chardev/char.h"
#include "ui/qemu-spice.h"
#include "ui/vnc.h"
#include "sysemu/kvm.h"
#include "sysemu/arch_init.h"
#include "hw/qdev.h"
#include "sysemu/blockdev.h"
#include "sysemu/block-backend.h"
#include "qom/qom-qobject.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-block-core.h"
#include "qapi/qapi-commands-misc.h"
#include "qapi/qapi-commands-ui.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qobject-input-visitor.h"
#include "hw/boards.h"
#include "qom/object_interfaces.h"
#include "hw/mem/memory-device.h"
#include "hw/acpi/acpi_dev_interface.h"

NameInfo *qmp_query_name(Error **errp)
{
    NameInfo *info = g_malloc0(sizeof(*info));

    if (qemu_name) {
        info->has_name = true;
        info->name = g_strdup(qemu_name);
    }

    return info;
}

VersionInfo *qmp_query_version(Error **errp)
{
    VersionInfo *info = g_new0(VersionInfo, 1);

    info->qemu = g_new0(VersionTriple, 1);
    info->qemu->major = QEMU_VERSION_MAJOR;
    info->qemu->minor = QEMU_VERSION_MINOR;
    info->qemu->micro = QEMU_VERSION_MICRO;
    info->package = g_strdup(QEMU_PKGVERSION);

    return info;
}

KvmInfo *qmp_query_kvm(Error **errp)
{
    KvmInfo *info = g_malloc0(sizeof(*info));

    info->enabled = kvm_enabled();
    info->present = kvm_available();

    return info;
}

UuidInfo *qmp_query_uuid(Error **errp)
{
    UuidInfo *info = g_malloc0(sizeof(*info));

    info->UUID = qemu_uuid_unparse_strdup(&qemu_uuid);
    return info;
}

void qmp_quit(Error **errp)
{
    no_shutdown = 0;
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_QMP_QUIT);
}

void qmp_stop(Error **errp)
{
    /* if there is a dump in background, we should wait until the dump
     * finished */
    if (dump_in_progress()) {
        error_setg(errp, "There is a dump in process, please wait.");
        return;
    }

    if (runstate_check(RUN_STATE_INMIGRATE)) {
        autostart = 0;
    } else {
        vm_stop(RUN_STATE_PAUSED);
    }
}

void qmp_system_reset(Error **errp)
{
    qemu_system_reset_request(SHUTDOWN_CAUSE_HOST_QMP_SYSTEM_RESET);
}

void qmp_system_powerdown(Error **erp)
{
    qemu_system_powerdown_request();
}

void qmp_cpu_add(int64_t id, Error **errp)
{
    MachineClass *mc;

    mc = MACHINE_GET_CLASS(current_machine);
    if (mc->hot_add_cpu) {
        mc->hot_add_cpu(id, errp);
    } else {
        error_setg(errp, "Not supported");
    }
}

void qmp_x_exit_preconfig(Error **errp)
{
    if (!runstate_check(RUN_STATE_PRECONFIG)) {
        error_setg(errp, "The command is permitted only in '%s' state",
                   RunState_str(RUN_STATE_PRECONFIG));
        return;
    }
    qemu_exit_preconfig_request();
}

void qmp_cont(Error **errp)
{
    BlockBackend *blk;
    Error *local_err = NULL;

    /* if there is a dump in background, we should wait until the dump
     * finished */
    if (dump_in_progress()) {
        error_setg(errp, "There is a dump in process, please wait.");
        return;
    }

    if (runstate_needs_reset()) {
        error_setg(errp, "Resetting the Virtual Machine is required");
        return;
    } else if (runstate_check(RUN_STATE_SUSPENDED)) {
        return;
    }

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        blk_iostatus_reset(blk);
    }

    /* Continuing after completed migration. Images have been inactivated to
     * allow the destination to take control. Need to get control back now.
     *
     * If there are no inactive block nodes (e.g. because the VM was just
     * paused rather than completing a migration), bdrv_inactivate_all() simply
     * doesn't do anything. */
    bdrv_invalidate_cache_all(&local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (runstate_check(RUN_STATE_INMIGRATE)) {
        autostart = 1;
    } else {
        vm_start();
    }
}

void qmp_system_wakeup(Error **errp)
{
    if (!qemu_wakeup_suspend_enabled()) {
        error_setg(errp,
                   "wake-up from suspend is not supported by this guest");
        return;
    }

    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER, errp);
}

ObjectPropertyInfoList *qmp_qom_list(const char *path, Error **errp)
{
    Object *obj;
    bool ambiguous = false;
    ObjectPropertyInfoList *props = NULL;
    ObjectProperty *prop;
    ObjectPropertyIterator iter;

    obj = object_resolve_path(path, &ambiguous);
    if (obj == NULL) {
        if (ambiguous) {
            error_setg(errp, "Path '%s' is ambiguous", path);
        } else {
            error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                      "Device '%s' not found", path);
        }
        return NULL;
    }

    object_property_iter_init(&iter, obj);
    while ((prop = object_property_iter_next(&iter))) {
        ObjectPropertyInfoList *entry = g_malloc0(sizeof(*entry));

        entry->value = g_malloc0(sizeof(ObjectPropertyInfo));
        entry->next = props;
        props = entry;

        entry->value->name = g_strdup(prop->name);
        entry->value->type = g_strdup(prop->type);
    }

    return props;
}

void qmp_qom_set(const char *path, const char *property, QObject *value,
                 Error **errp)
{
    Object *obj;

    obj = object_resolve_path(path, NULL);
    if (!obj) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", path);
        return;
    }

    object_property_set_qobject(obj, value, property, errp);
}

QObject *qmp_qom_get(const char *path, const char *property, Error **errp)
{
    Object *obj;

    obj = object_resolve_path(path, NULL);
    if (!obj) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", path);
        return NULL;
    }

    return object_property_get_qobject(obj, property, errp);
}

void qmp_set_password(const char *protocol, const char *password,
                      bool has_connected, const char *connected, Error **errp)
{
    int disconnect_if_connected = 0;
    int fail_if_connected = 0;
    int rc;

    if (has_connected) {
        if (strcmp(connected, "fail") == 0) {
            fail_if_connected = 1;
        } else if (strcmp(connected, "disconnect") == 0) {
            disconnect_if_connected = 1;
        } else if (strcmp(connected, "keep") == 0) {
            /* nothing */
        } else {
            error_setg(errp, QERR_INVALID_PARAMETER, "connected");
            return;
        }
    }

    if (strcmp(protocol, "spice") == 0) {
        if (!qemu_using_spice(errp)) {
            return;
        }
        rc = qemu_spice_set_passwd(password, fail_if_connected,
                                   disconnect_if_connected);
        if (rc != 0) {
            error_setg(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    if (strcmp(protocol, "vnc") == 0) {
        if (fail_if_connected || disconnect_if_connected) {
            /* vnc supports "connected=keep" only */
            error_setg(errp, QERR_INVALID_PARAMETER, "connected");
            return;
        }
        /* Note that setting an empty password will not disable login through
         * this interface. */
        rc = vnc_display_password(NULL, password);
        if (rc < 0) {
            error_setg(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    error_setg(errp, QERR_INVALID_PARAMETER, "protocol");
}

void qmp_expire_password(const char *protocol, const char *whenstr,
                         Error **errp)
{
    time_t when;
    int rc;

    if (strcmp(whenstr, "now") == 0) {
        when = 0;
    } else if (strcmp(whenstr, "never") == 0) {
        when = TIME_MAX;
    } else if (whenstr[0] == '+') {
        when = time(NULL) + strtoull(whenstr+1, NULL, 10);
    } else {
        when = strtoull(whenstr, NULL, 10);
    }

    if (strcmp(protocol, "spice") == 0) {
        if (!qemu_using_spice(errp)) {
            return;
        }
        rc = qemu_spice_set_pw_expire(when);
        if (rc != 0) {
            error_setg(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    if (strcmp(protocol, "vnc") == 0) {
        rc = vnc_display_pw_expire(NULL, when);
        if (rc != 0) {
            error_setg(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    error_setg(errp, QERR_INVALID_PARAMETER, "protocol");
}

#ifdef CONFIG_VNC
void qmp_change_vnc_password(const char *password, Error **errp)
{
    if (vnc_display_password(NULL, password) < 0) {
        error_setg(errp, QERR_SET_PASSWD_FAILED);
    }
}

static void qmp_change_vnc_listen(const char *target, Error **errp)
{
    QemuOptsList *olist = qemu_find_opts("vnc");
    QemuOpts *opts;

    if (strstr(target, "id=")) {
        error_setg(errp, "id not supported");
        return;
    }

    opts = qemu_opts_find(olist, "default");
    if (opts) {
        qemu_opts_del(opts);
    }
    opts = vnc_parse(target, errp);
    if (!opts) {
        return;
    }

    vnc_display_open("default", errp);
}

static void qmp_change_vnc(const char *target, bool has_arg, const char *arg,
                           Error **errp)
{
    if (strcmp(target, "passwd") == 0 || strcmp(target, "password") == 0) {
        if (!has_arg) {
            error_setg(errp, QERR_MISSING_PARAMETER, "password");
        } else {
            qmp_change_vnc_password(arg, errp);
        }
    } else {
        qmp_change_vnc_listen(target, errp);
    }
}
#endif /* !CONFIG_VNC */

void qmp_change(const char *device, const char *target,
                bool has_arg, const char *arg, Error **errp)
{
    if (strcmp(device, "vnc") == 0) {
#ifdef CONFIG_VNC
        qmp_change_vnc(target, has_arg, arg, errp);
#else
        error_setg(errp, QERR_FEATURE_DISABLED, "vnc");
#endif
    } else {
        qmp_blockdev_change_medium(true, device, false, NULL, target,
                                   has_arg, arg, false, 0, errp);
    }
}

static void qom_list_types_tramp(ObjectClass *klass, void *data)
{
    ObjectTypeInfoList *e, **pret = data;
    ObjectTypeInfo *info;
    ObjectClass *parent = object_class_get_parent(klass);

    info = g_malloc0(sizeof(*info));
    info->name = g_strdup(object_class_get_name(klass));
    info->has_abstract = info->abstract = object_class_is_abstract(klass);
    if (parent) {
        info->has_parent = true;
        info->parent = g_strdup(object_class_get_name(parent));
    }

    e = g_malloc0(sizeof(*e));
    e->value = info;
    e->next = *pret;
    *pret = e;
}

ObjectTypeInfoList *qmp_qom_list_types(bool has_implements,
                                       const char *implements,
                                       bool has_abstract,
                                       bool abstract,
                                       Error **errp)
{
    ObjectTypeInfoList *ret = NULL;

    object_class_foreach(qom_list_types_tramp, implements, abstract, &ret);

    return ret;
}

/* Return a DevicePropertyInfo for a qdev property.
 *
 * If a qdev property with the given name does not exist, use the given default
 * type.  If the qdev property info should not be shown, return NULL.
 *
 * The caller must free the return value.
 */
static ObjectPropertyInfo *make_device_property_info(ObjectClass *klass,
                                                  const char *name,
                                                  const char *default_type,
                                                  const char *description)
{
    ObjectPropertyInfo *info;
    Property *prop;

    do {
        for (prop = DEVICE_CLASS(klass)->props; prop && prop->name; prop++) {
            if (strcmp(name, prop->name) != 0) {
                continue;
            }

            /*
             * TODO Properties without a parser are just for dirty hacks.
             * qdev_prop_ptr is the only such PropertyInfo.  It's marked
             * for removal.  This conditional should be removed along with
             * it.
             */
            if (!prop->info->set && !prop->info->create) {
                return NULL;           /* no way to set it, don't show */
            }

            info = g_malloc0(sizeof(*info));
            info->name = g_strdup(prop->name);
            info->type = default_type ? g_strdup(default_type)
                                      : g_strdup(prop->info->name);
            info->has_description = !!prop->info->description;
            info->description = g_strdup(prop->info->description);
            return info;
        }
        klass = object_class_get_parent(klass);
    } while (klass != object_class_by_name(TYPE_DEVICE));

    /* Not a qdev property, use the default type */
    info = g_malloc0(sizeof(*info));
    info->name = g_strdup(name);
    info->type = g_strdup(default_type);
    info->has_description = !!description;
    info->description = g_strdup(description);

    return info;
}

ObjectPropertyInfoList *qmp_device_list_properties(const char *typename,
                                                Error **errp)
{
    ObjectClass *klass;
    Object *obj;
    ObjectProperty *prop;
    ObjectPropertyIterator iter;
    ObjectPropertyInfoList *prop_list = NULL;

    klass = object_class_by_name(typename);
    if (klass == NULL) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", typename);
        return NULL;
    }

    klass = object_class_dynamic_cast(klass, TYPE_DEVICE);
    if (klass == NULL) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "typename", TYPE_DEVICE);
        return NULL;
    }

    if (object_class_is_abstract(klass)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "typename",
                   "non-abstract device type");
        return NULL;
    }

    obj = object_new(typename);

    object_property_iter_init(&iter, obj);
    while ((prop = object_property_iter_next(&iter))) {
        ObjectPropertyInfo *info;
        ObjectPropertyInfoList *entry;

        /* Skip Object and DeviceState properties */
        if (strcmp(prop->name, "type") == 0 ||
            strcmp(prop->name, "realized") == 0 ||
            strcmp(prop->name, "hotpluggable") == 0 ||
            strcmp(prop->name, "hotplugged") == 0 ||
            strcmp(prop->name, "parent_bus") == 0) {
            continue;
        }

        /* Skip legacy properties since they are just string versions of
         * properties that we already list.
         */
        if (strstart(prop->name, "legacy-", NULL)) {
            continue;
        }

        info = make_device_property_info(klass, prop->name, prop->type,
                                         prop->description);
        if (!info) {
            continue;
        }

        entry = g_malloc0(sizeof(*entry));
        entry->value = info;
        entry->next = prop_list;
        prop_list = entry;
    }

    object_unref(obj);

    return prop_list;
}

ObjectPropertyInfoList *qmp_qom_list_properties(const char *typename,
                                             Error **errp)
{
    ObjectClass *klass;
    Object *obj = NULL;
    ObjectProperty *prop;
    ObjectPropertyIterator iter;
    ObjectPropertyInfoList *prop_list = NULL;

    klass = object_class_by_name(typename);
    if (klass == NULL) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Class '%s' not found", typename);
        return NULL;
    }

    klass = object_class_dynamic_cast(klass, TYPE_OBJECT);
    if (klass == NULL) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "typename", TYPE_OBJECT);
        return NULL;
    }

    if (object_class_is_abstract(klass)) {
        object_class_property_iter_init(&iter, klass);
    } else {
        obj = object_new(typename);
        object_property_iter_init(&iter, obj);
    }
    while ((prop = object_property_iter_next(&iter))) {
        ObjectPropertyInfo *info;
        ObjectPropertyInfoList *entry;

        info = g_malloc0(sizeof(*info));
        info->name = g_strdup(prop->name);
        info->type = g_strdup(prop->type);
        info->has_description = !!prop->description;
        info->description = g_strdup(prop->description);

        entry = g_malloc0(sizeof(*entry));
        entry->value = info;
        entry->next = prop_list;
        prop_list = entry;
    }

    object_unref(obj);

    return prop_list;
}

void qmp_add_client(const char *protocol, const char *fdname,
                    bool has_skipauth, bool skipauth, bool has_tls, bool tls,
                    Error **errp)
{
    Chardev *s;
    int fd;

    fd = monitor_get_fd(cur_mon, fdname, errp);
    if (fd < 0) {
        return;
    }

    if (strcmp(protocol, "spice") == 0) {
        if (!qemu_using_spice(errp)) {
            close(fd);
            return;
        }
        skipauth = has_skipauth ? skipauth : false;
        tls = has_tls ? tls : false;
        if (qemu_spice_display_add_client(fd, skipauth, tls) < 0) {
            error_setg(errp, "spice failed to add client");
            close(fd);
        }
        return;
#ifdef CONFIG_VNC
    } else if (strcmp(protocol, "vnc") == 0) {
        skipauth = has_skipauth ? skipauth : false;
        vnc_display_add_client(NULL, fd, skipauth);
        return;
#endif
    } else if ((s = qemu_chr_find(protocol)) != NULL) {
        if (qemu_chr_add_client(s, fd) < 0) {
            error_setg(errp, "failed to add client");
            close(fd);
            return;
        }
        return;
    }

    error_setg(errp, "protocol '%s' is invalid", protocol);
    close(fd);
}


void qmp_object_add(const char *type, const char *id,
                    bool has_props, QObject *props, Error **errp)
{
    QDict *pdict;
    Visitor *v;
    Object *obj;

    if (props) {
        pdict = qobject_to(QDict, props);
        if (!pdict) {
            error_setg(errp, QERR_INVALID_PARAMETER_TYPE, "props", "dict");
            return;
        }
        qobject_ref(pdict);
    } else {
        pdict = qdict_new();
    }

    v = qobject_input_visitor_new(QOBJECT(pdict));
    obj = user_creatable_add_type(type, id, pdict, v, errp);
    visit_free(v);
    if (obj) {
        object_unref(obj);
    }
    qobject_unref(pdict);
}

void qmp_object_del(const char *id, Error **errp)
{
    user_creatable_del(id, errp);
}

MemoryDeviceInfoList *qmp_query_memory_devices(Error **errp)
{
    return qmp_memory_device_list();
}

ACPIOSTInfoList *qmp_query_acpi_ospm_status(Error **errp)
{
    bool ambig;
    ACPIOSTInfoList *head = NULL;
    ACPIOSTInfoList **prev = &head;
    Object *obj = object_resolve_path_type("", TYPE_ACPI_DEVICE_IF, &ambig);

    if (obj) {
        AcpiDeviceIfClass *adevc = ACPI_DEVICE_IF_GET_CLASS(obj);
        AcpiDeviceIf *adev = ACPI_DEVICE_IF(obj);

        adevc->ospm_status(adev, &prev);
    } else {
        error_setg(errp, "command is not supported, missing ACPI device");
    }

    return head;
}

MemoryInfo *qmp_query_memory_size_summary(Error **errp)
{
    MemoryInfo *mem_info = g_malloc0(sizeof(MemoryInfo));

    mem_info->base_memory = ram_size;

    mem_info->plugged_memory = get_plugged_memory_size();
    mem_info->has_plugged_memory =
        mem_info->plugged_memory != (uint64_t)-1;

    return mem_info;
}
