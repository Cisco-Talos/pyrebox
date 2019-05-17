/*
 * Virtio scsi PCI Bindings
 *
 * Copyright IBM, Corp. 2007
 * Copyright (c) 2009 CodeSourcery
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Paul Brook        <paul@codesourcery.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#include "qemu/osdep.h"

#include "hw/virtio/virtio-scsi.h"
#include "virtio-pci.h"

typedef struct VirtIOSCSIPCI VirtIOSCSIPCI;

/*
 * virtio-scsi-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_SCSI_PCI "virtio-scsi-pci-base"
#define VIRTIO_SCSI_PCI(obj) \
        OBJECT_CHECK(VirtIOSCSIPCI, (obj), TYPE_VIRTIO_SCSI_PCI)

struct VirtIOSCSIPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOSCSI vdev;
};

static Property virtio_scsi_pci_properties[] = {
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCIProxy, flags,
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors,
                       DEV_NVECTORS_UNSPECIFIED),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_scsi_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOSCSIPCI *dev = VIRTIO_SCSI_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    VirtIOSCSICommon *vs = VIRTIO_SCSI_COMMON(vdev);
    DeviceState *proxy = DEVICE(vpci_dev);
    char *bus_name;

    if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED) {
        vpci_dev->nvectors = vs->conf.num_queues + 3;
    }

    /*
     * For command line compatibility, this sets the virtio-scsi-device bus
     * name as before.
     */
    if (proxy->id) {
        bus_name = g_strdup_printf("%s.0", proxy->id);
        virtio_device_set_child_bus_name(VIRTIO_DEVICE(vdev), bus_name);
        g_free(bus_name);
    }

    qdev_set_parent_bus(vdev, BUS(&vpci_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", errp);
}

static void virtio_scsi_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    k->realize = virtio_scsi_pci_realize;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->props = virtio_scsi_pci_properties;
    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    pcidev_k->device_id = PCI_DEVICE_ID_VIRTIO_SCSI;
    pcidev_k->revision = 0x00;
    pcidev_k->class_id = PCI_CLASS_STORAGE_SCSI;
}

static void virtio_scsi_pci_instance_init(Object *obj)
{
    VirtIOSCSIPCI *dev = VIRTIO_SCSI_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_SCSI);
}

static const VirtioPCIDeviceTypeInfo virtio_scsi_pci_info = {
    .base_name              = TYPE_VIRTIO_SCSI_PCI,
    .generic_name           = "virtio-scsi-pci",
    .transitional_name      = "virtio-scsi-pci-transitional",
    .non_transitional_name  = "virtio-scsi-pci-non-transitional",
    .instance_size = sizeof(VirtIOSCSIPCI),
    .instance_init = virtio_scsi_pci_instance_init,
    .class_init    = virtio_scsi_pci_class_init,
};

static void virtio_scsi_pci_register(void)
{
    virtio_pci_types_register(&virtio_scsi_pci_info);
}

type_init(virtio_scsi_pci_register)
