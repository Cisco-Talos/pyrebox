/*
 * virtio ccw target definitions
 *
 * Copyright 2012,2015 IBM Corp.
 * Author(s): Cornelia Huck <cornelia.huck@de.ibm.com>
 *            Pierre Morel <pmorel@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#ifndef HW_S390X_VIRTIO_CCW_H
#define HW_S390X_VIRTIO_CCW_H

#include "hw/virtio/virtio-blk.h"
#include "hw/virtio/virtio-net.h"
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-scsi.h"
#ifdef CONFIG_VHOST_SCSI
#include "hw/virtio/vhost-scsi.h"
#endif
#include "hw/virtio/virtio-balloon.h"
#include "hw/virtio/virtio-rng.h"
#include "hw/virtio/virtio-crypto.h"
#include "hw/virtio/virtio-bus.h"
#ifdef CONFIG_VHOST_VSOCK
#include "hw/virtio/vhost-vsock.h"
#endif /* CONFIG_VHOST_VSOCK */
#include "hw/virtio/virtio-gpu.h"
#include "hw/virtio/virtio-input.h"

#include "hw/s390x/s390_flic.h"
#include "hw/s390x/css.h"
#include "ccw-device.h"
#include "hw/s390x/css-bridge.h"

#define VIRTIO_CCW_CU_TYPE 0x3832
#define VIRTIO_CCW_CHPID_TYPE 0x32

#define CCW_CMD_SET_VQ       0x13
#define CCW_CMD_VDEV_RESET   0x33
#define CCW_CMD_READ_FEAT    0x12
#define CCW_CMD_WRITE_FEAT   0x11
#define CCW_CMD_READ_CONF    0x22
#define CCW_CMD_WRITE_CONF   0x21
#define CCW_CMD_WRITE_STATUS 0x31
#define CCW_CMD_SET_IND      0x43
#define CCW_CMD_SET_CONF_IND 0x53
#define CCW_CMD_READ_VQ_CONF 0x32
#define CCW_CMD_READ_STATUS  0x72
#define CCW_CMD_SET_IND_ADAPTER 0x73
#define CCW_CMD_SET_VIRTIO_REV 0x83

#define TYPE_VIRTIO_CCW_DEVICE "virtio-ccw-device"
#define VIRTIO_CCW_DEVICE(obj) \
     OBJECT_CHECK(VirtioCcwDevice, (obj), TYPE_VIRTIO_CCW_DEVICE)
#define VIRTIO_CCW_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(VirtIOCCWDeviceClass, (klass), TYPE_VIRTIO_CCW_DEVICE)
#define VIRTIO_CCW_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(VirtIOCCWDeviceClass, (obj), TYPE_VIRTIO_CCW_DEVICE)

typedef struct VirtioBusState VirtioCcwBusState;
typedef struct VirtioBusClass VirtioCcwBusClass;

#define TYPE_VIRTIO_CCW_BUS "virtio-ccw-bus"
#define VIRTIO_CCW_BUS(obj) \
     OBJECT_CHECK(VirtioCcwBus, (obj), TYPE_VIRTIO_CCW_BUS)
#define VIRTIO_CCW_BUS_GET_CLASS(obj) \
    OBJECT_CHECK(VirtioCcwBusState, (obj), TYPE_VIRTIO_CCW_BUS)
#define VIRTIO_CCW_BUS_CLASS(klass) \
    OBJECT_CLASS_CHECK(VirtioCcwBusClass, klass, TYPE_VIRTIO_CCW_BUS)

typedef struct VirtioCcwDevice VirtioCcwDevice;

typedef struct VirtIOCCWDeviceClass {
    CCWDeviceClass parent_class;
    void (*realize)(VirtioCcwDevice *dev, Error **errp);
    void (*unrealize)(VirtioCcwDevice *dev, Error **errp);
    void (*parent_reset)(DeviceState *dev);
} VirtIOCCWDeviceClass;

/* Performance improves when virtqueue kick processing is decoupled from the
 * vcpu thread using ioeventfd for some devices. */
#define VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT 1
#define VIRTIO_CCW_FLAG_USE_IOEVENTFD   (1 << VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT)

struct VirtioCcwDevice {
    CcwDevice parent_obj;
    int revision;
    uint32_t max_rev;
    VirtioBusState bus;
    uint32_t flags;
    uint8_t thinint_isc;
    AdapterRoutes routes;
    /* Guest provided values: */
    IndAddr *indicators;
    IndAddr *indicators2;
    IndAddr *summary_indicator;
    uint64_t ind_bit;
    bool force_revision_1;
};

/* The maximum virtio revision we support. */
#define VIRTIO_CCW_MAX_REV 2
static inline int virtio_ccw_rev_max(VirtioCcwDevice *dev)
{
    return dev->max_rev;
}

/* virtio-scsi-ccw */

#define TYPE_VIRTIO_SCSI_CCW "virtio-scsi-ccw"
#define VIRTIO_SCSI_CCW(obj) \
        OBJECT_CHECK(VirtIOSCSICcw, (obj), TYPE_VIRTIO_SCSI_CCW)

typedef struct VirtIOSCSICcw {
    VirtioCcwDevice parent_obj;
    VirtIOSCSI vdev;
} VirtIOSCSICcw;

#ifdef CONFIG_VHOST_SCSI
/* vhost-scsi-ccw */

#define TYPE_VHOST_SCSI_CCW "vhost-scsi-ccw"
#define VHOST_SCSI_CCW(obj) \
        OBJECT_CHECK(VHostSCSICcw, (obj), TYPE_VHOST_SCSI_CCW)

typedef struct VHostSCSICcw {
    VirtioCcwDevice parent_obj;
    VHostSCSI vdev;
} VHostSCSICcw;
#endif

/* virtio-blk-ccw */

#define TYPE_VIRTIO_BLK_CCW "virtio-blk-ccw"
#define VIRTIO_BLK_CCW(obj) \
        OBJECT_CHECK(VirtIOBlkCcw, (obj), TYPE_VIRTIO_BLK_CCW)

typedef struct VirtIOBlkCcw {
    VirtioCcwDevice parent_obj;
    VirtIOBlock vdev;
} VirtIOBlkCcw;

/* virtio-balloon-ccw */

#define TYPE_VIRTIO_BALLOON_CCW "virtio-balloon-ccw"
#define VIRTIO_BALLOON_CCW(obj) \
        OBJECT_CHECK(VirtIOBalloonCcw, (obj), TYPE_VIRTIO_BALLOON_CCW)

typedef struct VirtIOBalloonCcw {
    VirtioCcwDevice parent_obj;
    VirtIOBalloon vdev;
} VirtIOBalloonCcw;

/* virtio-serial-ccw */

#define TYPE_VIRTIO_SERIAL_CCW "virtio-serial-ccw"
#define VIRTIO_SERIAL_CCW(obj) \
        OBJECT_CHECK(VirtioSerialCcw, (obj), TYPE_VIRTIO_SERIAL_CCW)

typedef struct VirtioSerialCcw {
    VirtioCcwDevice parent_obj;
    VirtIOSerial vdev;
} VirtioSerialCcw;

/* virtio-net-ccw */

#define TYPE_VIRTIO_NET_CCW "virtio-net-ccw"
#define VIRTIO_NET_CCW(obj) \
        OBJECT_CHECK(VirtIONetCcw, (obj), TYPE_VIRTIO_NET_CCW)

typedef struct VirtIONetCcw {
    VirtioCcwDevice parent_obj;
    VirtIONet vdev;
} VirtIONetCcw;

/* virtio-rng-ccw */

#define TYPE_VIRTIO_RNG_CCW "virtio-rng-ccw"
#define VIRTIO_RNG_CCW(obj) \
        OBJECT_CHECK(VirtIORNGCcw, (obj), TYPE_VIRTIO_RNG_CCW)

typedef struct VirtIORNGCcw {
    VirtioCcwDevice parent_obj;
    VirtIORNG vdev;
} VirtIORNGCcw;

/* virtio-crypto-ccw */

#define TYPE_VIRTIO_CRYPTO_CCW "virtio-crypto-ccw"
#define VIRTIO_CRYPTO_CCW(obj) \
        OBJECT_CHECK(VirtIOCryptoCcw, (obj), TYPE_VIRTIO_CRYPTO_CCW)

typedef struct VirtIOCryptoCcw {
    VirtioCcwDevice parent_obj;
    VirtIOCrypto vdev;
} VirtIOCryptoCcw;

VirtIODevice *virtio_ccw_get_vdev(SubchDev *sch);

#ifdef CONFIG_VIRTFS
#include "hw/9pfs/virtio-9p.h"

#define TYPE_VIRTIO_9P_CCW "virtio-9p-ccw"
#define VIRTIO_9P_CCW(obj) \
    OBJECT_CHECK(V9fsCCWState, (obj), TYPE_VIRTIO_9P_CCW)

typedef struct V9fsCCWState {
    VirtioCcwDevice parent_obj;
    V9fsVirtioState vdev;
} V9fsCCWState;

#endif /* CONFIG_VIRTFS */

#ifdef CONFIG_VHOST_VSOCK
#define TYPE_VHOST_VSOCK_CCW "vhost-vsock-ccw"
#define VHOST_VSOCK_CCW(obj) \
    OBJECT_CHECK(VHostVSockCCWState, (obj), TYPE_VHOST_VSOCK_CCW)

typedef struct VHostVSockCCWState {
    VirtioCcwDevice parent_obj;
    VHostVSock vdev;
} VHostVSockCCWState;

#endif /* CONFIG_VHOST_VSOCK */

#define TYPE_VIRTIO_GPU_CCW "virtio-gpu-ccw"
#define VIRTIO_GPU_CCW(obj) \
        OBJECT_CHECK(VirtIOGPUCcw, (obj), TYPE_VIRTIO_GPU_CCW)

typedef struct VirtIOGPUCcw {
    VirtioCcwDevice parent_obj;
    VirtIOGPU vdev;
} VirtIOGPUCcw;

#define TYPE_VIRTIO_INPUT_CCW "virtio-input-ccw"
#define VIRTIO_INPUT_CCW(obj) \
        OBJECT_CHECK(VirtIOInputCcw, (obj), TYPE_VIRTIO_INPUT_CCW)

typedef struct VirtIOInputCcw {
    VirtioCcwDevice parent_obj;
    VirtIOInput vdev;
} VirtIOInputCcw;

#define TYPE_VIRTIO_INPUT_HID_CCW "virtio-input-hid-ccw"
#define TYPE_VIRTIO_KEYBOARD_CCW "virtio-keyboard-ccw"
#define TYPE_VIRTIO_MOUSE_CCW "virtio-mouse-ccw"
#define TYPE_VIRTIO_TABLET_CCW "virtio-tablet-ccw"
#define VIRTIO_INPUT_HID_CCW(obj) \
        OBJECT_CHECK(VirtIOInputHIDCcw, (obj), TYPE_VIRTIO_INPUT_HID_CCW)

typedef struct VirtIOInputHIDCcw {
    VirtioCcwDevice parent_obj;
    VirtIOInputHID vdev;
} VirtIOInputHIDCcw;

#endif
