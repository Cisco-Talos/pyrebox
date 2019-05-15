/*
 * QTest testcase for VirtIO SCSI
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH
 * Copyright (c) 2015 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "scsi/constants.h"
#include "libqos/libqos-pc.h"
#include "libqos/libqos-spapr.h"
#include "libqos/virtio.h"
#include "libqos/virtio-pci.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_pci.h"
#include "standard-headers/linux/virtio_scsi.h"
#include "libqos/virtio-scsi.h"
#include "libqos/qgraph.h"

#define PCI_SLOT                0x02
#define PCI_FN                  0x00
#define QVIRTIO_SCSI_TIMEOUT_US (1 * 1000 * 1000)

#define MAX_NUM_QUEUES 64

typedef struct {
    QVirtioDevice *dev;
    int num_queues;
    QVirtQueue *vq[MAX_NUM_QUEUES + 2];
} QVirtioSCSIQueues;

static QGuestAllocator *alloc;

static void qvirtio_scsi_pci_free(QVirtioSCSIQueues *vs)
{
    int i;

    for (i = 0; i < vs->num_queues + 2; i++) {
        qvirtqueue_cleanup(vs->dev->bus, vs->vq[i], alloc);
    }
    g_free(vs);
}

static uint64_t qvirtio_scsi_alloc(QVirtioSCSIQueues *vs, size_t alloc_size,
                                   const void *data)
{
    uint64_t addr;

    addr = guest_alloc(alloc, alloc_size);
    if (data) {
        memwrite(addr, data, alloc_size);
    }

    return addr;
}

static uint8_t virtio_scsi_do_command(QVirtioSCSIQueues *vs,
                                      const uint8_t *cdb,
                                      const uint8_t *data_in,
                                      size_t data_in_len,
                                      uint8_t *data_out, size_t data_out_len,
                                      struct virtio_scsi_cmd_resp *resp_out)
{
    QVirtQueue *vq;
    struct virtio_scsi_cmd_req req = { { 0 } };
    struct virtio_scsi_cmd_resp resp = { .response = 0xff, .status = 0xff };
    uint64_t req_addr, resp_addr, data_in_addr = 0, data_out_addr = 0;
    uint8_t response;
    uint32_t free_head;

    vq = vs->vq[2];

    req.lun[0] = 1; /* Select LUN */
    req.lun[1] = 1; /* Select target 1 */
    memcpy(req.cdb, cdb, VIRTIO_SCSI_CDB_SIZE);

    /* XXX: Fix endian if any multi-byte field in req/resp is used */

    /* Add request header */
    req_addr = qvirtio_scsi_alloc(vs, sizeof(req), &req);
    free_head = qvirtqueue_add(vq, req_addr, sizeof(req), false, true);

    if (data_out_len) {
        data_out_addr = qvirtio_scsi_alloc(vs, data_out_len, data_out);
        qvirtqueue_add(vq, data_out_addr, data_out_len, false, true);
    }

    /* Add response header */
    resp_addr = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
    qvirtqueue_add(vq, resp_addr, sizeof(resp), true, !!data_in_len);

    if (data_in_len) {
        data_in_addr = qvirtio_scsi_alloc(vs, data_in_len, data_in);
        qvirtqueue_add(vq, data_in_addr, data_in_len, true, false);
    }

    qvirtqueue_kick(vs->dev, vq, free_head);
    qvirtio_wait_used_elem(vs->dev, vq, free_head, NULL,
                           QVIRTIO_SCSI_TIMEOUT_US);

    response = readb(resp_addr +
                     offsetof(struct virtio_scsi_cmd_resp, response));

    if (resp_out) {
        memread(resp_addr, resp_out, sizeof(*resp_out));
    }

    guest_free(alloc, req_addr);
    guest_free(alloc, resp_addr);
    guest_free(alloc, data_in_addr);
    guest_free(alloc, data_out_addr);
    return response;
}

static QVirtioSCSIQueues *qvirtio_scsi_init(QVirtioDevice *dev)
{
    QVirtioSCSIQueues *vs;
    const uint8_t test_unit_ready_cdb[VIRTIO_SCSI_CDB_SIZE] = {};
    struct virtio_scsi_cmd_resp resp;
    int i;

    vs = g_new0(QVirtioSCSIQueues, 1);
    vs->dev = dev;
    vs->num_queues = qvirtio_config_readl(dev, 0);

    g_assert_cmpint(vs->num_queues, <, MAX_NUM_QUEUES);

    for (i = 0; i < vs->num_queues + 2; i++) {
        vs->vq[i] = qvirtqueue_setup(dev, alloc, i);
    }

    /* Clear the POWER ON OCCURRED unit attention */
    g_assert_cmpint(virtio_scsi_do_command(vs, test_unit_ready_cdb,
                                           NULL, 0, NULL, 0, &resp),
                    ==, 0);
    g_assert_cmpint(resp.status, ==, CHECK_CONDITION);
    g_assert_cmpint(resp.sense[0], ==, 0x70); /* Fixed format sense buffer */
    g_assert_cmpint(resp.sense[2], ==, UNIT_ATTENTION);
    g_assert_cmpint(resp.sense[12], ==, 0x29); /* POWER ON */
    g_assert_cmpint(resp.sense[13], ==, 0x00);

    return vs;
}

static void hotplug(void *obj, void *data, QGuestAllocator *alloc)
{
    qtest_qmp_device_add("scsi-hd", "scsihd", "{'drive': 'drv1'}");
    qtest_qmp_device_del("scsihd");
}

/* Test WRITE SAME with the lba not aligned */
static void test_unaligned_write_same(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    uint8_t buf1[512] = { 0 };
    uint8_t buf2[512] = { 1 };
    const uint8_t write_same_cdb_1[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00
    };
    const uint8_t write_same_cdb_2[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x33, 0x00, 0x00
    };
    const uint8_t write_same_cdb_ndob[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x33, 0x00, 0x00
    };

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_1, NULL, 0, buf1, 512,
                               NULL));

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_2, NULL, 0, buf2, 512,
                               NULL));

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_ndob, NULL, 0, NULL, 0,
                               NULL));

    qvirtio_scsi_pci_free(vs);
}

static void *virtio_scsi_hotplug_setup(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive id=drv1,if=none,file=null-co://,format=raw");
    return arg;
}

static void *virtio_scsi_setup(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive file=blkdebug::null-co://,"
                    "if=none,id=dr1,format=raw,file.align=4k "
                    "-device scsi-hd,drive=dr1,lun=0,scsi-id=1");
    return arg;
}

static void register_virtio_scsi_test(void)
{
    QOSGraphTestOptions opts = { };

    opts.before = virtio_scsi_hotplug_setup;
    qos_add_test("hotplug", "virtio-scsi", hotplug, &opts);

    opts.before = virtio_scsi_setup;
    qos_add_test("unaligned-write-same", "virtio-scsi",
                 test_unaligned_write_same, &opts);
}

libqos_init(register_virtio_scsi_test);
