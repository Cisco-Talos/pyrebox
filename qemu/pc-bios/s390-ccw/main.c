/*
 * S390 virtio-ccw loading program
 *
 * Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "libc.h"
#include "s390-ccw.h"
#include "virtio.h"

char stack[PAGE_SIZE * 8] __attribute__((__aligned__(PAGE_SIZE)));
static SubChannelId blk_schid = { .one = 1 };
IplParameterBlock iplb __attribute__((__aligned__(PAGE_SIZE)));
static char loadparm_str[LOADPARM_LEN + 1] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
QemuIplParameters qipl;

#define LOADPARM_PROMPT "PROMPT  "
#define LOADPARM_EMPTY  "        "
#define BOOT_MENU_FLAG_MASK (QIPL_FLAG_BM_OPTS_CMD | QIPL_FLAG_BM_OPTS_ZIPL)

/*
 * Priniciples of Operations (SA22-7832-09) chapter 17 requires that
 * a subsystem-identification is at 184-187 and bytes 188-191 are zero
 * after list-directed-IPL and ccw-IPL.
 */
void write_subsystem_identification(void)
{
    SubChannelId *schid = (SubChannelId *) 184;
    uint32_t *zeroes = (uint32_t *) 188;

    *schid = blk_schid;
    *zeroes = 0;
}

void panic(const char *string)
{
    sclp_print(string);
    disabled_wait();
    while (1) { }
}

unsigned int get_loadparm_index(void)
{
    return atoui(loadparm_str);
}

static bool find_dev(Schib *schib, int dev_no)
{
    int i, r;

    for (i = 0; i < 0x10000; i++) {
        blk_schid.sch_no = i;
        r = stsch_err(blk_schid, schib);
        if ((r == 3) || (r == -EIO)) {
            break;
        }
        if (!schib->pmcw.dnv) {
            continue;
        }
        if (!virtio_is_supported(blk_schid)) {
            continue;
        }
        /* Skip net devices since no IPLB is created and therefore no
         * no network bootloader has been loaded
         */
        if (virtio_get_device_type() == VIRTIO_ID_NET && dev_no < 0) {
            continue;
        }
        if ((dev_no < 0) || (schib->pmcw.dev == dev_no)) {
            return true;
        }
    }

    return false;
}

static void menu_setup(void)
{
    if (memcmp(loadparm_str, LOADPARM_PROMPT, LOADPARM_LEN) == 0) {
        menu_set_parms(QIPL_FLAG_BM_OPTS_CMD, 0);
        return;
    }

    /* If loadparm was set to any other value, then do not enable menu */
    if (memcmp(loadparm_str, LOADPARM_EMPTY, LOADPARM_LEN) != 0) {
        return;
    }

    switch (iplb.pbt) {
    case S390_IPL_TYPE_CCW:
    case S390_IPL_TYPE_QEMU_SCSI:
        menu_set_parms(qipl.qipl_flags & BOOT_MENU_FLAG_MASK,
                       qipl.boot_menu_timeout);
        return;
    }
}

static void virtio_setup(void)
{
    Schib schib;
    int ssid;
    bool found = false;
    uint16_t dev_no;
    char ldp[] = "LOADPARM=[________]\n";
    VDev *vdev = virtio_get_device();
    QemuIplParameters *early_qipl = (QemuIplParameters *)QIPL_ADDRESS;

    /*
     * We unconditionally enable mss support. In every sane configuration,
     * this will succeed; and even if it doesn't, stsch_err() can deal
     * with the consequences.
     */
    enable_mss_facility();

    sclp_get_loadparm_ascii(loadparm_str);
    memcpy(ldp + 10, loadparm_str, LOADPARM_LEN);
    sclp_print(ldp);

    memcpy(&qipl, early_qipl, sizeof(QemuIplParameters));

    if (store_iplb(&iplb)) {
        switch (iplb.pbt) {
        case S390_IPL_TYPE_CCW:
            dev_no = iplb.ccw.devno;
            debug_print_int("device no. ", dev_no);
            blk_schid.ssid = iplb.ccw.ssid & 0x3;
            debug_print_int("ssid ", blk_schid.ssid);
            found = find_dev(&schib, dev_no);
            break;
        case S390_IPL_TYPE_QEMU_SCSI:
            vdev->scsi_device_selected = true;
            vdev->selected_scsi_device.channel = iplb.scsi.channel;
            vdev->selected_scsi_device.target = iplb.scsi.target;
            vdev->selected_scsi_device.lun = iplb.scsi.lun;
            blk_schid.ssid = iplb.scsi.ssid & 0x3;
            found = find_dev(&schib, iplb.scsi.devno);
            break;
        default:
            panic("List-directed IPL not supported yet!\n");
        }
        menu_setup();
    } else {
        for (ssid = 0; ssid < 0x3; ssid++) {
            blk_schid.ssid = ssid;
            found = find_dev(&schib, -1);
            if (found) {
                break;
            }
        }
    }

    IPL_assert(found, "No virtio device found");

    if (virtio_get_device_type() == VIRTIO_ID_NET) {
        sclp_print("Network boot device detected\n");
        vdev->netboot_start_addr = qipl.netboot_start_addr;
    } else {
        virtio_blk_setup_device(blk_schid);

        IPL_assert(virtio_ipl_disk_is_valid(), "No valid IPL device detected");
    }
}

int main(void)
{
    sclp_setup();
    virtio_setup();

    zipl_load(); /* no return */

    panic("Failed to load OS from hard disk\n");
    return 0; /* make compiler happy */
}
